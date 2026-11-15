#!/usr/bin/env python3
"""Renew the signed beta feed with its existing release declarations."""
import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

PUBLIC_KEY = base64.b64decode('6Bjy68hrvm7kyXifhjMC1QU+Qg3OQVEQWtglpI1jSPI=')
PRIVATE_PREFIX = bytes.fromhex('302e020100300506032b657004220420')
PUBLIC_PREFIX = bytes.fromhex('302a300506032b6570032100')
MAX_BYTES = 1_048_576


def openssl(arguments):
    result = subprocess.run(['openssl', *arguments], capture_output=True)
    if result.returncode:
        raise ValueError('Ed25519 operation failed')
    return result.stdout


def private_file(directory, seed):
    if len(seed) != 32:
        raise ValueError('The signing seed must contain 32 bytes')
    path = Path(directory) / 'private.der'
    path.touch(mode=0o600)
    path.write_bytes(PRIVATE_PREFIX + seed)
    return str(path)


def public_key(seed):
    with tempfile.TemporaryDirectory() as directory:
        key = private_file(directory, seed)
        der = openssl(['pkey', '-inform', 'DER', '-in', key, '-pubout', '-outform', 'DER'])
    if not der.startswith(PUBLIC_PREFIX) or len(der) != len(PUBLIC_PREFIX) + 32:
        raise ValueError('Unexpected Ed25519 public key encoding')
    return der[len(PUBLIC_PREFIX):]


def verify(payload, signature, public):
    if len(signature) != 64 or len(public) != 32:
        raise ValueError('Invalid Ed25519 signature or key size')
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / 'public.der').write_bytes(PUBLIC_PREFIX + public)
        (root / 'payload').write_bytes(payload)
        (root / 'signature').write_bytes(signature)
        openssl(['pkeyutl', '-verify', '-pubin', '-keyform', 'DER', '-inkey', str(root / 'public.der'),
                 '-rawin', '-in', str(root / 'payload'), '-sigfile', str(root / 'signature')])


def sign_payload(payload, seed):
    with tempfile.TemporaryDirectory() as directory:
        key = private_file(directory, seed)
        source = Path(directory) / 'payload'
        source.write_bytes(payload)
        signature = openssl(['pkeyutl', '-sign', '-keyform', 'DER', '-inkey', key, '-rawin', '-in', str(source)])
    return json.dumps({'payload': base64.b64encode(payload).decode(),
                       'signature': base64.b64encode(signature).decode()}, separators=(',', ':')).encode()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON field')
        result[key] = value
    return result


def read_json(data):
    return json.loads(data, object_pairs_hook=unique_object)


def renew(envelope_bytes, seed, now=None, public=PUBLIC_KEY):
    if len(envelope_bytes) > MAX_BYTES:
        raise ValueError('Feed exceeds size limit')
    if public_key(seed) != public:
        raise ValueError('Signing key does not match the pinned public key')
    envelope = read_json(envelope_bytes)
    payload_bytes = base64.b64decode(envelope['payload'], validate=True)
    signature = base64.b64decode(envelope['signature'], validate=True)
    verify(payload_bytes, signature, public)
    payload = read_json(payload_bytes)
    sequence = payload['sequence']
    if (payload.get('schemaVersion') != 1 or type(sequence) is not int or
            not 0 < sequence < 2**64 - 1 or not isinstance(payload.get('releases'), list) or not payload['releases']):
        raise ValueError('Unsupported feed schema, sequence, or releases')
    now = (now or datetime.datetime.now(datetime.timezone.utc)).astimezone(datetime.timezone.utc).replace(microsecond=0)
    payload['sequence'] = max(sequence + 1, int(now.strftime('%Y%m%d%H%M%S')))
    payload['issuedAt'] = now.isoformat().replace('+00:00', 'Z')
    payload['expiresAt'] = (now + datetime.timedelta(days=30)).isoformat().replace('+00:00', 'Z')
    renewed = json.dumps(payload, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()
    result = sign_payload(renewed, seed)
    if len(result) > MAX_BYTES:
        raise ValueError('Renewed feed exceeds size limit')
    return result


def gh(arguments):
    result = subprocess.run(['gh', *arguments], capture_output=True)
    if result.returncode:
        raise ValueError('GitHub operation failed')
    return result.stdout


def select_release(releases):
    eligible = [release for release in releases if release.get('prerelease') is True
                and release.get('draft') is False and release.get('published_at')
                and any(asset.get('name') == 'update-manifest.json' for asset in release.get('assets', []))]
    if not eligible:
        raise ValueError('No published prerelease with an update manifest')
    return max(eligible, key=lambda release: (release['published_at'], release['id']))


def latest_release(repository):
    pages = read_json(gh(['api', '--paginate', '--slurp', f'repos/{repository}/releases?per_page=100']))
    return select_release([release for page in pages for release in page])


def manifest_asset(release):
    assets = [asset for asset in release['assets'] if asset['name'] == 'update-manifest.json']
    if len(assets) != 1:
        raise ValueError('Expected exactly one update manifest asset')
    return assets[0]


def download(repository, asset):
    data = gh(['api', '-H', 'Accept: application/octet-stream', f'repos/{repository}/releases/assets/{asset["id"]}'])
    if len(data) > MAX_BYTES:
        raise ValueError('Feed exceeds size limit')
    return data


def asset_exists(repository, release_id):
    release = read_json(gh(['api', f'repos/{repository}/releases/{release_id}']))
    return any(asset.get('name') == 'update-manifest.json' for asset in release['assets'])


def require_asset_absent(repository, release_id):
    if asset_exists(repository, release_id):
        raise ValueError('Concurrent manifest appeared. Preserved its signed bytes')


def publish(repository, seed):
    release = latest_release(repository)
    asset = manifest_asset(release)
    previous = download(repository, asset)
    renewed = renew(previous, seed)
    # Refuse to overwrite a concurrent publisher's release or feed revision.
    current = latest_release(repository)
    current_asset = manifest_asset(current)
    if (current['id'] != release['id'] or current_asset['id'] != asset['id'] or
            hashlib.sha256(download(repository, current_asset)).digest() != hashlib.sha256(previous).digest()):
        raise ValueError('Release changed during renewal. Retry against the current feed')
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / 'update-manifest.json'
        output.write_bytes(renewed)
        # Delete only the exact verified asset. A concurrent replacement has a new ID.
        gh(['api', '--method', 'DELETE', f'repos/{repository}/releases/assets/{asset["id"]}'])
        upload = ['release', 'upload', release['tag_name'], str(output), '--repo', repository]
        try:
            gh(upload)
        except ValueError:
            # Every upload fails safely if another publisher has claimed the name.
            require_asset_absent(repository, release['id'])
            try:
                gh(upload)
            except ValueError:
                require_asset_absent(repository, release['id'])
                output.write_bytes(previous)
                gh(upload)
                raise ValueError('Renewal upload failed. Restored the prior signed feed')
    uploaded = download(repository, manifest_asset(latest_release(repository)))
    if uploaded != renewed:
        raise ValueError('Uploaded feed did not match the renewed signed bytes')
    print('Renewed and verified the published beta update manifest')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', args.repository):
        parser.error('Invalid repository name')
    try:
        seed = base64.b64decode(os.environ.pop('WEHNIX_UPDATE_PRIVATE_KEY_B64'), validate=True)
        publish(args.repository, seed)
    except (ValueError, KeyError, TypeError, OSError):
        parser.exit(1, 'Feed renewal refused. Check the signing secret, existing signature, and release state.\n')


if __name__ == '__main__':
    main()
