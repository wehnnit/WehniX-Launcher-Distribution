# WehniX Launcher distribution materials

This repository hosts internal automatic-updater assets and third-party source materials for WehniX Launcher releases. Proprietary launcher source remains private.

Download the installer from the [official WehniX Launcher releases](https://github.com/wehnnit/WehniX-Launcher/releases).

Release assets include the signed update feed, updater archive, third-party source archives, source indexes and checksums. The third-party source indexes describe the included materials and applicable licenses.

The renewal workflow verifies the existing feed against the pinned publisher key and preserves its release declarations. It requires the `WEHNIX_UPDATE_PRIVATE_KEY_B64` secret. Scheduled renewal remains inactive until the repository variable `WEHNIX_UPDATE_RENEWAL_ENABLED` is set to `true` after feed routing is ready.
