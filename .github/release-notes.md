Unlock with your finger, on every device.

- Touch ID on macOS, and your fingerprint on Android, now open the vault,
  alongside Windows Hello.
- Security keys (YubiKey or any FIDO2 key) now work on Android too, over
  USB or NFC.
- Fixed: the session list could stay on "Loading sessions..." forever when
  Turso stopped answering. Reach now gives up after ten seconds, retries,
  and shows the rest of your sessions.
- Fixed: after locking Reach, your own vaults could show no sessions until
  Reach restarted. They now come back as soon as you unlock. Nothing was
  lost: your sessions were safe the whole time.

Full details: https://github.com/alexandrosnt/Reach/blob/main/CHANGELOG.md
