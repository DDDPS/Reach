Your vault, locked down and instant.

Security
- Lock Reach whenever you like, after it sits idle, or when your computer
  locks or sleeps. Open sessions keep running underneath.
- Unlock with Windows Hello, or with a security key: a YubiKey or any FIDO2
  key. Add a spare key as a backup; your master password always works too.
- With a master password set, a lock can no longer be undone with one click.
- Vault keys stay encrypted in memory and never reach the swap file, and other
  programs are kept out of Reach's memory.

Speed
- Synced vaults open instantly and work offline, from an encrypted copy on
  this device.
- Session lists load in one step instead of one request per session.

Fixes and updates
- Fixed a crash on Windows when a vault closed, and the vault staying
  unreadable after locking and unlocking.
- Every library Reach is built on is on its latest version, closing all the
  known security issues in them, including 12 in the SSH library. Remote
  desktop runs on the newest IronRDP.
- Your vault, saved logins and known servers carry over untouched.

Full details: https://github.com/alexandrosnt/Reach/blob/main/CHANGELOG.md
