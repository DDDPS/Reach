VNC, and logins that try only what you set.

- New: VNC sessions, directly or through one of your SSH sessions, with
  the same full screen and phone keys as remote desktop.
- Sessions now try only their own key or password. If a session that
  used to connect now says its key was refused, your SSH agent was
  covering for it: add the session's public key to the server.
- A refused key now tells you which key it was.
- Fixed: importing ~/.ssh/config could hang.
- Fixed: the vault merge message showed {name} instead of the name.
- More time to check a new server's fingerprint.

Full details: https://github.com/alexandrosnt/Reach/blob/main/CHANGELOG.md
