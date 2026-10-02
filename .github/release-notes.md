VNC, and logins that try only what you set.

- Fixed: on a Windows without the Visual C++ runtime, Reach did not
  start at all. It now needs nothing but Windows.
- New: VNC sessions, directly or through one of your SSH sessions, with
  the same full screen and phone keys as remote desktop.
- Android: Reach now tells you when a new version is out, links open
  again, and nothing hides under the phone's status bar.
- Android: Reach now tells you when a new version is out, links open
  again, and nothing hides under the phone's status bar.
- New: SSH session logging to a text file (Settings → Appearance),
  printable text or everything, PuTTY-style file names. Off by default.
- Reach no longer types a colour setup into your shell, so nothing of
  Reach's ends up in your shell history. It can be switched back on.
- Sessions now try only their own key or password. If a session that
  used to connect now says its key was refused, your SSH agent was
  covering for it: add the session's public key to the server.
- A refused key now tells you which key it was.
- Fixed: importing ~/.ssh/config could hang.
- Fixed: the vault merge message showed {name} instead of the name.
- More time to check a new server's fingerprint.

Full details: https://github.com/alexandrosnt/Reach/blob/main/CHANGELOG.md
