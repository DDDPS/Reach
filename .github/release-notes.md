Unlock with your finger, and Reach on Android that works.

- Your fingerprint on Android, and Touch ID on macOS (beta: tell us how
  it works for you), now open the vault, alongside Windows Hello.
- Android: the vault stays set up after a restart, remote desktop
  connects, backups restore, and there are keys for typing (Esc, Tab,
  Ctrl, Alt, arrows) and a keyboard button for remote desktops. The app
  also fits a phone screen and has its proper icon.
- The server's login message (MOTD, last login) now stays on screen
  after connecting, as in other SSH clients.
- Fixed: the session list could stay on "Loading sessions..." forever
  when Turso stopped answering. Reach now gives up after ten seconds,
  retries, and shows the rest of your sessions.
- Fixed: after locking Reach, your own vaults could show no sessions until
  Reach restarted. Nothing was lost: your sessions were safe the whole time.
- Fixed: importing a backup key and sharing a session failed with
  "invalid args".

Full details: https://github.com/alexandrosnt/Reach/blob/main/CHANGELOG.md
