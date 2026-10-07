A fix for Linux: saved sessions are back after a restart.

- Fixed: on Linux the vault could no longer be opened after a reboot, so
  saved sessions seemed gone. They were never deleted; Reach opens the vault
  again and keeps its key. If you set a master password, Reach asks for it.
- Fixed: the update dialog can always be closed with Later.

Full details: https://github.com/alexandrosnt/Reach/blob/main/CHANGELOG.md
