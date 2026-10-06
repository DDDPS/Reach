Your ssh_config in full, Kerberos, X11 on Windows, and moving many sessions at once.

- New: every ssh_config keyword works. An imported host connects exactly as
  it does from a terminal, old servers that need hmac-sha1 included.
- New: Kerberos (GSSAPI) logins and key exchange, smart cards (PKCS#11),
  FIDO security keys and hostbased logins.
- Weaker settings and commands from a config wait for your approval, and
  approvals are signed so nobody else can give them for you.
- New: X11 on Windows. Turn on the X11 server in Settings → General and
  windows from your servers open on your desktop.
- New: select several sessions, move them to a folder in one step, search
  with /regex/, and import an ssh_config into a folder.
- Fixed: Turso sync setup on a new account, and its errors now say why.

Full details: https://github.com/alexandrosnt/Reach/blob/main/CHANGELOG.md
