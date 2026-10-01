use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use russh::keys::PrivateKeyWithHashAlg;
use serde::{Deserialize, Serialize};
use russh::ChannelMsg;
use tauri::{Emitter, Manager};
use thiserror::Error;
use tokio::sync::mpsc;

use crate::state::ProxyConfig;

/// Expand `~` and `~/` to the user's home directory. Cross-platform: works
/// on Windows (resolves to %USERPROFILE%), macOS, and Linux. Leaves absolute
/// paths and paths without leading `~` unchanged.
pub fn expand_tilde(path: &str) -> PathBuf {
    let trimmed = path.trim();
    if trimmed == "~" {
        return dirs::home_dir().unwrap_or_else(|| PathBuf::from(trimmed));
    }
    if let Some(rest) = trimmed.strip_prefix("~/").or_else(|| trimmed.strip_prefix("~\\")) {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(trimmed)
}

/// POSIX color/prompt initialization injected after login. Safe for bash, zsh,
/// sh, dash, etc. It sets truecolor + `ls`/`grep` color aliases and, for bash
/// without a colored prompt, a sensible `PS1`. A blank prompt while it runs and
/// a clear at the end are what hide it.
/// NOTE: this is bash/POSIX syntax — it is NOT valid in fish, which is why the
/// init is selected per shell family (see `shell_init`).
///
/// Hardened for cross-platform edge cases:
/// - `dircolors` is guarded with `command -v` (absent on macOS/BSD).
/// - `ls` color flag is detected: GNU `--color=auto` vs BSD `-G`, so the alias
///   doesn't break `ls` on macOS/BSD where `--color` is an unknown option.
/// - `alias` calls are wrapped in `{ …; } 2>/dev/null`, because a strict POSIX
///   shell without the builtin (posh) prints `alias: not found` from the SHELL,
///   which a redirection on the command itself does not catch.
/// - `clear` is tolerated-if-missing, and backed by a raw escape sequence.
///
/// 🔴 NO `stty` HERE. It was the obvious way to hide the init, it was in this
/// code, and it drops input. `stty` applies the new termios with a flush, which
/// discards whatever is still sitting unread in the tty input queue — that is,
/// the init lines written behind it in the same burst. Measured with one
/// `stty -echo` followed by twenty `echo` lines in a single write, five runs
/// each, on a real PTY:
///
///     ksh93   12/20 survived, the SAME first 8 lines lost every run
///     BusyBox ash, dash, bash, zsh, mksh, posh   20/20
///     every one of the seven   20/20 with no stty at all
///
/// Only ksh93 loses lines here, but it loses them silently and reproducibly,
/// and a shell that swallows the middle of its own init is the exact failure
/// class of issue #47. The prompt is blanked for the duration instead: it costs
/// nothing, hides just as much, and cannot discard input on any shell.
///
/// 🔴 ONE COMPLETE COMMAND PER LINE, AND EVERY LINE SHORT. This used to be a
/// single 606-byte line, which hung the shell on OpenWrt (issue #47 follow-up).
/// BusyBox's line editor keeps the input line in an on-stack buffer capped at
/// `CONFIG_FEATURE_EDITING_MAX_LEN`, and silently drops every character past it
/// — `libbb/lineedit.c` breaks out of the insert with no beep and no error:
///
///     if ((int)command_len >= (maxsize - 2)) { /* no space for char and EOL */ break; }
///
/// OpenWrt ships that cap at 512 (its own ticket #18844 is titled "/bin/sh in
/// some cases needed command prompt more than 512 bytes"), so 510 bytes of the
/// 606 arrived, the cut landed inside `PS1="…`, and the surviving text carried
/// an unterminated double quote. ash then sat at its `>` continuation prompt
/// waiting for a quote that was never coming, and the session was dead on
/// arrival. It applies to interactive sessions, which is exactly a PTY shell.
///
/// So: each line below is a COMPLETE command, quote-balanced, and under 96
/// bytes — comfortably inside the 126 usable bytes of the smallest cap BusyBox
/// can even be configured to (`range 128 8192`). A device cannot truncate us
/// into a hang no matter how it was built. `posix_init_lines_are_short` pins
/// it. Do not merge these back onto one line to make it tidy.
const POSIX_COLOR_INIT: &str = concat!(
    // Blanking the prompt is not cosmetics. The shell prints a prompt for EVERY
    // line it reads, so the moment this stopped being one line it started
    // printing one prompt per line, running together into a single garbage line
    // of repeated prompts. `_op` carries the real prompt across; it is put back
    // at the end, and the screen is cleared after that.
    "_op=$PS1; PS1=''\n",
    "export COLORTERM=truecolor\n",
    r#"_dc=''; command -v dircolors >/dev/null 2>&1 && [ -z "$LS_COLORS" ] && _dc=1"#,
    "\n",
    r#"[ -n "$_dc" ] && eval "$(dircolors -b 2>/dev/null)""#,
    "\n",
    r#"_lsc=''; ls --color=auto >/dev/null 2>&1 && _lsc='ls --color=auto'"#,
    "\n",
    r#"[ -n "$_lsc" ] || { ls -G >/dev/null 2>&1 && _lsc='ls -G'; }"#,
    "\n",
    // Braces, not a trailing `2>/dev/null` on the command. A strict-POSIX shell
    // with no `alias` builtin (posh) reports `alias: not found` from the SHELL,
    // not from the command, and a redirection attached to the command does not
    // cover that: it printed the error straight onto the user's screen. A
    // redirection on the group covers everything inside it, error included.
    r#"{ [ -n "$_lsc" ] && alias ls="$_lsc"; } 2>/dev/null"#,
    "\n",
    r#"{ alias grep='grep --color=auto'; } 2>/dev/null"#,
    "\n",
    r#"{ alias diff='diff --color=auto'; } 2>/dev/null"#,
    "\n",
    r#"_rp=0; [ -n "$BASH" ] && _rp=1"#,
    "\n",
    // Against `_op`, not `$PS1`: PS1 is blank at this point, so testing it
    // would never see the colored prompt the user already had, and we would
    // stomp on it instead of leaving it alone.
    r#"case "$_op" in *033*|*\\e\[*) _rp=0;; esac"#,
    "\n",
    // The prompt we will end up with is chosen into `_np` and NOT installed
    // yet. Assigning PS1 here would make every line after it print a prompt
    // again: measured under BusyBox ash, restoring it at this point printed
    // exactly one prompt per remaining line. That is the whole bug.
    "_np=$_op\n",
    r#"[ "$_rp" = 1 ] && { _c=32; [ "${EUID:-$(id -u)}" = "0" ] && _c=31; }"#,
    "\n",
    r#"[ "$_rp" = 1 ] && _pp="\\[\\033[01;${_c}m\\]\\u@\\h\\[\\033[00m\\]""#,
    "\n",
    r#"[ "$_rp" = 1 ] && _np="$_pp:\\[\\033[01;34m\\]\\w\\[\\033[00m\\]\\$ ""#,
    "\n",
    // The real prompt goes in, the temporaries go out. BEFORE the clears: a
    // shell with its own line editor (mksh, BusyBox ash, zsh) echoes each line
    // as it reads it, so anything typed after the final clear gets echoed back
    // onto the screen that clear just cleaned. Measured on mksh: with this line
    // last, its own text was left sitting on the fresh screen.
    "PS1=$_np; unset _c _dc _lsc _np _op _pp _rp\n",
    // Both, deliberately, and last. `clear` is an ncurses binary on most
    // distros and it fails silently (its stderr is discarded) when the terminfo
    // database is absent, which is the default on a minimal Alpine: the init
    // noise then just stayed on screen. The raw sequence needs no terminfo and
    // no binary, and being last it wipes its own echo along with every other
    // line above, so the user lands on a clean screen with one prompt on it.
    "clear 2>/dev/null\n",
    // The same line prints INIT_DONE right after its clear, so Reach knows
    // where the init's output ends without typing another line (which would
    // be echoed onto the clean screen).
    r#"printf '\033[H\033[2J\033]7776;reach-init\007' 2>/dev/null"#,
    "\n",
);

/// What the init prints the moment its clear is done: an OSC sequence no
/// terminal acts on, taken out of the output before it is shown. The
/// server's login message is drawn again in its place (see `LoginFlow`).
const INIT_DONE: &str = "\x1b]7776;reach-init\x07";

/// The largest line we will ever type into a remote shell. BusyBox's smallest
/// configurable input buffer is 128 bytes and it reserves two, so 126 is the
/// floor across every device that exists; 96 leaves a margin for a prompt that
/// shares the buffer and for anything appended later. Enforced by
/// `posix_init_lines_are_short`, which is the only thing that reads it.
#[cfg(test)]
const MAX_INIT_LINE_BYTES: usize = 96;

/// Shell families we tailor the post-login init for.
enum ShellFamily {
    /// bash / zsh / sh / dash / ksh … — gets `POSIX_COLOR_INIT`.
    Posix,
    /// fish — gets a minimal fish-native init (its prompt/colors are good by default).
    Fish,
    /// Anything we don't recognize — inject nothing rather than guess its syntax.
    Other,
}

/// Classify a configured login-shell command (e.g. `"fish"`, `"/usr/bin/zsh -l"`).
/// `None`/empty means "use the account's default shell", which we treat as POSIX
/// to preserve the long-standing behavior for the common bash/zsh case.
fn shell_family(shell: Option<&str>) -> ShellFamily {
    let Some(s) = shell.map(str::trim).filter(|s| !s.is_empty()) else {
        return ShellFamily::Posix;
    };
    let prog = s.split_whitespace().next().unwrap_or("");
    let base = prog.rsplit(['/', '\\']).next().unwrap_or(prog).to_ascii_lowercase();
    match base.as_str() {
        "fish" => ShellFamily::Fish,
        "bash" | "sh" | "zsh" | "dash" | "ash" | "ksh" | "mksh" | "busybox" => ShellFamily::Posix,
        _ => ShellFamily::Other,
    }
}

/// The post-login init to inject for the given shell, or `None` to inject nothing.
fn shell_init(shell: Option<&str>) -> Option<String> {
    match shell_family(shell) {
        ShellFamily::Posix => Some(POSIX_COLOR_INIT.to_string()),
        // Valid fish: avoids the bash-isms (`export`, `$(...)`, `if…then…fi`)
        // that make fish throw a syntax error on every connect.
        ShellFamily::Fish => Some("set -gx COLORTERM truecolor; clear; printf '\\e]7776;reach-init\\a'\n".to_string()),
        ShellFamily::Other => None,
    }
}

/// Request a PTY and start the interactive shell on `channel`. When `shell` is
/// set, `exec` it as the login shell instead of the account's default; a bare
/// program name (e.g. `fish`) gets a `-l` login flag, while a value with flags
/// (e.g. `fish -l`) is run verbatim. When `shell` is empty, request the default
/// login shell exactly as before.
async fn open_interactive_shell(
    channel: &russh::Channel<russh::client::Msg>,
    cols: u16,
    rows: u16,
    shell: Option<&str>,
) -> Result<(), SshError> {
    channel
        .request_pty(false, "xterm-256color", cols as u32, rows as u32, 0, 0, &[])
        .await
        .map_err(|e| SshError::ChannelError(format!("PTY request failed: {}", e)))?;

    match shell.map(str::trim).filter(|s| !s.is_empty()) {
        Some(cmd) => {
            let full = if cmd.split_whitespace().nth(1).is_some() {
                format!("exec {}", cmd)
            } else {
                format!("exec {} -l", cmd)
            };
            channel
                .exec(false, full.as_bytes())
                .await
                .map_err(|e| SshError::ChannelError(format!("Shell exec failed: {}", e)))?;
        }
        None => {
            channel
                .request_shell(false)
                .await
                .map_err(|e| SshError::ChannelError(format!("Shell request failed: {}", e)))?;
        }
    }
    Ok(())
}

/// The one phrase that means "this key wants a passphrase and I do not have
/// it". The connect dialog matches on it to decide whether asking the user for
/// one could possibly help, so it must stay in step with the messages below.
pub const NEEDS_PASSPHRASE: &str = "This private key is passphrase-protected. Enter its passphrase to unlock";

/// Turn an opaque key-loading failure into a message that tells the user
/// what's actually wrong. The most common mistake is selecting an OpenSSH
/// *public* key (`id_ed25519.pub`) where the *private* key is required — russh
/// reports that as a generic parse error (the public key's spaces look like a
/// formatting problem), so we classify the file ourselves and point at the fix.
fn describe_key_load_error(
    raw_path: Option<&str>,
    label: &str,
    had_passphrase: bool,
    encrypted: Option<bool>,
    err: &impl std::fmt::Display,
) -> String {
    use crate::ssh::keyfile::{classify_path, KeyFileKind};

    // An imported key has no file to classify. It was read once already, at
    // import, so a key that will not load now is either locked or damaged;
    // calling every failure "passphrase-protected" sent people looking for a
    // passphrase their key never had.
    let Some(raw_path) = raw_path else {
        return if had_passphrase {
            format!("Could not open {} — wrong passphrase? ({})", label, err)
        } else if encrypted == Some(false) || encrypted.is_none() {
            format!("Could not read {}: it is damaged or not a private key Reach understands. Import it again from the original key file. ({})", label, err)
        } else {
            format!("{} {} ({})", NEEDS_PASSPHRASE, label, err)
        };
    };

    let info = classify_path(raw_path);
    match info.kind {
        KeyFileKind::PublicKey => {
            let algo = info
                .algo
                .as_deref()
                .map(|a| format!(" ({a})"))
                .unwrap_or_default();
            let fix = if let Some(c) = &info.suggested_private_key {
                format!(" Use the matching private key instead: {}", c.path)
            } else if !info.sibling_private_keys.is_empty() {
                let names: Vec<_> = info
                    .sibling_private_keys
                    .iter()
                    .map(|c| c.name.clone())
                    .collect();
                format!(" Private keys in that folder: {}", names.join(", "))
            } else {
                String::new()
            };
            format!("'{}' is an OpenSSH public key{}, not a private key.{}", label, algo, fix)
        }
        KeyFileKind::NotFound => format!("Key file not found: {}", label),
        KeyFileKind::NotAKey => {
            format!("'{}' is not a recognized private key file ({})", label, err)
        }
        KeyFileKind::PrivateKey => {
            if had_passphrase {
                format!("Could not load private key '{}' — wrong passphrase? ({})", label, err)
            } else if encrypted == Some(false) {
                format!("Could not read the private key '{}': the file is damaged. ({})", label, err)
            } else {
                format!("{} '{}' ({})", NEEDS_PASSPHRASE, label, err)
            }
        }
    }
}

/// Attempt to authenticate via the local SSH agent (OpenSSH agent or Pageant
/// on Windows; SSH_AUTH_SOCK on Unix). Tries every identity the agent offers
/// and returns Ok(true) on the first one the server accepts. Returns Ok(false)
/// if no agent identity is accepted, or Err if the agent is unreachable.
/// Cascade through the available auth methods in OpenSSH order: configured
/// public key → ssh-agent identities → password. Returns Ok(true) when the
/// server accepts a method, Ok(false) when every available method is rejected.
/// Returns Err only on hard transport-level errors; all "auth was tried but
/// rejected" outcomes resolve to Ok(false) so the caller can decide what to
/// do (e.g. surface a password fallback prompt to the user).
/// How a login got in, and the fingerprint of the session's own key if the
/// server refused it on the way.
#[derive(Debug, Default)]
struct AuthOutcome {
    by: Option<AuthBy>,
    refused_key: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthBy {
    Key,
    Agent,
    Password,
}

impl AuthOutcome {
    /// Ok when something got in; otherwise the error that says what to fix.
    fn into_result(self) -> Result<AuthBy, SshError> {
        match (self.by, self.refused_key) {
            (Some(by), _) => Ok(by),
            (None, Some(fingerprint)) => Err(SshError::KeyRefused(fingerprint)),
            (None, None) => Err(SshError::AuthFailed),
        }
    }
}

/// The RSA signature hash to offer: the one the server said it accepts
/// (server-sig-algs, RFC 8308), or SHA-1 when it said nothing, which is what
/// OpenSSH does (`key_sig_algorithm` in sshconnect2.c). One offer per key,
/// never a guess at others: each refusal counts against the server's
/// MaxAuthTries and its brute-force protection. Every server new enough to
/// refuse SHA-1 (OpenSSH 8.8+) sends its list, as all have since 7.2.
fn rsa_hashes(known: Option<Option<russh::keys::HashAlg>>) -> Vec<Option<russh::keys::HashAlg>> {
    vec![known.flatten()]
}

async fn cascade_authenticate<H: russh::client::Handler>(
    handle: &mut russh::client::Handle<H>,
    username: &str,
    auth: &AuthParams,
) -> Result<AuthOutcome, SshError> {
    let mut outcome = AuthOutcome::default();
    // 1. Configured private key — a file on this machine, or material the
    //    user imported into the vault.
    if let Some(key_auth) = &auth.key {
        let material = match &key_auth.source {
            KeySource::Path(path) => {
                let expanded = expand_tilde(path);
                tracing::info!(
                    "SSH key auth: loading key from '{}' (raw input: '{}')",
                    expanded.display(),
                    path
                );
                std::fs::read_to_string(&expanded).map_err(|e| {
                    tracing::error!("SSH key read failed for '{}': {}", expanded.display(), e);
                    SshError::ConnectionFailed(describe_key_load_error(
                        Some(path),
                        &key_auth.label(),
                        key_auth.passphrase.is_some(),
                        None,
                        &e,
                    ))
                })?
            }
            KeySource::Material(material) => {
                tracing::info!("SSH key auth: using an imported key from the vault");
                material.clone()
            }
        };
        let key = decode_key(&material, key_auth.passphrase.as_deref()).map_err(|e| {
            tracing::error!("SSH key load failed for {}: {}", key_auth.label(), e);
            SshError::ConnectionFailed(describe_key_load_error(
                match &key_auth.source {
                    KeySource::Path(p) => Some(p.as_str()),
                    KeySource::Material(_) => None,
                },
                &key_auth.label(),
                key_auth.passphrase.is_some(),
                key_is_encrypted(&material),
                &e,
            ))
        })?;
        let fingerprint = key.public_key().fingerprint(russh::keys::HashAlg::Sha256).to_string();
        tracing::info!(
            "SSH key loaded successfully, attempting publickey auth as '{}'",
            username
        );
        // An RSA key signs with a hash the server accepts; see rsa_hashes.
        let hashes = if key.algorithm().is_rsa() {
            rsa_hashes(handle.best_supported_rsa_hash().await.ok().flatten())
        } else {
            vec![None]
        };
        let key = Arc::new(key);
        for hash_alg in hashes {
            let accepted = handle
                .authenticate_publickey(username, PrivateKeyWithHashAlg::new(Arc::clone(&key), hash_alg))
                .await
                .map_err(|e| {
                    tracing::error!("SSH publickey auth error: {}", e);
                    SshError::ConnectionFailed(format!("Auth error: {}", e))
                })?
                .success();
            tracing::info!("SSH publickey auth result for {fingerprint} ({hash_alg:?}): {accepted}");
            if accepted {
                outcome.by = Some(AuthBy::Key);
                return Ok(outcome);
            }
        }
        tracing::warn!("SSH: the server refused this session's key {fingerprint}");
        outcome.refused_key = Some(fingerprint);
    }

    // 2. ssh-agent identities (auto-detected: OpenSSH agent / Pageant / SSH_AUTH_SOCK).
    if auth.allow_agent {
        match try_agent_auth(handle, username.to_string()).await {
            Ok(true) => {
                if let Some(refused) = &outcome.refused_key {
                    tracing::warn!(
                        "SSH: logged in with a key from the SSH agent; this session's own key {refused} was refused, so it will not work where there is no agent (a phone, another computer)"
                    );
                }
                outcome.by = Some(AuthBy::Agent);
                return Ok(outcome);
            }
            Ok(false) => tracing::info!("SSH agent: no identity accepted"),
            Err(e) => tracing::info!("SSH agent fallback skipped: {}", e),
        }
    }

    // 3. Password.
    if let Some(password) = &auth.password {
        tracing::info!(
            "SSH password auth: attempting as '{}' (password length: {})",
            username,
            password.len()
        );
        let accepted = handle
            .authenticate_password(username, password)
            .await
            .map_err(|e| {
                tracing::error!("SSH password auth error: {}", e);
                SshError::ConnectionFailed(format!("Auth error: {}", e))
            })?
            .success();
        tracing::info!("SSH password auth result: {}", accepted);
        if accepted {
            outcome.by = Some(AuthBy::Password);
            return Ok(outcome);
        }
    }

    Ok(outcome)
}

/// Try every identity from the local SSH agent. Returns Ok(true) on the first
/// identity accepted by the server, Ok(false) if none are accepted, or Err if
/// the agent is unreachable or holds no keys. Cross-platform: uses OpenSSH's
/// Windows named pipe / Pageant on Windows; SSH_AUTH_SOCK on Unix.
async fn try_agent_auth<H: russh::client::Handler>(
    handle: &mut russh::client::Handle<H>,
    username: String,
) -> Result<bool, String> {
    #[cfg(unix)]
    {
        let agent = russh::keys::agent::client::AgentClient::connect_env()
            .await
            .map_err(|e| format!("ssh-agent unavailable (SSH_AUTH_SOCK): {}", e))?;
        try_agent_auth_inner(handle, username, agent).await
    }
    #[cfg(windows)]
    {
        // Try OpenSSH for Windows agent named pipe first (most common on Win10+).
        match russh::keys::agent::client::AgentClient::connect_named_pipe(
            r"\\.\pipe\openssh-ssh-agent",
        )
        .await
        {
            Ok(agent) => try_agent_auth_inner(handle, username, agent).await,
            Err(e) => {
                tracing::debug!("OpenSSH Windows agent named pipe unavailable: {}", e);
                // The pageant transport unwraps the window lookup inside a
                // spawned task: with no Pageant running, that task panics
                // and the stream reads as an early EOF. Look for the window
                // first, so the panic never happens.
                if !pageant_is_running() {
                    return Err("no SSH agent running (OpenSSH agent or Pageant)".into());
                }
                let pageant = russh::keys::agent::client::AgentClient::connect_pageant()
                    .await
                    .map_err(|e| format!("Pageant unavailable: {}", e))?;
                try_agent_auth_inner(handle, username, pageant).await
            }
        }
    }
}

/// Pageant announces itself with a hidden window of class and title
/// "Pageant"; that window is how every client finds it.
#[cfg(windows)]
fn pageant_is_running() -> bool {
    use windows::core::w;
    use windows::Win32::UI::WindowsAndMessaging::FindWindowW;
    // SAFETY: two valid, NUL-terminated wide strings; no other state involved.
    unsafe { FindWindowW(w!("Pageant"), w!("Pageant")).is_ok() }
}

async fn try_agent_auth_inner<S, H: russh::client::Handler>(
    handle: &mut russh::client::Handle<H>,
    username: String,
    mut agent: russh::keys::agent::client::AgentClient<S>,
) -> Result<bool, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let identities = agent
        .request_identities()
        .await
        .map_err(|e| format!("agent request_identities failed: {}", e))?;
    if identities.is_empty() {
        return Err("ssh agent is reachable but holds no identities".into());
    }
    tracing::info!(
        "SSH agent offers {} identit{}",
        identities.len(),
        if identities.len() == 1 { "y" } else { "ies" }
    );
    let rsa_hash = handle.best_supported_rsa_hash().await.ok().flatten().flatten();
    for (idx, identity) in identities.iter().enumerate() {
        let key = identity.public_key().into_owned();
        tracing::info!(
            "SSH agent: trying identity #{} (type: {})",
            idx + 1,
            key.algorithm()
        );
        let hash_alg = if key.algorithm().is_rsa() { rsa_hash } else { None };
        let result = handle
            .authenticate_publickey_with(username.clone(), key, hash_alg, &mut agent)
            .await
            .map(|r| r.success());
        match result {
            Ok(true) => {
                tracing::info!("SSH agent: identity #{} accepted by server", idx + 1);
                return Ok(true);
            }
            Ok(false) => {
                tracing::info!("SSH agent: identity #{} rejected by server", idx + 1);
            }
            Err(e) => {
                tracing::warn!("SSH agent: identity #{} signing error: {:?}", idx + 1, e);
            }
        }
    }
    Ok(false)
}

/// A shared, clonable wrapper around the russh Handle.
/// Handle is not Clone, so we wrap it in Arc<Mutex<>> for reuse.
pub type SharedHandle = Arc<tokio::sync::Mutex<russh::client::Handle<SshClientHandler>>>;

#[derive(Debug, Error)]
pub enum SshError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    #[error("Authentication rejected — server did not accept the public key (not in authorized_keys?) or password is wrong")]
    AuthFailed,
    /// The session's own key was offered and refused, and nothing else got
    /// in. Named by fingerprint so it can be compared with the server's
    /// `authorized_keys` (`ssh-keygen -lf`). Worded to start like
    /// `AuthFailed`: the connect dialog offers a password on "rejected".
    #[error("Authentication rejected — the server refused this session's key ({0}). Its public key must be in ~/.ssh/authorized_keys on the server; check with ssh-keygen -lf, or import the key the server already trusts")]
    KeyRefused(String),
    #[error("Channel error: {0}")]
    ChannelError(String),
    #[error("Connection not found: {0}")]
    NotFound(String),
    #[error("Send error: {0}")]
    SendError(String),
}

/// What happens in the shell right after login.
#[derive(Clone, Copy, Debug)]
pub struct LoginOptions {
    /// Type the color and prompt init into the shell (Settings → Appearance).
    pub inject_colors: bool,
    /// Keep the server's login message (MOTD, "Last login") on screen. The
    /// init ends with a clear that used to wipe it (issue #76).
    pub show_login_message: bool,
}

/// Getting the server's login message past the init's clear. The init is
/// typed only once the server has gone quiet after login, so everything
/// printed before it is the message (MOTD, "Last login") and the first
/// prompt. The init's last line clears the screen and prints `INIT_DONE`;
/// that marker is replaced with the message, so it ends up above the prompt
/// the shell prints next, where PuTTY and ssh leave it.
struct LoginFlow {
    /// The init, until it is typed.
    init: Option<String>,
    /// What the server printed before the init was typed.
    captured: String,
    started: std::time::Instant,
    last_output: Option<std::time::Instant>,
    /// When the init was typed; the marker is looked for after that.
    typed_at: Option<std::time::Instant>,
    /// The end of an output chunk that might be the start of the marker.
    held: String,
    done: bool,
}

impl LoginFlow {
    /// How long the server must be quiet before the login counts as over.
    const QUIET: std::time::Duration = std::time::Duration::from_millis(300);
    /// Type the init by then even if the server never stops talking.
    const MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(3);
    /// Give up on the marker (a shell that did not run the init) by then.
    const MARKER_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

    fn new(init: String, now: std::time::Instant) -> Self {
        LoginFlow {
            init: Some(init),
            captured: String::new(),
            started: now,
            last_output: None,
            typed_at: None,
            held: String::new(),
            done: false,
        }
    }

    fn done(&self) -> bool {
        self.done
    }

    /// Output from the server; returns what to show now.
    fn output(&mut self, text: &str, now: std::time::Instant) -> String {
        if self.done {
            return text.to_string();
        }
        if self.init.is_some() {
            self.captured.push_str(text);
            self.last_output = Some(now);
            return text.to_string();
        }
        let mut buf = std::mem::take(&mut self.held);
        buf.push_str(text);
        if let Some(at) = buf.find(INIT_DONE) {
            self.done = true;
            let mut out = String::with_capacity(buf.len() + self.captured.len());
            out.push_str(&buf[..at]);
            out.push_str(&self.message());
            out.push_str(&buf[at + INIT_DONE.len()..]);
            return out;
        }
        let keep = partial_suffix(&buf, INIT_DONE);
        self.held = buf.split_off(buf.len() - keep);
        buf
    }

    /// Time passing: returns the init to type once the server has gone
    /// quiet, or output held back if the marker never came.
    fn tick(&mut self, now: std::time::Instant) -> (Option<String>, Option<String>) {
        if self.done {
            return (None, None);
        }
        if self.init.is_some() {
            let quiet = self.last_output.is_some_and(|t| now.duration_since(t) >= Self::QUIET);
            if quiet || now.duration_since(self.started) >= Self::MAX_WAIT {
                self.typed_at = Some(now);
                return (self.init.take(), None);
            }
            return (None, None);
        }
        if self.typed_at.is_some_and(|t| now.duration_since(t) >= Self::MARKER_WAIT) {
            self.done = true;
            let held = std::mem::take(&mut self.held);
            return (None, (!held.is_empty()).then_some(held));
        }
        (None, None)
    }

    /// The login message: what was printed before the init, up to its last
    /// line break, which leaves out the first prompt.
    fn message(&self) -> String {
        match self.captured.rfind('\n') {
            Some(end) => self.captured[..=end].to_string(),
            None => String::new(),
        }
    }
}

/// The length of the longest proper start of `marker` that `buf` ends with.
fn partial_suffix(buf: &str, marker: &str) -> usize {
    (1..marker.len()).rev().find(|&k| buf.ends_with(&marker[..k])).unwrap_or(0)
}

enum SessionCommand {
    Data(Vec<u8>),
    Resize { cols: u32, rows: u32 },
    /// The frontend has attached its data listener — flush any buffered output
    /// and switch to live streaming. Until this arrives, the session task holds
    /// remote output (motd/banner) so nothing emitted before the terminal
    /// mounts is lost.
    Ready,
    Close,
}

/// Cascading SSH auth parameters. Each field is optional and tried in order:
/// configured key → ssh-agent identities → password. The first method the
/// server accepts wins. This mirrors OpenSSH's progressive auth — `ssh root@h`
/// without an `IdentitiesOnly yes` will try every loaded identity, then prompt
/// for a password if all fail.
#[derive(Debug, Clone, Default)]
pub struct AuthParams {
    pub key: Option<KeyAuth>,
    pub password: Option<String>,
    pub allow_agent: bool,
}

/// Where a private key comes from. A path is read at connect time from this
/// machine's disk; material was imported into the vault and travels with the
/// session, which is what lets the same session connect from a machine that
/// has never seen the user's `~/.ssh` (issue #46).
#[derive(Debug, Clone)]
pub enum KeySource {
    Path(String),
    Material(String),
}

#[derive(Debug, Clone)]
pub struct KeyAuth {
    pub source: KeySource,
    pub passphrase: Option<String>,
}

impl KeyAuth {
    /// How to name this key in a message to the user.
    fn label(&self) -> String {
        match &self.source {
            KeySource::Path(p) => expand_tilde(p).display().to_string(),
            KeySource::Material(_) => "the imported key".to_string(),
        }
    }
}

/// Read a private key, forgiving a passphrase that was never needed.
///
/// russh hands the passphrase straight to `PrivateKey::decrypt`, and ssh-key
/// refuses to decrypt a key that was never encrypted — so a passphrase typed
/// against an unencrypted key turned a working key into a hard failure
/// (issue #46). A passphrase that the key does not want is not an error the
/// user should ever have to understand: try it, then try without it, and keep
/// the first error if neither works.
/// Key text as it should have been. A key copied between machines picks up a
/// byte order mark (Notepad, PowerShell), Windows line ends, trailing spaces
/// or blank lines; russh wants the `-----BEGIN` line exactly and skips any
/// body line with a stray character, which then reads as a damaged key. None
/// of that is part of the key, so it goes. Every format Reach reads (OpenSSH,
/// PEM, PuTTY's .ppk) is line-based with no meaningful trailing space.
pub fn normalize_key_text(material: &str) -> String {
    let text = material.strip_prefix('\u{feff}').unwrap_or(material);
    let lines: Vec<&str> = text.lines().map(str::trim_end).collect();
    let start = lines.iter().position(|l| !l.trim().is_empty()).unwrap_or(lines.len());
    let end = lines.iter().rposition(|l| !l.trim().is_empty()).map_or(start, |i| i + 1);
    let mut out = lines[start..end].iter().map(|l| l.trim_start()).collect::<Vec<_>>().join("\n");
    out.push('\n');
    out
}

/// Whether key text is passphrase-protected, when that can be told without
/// the passphrase: an OpenSSH key says so in its header, a PEM key in its
/// `Proc-Type`/`ENCRYPTED` label, a .ppk in its `Encryption:` line. `None`
/// when the text is none of those.
pub fn key_is_encrypted(material: &str) -> Option<bool> {
    let text = normalize_key_text(material);
    if let Ok(key) = russh::keys::ssh_key::PrivateKey::from_openssh(&text) {
        return Some(key.is_encrypted());
    }
    if text.starts_with("PuTTY-User-Key-File-") {
        return text
            .lines()
            .find_map(|l| l.strip_prefix("Encryption:"))
            .map(|v| v.trim() != "none");
    }
    if text.starts_with("-----BEGIN ") {
        return Some(text.contains("ENCRYPTED"));
    }
    None
}

pub fn decode_key(
    material: &str,
    passphrase: Option<&str>,
) -> Result<russh::keys::PrivateKey, russh::keys::Error> {
    let pass = passphrase.filter(|p| !p.is_empty());
    let normalized = normalize_key_text(material);
    let material = normalized.as_str();
    match russh::keys::decode_secret_key(material, pass) {
        Ok(key) => Ok(key),
        Err(e) if pass.is_some() => russh::keys::decode_secret_key(material, None).map_err(|_| e),
        Err(e) => Err(e),
    }
}

impl AuthParams {
    pub fn from_password(password: String) -> Self {
        Self { password: Some(password), ..Default::default() }
    }

    pub fn from_key(path: String, passphrase: Option<String>) -> Self {
        Self { key: Some(KeyAuth { source: KeySource::Path(path), passphrase }), ..Default::default() }
    }

    pub fn from_agent() -> Self {
        Self { allow_agent: true, ..Default::default() }
    }
}

/// Parameters for a single jump host in a proxy chain.
#[derive(Debug, Clone)]
pub struct JumpHostParams {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: AuthParams,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ConnectionInfo {
    pub id: String,
    pub host: String,
    pub port: u16,
    pub username: String,
}

pub(crate) struct ActiveConnection {
    cmd_tx: mpsc::UnboundedSender<SessionCommand>,
    info: ConnectionInfo,
    handle: SharedHandle,
    /// Keep intermediate jump host sessions alive for the lifetime of this connection.
    /// These are intentionally stored but never directly read — dropping them closes the tunnels.
    #[allow(dead_code)]
    jump_handles: Vec<SharedHandle>,
}

/// See [`SshManager::open_headless`]. Dropping it closes the connection.
pub(crate) struct HeadlessConnection {
    pub handle: SharedHandle,
    /// Kept alive for as long as `handle`; see `ActiveConnection::jump_handles`.
    #[allow(dead_code)]
    jump_handles: Vec<SharedHandle>,
}

pub struct SshManager {
    connections: HashMap<String, ActiveConnection>,
}

impl SshManager {
    pub fn new() -> Self {
        Self { connections: HashMap::new() }
    }

    /// Register a freshly-established connection and return its info.
    ///
    /// The slow connect work (`connect` / `connect_via_jump`) runs lock-free;
    /// the caller takes the global `ssh_manager` lock only to call this, which
    /// is a single HashMap insert — so a slow/hanging handshake on one host no
    /// longer blocks `ssh_send` / `ssh_resize` / `ssh_disconnect` on others.
    pub(crate) fn register(&mut self, conn: ActiveConnection) -> ConnectionInfo {
        let info = conn.info.clone();
        self.connections.insert(info.id.clone(), conn);
        info
    }

    /// Establish a direct SSH connection. Takes no `self` and does NOT touch the
    /// connections map — it returns the finished `ActiveConnection` for the
    /// caller to `register` under a brief lock. This keeps the slow handshake/
    /// auth off the global lock so other connections stay responsive.
    #[expect(clippy::too_many_arguments, reason = "the connection settings ssh_connect receives, passed through as they are")]
    pub(crate) async fn connect(
        id: &str,
        host: &str,
        port: u16,
        username: &str,
        auth: AuthParams,
        cols: u16,
        rows: u16,
        app_handle: tauri::AppHandle,
        proxy: Option<ProxyConfig>,
        shell: Option<String>,
        login: LoginOptions,
    ) -> Result<ActiveConnection, SshError> {
        tracing::info!("SSH connecting to {}@{}:{}", username, host, port);

        let timeout_duration = std::time::Duration::from_secs(15);
        let connect_future = async {
            let handle = Self::handshake_direct(host, port, username, &auth, proxy.as_ref(), app_handle.clone()).await?;
            tracing::info!("SSH authenticated for {}@{}:{}", username, host, port);

            let channel = handle.channel_open_session().await
                .map_err(|e| SshError::ChannelError(format!("Failed to open session: {}", e)))?;

            open_interactive_shell(&channel, cols, rows, shell.as_deref()).await?;

            tracing::info!("SSH shell opened for {}@{}:{}", username, host, port);

            Ok((handle, channel))
        };

        let (handle, channel) = tokio::time::timeout(timeout_duration, connect_future)
            .await
            .map_err(|_| SshError::ConnectionFailed("Connection timed out".into()))??;

        let info = ConnectionInfo {
            id: id.to_string(),
            host: host.to_string(),
            port,
            username: username.to_string(),
        };

        into_active_connection(channel, handle, info, shell.as_deref(), login, app_handle, Vec::new()).await
    }

    /// Connect and authenticate, directly or through a proxy. Opens no channel:
    /// the terminal asks for a shell on top, a database tunnel only for
    /// direct-tcpip channels.
    async fn handshake_direct(
        host: &str,
        port: u16,
        username: &str,
        auth: &AuthParams,
        proxy: Option<&ProxyConfig>,
        app_handle: tauri::AppHandle,
    ) -> Result<russh::client::Handle<SshClientHandler>, SshError> {
        let config = Arc::new(russh::client::Config::default());
        let handler = SshClientHandler::new(host, port, Some(app_handle.clone()));

        let mut handle = if let Some(proxy) = proxy {
            tracing::info!("SSH connecting via {} proxy {}:{}", proxy.proxy_type, proxy.host, proxy.port);
            let stream = Self::connect_via_proxy(proxy, host, port).await?;
            russh::client::connect_stream(config, stream, handler)
                .await
                .map_err(|e| SshError::ConnectionFailed(format!("Proxy SSH handshake failed: {}", e)))?
        } else {
            russh::client::connect(config, (host, port), handler)
                .await
                // "No route to host" on a Mac usually means the local
                // network permission, not the route (issue #47).
                .map_err(|e| SshError::ConnectionFailed(
                    crate::ssh::netdiag::describe_connect_error(host, &e),
                ))?
        };

        // Authenticate using a cascading strategy: configured key → agent → password.
        // The first method the server accepts wins. Mirrors OpenSSH's progressive auth.
        let outcome = cascade_authenticate(&mut handle, username, auth).await?;
        let refused = outcome.refused_key.clone();
        let by = outcome.into_result()?;
        // Logged in, but not with the session's key: the agent or a password
        // covered for a key the server refuses. Said out loud, because on a
        // device without that agent the same session fails (a phone has none).
        if let (Some(fingerprint), AuthBy::Agent | AuthBy::Password) = (refused, by) {
            let _ = app_handle.emit(
                "ssh-key-refused-notice",
                serde_json::json!({ "host": host, "fingerprint": fingerprint, "via": if by == AuthBy::Agent { "agent" } else { "password" } }),
            );
        }
        Ok(handle)
    }

    /// Connect to a target host through one or more jump hosts (ProxyJump).
    /// `jump_chain` is ordered outermost-first: connect to first hop, then tunnel through.
    /// Connect to a target host through a SOCKS5/SOCKS4/HTTP proxy.
    async fn connect_via_proxy(
        proxy: &ProxyConfig,
        target_host: &str,
        target_port: u16,
    ) -> Result<tokio::net::TcpStream, SshError> {
        let proxy_addr = format!("{}:{}", proxy.host, proxy.port);
        let target_addr = (target_host, target_port);

        match proxy.proxy_type.to_lowercase().as_str() {
            "socks5" => {
                let stream = if let (Some(user), Some(pass)) = (&proxy.username, &proxy.password) {
                    tokio_socks::tcp::Socks5Stream::connect_with_password(
                        proxy_addr.as_str(),
                        target_addr,
                        user.as_str(),
                        pass.as_str(),
                    )
                    .await
                    .map_err(|e| SshError::ConnectionFailed(format!("SOCKS5 proxy error: {}", e)))?
                } else {
                    tokio_socks::tcp::Socks5Stream::connect(
                        proxy_addr.as_str(),
                        target_addr,
                    )
                    .await
                    .map_err(|e| SshError::ConnectionFailed(format!("SOCKS5 proxy error: {}", e)))?
                };
                Ok(stream.into_inner())
            }
            "socks4" => {
                let stream = tokio_socks::tcp::Socks4Stream::connect(
                    proxy_addr.as_str(),
                    target_addr,
                )
                .await
                .map_err(|e| SshError::ConnectionFailed(format!("SOCKS4 proxy error: {}", e)))?;
                Ok(stream.into_inner())
            }
            "http" => {
                // HTTP CONNECT proxy
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut stream = tokio::net::TcpStream::connect(&proxy_addr)
                    .await
                    .map_err(|e| SshError::ConnectionFailed(format!("HTTP proxy connect error: {}", e)))?;

                let connect_req = if let (Some(user), Some(pass)) = (&proxy.username, &proxy.password) {
                    let creds = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, format!("{}:{}", user, pass));
                    format!(
                        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\nProxy-Authorization: Basic {}\r\n\r\n",
                        target_host, target_port, target_host, target_port, creds
                    )
                } else {
                    format!(
                        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
                        target_host, target_port, target_host, target_port
                    )
                };

                stream.write_all(connect_req.as_bytes()).await
                    .map_err(|e| SshError::ConnectionFailed(format!("HTTP proxy write error: {}", e)))?;

                let mut buf = [0u8; 1024];
                let n = stream.read(&mut buf).await
                    .map_err(|e| SshError::ConnectionFailed(format!("HTTP proxy read error: {}", e)))?;
                let response = String::from_utf8_lossy(&buf[..n]);

                if !response.contains("200") {
                    return Err(SshError::ConnectionFailed(format!("HTTP proxy rejected: {}", response.lines().next().unwrap_or(""))));
                }

                Ok(stream)
            }
            _ => Err(SshError::ConnectionFailed(format!("Unsupported proxy type: {}", proxy.proxy_type))),
        }
    }

    /// Establish an SSH connection through one or more jump hosts. Like
    /// [`connect`], takes no `self` and returns the finished `ActiveConnection`
    /// for the caller to `register` under a brief lock.
    #[expect(clippy::too_many_arguments, reason = "the connection settings ssh_connect receives, passed through as they are")]
    pub(crate) async fn connect_via_jump(
        id: &str,
        target_host: &str,
        target_port: u16,
        target_username: &str,
        target_auth: AuthParams,
        jump_chain: Vec<JumpHostParams>,
        cols: u16,
        rows: u16,
        app_handle: tauri::AppHandle,
        shell: Option<String>,
        login: LoginOptions,
    ) -> Result<ActiveConnection, SshError> {
        tracing::info!(
            "SSH connecting to {}@{}:{} via {} jump host(s)",
            target_username, target_host, target_port, jump_chain.len()
        );

        let timeout_duration = std::time::Duration::from_secs(30);
        let connect_future = Self::handshake_via_jump(
            target_host,
            target_port,
            target_username,
            &target_auth,
            &jump_chain,
            app_handle.clone(),
        );

        let (target_handle, jump_handles) =
            tokio::time::timeout(timeout_duration, connect_future)
                .await
                .map_err(|_| SshError::ConnectionFailed("Connection via jump timed out".into()))??;

        tracing::info!(
            "SSH authenticated for {}@{}:{} (via jump)",
            target_username, target_host, target_port
        );

        // Open session, request PTY and the (optionally overridden) shell on target
        let channel = target_handle
            .channel_open_session()
            .await
            .map_err(|e| SshError::ChannelError(format!("Failed to open session: {}", e)))?;

        open_interactive_shell(&channel, cols, rows, shell.as_deref()).await?;

        tracing::info!(
            "SSH shell opened for {}@{}:{} (via jump)",
            target_username, target_host, target_port
        );

        let info = ConnectionInfo {
            id: id.to_string(),
            host: target_host.to_string(),
            port: target_port,
            username: target_username.to_string(),
        };

        into_active_connection(channel, target_handle, info, shell.as_deref(), login, app_handle, jump_handles).await
    }

    /// Connect and authenticate on the target through each jump host in turn.
    /// Returns the target's handle and the hops, which must outlive it.
    async fn handshake_via_jump(
        target_host: &str,
        target_port: u16,
        target_username: &str,
        target_auth: &AuthParams,
        jump_chain: &[JumpHostParams],
        app_handle: tauri::AppHandle,
    ) -> Result<(russh::client::Handle<SshClientHandler>, Vec<SharedHandle>), SshError> {
        let mut jump_handles: Vec<SharedHandle> = Vec::new();

        // Step 1: Connect to the first jump host directly
        let first_jump = &jump_chain[0];
        let config = Arc::new(russh::client::Config::default());
        let handler = SshClientHandler::new(first_jump.host.as_str(), first_jump.port, Some(app_handle.clone()));

        let mut current_handle = russh::client::connect(
            config,
            (first_jump.host.as_str(), first_jump.port),
            handler,
        )
        .await
        .map_err(|e| {
            SshError::ConnectionFailed(format!(
                "Jump host {} connection failed: {}",
                first_jump.host, e
            ))
        })?;

        // Authenticate on first jump host
        Self::authenticate_handle(&mut current_handle, &first_jump.username, &first_jump.auth)
            .await?;

        tracing::info!("Authenticated on jump host {}", first_jump.host);

        // Step 2: Chain through remaining jump hosts or tunnel to target
        if jump_chain.len() > 1 {
            let shared = Arc::new(tokio::sync::Mutex::new(current_handle));
            jump_handles.push(shared.clone());

            let mut prev_shared = shared;

            for next_jump in jump_chain.iter().skip(1) {

                // Open direct-tcpip channel to next hop through current handle
                let channel = {
                    let guard = prev_shared.lock().await;
                    guard
                        .channel_open_direct_tcpip(
                            &next_jump.host,
                            next_jump.port as u32,
                            "127.0.0.1",
                            0,
                        )
                        .await
                        .map_err(|e| {
                            SshError::ConnectionFailed(format!(
                                "Failed to open tunnel to {}: {}",
                                next_jump.host, e
                            ))
                        })?
                };

                let stream = channel.into_stream();
                let config = Arc::new(russh::client::Config::default());
                let handler = SshClientHandler::new(next_jump.host.as_str(), next_jump.port, Some(app_handle.clone()));

                let mut next_handle =
                    russh::client::connect_stream(config, stream, handler)
                        .await
                        .map_err(|e| {
                            SshError::ConnectionFailed(format!(
                                "SSH over tunnel to {} failed: {}",
                                next_jump.host, e
                            ))
                        })?;

                Self::authenticate_handle(
                    &mut next_handle,
                    &next_jump.username,
                    &next_jump.auth,
                )
                .await?;

                tracing::info!("Authenticated on jump host {}", next_jump.host);

                let next_shared = Arc::new(tokio::sync::Mutex::new(next_handle));
                jump_handles.push(next_shared.clone());
                prev_shared = next_shared;
            }

            // Now open a tunnel from the last jump host to the target
            let channel = {
                let guard = prev_shared.lock().await;
                guard
                    .channel_open_direct_tcpip(
                        target_host,
                        target_port as u32,
                        "127.0.0.1",
                        0,
                    )
                    .await
                    .map_err(|e| {
                        SshError::ConnectionFailed(format!(
                            "Failed to open tunnel to target {}:{}: {}",
                            target_host, target_port, e
                        ))
                    })?
            };

            let stream = channel.into_stream();
            let config = Arc::new(russh::client::Config::default());
            let handler = SshClientHandler::new(target_host, target_port, Some(app_handle.clone()));

            let mut target_handle =
                russh::client::connect_stream(config, stream, handler)
                    .await
                    .map_err(|e| {
                        SshError::ConnectionFailed(format!(
                            "SSH to target {}:{} via jump failed: {}",
                            target_host, target_port, e
                        ))
                    })?;

            Self::authenticate_handle(
                &mut target_handle,
                target_username,
                target_auth,
            )
            .await?;

            Ok((target_handle, jump_handles))
        } else {
            // Single jump host: tunnel directly to target
            let shared = Arc::new(tokio::sync::Mutex::new(current_handle));
            jump_handles.push(shared.clone());

            let channel = {
                let guard = shared.lock().await;
                guard
                    .channel_open_direct_tcpip(
                        target_host,
                        target_port as u32,
                        "127.0.0.1",
                        0,
                    )
                    .await
                    .map_err(|e| {
                        SshError::ConnectionFailed(format!(
                            "Failed to open tunnel to target {}:{}: {}",
                            target_host, target_port, e
                        ))
                    })?
            };

            let stream = channel.into_stream();
            let config = Arc::new(russh::client::Config::default());
            let handler = SshClientHandler::new(target_host, target_port, Some(app_handle.clone()));

            let mut target_handle =
                russh::client::connect_stream(config, stream, handler)
                    .await
                    .map_err(|e| {
                        SshError::ConnectionFailed(format!(
                            "SSH to target {}:{} via jump failed: {}",
                            target_host, target_port, e
                        ))
                    })?;

            Self::authenticate_handle(
                &mut target_handle,
                target_username,
                target_auth,
            )
            .await?;

            Ok((target_handle, jump_handles))
        }
    }

    /// An authenticated connection with no shell, for callers that only need
    /// channels — a database reached through a saved session, for one. Uses
    /// the same handshake, host-key check and jump chain as the terminal.
    pub(crate) async fn open_headless(
        host: &str,
        port: u16,
        username: &str,
        auth: AuthParams,
        jump_chain: Vec<JumpHostParams>,
        proxy: Option<ProxyConfig>,
        app_handle: tauri::AppHandle,
    ) -> Result<HeadlessConnection, SshError> {
        let timeout = std::time::Duration::from_secs(if jump_chain.is_empty() { 15 } else { 30 });
        let connect = async {
            if jump_chain.is_empty() {
                let handle = Self::handshake_direct(host, port, username, &auth, proxy.as_ref(), app_handle).await?;
                Ok::<_, SshError>((handle, Vec::new()))
            } else {
                Self::handshake_via_jump(host, port, username, &auth, &jump_chain, app_handle).await
            }
        };
        let (handle, jump_handles) = tokio::time::timeout(timeout, connect)
            .await
            .map_err(|_| SshError::ConnectionFailed("Connection timed out".into()))??;
        Ok(HeadlessConnection { handle: Arc::new(tokio::sync::Mutex::new(handle)), jump_handles })
    }

    /// Authenticate on a russh handle by cascading through the configured
    /// methods. Used by jump hosts; the direct connect path uses the same
    /// `cascade_authenticate` free function.
    async fn authenticate_handle(
        handle: &mut russh::client::Handle<SshClientHandler>,
        username: &str,
        auth: &AuthParams,
    ) -> Result<(), SshError> {
        cascade_authenticate(handle, username, auth).await?.into_result().map(|_| ())
    }

    pub fn send_data(&self, id: &str, data: &[u8]) -> Result<(), SshError> {
        let conn = self.connections.get(id)
            .ok_or_else(|| SshError::NotFound(id.to_string()))?;
        conn.cmd_tx.send(SessionCommand::Data(data.to_vec()))
            .map_err(|e| SshError::SendError(format!("{}", e)))
    }

    /// Signal that the frontend has attached its listener: flush buffered output
    /// and stream live. Idempotent — extra calls after the first are no-ops.
    pub fn mark_ready(&self, id: &str) -> Result<(), SshError> {
        let conn = self.connections.get(id)
            .ok_or_else(|| SshError::NotFound(id.to_string()))?;
        conn.cmd_tx.send(SessionCommand::Ready)
            .map_err(|e| SshError::SendError(format!("{}", e)))
    }

    pub fn resize(&self, id: &str, cols: u16, rows: u16) -> Result<(), SshError> {
        let conn = self.connections.get(id)
            .ok_or_else(|| SshError::NotFound(id.to_string()))?;
        conn.cmd_tx.send(SessionCommand::Resize { cols: cols as u32, rows: rows as u32 })
            .map_err(|e| SshError::SendError(format!("{}", e)))
    }

    pub fn disconnect(&mut self, id: &str) -> Result<(), SshError> {
        let conn = self.connections.remove(id)
            .ok_or_else(|| SshError::NotFound(id.to_string()))?;
        let _ = conn.cmd_tx.send(SessionCommand::Close);
        tracing::info!("SSH disconnected: {}", id);
        Ok(())
    }

    pub fn list_connections(&self) -> Vec<ConnectionInfo> {
        self.connections.values().map(|c| c.info.clone()).collect()
    }

    pub fn is_connected(&self, id: &str) -> bool {
        self.connections.contains_key(id)
    }

    pub fn get_handle(&self, id: &str) -> Result<SharedHandle, SshError> {
        self.connections.get(id)
            .map(|c| c.handle.clone())
            .ok_or_else(|| SshError::NotFound(id.to_string()))
    }
}

impl Default for SshManager {
    fn default() -> Self { Self::new() }
}

/// Run a command with bytes on its stdin — a tarball, a secret — and wait
/// for it. Returns the exit code and the combined stdout.
pub async fn exec_with_stdin(
    handle: &SharedHandle,
    command: &str,
    input: Vec<u8>,
) -> Result<(i32, String), SshError> {
    let mut channel = {
        let guard = handle.lock().await;
        guard.channel_open_session().await
            .map_err(|e| SshError::ChannelError(format!("{}", e)))?
    };
    channel.exec(true, command).await
        .map_err(|e| SshError::ChannelError(format!("{}", e)))?;
    channel.data(&input[..]).await
        .map_err(|e| SshError::ChannelError(format!("{}", e)))?;
    channel.eof().await
        .map_err(|e| SshError::ChannelError(format!("{}", e)))?;
    let mut output = String::new();
    let mut decoder = crate::text::Utf8Stream::new();
    let mut exit_code: i32 = -1;
    let mut got_eof = false;
    let mut got_exit = false;
    loop {
        let msg = tokio::time::timeout(
            std::time::Duration::from_secs(120),
            channel.wait(),
        ).await;
        match msg {
            Ok(Some(ChannelMsg::Data { ref data })) => output.push_str(&decoder.push(data)),
            Ok(Some(ChannelMsg::ExtendedData { ref data, .. })) => output.push_str(&decoder.push(data)),
            Ok(Some(ChannelMsg::Eof)) => {
                got_eof = true;
                if got_exit { break; }
            }
            Ok(Some(ChannelMsg::ExitStatus { exit_status })) => {
                exit_code = exit_status as i32;
                got_exit = true;
                if got_eof { break; }
            }
            Ok(None) | Err(_) => break,
            _ => {}
        }
    }
    Ok((exit_code, output))
}

pub async fn exec_on_connection(
    handle: &SharedHandle,
    command: &str,
) -> Result<String, SshError> {
    let mut channel = {
        let guard = handle.lock().await;
        guard.channel_open_session().await
            .map_err(|e| SshError::ChannelError(format!("{}", e)))?
    };
    channel.exec(true, command).await
        .map_err(|e| SshError::ChannelError(format!("{}", e)))?;
    let mut output = String::new();
    let mut decoder = crate::text::Utf8Stream::new();
    let mut got_eof = false;
    let mut got_exit = false;
    loop {
        // Timeout to avoid hanging forever
        let msg = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            channel.wait(),
        ).await;

        match msg {
            Ok(Some(ChannelMsg::Data { ref data })) => {
                output.push_str(&decoder.push(data));
            }
            Ok(Some(ChannelMsg::ExtendedData { .. })) => {
                // stderr — skip
            }
            Ok(Some(ChannelMsg::Eof)) => {
                got_eof = true;
                if got_exit { break; }
            }
            Ok(Some(ChannelMsg::ExitStatus { .. })) => {
                got_exit = true;
                if got_eof { break; }
            }
            Ok(None) | Err(_) => break, // channel closed or timeout
            _ => {
                // WindowAdjusted, etc.
            }
        }
    }
    Ok(output)
}

/// Execute a command on an existing SSH connection and return (stdout, stderr, exit_code).
/// Unlike `exec_on_connection`, this captures stderr separately and returns the exit code.
pub async fn exec_on_connection_with_exit_code(
    handle: &SharedHandle,
    command: &str,
) -> Result<(String, String, i32), SshError> {
    let mut channel = {
        let guard = handle.lock().await;
        guard.channel_open_session().await
            .map_err(|e| SshError::ChannelError(format!("{}", e)))?
    };
    channel.exec(true, command).await
        .map_err(|e| SshError::ChannelError(format!("{}", e)))?;

    let mut stdout = String::new();
    let mut stderr = String::new();
    let mut exit_code: i32 = -1;
    let mut out_decoder = crate::text::Utf8Stream::new();
    let mut err_decoder = crate::text::Utf8Stream::new();
    let mut got_eof = false;
    let mut got_exit = false;

    loop {
        let msg = tokio::time::timeout(
            std::time::Duration::from_secs(300),
            channel.wait(),
        ).await;

        match msg {
            Ok(Some(ChannelMsg::Data { ref data })) => {
                stdout.push_str(&out_decoder.push(data));
            }
            Ok(Some(ChannelMsg::ExtendedData { ref data, .. })) => {
                stderr.push_str(&err_decoder.push(data));
            }
            Ok(Some(ChannelMsg::Eof)) => {
                got_eof = true;
                if got_exit { break; }
            }
            Ok(Some(ChannelMsg::ExitStatus { exit_status })) => {
                exit_code = exit_status as i32;
                got_exit = true;
                if got_eof { break; }
            }
            Ok(None) | Err(_) => break,
            _ => {}
        }
    }

    Ok((stdout, stderr, exit_code))
}

/// Generic streaming output event used by all remote streaming commands.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StreamingOutputEvent {
    pub run_id: String,
    pub stream: String,
    pub data: String,
}

/// Streaming variant of `exec_on_connection`.
/// Emits each chunk as a `{event_prefix}-{run_id}` Tauri event.
/// Returns the exit code (defaults to -1 if not received).
pub async fn exec_on_connection_streaming(
    handle: &SharedHandle,
    command: &str,
    run_id: &str,
    event_prefix: &str,
    app_handle: &tauri::AppHandle,
) -> Result<i32, SshError> {
    exec_streaming_inner(handle, command, run_id, event_prefix, app_handle, false).await
}

/// Same, but with a pseudo-terminal attached.
///
/// A program writing to a pipe switches its C library to block buffering and
/// holds several kilobytes back, so output that is being counted for progress
/// arrives all at once at the end and the bar never moves. Writing to a
/// terminal makes it line-buffer instead, which is what we want, and unlike
/// `stdbuf` it needs nothing installed on the far end.
///
/// The cost is that stderr is folded into stdout and lines end with CRLF, so
/// anything parsing this has to tolerate both.
pub async fn exec_on_connection_streaming_pty(
    handle: &SharedHandle,
    command: &str,
    run_id: &str,
    event_prefix: &str,
    app_handle: &tauri::AppHandle,
) -> Result<i32, SshError> {
    exec_streaming_inner(handle, command, run_id, event_prefix, app_handle, true).await
}

async fn exec_streaming_inner(
    handle: &SharedHandle,
    command: &str,
    run_id: &str,
    event_prefix: &str,
    app_handle: &tauri::AppHandle,
    want_pty: bool,
) -> Result<i32, SshError> {
    let mut channel = {
        let guard = handle.lock().await;
        guard.channel_open_session().await
            .map_err(|e| SshError::ChannelError(format!("{}", e)))?
    };
    if want_pty {
        // "dumb" so nothing decides to emit colour or cursor movement into
        // output we are counting lines in.
        channel
            .request_pty(false, "dumb", 200, 50, 0, 0, &[])
            .await
            .map_err(|e| SshError::ChannelError(format!("{}", e)))?;
    }
    channel.exec(true, command).await
        .map_err(|e| SshError::ChannelError(format!("{}", e)))?;

    let output_event = format!("{}-{}", event_prefix, run_id);
    let mut exit_code: i32 = -1;
    let mut got_eof = false;
    let mut got_exit = false;
    let mut out_decoder = crate::text::Utf8Stream::new();
    let mut err_decoder = crate::text::Utf8Stream::new();

    loop {
        let msg = tokio::time::timeout(
            std::time::Duration::from_secs(300),
            channel.wait(),
        ).await;

        match msg {
            Ok(Some(ChannelMsg::Data { ref data })) => {
                let text = out_decoder.push(data);
                if text.is_empty() {
                    continue;
                }
                let _ = app_handle.emit(
                    &output_event,
                    StreamingOutputEvent {
                        run_id: run_id.to_string(),
                        stream: "stdout".to_string(),
                        data: text,
                    },
                );
            }
            Ok(Some(ChannelMsg::ExtendedData { ref data, .. })) => {
                let text = err_decoder.push(data);
                if text.is_empty() {
                    continue;
                }
                let _ = app_handle.emit(
                    &output_event,
                    StreamingOutputEvent {
                        run_id: run_id.to_string(),
                        stream: "stderr".to_string(),
                        data: text,
                    },
                );
            }
            Ok(Some(ChannelMsg::Eof)) => {
                got_eof = true;
                if got_exit { break; }
            }
            Ok(Some(ChannelMsg::ExitStatus { exit_status })) => {
                exit_code = exit_status as i32;
                got_exit = true;
                if got_eof { break; }
            }
            Ok(None) | Err(_) => break,
            _ => {}
        }
    }

    Ok(exit_code)
}

/// Pending host-key prompts awaiting a user decision, keyed by a per-prompt id.
/// The SSH handshake parks on the oneshot here while the frontend shows the
/// verification dialog; `resolve_hostkey_prompt` (via the `ssh_hostkey_response`
/// IPC command) wakes it. Safe to add now that connect runs lock-free, so a
/// parked handshake no longer blocks other SSH operations.
static HOSTKEY_PROMPTS: std::sync::OnceLock<
    std::sync::Mutex<HashMap<String, tokio::sync::oneshot::Sender<bool>>>,
> = std::sync::OnceLock::new();

fn hostkey_prompts(
) -> &'static std::sync::Mutex<HashMap<String, tokio::sync::oneshot::Sender<bool>>> {
    HOSTKEY_PROMPTS.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

/// Resolve a pending host-key prompt with the user's accept/reject decision.
pub(crate) fn resolve_hostkey_prompt(prompt_id: &str, accept: bool) {
    let sender = hostkey_prompts().lock().unwrap().remove(prompt_id);
    if let Some(tx) = sender {
        let _ = tx.send(accept);
    }
}

/// Emitted to the frontend when a host key needs user verification.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct HostKeyPrompt {
    prompt_id: String,
    host: String,
    port: u16,
    fingerprint: String,
    key_type: String,
    /// true = the stored key for this host CHANGED (possible MITM); false = a
    /// brand-new (unknown) host being trusted on first use (TOFU).
    changed: bool,
    old_fingerprint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SshClientHandler {
    host: String,
    port: u16,
    app_handle: Option<tauri::AppHandle>,
}

impl SshClientHandler {
    pub fn new(host: impl Into<String>, port: u16, app_handle: Option<tauri::AppHandle>) -> Self {
        Self { host: host.into(), port, app_handle }
    }

    fn known_hosts_path() -> std::path::PathBuf {
        // Use the Tauri-resolved writable app data dir (not `dirs::data_dir()`)
        // so this works inside the Android/iOS sandbox too.
        crate::app_data_dir().join("ssh").join("known_hosts.json")
    }

    /// Ask the user to verify a host key. Emits `ssh-hostkey-prompt` and parks
    /// on a oneshot until `ssh_hostkey_response` resolves it, or a 120s timeout.
    /// Fails closed: rejects on a missing UI handle, emit error, or timeout.
    async fn prompt_hostkey(
        &self,
        fingerprint: &str,
        key_type: &str,
        changed: bool,
        old_fingerprint: Option<String>,
    ) -> bool {
        let Some(app) = self.app_handle.clone() else {
            tracing::warn!(
                "No UI handle to verify host key for {}:{}; rejecting",
                self.host,
                self.port
            );
            return false;
        };

        let prompt_id = uuid::Uuid::new_v4().to_string();
        let (tx, rx) = tokio::sync::oneshot::channel();
        hostkey_prompts().lock().unwrap().insert(prompt_id.clone(), tx);

        let payload = HostKeyPrompt {
            prompt_id: prompt_id.clone(),
            host: self.host.clone(),
            port: self.port,
            fingerprint: fingerprint.to_string(),
            key_type: key_type.to_string(),
            changed,
            old_fingerprint,
        };
        if app.emit("ssh-hostkey-prompt", &payload).is_err() {
            hostkey_prompts().lock().unwrap().remove(&prompt_id);
            return false;
        }

        match tokio::time::timeout(std::time::Duration::from_secs(120), rx).await {
            Ok(Ok(accept)) => accept,
            _ => {
                hostkey_prompts().lock().unwrap().remove(&prompt_id);
                false
            }
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct KnownHosts {
    entries: HashMap<String, String>,
}

impl russh::client::Handler for SshClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let host_id = format!("{}:{}", self.host, self.port);
        let key = server_public_key.public_key();
        let fingerprint = host_key_fingerprint(&key);
        let key_type = key.algorithm().to_string();

        Ok(verify_host_identity(self.app_handle.clone(), &self.host, self.port, &host_id, &fingerprint, &key_type).await)
    }
}

/// SHA-256 of the key, base64 without padding and without the `SHA256:`
/// prefix: the form russh-keys produced, which every fingerprint already
/// saved in known_hosts.json is in.
fn host_key_fingerprint(key: &russh::keys::PublicKey) -> String {
    let fingerprint = key.fingerprint(russh::keys::HashAlg::Sha256).to_string();
    fingerprint.strip_prefix("SHA256:").map(str::to_owned).unwrap_or(fingerprint)
}

/// Trust on first use, shared by SSH and RDP. The identity is remembered
/// under `host_id` in known_hosts.json; a new one is put to the user through
/// the host-key dialog, and a changed one is put to them loudly. Returns
/// whether to proceed.
pub(crate) async fn verify_host_identity(
    app_handle: Option<tauri::AppHandle>,
    host: &str,
    port: u16,
    host_id: &str,
    fingerprint: &str,
    key_type: &str,
) -> bool {
    let path = SshClientHandler::known_hosts_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let mut known: KnownHosts = match std::fs::read_to_string(&path) {
        Ok(raw) => serde_json::from_str(&raw).unwrap_or_default(),
        Err(_) => KnownHosts::default(),
    };

    if known.entries.get(host_id).map(String::as_str) == Some(fingerprint) {
        return true;
    }

    let (changed, old_fingerprint) = match known.entries.get(host_id) {
        Some(existing) => {
            tracing::warn!(
                "Host identity CHANGED for {} (possible MITM). Old: {}, New: {}",
                host_id, existing, fingerprint
            );
            (true, Some(existing.clone()))
        }
        None => {
            tracing::info!("Host identity unknown for {} — prompting (TOFU)", host_id);
            (false, None)
        }
    };

    let handler = SshClientHandler::new(host, port, app_handle);
    let accepted = handler
        .prompt_hostkey(fingerprint, key_type, changed, old_fingerprint)
        .await;

    if accepted {
        known.entries.insert(host_id.to_string(), fingerprint.to_string());
        if let Ok(raw) = serde_json::to_string_pretty(&known) {
            let _ = std::fs::write(&path, raw);
        }
        tracing::info!("Host identity accepted by user for {}", host_id);
    } else {
        tracing::warn!("Host identity rejected for {} — aborting connect", host_id);
    }
    accepted
}

/// Finish a connection once the channel is open: inject shell color/prompt init
/// (when enabled for the shell), spawn the streaming session task, and build the
/// `ActiveConnection`. Shared by both the direct and jump-host connect paths.
async fn into_active_connection(
    channel: russh::Channel<russh::client::Msg>,
    handle: russh::client::Handle<SshClientHandler>,
    info: ConnectionInfo,
    shell: Option<&str>,
    login: LoginOptions,
    app_handle: tauri::AppHandle,
    jump_handles: Vec<SharedHandle>,
) -> Result<ActiveConnection, SshError> {
    // Inject shell-appropriate color/prompt init (chosen per shell family so a
    // fish login never gets bash syntax), unless the user disabled it. `None`
    // shell-family => nothing injected. Keeping the login message means
    // typing it later, once the server is quiet; otherwise it goes now.
    let init = if login.inject_colors { shell_init(shell) } else { None };
    let flow = match init {
        Some(init) if login.show_login_message => Some(LoginFlow::new(init, std::time::Instant::now())),
        Some(init) => {
            channel
                .data(init.as_bytes())
                .await
                .map_err(|e| SshError::ChannelError(format!("Color init failed: {}", e)))?;
            None
        }
        None => None,
    };

    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let task_id = info.id.clone();
    let task_handle = app_handle.clone();
    tokio::spawn(async move {
        ssh_session_task(channel, cmd_rx, task_id, task_handle, flow).await;
    });

    Ok(ActiveConnection {
        cmd_tx,
        info,
        handle: Arc::new(tokio::sync::Mutex::new(handle)),
        jump_handles,
    })
}

async fn ssh_session_task(
    mut channel: russh::Channel<russh::client::Msg>,
    mut cmd_rx: mpsc::UnboundedReceiver<SessionCommand>,
    connection_id: String,
    app_handle: tauri::AppHandle,
    mut flow: Option<LoginFlow>,
) {
    let data_event = format!("ssh-data-{}", connection_id);
    // Drives the login flow while it runs: types the init once the server
    // is quiet, and lets go of output if the init's marker never comes.
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(50));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let exit_event = format!("ssh-exit-{}", connection_id);

    // Remote output arrives in arbitrary packet-sized chunks, so a
    // multi-byte character can straddle two of them. Decode as a stream,
    // not per chunk. stdout and stderr are independent streams and each
    // needs its own carry-over.
    let mut out_decoder = crate::text::Utf8Stream::new();
    let mut err_decoder = crate::text::Utf8Stream::new();

    // Hold remote output until the frontend signals it's listening
    // (SessionCommand::Ready) so the motd/banner emitted before the terminal
    // mounts isn't dropped. A safety cap flushes anyway if Ready never arrives.
    const BACKLOG_CAP: usize = 2 * 1024 * 1024;
    let mut ready = false;
    let mut backlog: Vec<String> = Vec::new();
    let mut backlog_bytes = 0usize;

    // Tap for the MCP server. Output is mirrored into the shared-session
    // buffer *before* the ready/backlog logic, because an AI client attaches
    // independently of the terminal UI: a session can be shared while its tab
    // has never been opened, and waiting for Ready would leave the model
    // reading an empty screen. A no-op unless the user shared this session.
    let mcp_state = app_handle.try_state::<crate::state::AppState>().map(|s| s.mcp.clone());
    let mcp_id = connection_id.clone();
    macro_rules! mirror_to_mcp {
        ($text:expr) => {{
            if let Some(mcp) = mcp_state.clone() {
                let id = mcp_id.clone();
                let bytes = $text.as_bytes().to_vec();
                // Spawned so a slow reader can never stall the SSH loop.
                tokio::spawn(async move { mcp.push_output(&id, &bytes).await; });
            }
        }};
    }

    // Emit live once ready, otherwise buffer. `break`s the loop on emit failure.
    macro_rules! deliver {
        ($payload:expr) => {{
            let payload = $payload;
            mirror_to_mcp!(payload);
            if ready {
                if let Err(e) = app_handle.emit(&data_event, &payload) {
                    tracing::error!("Failed to emit '{}': {}", data_event, e);
                    break;
                }
            } else {
                backlog_bytes += payload.len();
                backlog.push(payload);
                if backlog_bytes >= BACKLOG_CAP {
                    ready = true;
                    for p in backlog.drain(..) {
                        let _ = app_handle.emit(&data_event, &p);
                    }
                }
            }
        }};
    }

    loop {
        tokio::select! {
            msg = channel.wait() => {
                match msg {
                    Some(ChannelMsg::Data { ref data }) => {
                        let mut text = out_decoder.push(data);
                        if let Some(f) = flow.as_mut() {
                            text = f.output(&text, std::time::Instant::now());
                        }
                        if !text.is_empty() {
                            deliver!(text);
                        }
                    }
                    Some(ChannelMsg::ExtendedData { ref data, .. }) => {
                        let text = err_decoder.push(data);
                        if !text.is_empty() {
                            deliver!(text);
                        }
                    }
                    Some(ChannelMsg::ExitStatus { exit_status }) => {
                        tracing::info!("SSH '{}' exited with status {}", connection_id, exit_status);
                        let _ = app_handle.emit(&exit_event, exit_status);
                        break;
                    }
                    Some(ChannelMsg::Eof) => {
                        tracing::info!("SSH '{}' received EOF", connection_id);
                        break;
                    }
                    None => {
                        tracing::info!("SSH '{}' channel closed", connection_id);
                        break;
                    }
                    _ => {}
                }
            }
            _ = tick.tick(), if flow.as_ref().is_some_and(|f| !f.done()) => {
                let (init, held) = flow.as_mut().map(|f| f.tick(std::time::Instant::now())).unwrap_or_default();
                if let Some(init) = init {
                    if let Err(e) = channel.data(init.as_bytes()).await {
                        tracing::error!("SSH '{}' color init failed: {}", connection_id, e);
                    }
                }
                if let Some(held) = held {
                    deliver!(held);
                }
            }
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(SessionCommand::Data(data)) => {
                        if let Err(e) = channel.data(&data[..]).await {
                            tracing::error!("SSH '{}' write error: {}", connection_id, e);
                            break;
                        }
                    }
                    Some(SessionCommand::Resize { cols, rows }) => {
                        if let Err(e) = channel.window_change(cols, rows, 0, 0).await {
                            tracing::error!("SSH '{}' resize error: {}", connection_id, e);
                        }
                    }
                    Some(SessionCommand::Ready) => {
                        if !ready {
                            ready = true;
                            for p in backlog.drain(..) {
                                let _ = app_handle.emit(&data_event, &p);
                            }
                        }
                    }
                    Some(SessionCommand::Close) | None => {
                        tracing::info!("SSH '{}' closing", connection_id);
                        let _ = channel.close().await;
                        break;
                    }
                }
            }
        }
    }

    // The stream ended; surface any bytes held back mid-character rather
    // than swallowing them.
    for tail in [out_decoder.flush(), err_decoder.flush()].into_iter().flatten() {
        let _ = app_handle.emit(&data_event, &tail);
    }

    if let Err(e) = app_handle.emit(&exit_event, ()) {
        tracing::error!("Failed to emit '{}': {}", exit_event, e);
    }
    tracing::info!("SSH '{}' session task exiting", connection_id);
}

#[cfg(test)]
mod shell_tests {
    use super::*;

    #[test]
    fn family_defaults_to_posix_when_unset() {
        assert!(matches!(shell_family(None), ShellFamily::Posix));
        assert!(matches!(shell_family(Some("   ")), ShellFamily::Posix));
    }

    #[test]
    fn family_detects_fish_by_basename_and_flags() {
        assert!(matches!(shell_family(Some("fish")), ShellFamily::Fish));
        assert!(matches!(shell_family(Some("/usr/bin/fish")), ShellFamily::Fish));
        assert!(matches!(shell_family(Some("fish -l")), ShellFamily::Fish));
    }

    #[test]
    fn family_detects_posix_shells() {
        for s in ["bash", "/bin/bash", "zsh", "sh", "dash", "/usr/bin/zsh -l"] {
            assert!(matches!(shell_family(Some(s)), ShellFamily::Posix), "{s}");
        }
    }

    #[test]
    fn family_unknown_shell_is_other() {
        assert!(matches!(shell_family(Some("nu")), ShellFamily::Other));
        assert!(matches!(shell_family(Some("xonsh")), ShellFamily::Other));
    }

    #[test]
    fn init_is_posix_blob_when_unset_or_posix() {
        assert_eq!(shell_init(None).as_deref(), Some(POSIX_COLOR_INIT));
        assert_eq!(shell_init(Some("bash")).as_deref(), Some(POSIX_COLOR_INIT));
    }

    /// Writes the init exactly as it is sent, so it can be run through real
    /// shells on a real PTY instead of being reasoned about. Ignored by
    /// default; this is how the BusyBox/dash/ksh93/mksh/posh/zsh behaviour
    /// recorded in the comments above was measured, and how to re-measure it:
    ///
    ///     REACH_INIT_DUMP=/tmp/init.sh cargo test --lib dump_posix_init \
    ///         -- --ignored --exact
    #[test]
    #[ignore = "dumps the init for out-of-process shell testing"]
    fn dump_posix_init() {
        let p = std::env::var("REACH_INIT_DUMP").expect("set REACH_INIT_DUMP to an output path");
        std::fs::write(p, POSIX_COLOR_INIT).unwrap();
    }

    /// 🔴 The OpenWrt hang. BusyBox drops everything past its input buffer
    /// without a word, so one long line arrives cut in half and the shell waits
    /// forever for a quote to close. No line may approach that limit.
    #[test]
    fn posix_init_lines_are_short() {
        for (n, line) in POSIX_COLOR_INIT.lines().enumerate() {
            assert!(
                line.len() <= MAX_INIT_LINE_BYTES,
                "init line {} is {} bytes, over the {}-byte ceiling, and would be \
                 truncated on a device with a small input buffer: {:?}",
                n + 1,
                line.len(),
                MAX_INIT_LINE_BYTES,
                line
            );
        }
    }

    /// Every line has to stand on its own. A line left quote-open, or ending in
    /// `&&`, leaves the shell at its `>` continuation prompt: the exact state
    /// the truncation used to produce, just reached a different way.
    #[test]
    fn posix_init_lines_are_self_contained() {
        for (n, line) in POSIX_COLOR_INIT.lines().enumerate() {
            assert_eq!(
                line.matches('"').count() % 2,
                0,
                "init line {} leaves a double quote open: {:?}",
                n + 1,
                line
            );
            let t = line.trim_end();
            assert!(
                !(t.ends_with("&&") || t.ends_with("||") || t.ends_with('|') || t.ends_with('\\')),
                "init line {} ends mid-construct: {:?}",
                n + 1,
                line
            );
        }
    }

    /// 🔴 `stty` in the init drops the init. It applies termios with a flush,
    /// which throws away whatever is still queued unread behind it — measured
    /// on ksh93, the same 8 of 20 following lines vanished on every run, with
    /// no error anywhere. Nothing about hiding the init is worth that, and the
    /// blanked prompt plus the final clear already hide it.
    #[test]
    fn posix_init_never_calls_stty() {
        assert!(
            !POSIX_COLOR_INIT.contains("stty"),
            "stty is back in the init; it silently discards the queued lines behind it"
        );
    }

    /// The prompt is blanked for the duration and put back at the end. Without
    /// the blanking the shell prints one prompt per line and they run together
    /// into a row of garbage; without the restore the user gets no prompt.
    #[test]
    fn posix_init_blanks_then_restores_the_prompt() {
        let text = POSIX_COLOR_INIT;
        let blank = text.find("PS1=''").expect("the init must blank the prompt");
        let save = text.find("_op=$PS1").expect("the original prompt must be saved first");
        let restore = text.find("PS1=$_np").expect("the prompt must be restored");
        assert!(save < blank, "PS1 is blanked before the original is saved");
        assert!(blank < restore, "PS1 is restored before it is blanked");
        // Nothing between the restore and the end may print a prompt of its own.
        assert!(
            !text[restore..].contains("PS1=''"),
            "the prompt is blanked again after being restored"
        );
    }

    /// The last thing typed must be a screen clear. A shell with its own line
    /// editor echoes each line as it reads it, so anything typed after the
    /// clear lands on the screen the clear just cleaned (seen on mksh).
    #[test]
    fn posix_init_ends_with_a_clear() {
        let last = POSIX_COLOR_INIT.lines().last().expect("the init has lines");
        assert!(
            last.contains("[2J") || last.contains("clear"),
            "the init must end on a clear, ends on: {:?}",
            last
        );
    }

    /// A strict-POSIX shell with no `alias` builtin reports `alias: not found`
    /// from the SHELL, which a redirection on the command does not catch. Only
    /// a redirection on the surrounding group does. Seen on posh.
    #[test]
    fn posix_init_alias_errors_cannot_reach_the_screen() {
        for (n, line) in POSIX_COLOR_INIT.lines().enumerate() {
            if line.contains("alias ") {
                assert!(
                    line.trim_start().starts_with('{') && line.contains("} 2>/dev/null"),
                    "init line {} runs alias without a group redirection, so a shell \
                     without the builtin prints its error to the user: {:?}",
                    n + 1,
                    line
                );
            }
        }
    }

    /// The init must be lines, not one blob: a single-line init is how this
    /// broke, and a well-meant tidy-up could put it back.
    #[test]
    fn posix_init_is_many_lines() {
        assert!(
            POSIX_COLOR_INIT.lines().count() >= 10,
            "the init collapsed back onto too few lines"
        );
        assert!(POSIX_COLOR_INIT.ends_with('\n'), "the last line needs its newline to run");
    }

    /// The behaviour the init exists for must survive being split up.
    #[test]
    fn posix_init_still_does_its_job() {
        assert!(POSIX_COLOR_INIT.contains("COLORTERM=truecolor"));
        assert!(POSIX_COLOR_INIT.contains("dircolors"));
        assert!(POSIX_COLOR_INIT.contains("--color=auto"));
        assert!(POSIX_COLOR_INIT.contains("ls -G"), "BSD/macOS ls must still be handled");
        assert!(POSIX_COLOR_INIT.contains("PS1="));
        assert!(POSIX_COLOR_INIT.contains("clear"));
        // Temporaries must not be left behind in the user's shell. Every `_x`
        // the init assigns has to appear in the `unset`, so adding a new one
        // without cleaning it up fails here rather than leaking into the shell.
        let unset = POSIX_COLOR_INIT
            .lines()
            .find(|l| l.contains("unset "))
            .expect("the init must unset its temporaries");
        let cleaned: Vec<&str> = unset
            .split("unset ")
            .nth(1)
            .expect("unset has arguments")
            .split_whitespace()
            .collect();
        let mut assigned: Vec<String> = Vec::new();
        for line in POSIX_COLOR_INIT.lines() {
            for tok in line.split(|c: char| !(c.is_alphanumeric() || c == '_')) {
                if tok.starts_with('_') && tok.len() > 1 && line.contains(&format!("{}=", tok)) {
                    let t = tok.to_string();
                    if !assigned.contains(&t) {
                        assigned.push(t);
                    }
                }
            }
        }
        assert!(!assigned.is_empty(), "no temporaries found - parser broken?");
        for v in &assigned {
            assert!(
                cleaned.contains(&v.as_str()),
                "temporary {} is set by the init but never unset (unset line: {:?})",
                v,
                unset
            );
        }
    }

    #[test]
    fn the_login_message_is_drawn_again_after_the_init_clears() {
        let t0 = std::time::Instant::now();
        let ms = |n| t0 + std::time::Duration::from_millis(n);
        let mut flow = LoginFlow::new("init\n".into(), t0);

        // The login message and the first prompt pass through as they come.
        assert_eq!(flow.output("Welcome to Debian\r\nLast login: today\r\n", ms(10)), "Welcome to Debian\r\nLast login: today\r\n");
        assert_eq!(flow.output("user@host:~$ ", ms(20)), "user@host:~$ ");
        // Not quiet long enough yet: no init.
        assert_eq!(flow.tick(ms(100)).0, None);
        // Quiet: the init is typed.
        assert_eq!(flow.tick(ms(400)).0.as_deref(), Some("init\n"));

        // The init's echo, then its clear and marker split across two chunks.
        let first = flow.output("echo of the init\x1b[H\x1b[2J\x1b]7776;rea", ms(450));
        assert_eq!(first, "echo of the init\x1b[H\x1b[2J");
        let second = flow.output("ch-init\x07user@host:~$ ", ms(460));
        // The message comes back after the clear, without the first prompt;
        // the marker itself never reaches the screen.
        assert_eq!(second, "Welcome to Debian\r\nLast login: today\r\nuser@host:~$ ");
        assert!(flow.done());
        assert_eq!(flow.output("ls\r\n", ms(500)), "ls\r\n");
    }

    #[test]
    fn a_marker_that_never_comes_lets_the_output_go() {
        let t0 = std::time::Instant::now();
        let ms = |n| t0 + std::time::Duration::from_millis(n);
        let mut flow = LoginFlow::new("init\n".into(), t0);
        // A server that says nothing: the init is typed anyway, in time.
        assert_eq!(flow.tick(ms(3100)).0.as_deref(), Some("init\n"));
        assert_eq!(flow.output("prompt\x1b]77", ms(3200)), "prompt");
        let (init, held) = flow.tick(ms(9000));
        assert_eq!(init, None);
        assert_eq!(held.as_deref(), Some("\x1b]77"));
        assert!(flow.done());
    }

    #[test]
    fn the_init_prints_its_marker_last() {
        for shell in [None, Some("fish")] {
            let init = shell_init(shell).unwrap();
            let last = init.lines().last().unwrap();
            assert!(last.contains("7776;reach-init"), "{shell:?}: {last}");
        }
    }

    #[test]
    fn init_for_fish_avoids_bash_syntax() {
        // The whole point: fish must not receive `export`, `$(...)`, or `then/fi`.
        let init = shell_init(Some("fish")).expect("fish gets an init");
        assert!(init.contains("set -gx COLORTERM"));
        assert!(!init.contains("export "));
        assert!(!init.contains("$("));
        assert!(!init.contains("fi;"));
    }

    #[test]
    fn init_skipped_for_unknown_shell() {
        assert!(shell_init(Some("nu")).is_none());
    }
}

#[cfg(test)]
#[path = "client_live_tests.rs"]
mod live_tests;
