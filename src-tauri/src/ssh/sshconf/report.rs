//! What Reach does with each line of a host's ssh_config: shown on import
//! and on the session, so no line is dropped without a word.

use serde::Serialize;

use super::apply::{Plan, Use, Weakening};
use super::keyword::Kw;
use super::resolve::{At, Resolved, Status};

/// Whether Reach acts on a keyword yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Support {
    /// Used when connecting.
    Yes,
    /// Shapes how the file is read (Host, Match, Include, IgnoreUnknown…).
    Structure,
    /// Taken by the session's own fields (host, port, user, key, jump hosts).
    SessionField,
    /// Read and kept with the session, not acted on yet.
    NotYet,
}

/// Where each keyword stands. Every keyword is listed here, so a new one
/// cannot be forgotten.
pub fn support(kw: Kw) -> Support {
    use Kw::*;
    match kw {
        Host | Match | Include | IgnoreUnknown | Tag | CanonicalizeHostname | CanonicalDomains
        | CanonicalizeFallbackLocal | CanonicalizeMaxDots | CanonicalizePermittedCNAMEs => Support::Structure,
        Hostname | Port | User | ProxyJump => Support::SessionField,
        Ciphers | MACs | KexAlgorithms | HostKeyAlgorithms | Compression | ServerAliveInterval | ServerAliveCountMax
        | RekeyLimit | VersionAddendum | ConnectTimeout | ConnectionAttempts | AddressFamily | BindAddress
        | BindInterface | TCPKeepAlive | IPQoS => Support::Yes,
        // Logging in (ssh/userauth.rs).
        IdentityFile | IdentitiesOnly | IdentityAgent | CertificateFile | AddKeysToAgent | BatchMode
        | KbdInteractiveAuthentication | KbdInteractiveDevices | NumberOfPasswordPrompts | PasswordAuthentication
        | PreferredAuthentications | PubkeyAcceptedAlgorithms | PubkeyAuthentication | UseKeychain => Support::Yes,
        // Kerberos (ssh/gssapi.rs), with the Debian/Fedora patch's options.
        GSSAPIAuthentication | GSSAPIDelegateCredentials | GSSAPIClientIdentity | GSSAPIServerIdentity
        | GSSAPITrustDns => Support::Yes,
        // Host keys (ssh/hostkeys.rs).
        StrictHostKeyChecking | UserKnownHostsFile | GlobalKnownHostsFile | HostKeyAlias | CheckHostIP
        | HashKnownHosts | NoHostAuthenticationForLocalhost | RevokedHostKeys | KnownHostsCommand | VisualHostKey
        | FingerprintHash | RequiredRSASize | CASignatureAlgorithms | VerifyHostKeyDNS => Support::Yes,
        // The session (ssh/session_opts.rs), ProxyCommand (ssh/proxycmd.rs).
        // ForkAfterAuthentication backgrounds ssh before the session: a
        // Reach connection already runs in the background. SyslogFacility
        // applies to ssh only when it logs to syslog (-y); it never does by
        // its own choice, and Reach does not either.
        RequestTTY | RemoteCommand | SessionType | SetEnv | SendEnv | StdinNull | EscapeChar | ObscureKeystrokeTiming | LocalCommand | PermitLocalCommand | RefuseConnection | ProxyCommand | ProxyUseFdpass | WarnWeakCrypto | ForkAfterAuthentication | SyslogFacility => Support::Yes,
        // Forwarding (ssh/forwarding.rs).
        LocalForward | RemoteForward | DynamicForward | ClearAllForwardings | ExitOnForwardFailure | GatewayPorts | PermitRemoteOpen | StreamLocalBindMask | StreamLocalBindUnlink | ChannelTimeout | EnableEscapeCommandline | ForwardAgent => Support::Yes,
        // Connection sharing (ssh/control.rs).
        ControlMaster | ControlPath | ControlPersist => Support::Yes,
        // Logging (ssh/connlog.rs).
        LogLevel | LogVerbose => Support::Yes,
        // X11 (ssh/x11.rs).
        ForwardX11 | ForwardX11Trusted | ForwardX11Timeout | XAuthLocation => Support::Yes,
        EnableSSHKeysign | HostbasedAcceptedAlgorithms | HostbasedAuthentication
        | PKCS11Provider | SecurityKeyProvider | Tunnel
        | TunnelDevice | UpdateHostKeys
        | GSSAPIKeyExchange | GSSAPIRenewalForcesRekey | GSSAPIKexAlgorithms => Support::NotYet,
    }
}

/// Keywords that run a program on this machine; they need the user's
/// approval before Reach runs them.
pub fn runs_command(kw: Kw) -> bool {
    matches!(kw, Kw::ProxyCommand | Kw::LocalCommand | Kw::KnownHostsCommand | Kw::XAuthLocation)
}

/// Settings that make the connection less safe than Reach's defaults,
/// besides the algorithms the plan reports.
pub fn weakening(kw: Kw, args: &[String]) -> Option<&'static str> {
    let v = args.first().map(String::as_str).unwrap_or("");
    Some(match (kw, v) {
        (Kw::StrictHostKeyChecking, "no") => "accepts any host key, including one an attacker presents",
        (Kw::UserKnownHostsFile, "/dev/null") | (Kw::GlobalKnownHostsFile, "/dev/null") => {
            "never remembers host keys, so every key is new and none can be checked"
        }
        (Kw::ForwardAgent, x) if x != "no" => "lets the server use your keys while you are connected",
        (Kw::GSSAPIDelegateCredentials, "yes") => "gives the server your Kerberos credentials",
        (Kw::ForwardX11Trusted, "yes") => "gives the server full access to your display",
        (Kw::ForwardX11, "yes") => "lets the server open windows on your display",
        (Kw::GatewayPorts, "yes") => "opens forwarded ports to the whole network, not just this machine",
        (Kw::NoHostAuthenticationForLocalhost, "yes") => "skips the host key check for localhost",
        (Kw::CheckHostIP, "no") => return None,
        (Kw::PubkeyAcceptedAlgorithms | Kw::CASignatureAlgorithms | Kw::HostbasedAcceptedAlgorithms, x)
            if x.contains("ssh-rsa") || x.contains("ssh-dss") =>
        {
            "allows SHA-1 RSA or DSA signatures"
        }
        _ => return None,
    })
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Line {
    pub at: At,
    pub keyword: String,
    pub text: String,
    pub status: Status,
    pub support: Option<Support>,
    /// For an applied line: what the connection did with it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub used: Option<Use>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weakening: Option<String>,
    /// The command it would run, when it runs one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub host: String,
    pub lines: Vec<Line>,
    pub weakenings: Vec<Weakening>,
    /// Commands the config would run for this host.
    pub commands: Vec<String>,
    /// A RefuseConnection that applies.
    pub refused: Option<String>,
    /// Errors that would make ssh refuse the files, and expansion errors.
    pub errors: Vec<String>,
}

/// The report for a resolved host and the plan made from it. `exec_asked`
/// lists `Match exec` commands that wanted to run.
pub fn build(r: &Resolved, plan: &Plan, finish_errors: &[String], exec_asked: &[String]) -> Report {
    let mut weakenings = plan.weakenings.clone();
    let mut commands: Vec<String> = exec_asked.to_vec();
    let mut lines = Vec::new();
    for n in &r.notes {
        let mut line = Line {
            at: n.at.clone(),
            keyword: n.keyword.clone(),
            text: n.text.clone(),
            status: n.status.clone(),
            support: n.kw.map(support),
            used: None,
            weakening: None,
            command: None,
        };
        if let (Some(kw), Status::Applied) = (n.kw, &n.status) {
            line.used = plan.uses.iter().find(|(k, _)| *k == kw).map(|(_, u)| u.clone());
            let args = r.options.get(kw).map(|s| s.args.clone()).unwrap_or_default();
            if let Some(why) = weakening(kw, &args) {
                line.weakening = Some(why.to_string());
                if !weakenings.iter().any(|w| w.keyword == kw.name()) {
                    let value = args.join(" ");
                    let accepted = plan.approved(&r.options, kw, &value);
                    weakenings.push(Weakening { keyword: kw.name().into(), value, reason: why.into(), accepted });
                }
            }
            let weak: Vec<String> = plan
                .weakenings
                .iter()
                .filter(|w| w.keyword == kw.name())
                .map(|w| format!("{}: {}{}", w.value, w.reason, if w.accepted { "" } else { " (waiting for your approval)" }))
                .collect();
            if !weak.is_empty() {
                line.weakening = Some(weak.join("; "));
            }
            if runs_command(kw) {
                if let Some(c) = r.options.first(kw).filter(|c| !c.eq_ignore_ascii_case("none")) {
                    line.command = Some(c.to_string());
                    if !commands.iter().any(|x| x == c) {
                        commands.push(c.to_string());
                    }
                }
            }
        }
        lines.push(line);
    }
    // SendEnv: the local variables it would share, by name, for approval.
    if !r.options.send_env.is_empty() {
        let names = crate::ssh::session_opts::send_env_names(&r.options);
        let key = crate::ssh::session_opts::send_env_key(&r.options);
        let shown = if names.is_empty() { "none right now".to_string() } else { names.join(", ") };
        weakenings.push(Weakening {
            keyword: "SendEnv".into(),
            value: r.options.send_env.join(" "),
            reason: format!("sends this computer's environment variables to the server; would send: {shown}"),
            accepted: plan.accepted.contains(&key),
        });
    }
    let mut errors: Vec<String> = r
        .notes
        .iter()
        .filter_map(|n| match &n.status {
            Status::Error(e) => Some(format!("{} line {}: {e}", n.at.file, n.at.line)),
            _ => None,
        })
        .collect();
    errors.extend(finish_errors.iter().cloned());
    Report { host: r.host.clone(), lines, weakenings, commands, refused: r.refused.clone(), errors }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_keyword_has_a_place() {
        for kw in Kw::ALL {
            let _ = support(*kw);
        }
    }
}
