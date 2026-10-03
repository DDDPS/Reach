//! Against a real SSH server: Reach's own login code, with keys as they
//! arrive from another device. Run with
//! `REACH_SSH_TEST=host:port REACH_SSH_USER=user REACH_SSH_KEYS=dir
//! cargo test --lib ssh::client::live -- --ignored --nocapture`, where `dir`
//! holds `k_good` and `k_rsa` (both in the server's authorized_keys) and
//! `k_other` (not).

use super::*;

/// Accepts any host key: the test server's identity is not under test, and
/// this keeps the user's own known-hosts list out of it.
struct AnyHost;

impl russh::client::Handler for AnyHost {
    type Error = russh::Error;
    async fn check_server_key(&mut self, _key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

fn env() -> Option<(String, u16, String, std::path::PathBuf)> {
    let addr = std::env::var("REACH_SSH_TEST").ok()?;
    let (host, port) = addr.rsplit_once(':')?;
    Some((
        host.to_string(),
        port.parse().ok()?,
        std::env::var("REACH_SSH_USER").ok()?,
        std::env::var("REACH_SSH_KEYS").ok()?.into(),
    ))
}

/// Log in with `material` as an imported key, no agent: as on a phone.
async fn login(host: &str, port: u16, user: &str, material: &str) -> Result<bool, String> {
    login_with(host, port, user, material, false).await
}

async fn login_with(host: &str, port: u16, user: &str, material: &str, allow_agent: bool) -> Result<bool, String> {
    let config = Arc::new(russh::client::Config::default());
    let mut handle = russh::client::connect(config, (host, port), AnyHost).await.map_err(|e| e.to_string())?;
    let auth = AuthParams {
        key: Some(KeyAuth { source: KeySource::Material(material.to_string()), passphrase: None }),
        password: None,
        allow_agent,
    };
    let outcome = cascade_authenticate(&mut handle, user, &auth).await.map_err(|e| e.to_string())?;
    if outcome.by == Some(AuthBy::Agent) && outcome.refused_key.is_some() {
        println!("      (Reach now warns: logged in through the agent, this session's key was refused)");
    }
    outcome.into_result().map(|_| true).map_err(|e| e.to_string())
}

#[tokio::test]
#[ignore = "needs an SSH server"]
async fn live_imported_keys() {
    let Some((host, port, user, dir)) = env() else { panic!("set REACH_SSH_TEST, REACH_SSH_USER, REACH_SSH_KEYS") };
    let read = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap();

    let mut cases: Vec<(String, String)> = Vec::new();
    for key in ["k_good", "k_rsa", "k_other"] {
        let text = read(key);
        cases.push((format!("{key} as made"), text.clone()));
        cases.push((format!("{key} CRLF"), text.replace('\n', "\r\n")));
        cases.push((format!("{key} trailing spaces"), text.lines().map(|l| format!("{l}  ")).collect::<Vec<_>>().join("\n")));
        cases.push((format!("{key} BOM"), format!("\u{feff}{text}")));
        cases.push((format!("{key} leading blank line"), format!("\n{text}")));
    }
    for (name, material) in cases {
        let out = match login(&host, port, &user, &material).await {
            Ok(true) => "LOGGED IN".to_string(),
            Ok(false) => "REFUSED by the server".to_string(),
            Err(e) => format!("ERROR: {e}"),
        };
        println!("{name:>30}: {out}");
    }
}

/// The same session on a Windows PC with an agent and on a phone without:
/// a key the server refuses is hidden by the agent on one and not the other.
#[tokio::test]
#[ignore = "needs an SSH server and an agent holding k_good"]
async fn live_agent_hides_a_refused_key() {
    let Some((host, port, user, dir)) = env() else { panic!("set REACH_SSH_TEST, REACH_SSH_USER, REACH_SSH_KEYS") };
    let wrong = std::fs::read_to_string(dir.join("k_other")).unwrap();
    for (name, agent) in [("Windows, agent running", true), ("phone, no agent", false)] {
        let out = match login_with(&host, port, &user, &wrong, agent).await {
            Ok(true) => "LOGGED IN".to_string(),
            Ok(false) => "REFUSED by the server".to_string(),
            Err(e) => format!("ERROR: {e}"),
        };
        println!("{name:>24}: {out}");
    }
}

/// A session whose key the server refuses makes exactly one attempt, with an
/// agent holding the right key running: the agent is not offered behind it.
/// Count the server's own `Failed publickey` lines for the proof.
#[tokio::test]
#[ignore = "needs an SSH server and an agent holding k_good"]
async fn live_one_attempt_per_refused_key() {
    let Some((host, port, user, dir)) = env() else { panic!("set REACH_SSH_TEST, REACH_SSH_USER, REACH_SSH_KEYS") };
    let wrong = std::fs::read_to_string(dir.join("k_other")).unwrap();
    let auth = crate::ipc::ssh_commands::build_auth("key", None, Some(KeySource::Material(wrong)), None, false).unwrap();
    let config = Arc::new(russh::client::Config::default());
    let mut handle = russh::client::connect(config, (host.as_str(), port), AnyHost).await.unwrap();
    let outcome = cascade_authenticate(&mut handle, &user, &auth).await.unwrap();
    println!("default session, wrong key, agent running: {:?}", outcome.into_result().map_err(|e| e.to_string()));
}

/// A server that only offers old MACs (and no AEAD cipher), as in the
/// Discord report: fails with Reach's defaults, logs in once the session
/// says `MACs +hmac-sha1`. Run with `REACH_SSH_LEGACY=host:port`, plus
/// REACH_SSH_USER and REACH_SSH_KEYS as above.
#[tokio::test]
#[ignore = "needs an SSH server offering only legacy MACs"]
async fn live_legacy_macs() {
    let addr = std::env::var("REACH_SSH_LEGACY").expect("REACH_SSH_LEGACY");
    let (host, port) = addr.rsplit_once(':').unwrap();
    let port: u16 = port.parse().unwrap();
    let user = std::env::var("REACH_SSH_USER").unwrap();
    let key = std::fs::read_to_string(std::path::Path::new(&std::env::var("REACH_SSH_KEYS").unwrap()).join("k_good")).unwrap();

    async fn attempt(host: &str, port: u16, user: &str, key: &str, opts: Option<&crate::ssh::sshconf::session::SshOptions>) -> Result<(), String> {
        let plan = crate::ssh::sshconf::session::plan_for(opts, host, port, user, false);
        let stream = crate::ssh::sshconf::net::connect(host, port, &plan.socket, true).await.map_err(|e| e.to_string())?;
        let mut handle = russh::client::connect_stream(Arc::new(plan.config), stream, AnyHost).await.map_err(|e| e.to_string())?;
        let auth = AuthParams { key: Some(KeyAuth { source: KeySource::Material(key.to_string()), passphrase: None }), password: None, allow_agent: false };
        cascade_authenticate(&mut handle, user, &auth).await.map_err(|e| e.to_string())?.into_result().map(|_| ()).map_err(|e| e.to_string())
    }

    let before = attempt(host, port, &user, &key, None).await;
    println!("Reach's defaults: {before:?}");
    assert!(before.as_ref().is_err_and(|e| e.to_lowercase().contains("mac")), "{before:?}");

    let opts = crate::ssh::sshconf::session::SshOptions { lines: vec!["MACs +hmac-sha1".into()], ..Default::default() };
    let after = attempt(host, port, &user, &key, Some(&opts)).await;
    println!("With MACs +hmac-sha1: {after:?}");
    assert!(after.is_ok(), "{after:?}");

    // The MACs added to the vendored russh, each alone, through Reach's plan.
    for mac in ["hmac-md5", "hmac-md5-96", "hmac-sha1-96", "umac-64@openssh.com"] {
        let opts = crate::ssh::sshconf::session::SshOptions { lines: vec![format!("MACs {mac}")], ..Default::default() };
        let r = attempt(host, port, &user, &key, Some(&opts)).await;
        println!("With MACs {mac}: {r:?}");
        assert!(r.is_ok(), "{mac}: {r:?}");
    }
}

/// OpenSSH-style login from ssh_config settings, against real servers.
/// Run with `REACH_SSH_AUTH=127.0.0.1:2226` (TrustedUserCAKeys, password
/// and keyboard-interactive on), `REACH_SSH_TEST=127.0.0.1:2222`, and
/// REACH_SSH_KEYS holding k_good, k_enc (passphrase enc-pass-123),
/// k_certkey with k_certkey-cert.pub signed by the server's CA; user
/// `plain` has the password plain-test-pw.
#[tokio::test]
#[ignore = "needs the SSH test servers"]
async fn live_config_login() {
    use crate::ssh::sshconf::session::{ConfigFile, FileRole, Imported, SshOptions};
    let addr = |var: &str| -> (String, u16) {
        let a = std::env::var(var).unwrap_or_else(|_| panic!("{var}"));
        let (h, p) = a.rsplit_once(':').unwrap();
        (h.to_string(), p.parse().unwrap())
    };
    let (h1, p1) = addr("REACH_SSH_TEST");
    let (h2, p2) = addr("REACH_SSH_AUTH");
    let keys = std::path::PathBuf::from(std::env::var("REACH_SSH_KEYS").unwrap());
    let k = |n: &str| keys.join(n).display().to_string().replace('\\', "/");

    fn options(text: String) -> SshOptions {
        SshOptions {
            imported: Some(Imported { alias: "t".into(), files: vec![ConfigFile { path: "cfg".into(), text, role: FileRole::User }], at: 0 }),
            ..Default::default()
        }
    }
    async fn run(host: &str, port: u16, user: &str, text: String, auth: AuthParams) -> Result<AuthBy, String> {
        let o = options(text);
        let plan = crate::ssh::sshconf::session::plan_for(Some(&o), host, port, user, false);
        let opts: HopOptions = plan.into();
        let stream = crate::ssh::sshconf::net::connect(host, port, &opts.socket, false).await.map_err(|e| e.to_string())?;
        let mut handle = russh::client::connect_stream(opts.config.clone(), stream, AnyHost).await.map_err(|e| e.to_string())?;
        crate::ssh::client::login(&mut handle, user, &auth, &opts, None, host, port).await.map_err(|e| e.to_string())?.into_result().map_err(|e| e.to_string())
    }

    let mut results = Vec::new();
    let mut check = |name: &str, got: Result<AuthBy, String>, want: Result<AuthBy, ()>| {
        println!("{name}: {got:?}");
        let ok = match (&got, &want) {
            (Ok(a), Ok(b)) => a == b,
            (Err(_), Err(())) => true,
            _ => false,
        };
        results.push((name.to_string(), ok));
    };

    check("IdentityFile from the config", run(&h1, p1, "reach", format!("Host t\n  IdentityFile {}\n  IdentitiesOnly yes\n", k("k_good")), AuthParams::default()).await, Ok(AuthBy::Key));
    check("certificate (CertificateFile)", run(&h2, p2, "reach", format!("Host t\n  IdentityFile {}\n  CertificateFile {}\n  IdentitiesOnly yes\n  PreferredAuthentications publickey\n", k("k_certkey"), k("k_certkey-cert.pub")), AuthParams::default()).await, Ok(AuthBy::Key));
    let bare = keys.join("k_certkey_bare");
    std::fs::copy(keys.join("k_certkey"), &bare).unwrap();
    check("the same key without its certificate", run(&h2, p2, "reach", format!("Host t\n  IdentityFile {}\n  IdentitiesOnly yes\n  PreferredAuthentications publickey\n", bare.display().to_string().replace('\\', "/")), AuthParams::default()).await, Err(()));
    std::fs::remove_file(&bare).ok();
    check("password", run(&h2, p2, "plain", "Host t\n  PreferredAuthentications password\n".into(), AuthParams::from_password("plain-test-pw".into())).await, Ok(AuthBy::Password));
    check("keyboard-interactive (PAM) with the stored password", run(&h2, p2, "plain", "Host t\n  PreferredAuthentications keyboard-interactive\n".into(), AuthParams::from_password("plain-test-pw".into())).await, Ok(AuthBy::Password));
    check("wrong password refused", run(&h2, p2, "plain", "Host t\n  PreferredAuthentications password\n  NumberOfPasswordPrompts 1\n".into(), AuthParams::from_password("nope".into())).await, Err(()));
    check("PasswordAuthentication no", run(&h2, p2, "plain", "Host t\n  PreferredAuthentications password\n  PasswordAuthentication no\n".into(), AuthParams::from_password("plain-test-pw".into())).await, Err(()));
    let enc = k("k_enc");
    check("encrypted key, BatchMode, no passphrase", run(&h1, p1, "reach", format!("Host t\n  IdentityFile {enc}\n  IdentitiesOnly yes\n  BatchMode yes\n"), AuthParams::default()).await, Err(()));
    crate::vault::manager::keychain_entry_in("Reach SSH key passphrase", &enc).unwrap().set_password("enc-pass-123").unwrap();
    check("encrypted key, passphrase from UseKeychain", run(&h1, p1, "reach", format!("Host t\n  IdentityFile {enc}\n  IdentitiesOnly yes\n  UseKeychain yes\n"), AuthParams::default()).await, Ok(AuthBy::Key));
    check("PubkeyAuthentication no", run(&h1, p1, "reach", format!("Host t\n  IdentityFile {}\n  PubkeyAuthentication no\n  PreferredAuthentications publickey\n", k("k_good")), AuthParams::default()).await, Err(()));

    let failed: Vec<_> = results.iter().filter(|(_, ok)| !ok).map(|(n, _)| n.clone()).collect();
    assert!(failed.is_empty(), "failed: {failed:?}");
}
