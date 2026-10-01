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
