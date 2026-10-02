//! ssh_config settings as a session keeps them, and resolving them for a
//! connection. The files are stored with the session, so it resolves the
//! same way on every device it syncs to.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::env::{ExecPolicy, SystemEnv};
use super::resolve::{resolve, Env, Query, Resolved, Source};

/// What part a stored file played.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FileRole {
    /// ~/.ssh/config, read first.
    User,
    /// /etc/ssh/ssh_config (or Windows' %ProgramData%\ssh\ssh_config).
    System,
    /// A file one of them includes.
    Included,
}

/// One config file as it was read when the session was imported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigFile {
    pub path: String,
    pub text: String,
    pub role: FileRole,
}

/// What a session was imported from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Imported {
    /// The name the host was asked for by (the `Host` alias): `%n`,
    /// `Match originalhost`, and what `Host` patterns are matched against.
    pub alias: String,
    pub files: Vec<ConfigFile>,
    /// When, in Unix seconds.
    #[serde(default)]
    pub at: i64,
}

/// A session's ssh_config settings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imported: Option<Imported>,
    /// Lines set in Reach ("MACs +hmac-sha1"). They win over the files, as
    /// `ssh -o` does.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lines: Vec<String>,
    /// Local commands the user allowed to run for this session
    /// (ProxyCommand, LocalCommand, KnownHostsCommand, Match exec), exactly
    /// as written in the config.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approved_commands: Vec<String>,
    /// Weakening settings the user has seen and kept ("Keyword value").
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_weakenings: Vec<String>,
}

impl SshOptions {
    pub fn is_empty(&self) -> bool {
        self.imported.is_none() && self.lines.is_empty()
    }
}

/// The machine, answering file reads from the stored copies: an Include
/// finds the file it found at import, on any device.
struct StoredEnv<'a> {
    sys: &'a SystemEnv,
    files: &'a [ConfigFile],
}

fn norm(p: &str) -> String {
    p.replace('\\', "/")
}

impl Env for StoredEnv<'_> {
    fn home(&self) -> String {
        self.sys.home()
    }
    fn local_user(&self) -> String {
        self.sys.local_user()
    }
    fn uid(&self) -> String {
        self.sys.uid()
    }
    fn local_host(&self) -> String {
        self.sys.local_host()
    }
    fn system_dir(&self) -> String {
        self.sys.system_dir()
    }
    fn read(&self, path: &Path) -> Option<String> {
        let want = norm(&path.display().to_string());
        self.files.iter().find(|f| norm(&f.path) == want).map(|f| f.text.clone())
    }
    fn glob(&self, pattern: &str) -> Vec<PathBuf> {
        let pat = norm(pattern);
        self.files
            .iter()
            .filter(|f| super::pattern::match_pattern(&norm(&f.path), &pat))
            .map(|f| PathBuf::from(&f.path))
            .collect()
    }
    fn getenv(&self, name: &str) -> Option<String> {
        self.sys.getenv(name)
    }
    fn local_addresses(&self) -> Vec<std::net::IpAddr> {
        self.sys.local_addresses()
    }
    fn exec(&self, command: &str) -> Result<bool, String> {
        self.sys.exec(command)
    }
    fn resolve(&self, name: &str) -> Option<String> {
        self.sys.resolve(name)
    }
}

/// Resolve a session's settings for connecting. `host`, `port` and `user`
/// are the session's own fields; like ssh's command line they win.
pub fn resolve_session(opts: &SshOptions, host: &str, port: u16, user: &str) -> (Resolved, Vec<String>) {
    let sys = SystemEnv::new(ExecPolicy::Approved(opts.approved_commands.clone()));
    let empty = Vec::new();
    let files = opts.imported.as_ref().map_or(&empty, |i| &i.files);
    let env = StoredEnv { sys: &sys, files };
    let alias = opts.imported.as_ref().map_or(host.to_string(), |i| i.alias.clone());
    let mut overrides = vec![("HostName".to_string(), host.to_string()), ("Port".to_string(), port.to_string())];
    if !user.is_empty() {
        overrides.push(("User".to_string(), user.to_string()));
    }
    for line in &opts.lines {
        if let Some(l) = super::lex::split_keyword(line) {
            overrides.push((l.keyword, l.rest));
        }
    }
    // ssh reads the user's file, then the system's; included files are
    // reached through them.
    let sources: Vec<Source> = [FileRole::User, FileRole::System]
        .iter()
        .filter_map(|role| files.iter().find(|f| f.role == *role))
        .map(|f| Source { path: PathBuf::from(&f.path), text: Some(f.text.clone()), user: f.role == FileRole::User })
        .collect();
    let mut r = resolve(&sources, &Query { host: alias, command: None, overrides }, &env);
    let errors = r.finish(&env);
    (r, errors)
}

/// The plan for one hop of a session: the session's settings for its own
/// host, or, for a jump host, the imported files looked up by that host's
/// name (as ssh does for each ProxyJump hop), without the session's own
/// lines, which are for the target.
pub fn plan_for(opts: Option<&SshOptions>, host: &str, port: u16, user: &str, jump: bool) -> super::apply::Plan {
    let base = russh::client::Config::default();
    let Some(opts) = opts.filter(|o| !o.is_empty()) else {
        let empty = Resolved::empty(host);
        return super::apply::Plan::new(&empty, base);
    };
    let scoped;
    let opts = if jump {
        scoped = SshOptions { lines: Vec::new(), ..opts.clone() };
        &scoped
    } else {
        opts
    };
    let (r, errors) = resolve_session(opts, host, port, user);
    for e in &errors {
        tracing::warn!("ssh_config for {host}: {e}");
    }
    let plan = super::apply::Plan::new(&r, base);
    for w in &plan.weakenings {
        tracing::warn!("ssh_config for {host}: {} {} weakens the connection: {}", w.keyword, w.value, w.reason);
    }
    for (kw, u) in &plan.uses {
        tracing::info!("ssh_config for {host}: {} {:?}", kw.name(), u);
    }
    plan
}
