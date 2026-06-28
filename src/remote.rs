use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

// ── Config model ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RemoteType {
    Ssh,
    Ftp,
}

impl std::fmt::Display for RemoteType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RemoteType::Ssh => write!(f, "ssh"),
            RemoteType::Ftp => write!(f, "ftp"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Remote {
    pub name: String,
    #[serde(rename = "type")]
    pub remote_type: RemoteType,
    pub host: String,
    pub user: String,
    /// Port on the remote. If omitted, ssh uses its own defaults / ~/.ssh/config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Absolute path on the remote where the encrypted store is stored.
    pub path: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct RemotesConfig {
    #[serde(default)]
    pub remote: Vec<Remote>,
}

impl RemotesConfig {
    pub fn load(config_path: &Path) -> Result<Self> {
        if !config_path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(config_path)
            .with_context(|| format!("Cannot read remotes config at {}", config_path.display()))?;
        toml::from_str(&content).map_err(|e| anyhow::anyhow!("Invalid remotes config: {e}"))
    }

    pub fn save(config_path: &Path, remotes: &[Remote]) -> Result<()> {
        let cfg = Self {
            remote: remotes.to_vec(),
        };
        let toml_str = toml::to_string_pretty(&cfg)
            .map_err(|e| anyhow::anyhow!("Failed to serialize remotes config: {e}"))?;
        fs::write(config_path, toml_str)
            .with_context(|| format!("Cannot write remotes config to {}", config_path.display()))?;
        Ok(())
    }
}

// ── Manager ───────────────────────────────────────────────────────────

pub struct RemoteManager {
    config_path: PathBuf,
}

impl RemoteManager {
    pub fn new(config_path: PathBuf) -> Self {
        Self { config_path }
    }

    pub fn load(&self) -> Result<Vec<Remote>> {
        Ok(RemotesConfig::load(&self.config_path)?.remote)
    }

    pub fn find(&self, name: &str) -> Result<Remote> {
        let remotes = self.load()?;
        remotes
            .into_iter()
            .find(|r| r.name == name)
            .with_context(|| format!("Remote '{name}' not configured. Run: vault remote list"))
    }

    pub fn add(&self, remote: Remote) -> Result<()> {
        let mut remotes = self.load()?;
        if remotes.iter().any(|r| r.name == remote.name) {
            bail!(
                "Remote '{}' already exists. Remove it first: vault remote rm {}",
                remote.name,
                remote.name
            );
        }
        remotes.push(remote);
        RemotesConfig::save(&self.config_path, &remotes)?;
        Ok(())
    }

    pub fn remove(&self, name: &str) -> Result<()> {
        let mut remotes = self.load()?;
        let before = remotes.len();
        remotes.retain(|r| r.name != name);
        if remotes.len() == before {
            bail!("Remote '{name}' not found");
        }
        RemotesConfig::save(&self.config_path, &remotes)?;
        Ok(())
    }
}

// ── Push / Pull ────────────────────────────────────────────────────────

/// Push the encrypted store (and optionally the age key) to a remote.
/// The store is already encrypted with age — SSH provides the transport.
pub fn push(remote: &Remote, store_path: &Path, key_path: &Path, include_key: bool) -> Result<()> {
    match remote.remote_type {
        RemoteType::Ssh => push_ssh(remote, store_path, key_path, include_key),
        RemoteType::Ftp => bail!("FTP remotes are not yet implemented. Use type ssh for now."),
    }
}

/// Pull the encrypted store from a remote, overwriting the local store.
pub fn pull(remote: &Remote, store_path: &Path) -> Result<()> {
    match remote.remote_type {
        RemoteType::Ssh => pull_ssh(remote, store_path),
        RemoteType::Ftp => bail!("FTP remotes are not yet implemented. Use type ssh for now."),
    }
}

// ── SSH backend ────────────────────────────────────────────────────────

fn ssh_target(remote: &Remote) -> String {
    format!("{}@{}", remote.user, remote.host)
}

/// Common ssh option args: optional port, BatchMode, ConnectTimeout.
fn ssh_opts(remote: &Remote) -> Vec<String> {
    let mut v = Vec::new();
    if let Some(p) = remote.port {
        v.push("-p".to_string());
        v.push(p.to_string());
    }
    v.push("-o".to_string());
    v.push("BatchMode=yes".to_string());
    v.push("-o".to_string());
    v.push("ConnectTimeout=10".to_string());
    v
}

/// Run a remote command via ssh, inheriting stdio, capturing status.
fn ssh_exec(remote: &Remote, remote_cmd: &str) -> Result<()> {
    let status = Command::new("ssh")
        .args(ssh_opts(remote))
        .arg(ssh_target(remote))
        .arg(remote_cmd)
        .status()
        .with_context(|| format!("Failed to invoke ssh for {}", remote.name))?;
    if !status.success() {
        bail!(
            "ssh command failed on '{}' (exit {:?})",
            remote.name,
            status.code()
        );
    }
    Ok(())
}

fn parent_dir(path: &str) -> String {
    match path.rfind('/') {
        Some(0) => "/".to_string(),
        Some(i) => path[..i].to_string(),
        None => ".".to_string(),
    }
}

/// Shell-quote a single-quoted string (escape embedded single quotes).
fn sq(s: &str) -> String {
    s.replace('\'', "'\\''")
}

/// Pipe a local file to a remote path via `ssh host "cat > 'path'"`.
/// This avoids scp's remote-path quoting pitfalls entirely.
fn ssh_put(remote: &Remote, local_path: &Path, remote_path: &str) -> Result<()> {
    let remote_cmd = format!("cat > '{}'", sq(remote_path));
    let mut child = Command::new("ssh")
        .args(ssh_opts(remote))
        .arg(ssh_target(remote))
        .arg(&remote_cmd)
        .stdin(Stdio::piped())
        .spawn()
        .with_context(|| format!("Failed to spawn ssh for {}", remote.name))?;

    {
        let mut input = child.stdin.take().context("no stdin")?;
        let data = fs::read(local_path)
            .with_context(|| format!("Cannot read {}", local_path.display()))?;
        input
            .write_all(&data)
            .with_context(|| format!("Failed to pipe file to ssh for {}", remote.name))?;
    } // dropping stdin closes it, signalling EOF to remote `cat`

    let status = child
        .wait()
        .with_context(|| format!("Failed to wait on ssh for {}", remote.name))?;
    if !status.success() {
        bail!(
            "ssh upload failed for '{}' (exit {:?})",
            remote.name,
            status.code()
        );
    }
    Ok(())
}

/// Pull a remote path into a local file via `ssh host "cat 'path'"`.
fn ssh_get(remote: &Remote, remote_path: &str, local_path: &Path) -> Result<()> {
    let remote_cmd = format!("cat '{}'", sq(remote_path));
    let mut child = Command::new("ssh")
        .args(ssh_opts(remote))
        .arg(ssh_target(remote))
        .arg(&remote_cmd)
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("Failed to spawn ssh for {}", remote.name))?;

    {
        let mut out = child.stdout.take().context("no stdout")?;
        let mut buf = Vec::new();
        out.read_to_end(&mut buf)
            .with_context(|| format!("Failed to read remote file from {}", remote.name))?;
        fs::write(local_path, &buf)
            .with_context(|| format!("Cannot write {}", local_path.display()))?;
    }

    let status = child
        .wait()
        .with_context(|| format!("Failed to wait on ssh for {}", remote.name))?;
    if !status.success() {
        bail!(
            "ssh download failed for '{}' (exit {:?})",
            remote.name,
            status.code()
        );
    }
    Ok(())
}

fn push_ssh(
    remote: &Remote,
    store_path: &Path,
    key_path: &Path,
    include_key: bool,
) -> Result<()> {
    if !store_path.exists() {
        bail!(
            "Encrypted store not found at {}. Run `vault init` first.",
            store_path.display()
        );
    }

    // Ensure the parent directory exists on the remote.
    let dir = parent_dir(&remote.path);
    let mkdir_cmd = format!("mkdir -p -- '{}'", sq(&dir));
    ssh_exec(remote, &mkdir_cmd)
        .with_context(|| format!("Failed to create remote directory on '{}'", remote.name))?;

    // Upload the encrypted store.
    ssh_put(remote, store_path, &remote.path)?;
    eprintln!(
        "✓ Pushed encrypted store to '{}' → {}:{}",
        remote.name,
        ssh_target(remote),
        remote.path
    );

    if include_key {
        if !key_path.exists() {
            bail!(
                "Key file not found at {}. Cannot include key.",
                key_path.display()
            );
        }
        let key_remote_path = format!("{}.key", remote.path);
        ssh_put(remote, key_path, &key_remote_path)?;
        eprintln!(
            "✓ Pushed age key to '{}' → {}:{}",
            remote.name,
            ssh_target(remote),
            key_remote_path
        );
    }

    Ok(())
}

fn pull_ssh(remote: &Remote, store_path: &Path) -> Result<()> {
    ssh_get(remote, &remote.path, store_path)?;
    // Restore restrictive permissions on the pulled store.
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(store_path, PermissionsExt::from_mode(0o600))?;
    eprintln!(
        "✓ Pulled encrypted store from '{}' → {}",
        remote.name,
        store_path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parent_dir() {
        assert_eq!(parent_dir("/home/maxi/backup/store.env.age"), "/home/maxi/backup");
        assert_eq!(parent_dir("/store.env.age"), "/");
        assert_eq!(parent_dir("store.env.age"), ".");
    }

    #[test]
    fn test_sq() {
        // sq replaces ' with '\'' (close-quote, escaped-quote, reopen-quote)
        assert_eq!(sq("simple"), "simple");
        assert_eq!(sq("it's here"), "it'\\''s here");
        assert_eq!(sq("a'b'c"), "a'\\''b'\\''c");
    }

    #[test]
    fn test_remotes_roundtrip() {
        let remotes = vec![Remote {
            name: "nas".to_string(),
            remote_type: RemoteType::Ssh,
            host: "nas.local".to_string(),
            user: "backup".to_string(),
            port: Some(22),
            path: "/volume1/vault/store.env.age".to_string(),
        }];
        let cfg = RemotesConfig { remote: remotes };
        let s = toml::to_string(&cfg).unwrap();
        let parsed: RemotesConfig = toml::from_str(&s).unwrap();
        assert_eq!(parsed.remote.len(), 1);
        assert_eq!(parsed.remote[0].name, "nas");
        assert_eq!(parsed.remote[0].remote_type, RemoteType::Ssh);
        assert_eq!(parsed.remote[0].port, Some(22));
    }

    #[test]
    fn test_remotes_default_port() {
        let toml_str = r#"
[[remote]]
name = "x"
type = "ssh"
host = "h"
user = "u"
path = "/p"
"#;
        let cfg: RemotesConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.remote[0].port, None);
    }
}