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

impl Remote {
    /// Reject values that ssh would parse as options (leading '-') or that
    /// would garble the user@host target.
    pub fn validate(&self) -> Result<()> {
        for (label, v) in [("name", &self.name), ("host", &self.host), ("user", &self.user)] {
            if v.is_empty() {
                bail!("Remote {label} must not be empty");
            }
            if v.starts_with('-') {
                bail!("Remote {label} must not start with '-'");
            }
            if v.chars().any(|c| c.is_whitespace() || c.is_control()) {
                bail!("Remote {label} must not contain whitespace");
            }
        }
        if self.host.contains('@') || self.user.contains('@') {
            bail!("Remote host/user must not contain '@'");
        }
        if self.path.is_empty() {
            bail!("Remote path must not be empty");
        }
        Ok(())
    }
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
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(config_path, PermissionsExt::from_mode(0o600))?;
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
        remote.validate()?;
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

/// Remote path of the passphrase-encrypted key backup, next to the store.
fn key_backup_path(store_path: &str) -> String {
    format!("{store_path}.key.age")
}

/// Push the encrypted store (and optionally the passphrase-encrypted age
/// key) to a remote. The store is already encrypted with age — SSH provides
/// the transport.
pub fn push(remote: &Remote, store_path: &Path, key_ciphertext: Option<&[u8]>) -> Result<()> {
    match remote.remote_type {
        RemoteType::Ssh => push_ssh(remote, store_path, key_ciphertext),
        RemoteType::Ftp => bail!("FTP remotes are not yet implemented. Use type ssh for now."),
    }
}

/// Download the remote store into a temp file next to `store_path`.
/// Returns the temp path — the caller verifies it decrypts, then renames it
/// over the real store. The local store is never touched here.
pub fn pull(remote: &Remote, store_path: &Path) -> Result<PathBuf> {
    match remote.remote_type {
        RemoteType::Ssh => {
            let data = ssh_read(remote, &remote.path)?;
            let tmp = PathBuf::from(format!("{}.pull-tmp", store_path.display()));
            crate::store::write_private(&tmp, &data)?;
            Ok(tmp)
        }
        RemoteType::Ftp => bail!("FTP remotes are not yet implemented. Use type ssh for now."),
    }
}

/// Download the passphrase-encrypted key backup from a remote.
pub fn pull_key(remote: &Remote) -> Result<Vec<u8>> {
    match remote.remote_type {
        RemoteType::Ssh => ssh_read(remote, &key_backup_path(&remote.path)),
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
        .arg("--")
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

/// Pipe bytes to a remote path via `ssh host "umask 077 && cat > 'path'"`.
/// This avoids scp's remote-path quoting pitfalls entirely. The umask makes
/// new files owner-only from creation; chmod covers pre-existing files.
fn ssh_put_bytes(remote: &Remote, data: &[u8], remote_path: &str) -> Result<()> {
    let quoted = sq(remote_path);
    let remote_cmd = format!("umask 077 && cat > '{quoted}' && chmod 600 '{quoted}'");
    let mut child = Command::new("ssh")
        .args(ssh_opts(remote))
        .arg("--")
        .arg(ssh_target(remote))
        .arg(&remote_cmd)
        .stdin(Stdio::piped())
        .spawn()
        .with_context(|| format!("Failed to spawn ssh for {}", remote.name))?;

    {
        let mut input = child.stdin.take().context("no stdin")?;
        input
            .write_all(data)
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

/// Read a remote path via `ssh host "cat 'path'"`, returning its bytes.
/// The exit status is checked before the data is handed to the caller, so a
/// failed `cat` can never masquerade as an empty file.
fn ssh_read(remote: &Remote, remote_path: &str) -> Result<Vec<u8>> {
    let remote_cmd = format!("cat '{}'", sq(remote_path));
    let mut child = Command::new("ssh")
        .args(ssh_opts(remote))
        .arg("--")
        .arg(ssh_target(remote))
        .arg(&remote_cmd)
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("Failed to spawn ssh for {}", remote.name))?;

    let mut buf = Vec::new();
    child
        .stdout
        .take()
        .context("no stdout")?
        .read_to_end(&mut buf)
        .with_context(|| format!("Failed to read remote file from {}", remote.name))?;

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
    Ok(buf)
}

fn push_ssh(remote: &Remote, store_path: &Path, key_ciphertext: Option<&[u8]>) -> Result<()> {
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
    let store_data = fs::read(store_path)
        .with_context(|| format!("Cannot read {}", store_path.display()))?;
    ssh_put_bytes(remote, &store_data, &remote.path)?;
    eprintln!(
        "✓ Pushed encrypted store to '{}' → {}:{}",
        remote.name,
        ssh_target(remote),
        remote.path
    );

    if let Some(ciphertext) = key_ciphertext {
        let key_remote_path = key_backup_path(&remote.path);
        ssh_put_bytes(remote, ciphertext, &key_remote_path)?;
        eprintln!(
            "✓ Pushed passphrase-encrypted age key to '{}' → {}:{}",
            remote.name,
            ssh_target(remote),
            key_remote_path
        );
    }

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
    fn test_remote_validation() {
        let base = Remote {
            name: "nas".to_string(),
            remote_type: RemoteType::Ssh,
            host: "nas.local".to_string(),
            user: "backup".to_string(),
            port: None,
            path: "/volume1/vault/store.env.age".to_string(),
        };
        assert!(base.validate().is_ok());

        let mut r = base.clone();
        r.host = "-oProxyCommand=evil".to_string();
        assert!(r.validate().is_err());

        let mut r = base.clone();
        r.user = "user name".to_string();
        assert!(r.validate().is_err());

        let mut r = base.clone();
        r.host = "evil@host".to_string();
        assert!(r.validate().is_err());

        let mut r = base.clone();
        r.name = String::new();
        assert!(r.validate().is_err());

        let mut r = base;
        r.path = String::new();
        assert!(r.validate().is_err());
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