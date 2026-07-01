use anyhow::{bail, Context, Result};
use age::{
    Decryptor, Encryptor,
    secrecy::{ExposeSecret, SecretString},
    x25519::{Identity, Recipient},
};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct Store {
    dir: PathBuf,
    key_path: PathBuf,
    store_path: PathBuf,
}

impl Store {
    pub fn new() -> Result<Self> {
        let dir = dirs::data_local_dir()
            .or_else(dirs::home_dir)
            .context("Cannot find home directory")?
            .join("vault");
        Ok(Self {
            key_path: dir.join("key.txt"),
            store_path: dir.join("store.env.age"),
            dir,
        })
    }

    /// Directory holding vault data (key, store, remotes config).
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Path to the encrypted store.
    pub fn store_path(&self) -> &Path {
        &self.store_path
    }

    /// Path to the age identity key.
    pub fn key_path(&self) -> &Path {
        &self.key_path
    }

    /// Path to the remotes configuration file.
    pub fn remotes_config_path(&self) -> PathBuf {
        self.dir.join("remotes.toml")
    }

    /// Create the vault directory owner-only (0700) if it doesn't exist yet.
    pub fn ensure_dir(&self) -> Result<()> {
        if !self.dir.exists() {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&self.dir)
                .with_context(|| format!("Cannot create directory {}", self.dir.display()))?;
        }
        Ok(())
    }

    // ── Key / crypto helpers ───────────────────────────────────────────

    fn load_identity(&self) -> Result<Identity> {
        let key_str = fs::read_to_string(&self.key_path)
            .with_context(|| format!("Cannot read key at {}", self.key_path.display()))?;
        let key_line = key_str
            .lines()
            .find(|l| l.starts_with("AGE-SECRET-KEY-"))
            .context("Invalid key file — no AGE-SECRET-KEY line found")?;
        key_line
            .parse::<Identity>()
            .map_err(|e| anyhow::anyhow!("Invalid age identity: {e}"))
    }

    fn encrypt(&self, plaintext: &str) -> Result<Vec<u8>> {
        let identity = self.load_identity()?;
        let recipient: Recipient = identity.to_public();
        age_encrypt(&recipient as &dyn age::Recipient, plaintext.as_bytes())
    }

    fn decrypt_file_to_string(&self, path: &Path) -> Result<String> {
        let identity = self.load_identity()?;
        let encrypted = fs::read(path)
            .with_context(|| format!("Cannot read store at {}", path.display()))?;
        let plaintext = age_decrypt(&identity as &dyn age::Identity, &encrypted)
            .map_err(|e| anyhow::anyhow!("Failed to decrypt store: {e}"))?;
        String::from_utf8(plaintext).context("Decrypted store is not valid UTF-8")
    }

    fn decrypt_to_string(&self) -> Result<String> {
        self.decrypt_file_to_string(&self.store_path)
    }

    /// Check that a file is an age ciphertext decryptable with the local identity.
    pub fn verify_encrypted_file(&self, path: &Path) -> Result<()> {
        self.decrypt_file_to_string(path).map(|_| ())
    }

    /// Encrypt the local key file with a passphrase (age scrypt) for remote backup.
    pub fn export_key_encrypted(&self, passphrase: SecretString) -> Result<Vec<u8>> {
        let key_bytes = fs::read(&self.key_path)
            .with_context(|| format!("Cannot read key at {}", self.key_path.display()))?;
        let recipient = age::scrypt::Recipient::new(passphrase);
        age_encrypt(&recipient as &dyn age::Recipient, &key_bytes)
    }

    /// Decrypt a passphrase-protected key backup and install it as key.txt.
    /// Refuses to overwrite an existing key.
    pub fn import_key_encrypted(&self, ciphertext: &[u8], passphrase: SecretString) -> Result<()> {
        if self.key_path.exists() {
            bail!(
                "A key already exists at {} — move it away first, then retry.",
                self.key_path.display()
            );
        }
        let identity = age::scrypt::Identity::new(passphrase);
        let plaintext = age_decrypt(&identity as &dyn age::Identity, ciphertext)
            .map_err(|e| anyhow::anyhow!("Failed to decrypt key backup (wrong passphrase?): {e}"))?;
        let text = String::from_utf8(plaintext).context("Decrypted key is not valid UTF-8")?;
        if !text.lines().any(|l| l.starts_with("AGE-SECRET-KEY-")) {
            bail!("Decrypted backup contains no AGE-SECRET-KEY line — refusing to install");
        }
        self.ensure_dir()?;
        write_private(&self.key_path, text.as_bytes())?;
        Ok(())
    }

    // ── .env parsing / serialization ───────────────────────────────────

    fn parse(content: &str) -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim().to_string();
                let value = value.trim().to_string();
                if !key.is_empty() {
                    map.insert(key, value);
                }
            }
        }
        map
    }

    fn serialize(map: &BTreeMap<String, String>) -> String {
        let mut out = String::new();
        out.push_str("# Vault secrets — edit this file, save to encrypt.\n");
        out.push_str("# Format: KEY=value  (one per line, lines starting with # are ignored)\n\n");
        for (key, value) in map {
            out.push_str(&format!("{key}={value}\n"));
        }
        if map.is_empty() {
            out.push_str("# No secrets yet. Add lines like:\n");
            out.push_str("# OPENAI_API_KEY=sk-...\n");
        }
        out
    }

    fn load(&self) -> Result<BTreeMap<String, String>> {
        if !self.store_path.exists() {
            return Ok(BTreeMap::new());
        }
        let plaintext = self.decrypt_to_string()?;
        Ok(Self::parse(&plaintext))
    }

    fn save(&self, map: &BTreeMap<String, String>) -> Result<()> {
        let plaintext = Self::serialize(map);
        let encrypted = self.encrypt(&plaintext)?;
        // Temp file + rename: a crash mid-write can never leave a truncated store.
        let tmp = self.dir.join(format!("store.env.age.tmp-{}", std::process::id()));
        write_private(&tmp, &encrypted)?;
        fs::rename(&tmp, &self.store_path)
            .with_context(|| format!("Cannot write store to {}", self.store_path.display()))?;
        Ok(())
    }

    pub fn ensure_init(&self) -> Result<()> {
        if !self.key_path.exists() {
            bail!("Vault not initialized. Run: vault init");
        }
        Ok(())
    }

    // ── Commands ───────────────────────────────────────────────────────

    pub fn init(&self) -> Result<()> {
        if self.key_path.exists() {
            bail!("Vault already initialized at {}", self.dir.display());
        }

        self.ensure_dir()?;

        // Generate age identity
        let identity = Identity::generate();
        let recipient: Recipient = identity.to_public();

        // Save key file (identity + public key as comment)
        let secret_key = identity.to_string();
        let key_content = format!(
            "# Vault age identity key — keep this secret!\n# public key: {recipient}\n{}\n",
            secret_key.expose_secret()
        );
        write_private(&self.key_path, key_content.as_bytes())?;

        // Create empty encrypted store
        self.save(&BTreeMap::new())?;

        eprintln!("✓ Vault initialized");
        eprintln!("  Location:   {}", self.dir.display());
        eprintln!("  Public key: {recipient}");
        eprintln!();
        eprintln!("  Next steps:");
        eprintln!("    vault add OPENAI_API_KEY sk-...");
        eprintln!("    vault edit              # open in $EDITOR");
        eprintln!(
            "    eval \"$(vault env)\"    # inject into shell",
        );
        Ok(())
    }

    pub fn edit(&self) -> Result<()> {
        self.ensure_init()?;

        let map = self.load()?;
        let content = Self::serialize(&map);

        // Plaintext goes to XDG_RUNTIME_DIR when available: tmpfs, mode 0700,
        // cleared on logout — nothing persists on disk or survives a crash.
        let tmp_dir = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .filter(|p| p.is_dir())
            .unwrap_or_else(std::env::temp_dir);
        let tmp = tmp_dir.join(format!("vault-edit-{}.env", std::process::id()));
        write_private(&tmp, content.as_bytes())?;
        let _guard = RemoveOnDrop(tmp.clone());

        let original_content = content;

        // Open $EDITOR (or $VISUAL, fallback vi)
        let editor = std::env::var("EDITOR")
            .or_else(|_| std::env::var("VISUAL"))
            .unwrap_or_else(|_| "vi".to_string());

        // Support editors with arguments (e.g. "nvim -p")
        let mut cmd = Command::new("sh");
        cmd.args(["-c", &format!("{} '{}'", editor, tmp.display())]);

        let status = cmd
            .status()
            .with_context(|| format!("Failed to launch editor: {editor}"))?;

        if !status.success() {
            bail!("Editor exited with non-zero status");
        }

        let new_content = fs::read_to_string(&tmp)?;

        if new_content.trim() == original_content.trim() {
            eprintln!("No changes — store not updated.");
            return Ok(());
        }

        let dropped = Self::count_dropped_lines(&new_content);
        if dropped > 0 {
            eprintln!("⚠ {dropped} line(s) without KEY=VALUE were ignored and not saved.");
        }

        let new_map = Self::parse(&new_content);
        self.save(&new_map)?;

        eprintln!("✓ Store updated ({} secrets)", new_map.len());
        Ok(())
    }

    /// Lines that are neither empty, comments, nor KEY=VALUE — parse() drops them.
    fn count_dropped_lines(content: &str) -> usize {
        content
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .filter(|l| match l.split_once('=') {
                Some((key, _)) => key.trim().is_empty(),
                None => true,
            })
            .count()
    }

    pub fn add(&self, key: &str, value: Option<String>) -> Result<()> {
        self.ensure_init()?;

        if !is_valid_env_key(key) {
            bail!(
                "Invalid key '{key}' — use letters, digits and underscores, not starting with a digit"
            );
        }

        let value = match value {
            Some(v) => v,
            None => {
                eprint!("Enter value for {key}: ");
                std::io::stderr().flush()?;
                rpassword::read_password()?
            }
        };

        let mut map = self.load()?;
        let existed = map.contains_key(key);
        map.insert(key.to_string(), value);
        self.save(&map)?;

        if existed {
            eprintln!("✓ Updated '{key}'");
        } else {
            eprintln!("✓ Added '{key}'");
        }
        Ok(())
    }

    pub fn get(&self, key: &str) -> Result<()> {
        self.ensure_init()?;
        let map = self.load()?;
        match map.get(key) {
            Some(value) => println!("{value}"),
            None => bail!("Key '{key}' not found"),
        }
        Ok(())
    }

    pub fn list(&self) -> Result<()> {
        self.ensure_init()?;
        let map = self.load()?;
        if map.is_empty() {
            eprintln!("No secrets stored. Use `vault add` or `vault edit`.");
            return Ok(());
        }
        for key in map.keys() {
            println!("{key}");
        }
        Ok(())
    }

    pub fn remove(&self, key: &str) -> Result<()> {
        self.ensure_init()?;
        let mut map = self.load()?;
        if map.remove(key).is_none() {
            bail!("Key '{key}' not found");
        }
        self.save(&map)?;
        eprintln!("✓ Removed '{key}'");
        Ok(())
    }

    pub fn env(&self) -> Result<()> {
        if !self.store_path.exists() {
            return Ok(());
        }
        let map = self.load()?;
        for (key, value) in &map {
            if !is_valid_env_key(key) {
                eprintln!("⚠ Skipping '{key}' — not a valid environment variable name");
                continue;
            }
            println!("export {key}={}", shell_quote(value));
        }
        Ok(())
    }

    pub fn cat(&self) -> Result<()> {
        self.ensure_init()?;
        let plaintext = self.decrypt_to_string()?;
        print!("{plaintext}");
        Ok(())
    }
}

// ── File / crypto primitives ───────────────────────────────────────────

/// Write a file that is owner-only (0600) from the moment it exists —
/// avoids the write-then-chmod window where the default umask applies.
/// Removing first drops any pre-planted file or symlink; create_new (O_EXCL)
/// never follows symlinks.
pub(crate) fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let _ = fs::remove_file(path);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("Cannot create {}", path.display()))?;
    f.write_all(data)?;
    Ok(())
}

/// Removes the wrapped path on drop — cleans up the plaintext temp file on
/// every exit path of edit(), including errors.
struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// Keys must be valid shell identifiers — `vault env` output is eval'd on
/// shell startup, so anything else could smuggle shell syntax into it.
fn is_valid_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn age_encrypt(recipient: &dyn age::Recipient, data: &[u8]) -> Result<Vec<u8>> {
    let encryptor = Encryptor::with_recipients(std::iter::once(recipient))?;
    let mut encrypted = Vec::new();
    let mut writer = encryptor.wrap_output(&mut encrypted)?;
    writer.write_all(data)?;
    writer.finish()?;
    Ok(encrypted)
}

fn age_decrypt(identity: &dyn age::Identity, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let decryptor = Decryptor::new_buffered(ciphertext)
        .map_err(|e| anyhow::anyhow!("Not a valid age file: {e}"))?;
    let mut reader = decryptor
        .decrypt(std::iter::once(identity))
        .map_err(|e| anyhow::anyhow!("Decryption failed: {e}"))?;
    let mut plaintext = Vec::new();
    reader.read_to_end(&mut plaintext)?;
    Ok(plaintext)
}

/// Single-quote a string for safe shell usage.
/// Escapes embedded single quotes using the shell idiom.
fn shell_quote(s: &str) -> String {
    const SQ: char = char::from_u32(0x27).unwrap();
    const BS: char = char::from_u32(0x5c).unwrap();
    const US: char = char::from_u32(0x5f).unwrap();

    if s.is_empty() {
        let mut empty = String::new();
        empty.push(SQ);
        empty.push(SQ);
        return empty;
    }
    if s.chars().all(|c| c.is_ascii_alphanumeric() || c == US || c == char::from_u32(0x2d).unwrap() || c == char::from_u32(0x2e).unwrap() || c == char::from_u32(0x2f).unwrap() || c == char::from_u32(0x3a).unwrap() || c == char::from_u32(0x2b).unwrap() || c == char::from_u32(0x40).unwrap()) {
        return s.to_string();
    }
    let mut result = String::new();
    result.push(SQ);
    for c in s.chars() {
        if c == SQ {
            result.push(SQ);
            result.push(BS);
            result.push(SQ);
            result.push(SQ);
        } else {
            result.push(c);
        }
    }
    result.push(SQ);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shell_quote() {
        let sq = char::from_u32(0x27).unwrap();
        let sqs = format!("{sq}{sq}");

        // safe strings pass through unquoted
        assert_eq!(shell_quote("simple"), "simple");
        assert_eq!(shell_quote("sk-abc123"), "sk-abc123");

        // strings with spaces get quoted
        let expected = format!("{sq}hello world{sq}");
        assert_eq!(shell_quote("hello world"), expected);

        // strings with single quotes get escaped
        let input = format!("it{sq}s");
        let expected = format!("{sq}it{sq}\\{sq}{sq}s{sq}");
        assert_eq!(shell_quote(&input), expected);

        // empty string
        assert_eq!(shell_quote(""), sqs);
    }

    #[test]
    fn test_parse() {
        let content = "FOO=bar\n# comment\nBAZ=qux\n\nEMPTY=\n";
        let map = Store::parse(content);
        assert_eq!(map.get("FOO").unwrap(), "bar");
        assert_eq!(map.get("BAZ").unwrap(), "qux");
        assert_eq!(map.get("EMPTY").unwrap(), "");
        assert_eq!(map.len(), 3);
    }

    #[test]
    fn test_is_valid_env_key() {
        assert!(is_valid_env_key("FOO"));
        assert!(is_valid_env_key("_FOO"));
        assert!(is_valid_env_key("TF_VAR_hcloud_token"));
        assert!(!is_valid_env_key(""));
        assert!(!is_valid_env_key("1FOO"));
        assert!(!is_valid_env_key("FOO-BAR"));
        assert!(!is_valid_env_key("FOO BAR"));
        assert!(!is_valid_env_key("FOO$(x)"));
        assert!(!is_valid_env_key("FOO;rm"));
    }

    #[test]
    fn test_count_dropped_lines() {
        let content = "FOO=bar\n# comment\n\noops no equals\n=no key\nBAZ=qux\n";
        assert_eq!(Store::count_dropped_lines(content), 2);
        assert_eq!(Store::count_dropped_lines("FOO=bar\n"), 0);
    }

    #[test]
    fn test_scrypt_roundtrip() {
        let recipient = age::scrypt::Recipient::new(String::from("test-pass").into());
        let ct = age_encrypt(&recipient as &dyn age::Recipient, b"AGE-SECRET-KEY-TEST").unwrap();

        let identity = age::scrypt::Identity::new(String::from("test-pass").into());
        let pt = age_decrypt(&identity as &dyn age::Identity, &ct).unwrap();
        assert_eq!(pt, b"AGE-SECRET-KEY-TEST");

        let wrong = age::scrypt::Identity::new(String::from("wrong").into());
        assert!(age_decrypt(&wrong as &dyn age::Identity, &ct).is_err());
    }
}