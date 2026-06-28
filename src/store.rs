use anyhow::{bail, Context, Result};
use age::{
    Decryptor, Encryptor,
    secrecy::ExposeSecret,
    x25519::{Identity, Recipient},
};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
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

        let encryptor = Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))?;
        let mut encrypted = Vec::new();
        let mut writer = encryptor.wrap_output(&mut encrypted)?;
        writer.write_all(plaintext.as_bytes())?;
        writer.finish()?;
        Ok(encrypted)
    }

    fn decrypt_to_string(&self) -> Result<String> {
        let identity = self.load_identity()?;
        let encrypted = fs::read(&self.store_path)
            .with_context(|| format!("Cannot read store at {}", self.store_path.display()))?;

        let decryptor = Decryptor::new_buffered(&encrypted[..])
            .map_err(|e| anyhow::anyhow!("Failed to create decryptor: {e}"))?;
        let mut reader = decryptor
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .map_err(|e| anyhow::anyhow!("Failed to decrypt store: {e}"))?;
        let mut plaintext = String::new();
        reader.read_to_string(&mut plaintext)?;
        Ok(plaintext)
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
        fs::write(&self.store_path, encrypted)
            .with_context(|| format!("Cannot write store to {}", self.store_path.display()))?;
        // Ensure store file is only readable by owner
        fs::set_permissions(&self.store_path, PermissionsExt::from_mode(0o600))?;
        Ok(())
    }

    fn ensure_init(&self) -> Result<()> {
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

        fs::create_dir_all(&self.dir)
            .with_context(|| format!("Cannot create directory {}", self.dir.display()))?;

        // Generate age identity
        let identity = Identity::generate();
        let recipient: Recipient = identity.to_public();

        // Save key file (identity + public key as comment)
        let secret_key = identity.to_string();
        let key_content = format!(
            "# Vault age identity key — keep this secret!\n# public key: {recipient}\n{}\n",
            secret_key.expose_secret()
        );
        fs::write(&self.key_path, key_content)?;
        fs::set_permissions(&self.key_path, PermissionsExt::from_mode(0o600))?;

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

        // Write to temp file with restricted permissions
        let tmp = std::env::temp_dir().join(format!("vault-edit-{}.env", std::process::id()));
        fs::write(&tmp, &content)?;
        fs::set_permissions(&tmp, PermissionsExt::from_mode(0o600))?;

        let original_content = content.clone();

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
            let _ = fs::remove_file(&tmp);
            bail!("Editor exited with non-zero status");
        }

        let new_content = fs::read_to_string(&tmp)?;
        let _ = fs::remove_file(&tmp);

        if new_content.trim() == original_content.trim() {
            eprintln!("No changes — store not updated.");
            return Ok(());
        }

        let new_map = Self::parse(&new_content);
        self.save(&new_map)?;

        eprintln!("✓ Store updated ({} secrets)", new_map.len());
        Ok(())
    }

    pub fn add(&self, key: &str, value: Option<String>) -> Result<()> {
        self.ensure_init()?;

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
}