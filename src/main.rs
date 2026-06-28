use anyhow::bail;
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};

mod remote;
mod store;

#[derive(Parser)]
#[command(
    name = "vault",
    version,
    about = "Encrypted secret manager with shell environment injection",
    long_about = "Stores secrets encrypted with age (X25519).\n\
                   Use `vault env` in your shell to inject secrets as env vars:\n\
                   \t eval \"$(vault env)\""
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize vault — generate age key and create empty store
    Init,

    /// Edit secrets in $EDITOR — re-encrypts on save
    Edit,

    /// Add or update a secret (prompts for value if not given)
    Add {
        /// Secret key name
        key: String,
        /// Secret value (if omitted, prompts interactively with hidden input)
        value: Option<String>,
    },

    /// Print a secret value to stdout
    Get {
        /// Secret key name
        key: String,
    },

    /// List all secret keys (values are not shown)
    List,

    /// Remove a secret
    Rm {
        /// Secret key name
        key: String,
    },

    /// Output `export KEY=VALUE` lines for shell sourcing
    Env,

    /// Print decrypted store contents (raw)
    Cat,

    /// Manage remote backup targets
    #[command(subcommand)]
    Remote(RemoteCmd),

    /// Push the encrypted store to one or all remotes
    Push {
        /// Remote name to push to. If omitted, pushes to all configured remotes.
        remote: Option<String>,
        /// Also push the age key file (needed to restore on a fresh machine).
        #[arg(long)]
        include_key: bool,
    },

    /// Pull the encrypted store from a remote, overwriting the local store
    Pull {
        /// Remote name to pull from.
        remote: String,
    },

    /// Generate shell completion script
    Completions {
        /// Shell to generate completions for
        shell: Shell,
    },

    /// Output configured remote names — used by shell completion (hidden)
    #[command(name = "__remotes", hide = true)]
    CompleteRemotes,
}

#[derive(Subcommand)]
enum RemoteCmd {
    /// Add a remote backup target
    Add {
        /// Name for this remote (e.g. "nas", "myserver")
        name: String,
        /// Remote type (ssh for now; ftp planned)
        #[arg(long, value_enum)]
        r#type: RemoteTypeArg,
        /// Remote host (e.g. example.com or 192.168.1.10)
        #[arg(long)]
        host: String,
        /// SSH/FTP user
        #[arg(long)]
        user: String,
        /// Port (default: 22 for ssh)
        #[arg(long)]
        port: Option<u16>,
        /// Absolute path on the remote where the encrypted store is stored
        #[arg(long)]
        path: String,
    },

    /// List configured remotes
    List,

    /// Remove a configured remote
    Rm {
        /// Remote name to remove
        name: String,
    },
}

#[derive(clap::ValueEnum, Clone, Copy)]
#[clap(rename_all = "lowercase")]
enum RemoteTypeArg {
    Ssh,
    Ftp,
}

impl From<RemoteTypeArg> for remote::RemoteType {
    fn from(t: RemoteTypeArg) -> Self {
        match t {
            RemoteTypeArg::Ssh => remote::RemoteType::Ssh,
            RemoteTypeArg::Ftp => remote::RemoteType::Ftp,
        }
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    // Handle completions before creating the store (no vault needed)
    if let Commands::Completions { shell } = cli.command {
        let mut cmd = Cli::command();
        let mut buf = Vec::new();
        generate(shell, &mut cmd, "vault", &mut buf);
        let out = String::from_utf8(buf)?;
        if shell == Shell::Zsh {
            print!("{}", patch_zsh_remote_completion(out));
        } else {
            print!("{out}");
        }
        return Ok(());
    }

    let store = store::Store::new()?;

    match cli.command {
        Commands::Init => store.init()?,
        Commands::Edit => store.edit()?,
        Commands::Add { key, value } => store.add(&key, value)?,
        Commands::Get { key } => store.get(&key)?,
        Commands::List => store.list()?,
        Commands::Rm { key } => store.remove(&key)?,
        Commands::Env => store.env()?,
        Commands::Cat => store.cat()?,
        Commands::Remote(cmd) => {
            // Ensure vault dir exists so remotes.toml can be written.
            std::fs::create_dir_all(store.dir())?;
            let mgr = remote::RemoteManager::new(store.remotes_config_path());
            handle_remote(mgr, store.dir(), cmd)?;
        }

        Commands::Push { remote, include_key } => {
            store.ensure_init()?;
            let mgr = remote::RemoteManager::new(store.remotes_config_path());
            handle_push(mgr, store.store_path(), store.key_path(), remote, include_key)?;
        }

        Commands::Pull { remote } => {
            store.ensure_init()?;
            let mgr = remote::RemoteManager::new(store.remotes_config_path());
            let r = mgr.find(&remote)?;
            remote::pull(&r, store.store_path())?;
        }

        Commands::Completions { .. } => unreachable!(),

        Commands::CompleteRemotes => {
            // No vault init required — remotes config may exist independently.
            let mgr = remote::RemoteManager::new(store.remotes_config_path());
            for r in mgr.load().unwrap_or_default() {
                println!("{}", r.name);
            }
        }
    }

    Ok(())
}

/// Patch generated zsh completion so that remote-name positionals
/// (`push`, `pull`, `remote rm`) complete from configured remotes.
fn patch_zsh_remote_completion(s: String) -> String {
    let names_fn = "\n_vault_remote_names() {\n    local -a names\n    names=(\"${(@f)$(vault __remotes 2>/dev/null)}\")\n    _describe -t remotes 'remote' names\n}\n";

    let s = s.replace(
        ":name -- Remote name to remove:_default'",
        ":name -- Remote name to remove:_vault_remote_names'",
    );
    let s = s.replace(
        "remotes:_default'",
        "remotes:_vault_remote_names'",
    );
    let s = s.replace(
        ":remote -- Remote name to pull from:_default'",
        ":remote -- Remote name to pull from:_vault_remote_names'",
    );

    // Inject the helper function near the top, after the initial header line.
    // clap_complete zsh output begins with '#compdef vault'; insert after it.
    if s.contains("_vault_remote_names") {
        if let Some(idx) = s.find('\n') {
            let (head, tail) = s.split_at(idx + 1);
            return format!("{head}{names_fn}{tail}");
        }
    }
    s
}

// ── Remote command handling ────────────────────────────────────────────

fn handle_remote(
    mgr: remote::RemoteManager,
    _vault_dir: &std::path::Path,
    cmd: RemoteCmd,
) -> anyhow::Result<()> {
    match cmd {
        RemoteCmd::Add { name, r#type, host, user, port, path } => {
            let r = remote::Remote {
                name: name.clone(),
                remote_type: r#type.into(),
                host,
                user,
                port,
                path,
            };
            mgr.add(r)?;
            eprintln!("✓ Added remote '{name}'");
            Ok(())
        }
        RemoteCmd::List => {
            let remotes = mgr.load()?;
            if remotes.is_empty() {
                eprintln!("No remotes configured. Add one with:");
                eprintln!("  vault remote add nas --type ssh --host nas.local \\\n    --user backup --path /volume1/vault/store.env.age");
                return Ok(());
            }
            eprintln!("{:<12} {:<6} {:<28} {:<6} PATH", "NAME", "TYPE", "HOST", "PORT");
            for r in &remotes {
                eprintln!(
                    "{:<12} {:<6} {:<28} {:<6} {}",
                    r.name, r.remote_type, r.host, port_label(r.port), r.path
                );
            }
            Ok(())
        }
        RemoteCmd::Rm { name } => {
            mgr.remove(&name)?;
            eprintln!("✓ Removed remote '{name}'");
            Ok(())
        }
    }
}

fn handle_push(
    mgr: remote::RemoteManager,
    store_path: &std::path::Path,
    key_path: &std::path::Path,
    name: Option<String>,
    include_key: bool,
) -> anyhow::Result<()> {
    let remotes = match &name {
        Some(n) => vec![mgr.find(n)?],
        None => {
            let all = mgr.load()?;
            if all.is_empty() {
                bail!("No remotes configured. Add one with `vault remote add`.");
            }
            all
        }
    };

    let mut errors = Vec::new();
    for r in &remotes {
        if let Err(e) = remote::push(r, store_path, key_path, include_key) {
            errors.push((r.name.clone(), e));
        }
    }

    if !errors.is_empty() {
        for (n, e) in &errors {
            eprintln!("✗ Failed to push to '{n}': {e}");
        }
        bail!("{} remote(s) failed", errors.len());
    }
    Ok(())
}

fn port_label(port: Option<u16>) -> String {
    match port {
        Some(p) => p.to_string(),
        None => "auto".to_string(),
    }
}