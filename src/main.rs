use clap::{Parser, Subcommand};

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
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
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
    }

    Ok(())
}