# vault

Encrypted secret manager with shell environment injection.

Stores secrets (API tokens, passwords, etc.) encrypted with [age](https://age-encryption.org) (X25519) and injects them into your shell environment.

## Features

- 🔒 **Encrypted at rest** — age X25519 encryption, key is `chmod 600`
- 📝 **Edit in $EDITOR** — `vault edit` opens nvim/vim/your editor, re-encrypts on save
- ⚡ **On-the-fly env updates** — zsh wrapper auto-reloads env after `edit`/`add`/`rm`
- 🚀 **No external deps** — pure Rust, age crate bundled, no `age` binary needed
- 🔑 **Hidden input** — `vault add KEY` prompts without echoing
- 📋 **Shell-safe** — values are properly single-quote escaped in `vault env`

## Build

```sh
cd /code/vault
cargo build --release
cp target/release/vault ~/.local/bin/
```

## Setup

### 1. Initialize vault

```sh
vault init
```

This generates an age keypair at `~/.local/share/vault/key.txt` and creates an empty encrypted store.

### 2. Add secrets

```sh
# Interactive (hidden input)
vault add OPENAI_API_KEY

# Or pass directly
vault add GITHUB_TOKEN ghp_xxxxxxxxxxxx
```

### 3. Edit all secrets at once

```sh
vault edit
```

Opens your `$EDITOR` with a decrypted temp file. Save and quit to re-encrypt.

### 4. zsh integration

Add to your `~/.config/zshrc.zsh`:

```zsh
[ -f "$HOME/.config/zsh/vault.zsh" ] && source "$HOME/.config/zsh/vault.zsh"
```

Or symlink:
```sh
ln -s /code/vault/zsh/vault.zsh ~/.config/zsh/vault.zsh
```

This gives you:
- Secrets loaded into env on shell startup
- `vault edit` → save in nvim → env **instantly updated**
- `vault add` / `vault rm` → env auto-reloads

## Commands

| Command | Description |
|---------|-------------|
| `vault init` | Initialize vault (generate key, create empty store) |
| `vault edit` | Open secrets in `$EDITOR`, re-encrypt on save |
| `vault add KEY [VALUE]` | Add/update a secret (prompts if value omitted) |
| `vault get KEY` | Print a secret value |
| `vault list` | List all secret keys (no values) |
| `vault rm KEY` | Remove a secret |
| `vault env` | Output `export KEY=VALUE` lines for shell sourcing |
| `vault cat` | Print decrypted store contents |

## How it works

```
~/.local/share/vault/
├── key.txt          # age identity key (chmod 600)
└── store.env.age    # encrypted KEY=VALUE store (chmod 600)
```

The zsh wrapper function shadows the `vault` binary. After mutating commands (`edit`, `add`, `rm`, `init`), it automatically runs `eval "$(vault env)"` to inject the updated secrets into the current shell's environment.

## Migration from plaintext .tokens

```sh
vault init
# For each key in your .tokens file:
vault add KEY value
# Then remove the plaintext file:
rm ~/.config/.tokens
# And remove the `source $HOME/.config/.tokens` line from zshrc
```