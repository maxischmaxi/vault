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
| `vault remote add NAME --type ssh --host H --user U --path P [--port N]` | Add a remote backup target |
| `vault remote list` | List configured remotes |
| `vault remote rm NAME` | Remove a remote |
| `vault push [REMOTE] [--include-key]` | Push encrypted store to one or all remotes |
| `vault pull REMOTE` | Pull & restore the encrypted store from a remote |

## How it works

```
~/.local/share/vault/
├── key.txt          # age identity key (chmod 600)
├── store.env.age    # encrypted KEY=VALUE store (chmod 600)
└── remotes.toml     # remote backup target definitions
```

The zsh wrapper function shadows the `vault` binary. After mutating commands (`edit`, `add`, `rm`, `init`, `pull`), it automatically runs `eval "$(vault env)"` to inject the updated secrets into the current shell's environment.

## Remote backups

Vault can push the encrypted store to one or more remote machines over SSH.
The store is already encrypted with age, so the remote only ever sees ciphertext.

### 1. Define a remote

```sh
vault remote add nas --type ssh \
  --host nas.local \
  --user backup \
  --path /volume1/vault/store.env.age
```

Options:
- `--type ssh` (FTP planned but not yet implemented)
- `--host` — hostname or `~/.ssh/config` Host alias
- `--user` — remote user
- `--path` — absolute path on the remote where the encrypted store is stored
- `--port N` — optional; if omitted, ssh uses its defaults / `~/.ssh/config`

You can define multiple remotes:

```sh
vault remote add vps --type ssh --host myvps.example.com --user maxi --path /home/maxi/vault/store.env.age
vault remote list
```

### 2. Push

```sh
# Push to all configured remotes
vault push

# Push to a specific remote
vault push nas

# Also back up the age key (needed to restore on a fresh machine — keep safe!)
vault push --include-key
```

Vault uses `ssh` (with `BatchMode=yes`) and pipes the file via `ssh host "cat > path"`,
so it relies on your existing SSH keys / `~/.ssh/config` — no passwords, no extra deps.

### 3. Pull (restore)

```sh
# Restore the encrypted store from a remote, overwriting the local copy
vault pull nas
```

After a `pull`, the zsh wrapper automatically reloads the env.

### Disaster recovery

If your machine dies, restore on a fresh box:

```sh
vault init                      # creates a new key + empty store
# pull the backed-up key + store, then overwrite:
vault pull nas                  # overwrites store with the remote copy
# if you backed up the key with --include-key, restore it manually:
scp nas:/volume1/vault/store.env.age.key ~/.local/share/vault/key.txt
chmod 600 ~/.local/share/vault/key.txt
vault list                      # secrets are back
```

## Migration from plaintext .tokens

```sh
vault init
# For each key in your .tokens file:
vault add KEY value
# Then remove the plaintext file:
rm ~/.config/.tokens
# And remove the `source $HOME/.config/.tokens` line from zshrc
```