# Vault — zsh integration
# Source this from your zshrc:
#   [ -f "$HOME/.config/zsh/vault.zsh" ] && source "$HOME/.config/zsh/vault.zsh"

# Binary path — adjust if installed elsewhere
VAULT_BIN="${HOME}/.local/bin/vault"

if [[ ! -x "$VAULT_BIN" ]]; then
    # Try PATH fallback
    if command -v vault &>/dev/null; then
        VAULT_BIN=$(command -v vault)
    else
        return 0  # vault not installed — skip silently
    fi
fi

# ── Wrapper function ───────────────────────────────────────────────────
# After any mutating command (edit/add/rm/init), automatically reload
# secrets into the current shell environment. This gives you on-the-fly
# updates: edit in vim → save → env is instantly updated.
vault() {
    "$VAULT_BIN" "$@"
    local ret=$?
    case "$1" in
        edit|add|rm|init)
            eval "$("$VAULT_BIN" env 2>/dev/null)"
            ;;
    esac
    return $ret
}

# ── Load secrets on shell startup ──────────────────────────────────────
eval "$("$VAULT_BIN" env 2>/dev/null)"