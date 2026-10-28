# Usage

```sh
keyring --help
keyring version
keyring --list-backends
keyring diagnose

# Linux: run the built-in Secret Service provider (starts locked).
keyring service
keyring service --replace

# Enroll and manage WebAuthn PRF security keys.
keyring enroll --label primary-yubikey
keyring enroll --add-key --label backup-yubikey
keyring enroll --list
keyring enroll --revoke <id>
keyring enroll --recover --label replacement-yubikey

# Unlock through a browser over an SSH local-forward, or with Recovery Key.
keyring unlock
keyring unlock --port 42317 --timeout 180
keyring unlock --recover

# Immediately clear the in-memory vault key.
keyring lock

# Prompt for a password and store it; exits 0 on success.
keyring set my-service alice

# Store a password from stdin; exits 0 on success.
echo TOKEN | keyring set my-service alice

# Print the password with no trailing newline; exits 3 when not found.
keyring get my-service alice

# Delete an entry; exits 3 when not found.
keyring del my-service alice

# Use a one-shot backend override.
keyring -b null get my-service alice
keyring -b secret_service set my-service alice
keyring -b ado get https://pkgs.dev.azure.com/myorg/_packaging/feed/pypi/simple/ VssSessionToken

# Export Azure CLI cache or GitHub CLI credentials for a headless machine.
keyring az export /tmp/az-export
keyring gh export /tmp/gh-export

# Authenticate with GitHub (github.com, *.ghe.com data residency, or GHES) and configure Git.
keyring gh login
keyring gh login -h example.ghe.com
keyring gh login --hostname example.ghe.com --device
keyring git config
keyring git config -h example.ghe.com

# Import GitHub CLI credentials into the OS keyring (from dir, file, stdin, or local hosts.yml).
keyring gh import /tmp/gh-export
keyring gh import
ssh vm 'cat ~/.config/gh/hosts.yml' | keyring gh import -

# Authenticate Azure Artifacts npm feeds from .npmrc and update ~/.npmrc.
keyring devops-npm
keyring devops-npm -c path/to/.npmrc -f
keyring devops-npm --validate-only

# Disable storage for this process.
keyring --disable
keyring --disable get my-service alice
```

## Backends

Backends are `secret_service`, `keychain`, `win_credential`, `file`, `ado`, and
`null_backend` (`null` is accepted as an alias for `null_backend`).

The `file` backend comes from the upstream keyring-zig package and stores
encrypted credentials on disk, which is useful when no secret-service daemon is
available. See [Headless Linux](headless-linux.md).

The Linux-only built-in service stores encrypted items in `vault.json` and is unlocked through WebAuthn PRF or the one-time Recovery Key. See [Hardware-backed unlocking over SSH](headless-linux.md#hardware-backed-unlocking-over-ssh).

## Git credential helper (`keyring git credential`)

`keyring git credential <get|store|erase>` (or invoking the binary via a `git-credential-keyring` symlink) implements the Git credential helper protocol over HTTPS for `github.com`, GitHub Enterprise Cloud with data residency (`*.ghe.com`, resolving REST calls to `https://api.<tenant>.ghe.com/user`), GitHub Enterprise Server, Azure DevOps (`dev.azure.com` and `*.visualstudio.com`), and generic HTTPS hosts stored in the active `keyring` backend.

Run `keyring git config` to configure `keyring` globally as your Git credential helper, or `keyring git config --hostname example.ghe.com` (`-h example.ghe.com`) to scope it to a specific host. When multiple GitHub accounts are stored in `gh:<host>` and `~/.config/gh/hosts.yml`, specifying a username in the remote URL (such as `https://alice@github.com/owner/repo.git`) or `credential.<url>.username` selects that account directly; otherwise the active `gh` user for that host is used, or an interactive OAuth login is initiated on demand.

See also [Environment variables](environment-variables.md) and
[Exit codes](exit-codes.md).
