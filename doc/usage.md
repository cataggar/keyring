# Usage

```sh
keyring --help
keyring version
keyring --list-backends
keyring diagnose

# Linux: run or manage the built-in Secret Service provider (starts locked).
keyring service
keyring service --replace --lock-timeout 3600
keyring service install
keyring service status
keyring service uninstall

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
keyring gh login -h example.ghe.com -s "repo read:org" -w
keyring gh login --hostname example.ghe.com --scopes "repo read:packages" --device
keyring git config
keyring git config -h example.ghe.com
keyring git config -h example.ghe.com -g

# Authenticate Azure DevOps before noninteractive Git operations.
keyring ado login --hostname example.visualstudio.com
keyring ado login --hostname https://dev.azure.com/example

# Import GitHub CLI credentials into the OS keyring (from dir, file, stdin, or local hosts.yml).
keyring gh import /tmp/gh-export
keyring gh import
ssh vm 'cat ~/.config/gh/hosts.yml' | keyring gh import -

# Authenticate Azure Artifacts npm feeds from .npmrc and update ~/.npmrc.
keyring devops-npm
keyring devops-npm -c path/to/.npmrc -f
keyring devops-npm --config-file path/to/.npmrc --validate-only

# Authenticate container registries for Podman Desktop and Podman CLI.
keyring podman login ghcr.io myregistry.azurecr.io
keyring podman login -f
keyring podman config ghcr.io myregistry.azurecr.io
keyring podman status
keyring podman logout myregistry.azurecr.io

# Authenticate container registries for wslc (GHCR, Azure Container Registry, generic).
keyring wslc login ghcr.io myregistry.azurecr.io
keyring wslc login -f
keyring wslc status
keyring wslc logout myregistry.azurecr.io

# Manage GitHub Copilot CLI credentials in the OS keyring.
keyring copilot login
keyring copilot status
keyring copilot token
eval "$(keyring copilot env)"
keyring copilot import
ssh vm 'cat ~/.copilot/config.json' | keyring copilot import -
keyring copilot export /tmp/copilot-export
keyring copilot logout

# Disable storage for this process.
keyring --disable
keyring --disable get my-service alice
```

## Backends

Backends are `secret_service`, `keychain`, `win_credential`, `file`, `ado`
(`azure_devops` is accepted as an alias), and `null_backend` (`null` is accepted
as an alias for `null_backend`).

The `file` backend comes from the upstream keyring-zig package and stores
encrypted credentials on disk, which is useful when no secret-service daemon is
available. See [Headless Linux](headless-linux.md).

The Linux-only built-in service stores encrypted items in `vault.json` and is unlocked through WebAuthn PRF or the one-time Recovery Key. See [Hardware-backed unlocking over SSH](headless-linux.md#hardware-backed-unlocking-over-ssh).

Typed credential providers layer target normalization, `get`/`login`/`logout` lifecycle, interaction policy, and expiry semantics over encrypted persistence backends; see [Credential provider contract](credential-provider.md).

## GitHub login and Git credential helper (`keyring gh` and `keyring git`)

`keyring gh login [-h|--hostname <host>] [-s|--scopes <scopes>] [-w|--web | --device]` authenticates to `github.com`, GitHub Enterprise Cloud with data residency (`*.ghe.com`), or GitHub Enterprise Server, storing OAuth tokens in the OS keyring (`gh:<host>`) and updating `hosts.yml` (`$GH_CONFIG_DIR/hosts.yml` or `~/.config/gh/hosts.yml`). Use `-s` / `--scopes <scopes>` to request custom OAuth scopes (default `repo read:org gist workflow`), and `-w` / `--web` or `--device` to select browser PKCE vs. device-code login explicitly.

`keyring git credential <get|store|erase>` (or invoking the binary via a `git-credential-keyring` symlink) implements the Git credential helper protocol over HTTPS for `github.com`, GitHub Enterprise Cloud with data residency (`*.ghe.com`, resolving REST calls to `https://api.<tenant>.ghe.com/user`), GitHub Enterprise Server, Azure DevOps (`dev.azure.com` and `*.visualstudio.com`), and generic HTTPS hosts stored in the active `keyring` backend.

Run `keyring git config` to configure `keyring` globally as your Git credential helper, or `keyring git config --hostname example.ghe.com` (`-h example.ghe.com`) to scope it to a specific host. When multiple GitHub accounts are stored in `gh:<host>` and `~/.config/gh/hosts.yml`, specifying a username in the remote URL (such as `https://alice@github.com/owner/repo.git`) or `credential.<url>.username` selects that account directly; otherwise the active `gh` user for that host is used, or an interactive OAuth login is initiated on demand.

`-g` is a short alias for `--global` (the default). Use `--local` to configure
only the current repository; when multiple scope flags are given, the last wins.

## Azure DevOps (`keyring ado login` and `keyring devops-npm`)

- `keyring ado login -h|--hostname <org>.visualstudio.com|https://dev.azure.com/<org>` authenticates and verifies organization access before noninteractive Git operations.
- `keyring devops-npm [-c|--config-file <path>] [-f|--force] [--validate-only]` discovers Azure Artifacts npm registries in a workspace `.npmrc` (or `--config-file <path>` / `--config-file=<path>`) and writes `//<registry>:_authToken=<token>` entries into `~/.npmrc` (or `$NPM_CONFIG_USERCONFIG`). In CI/CD pipelines, `SYSTEM_ACCESSTOKEN` and `AZURE_DEVOPS_EXT_PAT` are checked first before consulting cached `ado` / MSAL credentials or interactive browser OAuth. See [Azure DevOps feeds](azure-devops.md).

## WSL Container CLI (`keyring wslc`)

`keyring wslc` manages container registry credentials for Microsoft's WSL Container CLI (`wslc`):

- `keyring wslc login [<server>...] [-u|--username <user>] [--password-stdin] [-f|--force]` resolves credentials for GitHub Container Registry (`ghcr.io`, `containers.<tenant>.ghe.com`, requesting `read:packages` and `write:packages` OAuth scopes when authenticating interactively), Azure Container Registry (`<name>.azurecr.io`, discovering the registry's Microsoft Entra tenant via `/v2/` when available and exchanging an Entra ARM token from `az login` MSAL SSO or `ado-keyring` via `POST /oauth2/exchange`), or generic registries (`--username <user> --password-stdin` or refreshing existing `keyring` entries), and writes them directly into `wslc`'s configured `credentialStore` (`wincred` `wslc-credential/<server>` by default, or `%LOCALAPPDATA%\wslc\registry-credentials.json` when `credentialStore: file` is set in `%LOCALAPPDATA%\wslc\settings.yaml`). Passing `-f` / `--force` re-authenticates GHCR via OAuth with package scopes, bypasses cached ACR/ARM tokens, and refreshes generic or ACR repository-token secrets from `keyring`. Running `keyring wslc login` without arguments refreshes all registries currently present in `wslc` storage.
- `keyring wslc logout <server>...` removes the selected registry entry from `wslc` storage without revoking shared `gh` or Entra tokens.
- `keyring wslc status` reports `wslc`'s `settings.yaml` path, active `credentialStore` mode, and configured registries (including ACR JWT expiration status).
- `keyring wslc credential <get|store|erase>` provides a strictly noninteractive credential-helper protocol endpoint over `stdin`/`stdout`.

## Podman Desktop and Podman (`keyring podman`)

`keyring podman` and `docker-credential-keyring` authenticate **Podman Desktop** and **Podman CLI** (`podman`, `podman.exe`, `buildah`, `skopeo`) across GitHub Container Registry (`ghcr.io`, `containers.<tenant>.ghe.com`, `docker.<ghes>`), Azure Container Registry (`*.azurecr.io`), Docker Hub (`docker.io`), and generic OCI registries:

- `keyring podman login [<server>...] [-u|--username <user>] [--password-stdin] [-f|--force] [--helper-only | --auths-only] [--authfile <path>]` writes both `"auths"` (required by Podman Desktop) and `"credHelpers"` (checked first by Podman CLI for dynamic token refresh) to `auth.json` by default, provisions `docker-credential-keyring` onto `PATH`, and refreshes all configured bare registries when called with no `<server>` arguments. Use `--helper-only` to omit `"auths"` secrets or `--auths-only` to skip `"credHelpers"`.
- `keyring podman config <server>... [--authfile <path>]` registers `"credHelpers": { "<host>": "keyring" }` and provisions `docker-credential-keyring` on `PATH` without writing secrets to `auth.json`.
- `keyring podman logout [<server>...] [--all] [--authfile <path>]` removes matching `"auths"` and owned `"credHelpers"` entries from `auth.json` (and deletes stored generic registry credentials) without revoking shared `gh` or Entra tokens.
- `keyring podman status [--authfile <path>]` reports `auth.json` paths, `docker-credential-keyring` `PATH` status, configured registries, and ACR JWT expiration status.
- `keyring podman credential <get|store|erase|list|version>` (or invoking `docker-credential-keyring`) speaks the noninteractive Docker credential-helper protocol over `stdin`/`stdout`.

See [Podman Desktop and Podman](podman.md) for Windows WinGet + WSL 2 setup, platform `auth.json` paths, `ghr` helper provisioning, and Podman Desktop file-watcher notes.

## GitHub Copilot CLI (`keyring copilot`)

`keyring copilot` manages GitHub Copilot CLI (`copilot`) credentials across Windows Credential Manager, macOS Keychain, Linux Secret Service (`org.freedesktop.secrets`), and WSL (`ghr link cataggar/keyring`):

- `keyring copilot login [-h|--hostname <host>] [-u|--user|--username <login>] [--web|--device] [-f|--force]` resolves or acquires a GitHub token, writes it to the OS keyring in Copilot CLI's native format, updates `loggedInUsers` and `lastLoggedInUser` in `~/.copilot/config.json` (`$COPILOT_HOME/config.json`), and scrubs any matching plaintext `copilotTokens` entry.
- `keyring copilot logout [-h|--hostname <host>] [-u|--user|--username <login> | --all]` removes stored Copilot CLI credentials for the target account (or `--all` accounts) without revoking shared `gh` tokens.
- `keyring copilot status` reports the resolved `config.json` path, configured accounts, and whether tokens are stored in the OS keyring or plaintext `copilotTokens` (`keyring diagnose` also reports Copilot CLI config and vault status when `~/.copilot/config.json` exists).
- `keyring copilot token [-h|--hostname <host>] [-u|--user|--username <login>]` prints the stored Copilot CLI token for the selected or active account.
- `keyring copilot env [-h|--hostname <host>] [-u|--user|--username <login>] [--shell <sh|pwsh|cmd|fish>]` prints shell exports setting `COPILOT_GITHUB_TOKEN` without writing secrets to disk.
- `keyring copilot import [<dir-or-file|->]` migrates plaintext `copilotTokens` from `config.json` into the OS keyring (scrubbing `config.json` in place), imports an exported bundle or file, or reads JSON/JSONC from `stdin` when `-` is passed.
- `keyring copilot export <dir>` exports Copilot CLI credentials and account metadata to `<dir>` for transfer to another machine.

See [GitHub Copilot CLI](copilot.md) for platform credential schemas, WSL setup with `ghr link`, headless Linux `keyring service` setup, and migrating plaintext `copilotTokens`.

See also [Credential provider contract](credential-provider.md),
[Environment variables](environment-variables.md), and
[Exit codes](exit-codes.md).
