# Environment variables

## Backend, vault, and secret storage

| Variable | Purpose |
|---|---|
| `KEYRING_BACKEND` | Override the backend: `secret_service`, `keychain`, `win_credential`, `file`, `ado` (`azure_devops` alias, matched case-insensitively), or `null` (`null_backend` alias). |
| `KEYRING_FILE_PATH` | Path to the AES-256-GCM encrypted store used when `KEYRING_BACKEND=file` (defaults to the platform `store.bin` location when unset). |
| `KEYRING_FILE_PASSPHRASE` | Passphrase used to derive the encryption key for `KEYRING_BACKEND=file`. Required for stored credential provider operations on the `file` backend. |
| `KEYRING_VAULT_PATH` | Override the built-in Linux WebAuthn Secret Service vault path. Defaults to `$XDG_DATA_HOME/keyring/vault.json` or `~/.local/share/keyring/vault.json` (must not be group/world accessible). |
| `KEYRING_PROPERTY_<NAME>` | Backend-specific properties inspected by `keyring_zig` and `keyring diagnose`, such as `KEYRING_PROPERTY_KEYCHAIN`, `KEYRING_PROPERTY_COLLECTION`, `KEYRING_PROPERTY_APPID`, and `KEYRING_PROPERTY_FILE_PATH` (use `KEYRING_FILE_PATH` to configure the `file` backend path). |
| `DBUS_SESSION_BUS_ADDRESS` | Linux D-Bus session bus address used by `secret_service`, `keyring service`, `keyring unlock`, `keyring lock`, and `KEYRING_ADO_STORE=secret`. |

## Interaction, browser launch, and terminal output

| Variable | Purpose |
|---|---|
| `KEYRING_NONINTERACTIVE` | When set to `true` or `1`, disables interactive OAuth flows and interactive keyring unlock prompts across `ado`, `gh`, `podman`, `wslc`, and `stored_provider`. |
| `ADO_KEYRING_NONINTERACTIVE` | When set to `true` or `1`, disables interactive authentication instead of opening a browser or device prompt when cached credentials are unavailable. Applies to `ado` as well as `gh`, `podman`, `wslc`, and `stored_provider`. |
| `GIT_TERMINAL_PROMPT` | When set to `0` or `false`, disables interactive prompts across `ado`, `gh`, `podman`, `wslc`, and `stored_provider` (Git convention). |
| `GCM_INTERACTIVE` | When set to `never`, `false`, or `0`, disables interactive prompts across `ado`, `gh`, `podman`, `wslc`, and `stored_provider` (Git Credential Manager convention). |
| `GH_BROWSER`, `BROWSER` | Override the browser executable for OAuth login, or set to `false` / `none` / `0` / `no` / `echo` / `:` / `/bin/false` to disable launching a browser (falling back to device flow where supported). |
| `DISPLAY`, `WAYLAND_DISPLAY`, `SSH_TTY`, `SSH_CLIENT`, `SSH_CONNECTION` | Checked (along with WSL, `VSCODE_IPC_HOOK_CLI`, `REMOTE_CONTAINERS`, `CODESPACES`, and `ACC_CLOUD`) following Git Credential Manager and Azure CLI conventions to detect headless or SSH sessions without a local GUI display. |
| `NO_COLOR` | Disable ANSI colors in diagnostic and status output whenever set (even if empty). |
| `CLICOLOR_FORCE` | Force ANSI colors when non-empty and not `0`, even when stdout is not a TTY (`NO_COLOR` takes precedence). |

## Azure DevOps (`ado` and `devops-npm`)

| Variable | Purpose |
|---|---|
| `KEYRING_ADO_STORE` | **Linux only.** Where the `ado` backend keeps the long-lived refresh token: `file` (default, `refresh.dat`) or `secret` (Secret Service, `service=ado-keyring`, `account=refresh-token`). Any other value exits with code `2`. With `secret`, an unavailable or locked Secret Service exits with code `4` instead of falling back to `refresh.dat`. Ignored on Windows and macOS. |
| `KEYRING_ADO_MSAL_CACHE` | When set to `false` or `0`, the `ado` backend does not read the shared MSAL token cache for `az login` SSO. Defaults to on. |
| `KEYRING_ADO_DISK_CACHE` | When set to `false`, `0`, or `no`, the `ado` backend keeps no persistent cache (neither the platform secret store nor `.dat` files), so every process re-authenticates. Defaults to on. |
| `ARTIFACTS_CREDENTIALPROVIDER_MSAL_FILECACHE_LOCATION` | Path to an additional MSAL cache file consulted by the `ado` backend (parity with `artifacts-credprovider`). |
| `NPM_CONFIG_USERCONFIG` | Override the user `.npmrc` file updated by `keyring devops-npm` (defaults to `~/.npmrc` / `%USERPROFILE%\.npmrc`). |
| `SYSTEM_ACCESSTOKEN`, `AZURE_DEVOPS_EXT_PAT` | CI/CD bearer token or PAT environment variables checked first by `keyring devops-npm` before consulting cached `ado` / MSAL tokens or interactive login. |

## GitHub, Copilot CLI, and container registries

| Variable | Purpose |
|---|---|
| `GH_CONFIG_DIR` | Override the GitHub CLI configuration directory containing `hosts.yml` (defaults to `$XDG_CONFIG_HOME/gh`, `%AppData%\GitHub CLI` on Windows, or `~/.config/gh`). |
| `GH_TOKEN`, `GITHUB_TOKEN`, `GH_ENTERPRISE_TOKEN` | Token overrides consulted during non-forced Git credential and registry helper lookups (`GH_TOKEN` / `GITHUB_TOKEN` on `github.com`; `GH_ENTERPRISE_TOKEN` / `GH_TOKEN` on `*.ghe.com` and GHES). Never persisted by `git credential store` or read by `gh export`. |
| `KEYRING_GH_CLIENT_ID`, `KEYRING_GH_CLIENT_SECRET` | Override the OAuth application client ID and client secret used during interactive `keyring gh login` and GitHub OAuth flows. |
| `COPILOT_HOME` | Override the GitHub Copilot CLI configuration directory containing `config.json` (defaults to `~/.copilot` / `%USERPROFILE%\.copilot`). |
| `COPILOT_GITHUB_TOKEN` | Environment variable emitted by `keyring copilot env` (`eval "$(keyring copilot env)"`) and consumed by GitHub Copilot CLI (`copilot`). |
| `REGISTRY_AUTH_FILE` | Override the container registry `auth.json` path used by `keyring podman` when `--authfile` is not specified. |
| `WSLC_CONFIG_DIR` | Override the `wslc` configuration directory containing `settings.yaml` and `registry-credentials.json` (defaults to `%LOCALAPPDATA%\wslc` on Windows or `$XDG_CONFIG_HOME/wslc` / `~/.config/wslc`). |

## XDG base directories

| Variable | Purpose |
|---|---|
| `XDG_RUNTIME_DIR` | Linux runtime directory used for the default Podman `${XDG_RUNTIME_DIR}/containers/auth.json` path and session runtime sockets. |
| `XDG_DATA_HOME` | Base data directory on Linux/macOS (when set to an absolute path) for `vault.json`, `ado` `.dat` caches, `keyring service install` D-Bus activation files, and the default `file` backend store. |
| `XDG_CONFIG_HOME` | Base configuration directory (when set to an absolute path) for `keyring service install` `systemd --user` units, `gh/hosts.yml`, persistent Linux Podman `containers/auth.json`, and `wslc`. |

## Examples

```sh
KEYRING_BACKEND=null_backend keyring get svc user # exits 3 when the entry is not found
KEYRING_BACKEND=ado keyring get https://pkgs.dev.azure.com/myorg/_packaging/feed/pypi/simple/ VssSessionToken
KEYRING_BACKEND=file KEYRING_FILE_PATH="$HOME/.local/share/keyring/credentials.dat" KEYRING_FILE_PASSPHRASE="$PASS" keyring get svc user
KEYRING_NONINTERACTIVE=1 keyring podman credential get <<<"ghcr.io"
KEYRING_ADO_STORE=secret keyring diagnose # Linux: report the Secret Service store
KEYRING_PROPERTY_COLLECTION=default keyring diagnose
KEYRING_VAULT_PATH="$HOME/.local/share/keyring/work-vault.json" keyring enroll
```
