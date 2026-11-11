# GitHub Copilot CLI

`keyring copilot` (together with `keyring service` on headless Linux) manages credentials for the GitHub Copilot CLI (`copilot`) across `github.com`, GitHub Enterprise Cloud with data residency (`*.ghe.com`), and GitHub Enterprise Server without leaving plaintext tokens in `~/.copilot/config.json`.

## How Copilot CLI accesses OS secure storage

Rather than invoking an external `keyring` CLI executable, `copilot` accesses each operating system's native credential vault directly:

- **Windows**: Native Windows Credential Manager generic credential with target `<https-host>:<login>.copilot-cli` (for example `https://github.com:alice.copilot-cli`) encoded as UTF-16LE (`copilot-cli/<https-host>:<login>` legacy targets remain read-compatible).
- **macOS**: macOS Keychain generic password with `service = "copilot-cli"`, `account = "<https-host>:<login>"` (for example `https://github.com:alice`), and a raw UTF-8 secret.
- **Linux**: D-Bus Secret Service (`org.freedesktop.secrets`) item with attributes `service = "copilot-cli"` and `username = "<https-host>:<login>"`.

When no OS vault is reachable—common inside WSL or headless Linux SSH sessions—`copilot login` prints `! System vault not available` and falls back to storing tokens in plaintext under `"copilotTokens"` in `~/.copilot/config.json`, unless `COPILOT_GITHUB_TOKEN` is provided in the environment or an `org.freedesktop.secrets` daemon is active on D-Bus.

## WSL setup (`ghr link`)

Inside WSL, [`ghr` WSL linking](https://cataggar.github.io/ghr/docs/wsl-linking.html) lets WSL invoke the Windows `keyring.exe` binary over WSL interop so credentials stay in the **Windows native Credential Manager store** with no Linux Secret Service daemon and no plaintext secrets in WSL's `~/.copilot/config.json`:

1. Install `keyring` on Windows:

   ```powershell
   ghr install cataggar/keyring
   ```

2. Link `keyring` inside WSL so `keyring` delegates to Windows `keyring.exe`:

   ```sh
   ghr link cataggar/keyring
   ```

3. Authenticate on Windows or from WSL, then export `COPILOT_GITHUB_TOKEN` into your shell before running Linux `copilot`:

   ```sh
   keyring copilot login
   eval "$(keyring copilot env)"
   copilot
   ```

   For Fish (`--shell fish`), PowerShell (`--shell pwsh`), or Command Prompt (`--shell cmd`), pass `--shell` explicitly (for example `keyring copilot env --shell fish | source`).

   If you authenticate Copilot CLI via GitHub CLI (`gh`), linking Windows `gh.exe` inside WSL with `ghr link cli/cli` is also available as an alternative that reuses Windows Credential Manager credentials.

## Headless Linux setup (WebAuthn PRF)

On a remote Linux machine without `gnome-keyring-daemon`, install and unlock the built-in WebAuthn PRF Secret Service provider (`org.freedesktop.secrets`) over SSH:

```sh
keyring service install
keyring enroll --label primary-yubikey
keyring unlock            # or: keyring unlock --recover
keyring service status
```

Once unlocked, running `copilot login` connects directly to `org.freedesktop.secrets` over D-Bus without triggering `! System vault not available`, or you can store and configure the credential directly with `keyring copilot login`.

Run `keyring lock` to clear the in-memory vault key immediately, or pass `--lock-timeout <seconds>` when starting `keyring service`. See [Headless Linux](headless-linux.md) for SSH port-forwarding ceremony details and unit management.

## Migrating plaintext `~/.copilot/config.json` tokens

If `~/.copilot/config.json` already contains plaintext `"copilotTokens"` entries from an earlier vault-unavailable fallback, migrate them into the OS keyring and scrub the plaintext values in place:

```sh
# Move copilotTokens from ~/.copilot/config.json into the OS keyring and scrub plaintext secrets:
keyring copilot import
keyring copilot status

# Transfer Copilot CLI credentials to another machine without leaving plaintext tokens in config.json:
keyring copilot export ./copilot-export
keyring copilot import ./copilot-export
```

`keyring copilot import` accepts JSONC comments and preserves unrelated `config.json` fields such as `loggedInUsers`, `lastLoggedInUser`, and `trustedFolders`. `keyring copilot export <dir>` writes `<dir>/config.json` with restricted user-only permissions containing resolved tokens for transfer to another machine (delete `<dir>` once imported).

## Commands and examples

```sh
# Authenticate and store a Copilot CLI token in the native OS keyring:
keyring copilot login
keyring copilot login -h example.ghe.com -u alice --device
keyring copilot login -f

# Inspect config.json accounts and OS vault storage status:
keyring copilot status

# Print the resolved raw token or shell environment export:
keyring copilot token
eval "$(keyring copilot env)"
keyring copilot env --shell pwsh | Invoke-Expression

# Migrate local plaintext copilotTokens, or export/import across machines:
keyring copilot import
keyring copilot export ./copilot-export
keyring copilot import ./copilot-export

# Remove stored Copilot CLI credentials for one account or all accounts:
keyring copilot logout -h github.com -u alice
keyring copilot logout --all
```

### Subcommand reference

- `keyring copilot login [-h|--hostname <host>] [-u|--user <login>] [--web|--device] [-f|--force]` — Resolve or acquire a GitHub token (reusing stored `gh` / `keyring` credentials unless `-f` / `--force` is given, or authenticating via browser `--web` or device flow `--device`), store it in the OS keyring using Copilot CLI's native credential layout, update `loggedInUsers` and `lastLoggedInUser` in `config.json`, and scrub any matching plaintext `copilotTokens` entry.
- `keyring copilot logout [-h|--hostname <host>] [-u|--user <login> | --all]` — Delete the stored Copilot CLI credential (or `--all` configured accounts) from the OS keyring and `config.json` without revoking shared `gh` tokens.
- `keyring copilot status` — Report the resolved `config.json` path, active `lastLoggedInUser`, configured `loggedInUsers`, and whether each account's token is stored in the OS keyring or plaintext `copilotTokens`. `keyring diagnose` also summarizes Copilot CLI configuration and vault status when `~/.copilot/config.json` exists.
- `keyring copilot token [-h|--hostname <host>] [-u|--user <login>]` — Print the stored Copilot CLI token for the selected account (or `lastLoggedInUser` by default).
- `keyring copilot env [-h|--hostname <host>] [-u|--user <login>] [--shell <sh|pwsh|cmd|fish>]` — Print shell statements setting `COPILOT_GITHUB_TOKEN` from the OS keyring for `sh`, `pwsh`, `cmd`, or `fish`.
- `keyring copilot import [<dir-or-file>]` — Without arguments, migrate plaintext `copilotTokens` from `config.json` into the OS keyring and scrub `copilotTokens` from `config.json`. With `<dir-or-file>`, import exported Copilot CLI credentials into the OS keyring and update `config.json`.
- `keyring copilot export <dir>` — Export resolved Copilot CLI tokens and account metadata to `<dir>/config.json` with restricted user-only permissions for importing on another machine (delete `<dir>` once imported).

## Configuration path (`$COPILOT_HOME`)

Set `COPILOT_HOME` to override the default `~/.copilot` configuration directory (`%USERPROFILE%\.copilot` on Windows). Both `keyring copilot` and `keyring diagnose` read and update `$COPILOT_HOME/config.json` when `COPILOT_HOME` is set.

See also [Usage](usage.md), [Headless Linux](headless-linux.md), and [Environment variables](environment-variables.md).
