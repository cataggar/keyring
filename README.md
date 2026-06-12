# keyring

`keyring` is a Zig command-line interface for OS credential storage, intended to be compatible with the Python keyring CLI.

## Status

Phases A-C are complete; Phase D adds headless Linux ergonomics and diagnostics. The file backend is now available through the upstream keyring-zig package.

## Usage

```sh
keyring --help
keyring version
keyring --list-backends
keyring diagnose

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

# Disable storage for this process.
keyring --disable
keyring --disable get my-service alice
```

Backends are `secret_service`, `keychain`, `win_credential`, `file`, `ado`, and `null_backend` (`null` is accepted as an alias for `null_backend`).

## Environment variables

| Variable | Purpose |
|---|---|
| `KEYRING_BACKEND` | Override the backend: `secret_service`, `keychain`, `win_credential`, `file`, `ado`, or `null`. |
| `ADO_KEYRING_NONINTERACTIVE` | When set to `true` or `1`, the `ado` backend fails instead of opening a browser if cached credentials are unavailable. |
| `KEYRING_ADO_MSAL_CACHE` | When set to `false` or `0`, the `ado` backend will not read the shared MSAL token cache for `az login` SSO. Defaults to on. |
| `KEYRING_ADO_DISK_CACHE` | When set to `false`, `0`, or `no`, the `ado` backend keeps no persistent cache (neither the platform secret store nor the `.dat` files), so every process re-authenticates. Defaults to on. |
| `ARTIFACTS_CREDENTIALPROVIDER_MSAL_FILECACHE_LOCATION` | Path to an additional MSAL cache file the `ado` backend should consult (parity with `artifacts-credprovider`). |
| `KEYRING_PROPERTY_<NAME>` | Backend-specific properties, such as `KEYRING_PROPERTY_KEYCHAIN`, `KEYRING_PROPERTY_COLLECTION`, or `KEYRING_PROPERTY_APPID`. |
| `NO_COLOR` | Disable ANSI colors in diagnostic output. |
| `CLICOLOR_FORCE` | Force ANSI colors even when stdout is not a TTY. |

Examples:

```sh
KEYRING_BACKEND=null keyring get svc user # exits 3 when the entry is not found
KEYRING_BACKEND=ado keyring get https://pkgs.dev.azure.com/myorg/_packaging/feed/pypi/simple/ VssSessionToken
KEYRING_PROPERTY_COLLECTION=default keyring diagnose
```

## Azure DevOps feeds

The compiled-in `ado` backend authenticates Azure DevOps package feed URLs using the browser OAuth2 + PKCE flow from [`ado-keyring`](https://github.com/cataggar/ado-keyring). It returns a `VssSessionToken` password for Azure Artifacts feed URLs on `dev.azure.com`, `*.pkgs.visualstudio.com`, `pkgs.codedev.ms`, and `pkgs.vsts.me`.

Tokens are cached per platform. The long-lived OAuth **refresh token** is stored in the platform secret store on Windows (the **Windows Credential Manager**, target `ado-keyring` — inspect with `cmdkey /list:ado-keyring`, remove with `cmdkey /delete:ado-keyring`) and macOS (the **macOS Keychain**, a generic password under service `ado-keyring`, account `refresh-token` — inspect with `security find-generic-password -s ado-keyring`, remove with `security delete-generic-password -s ado-keyring`). On Linux it is stored in `refresh.dat` (mode `0600`).

Short-lived per-org **session tokens** live in `session.dat` on every platform — DPAPI-encrypted (current-user) on Windows via `CryptProtectData`, mode `0600` on macOS/Linux. Both files live under `${cache_root}/keyring/`, where `cache_root` is `%LocalAppData%` on Windows, `$XDG_DATA_HOME` (default `~/Library/Application Support`) on macOS, and `$XDG_DATA_HOME` (default `~/.local/share`) on Linux. A legacy `~/.ado-keyring/token-cache.json` (or `session-cache.json`) is migrated into these locations automatically on first run and then deleted. Set `KEYRING_ADO_DISK_CACHE=false` to disable persistent caching entirely. The backend is read-only: `get` authenticates or returns a cached token, `set` is unsupported, and `del` clears the cached tokens. Run `keyring diagnose` to print the resolved cache directory, which `.dat` files exist, and the at-rest protection in use.

### SSO with `az login`

On Windows, the `ado` backend can reuse a refresh token already issued to first-party Microsoft developer tools (Azure CLI, Visual Studio, git-credential-manager) via the shared MSAL token cache and the Family of Client IDs (FOCI) mechanism, so authenticating with `az login` lets `keyring` acquire Azure DevOps tokens without a separate browser prompt. It is read-only — the MSAL cache is never modified — and falls back to the browser flow when no usable token is found. On macOS and Linux only plaintext MSAL caches are readable. Disable with `KEYRING_ADO_MSAL_CACHE=false`. Run `keyring diagnose` to see which caches were found and whether a usable token is present.

## Using `keyring` on headless Linux

On a graphical Linux desktop, `gnome-keyring-daemon` is usually started by the session manager and exposes the Secret Service API. In SSH-only, container, or CI environments, no Secret Service daemon may be running, so `keyring` can return `NoStorageAccess` until you start one.

### Option A: oo7-daemon (recommended for headless servers + CI)

[`oo7-daemon`](https://github.com/linux-credentials/oo7) is a pure-Rust, MIT-licensed Secret Service daemon that is friendly to headless environments. Follow the install instructions in the [oo7 README](https://github.com/linux-credentials/oo7), then run it on a session bus and point clients at that bus:

```sh
export DBUS_SESSION_BUS_ADDRESS=unix:path="$XDG_RUNTIME_DIR/bus"
oo7-daemon &
keyring diagnose
```

### Option B: GNOME stack

If you already have the GNOME Secret Service stack available, start it under a D-Bus session. This is the pattern used by `cataggar/keyring-zig` CI tests:

```sh
dbus-run-session -- bash -lc 'eval "$(printf "\n" | gnome-keyring-daemon --unlock --components=secrets)"; keyring diagnose'
```

### Option C: file backend

`KEYRING_BACKEND=file` uses the upstream file backend for encrypted on-disk credentials when you do not want to rely on a secret-service daemon.

`keyring diagnose` detects the missing Secret Service daemon and prints these recommendations.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | generic failure, such as platform failure or locked storage |
| 2 | invalid usage |
| 3 | entry not found from `get` or `del` |
| 4 | no storage access or backend unavailable |

## Compatibility with Python `keyring`

The CLI follows Python `keyring` command shapes and the native backend schema/TargetName conventions aligned in [cataggar/keyring-zig#9](https://github.com/cataggar/keyring-zig/issues/9), so entries can be shared with Python `keyring` when both commands use the same backend.

```sh
python3 -m keyring set github me
keyring get github me
```

## Links

- Plan: https://github.com/cataggar/keyring/issues/1
- Library: https://github.com/cataggar/keyring-zig

## License

MIT; see [LICENSE](LICENSE).
