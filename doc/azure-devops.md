# Azure DevOps feeds

The compiled-in `ado` backend authenticates Azure DevOps package feed URLs using
the browser OAuth2 + PKCE flow from
[`ado-keyring`](https://github.com/cataggar/ado-keyring). It returns a
`VssSessionToken` password for Azure Artifacts feed URLs on `dev.azure.com`,
`*.pkgs.visualstudio.com`, `pkgs.codedev.ms`, and `pkgs.vsts.me`.

## Token caching

Tokens are cached per platform. The long-lived OAuth **refresh token** is stored
in the platform secret store on Windows (the **Windows Credential Manager**,
target `ado-keyring` — inspect with `cmdkey /list:ado-keyring`, remove with
`cmdkey /delete:ado-keyring`) and macOS (the **macOS Keychain**, a generic
password under service `ado-keyring`, account `refresh-token` — inspect with
`security find-generic-password -s ado-keyring`, remove with
`security delete-generic-password -s ado-keyring`). On Linux it is stored in
`refresh.dat` (mode `0600`).

Short-lived per-org **session tokens** live in `session.dat` on every platform —
DPAPI-encrypted (current-user) on Windows via `CryptProtectData`, mode `0600` on
macOS/Linux. Both files live under `${cache_root}/keyring/`, where `cache_root`
is `%LocalAppData%` on Windows, `$XDG_DATA_HOME` (default
`~/Library/Application Support`) on macOS, and `$XDG_DATA_HOME` (default
`~/.local/share`) on Linux.

A legacy `~/.ado-keyring/token-cache.json` (or `session-cache.json`) is migrated
into these locations automatically on first run and then deleted. Set
`KEYRING_ADO_DISK_CACHE=false` to disable persistent caching entirely.

The backend is read-only: `get` authenticates or returns a cached token, `set` is
unsupported, and `del` clears the cached tokens. Run `keyring diagnose` to print
the resolved cache directory, which `.dat` files exist, and the at-rest
protection in use.

## SSO with `az login`

On Windows, the `ado` backend can reuse a refresh token already issued to
first-party Microsoft developer tools (Azure CLI, Visual Studio,
git-credential-manager) via the shared MSAL token cache and the Family of Client
IDs (FOCI) mechanism, so authenticating with `az login` lets `keyring` acquire
Azure DevOps tokens without a separate browser prompt.

It is read-only — the MSAL cache is never modified — and falls back to the
browser flow when no usable token is found. On macOS and Linux only plaintext
MSAL caches are readable. Disable with `KEYRING_ADO_MSAL_CACHE=false`. Run
`keyring diagnose` to see which caches were found and whether a usable token is
present.
