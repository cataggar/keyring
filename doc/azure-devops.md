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
`refresh.dat` (mode `0600`) by default, or in the **Secret Service** when
`KEYRING_ADO_STORE=secret` (see below).

Short-lived per-org **session tokens** live in `session.dat` on every platform —
DPAPI-encrypted (current-user) on Windows via `CryptProtectData`, mode `0600` on
macOS/Linux. Both files live under `${cache_root}/keyring/`, where `cache_root`
is `%LocalAppData%` on Windows, `$XDG_DATA_HOME` (default
`~/Library/Application Support`) on macOS, and `$XDG_DATA_HOME` (default
`~/.local/share`) on Linux.

A legacy `~/.ado-keyring/token-cache.json` (or `session-cache.json`) is migrated
into these locations automatically on first run and then deleted. Set
`KEYRING_ADO_DISK_CACHE=false` to disable persistent caching entirely — neither
the Secret Service nor the `.dat` files are then read or written.

The backend is read-only: `get` authenticates or returns a cached token, `set` is
unsupported, and `del` clears the cached tokens. Run `keyring diagnose` to print
the resolved cache directory, which `.dat` files exist, and the at-rest
protection in use.

## Linux: Secret Service (opt-in)

Linux defaults to `refresh.dat`. Set `KEYRING_ADO_STORE=secret` to keep the
refresh token in the Secret Service (`org.freedesktop.secrets` — GNOME Keyring,
KWallet, oo7-daemon, …) instead, under the attributes `service=ado-keyring` and
`account=refresh-token`:

```sh
export KEYRING_ADO_STORE=secret
secret-tool search service ado-keyring   # inspect the stored entry
secret-tool clear service ado-keyring    # force a fresh authentication
```

`KEYRING_ADO_STORE` accepts `file` (the default) and `secret`; any other value is
rejected with `keyring: invalid KEYRING_ADO_STORE value` and exit code 2. The
selector is Linux-only — Windows and macOS always use the Credential Manager and
the Keychain.

Only the refresh token is stored, matching Windows and macOS; per-org session
tokens stay in `session.dat` and the access token is never persisted. On the
first run with `secret` selected, an existing `refresh.dat` (or legacy
`~/.ado-keyring/token-cache.json`) is written into the Secret Service and only
then deleted, so a failed migration leaves the token on disk and retries on the
next run. Migration is idempotent: once the entry exists, later runs read it
directly and delete any `refresh.dat` that a later switch back to `file` may
have recreated, so the refresh token is never left at rest on disk while
`secret` is selected.

There is no silent fallback. A missing entry simply means "authenticate", but a
Secret Service that is unavailable (no D-Bus session bus, no daemon) or that
stays locked fails with `keyring: no storage access` and exit code 4 rather than
writing the token to disk. In an interactive session the provider's own unlock
prompt may appear first. On headless machines either keep the default
`refresh.dat` store, run a daemon under `dbus-run-session`, or disable caching
with `KEYRING_ADO_DISK_CACHE=false`.

`keyring del <ado-url> <user>` removes the Secret Service entry along with the
cache files. `keyring diagnose` reports the configured store and, when `secret`
is selected, whether the entry is `present`, `reachable, no entry`, `locked`, or
`unavailable` — never the secret itself. The `refresh.dat` line describes what
the next run will do with the file (`migrates into the Secret Service on next
use`, `stale, removed on next use`, or `unused: disk cache disabled`):

```
ado linux store: secret (KEYRING_ADO_STORE=secret)
ado secret service (ado-keyring/refresh-token): present
ado refresh.dat: absent
```

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
