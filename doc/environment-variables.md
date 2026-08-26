# Environment variables

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

## Examples

```sh
KEYRING_BACKEND=null keyring get svc user # exits 3 when the entry is not found
KEYRING_BACKEND=ado keyring get https://pkgs.dev.azure.com/myorg/_packaging/feed/pypi/simple/ VssSessionToken
KEYRING_PROPERTY_COLLECTION=default keyring diagnose
```
