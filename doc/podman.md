# Podman Desktop and Podman

`keyring podman` and `docker-credential-keyring` (`docker-credential-keyring.exe` on Windows) authenticate **Podman Desktop** and **Podman CLI** (`podman`, `podman.exe`, `buildah`, `skopeo`) across:

- **GitHub Container Registry**: `ghcr.io`, GitHub Enterprise Cloud with data residency (`containers.<tenant>.ghe.com`), and GitHub Enterprise Server (`docker.<ghes>`), reusing `keyring` / `gh` credentials and requesting `read:packages` and `write:packages` OAuth scopes when authenticating interactively.
- **Azure Container Registry**: `*.azurecr.io` (and sovereign `*.azurecr.*` suffixes), discovering the registry's Microsoft Entra tenant via `/v2/` when available and exchanging an Entra ARM token from `az login` MSAL SSO or `ado-keyring` via `POST /oauth2/exchange` (using username `00000000-0000-0000-0000-000000000000` with the ACR OAuth2 refresh token so `podman-remote` forwards credentials cleanly to Podman machines).
- **Docker Hub and generic OCI registries**: `docker.io` and arbitrary hosts (`registry.example.com`, `registry.example.com:5000`), storing credentials in the OS keyring (`container-registry://<host>`) via `--username` (`-u`) and `--password-stdin`.

## Windows setup (WinGet + WSL 2)

See [Windows | Podman Desktop](https://podman-desktop.io/docs/installation/windows-install) for full prerequisites. To update WSL 2, install Podman CLI and Podman Desktop via WinGet, and start the default WSL 2 Podman machine:

```powershell
wsl --update
wsl --status
winget install --id RedHat.Podman -e
winget install --id RedHat.Podman-Desktop -e
podman machine init --now
```

If an existing WSL distribution is still on WSL 1 (`wsl --list --verbose`), convert it with `wsl --set-version <Distro> 2`. When running Windows inside a cloud or host VM, starting a WSL 2 Podman machine requires nested virtualization (`VirtualizationFirmwareEnabled=True` / Hyper-V platform support) on the VM SKU; host-side `keyring podman` and `podman.exe login`/`logout` manage `%USERPROFILE%\.config\containers\auth.json` natively on Windows regardless.

## Why dual-mode (`"auths"` + `"credHelpers"`)

Podman CLI and Podman Desktop read the same `auth.json` file, but resolve credentials differently:

- **Podman CLI** (`podman`, `podman.exe`, `buildah`, `skopeo`) checks `"credHelpers"` (`docker-credential-keyring`) **first** before `"auths"`, resolving tokens dynamically on demand with zero staleness.
- **Podman Desktop** (`Settings > Registries` and GUI Pull/Push/Build) ignores `"credHelpers"` and `"credsStore"`, reading base64-encoded `username:secret` entries exclusively from `"auths"` in `auth.json` keyed by bare hostnames (`ghcr.io`, `myregistry.azurecr.io`, `docker.io`).

By default, `keyring podman login` writes **both** `"credHelpers"` and `"auths"` (preserving unrelated fields such as `podmanDesktopAlias`). This gives Podman CLI dynamic token refresh via `docker-credential-keyring` while making registries work immediately in Podman Desktop's GUI.

For single-mode workflows:

- **CLI-only / headless (`--helper-only` or `keyring podman config`)**: Registers `"credHelpers": { "<host>": "keyring" }` with zero secrets written to `auth.json` (`--helper-only` also removes any existing `"auths"` entry for that host while keeping top-level `"auths": {}` valid).
- **Static `auth.json` only (`--auths-only`)**: Writes `"auths"` only and removes any owned `"credHelpers": { "<host>": "keyring" }` mapping when helper registration is undesired (refusing to overwrite a third-party `credHelpers` mapping unless `-f` / `--force` is passed).

## Commands and examples

```sh
# Log in for both Podman Desktop (auths) and Podman CLI (credHelpers):
keyring podman login ghcr.io myregistry.azurecr.io

# Refresh all bare registries configured in auth.json:
keyring podman login
keyring podman login -f

# CLI-only zero-disk-secret helper configuration:
keyring podman config ghcr.io myregistry.azurecr.io
keyring podman login --helper-only ghcr.io

# Store a generic registry credential in the OS keyring and configure Podman:
echo "$REGISTRY_PAT" | keyring podman login -u alice --password-stdin registry.example.com

# Inspect auth.json paths, helper PATH status, and ACR token validity:
keyring podman status

# Remove a registry (or --all) without revoking shared GitHub/Entra tokens:
keyring podman logout myregistry.azurecr.io

# Direct Docker/Podman credential-helper protocol (also via docker-credential-keyring):
keyring podman credential get
```

### Subcommand reference

- `keyring podman login [<server>...] [-u|--username <user>] [--password-stdin] [-f|--force] [--helper-only | --auths-only] [--authfile <path>]` — Authenticate one or more registries, or refresh all configured bare registries in `auth.json` when `<server>` is omitted. Passing `-f` / `--force` re-authenticates GHCR with package scopes, bypasses cached ACR/ARM tokens (otherwise valid ACR tokens with >5 minutes remaining are reused), and refreshes stored generic credentials.
- `keyring podman config <server>... [--authfile <path>]` — Configure `"credHelpers"` in `auth.json` and provision `docker-credential-keyring` onto `PATH` without writing secrets to `auth.json`.
- `keyring podman logout [<server>...] [--all] [--authfile <path>]` — Remove `<server>` (or `--all` managed registries) from `"auths"`, owned `"credHelpers"`, and stored generic `container-registry://<host>` keyring entries without revoking shared `gh` or Microsoft Entra tokens.
- `keyring podman status [--authfile <path>]` — Report resolved `auth.json` paths, Podman Desktop path alignment, `docker-credential-keyring` `PATH` availability, configured registries, and ACR JWT remaining lifetime (also summarized by `keyring diagnose`).
- `keyring podman credential <get|store|erase|list|version>` — Noninteractive Docker credential-helper protocol endpoint over `stdin`/`stdout`, identical to invoking `docker-credential-keyring` (`docker-credential-keyring.exe` on Windows) directly.

## Platform `auth.json` locations and `ghr` helper provisioning

### `auth.json` paths

- **Windows**: `%USERPROFILE%\.config\containers\auth.json`
- **macOS**: `$HOME/.config/containers/auth.json`
- **Linux**: `${XDG_RUNTIME_DIR}/containers/auth.json` (`tmpfs`, shared by Podman CLI and Podman Desktop when `$XDG_RUNTIME_DIR` is set; falls back to `/run/containers/<uid>/auth.json` when writable or `${XDG_CONFIG_HOME:-$HOME/.config}/containers/auth.json` in headless sessions), plus persistent `"credHelpers"` merged into `${XDG_CONFIG_HOME:-$HOME/.config}/containers/auth.json` so CLI helper mappings survive reboots without writing `"auths"` secrets to disk (`keyring podman logout` cleans both files).
- **Overrides**: `--authfile <path>` or `$REGISTRY_AUTH_FILE` overrides the target path (`keyring podman status` warns when `$REGISTRY_AUTH_FILE` diverges from Podman Desktop's fixed path).

`auth.json` updates use atomic replacement with optimistic concurrency checks and user-only permissions (current-user DACL on Windows, mode `0600` in a `0700` directory on macOS and Linux) so concurrent edits by Podman Desktop or `podman` are preserved.

### `docker-credential-keyring` provisioning and `ghr` upgrades

Running `keyring podman login` (unless `--auths-only`) or `keyring podman config` automatically provisions `docker-credential-keyring` (`docker-credential-keyring.exe` on Windows) onto `PATH` from the resolved `keyring` executable:

- When `keyring`'s own directory is already on `PATH` (for example `zig-out/bin`), `docker-credential-keyring` is linked or copied beside it.
- In `ghr install` layouts where `~/.local/bin/keyring` delegates to a cached release binary outside `PATH`, `keyring` provisions the real binary into the writable `PATH` directory (`~/.local/bin`). Re-running `keyring podman login` or `keyring podman config` after upgrading `keyring` automatically refreshes an older `docker-credential-keyring` binary on `PATH`.

## Podman Desktop notes and limitations

- **Initialize `auth.json` before starting Podman Desktop**: Run `keyring podman login` (or ensure `auth.json` exists) *before* launching Podman Desktop so Podman Desktop attaches its `fs.watchFile` listener at startup (`podman-desktop/podman-desktop#17610`).
- **Refreshing expired ACR tokens while Podman Desktop is open**: Podman Desktop's file watcher reloads added or removed registry keys rather than in-place secret edits. If an already-loaded short-lived ACR token expires while Podman Desktop is open, restart Podman Desktop after `keyring podman login -f` (or run `keyring podman logout <acr>`, wait ~6 seconds, then run `keyring podman login <acr>`). Podman CLI is unaffected because `"credHelpers"` refreshes tokens dynamically on every pull or push.
- **Repository-scoped entries**: Repository-scoped `auth.json` entries (`host/namespace`) are preserved untouched and skipped during no-argument `keyring podman login` refreshes.

See also [Usage](usage.md), [Azure DevOps feeds](azure-devops.md), [Headless Linux](headless-linux.md), and [Environment variables](environment-variables.md).
