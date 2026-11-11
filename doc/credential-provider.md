# Credential provider contract

`keyring` separates external client protocols, credential lifecycle management, and encrypted secret persistence into three distinct layers:

1. **Client wire protocols**: CLI surfaces and helper protocols such as `keyring git credential` (`git-credential-keyring`), `keyring podman credential` (`docker-credential-keyring`), `keyring podman`, and `keyring wslc` parse external inputs and format protocol responses without embedding storage or token-lifetime rules.
2. **Credential providers (`src/credential_provider.zig`)**: A typed internal contract governing target normalization, `get` / `login` / `logout` operations, interaction policy, expiration and noninteractive renewal, cache policy, secret zeroing, and `ProviderChain` fallback semantics.
3. **Secret persistence (`src/stored_provider.zig`)**: `PersistenceBackend` and `KeyringPersistence` store serialized credentials in encrypted OS keyrings or an explicitly configured encrypted file backend via `keyring_zig`, isolated from provider policy and wire formatting.

The contract borrows operation, expiration, cache-policy, and chain-fallback semantics from Cargo's credential-provider protocol and explicit interaction controls from Kubernetes `client-go` exec credential plugins. It is an internal Zig contract rather than an external plugin runtime and leaves the existing `ado` backend unchanged.

## Request context and target normalization

Every provider call takes a typed `Request` bound to a canonicalized `Target`:

- **`Target` normalization**: Normalizes the scheme, lowercases hostnames and IPv4 literals, and parses and formats bracketed `[IPv6]` literals in canonical RFC 4291 / RFC 5952 form (lowercased hex, leading zeros stripped, and the longest run of two or more zero hextets compressed as `::`), alongside an optional validated port (`1..65535`). Explicit ports are preserved (for example `https://registry.example.com:5000` remains distinct from `https://registry.example.com` and `:5001`) so separate registries or endpoints on the same host never collide.
- **Rejected target inputs**: `Target` validation rejects userinfo (`@`), query strings (`?`), fragments (`#`), backslashes (`\`), NUL or ASCII control bytes, and unexpected path segments with `error.InvalidInput`.
- **`Request` fields**:
  - `target`: Normalized `Target`.
  - `operation`: `Operation` (`get`, `login`, or `logout`).
  - `account`: Optional account or profile selector (`?[]const u8`) to disambiguate multiple identities for the same target.
  - `audience` and `scopes`: Optional token audience and requested scope list when known to the caller.
  - `interaction`: `InteractionPolicy` (`never`, `if_available`, or `always`).
  - `deadline`: `Deadline` pairing an optional wall-clock deadline timestamp with an atomic cancellation flag so blocking operations and renewals stay bounded.

## Credential kinds, ownership, and metadata honesty

### Typed credential variants

`CredentialSecret` is a tagged union keeping credential shapes distinct at compile time so callers and providers never silently interchange them:

- `basic`: `username` + `secret` (such as HTTP Basic or OCI registry username/password pairs).
- `bearer_token`: Opaque bearer or OAuth2 access token.
- `identity_token`: OIDC or federated identity token.

### Buffer ownership and zeroing

Callers take ownership of all heap buffers inside a returned `CredentialResult` and must release them via `result.deinit(allocator)`. `deinit` overwrites secret bytes in place with `std.crypto.secureZero` before freeing memory so credential material does not linger in freed heap allocations.

### Honest metadata

`CredentialResult` records only metadata actually supplied by the underlying source or protocol:

- When an input protocol (such as Git or Docker credential helpers) or static secret does not provide an expiration time, `expires_at` remains `null`.
- Unknown `audience` and `scopes` remain `null` (or unset) rather than synthesized defaults.
- `supports_noninteractive_renewal` is `false` unless the issuing provider can actually refresh the credential without user interaction.

## Lifecycle, interaction policy, and cache semantics

### Strict `get` / `login` / `logout` separation

Credential retrieval (`get`) is strictly separated from acquisition/persistence (`login`) and local removal (`logout`):

- **`Provider.executeGet` is always noninteractive**: `Provider.executeGet` unconditionally enforces `InteractionPolicy.never` during retrieval. Missing, revoked, or expired credentials never implicitly open a browser, start a device-code flow, or prompt on a terminal during `get`.
- **Explicit `login`**: Interactive authentication (browser OAuth, device code, or credential prompting) is permitted only during explicit `login` operations whose `InteractionPolicy` is `if_available` or `always`.
- **Expired credentials and bounded renewal**: When `expires_at <= now`, providers implementing `renewNoninteractiveFn` may attempt silent renewal strictly within the remaining `Request.deadline` budget (checking both wall-clock expiry and atomic cancellation). Static stored credentials set `supports_noninteractive_renewal = false` and fail immediately with `error.ReauthenticationRequired` once `expires_at <= now`.

### Cache policies

`CachePolicy` declares how long a credential may be retained:

| `CachePolicy` | Meaning | Accepted by `StoredCredentialProvider` |
|---|---|---|
| `eternal` | Valid until explicitly replaced or removed via `logout`. | Yes |
| `until_expiration` | Valid until `expires_at` (requires a non-null `expires_at` timestamp; rejected with `error.InvalidInput` otherwise). | Yes |
| `session` | Ephemeral in-memory / single-session use only. | No (refused for persistent storage) |
| `never` | Single-use; must never be cached. | No (refused for persistent storage) |

`StoredCredentialProvider` persists only `eternal` and `until_expiration` credentials and refuses to write `session` or `never` secrets to OS keyrings or disk.

## Stored-credential provider and secure-storage requirements

`StoredCredentialProvider` (`src/stored_provider.zig`) delegates at-rest storage through `PersistenceBackend` (forwarding `PersistenceOptions` carrying `InteractionPolicy` and `Deadline`) to `KeyringPersistence` (`KeyringOpsAdapter`), backed by `keyring_zig`:

- **Native OS secret stores**:
  - **Windows**: Windows Credential Manager (`win_credential`).
  - **macOS**: macOS Keychain (`keychain`).
  - **Linux**: Secret Service (`secret_service`), including the built-in WebAuthn PRF `keyring service`, `oo7-daemon`, or GNOME Keyring.
- **Explicit encrypted file backend**: `KEYRING_BACKEND=file` using AES-256-GCM encryption when configured with `KEYRING_FILE_PASSPHRASE` and either `KEYRING_FILE_PATH` or the platform default `store.bin` location (see [Headless Linux](headless-linux.md#option-c-file-backend)). `KEYRING_PROPERTY_FILE_PATH` is not read by `keyring_zig`'s file backend and fails closed with `error.StorageUnavailable` if set without `KEYRING_FILE_PATH`.

### Audience and scope matching

`StoredCredentialProvider` enforces requested `audience` and `scopes` without inventing unknown metadata:

- On `get`: when `Request.audience` is non-null, a stored credential whose `audience` is `null` (unknown) or differs returns `error.CredentialNotFound`. When `Request.scopes` is non-empty, a stored credential whose `scopes` is `null` (unknown) or omits any requested scope returns `error.CredentialNotFound`.
- On `login`: conflicting `Request.audience` vs `credential.audience`, or non-empty `Request.scopes` when `credential.scopes` is `null` or missing any requested scope, fails with `error.InvalidInput`.

### Fail-closed storage enforcement and non-prompting D-Bus preflight

`StoredCredentialProvider` and `KeyringPersistence` check `Deadline.checkBudget()` before and after underlying persistence calls and fail closed whenever encrypted secret storage is unavailable or locked:

- Returns `error.StorageUnavailable` when no Secret Service / OS store is reachable (including on Linux when `org.freedesktop.secrets` has no owner on the session bus and is not activatable via `org.freedesktop.DBus.ListActivatableNames`), when storage is disabled via `null_backend` (`--disable` or `KEYRING_BACKEND=null`), or when the read-only `ado` backend (`-b ado` or `KEYRING_BACKEND=ado`) is forced.
- Returns `error.StorageLocked` when the backing vault, Keychain, or Secret Service collection is locked. On Linux Secret Service, operations that disallow prompting (`InteractionPolicy.never`, including all `get` calls, or `InteractionPolicy.if_available` when no interactive display is available or noninteractive mode is set) preflight `org.freedesktop.DBus.Properties.Get("org.freedesktop.Secret.Collection", "Locked")` on `/org/freedesktop/secrets/aliases/default` (falling back to `org.freedesktop.Secret.Service.ReadAlias("default")`) and return `error.StorageLocked` immediately without calling `keyring_zig` or triggering an interactive unlock prompt. Non-`default` `KEYRING_PROPERTY_COLLECTION` values are not read by `keyring_zig` and fail closed with `error.StorageUnavailable`.
- Returns `error.AccessDenied` on D-Bus `AccessDenied` replies or OS access-denied errors (such as Windows `ERROR_ACCESS_DENIED`).
- **Never** falls back to plaintext or base64 files on disk.

### Namespace and store isolation

Stored provider entries use dedicated `credential-provider://...` service namespaces (and `container-registry://<host>` for generic OCI registries) and remain isolated from other `keyring` state:

- Separate from `ado-keyring`, `session.dat`, `gh:<host>`, `copilot-cli`, and `ado` feed URL auto-routing.
- Linux's mode-`0600` `refresh.dat` file used by the `ado` backend (see [Azure DevOps feeds](azure-devops.md#token-caching)) is a dedicated OAuth refresh cache — not general encrypted secret storage — and is never inherited or reused for stored provider or container-registry credentials.
- Podman's `auth.json` `"auths"` table (see [Podman Desktop and Podman](podman.md#why-dual-mode-auths--credhelpers)) is an external client configuration file written only when requested by `keyring podman login`, never a backing store for `StoredCredentialProvider`.
- **`logout` scoping**: `logout` removes only the targeted local `(target, account)` entry. It never revokes shared Azure/Entra MSAL tokens, `ado-keyring` refresh tokens, shared `gh:<host>` OAuth sessions, or credentials stored under other accounts or targets.

## Typed errors and `ProviderChain` fallback rules

`ProviderChain` evaluates providers in order and distinguishes harmless non-matches from authoritative failures. Once a provider owns a target and reports an expired credential, locked/unavailable storage, cancellation, timeout, or invalid input, the chain stops immediately so `keyring` never silently falls through to an unrelated fallback identity or masks a storage error.

| `ProviderError` | Fallback permitted | Behavior in `ProviderChain` |
|---|---|---|
| `UnsupportedTarget` | `true` | Provider does not handle this scheme, host, or target; try the next provider. |
| `UnsupportedOperation` | `true` | Provider does not implement the requested `Operation`; try the next provider. |
| `CredentialNotFound` | `true` | No credential stored or available for `(target, account)`; try the next provider. |
| `ReauthenticationRequired` | `false` | Hard stop: matching credential is expired or revoked and cannot renew noninteractively; caller must run explicit `login`. |
| `StorageUnavailable` | `false` | Hard stop: secure storage backend is unreachable, disabled (`null_backend`), or incompatible (`ado`). |
| `StorageLocked` | `false` | Hard stop: backing Secret Service vault or OS keychain is locked. |
| `AccessDenied` | `false` | Hard stop: OS secret store or upstream authority rejected access. |
| `Cancelled` | `false` | Hard stop: `Request.deadline` cancellation flag was tripped. |
| `DeadlineExceeded` | `false` | Hard stop: `Request.deadline` wall-clock budget expired. |
| `InvalidInput` | `false` | Hard stop: malformed `Target`, invalid `Request`, or inconsistent `CachePolicy` (such as `until_expiration` without `expires_at`). |
| `StorageFailure` | `false` | Hard stop: corrupt stored payload or underlying backend read/write failure. |
| `OutOfMemory` | `false` | Hard stop: allocator could not satisfy the request. |

See also [Usage](usage.md), [Podman Desktop and Podman](podman.md), [Azure DevOps feeds](azure-devops.md), [Headless Linux](headless-linux.md), and [Environment variables](environment-variables.md).
