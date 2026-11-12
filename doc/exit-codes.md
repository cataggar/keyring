# Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | operation failure, including locked storage, WebAuthn authentication/PRF failure, vault decryption failure, timeout, cloned-authenticator detection, an unavailable built-in service, or failed `devops-npm --validate-only` checks |
| 2 | invalid usage, malformed hostname/registry target, or invalid configuration selector (such as `KEYRING_ADO_STORE`) |
| 3 | credential, account, or import/export source not found across `get`, `del`, `az export`, `gh export` / `gh import`, `copilot` (`token`, `env`, `logout`, `import`, `export`), `podman`, and `wslc` |
| 4 | no storage access or backend unavailable / unsupported for the command (including `-b ado` / `KEYRING_BACKEND=ado` on `gh`, `copilot`, `podman`, or `wslc`) |

WebAuthn and built-in service failures use distinct diagnostics on stderr. In particular, `keyring unlock` tells the user whether authentication, PRF support, decryption, the signature counter, approval timeout, or D-Bus service availability caused the failure.

## Credential helper wire-protocol exit semantics

External credential-helper endpoints follow their caller's wire-protocol exit conventions rather than interactive CLI codes `3` / `4`:

- **`keyring git credential <get|store|erase>` (`git-credential-keyring`)**: Exits `0` with empty stdout when a protocol, host, or credential is unknown, missing, or unavailable so Git can fall through cleanly to subsequent helpers without aborting. Invalid helper subcommands or argument counts still exit `2`.
- **`keyring podman credential <get|store|erase|list|version>` (`docker-credential-keyring`) and `keyring wslc credential <get|store|erase>`**: Exit `0` on success (including idempotent `erase` when an entry is already absent) and exit `1` when a credential is not found, the store is locked/unavailable, or stdin contains malformed protocol input. Invalid helper subcommands or argument counts exit `2`.
