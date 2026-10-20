# Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | operation failure, including locked storage, WebAuthn authentication/PRF failure, vault decryption failure, timeout, cloned-authenticator detection, or an unavailable built-in service |
| 2 | invalid usage |
| 3 | entry not found from `get` or `del` |
| 4 | no storage access or backend unavailable |

WebAuthn and built-in service failures use distinct diagnostics on stderr. In particular, `keyring unlock` tells the user whether authentication, PRF support, decryption, the signature counter, approval timeout, or D-Bus service availability caused the failure.
