# keyring

`keyring` is a Zig command-line interface for OS credential storage, intended to be compatible with the Python keyring CLI.

## Status

Phase B implements the core Python-compatible CLI surface for storing, reading, deleting, listing, and diagnosing keyring backends.

## Usage

```sh
keyring --help
keyring --version
keyring --list-backends
keyring diagnose

# Prompt for a password and store it.
keyring set my-service alice

# Store a password from stdin.
echo TOKEN | keyring set my-service alice

# Print the password with no trailing newline.
keyring get my-service alice

# Delete an entry.
keyring del my-service alice

# Use a one-shot backend override.
keyring -b null get my-service alice
keyring -b secret_service set my-service alice

# Disable storage for this process.
keyring --disable
keyring --disable get my-service alice
```

Backends are `secret_service`, `keychain`, `win_credential`, and `null_backend` (`null` is accepted as an alias for `null_backend`).

### Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | generic failure, such as platform failure or locked storage |
| 2 | invalid usage |
| 3 | entry not found from `get` or `del` |
| 4 | no storage access or backend unavailable |

### Compatibility with Python `keyring`

The CLI follows Python `keyring` command shapes for `set`, `get`, and `del`. Entries written by Python's `keyring set svc user` are readable with `keyring get svc user`, and vice versa, when both commands use the same native backend.

## Links

- Plan: https://github.com/cataggar/keyring/issues/1
- Library: https://github.com/cataggar/keyring-zig

## License

MIT; see [LICENSE](LICENSE).
