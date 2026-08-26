# Usage

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

## Backends

Backends are `secret_service`, `keychain`, `win_credential`, `file`, `ado`, and
`null_backend` (`null` is accepted as an alias for `null_backend`).

The `file` backend comes from the upstream keyring-zig package and stores
encrypted credentials on disk, which is useful when no secret-service daemon is
available. See [Headless Linux](headless-linux.md).

See also [Environment variables](environment-variables.md) and
[Exit codes](exit-codes.md).
