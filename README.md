# keyring

`keyring` is a Zig command-line interface for OS credential storage, intended to be compatible with the Python keyring CLI.

On Linux, the built-in Secret Service provider supports browser-based, hardware-backed unlocking over an SSH tunnel using WebAuthn PRF (`hmac-secret`).

## Install

```sh
ghr install cataggar/keyring
```

Linux release assets are fully static musl binaries and do not require a system libc, libsecret, or GLib. The `secret_service` backend still requires access to a running Secret Service daemon.

## Quick start

```sh
keyring set my-service alice     # prompt for a password and store it
keyring get my-service alice     # print it; exits 3 when not found
keyring del my-service alice     # delete it; exits 3 when not found
keyring diagnose                 # report the resolved backend and its health

# Headless Linux with a local browser and security key:
keyring service                  # start the provider in its locked state
keyring enroll                   # enroll a YubiKey and print a Recovery Key
keyring unlock                   # unlock through the browser/SSH tunnel
keyring lock                     # immediately clear the in-memory master key

# Git credential helper for github.com, *.ghe.com, GHES, and Azure DevOps:
keyring gh login --hostname example.ghe.com
keyring git setup --hostname example.ghe.com
```

Use `keyring enroll --add-key`, `--list`, and `--revoke <id>` for multiple authenticators. `keyring unlock --recover` uses the one-time Recovery Key. Set `KEYRING_VAULT_PATH` to override the default encrypted vault path.

## Documentation

- [Usage](doc/usage.md) — commands, options, and backends
- [Environment variables](doc/environment-variables.md)
- [Azure DevOps feeds](doc/azure-devops.md) — the `ado` backend, token caching, and `az login` SSO
- [Headless Linux](doc/headless-linux.md)
- [Exit codes](doc/exit-codes.md)
- [Compatibility with Python `keyring`](doc/python-compatibility.md)

## Links

- Plan: https://github.com/cataggar/keyring/issues/1
- Library: https://github.com/cataggar/keyring-zig

## License

MIT; see [LICENSE](LICENSE).
