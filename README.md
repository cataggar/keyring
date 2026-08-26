# keyring

`keyring` is a Zig command-line interface for OS credential storage, intended to be compatible with the Python keyring CLI.

Phases A-C are complete; Phase D adds headless Linux ergonomics and diagnostics.

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
```

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
