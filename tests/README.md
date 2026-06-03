# Integration tests

These tests exercise the built `keyring` CLI against the native OS keychain.
They also verify that the compiled-in `ado` backend is listed and short-circuits non-Azure-DevOps URLs without starting interactive auth.

## Prerequisites

- Linux: `libsecret-1-dev`, `libglib2.0-dev`, `dbus`, `gnome-keyring`, `libsecret-tools`, and `python3-pip`. Run inside an unlocked Secret Service session, for example with `dbus-run-session` and `gnome-keyring-daemon`.
- macOS: the `security` command-line tool. For isolated local runs, create and select a temporary keychain before running the tests, then delete it afterward.
- Windows: Git Bash and access to Windows Credential Manager.

## Running

Build first:

```sh
zig build -Doptimize=ReleaseSafe
bash tests/integration.sh
```

To test a custom binary:

```sh
KEYRING_BIN=./zig-out/bin/keyring bash tests/integration.sh
```

Linux Python interop tests require Python `keyring`:

```sh
pip install keyring
bash tests/python_interop.sh
```
