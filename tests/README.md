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

## Headless Linux coverage

`headless_linux.sh` requires Linux and Bash, but does not require a Secret
Service daemon, oo7-daemon, GNOME, or D-Bus session. It verifies the
`keyring diagnose` guidance for a missing daemon and an encrypted file-backend
set/get/delete round-trip using an isolated disposable file path.

Build normally and run:

```sh
zig build
bash tests/headless_linux.sh
```

CI runs this script only on Linux. It deliberately does not test starting
oo7-daemon or GNOME; those remain manual integration prerequisites for
`integration.sh`. Source builders can exclude the file backend with
`zig build -Dfile-backend=false`.
