# Integration tests

These tests exercise the built `keyring` CLI against the native OS keychain, helper `argv[0]` entrypoints (`docker-credential-keyring` and `git-credential-keyring`), the built-in Linux WebAuthn Secret Service daemon, headless Linux diagnostics, and static musl ELF linking.
They also verify that the compiled-in `ado` backend is listed and short-circuits non-Azure-DevOps URLs without starting interactive auth.

## Prerequisites

- Linux: `dbus`, `gnome-keyring`, `libsecret-tools`, `python3-cryptography`, and `python3-pip` (plus `binutils` / `readelf` for `verify_static_elf.sh`). `keyring` talks to D-Bus directly and does not require `libsecret` or GLib development headers. For `integration.sh` and `python_interop.sh`, run inside an unlocked Secret Service session, for example with `dbus-run-session` and `gnome-keyring-daemon`.
- macOS: the `security` command-line tool. For isolated local runs, create and select a temporary keychain before running the tests, then delete it afterward.
- Windows: Git Bash and access to Windows Credential Manager.

## Running

All scripts resolve the repository root automatically from `BASH_SOURCE[0]`, so they can be invoked from any working directory.

Build first:

```sh
zig build -Doptimize=safe
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

## Headless Linux coverage (`tests/headless_linux.sh`)

`headless_linux.sh` requires Linux and Bash, but does not require a Secret
Service daemon, oo7-daemon, GNOME, or D-Bus session. It verifies the
`keyring diagnose` guidance for a missing daemon and an encrypted file-backend
set/get/delete round-trip using an isolated disposable directory under
`${TMPDIR:-/tmp}`.

Build normally and run:

```sh
zig build
bash tests/headless_linux.sh
```

CI runs this script only on Linux. It deliberately does not test starting
oo7-daemon or GNOME; those remain integration prerequisites for
`integration.sh`. Source builders can exclude the file backend with
`zig build -Dfile-backend=false`.

## WebAuthn Secret Service integration (`tests/webauthn_service_integration.sh`)

`webauthn_service_integration.sh` runs on Linux and re-execs itself inside an
isolated `dbus-run-session` automatically. Using `python3-cryptography` to drive
a virtual Ed25519 + PRF authenticator in an isolated `${TMPDIR:-/tmp}` workspace,
it verifies:

- `keyring service` startup, locked-by-default reads, and `keyring lock`
- Loopback HTTP Host/Origin/CSRF token enforcement during `keyring enroll` and `keyring unlock`
- Recovery Key unlocking (`keyring unlock --recover`), `secret-tool` interop (when `libsecret-tools` is installed), and `keyring service status` / `install` / `uninstall`
- `keyring copilot import`, `token`, `env`, and `status` against the unlocked Secret Service daemon

```sh
zig build
bash tests/webauthn_service_integration.sh
```

## Static Linux ELF verification (`tests/verify_static_elf.sh`)

`verify_static_elf.sh` uses `readelf` to verify that static Linux musl release
binaries contain no `INTERP` program header and no `(NEEDED)` dynamic library
entries:

```sh
zig build -Doptimize=safe -Dtarget=x86_64-linux-musl
bash tests/verify_static_elf.sh zig-out/bin/keyring
bash tests/verify_static_elf.sh zig-out/bin/docker-credential-keyring
```
