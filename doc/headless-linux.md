# Using `keyring` on headless Linux

On a graphical Linux desktop, `gnome-keyring-daemon` is usually started by the
session manager and exposes the Secret Service API. In SSH-only, container, or
CI environments, no Secret Service daemon may be running, so `keyring` can
return `NoStorageAccess` until you start one.

## Option A: oo7-daemon (recommended for headless servers + CI)

[`oo7-daemon`](https://github.com/linux-credentials/oo7) is a pure-Rust,
MIT-licensed Secret Service daemon that is friendly to headless environments.
Follow the install instructions in the
[oo7 README](https://github.com/linux-credentials/oo7), then run it on a session
bus and point clients at that bus:

```sh
export DBUS_SESSION_BUS_ADDRESS=unix:path="$XDG_RUNTIME_DIR/bus"
oo7-daemon &
keyring diagnose
```

## Option B: GNOME stack

If you already have the GNOME Secret Service stack available, start it under a
D-Bus session. This is the pattern used by `cataggar/keyring-zig` CI tests:

```sh
dbus-run-session -- bash -lc 'eval "$(printf "\n" | gnome-keyring-daemon --unlock --components=secrets)"; keyring diagnose'
```

## Option C: file backend

`KEYRING_BACKEND=file` uses an AES-256-GCM encrypted on-disk credential store
when you do not want to rely on a Secret Service daemon. It is an optional
build feature, so builds from source must enable it:

```sh
zig build -Dfile-backend=true -Doptimize=ReleaseSafe
```

Set both the store path and passphrase before using it. Choose a private path
outside the repository for persistent credentials:

```sh
export KEYRING_BACKEND=file
export KEYRING_FILE_PATH="$HOME/.local/share/keyring/credentials.dat"
export KEYRING_FILE_PASSPHRASE='use-a-secret-from-your-password-manager'
keyring set my-service alice
keyring get my-service alice
```

`keyring diagnose` detects the missing Secret Service daemon and prints these
recommendations.

## Automated coverage

On Linux, `tests/headless_linux.sh` points D-Bus at a nonexistent socket and
checks that `keyring diagnose` exits successfully with the oo7-daemon, GNOME
under `dbus-run-session`, and file-backend hints. It also performs an isolated
file-backend set/get/delete round-trip using a disposable path under
`.zig-cache/`.

Run it with a binary built with the file backend:

```sh
zig build -Dfile-backend=true
bash tests/headless_linux.sh
```

The test does not start or exercise oo7-daemon or GNOME; it only verifies the
guidance shown when a Secret Service daemon is unavailable.
