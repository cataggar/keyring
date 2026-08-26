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

`KEYRING_BACKEND=file` uses the upstream file backend for encrypted on-disk
credentials when you do not want to rely on a secret-service daemon.

`keyring diagnose` detects the missing Secret Service daemon and prints these
recommendations.
