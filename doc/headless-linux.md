# Using `keyring` on headless Linux

On a graphical Linux desktop, `gnome-keyring-daemon` is usually started by the
session manager and exposes the Secret Service API. In SSH-only, container, or
CI environments, no Secret Service daemon may be running, so `keyring` can
return `NoStorageAccess` until you start one.

## Hardware-backed unlocking over SSH

The built-in `keyring service` provides Secret Service storage whose master key is released only after WebAuthn PRF approval by a local security key. It is intended for a headless remote machine reached over SSH.

Requirements:

- A YubiKey or other FIDO2 authenticator supporting CTAP2 `hmac-secret`.
- A browser supporting the WebAuthn `prf` extension.
- A D-Bus session bus on the remote Linux account.

Start the provider on the remote machine:

```sh
dbus-run-session -- bash
keyring service &
```

For persistent login sessions, install this user unit as `~/.config/systemd/user/keyring.service`:

```ini
[Unit]
Description=Keyring Secret Service

[Service]
ExecStart=/usr/local/bin/keyring service
Restart=on-failure

[Install]
WantedBy=default.target
```

Then run `systemctl --user daemon-reload && systemctl --user enable --now keyring.service`.

### Initial enrollment

Run `keyring enroll --label primary-yubikey`. The command prints an ephemeral port and an exact forwarding command such as:

```sh
ssh -L 42317:127.0.0.1:42317 remote.example
```

Create that tunnel from the machine with the browser and YubiKey, open the printed `http://localhost:42317/#token=...` URL, and approve the registration. Save the one-time Recovery Key in a password manager or other offline location. The token is short-lived and remains in the URL fragment; it is not sent in HTTP request URLs.

After enrollment, normal Secret Service clients work while the provider is unlocked:

```sh
keyring set my-service alice
keyring get my-service alice
```

### Locking and unlocking

Lock immediately with `keyring lock`. To unlock again, run `keyring unlock`, create the printed SSH forwarding tunnel, open the browser URL, and touch the enrolled key. Use `--port <port>` when firewall or forwarding configuration requires a fixed remote port and `--timeout <seconds>` to change the 120-second approval window.

If no enrolled key is available, recover with:

```sh
keyring unlock --recover
```

The Recovery Key is read from the TTY with echo disabled, or from stdin for automation.

### Multiple security keys

Enroll and manage backup authenticators with:

```sh
keyring enroll --add-key --label backup-yubikey
keyring enroll --list
keyring enroll --revoke <id>
```

Adding a key requires approval from an existing enrolled key. Add `--recover` to authorize with the Recovery Key instead. Revoking the last PRF key is refused unless `--force` is supplied; recovery enrollment remains available with `keyring enroll --recover`.

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
when you do not want to rely on a Secret Service daemon. Default and release
builds include this backend. Source builders that do not need it can opt out:

```sh
zig build -Dfile-backend=false
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

Run it with the default build:

```sh
zig build
bash tests/headless_linux.sh
```

The test does not start or exercise oo7-daemon or GNOME; it only verifies the
guidance shown when a Secret Service daemon is unavailable.
