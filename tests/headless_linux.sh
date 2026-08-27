#!/usr/bin/env bash
set -euo pipefail

case "$(uname -s)" in
  Linux*) ;;
  *)
    echo "SKIP: headless Linux tests require Linux"
    exit 0
    ;;
esac

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"

if [ -n "${KEYRING_BIN:-}" ]; then
  BIN="$KEYRING_BIN"
else
  BIN="$ROOT_DIR/zig-out/bin/keyring"
fi

if [ ! -f "$BIN" ]; then
  echo "FAIL: locate binary"
  echo "Could not find $ROOT_DIR/zig-out/bin/keyring. Set KEYRING_BIN to a custom path."
  exit 1
fi

SUFFIX="$$-$RANDOM"
TEST_DIR="$ROOT_DIR/.zig-cache/keyring-headless-linux-$SUFFIX"
STORE_PATH="$TEST_DIR/credentials.dat"
BAD_BUS_ADDRESS="unix:path=$TEST_DIR/no-session-bus"
SERVICE="keyring-headless-service-$SUFFIX"
USER="keyring-headless-user-$SUFFIX"
PASSPHRASE="keyring-headless-passphrase-$SUFFIX"

fail() {
  local name="$1"
  shift || true
  echo "FAIL: $name"
  if [ "$#" -gt 0 ]; then
    printf '%s\n' "$@"
  fi
  exit 1
}

pass() {
  echo "PASS: $1"
}

cleanup() {
  rm -rf -- "$TEST_DIR"
}

umask 077
mkdir "$TEST_DIR" || fail "create isolated test directory" "path: $TEST_DIR"
trap cleanup EXIT

# Point D-Bus at a socket within the test directory that cannot have a daemon.
set +e
DIAG_OUT=$(NO_COLOR=1 DBUS_SESSION_BUS_ADDRESS="$BAD_BUS_ADDRESS" "$BIN" diagnose 2>&1)
RC=$?
set -e
[ "$RC" -eq 0 ] || fail "headless diagnose exits 0" "expected rc: 0" "actual rc: $RC" "output: $DIAG_OUT"
for HINT in \
  'no Secret Service daemon detected.' \
  'install oo7-daemon' \
  'gnome-keyring-daemon --unlock --components=secrets under dbus-run-session' \
  'KEYRING_BACKEND=file'; do
  printf '%s\n' "$DIAG_OUT" | grep -Fq "$HINT" || fail "headless diagnose includes hint" "missing: $HINT" "output: $DIAG_OUT"
done
pass "headless diagnose exits 0 with recovery hints"

BACKENDS=$("$BIN" --list-backends)
printf '%s\n' "$BACKENDS" | grep -Fxq 'file' || fail "file backend is enabled" "output: $BACKENDS"

EXPECTED="headless-secret-$SUFFIX"
env \
  DBUS_SESSION_BUS_ADDRESS="$BAD_BUS_ADDRESS" \
  KEYRING_BACKEND=file \
  KEYRING_FILE_PATH="$STORE_PATH" \
  KEYRING_FILE_PASSPHRASE="$PASSPHRASE" \
  "$BIN" set "$SERVICE" "$USER" <<<"$EXPECTED"

OUT=$(env \
  DBUS_SESSION_BUS_ADDRESS="$BAD_BUS_ADDRESS" \
  KEYRING_BACKEND=file \
  KEYRING_FILE_PATH="$STORE_PATH" \
  KEYRING_FILE_PASSPHRASE="$PASSPHRASE" \
  "$BIN" get "$SERVICE" "$USER")
[ "$OUT" = "$EXPECTED" ] || fail "file backend set + get round-trip" "expected: $EXPECTED" "actual: $OUT"
pass "file backend set + get round-trip"

env \
  DBUS_SESSION_BUS_ADDRESS="$BAD_BUS_ADDRESS" \
  KEYRING_BACKEND=file \
  KEYRING_FILE_PATH="$STORE_PATH" \
  KEYRING_FILE_PASSPHRASE="$PASSPHRASE" \
  "$BIN" del "$SERVICE" "$USER"

set +e
MISSING_OUT=$(env \
  DBUS_SESSION_BUS_ADDRESS="$BAD_BUS_ADDRESS" \
  KEYRING_BACKEND=file \
  KEYRING_FILE_PATH="$STORE_PATH" \
  KEYRING_FILE_PASSPHRASE="$PASSPHRASE" \
  "$BIN" get "$SERVICE" "$USER" 2>&1)
RC=$?
set -e
[ "$RC" -eq 3 ] || fail "file backend missing entry exits 3" "expected rc: 3" "actual rc: $RC" "output: $MISSING_OUT"
pass "file backend delete removes entry"
