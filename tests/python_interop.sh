#!/usr/bin/env bash
set -euo pipefail

if [ -n "${KEYRING_BIN:-}" ]; then
  BIN="$KEYRING_BIN"
elif [ -f ./zig-out/bin/keyring ]; then
  BIN="./zig-out/bin/keyring"
elif [ -f ./zig-out/bin/keyring.exe ]; then
  BIN="./zig-out/bin/keyring.exe"
else
  echo "FAIL: locate binary"
  echo "Could not find ./zig-out/bin/keyring or ./zig-out/bin/keyring.exe. Set KEYRING_BIN to a custom path."
  exit 1
fi

SUFFIX="$(date +%s)-$$-$RANDOM"
SERVICE="keyring-py-it-svc-$SUFFIX"
USER="keyring-py-it-usr-$SUFFIX"
SECRET="python-secret-$SUFFIX"
SECRET2="zig-secret-$SUFFIX"

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
  "$BIN" del "$SERVICE" "$USER" >/dev/null 2>&1 || true
  SERVICE="$SERVICE" USER="$USER" python3 - <<'PY' >/dev/null 2>&1 || true
import os
import keyring
try:
    keyring.delete_password(os.environ["SERVICE"], os.environ["USER"])
except Exception:
    pass
PY
}
trap cleanup EXIT

# 1. Python writes, Zig reads
SERVICE="$SERVICE" USER="$USER" SECRET="$SECRET" python3 - <<'PY'
import os
import keyring
keyring.set_password(os.environ["SERVICE"], os.environ["USER"], os.environ["SECRET"])
PY
ZIG_GET_RC=1
OUT=""
for _ in 1 2 3 4 5; do
  set +e
  OUT=$("$BIN" get "$SERVICE" "$USER" 2>&1)
  ZIG_GET_RC=$?
  set -e
  [ "$ZIG_GET_RC" -eq 0 ] && break
  sleep 0.2
done
[ "$ZIG_GET_RC" -eq 0 ] || fail "python->zig interop" \
  "Python keyring wrote service=$SERVICE user=$USER, but Zig could not read it." \
  "zig get rc: $ZIG_GET_RC" \
  "zig get output: $OUT" \
  "This may indicate a schema/attribute mismatch between Python keyring's SecretStorage backend and keyring-zig."
[ "$OUT" = "$SECRET" ] || fail "python->zig interop" \
  "Python keyring wrote service=$SERVICE user=$USER, but Zig read a different value." \
  "expected: $SECRET" \
  "actual: $OUT" \
  "This may indicate a schema/attribute mismatch between Python keyring's SecretStorage backend and keyring-zig."
pass "python->zig interop"

# 2. Zig writes, Python reads
"$BIN" del "$SERVICE" "$USER" >/dev/null 2>&1 || true
printf '%s' "$SECRET2" | "$BIN" set "$SERVICE" "$USER"
PY_GET_RC=1
OUT=""
for _ in 1 2 3 4 5; do
  set +e
  OUT=$(SERVICE="$SERVICE" USER="$USER" python3 - <<'PY'
import os
import keyring
password = keyring.get_password(os.environ["SERVICE"], os.environ["USER"])
print("" if password is None else password, end="")
PY
)
  PY_GET_RC=$?
  set -e
  [ "$PY_GET_RC" -eq 0 ] && [ "$OUT" = "$SECRET2" ] && break
  sleep 0.2
done
[ "$PY_GET_RC" -eq 0 ] || fail "zig->python interop" \
  "Zig wrote service=$SERVICE user=$USER, but Python keyring failed to read it." \
  "python get rc: $PY_GET_RC" \
  "python get output: $OUT" \
  "This may indicate a schema/attribute mismatch between keyring-zig and Python keyring's SecretStorage backend."
[ "$OUT" = "$SECRET2" ] || fail "zig->python interop" \
  "Zig wrote service=$SERVICE user=$USER, but Python keyring read a different value." \
  "expected: $SECRET2" \
  "actual: $OUT" \
  "This may indicate a schema/attribute mismatch between keyring-zig and Python keyring's SecretStorage backend."
pass "zig->python interop"
