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
SERVICE="keyring-it-svc-$SUFFIX"
USER="keyring-it-usr-$SUFFIX"

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
}
trap cleanup EXIT

# 1. set + get round-trip
EXPECTED="secret-value-$SUFFIX"
printf 'secret-value-%s' "$SUFFIX" | "$BIN" set "$SERVICE" "$USER"
OUT=$("$BIN" get "$SERVICE" "$USER")
[ "$OUT" = "$EXPECTED" ] || fail "set + get round-trip" "expected: $EXPECTED" "actual: $OUT"
pass "set + get round-trip"

# 2. get of missing entry returns exit 3
MISSING_SERVICE="$SERVICE-missing"
MISSING_USER="$USER-missing"
"$BIN" del "$MISSING_SERVICE" "$MISSING_USER" >/dev/null 2>&1 || true
set +e
MISSING_OUT=$("$BIN" get "$MISSING_SERVICE" "$MISSING_USER" 2>&1)
RC=$?
set -e
[ "$RC" -eq 3 ] || fail "get missing exits 3" "expected rc: 3" "actual rc: $RC" "output: $MISSING_OUT"
pass "get missing exits 3"

# 3. del removes the entry; second del also exits 3
printf 'delete-me-%s' "$SUFFIX" | "$BIN" set "$SERVICE" "$USER"
"$BIN" del "$SERVICE" "$USER"
set +e
SECOND_DEL_OUT=$("$BIN" del "$SERVICE" "$USER" 2>&1)
RC=$?
set -e
if [ "$RC" -ne 3 ]; then
  if [ "$RC" -eq 1 ] && [ "$(uname -s)" = "Linux" ] && printf '%s\n' "$SECOND_DEL_OUT" | grep -Fq 'platform failure'; then
    set +e
    VERIFY_GET_OUT=$("$BIN" get "$SERVICE" "$USER" 2>&1)
    VERIFY_GET_RC=$?
    set -e
    [ "$VERIFY_GET_RC" -eq 3 ] || fail "del removes entry and second del exits 3" \
      "second del returned Linux secret_service platform failure, and get did not confirm removal" \
      "second del rc: $RC" \
      "second del output: $SECOND_DEL_OUT" \
      "verify get rc: $VERIFY_GET_RC" \
      "verify get output: $VERIFY_GET_OUT"
    echo "NOTE: Linux secret_service returned platform failure for second del; get confirmed the entry was removed."
  else
    fail "del removes entry and second del exits 3" "expected rc: 3" "actual rc: $RC" "output: $SECOND_DEL_OUT"
  fi
fi
pass "del removes entry and second del exits 3"

# 4. --disable + get returns exit 3
set +e
DISABLE_OUT=$("$BIN" --disable get "$SERVICE" "$USER" 2>&1)
RC=$?
set -e
[ "$RC" -eq 3 ] || fail "--disable get exits 3" "expected rc: 3" "actual rc: $RC" "output: $DISABLE_OUT"
pass "--disable get exits 3"

# 5. --list-backends includes native + null
BACKENDS=$("$BIN" --list-backends)
case "$(uname -s)" in
  Linux*) NATIVE_PATTERN='secret_service' ;;
  Darwin*) NATIVE_PATTERN='keychain' ;;
  MINGW*|MSYS*|CYGWIN*) NATIVE_PATTERN='win_credential' ;;
  *) NATIVE_PATTERN='secret_service|keychain|win_credential' ;;
esac
printf '%s\n' "$BACKENDS" | grep -Eq "$NATIVE_PATTERN" || fail "--list-backends includes native" "pattern: $NATIVE_PATTERN" "output: $BACKENDS"
printf '%s\n' "$BACKENDS" | grep -Eq 'null' || fail "--list-backends includes null" "output: $BACKENDS"
pass "--list-backends includes native + null"

# 6. diagnose exits 0 and contains current backend
set +e
DIAG_OUT=$("$BIN" diagnose 2>&1)
RC=$?
set -e
[ "$RC" -eq 0 ] || fail "diagnose exits 0" "expected rc: 0" "actual rc: $RC" "output: $DIAG_OUT"
printf '%s\n' "$DIAG_OUT" | grep -Fq 'current backend:' || fail "diagnose shows current backend" "output: $DIAG_OUT"
pass "diagnose exits 0"

# 7. set then update with a new value, get returns the new value
OLD_SECRET="old-secret-$SUFFIX"
NEW_SECRET="new-secret-$SUFFIX"
printf '%s' "$OLD_SECRET" | "$BIN" set "$SERVICE" "$USER"
printf '%s' "$NEW_SECRET" | "$BIN" set "$SERVICE" "$USER"
OUT=$("$BIN" get "$SERVICE" "$USER")
[ "$OUT" = "$NEW_SECRET" ] || fail "set update returns new value" "expected: $NEW_SECRET" "actual: $OUT"
pass "set update returns new value"

# 8. exit code 2 on bad arity
set +e
BAD_ARITY_OUT=$("$BIN" set 2>&1)
RC=$?
set -e
[ "$RC" -eq 2 ] || fail "bad arity exits 2" "expected rc: 2" "actual rc: $RC" "output: $BAD_ARITY_OUT"
pass "bad arity exits 2"
