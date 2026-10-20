#!/usr/bin/env bash
set -euo pipefail

case "$(uname -s)" in
  Linux*) ;;
  *)
    echo "SKIP: WebAuthn service integration requires Linux"
    exit 0
    ;;
esac

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
BIN="${KEYRING_BIN:-$ROOT_DIR/zig-out/bin/keyring}"

if [ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ]; then
  exec dbus-run-session -- "$0"
fi

[ -x "$BIN" ] || {
  echo "FAIL: keyring binary not found at $BIN"
  exit 1
}

SUFFIX="$$-$RANDOM"
TEST_DIR="$ROOT_DIR/.zig-cache/webauthn-service-$SUFFIX"
VAULT_PATH="$TEST_DIR/vault.json"
HELPER="$TEST_DIR/virtual_webauthn.py"
SERVICE_LOG="$TEST_DIR/service.log"
ENROLL_OUT="$TEST_DIR/enroll.out"
ENROLL_ERR="$TEST_DIR/enroll.err"
UNLOCK_OUT="$TEST_DIR/unlock.out"
UNLOCK_ERR="$TEST_DIR/unlock.err"
SERVICE_PID=""

cleanup() {
  if [ -n "$SERVICE_PID" ] && kill -0 "$SERVICE_PID" 2>/dev/null; then
    kill "$SERVICE_PID" 2>/dev/null || true
    wait "$SERVICE_PID" 2>/dev/null || true
  fi
  rm -rf -- "$TEST_DIR"
}

fail() {
  echo "FAIL: $1"
  for log in "$SERVICE_LOG" "$ENROLL_OUT" "$ENROLL_ERR" "$UNLOCK_OUT" "$UNLOCK_ERR"; do
    if [ -f "$log" ]; then
      echo "--- $(basename "$log") ---"
      cat "$log"
    fi
  done
  exit 1
}

wait_for_url() {
  local file="$1"
  local url=""
  for _ in $(seq 1 200); do
    url="$(grep -Eo 'http://localhost:[0-9]+/#token=[A-Za-z0-9_-]+' "$file" 2>/dev/null | tail -1 || true)"
    if [ -n "$url" ]; then
      printf '%s\n' "$url"
      return 0
    fi
    sleep 0.05
  done
  return 1
}

umask 077
mkdir -p "$TEST_DIR"
trap cleanup EXIT

cat >"$HELPER" <<'PY'
import base64
import hashlib
import hmac
import http.client
import json
import struct
import sys
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

mode, browser_url = sys.argv[1:3]
parsed = urlsplit(browser_url)
port = parsed.port
token = parsed.fragment.split("token=", 1)[1]
origin = f"http://localhost:{port}"
credential_id = b"keyring-ci-ed25519-credential"
private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
prf_key = bytes(range(33, 65))

def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()

def unb64(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

def request(path, body=b"{}", headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    request_headers = {
        "Host": f"localhost:{port}",
        "Origin": origin,
        "Content-Type": "application/json",
    }
    if headers:
        request_headers.update(headers)
    connection.request("POST", path, body=body, headers=request_headers)
    response = connection.getresponse()
    payload = response.read()
    connection.close()
    return response.status, payload

status, _ = request("/api/options")
assert status == 401, status
status, _ = request("/api/options", headers={"X-Keyring-Token": token, "Origin": "http://evil.invalid"})
assert status == 403, status
status, _ = request("/api/options", headers={"X-Keyring-Token": token, "Host": f"127.0.0.1:{port}"})
assert status == 403, status

status, payload = request("/api/options", headers={"X-Keyring-Token": token})
assert status == 200, (status, payload)
options = json.loads(payload)
challenge = options["challenge"]
client_data = json.dumps(
    {
        "type": "webauthn.create" if mode == "enroll" else "webauthn.get",
        "challenge": challenge,
        "origin": origin,
    },
    separators=(",", ":"),
).encode()

def cbor_head(major, value):
    if value < 24:
        return bytes([(major << 5) | value])
    if value < 256:
        return bytes([(major << 5) | 24, value])
    return bytes([(major << 5) | 25]) + struct.pack(">H", value)

def cbor_bytes(value):
    return cbor_head(2, len(value)) + value

def cbor_text(value):
    encoded = value.encode()
    return cbor_head(3, len(encoded)) + encoded

rp_hash = hashlib.sha256(b"localhost").digest()
if mode == "enroll":
    cose = (
        cbor_head(5, 4)
        + b"\x01\x01"
        + b"\x03\x27"
        + b"\x20\x06"
        + b"\x21"
        + cbor_bytes(public_key)
    )
    auth_data = (
        rp_hash
        + b"\x41"
        + struct.pack(">I", 1)
        + bytes(16)
        + struct.pack(">H", len(credential_id))
        + credential_id
        + cose
    )
    attestation = cbor_head(5, 1) + cbor_text("authData") + cbor_bytes(auth_data)
    salt = unb64(options["prfSalt"])
    complete = {
        "credentialId": b64(credential_id),
        "clientDataJSON": b64(client_data),
        "attestationObject": b64(attestation),
        "prfOutput": b64(hmac.new(prf_key, salt, hashlib.sha256).digest()),
    }
else:
    credential = next(item for item in options["credentials"] if item["credentialId"] == b64(credential_id))
    salt = unb64(credential["prfSalt"])
    auth_data = rp_hash + b"\x01" + struct.pack(">I", 2)
    signed = auth_data + hashlib.sha256(client_data).digest()
    complete = {
        "credentialId": b64(credential_id),
        "clientDataJSON": b64(client_data),
        "authenticatorData": b64(auth_data),
        "signature": b64(private_key.sign(signed)),
        "prfOutput": b64(hmac.new(prf_key, salt, hashlib.sha256).digest()),
    }

encoded = json.dumps(complete, separators=(",", ":")).encode()
status, payload = request(
    "/api/complete",
    body=encoded,
    headers={"X-Keyring-Token": token},
)
assert status == 200, (status, payload)
PY

export KEYRING_VAULT_PATH="$VAULT_PATH"
export KEYRING_BACKEND=secret_service

"$BIN" service >"$SERVICE_LOG" 2>&1 &
SERVICE_PID=$!
for _ in $(seq 1 100); do
  if "$BIN" lock >/dev/null 2>&1; then
    break
  fi
  sleep 0.05
done
kill -0 "$SERVICE_PID" 2>/dev/null || fail "keyring service did not start"

set +e
LOCKED_OUTPUT="$("$BIN" get test-svc test-user 2>&1)"
LOCKED_RC=$?
set -e
[ "$LOCKED_RC" -eq 1 ] || fail "locked get should exit 1"
printf '%s\n' "$LOCKED_OUTPUT" | grep -Fqi locked || fail "locked get should report locked"

"$BIN" enroll --label test-yubikey >"$ENROLL_OUT" 2>"$ENROLL_ERR" &
ENROLL_PID=$!
ENROLL_URL="$(wait_for_url "$ENROLL_ERR")" || fail "enrollment URL was not printed"
python3 "$HELPER" enroll "$ENROLL_URL" || fail "virtual enrollment ceremony failed"
wait "$ENROLL_PID" || fail "keyring enroll failed"

RECOVERY_KEY="$(grep -Eo '([0-9A-HJKMNP-TV-Z]{4}-){5}[0-9A-HJKMNP-TV-Z]{4}' "$ENROLL_OUT" | head -1)"
[ -n "$RECOVERY_KEY" ] || fail "recovery key was not printed"
"$BIN" enroll --list | grep -Fq 'label=test-yubikey' || fail "enrolled key was not listed"

printf '%s\n' 'integration-secret' | "$BIN" set test-svc test-user
[ "$("$BIN" get test-svc test-user)" = "integration-secret" ] || fail "keyring set/get round-trip failed"

if command -v secret-tool >/dev/null 2>&1; then
  printf '%s' 'secret-tool-value' | secret-tool store --label=keyring-ci service test-svc username secret-tool-user
  [ "$(secret-tool lookup service test-svc username secret-tool-user)" = "secret-tool-value" ] || fail "secret-tool round-trip failed"
fi

"$BIN" lock
set +e
LOCKED_OUTPUT="$("$BIN" get test-svc test-user 2>&1)"
LOCKED_RC=$?
set -e
[ "$LOCKED_RC" -eq 1 ] || fail "locked get after lock should exit 1"
printf '%s\n' "$LOCKED_OUTPUT" | grep -Fqi locked || fail "locked get after lock should report locked"

"$BIN" unlock >"$UNLOCK_OUT" 2>"$UNLOCK_ERR" &
UNLOCK_PID=$!
UNLOCK_URL="$(wait_for_url "$UNLOCK_ERR")" || fail "unlock URL was not printed"
python3 "$HELPER" unlock "$UNLOCK_URL" || fail "virtual unlock ceremony failed"
wait "$UNLOCK_PID" || fail "keyring unlock failed"
[ "$("$BIN" get test-svc test-user)" = "integration-secret" ] || fail "browser unlock did not restore access"

"$BIN" lock
printf '%s\n' "$RECOVERY_KEY" | "$BIN" unlock --recover
[ "$("$BIN" get test-svc test-user)" = "integration-secret" ] || fail "recovery unlock did not restore access"

echo "PASS: WebAuthn enrollment, browser unlock, recovery unlock, and Secret Service round-trip"
