#!/usr/bin/env bash
set -euo pipefail

binary="${1:?usage: verify_static_elf.sh <binary>}"

if [ ! -f "$binary" ]; then
  echo "$binary does not exist" >&2
  exit 1
fi

readelf -hW "$binary" >/dev/null

if readelf -lW "$binary" | grep -q 'INTERP'; then
  echo "$binary contains a dynamic program interpreter" >&2
  exit 1
fi

if readelf -dW "$binary" 2>/dev/null | grep -q '(NEEDED)'; then
  echo "$binary contains dynamic library dependencies" >&2
  exit 1
fi
