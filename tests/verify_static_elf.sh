#!/usr/bin/env bash
set -euo pipefail

binary="${1:?usage: verify_static_elf.sh <binary>}"

if ! command -v readelf >/dev/null 2>&1; then
  echo "readelf is required to verify static ELF binaries" >&2
  exit 1
fi

if [ ! -f "$binary" ]; then
  echo "$binary does not exist" >&2
  exit 1
fi

readelf -hW "$binary" >/dev/null
prog_headers="$(readelf -lW "$binary")"
dyn_section="$(readelf -dW "$binary")"

if grep -Fq 'INTERP' <<<"$prog_headers"; then
  echo "$binary contains a dynamic program interpreter" >&2
  exit 1
fi

if grep -Fq '(NEEDED)' <<<"$dyn_section"; then
  echo "$binary contains dynamic library dependencies" >&2
  exit 1
fi
