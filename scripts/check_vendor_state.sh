#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

missing=0

check_path() {
  local p="$1"
  if [[ ! -e "$p" ]]; then
    echo "MISSING: $p"
    missing=1
  else
    echo "OK: $p"
  fi
}

check_path "api/go.sum"
check_path "worker/go.sum"
check_path "api/vendor"
check_path "worker/vendor"

if [[ "$missing" -ne 0 ]]; then
  echo "Vendor state incomplete. See VENDORING.md"
  exit 1
fi

echo "Vendor state is complete."
