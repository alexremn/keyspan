#!/usr/bin/env bash
# scripts/check_spdx.sh — verifies LICENSE exists and every .go file has the SPDX header.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

fail=0

if [[ ! -f LICENSE ]]; then
  echo "MISSING: LICENSE file" >&2
  fail=1
elif ! grep -q "Apache License" LICENSE; then
  echo "LICENSE does not contain 'Apache License'" >&2
  fail=1
fi

expected='// SPDX-License-Identifier: Apache-2.0'
while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  if [[ "$(head -n 1 "$f")" != "$expected" ]]; then
    echo "MISSING SPDX header: $f" >&2
    fail=1
  fi
done < <(git ls-files '*.go')

if [[ "$fail" -ne 0 ]]; then
  echo "SPDX/LICENSE check FAILED" >&2
  exit 1
fi
echo "SPDX/LICENSE check passed"
