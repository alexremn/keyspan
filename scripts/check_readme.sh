#!/usr/bin/env bash
# scripts/check_readme.sh — asserts README has the mandatory sections and no leaks.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

fail=0
require() {
  if ! grep -qF "$1" README.md; then
    echo "README missing required content: $1" >&2
    fail=1
  fi
}

[[ -f README.md ]] || { echo "MISSING: README.md" >&2; exit 1; }

require "rotate this credential"
require "keyspan ingest gitleaks examples/reports/gitleaks.json"
require "keyspan blast-radius name:DATABASE_PASSWORD"
require "go install github.com/alexremn/keyspan/cmd/keyspan@latest"
require "cosign verify-blob"
require "checksums.txt.sigstore.json"

if grep -qF 'AKIAIOSFODNN7EXAMPLE' README.md || grep -qF 's3cr3t-pw-do-not-use' README.md; then
  echo "LEAK: raw fixture secret value present in README.md" >&2
  fail=1
fi

[[ "$fail" -eq 0 ]] || { echo "README check FAILED" >&2; exit 1; }
echo "README check passed"
