#!/usr/bin/env bash
# scripts/check_community_docs.sh — asserts community health docs are substantive.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

fail=0
need_file() { [[ -f "$1" ]] || { echo "MISSING: $1" >&2; fail=1; }; }
need_text() {
  if ! grep -qiF "$2" "$1"; then
    echo "$1 missing required content: $2" >&2
    fail=1
  fi
}

need_file SECURITY.md
need_file CONTRIBUTING.md
need_file CODE_OF_CONDUCT.md
need_file CHANGELOG.md

need_text SECURITY.md "Supported Versions"
need_text SECURITY.md "Reporting a Vulnerability"
need_text SECURITY.md "business days"
need_text SECURITY.md "Sensitive Artifacts"
need_text SECURITY.md "fingerprints, not raw values"
need_text SECURITY.md "low-entropy"

need_text CONTRIBUTING.md "go test -race"
need_text CODE_OF_CONDUCT.md "Contributor Covenant"

need_text CHANGELOG.md "Keep a Changelog"
need_text CHANGELOG.md "## [Unreleased]"

[[ "$fail" -eq 0 ]] || { echo "community docs check FAILED" >&2; exit 1; }
echo "community docs check passed"
