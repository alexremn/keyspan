#!/usr/bin/env bash
# scripts/check_docs.sh — asserts ARCHITECTURE.md and ROADMAP.md cover the essentials.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

fail=0
need() {
  if ! grep -qiF "$2" "$1"; then
    echo "$1 missing required content: $2" >&2
    fail=1
  fi
}

[[ -f docs/ARCHITECTURE.md ]] || { echo "MISSING: docs/ARCHITECTURE.md" >&2; fail=1; }
[[ -f docs/ROADMAP.md ]] || { echo "MISSING: docs/ROADMAP.md" >&2; fail=1; }
[[ "$fail" -eq 0 ]] || { echo "docs check FAILED (missing file)" >&2; exit 1; }

need docs/ARCHITECTURE.md "Scan/Ingest"
need docs/ARCHITECTURE.md "Correlate"
need docs/ARCHITECTURE.md "Render"
need docs/ARCHITECTURE.md "does not physically merge"
need docs/ARCHITECTURE.md "widest-path"
need docs/ARCHITECTURE.md "High"
need docs/ARCHITECTURE.md "0.85"

need docs/ROADMAP.md "AWS"
need docs/ROADMAP.md "GitLab"
need docs/ROADMAP.md "SealedSecret"
need docs/ROADMAP.md "open-core"
need docs/ROADMAP.md "diff"
need docs/ROADMAP.md "alerting"

[[ "$fail" -eq 0 ]] || { echo "docs check FAILED" >&2; exit 1; }
echo "docs check passed"
