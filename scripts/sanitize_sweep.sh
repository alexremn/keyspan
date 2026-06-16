#!/usr/bin/env bash
# scripts/sanitize_sweep.sh — final public-readiness sweep: no TECH_SPEC,
# gitignore guards artifacts, no stray raw secret markers in tracked files.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

fail=0

# 1. TECH_SPEC.md must no longer be tracked.
if git ls-files --error-unmatch TECH_SPEC.md >/dev/null 2>&1; then
  echo "TECH_SPEC.md is still tracked (should be removed)" >&2
  fail=1
fi

# 2. .gitignore must guard the sensitive artifacts.
for pat in 'keyspan.db' '*.db' 'keyspan-report.*'; do
  grep -qF "$pat" .gitignore || { echo ".gitignore missing pattern: $pat" >&2; fail=1; }
done

# 3. No raw secret markers in tracked files, except the deliberate fixtures.
#    Allowed to contain fixture markers: gitleaks demo report, security/testdata fixtures.
allow_re='^(examples/reports/gitleaks\.json|internal/security/|internal/scan/|internal/normalize/|scripts/|testdata/)'
markers='AKIA[0-9A-Z]{16}|-----BEGIN[A-Z ]*PRIVATE KEY-----|s3cr3t-pw-do-not-use'

while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  if [[ "$f" =~ $allow_re ]]; then
    continue
  fi
  if LC_ALL=C grep -InE "$markers" "$f" >/dev/null 2>&1; then
    echo "STRAY SECRET MARKER in tracked file: $f" >&2
    LC_ALL=C grep -InE "$markers" "$f" >&2 || true
    fail=1
  fi
done < <(git ls-files)

[[ "$fail" -eq 0 ]] || { echo "sanitize sweep FAILED" >&2; exit 1; }
echo "sanitize sweep passed"
