#!/usr/bin/env bash
# scripts/check_ci_config.sh — validates CI/lint/dependabot config and Makefile.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

fail=0
need_file() { [[ -f "$1" ]] || { echo "MISSING: $1" >&2; fail=1; }; }

for f in .github/workflows/ci.yml .golangci.yml .github/dependabot.yml \
         .github/ISSUE_TEMPLATE/bug_report.md \
         .github/ISSUE_TEMPLATE/feature_request.md \
         .github/pull_request_template.md .github/CODEOWNERS Makefile; do
  need_file "$f"
done
[[ "$fail" -eq 0 ]] || { echo "CI config check FAILED (missing file)" >&2; exit 1; }

# Every YAML must parse.
for y in .github/workflows/ci.yml .golangci.yml .github/dependabot.yml; do
  python3 -c "import sys,yaml; yaml.safe_load(open('$y'))" \
    || { echo "YAML parse error: $y" >&2; fail=1; }
done

grep -qF "go test -race" .github/workflows/ci.yml || { echo "CI missing race test" >&2; fail=1; }
grep -qF "golangci-lint" .github/workflows/ci.yml || { echo "CI missing golangci-lint" >&2; fail=1; }

for t in build test lint cover run; do
  grep -qE "^${t}:" Makefile || { echo "Makefile missing target: $t" >&2; fail=1; }
done

[[ "$fail" -eq 0 ]] || { echo "CI config check FAILED" >&2; exit 1; }
echo "CI config check passed"
