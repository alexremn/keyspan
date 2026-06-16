#!/usr/bin/env bash
# scripts/check_release_config.sh — validates goreleaser + release workflow.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

fail=0
[[ -f .goreleaser.yaml ]] || { echo "MISSING: .goreleaser.yaml" >&2; fail=1; }
[[ -f .github/workflows/release.yml ]] || { echo "MISSING: .github/workflows/release.yml" >&2; fail=1; }
[[ "$fail" -eq 0 ]] || { echo "release config check FAILED (missing file)" >&2; exit 1; }

for y in .goreleaser.yaml .github/workflows/release.yml; do
  python3 -c "import yaml; yaml.safe_load(open('$y'))" \
    || { echo "YAML parse error: $y" >&2; fail=1; }
done

g=.goreleaser.yaml
grep -qE '^version:\s*2' "$g"           || { echo "goreleaser: missing version: 2" >&2; fail=1; }
grep -qF 'CGO_ENABLED=0' "$g"           || { echo "goreleaser: missing CGO_ENABLED=0" >&2; fail=1; }
grep -qF -- '-trimpath' "$g"             || { echo "goreleaser: missing -trimpath" >&2; fail=1; }
grep -qF 'main.version=' "$g"           || { echo "goreleaser: missing version ldflag" >&2; fail=1; }
grep -qF 'sign-blob' "$g"               || { echo "goreleaser: missing cosign sign-blob" >&2; fail=1; }
grep -qF 'artifacts: checksum' "$g"     || { echo "goreleaser: missing checksum signing" >&2; fail=1; }
grep -qF 'cmd: syft' "$g"               || { echo "goreleaser: missing syft sbom" >&2; fail=1; }
for plat in linux darwin windows amd64 arm64; do
  grep -qF "$plat" "$g" || { echo "goreleaser: missing platform $plat" >&2; fail=1; }
done

r=.github/workflows/release.yml
grep -qF 'generator_generic_slsa3.yml' "$r" || { echo "release: missing SLSA generator" >&2; fail=1; }
grep -qF 'id-token: write' "$r"             || { echo "release: missing id-token: write" >&2; fail=1; }
grep -qF 'needs.goreleaser.outputs.hashes' "$r" || { echo "release: missing hashes wiring" >&2; fail=1; }

if command -v goreleaser >/dev/null 2>&1; then
  goreleaser check || { echo "goreleaser check failed" >&2; fail=1; }
else
  echo "note: goreleaser not installed; skipped 'goreleaser check'"
fi

[[ "$fail" -eq 0 ]] || { echo "release config check FAILED" >&2; exit 1; }
echo "release config check passed"
