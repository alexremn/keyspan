#!/usr/bin/env bash
# scripts/reproduce_examples.sh — regenerates the committed sample outputs and
# asserts the quickstart in examples/README.md reproduces them byte-for-byte.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
db="$work/keyspan.db"
bin="$work/keyspan"

go build -o "$bin" ./cmd/keyspan

"$bin" --db "$db" ingest gitleaks examples/reports/gitleaks.json >/dev/null
"$bin" --db "$db" scan examples/repo >/dev/null
"$bin" --db "$db" recorrelate >/dev/null

got_txt="$work/blast-radius.txt"
got_json="$work/blast-radius.json"
got_html="$work/blast-radius.html"

"$bin" --db "$db" --format human blast-radius name:DATABASE_PASSWORD > "$got_txt"
"$bin" --db "$db" --format json  blast-radius name:DATABASE_PASSWORD > "$got_json"
"$bin" --db "$db" --format html  blast-radius name:DATABASE_PASSWORD > "$got_html"

fail=0
for pair in "examples/outputs/blast-radius.txt:$got_txt" \
            "examples/outputs/blast-radius.json:$got_json" \
            "examples/outputs/blast-radius.html:$got_html"; do
  committed="${pair%%:*}"
  produced="${pair##*:}"
  if ! diff -u "$committed" "$produced"; then
    echo "MISMATCH: $committed differs from freshly produced output" >&2
    fail=1
  fi
done

# Validate asciicast v2: first line is JSON header with version 2; every later
# line is a 3-element JSON array.
if ! head -n 1 examples/demo.cast | grep -Eq '"version"[[:space:]]*:[[:space:]]*2'; then
  echo "examples/demo.cast: header missing version 2" >&2
  fail=1
fi
python3 - <<'PY' || fail=1
import json, sys
with open("examples/demo.cast") as f:
    lines = [l for l in f.read().splitlines() if l.strip()]
hdr = json.loads(lines[0])
assert hdr["version"] == 2, "header version must be 2"
assert isinstance(hdr["width"], int) and isinstance(hdr["height"], int)
for l in lines[1:]:
    ev = json.loads(l)
    assert isinstance(ev, list) and len(ev) == 3, f"bad event: {l}"
    assert isinstance(ev[0], (int, float)) and ev[1] in ("o", "i", "m", "r")
print("demo.cast OK")
PY

# Assert no raw fixture secret value leaked into any committed sample output.
if grep -RIlq 'AKIAIOSFODNN7EXAMPLE\|s3cr3t-pw-do-not-use' examples/outputs/; then
  echo "LEAK: raw fixture secret value present in examples/outputs/" >&2
  fail=1
fi

[[ "$fail" -eq 0 ]] || { echo "reproduce_examples FAILED" >&2; exit 1; }
echo "examples reproduce cleanly"
