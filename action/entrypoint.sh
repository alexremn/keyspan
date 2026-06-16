#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# entrypoint.sh — compute the secrets touched by a PR diff, run keyspan
# blast-radius for each, and emit a masked-by-default markdown PR comment.
#
# Required env (set by action.yml or by the smoke test):
#   KEYSPAN_BIN, KEYSPAN_DB, KEYSPAN_PATH, KEYSPAN_MIN_CONFIDENCE
#   KEYSPAN_REVEAL_NAMES, KEYSPAN_INCLUDE_LOCATIONS, KEYSPAN_IS_PUBLIC
# Optional test seams:
#   KEYSPAN_DIFF_FILE   — file with one changed path per line (skips git diff)
#   KEYSPAN_COMMENT_OUT — write the rendered markdown here (default: stdout)
#   KEYSPAN_SKIP_POST   — when "1", do not post to GitHub
set -euo pipefail

# --- config with defaults -------------------------------------------------
KEYSPAN_BIN="${KEYSPAN_BIN:-keyspan}"
KEYSPAN_DB="${KEYSPAN_DB:?KEYSPAN_DB is required}"
KEYSPAN_MIN_CONFIDENCE="${KEYSPAN_MIN_CONFIDENCE:-0.50}"
KEYSPAN_REVEAL_NAMES="${KEYSPAN_REVEAL_NAMES:-false}"
KEYSPAN_INCLUDE_LOCATIONS="${KEYSPAN_INCLUDE_LOCATIONS:-false}"
KEYSPAN_IS_PUBLIC="${KEYSPAN_IS_PUBLIC:-false}"
KEYSPAN_BASE_SHA="${KEYSPAN_BASE_SHA:-}"
KEYSPAN_HEAD_SHA="${KEYSPAN_HEAD_SHA:-}"

reveal_names="$KEYSPAN_REVEAL_NAMES"
warning=""

# --- public-repo guard ----------------------------------------------------
# A blast-radius comment on a public PR can leak infra topology. Force masked
# output and warn (do not fail) unless the caller has explicitly accepted it.
if [ "$KEYSPAN_IS_PUBLIC" = "true" ] && [ "$reveal_names" = "true" ]; then
  reveal_names="false"
  warning="> :warning: This is a **public repository**. Secret names are kept masked despite \`reveal-names: true\` to avoid leaking infrastructure topology. Run keyspan locally or on a private mirror to reveal names."
fi

# --- changed files in the PR diff ----------------------------------------
changed_files=""
if [ -n "${KEYSPAN_DIFF_FILE:-}" ]; then
  changed_files="$(cat "$KEYSPAN_DIFF_FILE")"
elif [ -n "$KEYSPAN_BASE_SHA" ] && [ -n "$KEYSPAN_HEAD_SHA" ]; then
  changed_files="$(git diff --name-only "$KEYSPAN_BASE_SHA" "$KEYSPAN_HEAD_SHA")"
else
  changed_files="$(git diff --name-only HEAD~1 HEAD)"
fi

# Extract the secret NAMES referenced in changed workflow/manifest files. We
# query keyspan per secret name (ResolveRef accepts name:/fp:/finding:, NOT a
# file path), so we resolve names here from file content. keyspan stores names
# canonically lowercased (normalize.IdentityName), so we lowercase to match.
touched_secrets=""
while IFS= read -r f; do
  [ -z "$f" ] && continue
  case "$f" in
    *.yml|*.yaml) ;;   # GHA workflows + k8s/ESO manifests
    *) continue ;;
  esac
  [ -f "$f" ] || continue
  # GHA: ${{ secrets.NAME }}
  while IFS= read -r n; do
    [ -n "$n" ] && touched_secrets+="${n#secrets.}"$'\n'
  done < <(grep -hoE 'secrets\.[A-Za-z_][A-Za-z0-9_]*' "$f" 2>/dev/null || true)
  # k8s: the `name:` adjacent to secretKeyRef:/secretRef:
  while IFS= read -r n; do
    [ -n "$n" ] && touched_secrets+="$n"$'\n'
  done < <(grep -hA1 -E 'secretKeyRef:|secretRef:' "$f" 2>/dev/null \
            | grep -oE 'name:[[:space:]]*[A-Za-z0-9_-]+' | awk '{print $2}' || true)
  # k8s: volumes[].secret.secretName (hyphen included for names like database-password)
  while IFS= read -r n; do
    [ -n "$n" ] && touched_secrets+="$n"$'\n'
  done < <(grep -oE 'secretName:[[:space:]]*[A-Za-z0-9_-]+' "$f" 2>/dev/null | awk '{print $2}' || true)
done <<< "$changed_files"

# Dedup + lowercase to match keyspan's canonical names.
touched_secrets="$(printf '%s' "$touched_secrets" | tr '[:upper:]' '[:lower:]' | sort -u | sed '/^$/d')"

# --- markdown assembly ----------------------------------------------------
emit() { printf '%s\n' "$1"; }
md=""
md+="## keyspan — secret blast radius"$'\n\n'
if [ -n "$warning" ]; then
  md+="$warning"$'\n\n'
fi

if [ -z "${touched_secrets//[$'\n']/}" ]; then
  md+="No secret surfaces touched by this PR diff. :white_check_mark:"$'\n'
else
  # One blast-radius query per touched secret name, aggregated.
  total_consumers=0
  rows=""
  while IFS= read -r secret; do
    [ -z "$secret" ] && continue
    json="$("$KEYSPAN_BIN" --db "$KEYSPAN_DB" \
      --min-confidence "$KEYSPAN_MIN_CONFIDENCE" \
      blast-radius "name:$secret" --format json || true)"
    [ -z "$json" ] && continue

    # Aggregate consumer count and bands with jq (snake_case schema, §Foundations).
    count="$(printf '%s' "$json" | jq '[.consumers[]] | length')"
    total_consumers=$((total_consumers + count))

    if [ "$reveal_names" = "true" ]; then
      sname="$(printf '%s' "$json" | jq -r '.start.name')"
    else
      sname="«secret»"
    fi

    # Per-consumer rows: type + band (+ name/location only when opted in).
    while IFS=$'\t' read -r ctype cband cname cloc; do
      [ -z "$ctype" ] && continue
      row="| $ctype | $cband |"
      if [ "$reveal_names" = "true" ]; then
        row+=" $cname |"
      fi
      if [ "$KEYSPAN_INCLUDE_LOCATIONS" = "true" ]; then
        row+=" $cloc |"
      fi
      rows+="$row"$'\n'
    done < <(printf '%s' "$json" | jq -r '
      .consumers[] |
      [ (.node.attrs.surface // "consumer"),
        (.band | ascii_upcase[0:1] + .[1:]),
        (.node.name // ""),
        ( (.chain[0].provenance.locations // [])
          | if length > 0
            then "\(.[0].file):\(.[0].line)"
            else "-" end ) ]
      | @tsv')

    if [ "$reveal_names" = "true" ]; then
      md+="### Secret \`$sname\` — $count consumer(s)"$'\n\n'
    else
      md+="### secret (masked) — $count consumer(s)"$'\n\n'
    fi
  done <<< "$touched_secrets"

  header="| Consumer | Band |"
  sep="| --- | --- |"
  if [ "$reveal_names" = "true" ]; then
    header+=" Name |"; sep+=" --- |"
  fi
  if [ "$KEYSPAN_INCLUDE_LOCATIONS" = "true" ]; then
    header+=" Location |"; sep+=" --- |"
  fi
  md+="$header"$'\n'"$sep"$'\n'"$rows"$'\n'
  md+="_Total consumers across touched refs: ${total_consumers}_"$'\n'
fi

# --- output ---------------------------------------------------------------
if [ -n "${KEYSPAN_COMMENT_OUT:-}" ]; then
  emit "$md" > "$KEYSPAN_COMMENT_OUT"
else
  emit "$md"
fi
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  emit "$md" >> "$GITHUB_STEP_SUMMARY"
fi

# --- post to GitHub (skipped under test) ----------------------------------
if [ "${KEYSPAN_SKIP_POST:-0}" = "1" ]; then
  exit 0
fi
if [ -z "${GITHUB_TOKEN:-}" ] || [ -z "${GITHUB_REPOSITORY:-}" ] || [ -z "${KEYSPAN_PR_NUMBER:-}" ]; then
  echo "keyspan: GITHUB_TOKEN/REPOSITORY/PR_NUMBER missing; printed comment instead of posting" >&2
  exit 0
fi
api="https://api.github.com/repos/${GITHUB_REPOSITORY}/issues/${KEYSPAN_PR_NUMBER}/comments"
jq -n --arg body "$md" '{body: $body}' \
  | curl -sS -X POST "$api" \
      -H "Authorization: Bearer ${GITHUB_TOKEN}" \
      -H "Accept: application/vnd.github+json" \
      --data-binary @- >/dev/null
