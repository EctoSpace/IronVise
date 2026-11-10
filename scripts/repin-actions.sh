#!/usr/bin/env bash
# repin-actions.sh - resolve the latest release of each GitHub Action used in
# .github/workflows, rewrite every `uses:` pin to that release's commit SHA,
# and keep a `# vX.Y.Z` comment so the pin stays readable.
#
# Fixes the "Node.js 20 is deprecated ... forced to run on Node.js 24" warnings.
#
# Requires: python3 or jq, and ONE of:
#   - gh (authenticated)                    - preferred, no rate-limit worries
#   - curl + GITHUB_TOKEN / GH_TOKEN in env - 5,000 requests/hour
#   - curl alone                            - unauthenticated, 60 requests/hour
#
# A full resolve costs 2 API calls per action (24 total), which fits in the
# unauthenticated budget but not twice in one hour. Resolutions are therefore
# cached in .repin-cache.tsv so the dry run and the subsequent --apply share
# one set of calls. Use --refresh to force re-resolution.
#
# Run from the repo root:   bash scripts/repin-actions.sh            # dry run, shows diff
#                           bash scripts/repin-actions.sh --apply    # writes the files
#                           bash scripts/repin-actions.sh --refresh  # discard cache, re-resolve

set -euo pipefail

APPLY=0
REFRESH=0
for arg in "$@"; do
  case "$arg" in
    --apply)   APPLY=1 ;;
    --refresh) REFRESH=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

WF_DIR=".github/workflows"
[[ -d "$WF_DIR" ]] || { echo "run me from the repo root"; exit 1; }

CACHE=".repin-cache.tsv"
(( REFRESH )) && rm -f "$CACHE"

# Actions to repin. Add a "@<tag>" suffix to force a specific major instead of
# "latest release" - useful when a new major has breaking changes.
ACTIONS=(
  actions/checkout@v6             # v7 exists; v6 is the agreed target for this sweep
  actions/setup-node@v6           # v7 exists; v6 is the agreed target
  actions/setup-python@v6         # v7 exists; v6 is the agreed target
  actions/upload-artifact@v7      # v7, not v6: see the note below
  actions/download-artifact@v7    # keep majors matched with upload-artifact
  Swatinem/rust-cache
  softprops/action-gh-release
  docker/login-action
  docker/metadata-action
  docker/setup-buildx-action
  docker/build-push-action
)

# WHY THE ARTIFACT ACTIONS GO TO v7 AND NOT v6.
#
# The obvious target was v6 for both, keeping the majors matched while avoiding
# upload-artifact v7's switch to ESM and a new upload path. That does not work:
#
#     upload-artifact   v6.0.0  node24
#     download-artifact v6.0.0  node20   <-- still warns
#     download-artifact v7.0.0  node24
#
# download-artifact never shipped a node24 v6, so "both at v6" cannot clear the
# deprecation warnings. Matching the majors at v7 keeps the upload/download
# pairing intact - they are released together and tested against each other -
# at the cost of taking upload v7's new upload path earlier than planned.
# Validate it in the release.yml rehearsal, which is where artifacts actually
# round-trip between jobs.

# DELIBERATELY NOT REPINNED - dtolnay/rust-toolchain.
#
# It is a composite action with no Node runtime, so it never appears in the
# Node 20 deprecation warnings this sweep exists to clear: bumping it buys
# nothing. And it is not a safe bump. The current pin tracks the `stable` ref,
# whose action.yml declares:
#
#     toolchain:
#       required: false
#       default: stable
#
# At the `v1` tag that input became `required: true` with no default. All
# seventeen call sites in this repo rely on the default and pass only
# `components:` / `targets:`, so moving the pin to v1 would fail every Rust job
# in all nine workflows. Bumping it means editing seventeen call sites to add
# `toolchain: stable` first - a separate change with its own risk, not part of
# a Node 24 sweep.

# gh if we have it; otherwise curl, with a token when one is in the environment.
TOKEN="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  TRANSPORT="gh"
elif command -v curl >/dev/null 2>&1; then
  TRANSPORT="curl"
else
  echo "need either an authenticated gh or curl" >&2; exit 1
fi

api() { # api <path> -> raw JSON on stdout
  case "$TRANSPORT" in
    gh)   gh api "$1" 2>/dev/null || true ;;
    curl) if [[ -n "$TOKEN" ]]; then
            curl -sSL -H "Authorization: Bearer $TOKEN" \
                 -H "Accept: application/vnd.github+json" \
                 "https://api.github.com/$1" 2>/dev/null || true
          else
            curl -sSL -H "Accept: application/vnd.github+json" \
                 "https://api.github.com/$1" 2>/dev/null || true
          fi ;;
  esac
}

if command -v jq >/dev/null 2>&1; then
  jqf() { jq -r "$1" 2>/dev/null || true; }
else
  jqf() { python3 -c '
import json,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit(0)
q=sys.argv[1]
if q==".tag_name": print(d.get("tag_name","") if isinstance(d,dict) else "")
elif q==".sha":    print(d.get("sha","")      if isinstance(d,dict) else "")
elif q=="tags":    [print(r.get("tag_name","")) for r in (d if isinstance(d,list) else [])]
' "$1" || true; }
fi

# Report which transport and budget we are working with, so a rate-limit
# failure is diagnosable rather than mysterious.
if [[ "$TRANSPORT" == "curl" ]]; then
  rl=$(api "rate_limit" | jqf '.rate.remaining' 2>/dev/null || echo "?")
  auth_note="unauthenticated"; [[ -n "$TOKEN" ]] && auth_note="token from env"
  echo "transport: curl ($auth_note), API requests remaining: ${rl:-?}"
else
  echo "transport: gh (authenticated)"
fi
echo

touch "$CACHE"

printf '%-34s %-10s %s\n' "ACTION" "TAG" "SHA"
printf '%-34s %-10s %s\n' "------" "---" "---"

for entry in "${ACTIONS[@]}"; do
  repo="${entry%%@*}"
  forced=""
  [[ "$entry" == *@* ]] && forced="${entry##*@}"

  cached=$(awk -F'\t' -v r="$repo" '$1==r {print $2"\t"$3; exit}' "$CACHE")
  if [[ -n "$cached" ]]; then
    tag="${cached%%$'\t'*}"; sha="${cached##*$'\t'}"
    printf '%-34s %-10s %s  (cached)\n' "$repo" "$tag" "$sha"
  else
    if [[ -n "$forced" ]]; then
      # Highest release whose tag is under the forced major (e.g. v6 -> v6.2.1).
      tag=$(api "repos/$repo/releases?per_page=100" | jqf '.[].tag_name' \
            | grep -E "^${forced}(\.[0-9]+){0,2}$" | sort -V | tail -1)
    else
      tag=$(api "repos/$repo/releases/latest" | jqf '.tag_name')
    fi
    [[ -n "$tag" ]] || { echo "!! could not resolve a tag for $repo - skipping"; continue; }

    # Dereference annotated tags to the real commit.
    sha=$(api "repos/$repo/commits/$tag" | jqf '.sha')
    [[ -n "$sha" ]] || { echo "!! could not resolve a SHA for $repo@$tag - skipping"; continue; }

    printf '%s\t%s\t%s\n' "$repo" "$tag" "$sha" >> "$CACHE"
    printf '%-34s %-10s %s\n' "$repo" "$tag" "$sha"
  fi
done

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
cp "$WF_DIR"/*.yml "$tmp/"

while IFS=$'\t' read -r repo tag sha; do
  [[ -n "$repo" ]] || continue
  for f in "$tmp"/*.yml; do
    # Match the pin whatever form it currently takes: full SHA, short SHA, or a
    # floating tag such as @stable / @v4 / @v4.2.2 - plus any trailing comment.
    perl -0pi -e "s{\Q$repo\E\@[A-Za-z0-9._-]+([ \t]*\#[^\n]*)?}{$repo\@$sha # $tag}g" "$f"
  done
done < "$CACHE"

echo
echo "=== diff ==="
for f in "$tmp"/*.yml; do
  diff -u "$WF_DIR/$(basename "$f")" "$f" || true
done

if (( APPLY )); then
  cp "$tmp"/*.yml "$WF_DIR/"
  echo
  echo "Applied. Review with: git diff $WF_DIR"
else
  echo
  echo "Dry run only. Re-run with --apply to write the files."
  echo "(Resolutions are cached in $CACHE - --apply will not spend more API calls.)"
fi
