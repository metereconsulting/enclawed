#!/usr/bin/env bash
# Snapshot the current working tree to the `public` remote as a single orphan
# commit on `main`, after wiping every branch and tag on that remote. The
# private remote (`origin`) and the local working tree / HEAD are not touched.
#
# Usage: scripts/publish-public.sh [--yes]
#   --yes  skip the interactive confirmation
#
# Requires:
#   - a remote named `public` configured in this repo
#   - push access to that remote
#
# Notes:
#   - Snapshot includes uncommitted changes and new files (anything `git add -A`
#     would stage). It respects .gitignore.
#   - GitHub-managed `refs/pull/*` refs on the public remote cannot be deleted
#     by push and are left as-is.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

if ! git remote get-url public >/dev/null 2>&1; then
  echo "error: no remote named 'public' configured" >&2
  echo "  add one with: git remote add public <url>" >&2
  exit 1
fi

PUBLIC_URL=$(git remote get-url public)

# Cheap filename sanity check — flag, don't block.
SUSPECT=$(
  { git ls-files; git ls-files --others --exclude-standard; } \
    | grep -iE '(^|/)\.env($|\.[^e]|_)|\.pem$|\.key$|id_rsa|id_ed25519|\.netrc|\.p12$|\.pfx$' \
    || true
)
if [ -n "$SUSPECT" ]; then
  echo "warning: filenames that look sensitive will be included in the snapshot:" >&2
  echo "$SUSPECT" >&2
  echo >&2
fi

DIRTY=$(git status --short | wc -l | tr -d ' ')
HEAD_SHA=$(git rev-parse --short HEAD)
BRANCH=$(git symbolic-ref --short HEAD 2>/dev/null || echo "(detached)")

echo "About to publish snapshot to: $PUBLIC_URL"
echo "  source branch : $BRANCH @ $HEAD_SHA"
echo "  dirty files   : $DIRTY (will be included in snapshot)"
echo "  destination   : public/main (force-replace, single orphan commit)"
echo

if [ "${1:-}" != "--yes" ]; then
  read -r -p "Proceed? [y/N] " ans
  case "$ans" in
    y|Y|yes|YES) ;;
    *) echo "aborted"; exit 1 ;;
  esac
fi

# Build the orphan snapshot via plumbing — no branch switch, no working-tree
# touch, no real-index touch.
SNAP_INDEX=$(mktemp -u)
trap 'rm -f "$SNAP_INDEX"' EXIT
GIT_INDEX_FILE="$SNAP_INDEX" git add -A
TREE=$(GIT_INDEX_FILE="$SNAP_INDEX" git write-tree)
COMMIT=$(git commit-tree "$TREE" -m "Snapshot $(date -u +%Y-%m-%d)")
echo "built snapshot commit $COMMIT (tree $TREE)"

# Wipe every branch on `public` except `main` (we'll overwrite that next).
git ls-remote --heads public \
  | awk '$2 != "refs/heads/main" {print $2}' \
  | sed 's|^|:|' \
  | xargs -r -n1 git push public

# Wipe every tag on `public`.
git ls-remote --tags public \
  | awk '{print $2}' \
  | sed 's|^|:|' \
  | xargs -r -n1 git push public

# Force-push the new orphan commit as `main`.
git push public "$COMMIT:refs/heads/main" --force

echo
echo "done. public/main → $COMMIT"
