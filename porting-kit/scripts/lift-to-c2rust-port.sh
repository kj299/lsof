#!/bin/sh
# Lift porting-kit/ into its own GitHub repo over SSH. No token, no gh, no curl.
#
# With git + GitHub SSH access this is really just two commands — run them by
# hand if this script's guardrails feel like overkill:
#
#     git subtree split --prefix=porting-kit origin/master -b _lift
#     git push git@github.com:kj299/c2rust-port.git _lift:main
#     git branch -D _lift          # tidy up the temporary split branch
#
# The one thing SSH can't do is CREATE the repo — do that once in the browser:
#     https://github.com/new   ->   name: c2rust-port   ->   Create repository   (empty)
#
# Filing the readiness backlog as issues is a separate, API-only step (tracked
# meanwhile as kj299/lsof #8-#19); create them from the web UI or `gh issue
# create` when ready — this script deliberately does NOT reach for a token.
#
# USAGE
#   sh porting-kit/scripts/lift-to-c2rust-port.sh        # run from your lsof clone
#   OWNER=me REPO=my-kit sh ...                          # different destination
#   BASE=HEAD sh ...                                     # lift local HEAD instead of origin/master
set -eu

OWNER="${OWNER:-kj299}"
REPO="${REPO:-c2rust-port}"
PREFIX="${PREFIX:-porting-kit}"
DEST="${DEST:-git@github.com:$OWNER/$REPO.git}"      # SSH by default; override for HTTPS
BASE="${BASE:-origin/master}"

command -v git >/dev/null 2>&1 || { echo "ERROR: git not found." >&2; exit 1; }

# Must run inside a git checkout.
TOP=$(git rev-parse --show-toplevel 2>/dev/null) \
  || { echo "ERROR: not inside a git checkout. cd into your kj299/lsof clone and re-run." >&2; exit 1; }
cd "$TOP"

# Refresh and resolve the base ref (fall back to local HEAD if origin/master is absent).
git fetch origin master --quiet 2>/dev/null || true
git rev-parse -q --verify "$BASE" >/dev/null 2>&1 || BASE=HEAD

# Verify PREFIX/ exists AT THE BASE WE WILL LIFT FROM — not just in the working
# tree, which can differ from $BASE (wrong branch checked out, etc.).
git cat-file -e "$BASE:$PREFIX" 2>/dev/null \
  || { echo "ERROR: '$PREFIX/' not found at $BASE. Run from the lsof clone, or set BASE to a ref that has it." >&2; exit 1; }

# Reachability check without hanging on an SSH prompt: BatchMode fails fast
# instead of asking for a password when keys aren't set up.
GIT_SSH_COMMAND="${GIT_SSH_COMMAND:-ssh -o BatchMode=yes}" \
  git ls-remote "$DEST" >/dev/null 2>&1 || {
  echo "ERROR: can't reach $DEST." >&2
  echo "  - create the empty repo first:  https://github.com/new  (name: $REPO)" >&2
  echo "  - check SSH auth:               ssh -T git@github.com" >&2
  exit 1
}

echo "Lifting $PREFIX/ @ $BASE  ->  $DEST  (branch: main, with history)"

# Default is a NON-force push (safe into the empty repo you just created). If the
# destination's main already has commits the push is rejected — re-run with
# FORCE=1 to overwrite. No interactive prompt, so this stays pipe/CI-friendly.
FORCE_FLAG=""
[ "${FORCE:-0}" = 1 ] && FORCE_FLAG="--force"
push_main() { # push_main <local-ref-to-put-on-main>
  git push $FORCE_FLAG "$DEST" "$1:refs/heads/main" && return 0
  echo "ERROR: push to $DEST 'main' was rejected — it already has commits." >&2
  echo "       Re-run with FORCE=1 to overwrite it:  FORCE=1 sh $0" >&2
  exit 1
}

if SPLIT=$(git subtree split --prefix="$PREFIX" "$BASE" 2>/dev/null) && [ -n "$SPLIT" ]; then
  push_main "$SPLIT"
else
  # git-subtree not installed: push a no-history snapshot instead.
  echo "  (git subtree unavailable — pushing a snapshot without history)"
  snap=$(mktemp -d)
  git archive "$BASE" "$PREFIX" | ( cd "$snap" && tar -x )
  cd "$snap/$PREFIX"
  git init -q && git add -A
  git -c user.email=lift@localhost -c user.name=lift commit -q -m "Import $PREFIX"
  push_main HEAD
fi

echo "Done -> https://github.com/$OWNER/$REPO"
echo "Next (optional): file the backlog issues in the new repo (they're kj299/lsof #8-#19)."
