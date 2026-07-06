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
#   BASE=<ref> sh ...                                    # lift a specific ref
#                                                        # (default: origin/master,
#                                                        #  else origin/main, else HEAD)
#   FORCE=1 sh ...                                       # overwrite a non-empty main
set -eu

# Refuse to be sourced (`. ./script`) — that would apply set -eu to YOUR shell
# and exit it on the first error. Run it instead:  sh <path-to-script>
case "${0##*/}" in
  sh|-sh|ash|-ash|dash|-dash|bash|-bash|ksh|-ksh|zsh|-zsh)
    echo "ERROR: run me, don't source me:  sh porting-kit/scripts/lift-to-c2rust-port.sh" >&2
    return 1 2>/dev/null || exit 1 ;;
esac

OWNER="${OWNER:-kj299}"
REPO="${REPO:-c2rust-port}"
PREFIX="${PREFIX:-porting-kit}"
DEST="${DEST:-git@github.com:$OWNER/$REPO.git}"      # SSH by default; override for HTTPS
BASE="${BASE:-}"                                     # empty = auto-pick below

command -v git >/dev/null 2>&1 || { echo "ERROR: git not found." >&2; exit 1; }

# Absolute path to this script, captured BEFORE any cd, so re-run hints are
# paste-able no matter where we end up.
case "$0" in /*) SELF=$0 ;; *) SELF=$PWD/$0 ;; esac

# Must run inside a git checkout.
TOP=$(git rev-parse --show-toplevel 2>/dev/null) \
  || { echo "ERROR: not inside a git checkout. cd into your kj299/lsof clone and re-run." >&2; exit 1; }
cd "$TOP"

# Resolve the base ref. An explicitly requested BASE must exist — never
# silently substitute something else for what the user asked for. With no BASE
# given, prefer origin/master, then origin/main, then HEAD — and say so when
# not using the primary default, so a stale/odd clone can't lift the wrong
# tree unnoticed.
git fetch origin master --quiet 2>/dev/null || git fetch origin main --quiet 2>/dev/null || true
if [ -n "$BASE" ]; then
  git rev-parse -q --verify "$BASE" >/dev/null 2>&1 \
    || { echo "ERROR: requested BASE '$BASE' does not resolve in this clone." >&2; exit 1; }
else
  for cand in origin/master origin/main HEAD; do
    if git rev-parse -q --verify "$cand" >/dev/null 2>&1; then BASE=$cand; break; fi
  done
  [ -n "$BASE" ] || { echo "ERROR: no usable base ref (no origin/master, origin/main, or HEAD)." >&2; exit 1; }
  [ "$BASE" = origin/master ] || echo "note: origin/master not found — lifting from $BASE instead."
fi

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

echo "Lifting $PREFIX/ @ $BASE  ->  $DEST  (branch: main)"

# Default is a NON-force push (safe into the empty repo you just created). If the
# destination's main already has commits the push is rejected — re-run with
# FORCE=1 to overwrite. No interactive prompt, so this stays pipe/CI-friendly.
FORCE_FLAG=""
[ "${FORCE:-0}" = 1 ] && FORCE_FLAG="--force"
push_main() { # push_main <local-ref-to-put-on-main>
  git push $FORCE_FLAG "$DEST" "$1:refs/heads/main" && return 0
  echo "ERROR: push to $DEST 'main' was rejected — it already has commits." >&2
  echo "       Re-run with FORCE=1 to overwrite it:  FORCE=1 sh $SELF" >&2
  exit 1
}

# Prefer git-subtree (keeps history). Keep its stderr so a real subtree ERROR is
# shown, and only fall back to the snapshot when subtree is genuinely absent —
# don't conflate "not installed" with "failed".
split_err=$(mktemp)
if SPLIT=$(git subtree split --prefix="$PREFIX" "$BASE" 2>"$split_err") && [ -n "$SPLIT" ]; then
  rm -f "$split_err"
  echo "  full history preserved: $(git rev-list --count "$SPLIT") commits"
  push_main "$SPLIT"
elif grep -q "not a git command" "$split_err" 2>/dev/null; then
  rm -f "$split_err"
  echo "  (git subtree not installed — pushing a snapshot WITHOUT history)"
  snap=$(mktemp -d)
  # No pipeline here: `git archive | tar` would let an archive failure vanish
  # behind tar's exit status; -o + set -e aborts cleanly instead.
  git archive -o "$snap/_kit.tar" "$BASE" "$PREFIX"
  ( cd "$snap" && tar -xf _kit.tar && rm -f _kit.tar )
  cd "$snap/$PREFIX"
  git init -q && git add -A
  git -c user.email=lift@localhost -c user.name=lift commit -q -m "Import $PREFIX"
  push_main HEAD
else
  echo "ERROR: git subtree split failed:" >&2
  cat "$split_err" >&2
  rm -f "$split_err"
  exit 1
fi

echo "Done -> https://github.com/$OWNER/$REPO"
echo "Next (optional): file the backlog issues in the new repo (they're kj299/lsof #8-#19)."
