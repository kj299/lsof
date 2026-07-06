#!/usr/bin/env bash
#
# lift-to-c2rust-port.sh
# ----------------------
# Creates the kj299/c2rust-port repo, lifts porting-kit/ into it (root, WITH
# history), and files the readiness backlog as labeled issues.
#
# I (the agent) could not do this from the session: the GitHub integration is
# scoped to kj299/lsof and lacks repo-creation permission (create_repository ->
# 403). Run this yourself; it uses YOUR gh auth.
#
# PREREQUISITES
#   - gh CLI authenticated:   gh auth status        (login: gh auth login)
#   - git credential helper:  gh auth setup-git     (so the HTTPS push works)
#   - run from a clone of kj299/lsof with origin/master up to date
#
# USAGE
#   bash porting-kit/scripts/lift-to-c2rust-port.sh
#   VIS=public bash .../lift-to-c2rust-port.sh              # publish the repo
#   OWNER=me REPO=my-kit bash .../lift-to-c2rust-port.sh    # different destination
set -euo pipefail

OWNER="${OWNER:-kj299}"          # override with OWNER=... (your gh account/org)
REPO="${REPO:-c2rust-port}"      # override with REPO=...
VIS="${VIS:-private}"            # default private; VIS=public to publish
DESC="Reusable, safety-first C-to-Rust porting kit: playbook, runnable harnesses, architecture skeleton, invokable skills, and a self-improving lessons loop."

echo "==> 1/4  create $OWNER/$REPO ($VIS)"
gh repo create "$OWNER/$REPO" "--$VIS" --description "$DESC" \
  || echo "    (repo may already exist — continuing)"

echo "==> 2/4  lift porting-kit/ into it (root, with history)"
git fetch origin master
# subtree split rewrites just the porting-kit/ history to a synthetic root commit.
SPLIT="$(git subtree split --prefix=porting-kit origin/master)"
echo "    split commit: $SPLIT"
git push "https://github.com/$OWNER/$REPO.git" "$SPLIT:refs/heads/main" --force
echo "    pushed to $OWNER/$REPO@main"
# --- No-history fallback (if subtree split is unavailable): comment the two lines
#     above and uncomment below to push a clean snapshot instead.
# tmp="$(mktemp -d)"; git archive origin/master porting-kit | tar -x -C "$tmp"
# ( cd "$tmp/porting-kit" && git init -q && git add -A \
#   && git -c user.email=you@example.com -c user.name=you commit -qm "Import porting-kit" \
#   && git branch -M main \
#   && git push -f "https://github.com/$OWNER/$REPO.git" main )

echo "==> 3/4  labels"
# name:hexcolor
for L in "P0:b60205" "P1:fbca04" "P2:0e8a16" "harness:1d76db" "skill:5319e7" \
         "security:d93f0b" "ci:c5def5" "epic:6f42c1"; do
  gh label create "${L%%:*}" --color "${L##*:}" --repo "$OWNER/$REPO" 2>/dev/null || true
done

echo "==> 4/4  issues"
mk() {  # mk "title" "labels" "body"
  gh issue create --repo "$OWNER/$REPO" --title "$1" --label "$2" --body "$3" >/dev/null \
    && echo "    + $1"
}

mk "Epic: bring the kit to v1.0 (turnkey for library & security-critical ports)" "epic" \
"$(cat <<'EOF'
Tracks the readiness gap from OPERATING-GUIDE.md §0. The kit's spine is proven on
an executable port; the edges below make it turnkey for a **C-ABI library** port and
for a **security-critical** claim.

Blocked by the P0 items:
- Library (C-ABI) function-level differential harness
- Performance gate harness
- Held-back vectors + C-baseline validation

Definition of done: a library port can be driven end-to-end through the six gates
with the same rigor as the executable path, and a release can substantiate its
safety/security claims (SBOM, signing, differential fuzzing).
EOF
)"

mk "P0: library (C-ABI) function-level differential harness (cando-style)" "P0,harness" \
"$(cat <<'EOF'
**Why.** The differential harness (`harnesses/differential/diff_run.py`) is
executable-shaped: it drives argv/stdin and compares stdout+exit. A C-ABI **library**
port has no CLI — you must compare per-function I/O and output state. This is the
single biggest gap for library migrations (OPERATING-GUIDE §5 P0).

**Build.** A harness that loads a C `.so` and the Rust `cdylib` **interchangeably**
through a per-test shim and checks conformance on a function-vector suite (function
args, return value, and mutated output state / env / file contents). Crib MIT LL's
public `cando` tool and JSON schema (DARPA-TRACTOR PUBLIC-Test-Corpus).

**Acceptance.**
- Diffs a C `.so` vs a Rust `cdylib` over a function-vector file; verdict = return
  value AND output state (mirrors diff_run's stdout+exit rule).
- Divergence-ledger aware (`DIVERGENCES.md`), like diff_run.
- `--self-test` fixture; wired into `make check-kit`.
EOF
)"

mk "P0: performance gate harness (fail on >1.3x the C median)" "P0,harness" \
"$(cat <<'EOF'
**Why.** The kit checks correctness and safety but never performance. TRACTOR's
envelope: 3–5% median runtime overhead, max ~1.3x. >1.3x means a specific bug (an
accidental copy, a missed release build, bounds checks in a hot loop) — not "the
cost of Rust" (OPERATING-GUIDE §2/§5 P0).

**Build.** A harness that runs the C baseline and the Rust build over a workload N
times, computes the median of each, and **exits nonzero if rust/c > 1.3** (threshold
configurable). Report the ratio and the offending workload.

**Acceptance.** Runs both, medians over N, ratio gate; `--self-test` (e.g. two
sleep/loop stand-ins); documented in PLAYBOOK Phase 4 / SECURITY-CHECKLIST.
EOF
)"

mk "P0: held-back vectors + C-baseline validation in golden.py" "P0,harness" \
"$(cat <<'EOF'
**Why.** Two TRACTOR findings the kit describes but doesn't enforce (synthesis Step
0.5): performers failed hidden tests more than public ones (an LLM in the loop
overfits to visible vectors), and MIT LL validates every vector against the C
**before** it may judge a translation. A wrong vector that "passes" teaches nothing.

**Build.** Extend `harnesses/golden/golden.py`:
- `--holdout <frac|file>` reserves a hidden acceptance set, excluded from the
  iteration loop and run only at final acceptance.
- a capture/validate mode that **rejects any vector that does not pass on the C
  baseline** before it is admitted to the corpus.

**Acceptance.** Holdout set is provably excluded from iteration; a C-failing vector
is rejected with a clear message; `--self-test` covers both.
EOF
)"

mk "P1: differential fuzzing harness (C vs Rust on shared inputs)" "P1,harness,security" \
"$(cat <<'EOF'
**Why.** The fixed input matrix can't cover the input space; differential fuzzing
feeds the **same** fuzz input to the C oracle and the Rust and compares
normalized output+exit — finding semantic divergences the matrix never reaches. The
highest-value single addition for a security-critical port (OPERATING-GUIDE §3).

**Build.** A libFuzzer/AFL harness template + runner that drives both binaries per
input, normalizes (reuse `normalize.py`), and reports the minimized diverging input.
Ledger-aware.

**Acceptance.** Template + runner; `--self-test` using an echo/printf-style
divergence; a `porting-kit-diff-fuzz` skill can follow (see the P2 skill issue).
EOF
)"

mk "P1: harden the CI template (SHA-pin actions, smoke/nightly split, cargo-vet, SBOM, gitleaks)" "P1,ci,security" \
"$(cat <<'EOF'
**Why.** `harnesses/ci/porting-ci.template.yml` uses tag-pinned actions and runs the
whole safety matrix on every push. Hardening + tiering per OPERATING-GUIDE §2/§3.

**Do.**
- Pin every `uses:` by **commit SHA**, not tag; keep `permissions: contents: read`;
  add `persist-credentials: false`.
- Tier slow gates: fuzz 60s smoke per-PR + a nightly deep `schedule:`; Miri/ASan on
  changed crates per-PR, full sweep nightly.
- Add jobs: `cargo vet` (dep code review) alongside audit/deny; SBOM via
  `cargo auditable` / `cargo cyclonedx`; `gitleaks` secret scan.

**Acceptance.** Template YAML validates; jobs present; docs updated.
EOF
)"

mk "P1: scan_c_flaws.py depth + multi-line robustness" "P1,harness" \
"$(cat <<'EOF'
**Why.** The Phase-0 scanner covers 6 CWE classes; a few high-value ones are missing,
and most checks are line-based (the format-string check is already whole-file after
LESSONS #2 — extend the rest).

**Add.** heuristics for use-after-free / double-free (free() then use), uninitialized
reads, `strncpy` non-termination, `snprintf` truncation-ignored. Make the remaining
line-based regex checks whole-file so multi-line calls aren't missed.

**Acceptance.** New categories with `--self-test` fixtures (positive + negative);
re-run against lsof — no regression in the signal-to-noise won back in LESSONS #2.
EOF
)"

mk "P1: porting-kit-precondition skill (Step 0 C->C refactor)" "P1,skill" \
"$(cat <<'EOF'
**Why.** Step 0 (C→C preconditioning) is the most portable idea in the TRACTOR
synthesis but exists only as prose. Make it an invokable skill.

**Build.** `skills/porting-kit-precondition/SKILL.md` guiding: localize global state
into a context struct threaded by pointer (verified with the C test suite before
translating); reduce aliasing (lift subfield args, split multi-var decls); decide the
`#ifdef`/macro configuration story. References PLAYBOOK Step 0 /
C-to-Rust-Playbook-Best-of-Both.md.

**Acceptance.** Passes `skills/check_skills.py` (frontmatter + valid kit refs); listed
in `skills/README.md` and the OPERATING-GUIDE phase map.
EOF
)"

mk "P2: normalize.py rules as a per-project data file" "P2,harness" \
"$(cat <<'EOF'
**Why.** Normalization rules are code constants (`DEFAULT_RULES`); each port should
tune masking (PIDs/paths/timestamps/tokens) without editing the harness.

**Build.** `--rules <file>` loading rules as data (name, regex, replacement);
keep the current defaults as the fallback.

**Acceptance.** Custom rules file overrides/extends defaults; back-compatible;
`--self-test` covers a project-specific rule.
EOF
)"

mk "P2: progress.py ingest parses harness JSON to auto-advance gates" "P2,harness" \
"$(cat <<'EOF'
**Why.** `progress.py ingest` is heuristic. It should consume the harnesses' own
`--json` output (`audit_unsafe`, `diff_run`, fuzz, sanitizers) and tick a module's
gate automatically when its report is clean.

**Acceptance.** ingest advances a module to the right gate from real harness JSON;
`--self-test`; documented in the module/audit skills.
EOF
)"

mk "P2: document Windows / cross-platform caveats" "P2" \
"$(cat <<'EOF'
**Why.** The sanitizer/Miri/nightly guidance is Linux-centric, yet the kit was
distilled from a **Windows** port (winlsof). Document the deltas so a Windows or
macOS port isn't surprised.

**Cover.** Miri/ASan/UBSan/TSan availability per toolchain (MSVC vs GNU); the
"exit hard after output so an abandoned worker can't hang teardown" pattern; ASCII-
default output for legacy shells; `target/` file-lock hazards on synced folders.

**Acceptance.** A CAVEATS section/doc referenced from README and PLAYBOOK Phase 3.
EOF
)"

mk "P2: porting-kit-diff-fuzz skill (after differential fuzzing lands)" "P2,skill" \
"$(cat <<'EOF'
**Why.** Once the differential-fuzzing harness exists (P1), wrap it as an invokable
skill so it's part of the standard security pass.

**Depends on:** the differential fuzzing harness issue.

**Acceptance.** `skills/porting-kit-diff-fuzz/SKILL.md` passes `check_skills.py`;
added to `skills/README.md`, the OPERATING-GUIDE, and the audit skill's security gate.
EOF
)"

echo
echo "Done. Repo: https://github.com/$OWNER/$REPO   Issues: https://github.com/$OWNER/$REPO/issues"
echo "If you kept it private and want it shared: gh repo edit $OWNER/$REPO --visibility public"
