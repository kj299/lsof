---
name: porting-kit-diff-fuzz
description: Differential-fuzz a C-to-Rust port — feed the same mutated input to the C oracle and the Rust rewrite over many iterations and triage every divergence. Use after the fixed-matrix differential passes, when the user wants to hunt semantic divergences the matrix never covered, or asks to fuzz the port against C / find where Rust and C disagree / stress the parser against the oracle.
---

# Porting Kit — differential fuzzing (C vs Rust on shared inputs)

<!-- KIT-IMPORT: from the c2rust-port lineage of this kit.
     Re-cited: #1->#001, #4->#004, #6->#034, #8->#041;
     #16, #28, #42 and #43 by title (no entries in this log). -->

Wraps `porting-kit/harnesses/diff-fuzz/diff_fuzz.py`. Complements the fixed-matrix
differential (`porting-kit-oracle` / `diff_run.py`) and the crash-only fuzz gate
(`porting-kit-module` gate 3, `cargo-fuzz`): cargo-fuzz proves the Rust doesn't
**panic**; this proves it doesn't silently **disagree** with the C oracle on inputs
nobody wrote a case for. OPERATING-GUIDE §3 calls it "the highest-value single
addition for a security-critical port."

## When
After the matrix differential is green (a port that fails fixed cases isn't ready
to fuzz). Run a short budget per module/PR and a long `--max-time` sweep nightly.
Needs a runnable C oracle (or a golden-replay wrapper, `porting-kit/harnesses/golden`).

## Procedure
1. **Run it** against both binaries, seeded from the real corpus:
   `python3 porting-kit/harnesses/diff-fuzz/diff_fuzz.py --oracle <c> --rust <rust>
   --seed-file corpus/* --matrix <m> --ledger DIVERGENCES.md --findings-dir fuzz-findings
   --max-time 300`
   Inputs are fuzzed on stdin by default; fixed argv goes in `--args`. `--seed N`
   makes the run reproducible; `--iterations N` bounds it instead of wall-clock.
2. **Read verdicts, not corpora** (the token-firewall rule): the tool prints one
   line per *distinct* divergence (deduped and minimized), not per input. Use
   `--json` for machine output. Each finding is saved as `<fp>.input` (the smallest
   reproducer) + `<fp>.diff` under `--findings-dir` — committable.
3. **Triage each finding** exactly like a matrix divergence: fix the Rust, OR — if
   the C is the buggy side — record the intentional fix-of-C-defect in
   `DIVERGENCES.md`. Fuzz findings are suppressed **only by fingerprint** (an
   arbitrary input has no stable name), so the entry MUST be pinned:
   `- [x] fuzz:<desc> [sha256:<fingerprint>]: <why + CWE>`.
4. **Pin the reproducer as a matrix case** (fix-forward, then immediately pin): add
   the minimized input to the golden/matrix so `diff_run.py` covers it forever, not
   just this fuzz seed.
5. A **rust-side TIMEOUT** finding is a hang on some input — a design smell, not a
   wrap-it target (LESSONS #001/#034); design the blocking path out.
6. **If you fuzz against a CORRECTED oracle, measure how wide the correction is.**
   *(This whole item comes from the c2rust-port lineage — its lessons "A
   predicate-defined intentional divergence can't be pinned", "A corrected
   reference oracle can hide the bug it was built to reveal" and "A correction's
   completeness is relative to the modes that exercise it". This kit has no
   corrected-oracle harness yet, so the guidance stands without a local
   number to cite.)* A divergence class that is *predicate-defined* — every NaN,
   every buffer length below a boundary — has no finite fingerprint set, so the
   fix goes into a patched copy of the C and the fuzzer runs against that.
   That patch is code you wrote against the subject under test:
   if it is wider than the decision it encodes, it suppresses real divergences,
   and a suppressed finding is indistinguishable from no finding. So also fuzz
   the same mode against the **PRISTINE** oracle and classify every finding
   **mechanically** — parse the descriptor, assert the set of differing fields
   is the known one — rather than eyeballing the first few hunks, which are the
   common case by construction. Record both runs side by side; the pristine row
   is what makes the corrected rows mean anything.

   **That is the correction's width, not its completeness.** The
   two are independent and only width has a control: a route no mode calls
   produces zero findings against both oracles, so a clean width check is
   equally consistent with a complete correction and a badly incomplete one.
   When a change puts a new entry point on the compared contract, enumerate by
   CALL GRAPH which existing corrections it can reach and re-derive them —
   name similarity will not find them. Record, per correction, which public
   entry points reach it and which mode exercises each.

## Notes
- Fidelity is shared, not reimplemented: every input is judged by
  `diff_run.compare_one`, so the stdout-AND-exit-code verdict (LESSONS #004), the
  fail-closed timeout handling (LESSONS #034), and the ledger fingerprint (LESSONS #041)
  are identical to the matrix differential.
- Determinism: a finding always reproduces — re-run with the same `--seed`, or just
  feed the saved `<fp>.input` back through `diff_run.py`.

## Integrity
Paths/flags must match `diff_fuzz.py`. If they drift, fix the reference and re-run
the kit's `make check-kit` (`make -C porting-kit check-kit` when vendored) — its
doc-flag check hard-fails on a documented flag the harness doesn't have.
