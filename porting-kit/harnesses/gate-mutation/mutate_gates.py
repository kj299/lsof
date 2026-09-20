#!/usr/bin/env python3
# KIT-IMPORT: from the c2rust-port lineage of this kit.
# Local: #053 (this kit's own first sweep with it).
# Re-cited: #6->#036, #13->#033, #14->#037, #16->#050, #21->#041, #22->#051,
#          #25->#052; #36 by title (no entry in this log).
"""Gate-mutation harness — break each gate's verdict on purpose and PROVE the
suite goes red. The standing "failure the kit still would not prevent" since
retro #1 (RETROSPECTIVE-kit-v1.md §5 item 2), sharpened by LESSONS #033/#037: the
kit's fail-open holes (LEDGER-STALE, the wrapped-path skip, the fenced-block
harvest) were all gates that PASSED while checking nothing, each found by a
human probing by hand. This harness makes that probe mechanical.

For every gate in MUTATIONS, in a scratch copy of the kit:
  1. neutralize that gate's verdict logic (one surgical, table-driven edit —
     e.g. `is_match = True`, `return []`, `if False:`), then
  2. run the gate's own self-test and REQUIRE it to fail.
A self-test that stays green over a neutralized verdict is a survivor: the
"pinned regression suite" for that gate is theater, and this harness exits 1
naming it. The gate set becomes self-verifying — the next fail-open of the
LEDGER-STALE class is caught by `make check-kit`, not by luck.

A full sweep also audits the TABLE (LESSONS #052): any harness exposing a
self-test but carrying no mutation entry is reported as a coverage GAP and fails
the run. "N gate(s) mutated, 0 survivor(s)" used to read as the whole gate set
while silently covering only the python half — that blind spot hid a sanitizer
mode wired to a value rustc rejects, which could never pass, for a month.

Fail-closed by construction (LESSONS #036):
  * a mutation whose old-text is missing (the harness was rewritten) or
    ambiguous (matches twice) is a HARD ERROR — the table must track the code,
    exactly like check_lessons_pinned tracks the lessons;
  * a mutated .py that no longer compiles is a HARD ERROR — a SyntaxError would
    fail the self-test for the wrong reason and count as fake coverage;
  * a self-test that dies with a Traceback under mutation is a HARD ERROR for
    the same reason — we are proving verdict coverage, not crash detection;
  * the BASELINE (unmutated copy) must be green first — otherwise red can't be
    attributed to the mutation.

The live tree is never touched: each run works in fresh copies under a temp dir.

Usage:
  mutate_gates.py [KIT_ROOT] [--only GATE[,GATE..]] [--list] [--json]
  mutate_gates.py --self-test
Exit: 0 = every mutation caught; 1 = a survivor (or usage=2).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

# One entry per gate: neutralize the CROWN verdict — the single predicate whose
# silent failure would let the gate pass while checking nothing. `old` must
# appear EXACTLY ONCE in `file` (enforced), so a harness rewrite that moves the
# verdict forces a table update instead of silently mutating dead code.
# (LESSONS #050: this harness's first sweep found a survivor — a bundled
# two-defect fixture that pinned only the union of its checks.)
MUTATIONS = [
    {"gate": "diff_run", "file": "harnesses/differential/diff_run.py",
     "old": "    is_match = stdout_match and exit_match and stderr_match",
     "new": "    is_match = True",
     "why": "every case MATCHes regardless of output/exit",
     "cmd": ["harnesses/differential/diff_run.py", "--self-test"]},



    {"gate": "diff_fuzz", "file": "harnesses/diff-fuzz/diff_fuzz.py",
     "old": '    return verdict in ("DIVERGE", "TIMEOUT")',
     "new": "    return False",
     "why": "nothing is ever a finding: the fuzzer reports clean on divergence",
     "cmd": ["harnesses/diff-fuzz/diff_fuzz.py", "--self-test"]},

    {"gate": "unsafe-audit", "file": "harnesses/unsafe-audit/audit_unsafe.py",
     "old": "        break  # first real code line: the run is over, not documented\n"
            "    return False",
     "new": "        break  # first real code line: the run is over, not documented\n"
            "    return True",
     "why": "every unsafe block counts as documented",
     "cmd": ["harnesses/unsafe-audit/audit_unsafe.py", "--self-test"]},

    {"gate": "c-flaw-scan", "file": "harnesses/c-flaw-scan/scan_c_flaws.py",
     "old": "            if rx.search(code):",
     "new": "            if False:",
     "why": "the Phase-0 scanner reports 0 flaws on any C",
     "cmd": ["harnesses/c-flaw-scan/scan_c_flaws.py", "--self-test"]},

    # Not a verdict — an INPUT path, and that is the point. If the
    # `stdin_b64` resolution is dropped, a case carrying raw bytes feeds the
    # child NOTHING, both sides answer identically to empty input, and the case
    # reports MATCH. The test is silently narrowed rather than failed, which is
    # the one failure shape a differential cannot report on itself. Two gates
    # depend on it: the matrix and the fuzzer's seed corpus.
    {"gate": "diff-matrix-bytes", "file": "harnesses/differential/diff_run.py",
     "old": '                case["stdin_bytes"] = base64.b64decode(case["stdin_b64"], validate=True)',
     "new": '                case["stdin_bytes"] = b""',
     "why": "a matrix case's raw bytes silently become empty stdin: the case still MATCHes",
     "cmd": ["harnesses/differential/diff_run.py", "--self-test"]},

    # The BASH gates (LESSONS #051/#052). None could be here until `_run` stopped
    # assuming python — which is why a mode wired to a sanitizer rustc rejects
    # survived every sweep. `coverage_gaps()` now fails a full sweep if any
    # self-tested harness sits outside this table at all.
    {"gate": "fuzz-scaffolder", "file": "harnesses/fuzz/gen_fuzz_target.sh",
     "old": '  grep -q "fuzz_target!" "$f" || return 1\n  grep -q "$crate" "$f" || return 1',
     "new": "  :",
     "why": "an unexpanded template counts as a generated target",
     "cmd": ["harnesses/fuzz/gen_fuzz_target.sh", "--check"]},

    {"gate": "supply-chain", "file": "harnesses/supply-chain/run_supply_chain.sh",
     "old": 'have_deny_template() { test -f "$1/deny.template.toml"; }',
     "new": "have_deny_template() { true; }",
     "why": "a missing cargo-deny config no longer fails the check",
     "cmd": ["harnesses/supply-chain/run_supply_chain.sh", "--check"]},


    {"gate": "sanitizers", "file": "harnesses/sanitizers/run_sanitizers.sh",
     "old": '    *" $1 "*) return 0;;\n    *) return 1;;',
     "new": "    *) return 0;;",
     "why": "any string counts as a valid sanitizer: a never-runnable mode ships green",
     "cmd": ["harnesses/sanitizers/run_sanitizers.sh", "--check"]},

    # (LESSONS #041: test expectations are GENERATED from the oracle transcript;
    # a verify that can't see oracle drift would bless any live behavior)
    {"gate": "probe", "file": "harnesses/probe/probe.py",
     "old": '        behavior_matches = rc == e["rc"] and out_b64 == e["stdout_b64"]',
     "new": "        behavior_matches = True",
     "why": "oracle drift invisible: verify blesses any live behavior as pinned",
     "cmd": ["harnesses/probe/probe.py", "--self-test"]},

    {"gate": "golden", "file": "harnesses/golden/golden.py",
     "old": "        if got == golden:",
     "new": "        if True:",
     "why": "replay always MATCHes the golden regardless of output",
     "cmd": ["harnesses/golden/golden.py", "--self-test"]},


    {"gate": "normalize", "file": "harnesses/differential/normalize.py",
     "old": "    active = list(rules) + ([PID_RULE] if mask_numbers else [])",
     "new": "    active = []",
     "why": "no normalization rule is ever applied",
     "cmd": ["harnesses/differential/normalize.py", "--self-test"]},

    {"gate": "progress", "file": "harnesses/progress/progress.py",
     "old": '        if rep.get("undocumented", 1) == 0:',
     "new": "        if True:",
     "why": "any differential report (even all-DIVERGE, even empty) advances the gate",
     "cmd": ["harnesses/progress/progress.py", "--self-test"]},




    {"gate": "skills", "file": "skills/check_skills.py",
     "old": "        if not os.path.exists(os.path.join(kit_root, rel)):",
     "new": "        if False:",
     "why": "a skill referencing a deleted kit path is never flagged",
     "cmd": ["skills/check_skills.py", "--self-test"]},

    # ---- gates this lineage has that the source kit does not --------------
    # These five are authored here, not imported. A table inherited from
    # another lineage covers that lineage's harnesses; the ones this kit grew
    # on its own would sit outside it, and `coverage_gaps()` is what says so.

    {"gate": "doc-flags", "file": "harnesses/doc-check/check_doc_flags.py",
     "old": '                if not re.search(r"(?<![\\w-])" + re.escape(flag) + r"(?![\\w-])",\n'
            "                                 sources[script]):",
     "new": "                if False:",
     "why": "every documented flag counts as existing",
     "cmd": ["harnesses/doc-check/check_doc_flags.py", "--self-test"]},

    {"gate": "skeleton-check", "file": "harnesses/skeleton-check/check_skeleton.sh",
     "old": 'skel_present() { test -d "$1" && test -f "$1/Cargo.toml"; }',
     "new": "skel_present() { true; }",
     "why": "a missing skeleton directory still reports present",
     "cmd": ["harnesses/skeleton-check/check_skeleton.sh", "--check"]},

    {"gate": "coverage-gate", "file": "harnesses/coverage/coverage_gate.py",
     "old": "    uncovered = sorted(required - waived_ids - covered)",
     "new": "    uncovered = []",
     "why": "no feature is ever uncovered: an empty matrix reports full coverage",
     "cmd": ["harnesses/coverage/coverage_gate.py", "--self-test"]},

    {"gate": "ledgers", "file": "harnesses/ledgers/check_ledgers.py",
     "old": "    missing = [c for c in CHECKS if not found[c] and c not in allow]",
     "new": "    missing = []",
     "why": "every mandated ledger counts as present, including in an empty port",
     "cmd": ["harnesses/ledgers/check_ledgers.py", "--self-test"]},

    {"gate": "lesson-refs", "file": "harnesses/lessons/check_lesson_refs.py",
     "old": "        if num not in known:",
     "new": "        if False:",
     "why": "a citation of a lesson that does not exist resolves silently",
     "cmd": ["harnesses/lessons/check_lesson_refs.py", "--self-test"]},

    # check_imports has TWO independent verdicts and one entry would pin only
    # their union — the exact shape of the survivor this harness's own first
    # sweep found in the source lineage. So: one row each.
    {"gate": "imports-resolution",
     "file": "harnesses/lessons/check_imports.py",
     "old": "            elif normalize_title(titles[dest]) != normalize_title(title):",
     "new": "            elif False:",
     "why": "a re-cite to a real but WRONG entry passes: the title is never checked",
     "cmd": ["harnesses/lessons/check_imports.py", "--self-test"]},

    {"gate": "imports-completeness",
     "file": "harnesses/lessons/check_imports.py",
     "old": "            if ref not in mapped_dests:",
     "new": "            if False:",
     "why": "a number carried over from the source lineage is never accounted for",
     "cmd": ["harnesses/lessons/check_imports.py", "--self-test"]},
]

_IGNORE = shutil.ignore_patterns(
    ".git", "target", "corpus", "reports", "__pycache__", "fuzz-findings",
    "artifacts", "*.so", "*.o", "*.pyc")


def _copy_kit(kit_root, dst):
    shutil.copytree(kit_root, dst, ignore=_IGNORE, symlinks=True)


def _apply(kit_copy, m):
    """Apply one mutation in the copy. Hard error (fail closed) if the old text
    is missing (stale table) or ambiguous, or if the result doesn't compile."""
    path = os.path.join(kit_copy, m["file"])
    src = open(path, encoding="utf-8").read()
    n = src.count(m["old"])
    if n == 0:
        sys.exit(f"error: mutation table is STALE — {m['gate']}: the target text no "
                 f"longer appears in {m['file']}. The verdict moved; update the "
                 f"table entry (this is the table tracking the code, like "
                 f"check_lessons_pinned tracks the lessons).")
    if n > 1:
        sys.exit(f"error: mutation {m['gate']}: target text appears {n}x in "
                 f"{m['file']} — ambiguous; extend `old` with surrounding context.")
    mutated = src.replace(m["old"], m["new"], 1)
    if path.endswith(".py"):
        try:
            compile(mutated, path, "exec")
        except SyntaxError as e:
            sys.exit(f"error: mutation {m['gate']} breaks the syntax of {m['file']} "
                     f"({e}) — a SyntaxError fails the self-test for the wrong "
                     f"reason and would count as fake coverage. Fix the table.")
    open(path, "w", encoding="utf-8").write(mutated)


# Harnesses allowed to have a self-test but NO mutation entry. Keep this tiny and
# justified — an exemption is a hole somebody chose, in writing (LESSONS #052).
COVERAGE_EXEMPT = {
    "harnesses/gate-mutation/mutate_gates.py":
        "the mutator itself — its own self-test mutates a fixture gate and "
        "asserts both the caught and survived verdicts",
}


def coverage_gaps(kit_root, mutations=None):
    """Harnesses that expose a self-test but sit outside the mutation table.

    The gate above this gate (LESSONS #052). The table is hand-maintained, so
    "N gate(s) mutated, 0 survivor(s)" says nothing about the harnesses nobody
    added — and for the kit's whole life that silently meant *every bash
    harness*, one of which was shipping a mode that could never pass. A harness
    with a self-test and no entry is now a failure, not an absence.
    """
    covered = {m["file"] for m in (MUTATIONS if mutations is None else mutations)}
    gaps = []
    for base in ("harnesses", "skills"):
        top = os.path.join(kit_root, base)
        if not os.path.isdir(top):
            continue
        for root, _dirs, files in os.walk(top):
            for f in sorted(files):
                if not f.endswith((".py", ".sh")):
                    continue
                rel = os.path.relpath(os.path.join(root, f), kit_root)
                if rel in covered or rel in COVERAGE_EXEMPT:
                    continue
                try:
                    text = open(os.path.join(root, f), encoding="utf-8",
                                errors="replace").read()
                except OSError:
                    continue
                if '"--self-test"' in text or '"--check"' in text:
                    gaps.append(rel)
    return sorted(gaps)


def _run(kit_copy, cmd, timeout=300):
    # Dispatch by extension. This used to hardcode `sys.executable`, which meant
    # the sweep could only ever cover PYTHON gates — while still printing
    # "N gate(s) mutated, 0 survivor(s)", which reads as the whole gate set
    # (LESSONS #051). The kit's bash harnesses were structurally unreachable, and
    # one of them (`run_sanitizers.sh`) was shipping a mode that could never run.
    path = os.path.join(kit_copy, cmd[0])
    argv = ([sys.executable, path] if cmd[0].endswith(".py")
            else ["bash", path]) + cmd[1:]
    p = subprocess.run(argv, cwd=kit_copy, capture_output=True, text=True,
                       timeout=timeout)
    return p.returncode, p.stdout + p.stderr


def run_gates(kit_root, mutations, as_json=False, check_coverage=True):
    kit_root = os.path.abspath(kit_root)
    # A full sweep also audits the TABLE: a self-tested harness with no entry is
    # a gate this sweep silently does not cover (LESSONS #052). Skipped for
    # --only runs, which are deliberately partial.
    gaps = coverage_gaps(kit_root, mutations) if check_coverage else []
    results = []
    with tempfile.TemporaryDirectory(prefix="gate-mutation-") as tmp:
        # Baseline: every self-test must be green UNMUTATED, or red can't be
        # attributed to the mutation.
        clean = os.path.join(tmp, "baseline")
        _copy_kit(kit_root, clean)
        for cmd in {tuple(m["cmd"]) for m in mutations}:
            rc, out = _run(clean, list(cmd))
            if rc != 0:
                sys.exit(f"error: baseline is RED before any mutation — "
                         f"`{' '.join(cmd)}` exits {rc} on a clean copy. Fix that "
                         f"first; mutation results would be meaningless.\n{out[-2000:]}")

        for i, m in enumerate(mutations):
            work = os.path.join(tmp, f"m{i}")
            _copy_kit(kit_root, work)
            _apply(work, m)
            rc, out = _run(work, m["cmd"])
            if rc != 0 and "Traceback (most recent call last)" in out:
                sys.exit(f"error: mutation {m['gate']} CRASHES the self-test "
                         f"(Traceback) instead of failing its checks — that proves "
                         f"crash detection, not verdict coverage. Refine the "
                         f"mutation.\n{out[-2000:]}")
            results.append({"gate": m["gate"], "file": m["file"], "why": m["why"],
                            "caught": rc != 0, "self_test_rc": rc})

    survivors = [r for r in results if not r["caught"]]
    if as_json:
        print(json.dumps({"results": results,
                          "survivors": [r["gate"] for r in survivors],
                          "table_gaps": gaps}, indent=2))
    else:
        for r in results:
            print(f"[{'CAUGHT  ' if r['caught'] else 'SURVIVED'}] {r['gate']:16} "
                  f"{r['why']}")
        print(f"\n{len(results)} gate(s) mutated, {len(survivors)} survivor(s)")
        if gaps:
            print(f"\nTABLE GAP: {len(gaps)} self-tested harness(es) have no "
                  f"mutation entry — the sweep's verdict does not cover them "
                  f"(LESSONS #052):")
            for g in gaps:
                print(f"  {g}")
            print("Add an entry neutralizing that gate's crown verdict, or an "
                  "explicit COVERAGE_EXEMPT reason.")
        if survivors:
            print("SURVIVED = the gate's verdict was neutralized and its self-test "
                  "STAYED GREEN: that self-test is not pinning the verdict. Add a "
                  "fixture that fails under this mutation.")
    return 1 if (survivors or gaps) else 0


# ---------------------------------------------------------------- self-test --

_TOY_GATE = '''\
#!/usr/bin/env python3
import sys

def is_ok(x):
    # the verdict under test
    return x > 0

def self_test():
    ok = True
    ok &= is_ok(1) is True
    ok &= is_ok(-1) is False    # pins the verdict: red if is_ok is neutralized
    print("self-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(self_test())
'''


def _self_test():
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + f"  {name}")
        ok = ok and cond

    def exits(fn):
        try:
            fn()
            return False
        except SystemExit as e:
            return e.code not in (0, None)

    with tempfile.TemporaryDirectory() as root:
        kit = os.path.join(root, "kit")
        os.makedirs(os.path.join(kit, "harnesses", "toy"))
        gate = os.path.join(kit, "harnesses", "toy", "gate.py")
        open(gate, "w").write(_TOY_GATE)
        base = {"gate": "toy", "file": "harnesses/toy/gate.py",
                "cmd": ["harnesses/toy/gate.py"], "why": "toy verdict"}

        good = dict(base, old="    return x > 0", new="    return True")
        check("a real verdict-neutralization is CAUGHT (suite goes red)",
              run_gates(kit, [good], as_json=False) == 0)

        # a mutation that changes nothing the verdict depends on must SURVIVE,
        # and a survivor must fail the harness — that is the whole point.
        harmless = dict(base, old="    # the verdict under test",
                        new="    # a comment change, verdict intact")
        check("a harmless mutation SURVIVES and the harness exits 1",
              run_gates(kit, [harmless], as_json=False) == 1)

        # stale table: old text absent → hard error, not a silent skip
        stale = dict(base, old="    return x >= 42", new="    return True")
        check("a stale table entry is a hard error (fail closed)",
              exits(lambda: run_gates(kit, [stale])))

        # ambiguous old text → hard error
        open(gate, "a").write("\n# duplicated marker\n#     return x > 0\n")
        ambiguous = dict(base, old="    return x > 0", new="    return True")
        check("an ambiguous match is a hard error",
              exits(lambda: run_gates(kit, [ambiguous])))
        open(gate, "w").write(_TOY_GATE)

        # a mutation that breaks the syntax → hard error (fake coverage guard)
        broken = dict(base, old="    return x > 0", new="    return x >")
        check("a syntax-breaking mutation is a hard error",
              exits(lambda: run_gates(kit, [broken])))

        # a RED baseline → hard error before any mutation runs
        open(gate, "w").write(_TOY_GATE.replace("ok &= is_ok(1) is True",
                                                "ok &= is_ok(1) is False"))
        check("a red baseline is a hard error (red must be attributable)",
              exits(lambda: run_gates(kit, [good])))

        # LESSONS #052: the TABLE itself is audited. A harness with a self-test
        # and no mutation entry is a gate this sweep silently does not cover —
        # which is what hid the never-runnable sanitizer mode for a month.
        os.makedirs(os.path.join(kit, "harnesses", "lonely"))
        lonely = os.path.join(kit, "harnesses", "lonely", "ungated.sh")
        open(lonely, "w").write('#!/usr/bin/env bash\n'
                                'if [[ "${1:-}" == "--check" ]]; then exit 0; fi\n')
        check("a self-tested harness outside the table is a coverage GAP",
              coverage_gaps(kit, [good]) == ["harnesses/lonely/ungated.sh"])
        check("adding it to the table closes the gap",
              coverage_gaps(kit, [good, dict(good, file="harnesses/lonely/ungated.sh")])
              == [])
        # a harness with no self-test at all creates no obligation
        open(os.path.join(kit, "harnesses", "lonely", "helper.py"), "w").write(
            "# just a library, no self-test\n")
        check("a harness with no self-test creates no obligation",
              coverage_gaps(kit, [good, dict(good, file="harnesses/lonely/ungated.sh")])
              == [])

    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("kit_root", nargs="?", help="kit checkout to mutate (a scratch copy is used)")
    ap.add_argument("--only", help="comma-separated gate names to run (default: all)")
    ap.add_argument("--list", action="store_true", help="list the mutation table and exit")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()
    if args.list:
        for m in MUTATIONS:
            print(f"{m['gate']:16} {m['file']:44} {m['why']}")
        return 0
    if not args.kit_root:
        ap.print_usage(sys.stderr)
        print("error: give KIT_ROOT (usually `.`), or --self-test / --list", file=sys.stderr)
        return 2
    muts = MUTATIONS
    if args.only:
        names = {n.strip() for n in args.only.split(",")}
        unknown = names - {m["gate"] for m in MUTATIONS}
        if unknown:
            sys.exit(f"error: unknown gate(s): {', '.join(sorted(unknown))} "
                     f"(see --list)")
        muts = [m for m in MUTATIONS if m["gate"] in names]
    return run_gates(args.kit_root, muts, as_json=args.json,
                     check_coverage=not args.only)


if __name__ == "__main__":
    sys.exit(main())
