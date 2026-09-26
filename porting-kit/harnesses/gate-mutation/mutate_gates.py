#!/usr/bin/env python3
# KIT-IMPORT: from the c2rust-port lineage of this kit.
# Local: #053, #057, #058, #059, #060, #064, #065, #066, #070 (see below).
# Re-cited: #6->#036, #13->#033, #14->#037, #16->#050, #21->#041, #22->#051,
#          #25->#052, #44->#060, #48->#069; #20 by title, #36 by title (no
#          entry in this log).
# Those local lessons: this kit's first sweep, the resolver, pinned-lessons,
# lesson-refs and forbid rows, and the drivers behind the one-copy rule (#066).
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

And it audits every DECISION in a verdict function (LESSONS #069). The table is
one row per verdict by convention (LESSONS #050), and the table audit counts rows
per HARNESS, so a verdict added beside one that already had a row was invisible.
The sweep now finds the verdicts itself: each decision in a function that holds
a row's target is forced True, then False, and the self-test must go red. One it
does not catch is UNPINNED — it must get a fixture, or a line in LEDGER saying
why it stays. The ledger only shrinks.

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
  mutate_gates.py [KIT_ROOT] [--only GATE[,GATE..]] [--rows-only] [--list] [--json]
  mutate_gates.py --self-test
Exit: 0 = every mutation caught; 1 = a survivor, a table gap, a new unpinned
decision or a stale ledger entry (or usage=2).
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import warnings
from concurrent.futures import ThreadPoolExecutor

# One entry per gate: neutralize the CROWN verdict — the single predicate whose
# silent failure would let the gate pass while checking nothing. `old` must
# appear EXACTLY ONCE in `file` (enforced), so a harness rewrite that moves the
# verdict forces a table update instead of silently mutating dead code.
# (LESSONS #050: this harness's first sweep found a survivor — a bundled
# two-defect fixture that pinned only the union of its checks.)
#
# The table below was REBUILT against this kit, not copied with the harness: an
# inherited row names the source lineage's text, and 6 of 13 no longer matched
# here while 5 of this lineage's own harnesses had no row at all. A control
# imported from a sibling lineage carries its proof only for the tree it was
# proven in, so the first sweep is an audit of the importing tree — and a CLEAN
# first run is the suspicious one (LESSONS #053).
MUTATIONS = [
    {"gate": "diff_run", "file": "harnesses/differential/diff_run.py",
     "old": "    is_match = stdout_match and exit_match and stderr_match",
     "new": "    is_match = True",
     "why": "every case MATCHes regardless of output/exit",
     "cmd": ["harnesses/differential/diff_run.py", "--self-test"]},



    # A layout case asks for its spacing to be compared (LESSONS #070). If the
    # key is ignored, every such case collapses its whitespace like any other
    # and MATCHes whatever the alignment — the gate the key exists to be.
    {"gate": "diff-keep-whitespace", "file": "harnesses/differential/diff_run.py",
     "old": '    trim = not case.get("keep_whitespace", False)',
     "new": "    trim = True",
     "why": "keep_whitespace is ignored: a layout case MATCHes whatever the spacing",
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

    # Unsafe CONTAINED (LESSONS #065) — five verdicts, each of which lets a
    # crate that does not forbid unsafe pass on its own, so one row each
    # (LESSONS #050). Every "does not count" was checked against rustc.
    {"gate": "forbid-unsafe-deny", "file": "harnesses/unsafe-audit/check_forbid_unsafe.py",
     "old": '    return level == "forbid" and not conditional',
     "new": '    return level in ("forbid", "deny") and not conditional',
     "why": '`deny(unsafe_code)` counts as contained; a local #[allow] then admits unsafe',
     "cmd": ["harnesses/unsafe-audit/check_forbid_unsafe.py", "--self-test"]},

    {"gate": "forbid-unsafe-cfg-attr", "file": "harnesses/unsafe-audit/check_forbid_unsafe.py",
     "old": '    return level == "forbid" and not conditional',
     "new": '    return level == "forbid"',
     "why": '`cfg_attr(test, forbid(unsafe_code))` counts: every non-test build admits unsafe',
     "cmd": ["harnesses/unsafe-audit/check_forbid_unsafe.py", "--self-test"]},

    {"gate": "forbid-unsafe-nesting", "file": "harnesses/unsafe-audit/check_forbid_unsafe.py",
     "old": '        if text.startswith("/*", i):\n            depth += 1',
     "new": '        if text.startswith("/*", i):\n            depth = 1',
     "why": 'C comment rules: an attribute commented out inside `/* /* */ … */` reads as live',
     "cmd": ["harnesses/unsafe-audit/check_forbid_unsafe.py", "--self-test"]},

    {"gate": "forbid-unsafe-every-root", "file": "harnesses/unsafe-audit/check_forbid_unsafe.py",
     "old": '    for rel in roots:',
     "new": '    for rel in roots[:1]:',
     "why": "a forbidding lib.rs certifies lsof-cli's main.rs beside it, which is its own crate",
     "cmd": ["harnesses/unsafe-audit/check_forbid_unsafe.py", "--self-test"]},

    {"gate": "forbid-unsafe-no-roots", "file": "harnesses/unsafe-audit/check_forbid_unsafe.py",
     "old": '    if not roots:',
     "new": '    if False:',
     "why": 'a crate with no target root passes a containment check over nothing',
     "cmd": ["harnesses/unsafe-audit/check_forbid_unsafe.py", "--self-test"]},

    {"gate": "c-flaw-scan", "file": "harnesses/c-flaw-scan/scan_c_flaws.py",
     "old": "            if hit:",
     "new": "            if False:",
     "why": "the Phase-0 scanner reports 0 flaws on any C",
     "cmd": ["harnesses/c-flaw-scan/scan_c_flaws.py", "--self-test"]},

    # The literal blanking this scanner does must not reach `scanf("%s")`,
    # whose evidence IS the literal. It did, silently, until LESSONS #064.
    {"gate": "c-flaw-scan-reads-literals", "file": "harnesses/c-flaw-scan/scan_c_flaws.py",
     "old": '            if rx in READS_LITERALS:',
     "new": '            if False:',
     "why": 'scanf("%s") stops being flagged: a false negative in a security scanner',
     "cmd": ["harnesses/c-flaw-scan/scan_c_flaws.py", "--self-test"]},

    # The call-must-be-code rule (LESSONS #064) removes a false positive; its
    # dangerous direction is judging EVERY match prose, which silences the check.
    {"gate": "c-flaw-scan-call-is-code", "file": "harnesses/c-flaw-scan/scan_c_flaws.py",
     "old": "                hit = any(code[m.start(1):m.end(1)] == m.group(1)",
     "new": "                hit = any(False",
     "why": 'every scanf match is judged prose and skipped: scanf("%s") goes silent',
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

    {"gate": "threat-model", "file": "harnesses/threat-model/check_threat_model.py",
     "old": "    if problems:",
     "new": "    if False:",
     "why": "an unfilled or sectionless threat model passes: the gate reports nothing",
     "cmd": ["harnesses/threat-model/check_threat_model.py", "--self-test"]},

    {"gate": "perf", "file": "harnesses/perf/perf_gate.py",
     "old": '            verdict = "OK" if ratio <= threshold else "SLOW"',
     "new": '            verdict = "OK"',
     "why": "no ratio is ever SLOW",
     "cmd": ["harnesses/perf/perf_gate.py", "--self-test"]},

    {"gate": "control-coverage", "file": "harnesses/control-coverage/check_controls.py",
     "old": "    return any((control in executable_text(text)) or (base in executable_text(text))\n"
            "               for text in gate_texts)",
     "new": "    return True",
     "why": "every declared control counts as wired: an unrun gate ships green",
     "cmd": ["harnesses/control-coverage/check_controls.py", "--self-test"]},

    # A table row naming no harness used to vanish from the report; it was
    # `#![forbid(unsafe_code)]` on `core`, the table's first row (LESSONS #064).
    {"gate": "control-coverage-unreadable",
     "file": "harnesses/control-coverage/check_controls.py",
     "old": "                if name not in unreadable:",
     "new": "                if False:",
     "why": "a gate-table row naming no harness vanishes from the report without a word",
     "cmd": ["harnesses/control-coverage/check_controls.py", "--self-test"]},

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

    # That row pinned ONE of this checker's four verdicts; each of the other
    # three fails open alone. The primary line pinned all four when it took
    # the checker from here (LESSONS #064), so this is the fix coming back.
    {"gate": "lesson-refs-duplicate", "file": "harnesses/lessons/check_lesson_refs.py",
     "old": '    dupes = sorted({n for n in nums if nums.count(n) > 1})',
     "new": '    dupes = []',
     "why": 'two entries with one number: every citation of it resolves, to whichever',
     "cmd": ["harnesses/lessons/check_lesson_refs.py", "--self-test"]},

    {"gate": "lesson-refs-gap", "file": "harnesses/lessons/check_lesson_refs.py",
     "old": '            if n not in nums:',
     "new": '            if False:',
     "why": 'a deleted heading splices its body onto the entry above, unseen',
     "cmd": ["harnesses/lessons/check_lesson_refs.py", "--self-test"]},

    {"gate": "lesson-refs-offstyle", "file": "harnesses/lessons/check_lesson_refs.py",
     "old": '        if ENTRY_RE.match(head + " x"):\n            continue',
     "new": '        continue',
     "why": 'an entry written `### #032` is no entry at all, and nothing says so',
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

    # THREE rows, same reasoning as check_imports: the "is this lesson pinned in
    # the file it amends" verdict, the "is this field's spelling one we know"
    # verdict and the "which roots is an amended path resolved against" verdict
    # are independent. The latter two are the ones that were failing open — six
    # live host-repo paths counted as aged history (LESSONS #058), and any
    # parenthesised field spelling voiding an entry in silence (LESSONS #060).
    # The `old`-appears-exactly-once rule this harness enforces is what keeps
    # these rows honest: a pattern that no longer occurs would otherwise no-op
    # and read as a survivor (LESSONS #059).
    {"gate": "lessons-pinned",
     "file": "harnesses/doc-check/check_lessons_pinned.py",
     "old": "    return 1 if problems else 0",
     "new": "    return 0",
     "why": "a lesson may amend a file that never cites it; the log's links go stale silently",
     "cmd": ["harnesses/doc-check/check_lessons_pinned.py", "--self-test"]},

    {"gate": "lessons-pinned-variant",
     "file": "harnesses/doc-check/check_lessons_pinned.py",
     "old": "            if variant != ELSEWHERE_VARIANT:",
     "new": "            if False:",
     "why": "any parenthesised `Section amended (...)` spelling silently drops the entry's obligations",
     "cmd": ["harnesses/doc-check/check_lessons_pinned.py", "--self-test"]},

    {"gate": "lessons-pinned-scope",
     "file": "harnesses/doc-check/check_lessons_pinned.py",
     "old": "    roots = [kit_root, *also]",
     "new": "    roots = [kit_root]",
     "why": "a vendored kit's host-repo paths are unreachable again and report as aged, not unpinned",
     "cmd": ["harnesses/doc-check/check_lessons_pinned.py", "--self-test"]},

    # The platform ledger has THREE independent verdicts. One row would pin only
    # their union, so: one each, on the same reasoning as check_imports above.
    {"gate": "platforms-completeness",
     "file": "harnesses/platforms/check_platforms.py",
     "old": "        if name not in ledger:",
     "new": "        if False:",
     "why": "a platform the build system can select need never appear in the ledger",
     "cmd": ["harnesses/platforms/check_platforms.py", "--self-test"]},

    {"gate": "platforms-evidence",
     "file": "harnesses/platforms/check_platforms.py",
     "old": "            if hit is None:",
     "new": "            if False:",
     "why": "a platform claiming CI builds it passes with no evidence anywhere",
     "cmd": ["harnesses/platforms/check_platforms.py", "--self-test"]},

    {"gate": "platforms-stale-waiver",
     "file": "harnesses/platforms/check_platforms.py",
     "old": "            if hit is not None:",
     "new": "            if False:",
     "why": "a waiver becomes a mute button: CI may build what is waived as unbuilt",
     "cmd": ["harnesses/platforms/check_platforms.py", "--self-test"]},
    # The collision resolver has THREE independent refusal/rewrite verdicts, so
    # three rows: one fixture pins each, and one row would pin only their union.
    # Those three rows are the price of LESSONS #057 — the renumber had been done
    # by hand five times before it became a harness, and a harness this table
    # does not cover is a harness whose verdicts nothing holds.
    {"gate": "collision-provenance",
     "file": "harnesses/lessons/resolve_collision.py",
     "old": '    if line not in keep_lines:\n        return "move"',
     "new": '    if line not in keep_lines:\n        return "keep"',
     "why": "no line is ever the moving side's: the block is renumbered and every citation to it stays stale",
     "cmd": ["harnesses/lessons/resolve_collision.py", "--self-test"]},

    {"gate": "collision-ambiguity",
     "file": "harnesses/lessons/resolve_collision.py",
     "old": '    return "ambiguous" if line in move_lines else "keep"',
     "new": '    return "keep"',
     "why": "a line both sides wrote is silently read as the kept side's",
     "cmd": ["harnesses/lessons/resolve_collision.py", "--self-test"]},

    {"gate": "collision-displaced",
     "file": "harnesses/lessons/resolve_collision.py",
     "old": "    if displaced:\n        raise Refuse(",
     "new": "    if False:\n        raise Refuse(",
     "why": "a paragraph cut from an old entry and carried in the new block merges without a word",
     "cmd": ["harnesses/lessons/resolve_collision.py", "--self-test"]},
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
        "the mutator itself — its own self-test mutates fixture gates and "
        "asserts caught, survived, unpinned and stale; the decision sweep "
        "(LESSONS #069), run over its own verdict functions, leaves only report "
        "text, worker counts and unreachable guards unpinned",
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


# ------------------------------------------ one row per verdict (LESSONS #069) --
#
# The table audit above counts rows per harness. In this kit (LESSONS #064) a
# call-must-be-code rule landed in the scanner's verdict function with a
# fixture and no row; the scanner already had two rows, so nothing could
# notice. So the sweep derives the verdicts itself.
#
# A VERDICT FUNCTION is a top-level function (or a method of a top-level class)
# holding a row's `old` text. Every decision in it — an if/while/conditional
# test, a comparison, an and/or and each operand, a `not` — is a verdict: it is
# forced True, then False, and the harness's self-test must go red for each. A
# decision it does not catch is UNPINNED: either the gate behaves differently
# on some input and its self-test does not notice, or the decision can never
# matter (an equivalent mutant). Pin it with a fixture, or give it a line in
# LEDGER saying which and why it stays. The ledger only shrinks: an entry that
# is pinned now, or no longer names a decision, fails the sweep too.
#
# Two lines drawn on purpose. The helpers a verdict function calls are PLUMBING
# and are not enumerated: in this kit they are hundreds of bounds checks in
# parsers — and plumbing has bugs of its own, which this does not look for.
# A verdict moved into a helper escapes,
# unless its call site is itself a decision. And a mutant that crashes or hangs
# the self-test is CAUGHT, unlike a hand row (where a Traceback is a hard
# error): a row claims to neutralize a verdict, so a crash means the row is
# wrong, while these claim nothing, and a crash or a hang turns the real gate
# red as well.

LEDGER = "harnesses/gate-mutation/unpinned.jsonl"
_KEY = ("file", "func", "line", "expr", "to", "n")


def verdict_functions(src, targets):
    """{qualname: FunctionDef} for each function holding one of `targets` (row
    `old` texts). A target that is missing, or outside every function, names no
    verdict function here; the row sweep reports a missing one as stale."""
    tree = ast.parse(src)
    spans = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            spans.append((node.name, node))
        elif isinstance(node, ast.ClassDef):
            spans += [(f"{node.name}.{f.name}", f) for f in node.body
                      if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef))]
    found = {}
    for old in targets:
        i = src.find(old)
        if i < 0:
            continue
        i += len(old) - len(old.lstrip())
        first = src.count("\n", 0, i) + 1
        last = first + old.strip().count("\n")
        for name, fn in spans:
            if fn.lineno <= first and last <= fn.end_lineno:
                found[name] = fn
    return found


def _decisions(fn):
    """Every decision node in `fn`, nested functions included, once each, in
    source order. Constants are skipped (forcing `True` to True mutates nothing),
    and so is everything inside an f-string: positions there differ between
    Python versions, and the ledger's keys must not."""
    inside_fstring = {id(c) for n in ast.walk(fn) if isinstance(n, ast.JoinedStr)
                      for c in ast.walk(n)}
    found = {}

    def add(node):
        if id(node) not in inside_fstring and not isinstance(node, ast.Constant):
            found.setdefault((node.lineno, node.col_offset,
                              node.end_lineno, node.end_col_offset), node)

    for n in ast.walk(fn):
        if isinstance(n, (ast.If, ast.While, ast.IfExp)):
            add(n.test)
        elif isinstance(n, ast.comprehension):
            for t in n.ifs:
                add(t)
        elif isinstance(n, ast.Compare):
            add(n)
        elif isinstance(n, ast.BoolOp):
            add(n)
            for v in n.values:
                add(v)
        elif isinstance(n, ast.UnaryOp) and isinstance(n.op, ast.Not):
            add(n)
    return [found[k] for k in sorted(found)]


def decision_mutants(rel, src, targets):
    """[(key, mutated_src)]: every decision in the verdict functions of the
    harness at `rel`, forced True and then False. A key names its decision by
    function, source line and expression — never by line NUMBER, so an edit
    elsewhere in the file does not orphan the ledger."""
    raw = src.encode("utf-8")
    starts = [0] + [i + 1 for i, b in enumerate(raw) if b == 0x0A]
    lines = src.split("\n")
    out, seen = [], {}
    for qual, fn in sorted(verdict_functions(src, targets).items()):
        for node in _decisions(fn):
            a = starts[node.lineno - 1] + node.col_offset
            z = starts[node.end_lineno - 1] + node.end_col_offset
            expr = " ".join(raw[a:z].decode("utf-8").split())
            line = lines[node.lineno - 1].strip()
            for to in ("True", "False"):
                base = (rel, qual, line, expr, to)
                n = seen.get(base, 0)
                seen[base] = n + 1
                key = {"file": rel, "func": qual, "line": line, "expr": expr, "to": to}
                if n:
                    key["n"] = n
                out.append((key, (raw[:a] + f"({to})".encode() + raw[z:]).decode("utf-8")))
    return out


def _key(entry):
    return tuple(entry.get(f, 0) if f == "n" else entry.get(f) for f in _KEY)


def load_ledger(kit_root):
    """{key: entry} from LEDGER. A missing file is an EMPTY ledger, which fails
    closed: every unpinned decision is then new. A malformed line, a missing or
    empty field, an unknown field or a duplicate is a hard error — a ledger that
    drops a line it cannot read has waived that line silently, and a misspelled
    field is a line it cannot read (LESSONS #060)."""
    path = os.path.join(kit_root, LEDGER)
    if not os.path.exists(path):
        return {}
    entries = {}
    for i, text in enumerate(open(path, encoding="utf-8"), 1):
        if not text.strip() or text.lstrip().startswith("#"):
            continue
        where = f"{LEDGER}:{i}"
        try:
            e = json.loads(text)
        except ValueError as ex:
            sys.exit(f"error: {where}: not a JSON object ({ex})")
        if not isinstance(e, dict):
            sys.exit(f"error: {where}: not a JSON object")
        unknown = sorted(set(e) - set(_KEY) - {"why"})
        if unknown:
            sys.exit(f"error: {where}: unknown field(s) {', '.join(unknown)} — "
                     f"fields are {', '.join(_KEY)} and why")
        empty = [f for f in ("file", "func", "line", "expr", "to", "why")
                 if not isinstance(e.get(f), str) or not e[f].strip()]
        if empty:
            sys.exit(f"error: {where}: missing or empty {', '.join(empty)} — an "
                     f"entry names its decision and says WHY it stays unpinned")
        if e["to"] not in ("True", "False"):
            sys.exit(f"error: {where}: `to` is {e['to']!r}, not True or False")
        if "n" in e and (type(e["n"]) is not int or e["n"] < 1):
            sys.exit(f"error: {where}: `n` must be an integer >= 1 when present")
        if _key(e) in entries:
            sys.exit(f"error: {where}: duplicate entry for one decision")
        entries[_key(e)] = e
    return entries


def sweep_decisions(kit_root, files, table, tmp, durations, workers=None,
                    min_timeout=10):
    """Mutate every decision in the verdict functions of `files` and run each
    harness's self-test(s) from `table` against it. Returns a list of
    (key, outcome), outcome in caught / hang / survived.

    Every mutant gets a FRESH copy of the kit, as every hand row does. Mutating
    one copy in place and restoring it lets whatever a mutant leaves behind — a
    file its self-test wrote, a cache — reach the next mutant, which then
    reports a kill it did not earn, and a real survivor behind it is masked
    (LESSONS #066: two hand-rolled drivers here did exactly that)."""
    jobs = []
    for rel in files:
        src = open(os.path.join(kit_root, rel), encoding="utf-8").read()
        rows = [m for m in table if m["file"] == rel]
        cmds = sorted({tuple(m["cmd"]) for m in rows})
        for key, mutated in decision_mutants(rel, src, [m["old"] for m in rows]):
            jobs.append((len(jobs), rel, cmds, key, mutated))
    if not jobs:
        return []

    def one(job):
        i, rel, cmds, key, mutated = job
        try:
            # A mutant can be valid and still draw a compile-time warning —
            # `((True))[2]` — which is noise here: the run decides its fate.
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                compile(mutated, rel, "exec")
        except SyntaxError as e:
            return key, f"syntax error: {e}"
        copy = os.path.join(tmp, f"decision-{i}")
        _copy_kit(kit_root, copy)
        try:
            open(os.path.join(copy, rel), "w", encoding="utf-8").write(mutated)
            for c in cmds:
                try:
                    rc, _out = _run(copy, list(c),
                                    timeout=max(min_timeout, 10 * durations[c]))
                except subprocess.TimeoutExpired:
                    return key, "hang"
                if rc != 0:
                    return key, "caught"
            return key, "survived"
        finally:
            shutil.rmtree(copy, ignore_errors=True)

    with ThreadPoolExecutor(max_workers=min(workers or os.cpu_count() or 1,
                                            len(jobs))) as ex:
        results = list(ex.map(one, jobs))
    broken = [(k, o) for k, o in results if o.startswith("syntax error")]
    if broken:
        k, o = broken[0]
        sys.exit(f"error: forcing `{k['expr']}` to {k['to']} in {k['file']} "
                 f"({k['func']}) does not compile: {o}. That is a bug in this "
                 f"harness's decision finder, not in the gate.")
    return results


def _run(kit_copy, cmd, timeout=300):
    # Dispatch by extension. This used to hardcode `sys.executable`, which meant
    # the sweep could only ever cover PYTHON gates — while still printing
    # "N gate(s) mutated, 0 survivor(s)", which reads as the whole gate set
    # (LESSONS #051). The kit's bash harnesses were structurally unreachable, and
    # one of them (`run_sanitizers.sh`) was shipping a mode that could never run.
    path = os.path.join(kit_copy, cmd[0])
    argv = ([sys.executable, path] if cmd[0].endswith(".py")
            else ["bash", path]) + cmd[1:]
    # Its own process group, killed whole on timeout: a mutant that hangs can
    # leave a grandchild holding the output pipe, and reading after killing
    # only the child would then wait on the grandchild — for ever, if it hangs.
    posix = os.name == "posix"
    p = subprocess.Popen(argv, cwd=kit_copy, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True,
                         start_new_session=posix)
    try:
        out, err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        if posix:
            os.killpg(p.pid, signal.SIGKILL)
        else:
            p.kill()
        p.communicate()
        raise
    return p.returncode, out + err


def run_gates(kit_root, mutations, as_json=False, check_coverage=True,
              table=None, decisions=True, decision_timeout=10):
    """Run the hand rows in `mutations`, then (unless `decisions` is false) the
    decision sweep over the Python harnesses they touch. `table` is where verdict
    functions are read from — the whole table even when `mutations` is a subset,
    so a partial run enumerates the same decisions a full one does."""
    kit_root = os.path.abspath(kit_root)
    table = mutations if table is None else table
    # A full sweep also audits the TABLE: a self-tested harness with no entry is
    # a gate this sweep silently does not cover (LESSONS #052). Skipped for
    # --only runs, which are deliberately partial.
    gaps = coverage_gaps(kit_root, mutations) if check_coverage else []
    files = sorted({m["file"] for m in mutations
                    if m["file"].endswith(".py")}) if decisions else []
    cmds = ({tuple(m["cmd"]) for m in mutations}
            | {tuple(m["cmd"]) for m in table if m["file"] in files})
    ledger = load_ledger(kit_root) if decisions else {}
    results, durations = [], {}
    with tempfile.TemporaryDirectory(prefix="gate-mutation-") as tmp:
        # Baseline: every self-test must be green UNMUTATED, or red can't be
        # attributed to the mutation.
        clean = os.path.join(tmp, "baseline")
        _copy_kit(kit_root, clean)
        for cmd in sorted(cmds):
            t0 = time.monotonic()
            rc, out = _run(clean, list(cmd))
            durations[cmd] = time.monotonic() - t0
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

        swept = sweep_decisions(kit_root, files, table, tmp, durations,
                                min_timeout=decision_timeout)

    # LESSONS #069: an unpinned decision passes only if the ledger names it, and
    # a ledger line passes only if it still names an unpinned decision. On a
    # partial run, lines for harnesses outside the run are not judged.
    unpinned = {_key(k): k for k, outcome in swept if outcome == "survived"}
    new = [k for key, k in unpinned.items() if key not in ledger]
    stale = [e for key, e in ledger.items() if key not in unpinned
             and (check_coverage or e["file"] in files)]
    survivors = [r for r in results if not r["caught"]]
    if as_json:
        print(json.dumps({"results": results,
                          "survivors": [r["gate"] for r in survivors],
                          "table_gaps": gaps,
                          "decisions": {"mutants": len(swept),
                                        "unpinned": len(unpinned),
                                        "new": new, "stale": stale}}, indent=2))
    else:
        for r in results:
            print(f"[{'CAUGHT  ' if r['caught'] else 'SURVIVED'}] {r['gate']:16} "
                  f"{r['why']}")
        print(f"\n{len(results)} gate(s) mutated, {len(survivors)} survivor(s)")
        if decisions:
            funcs = {(k["file"], k["func"]) for k, _ in swept}
            print(f"{len(swept)} decision mutant(s) in {len(funcs)} verdict "
                  f"function(s): {len(unpinned)} unpinned, {len(new)} new, "
                  f"{len(stale)} stale ledger entr(ies)")
        if new:
            print(f"\nUNPINNED: {len(new)} decision mutant(s) in a verdict function "
                  f"leave the self-test green (LESSONS #069). Add a fixture that "
                  f"fails under each, or a line in {LEDGER} with a non-empty "
                  f"\"why\" saying why it stays:")
            for k in new:
                print("  " + json.dumps(dict(k, why=""), ensure_ascii=False))
        if stale:
            print(f"\nSTALE: {len(stale)} line(s) in {LEDGER} no longer name an "
                  f"unpinned decision — it is pinned now, or the code moved. "
                  f"Delete them; the ledger only shrinks:")
            for e in stale:
                print("  " + json.dumps(e, ensure_ascii=False))
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
    return 1 if (survivors or gaps or new or stale) else 0


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

# LESSONS #069: a verdict function with five decisions. `x is None` and `x < 0`
# are pinned both ways (forcing `x is None` False CRASHES on None — caught, not
# survived); nothing exercises `strict`, so five of its mutants survive.
# `plumbing` holds no row and is never enumerated.
_TOY_VERDICT = '''\
#!/usr/bin/env python3
import sys

def verdict(x, strict=False):
    if x is None:
        return None
    if x < 0:
        return False
    if strict and x == 0:
        return False
    return True

def plumbing(x):
    return x > 100

def self_test():
    ok = verdict(1) is True and verdict(-1) is False and verdict(None) is None
    ok = ok and plumbing(5) is False
    print("self-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(self_test())
'''

# Every decision shape, once: a bare-name test, a comparison inside a call (the
# shape this kit's missed verdict had, LESSONS #064), a comprehension filter, a `not` on its own,
# one expression twice on a line — and three that are NOT decisions: a
# constant `while True`, a test inside an f-string, and a unary minus.
_TOY_SHAPES = '''\
class Gate:
    def check(self, flag, xs, a, b):
        if flag:
            pass
        found = any(a == b for b in xs)
        kept = [v for v in xs if v]
        label = f"{a if b else xs}"
        done, neg = not a, -a
        while True:
            break
        return flag or a < b or a < b
'''

_TOY_BASH = '''\
#!/usr/bin/env bash
x=1
if [[ $x -eq 1 ]]; then exit 0; fi
exit 1
'''

_TOY_LOOP = '''\
#!/usr/bin/env python3
import sys

def count(x):
    i = 0
    while i < x:
        i += 1
    return i

if __name__ == "__main__":
    sys.exit(0 if count(3) == 3 else 1)
'''

# Forcing `x > 5` True writes a file into the kit copy, and the self-test fails
# if it finds one. In a copy shared between mutants the NEXT mutant (`x > 5`
# forced False, which changes nothing) would find it and be reported caught.
_TOY_POLLUTE = '''\
#!/usr/bin/env python3
import os, sys

def verdict(x):
    if x > 5:
        open("POLLUTED", "w").close()
    return x > 0

if __name__ == "__main__":
    clean = not os.path.exists("POLLUTED")
    sys.exit(0 if clean and verdict(1) and not verdict(-1) else 1)
'''

# Forcing `x > 5` True makes the gate hang AND leave a grandchild holding its
# output pipe: killing only the child would wait out the grandchild's sleep.
_TOY_ORPHAN = '''\
#!/usr/bin/env python3
import subprocess, sys, time

def verdict(x):
    if x > 5:
        subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        time.sleep(60)
    return x > 0

if __name__ == "__main__":
    sys.exit(0 if verdict(1) and not verdict(-1) else 1)
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

        # a row whose mutation CRASHES the self-test proves crash detection,
        # not the verdict → hard error. Unpinned until LESSONS #069's sweep was
        # run over this file.
        crash = dict(base, old="    return x > 0", new="    return x.no_such_attr")
        check("a row whose mutation crashes the self-test is a hard error",
              exits(lambda: run_gates(kit, [crash], decisions=False)))

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
        # ...and the SWEEP acts on it. The checks above call coverage_gaps
        # directly; run over this file, LESSONS #069's decision sweep found that
        # dropping the gap from run_gates' exit code left them all green.
        open(gate, "w").write(_TOY_GATE)
        check("a full sweep FAILS on a table gap",
              run_gates(kit, [good]) == 1)
        check("a partial (--only) run does not audit the table",
              run_gates(kit, [good], check_coverage=False) == 0)

    # LESSONS #069: one row per verdict, enforced. Every decision in a verdict
    # function is mutated both ways; one the self-test misses fails the sweep
    # unless the ledger names it with a reason, and a ledger line that names
    # nothing unpinned fails it too.
    with tempfile.TemporaryDirectory() as root:
        kit = os.path.join(root, "kit")
        os.makedirs(os.path.join(kit, "harnesses", "toy"))
        os.makedirs(os.path.join(kit, "harnesses", "gate-mutation"))
        gate = os.path.join(kit, "harnesses", "toy", "verdict.py")
        ledger = os.path.join(kit, LEDGER)
        open(gate, "w").write(_TOY_VERDICT)
        row = {"gate": "toy-verdict", "file": "harnesses/toy/verdict.py",
               "cmd": ["harnesses/toy/verdict.py"], "why": "toy verdict",
               "old": "    if x < 0:", "new": "    if False:"}

        def outcomes(r, text, **kw):
            open(os.path.join(kit, r["file"]), "w").write(text)
            with tempfile.TemporaryDirectory() as tmp:
                got = sweep_decisions(kit, [r["file"]], [r], tmp,
                                      {tuple(r["cmd"]): 0.1}, **kw)
            return {(k["expr"], k["to"]): o for k, o in got}

        def write_ledger(entries, header="# toy ledger\n"):
            open(ledger, "w").write(header + "".join(
                json.dumps(e) + "\n" for e in entries))

        keys = [k for k, _ in decision_mutants(row["file"], _TOY_VERDICT, [row["old"]])]
        check("every decision in the verdict function is enumerated, both ways",
              len(keys) == 10 and {k["func"] for k in keys} == {"verdict"})
        check("a function holding no row is plumbing and is not enumerated",
              not any("100" in k["expr"] for k in keys))
        shapes = decision_mutants("t.py", _TOY_SHAPES, ["        if flag:"])
        check("every decision SHAPE is found, in a method; constants and "
              "f-strings are not; a repeat on one line is numbered",
              sorted((k["func"], k["expr"], k.get("n", 0)) for k, _ in shapes
                     if k["to"] == "True")
              == sorted(("Gate.check", e, n) for e, n in [
                  ("flag", 0), ("a == b", 0), ("v", 0), ("not a", 0), ("flag", 0),
                  ("flag or a < b or a < b", 0), ("a < b", 0), ("a < b", 1)]))

        got = outcomes(row, _TOY_VERDICT)
        strict = {("strict and x == 0", "False"), ("strict", "True"),
                  ("strict", "False"), ("x == 0", "True"), ("x == 0", "False")}
        check("the decisions no fixture exercises survive; the rest are caught",
              {k for k, o in got.items() if o == "survived"} == strict
              and all(o == "caught" for k, o in got.items() if k not in strict))
        check("a mutant that crashes the self-test is caught, not survived",
              got[("x is None", "False")] == "caught")

        check("an unpinned decision with no ledger line FAILS the sweep",
              run_gates(kit, [row]) == 1)
        entries = [dict(k, why="toy: no fixture passes strict") for k in keys
                   if (k["expr"], k["to"]) in strict]
        write_ledger(entries)
        check("the same decisions, each with a reason in the ledger, pass",
              run_gates(kit, [row]) == 0)

        open(gate, "w").write(_TOY_VERDICT.replace(
            "import sys\n", "import sys\n\n# moved\ndef unrelated():\n    return 1 < 2\n"))
        check("ledger keys survive an edit elsewhere in the file (no line numbers)",
              run_gates(kit, [row]) == 0)
        open(gate, "w").write(_TOY_VERDICT)

        pinned = next(k for k in keys if (k["expr"], k["to"]) == ("x < 0", "True"))
        write_ledger(entries + [dict(pinned, why="claims a pinned decision")])
        check("a ledger line naming a PINNED decision is stale and fails",
              run_gates(kit, [row]) == 1)
        write_ledger(entries + [dict(entries[0], expr="strict or x == 0")])
        check("a ledger line naming NO decision is stale and fails",
              run_gates(kit, [row]) == 1)

        write_ledger([dict(entries[0], why="")] + entries[1:])
        check("a ledger line with an empty reason is a hard error",
              exits(lambda: run_gates(kit, [row])))
        e0 = dict(entries[0])
        e0["reason"] = e0.pop("why")
        write_ledger([e0] + entries[1:])
        check("a misspelled field is a hard error, not a dropped line (LESSONS #060)",
              exits(lambda: run_gates(kit, [row])))
        write_ledger(entries + entries[:1])
        check("a duplicate ledger line is a hard error",
              exits(lambda: run_gates(kit, [row])))
        write_ledger(entries, header="# toy ledger\n{not json\n")
        check("a malformed ledger line is a hard error",
              exits(lambda: run_gates(kit, [row])))
        # Each validation alone, with every other field intact: a fixture that
        # breaks two things pins only their union (LESSONS #050).
        for label, bad in [
                ("an unknown field", dict(entries[0], note="x")),
                ("a non-string field", dict(entries[0], func=3)),
                ("a `to` other than True/False", dict(entries[0], to="Maybe")),
                ("an `n` below 1", dict(entries[0], n=0)),
                ("a non-integer `n`", dict(entries[0], n="1"))]:
            write_ledger([bad] + entries[1:])
            check(f"{label} alone is a hard error", exits(lambda: run_gates(kit, [row])))
        open(ledger, "w").write("# toy ledger\n[1, 2]\n")
        check("a JSON line that is not an object is a hard error",
              exits(lambda: run_gates(kit, [row])))
        write_ledger([dict(entries[0], n=1)])
        check("a valid occurrence number `n` is accepted",
              not exits(lambda: load_ledger(kit)))
        write_ledger(entries, header="# toy ledger\n\n   \n")
        check("blank lines and comments in the ledger are allowed",
              run_gates(kit, [row]) == 0)

        # Verdict functions come from the WHOLE table, so a partial run sees
        # the decisions a full one does: a second row makes `plumbing` a
        # verdict function, and its `x > 100` forced False goes unpinned.
        # (row2's command differs, so its baseline has to be timed too.)
        row2 = dict(row, gate="toy-plumbing", old="    return x > 100",
                    new="    return True", cmd=row["cmd"] + ["--again"])
        check("a partial run reads verdict functions from the whole table",
              run_gates(kit, [row], check_coverage=False, table=[row, row2]) == 1)
        write_ledger(entries + [dict(pinned, why="claims a pinned decision")])
        check("a partial run still judges ledger lines for the harnesses it ran",
              run_gates(kit, [row], check_coverage=False) == 1)
        write_ledger(entries)
        # A partial run judges ledger lines only for the harnesses it ran.
        open(os.path.join(kit, "harnesses", "toy", "gate.py"), "w").write(_TOY_GATE)
        other = {"gate": "toy", "file": "harnesses/toy/gate.py",
                 "cmd": ["harnesses/toy/gate.py"], "why": "toy verdict",
                 "old": "    return x > 0", "new": "    return True"}
        check("a partial run does not judge ledger lines for harnesses it skipped",
              run_gates(kit, [other], check_coverage=False) == 0)
        check("a full run judges every ledger line: one for an unswept harness is stale",
              run_gates(kit, [other]) == 1)

        open(ledger, "w").write("{not json\n")
        check("--rows-only runs no decision sweep and reads no ledger",
              run_gates(kit, [row], decisions=False) == 0)
        write_ledger(entries)
        bash = {"gate": "toy-bash", "file": "harnesses/toy/gate.sh",
                "cmd": ["harnesses/toy/gate.sh"], "why": "toy bash",
                "old": "x=1", "new": "x=2"}
        open(os.path.join(kit, bash["file"]), "w").write(_TOY_BASH)
        check("a bash harness's row runs; the decision sweep reads Python only",
              run_gates(kit, [row, bash]) == 0)

        fixed = _TOY_VERDICT.replace(
            "    ok = ok and plumbing(5) is False\n",
            "    ok = ok and plumbing(5) is False\n"
            "    ok = ok and verdict(0, True) is False and verdict(0) is True\n"
            "    ok = ok and verdict(1, True) is True\n")
        open(gate, "w").write(fixed)
        write_ledger(entries)
        check("once a fixture pins them, their ledger lines are stale and fail",
              run_gates(kit, [row]) == 1)
        write_ledger([])
        check("...and deleting those lines passes: the ledger only shrinks",
              run_gates(kit, [row]) == 0)

        loop = {"gate": "toy-loop", "file": "harnesses/toy/loop.py",
                "cmd": ["harnesses/toy/loop.py"], "why": "toy loop",
                "old": "        i += 1", "new": "        i += 2"}
        got = outcomes(loop, _TOY_LOOP, min_timeout=2)
        check("a mutant that HANGS the self-test is caught (as a hang), not survived",
              got.get(("i < x", "True")) == "hang"
              and got.get(("i < x", "False")) == "caught")
        pollute = {"gate": "toy-pollute", "file": "harnesses/toy/pollute.py",
                   "cmd": ["harnesses/toy/pollute.py"], "why": "toy pollute",
                   "old": "    return x > 0", "new": "    return True"}
        got = outcomes(pollute, _TOY_POLLUTE, workers=1)
        check("each mutant runs in a fresh copy: one that writes into the kit "
              "cannot make the next look caught",
              got.get(("x > 5", "True")) == "survived"
              and got.get(("x > 5", "False")) == "survived")
        orphan = {"gate": "toy-orphan", "file": "harnesses/toy/orphan.py",
                  "cmd": ["harnesses/toy/orphan.py"], "why": "toy orphan",
                  "old": "    return x > 0", "new": "    return True"}
        t0 = time.monotonic()
        got = outcomes(orphan, _TOY_ORPHAN, min_timeout=2)
        check("a hang's grandchild is killed with it: the sweep does not wait it out",
              got.get(("x > 5", "True")) == "hang" and time.monotonic() - t0 < 30)

    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("kit_root", nargs="?", help="kit checkout to mutate (a scratch copy is used)")
    ap.add_argument("--only", help="comma-separated gate names to run (default: all)")
    ap.add_argument("--rows-only", action="store_true",
                    help="run the hand rows only, not the decision sweep (a quick "
                         "check of one row; `make check-kit` never passes this)")
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
                     check_coverage=not args.only, table=MUTATIONS,
                     decisions=not args.rows_only)


if __name__ == "__main__":
    sys.exit(main())
