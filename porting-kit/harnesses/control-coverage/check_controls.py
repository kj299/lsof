#!/usr/bin/env python3
# KIT-IMPORT: from the c2rust-port lineage of this kit.
# Re-cited: #18->#039, #25->#052; #31 by title (no entry in this log).
"""Control-coverage — the gate above the gates: every control the kit DECLARES
must actually be INVOKED by the port's gate script.

Why — the source lineage's lesson "A declared control nothing invokes is
indistinguishable from one that always passes", which has no entry in this
log: that kit had two independent guarantees and a hole between
them. `mutate_gates.py` proves each gate *detects and refuses* (its self-test
goes red when the verdict is neutralized), and `probe.py coverage` proves every
tracked module *has probes*. Neither asks the prior question: **is this control
run against the port at all?** At the cJSON port's cutover, three of the six
script-backed controls in `CLAUDE.md`'s table — `supply-chain`, `c-flaw-scan`
and `threat-model`, two of them marked "hard fail" — were never invoked by
`ports/cjson/check.sh`. All three passed the mutation sweep, because a sweep
measures a harness's self-test, not its use. The control table was prose, and no
gate read it. A control that never runs is indistinguishable from one that
always passes (LESSONS #039's 0-of-0 shape, lifted to the whole control set).

Mechanics (deliberately conservative, format-driven):
  * Read the controls doc (default `CLAUDE.md`) and take only MARKDOWN TABLE
    ROWS (lines starting with `|`) — the declared gate table, not prose that
    happens to mention a path.
  * From those rows extract runnable harness scripts: `harnesses/<...>.py|.sh`.
    A control naming a directory rather than a script (e.g. `harnesses/fuzz/`
    for cargo-fuzz) names no command to grep for and is reported as UNCHECKABLE,
    counted and listed, never silently dropped.
  * Require each extracted script to appear in at least one gate file's text.
  * Exemptions must be written down: `# control-coverage: exempt <path> -- <why>`
    in a gate file records a deliberate non-use with its reason.

A gate file that does not exist is an error, not a skip: pointing the check at a
missing script is exactly how this would quietly pass.

Usage:
  check_controls.py --gate PORT/check.sh [--gate ...] [--controls CLAUDE.md] [--json]
  check_controls.py --self-test
Exit: 0 = every declared control is invoked (or exempted); 1 = one is not.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ledgers"))
from check_ledgers import executable_text  # noqa: E402

# Only table rows count as declarations (see module docstring).
TABLE_ROW = re.compile(r"^\s*\|")
# A runnable control: a harness script with an extension we can grep a gate for.
CONTROL_RE = re.compile(r"harnesses/[A-Za-z0-9_./-]+\.(?:py|sh)\b")
# A control naming a bare harness directory — declared but not a command.
DIRONLY_RE = re.compile(r"harnesses/[A-Za-z0-9_-]+/(?![A-Za-z0-9_.-]*\.(?:py|sh)\b)")
EXEMPT_RE = re.compile(r"control-coverage:\s*exempt\s+(\S+)\s*--\s*(.+)")


def declared_controls(controls_path):
    """(runnable, dir_only) control paths declared in the doc's gate table."""
    with open(controls_path, encoding="utf-8") as fh:
        rows = [ln for ln in fh if TABLE_ROW.match(ln)]
    runnable, dir_only = [], []
    for row in rows:
        found = CONTROL_RE.findall(row)
        for m in CONTROL_RE.finditer(row):
            if m.group(0) not in runnable:
                runnable.append(m.group(0))
        if not found:
            for m in DIRONLY_RE.finditer(row):
                if m.group(0) not in dir_only:
                    dir_only.append(m.group(0))
    return runnable, dir_only


def control_is_wired(control, gate_texts):
    """THE VERDICT (kept as one predicate so gate-mutation can neutralize it and
    the self-test's negative fixture must then go red — LESSONS #052).

    The search runs over `executable_text` — the parts of a gate file that
    CONFIGURE OR RUN something — not the raw bytes. Searching raw text answers a
    different question, "does this file say the word", and the two came apart
    here immediately: the first run of this harness in this kit reported
    `run_sanitizers.sh` and `run_supply_chain.sh` as RUN because the *exemption
    comments explaining that they are not run* mention their paths. A comment
    certified the job it was documenting the absence of.

    This kit had already solved that for the ledgers check, so the fix is to
    import its `executable_text` rather than write a second comment-stripper to
    get wrong the same way."""
    base = os.path.basename(control)
    return any((control in executable_text(text)) or (base in executable_text(text))
               for text in gate_texts)


def exemptions(gate_texts):
    """Exemptions are read from the RAW text, deliberately: an exemption IS a
    comment. Only the wiring verdict above is restricted to executable text."""
    out = {}
    for text in gate_texts:
        for m in EXEMPT_RE.finditer(text):
            out[m.group(1)] = m.group(2).strip()
    return out


def check(controls_path, gate_paths, as_json=False):
    if not os.path.isfile(controls_path):
        print(f"error: controls doc not found: {controls_path}", file=sys.stderr)
        return 2
    missing_gates = [g for g in gate_paths if not os.path.isfile(g)]
    if missing_gates:
        # Fail closed: a gate file that isn't there cannot be shown to run anything.
        for g in missing_gates:
            print(f"error: gate script not found: {g}", file=sys.stderr)
        return 2

    texts = []
    for g in gate_paths:
        with open(g, encoding="utf-8") as fh:
            texts.append(fh.read())

    runnable, dir_only = declared_controls(controls_path)
    if not runnable:
        # 0-of-0 proves nothing and must not pass (LESSONS #039).
        print(f"error: no runnable controls found in {controls_path}'s table — "
              "a coverage check over zero controls proves nothing",
              file=sys.stderr)
        return 2

    exempt = exemptions(texts)
    wired, unwired, skipped = [], [], []
    for c in runnable:
        if control_is_wired(c, texts):
            wired.append(c)
        elif c in exempt:
            skipped.append((c, exempt[c]))
        else:
            unwired.append(c)

    if as_json:
        json.dump({"tool": "control-coverage", "controls": runnable,
                   "wired": wired, "unwired": unwired,
                   "exempt": [{"control": c, "why": w} for c, w in skipped],
                   "uncheckable": dir_only,
                   "gates": gate_paths, "ok": not unwired}, sys.stdout, indent=1)
        print()
    else:
        for c in wired:
            print(f"  RUN      {c}")
        for c, why in skipped:
            print(f"  EXEMPT   {c}  ({why})")
        for c in unwired:
            print(f"  NOT RUN  {c}", file=sys.stderr)
        for d in dir_only:
            print(f"  (uncheckable, names no script: {d})")
        if unwired:
            print(f"\ncontrol-coverage FAILED: {len(unwired)} declared control(s) "
                  f"never invoked by {', '.join(gate_paths)}.\n"
                  "A control that never runs cannot be told from one that always "
                  "passes. Wire it into the gate, or record\n"
                  "  # control-coverage: exempt <path> -- <why>\n"
                  "in the gate with the reason.", file=sys.stderr)
        else:
            print(f"\ncontrol coverage: {len(wired)} control(s) invoked, "
                  f"{len(skipped)} exempted, {len(dir_only)} uncheckable")
    return 1 if unwired else 0


def _self_test():
    import tempfile
    ok = True

    def check_case(label, cond):
        nonlocal ok
        print(f"{'PASS' if cond else 'FAIL'}  {label}")
        ok = ok and cond

    with tempfile.TemporaryDirectory() as d:
        controls = os.path.join(d, "CLAUDE.md")
        with open(controls, "w", encoding="utf-8") as fh:
            fh.write("prose mentioning harnesses/notatable/ignored.py must not count\n\n"
                     "| Control | Command |\n|---|---|\n"
                     "| a | `harnesses/alpha/a.py` |\n"
                     "| b | `harnesses/beta/b.sh` |\n"
                     "| c | `harnesses/fuzz/` (cargo-fuzz) |\n")

        runnable, dir_only = declared_controls(controls)
        check_case("table rows parsed, prose ignored",
                   runnable == ["harnesses/alpha/a.py", "harnesses/beta/b.sh"])
        check_case("a directory-only control is reported, not dropped",
                   dir_only == ["harnesses/fuzz/"])

        full = os.path.join(d, "full.sh")
        with open(full, "w", encoding="utf-8") as fh:
            fh.write("python3 harnesses/alpha/a.py\nbash harnesses/beta/b.sh\n")
        check_case("a gate running every control passes", check(controls, [full]) == 0)

        # NEGATIVE FIXTURE: the failure this gate exists to catch.
        partial = os.path.join(d, "partial.sh")
        with open(partial, "w", encoding="utf-8") as fh:
            fh.write("python3 harnesses/alpha/a.py\n")
        check_case("a gate MISSING a control fails", check(controls, [partial]) == 1)

        # the crown verdict must be what decides it (gate-mutation target)
        check_case("verdict predicate refuses an unwired control",
                   control_is_wired("harnesses/beta/b.sh", ["python3 harnesses/alpha/a.py"]) is False)

        exempted = os.path.join(d, "exempt.sh")
        with open(exempted, "w", encoding="utf-8") as fh:
            fh.write("python3 harnesses/alpha/a.py\n"
                     "# control-coverage: exempt harnesses/beta/b.sh -- no deps to audit\n")
        check_case("a written-down exemption passes", check(controls, [exempted]) == 0)

        # 0-of-0 must not pass (LESSONS #039)
        empty = os.path.join(d, "empty.md")
        with open(empty, "w", encoding="utf-8") as fh:
            fh.write("no table here\n")
        check_case("a controls doc with no table fails (0-of-0)",
                   check(empty, [full]) == 2)

        # a missing gate file is an error, not a silent pass
        check_case("a missing gate script fails closed",
                   check(controls, [os.path.join(d, "nope.sh")]) == 2)

    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--controls", default="CLAUDE.md")
    ap.add_argument("--gate", action="append", default=[])
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return _self_test()
    if not a.gate:
        print("error: give at least one --gate, or --self-test", file=sys.stderr)
        return 2
    return check(a.controls, a.gate, a.json)


if __name__ == "__main__":
    sys.exit(main())
