#!/usr/bin/env python3
# KIT-IMPORT: from the c2rust-port lineage of this kit.
# Re-cited: #7 by title (no entry in this log).
"""Doc-flag drift check — every flag the docs attribute to a kit harness must
exist in that harness's source. Documented commands are code: they get pasted.

Why this exists — the source lineage's lesson "Documented commands are code —
phantom flags and paste-broken examples drift silently", which has no entry in
this log: that kit's full-code-review pass found the docs
promising behavior the tools didn't have — a `--update-ledger` flag diff_run.py
never implemented, an `unchecked-malloc` scan category that could never fire, a
`progress.py ... --file` order argparse rejected, and a smoke-test command
(`make -C porting-kit check-kit`) that failed in the kit's own repo. The skills
suite already has a mechanical path-integrity check (`skills/check_skills.py`);
this is the same idea for *flags in the operative docs*: prose claims about tool
CLIs hard-fail when they drift, instead of waiting for a user to paste them.

Mechanics (deliberately conservative, line-based):
  * Scan the OPERATIVE docs only — the paste-able surface. Historical/report
    documents (LESSONS.md, RETROSPECTIVE-*.md, CODE-REVIEW*.md) legitimately
    quote flags that no longer exist and are excluded.
  * The mirror case is NOT excluded and deliberately so: forward-looking text —
    a backlog item proposing `--holdout` for a harness that has no such flag —
    is caught, because "proposed" is a word anyone can type and an exclusion for
    it would silence real drift. Write such an item with the script name and the
    flag on SEPARATE LINES; the attribution is per-line, so a proposal stops
    reading as a claim without the checker having to guess intent. This found
    exactly one such line in this kit on its first run (OPERATING-GUIDE §5 P0.3).
  * On each line, every `--flag` token is attributed to the NEAREST PRECEDING
    harness-script name on that same line; flags with no preceding script on
    the line are ignored (they may belong to cargo, clippy, etc.).
  * A documented flag "exists" if it appears as a literal token in the script's
    source (argparse add_argument / shell case arm). Wrapped multi-line
    commands are therefore only partially checked — misses are possible,
    phantom-flag false alarms are not.

Usage:  check_doc_flags.py [KIT_ROOT]   (defaults to this file's ../../)
        check_doc_flags.py --self-test
Exit: 0 = no drift; 1 = a documented flag is missing from its script.
"""
from __future__ import annotations

import os
import re
import sys

# The paste-able docs. Extend when a new operative doc joins the kit.
OPERATIVE_DOCS = [
    "README.md",
    "CLAUDE.md",
    "PLAYBOOK.md",
    "OPERATING-GUIDE.md",
    "SECURITY-CHECKLIST.md",
    "ARCHITECTURE-TEMPLATE.md",
    "PROMPTS",
    "skills",
    "skeleton",
]

SCRIPT_RE = re.compile(r"\b([A-Za-z0-9_-]+\.(?:py|sh))\b")
FLAG_RE = re.compile(r"(?<![\w-])(--[a-z][a-z0-9-]*)(?![\w-])")


def _find_scripts(kit_root):
    """Map script basename -> source path for every kit harness/script."""
    scripts = {}
    for sub in ("harnesses", "scripts", "skills"):
        top = os.path.join(kit_root, sub)
        for root, _dirs, files in os.walk(top) if os.path.isdir(top) else []:
            for f in files:
                if f.endswith((".py", ".sh")):
                    scripts[f] = os.path.join(root, f)
    return scripts


def _iter_doc_files(kit_root):
    for entry in OPERATIVE_DOCS:
        p = os.path.join(kit_root, entry)
        if os.path.isfile(p):
            yield p
        elif os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                for f in files:
                    if f.endswith(".md"):
                        yield os.path.join(root, f)


def _doc_claims(line, known_scripts):
    """Yield (script_basename, flag) for each flag on the line, attributed to
    the nearest preceding known script name on the same line."""
    marks = []  # (position, kind, value)
    for m in SCRIPT_RE.finditer(line):
        if m.group(1) in known_scripts:
            marks.append((m.start(), "script", m.group(1)))
    for m in FLAG_RE.finditer(line):
        marks.append((m.start(), "flag", m.group(1)))
    marks.sort()
    current = None
    for _pos, kind, value in marks:
        if kind == "script":
            current = value
        elif current is not None:
            yield current, value


def run(kit_root):
    scripts = _find_scripts(kit_root)
    sources = {}
    problems, checked = [], 0
    for doc in sorted(_iter_doc_files(kit_root)):
        rel = os.path.relpath(doc, kit_root)
        for lineno, line in enumerate(open(doc, encoding="utf-8"), 1):
            for script, flag in _doc_claims(line, scripts):
                checked += 1
                if script not in sources:
                    sources[script] = open(scripts[script], encoding="utf-8").read()
                if not re.search(r"(?<![\w-])" + re.escape(flag) + r"(?![\w-])",
                                 sources[script]):
                    problems.append(f"{rel}:{lineno}: documents `{script} ... {flag}` "
                                    f"but {flag} does not exist in {script}")
    for p in problems:
        print("DRIFT: " + p)
    print(f"{checked} documented flag reference(s) checked, {len(problems)} drifted")
    return 1 if problems else 0


def _self_test():
    import tempfile
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + f"  {name}")
        ok = ok and cond

    with tempfile.TemporaryDirectory() as root:
        os.makedirs(os.path.join(root, "harnesses", "x"))
        open(os.path.join(root, "harnesses", "x", "tool.py"), "w").write(
            'ap.add_argument("--real-flag", action="store_true")\n')
        # good doc: real flag; a flag with no preceding script must be ignored
        open(os.path.join(root, "README.md"), "w").write(
            "run `tool.py --real-flag`\nand cargo with --unrelated-flag\n")
        check("documented real flag passes", run(root) == 0)
        # phantom flag drifts
        with open(os.path.join(root, "README.md"), "a") as f:
            f.write("also try `tool.py --phantom-flag` for fun\n")
        check("documented phantom flag is caught", run(root) == 1)
        # nearest-preceding-script attribution: the phantom belongs to other.py
        open(os.path.join(root, "harnesses", "x", "other.py"), "w").write(
            'ap.add_argument("--other-flag")\n')
        open(os.path.join(root, "README.md"), "w").write(
            "`tool.py --real-flag` then `other.py --other-flag`\n")
        check("per-script attribution on one line", run(root) == 0)
    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "--self-test":
        return _self_test()
    here = os.path.dirname(os.path.abspath(__file__))
    kit_root = argv[0] if argv else os.path.dirname(os.path.dirname(here))
    return run(kit_root)


if __name__ == "__main__":
    sys.exit(main())
