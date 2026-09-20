#!/usr/bin/env python3
# KIT-IMPORT: from the c2rust-port lineage of this kit.
# Re-cited: #6->#036.
"""Threat-model gate — a port must not reach cutover with an UNFILLED threat
model. Hard-fails (exit 1) on leftover placeholders or a missing required
section.

Why this exists (the source lineage's kit audit, §6 item 2): `skeleton/THREAT-MODEL.md`
ships as a template whose first line is `# Threat model — <project>`. Phase 0 says
to fill it in — it is what tells the port loop which modules touch untrusted input
(fuzz those first) and which cross a privilege boundary (audit those hardest) — but
NOTHING checked. A port could copy the skeleton, never touch the file, and clear
every gate with `<project>` still in it: the threat model was documentation theater.

Two modes, because the kit's own copy is legitimately still a template:
  * default (FILLED)   — for a real port's THREAT-MODEL.md. Required sections must
                         be present AND no placeholder may remain.
  * --template         — for the shipped blank. Structure only: required sections
                         must be present, placeholders are expected. This is what
                         `make check-kit` runs against `skeleton/THREAT-MODEL.md`,
                         so template rot (a deleted section) still fails.

Fail-closed (LESSONS #036): a missing file, an unreadable file, or an empty one is a
FAILURE, not a skip — "no threat model" is the exact state this gate exists to
catch. Required sections are enforced in BOTH modes so a port cannot dodge the
placeholder check by deleting the section that still had placeholders in it.

Usage:
  check_threat_model.py PATH [--template] [--quiet]
  check_threat_model.py --self-test
Exit: 0 = filled (or a structurally valid template); 1 = unfilled/missing; 2 = usage.
"""
from __future__ import annotations

import argparse
import os
import re
import sys

# Required sections, matched case-insensitively against the file's headings. Keyed
# on wording, not on the `## N.` numbering, so a port may renumber or retitle
# around the same required content.
REQUIRED_SECTIONS = [
    ("assets", re.compile(r"asset", re.I)),
    ("trust boundaries", re.compile(r"trust\s+boundar", re.I)),
    ("privilege transitions", re.compile(r"privilege", re.I)),
    ("attacker capabilities", re.compile(r"attacker", re.I)),
    ("non-goals", re.compile(r"non-?goal", re.I)),
    ("C-defect inventory", re.compile(r"c-?defect|flaw\s+inventory", re.I)),
]

# Unambiguous "not filled in" markers.
_TODO_RE = re.compile(r"\b(TODO|FIXME|XXX|TBD)\b|\bFILL (THIS )?IN\b", re.I)
# `<project>`-style angle-bracket placeholders. Excludes HTML tags and autolinked
# URLs (`<https://…>`), which are legitimate markdown.
_ANGLE_RE = re.compile(r"<(?!/)(?!https?:)(?!br\b)(?!hr\b)(?!img\b)(?!a\s)"
                       r"([A-Za-z][A-Za-z0-9 _./|-]{0,40})>")
# A bullet that is still the template's own `- e.g. …` guidance: the instruction is
# to REPLACE these with the port's real content. (Prose may still say "e.g."
# mid-sentence; only a bullet that *starts* with it is flagged.)
_EG_BULLET_RE = re.compile(r"^\s*[-*]\s*e\.g\.", re.I)

MIN_CHARS = 200  # a stub shorter than this is not a threat model


def find_placeholders(text: str):
    """Yield (line_no, kind, snippet) for each leftover-placeholder signal."""
    for i, line in enumerate(text.splitlines(), 1):
        for m in _TODO_RE.finditer(line):
            yield (i, "todo-marker", m.group(0))
        for m in _ANGLE_RE.finditer(line):
            yield (i, "placeholder", m.group(0))
        if _EG_BULLET_RE.match(line):
            yield (i, "example-bullet", line.strip()[:60])


def missing_sections(text: str):
    """Required sections with no matching heading in the document."""
    headings = [ln for ln in text.splitlines() if ln.lstrip().startswith("#")]
    blob = "\n".join(headings)
    return [name for name, rx in REQUIRED_SECTIONS if not rx.search(blob)]


def check(path: str, template_mode: bool, quiet: bool = False) -> int:
    if not os.path.isfile(path):
        print(f"FAIL  no threat model at {path!r} — Phase 0 requires one "
              f"(copy skeleton/THREAT-MODEL.md and fill it in)", file=sys.stderr)
        return 1
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
    except OSError as e:
        print(f"FAIL  cannot read {path!r}: {e}", file=sys.stderr)
        return 1

    problems = []
    if len(text.strip()) < MIN_CHARS:
        problems.append(f"{path}: only {len(text.strip())} chars — a stub, not a "
                        f"threat model (expected >= {MIN_CHARS})")

    for name in missing_sections(text):
        problems.append(f"{path}: missing required section: {name}")

    if not template_mode:
        for line_no, kind, snip in find_placeholders(text):
            problems.append(f"{path}:{line_no}: unfilled {kind}: {snip}")

    if problems:
        for p in problems:
            print("FAIL  " + p, file=sys.stderr)
        if not template_mode:
            print("\nThe threat model drives the port loop: trust boundaries pick the "
                  "fuzz targets, privilege transitions pick the audit hotspots. Fill it "
                  "in (replace every <placeholder> and `- e.g.` bullet) before cutover.",
                  file=sys.stderr)
        return 1
    if not quiet:
        what = "valid template" if template_mode else "filled in"
        print(f"PASS  threat model {what}: {path}")
    return 0


_FILLED = """# Threat model - portlib

## 1. Assets
- the integrity of the host we run on; the confidentiality of parsed documents.

## 2. Trust boundaries
| Entry point | Source | Trust | Ported module |
|---|---|---|---|
| stdin document | pipe | untrusted | `port_core::parser` |

## 3. Privilege transitions
None: the tool never elevates and drops CAP_NET_RAW at startup.

## 4. Attacker capabilities we defend against
- Arbitrary bytes on stdin (no panic/UB: fuzz gate covers `parser`).

## 5. Explicit non-goals
- No side-channel resistance; a malicious operator is out of scope.

## 6. C-defect inventory
reports/scan_c_flaws.json - 3 confirmed, all ledgered in DIVERGENCES.md.
"""


def _self_test() -> int:
    import contextlib
    import io
    import tempfile
    ok = True

    def chk(name, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + f"  {name}")
        ok = ok and cond

    def rc(path, template_mode):
        """check() with the fixture's own diagnostics swallowed — the fixtures are
        *supposed* to fail, and their FAIL lines would drown out check-kit."""
        with contextlib.redirect_stderr(io.StringIO()):
            return check(path, template_mode, quiet=True)

    here = os.path.dirname(os.path.abspath(__file__))
    shipped = os.path.join(here, "..", "..", "skeleton", "THREAT-MODEL.md")

    with tempfile.TemporaryDirectory() as d:
        filled = os.path.join(d, "FILLED.md")
        open(filled, "w").write(_FILLED)
        chk("a filled-in threat model passes", rc(filled, False) == 0)

        # The shipped template must FAIL the filled check (it has <project> and
        # `- e.g.` bullets) and PASS the structural template check.
        if os.path.isfile(shipped):
            chk("the shipped template FAILS the filled check",
                rc(shipped, False) == 1)
            chk("the shipped template PASSES the --template structure check",
                rc(shipped, True) == 0)

        # Fail closed: a missing file is a FAILURE, not a skip.
        chk("a missing threat model FAILS (fail closed, never skip)",
            rc(os.path.join(d, "nope.md"), False) == 1)
        stub = os.path.join(d, "stub.md")
        open(stub, "w").write("# Threat model\n\nTODO\n")
        chk("a stub threat model FAILS", rc(stub, False) == 1)

        # A leftover <placeholder> must be caught even when everything else is filled.
        ph = os.path.join(d, "ph.md")
        open(ph, "w").write(_FILLED.replace("portlib", "<project>"))
        chk("a leftover <placeholder> is caught", rc(ph, False) == 1)

        # A leftover TODO must be caught.
        td = os.path.join(d, "td.md")
        open(td, "w").write(_FILLED + "\nTODO: finish section 3\n")
        chk("a leftover TODO is caught", rc(td, False) == 1)

        # A still-unreplaced `- e.g.` guidance bullet is caught...
        eg = os.path.join(d, "eg.md")
        open(eg, "w").write(_FILLED.replace(
            "- the integrity of the host we run on; the confidentiality of parsed documents.",
            "- e.g. the integrity of the host we run on."))
        chk("an unreplaced `- e.g.` guidance bullet is caught",
            rc(eg, False) == 1)
        # ...but prose using "e.g." mid-sentence is fine (no false alarm).
        prose = os.path.join(d, "prose.md")
        open(prose, "w").write(_FILLED.replace(
            "None: the tool never elevates",
            "None (e.g. no setuid path): the tool never elevates"))
        chk("mid-sentence \"e.g.\" is NOT a false alarm",
            rc(prose, False) == 0)

        # You cannot dodge the placeholder check by DELETING the section that had
        # them — required sections are enforced in both modes.
        cut = os.path.join(d, "cut.md")
        open(cut, "w").write(_FILLED.split("## 3.")[0])
        chk("deleting a required section FAILS (can't dodge by removal)",
            rc(cut, False) == 1)
        chk("deleting a required section FAILS in --template mode too",
            rc(cut, True) == 1)

        # A markdown autolink / HTML tag is not a placeholder.
        html = os.path.join(d, "html.md")
        open(html, "w").write(_FILLED + "\nSee <https://example.com/threats> and a<br>b\n")
        chk("autolinks and <br> are not placeholders",
            rc(html, False) == 0)

    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", nargs="?", help="THREAT-MODEL.md to check")
    ap.add_argument("--template", action="store_true",
                    help="structure-only check for the shipped blank (placeholders allowed)")
    ap.add_argument("--quiet", action="store_true", help="suppress the PASS line")
    ap.add_argument("--self-test", action="store_true", help="run the built-in fixture test")
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()
    if not args.path:
        ap.print_usage(sys.stderr)
        print("error: give a PATH to a threat model, or --self-test", file=sys.stderr)
        return 2
    return check(args.path, args.template, args.quiet)


if __name__ == "__main__":
    sys.exit(main())
