#!/usr/bin/env python3
"""Matrix-coverage gate — "green on the matrix" is a statement about the matrix,
not the port (LESSONS #8). This tool makes the matrix's completeness a *gate*:
it diffs the C's enumerated feature surface (option letters, emitted TYPE codes)
against the differential input matrix's cases and hard-fails on any feature no
case exercises.

The winlsof failure this prevents: the socket differential was fully green while
the port silently dropped every non-File kernel object type — no fixture ever
created a registry Key/Event/Mutant, so the gap was invisible to *both* sides of
the diff (a false MATCH, never a divergence). A green differential over a matrix
that omits a feature class says nothing about that class; this gate says it out
loud and exits 1.

Three layers:
  1. `--extract-options FILE.c ...` / `--extract-types FILE.c ...` — bootstrap
     the feature inventory from the C itself (best-effort scanners, validated
     against lsof: the getopt/snpf-built optstring union in src/main.c and the
     `snpf(buf, buf_len, "REG")` TYPE literals in lib/print.c). Add
     `--emit-inventory` to print a ready-to-curate TOML skeleton.
  2. The **inventory** (TOML/JSON) — the curated contract. `[features]` lists
     `options` (letters) and `types` (TYPE codes); `[[waive]]` entries document
     features deliberately out of the port's scope, each with a `reason`
     (a waiver without a reason is a silent drop with paperwork).
  3. The **gate**: `--inventory INV --matrix MATRIX` computes covered features —
     option letters inferred from each case's `args` (short-option clusters like
     `-nP` count both) plus each case's explicit `covers = ["type:KEY", ...]`
     list (TYPE coverage comes from *fixtures*, which no flag spells, so it must
     be declared) — and fails on `required - waived - covered`.

Usage:
  coverage_gate.py --inventory INV.toml --matrix MATRIX.toml [--warn] [--json]
  coverage_gate.py --extract-options FILE.c [...] [--emit-inventory]
  coverage_gate.py --extract-types FILE.c [...]   [--emit-inventory]
  coverage_gate.py --self-test

Exit: 0 = every non-waived feature covered (or --warn); 1 = uncovered features;
2 = usage/infra error (unreadable/unparseable inputs — never confused with 1,
per the three-way exit contract of LESSONS #6).
"""
from __future__ import annotations

import argparse
import json
import re
import sys

# ---------------------------------------------------------------- C extraction


def _strip_c_comments(src: str) -> str:
    """Remove // and /* */ comments, preserving string literals and newlines."""
    out = []
    i, n = 0, len(src)
    while i < n:
        two = src[i : i + 2]
        if two == "//":
            while i < n and src[i] != "\n":
                i += 1
            continue
        if two == "/*":
            i += 2
            while i < n and src[i : i + 2] != "*/":
                if src[i] == "\n":
                    out.append("\n")
                i += 1
            i += 2
            continue
        if src[i] == '"':
            out.append('"')
            i += 1
            while i < n and src[i] != '"':
                if src[i] == "\\" and i + 1 < n:
                    out.append(src[i : i + 2])
                    i += 2
                    continue
                out.append(src[i])
                i += 1
            if i < n:
                out.append('"')
                i += 1
            continue
        out.append(src[i])
        i += 1
    return "".join(out)


_STR_LIT = re.compile(r'"((?:[^"\\]|\\.)*)"')


def _call_span(src: str, start: int) -> str:
    """The full text of a call starting at the `(` at/after `start`, matching
    parens to depth 0. Returns "" if unbalanced."""
    i = src.find("(", start)
    if i < 0:
        return ""
    depth = 0
    for j in range(i, len(src)):
        if src[j] == "(":
            depth += 1
        elif src[j] == ")":
            depth -= 1
            if depth == 0:
                return src[i : j + 1]
    return ""


def _optstring_letters(fragment: str) -> tuple[set[str], set[str]]:
    """(all letters, value-taking letters) in a getopt-rules fragment.
    'c:' -> ({'c'}, {'c'}); 'ab' -> ({'a','b'}, set()). Format holes (%s), '?'
    and other punctuation are ignored. Knowing which options take a value is
    what stops `-iTCP:80` from being miscounted as the options i, T, C and P."""
    letters, takes = set(), set()
    frag = fragment.replace("%s", "")
    for i, ch in enumerate(frag):
        if not ch.isalnum():
            continue
        letters.add(ch)
        if i + 1 < len(frag) and frag[i + 1] == ":":
            takes.add(ch)
    return letters, takes


def extract_options(files) -> tuple[set[str], set[str]]:
    """(option letters, value-taking letters) any build of the C can accept.

    Handles two idioms: a direct string literal passed to getopt()/GetOpt(),
    and lsof's snpf-built rules string — a format literal full of `x:` pairs
    plus per-#if fragment literals as later arguments; all branches of every
    #if appear as literals inside the one call, so scanning the whole call
    text yields the superset across build configurations (which is exactly
    what a port-completeness inventory wants)."""
    letters: set[str] = set()
    takes: set[str] = set()

    def absorb(lit: str) -> None:
        l, t = _optstring_letters(lit)
        letters.update(l)
        takes.update(t)

    for path in files:
        src = _strip_c_comments(open(path, encoding="utf-8", errors="replace").read())
        # direct: getopt(argc, argv, "ab:c")  /  GetOpt(ctx, ct, opt, "ab:c", ...)
        for m in re.finditer(r"\b(?:getopt|getopt_long|GetOpt)\s*", src):
            call = _call_span(src, m.end())
            for lit in _STR_LIT.findall(call):
                if re.search(r"[A-Za-z]:", lit):
                    absorb(lit)
        # built: snpf(options, sizeof(options), "?a%sbc:...", "A:", "", ...)
        for m in re.finditer(r"\bsnpf?f?\s*\(|\bsnprintf\s*\(|\bsnpf\s*\(", src):
            call = _call_span(src, m.start())
            lits = _STR_LIT.findall(call)
            if not lits:
                continue
            # An optstring format has several `x:` option markers.
            if len(re.findall(r"[A-Za-z]:", lits[0])) >= 3:
                for lit in lits:
                    absorb(lit)
    return letters, takes


def extract_types(files) -> set[str]:
    """TYPE-code literals the C can emit, from the print_file_type idiom:
    `snpf(buf, buf_len, "REG")` — two identifiers then a %-free literal."""
    types: set[str] = set()
    pat = re.compile(r"\bsnpf?\s*\(\s*\w+\s*,\s*\w+\s*,\s*\"([^\"%]+)\"\s*\)")
    for path in files:
        src = _strip_c_comments(open(path, encoding="utf-8", errors="replace").read())
        for m in pat.finditer(src):
            types.add(m.group(1))
    return types


# ------------------------------------------------------------------- inventory


def load_toml_or_json(path: str):
    if path.endswith(".json"):
        with open(path, "rb") as f:
            return json.load(f)
    try:
        import tomllib
    except ImportError:
        sys.exit("error: TOML needs Python 3.11+ (tomllib); use a .json file instead")
    with open(path, "rb") as f:
        return tomllib.load(f)


def load_inventory(path: str):
    """-> (required ids, waives [{id, reason}], value-taking option letters).

    A `[[waive]]` names one `id` or a list of `ids` (explicit enumeration only —
    no globs, so a waiver can never silently swallow a feature added later), and
    every waiver must carry a non-empty `reason`."""
    data = load_toml_or_json(path)
    feats = data.get("features", {})
    required = {f"opt:{o}" for o in feats.get("options", [])}
    required |= {f"type:{t}" for t in feats.get("types", [])}
    required |= set(feats.get("extra", []))  # free-form ids (fmt:json, field:T, ...)
    takes_value = set(feats.get("takes_value", []))
    waives = []
    for w in data.get("waive", []):
        ids = w.get("ids") or ([w["id"]] if "id" in w else [])
        reason = str(w.get("reason", "")).strip()
        if not ids or not reason:
            sys.exit(f"error: every [[waive]] needs id/ids and a non-empty reason: {w}")
        for wid in ids:
            waives.append({"id": wid, "reason": reason})
    return required, waives, takes_value


def matrix_coverage(path: str, takes_value: set[str] | None = None) -> set[str]:
    """Feature ids the matrix's cases exercise: option letters inferred from
    `args` (short-option clusters; `--long` and bare `-` are skipped) plus each
    case's explicit `covers` list.

    Scanning a cluster STOPS after a value-taking option, because everything
    after it is that option's argument, not more options: `-iTCP:80` is `-i`
    with the value `TCP:80`, and crediting T/C/P would be *false coverage* —
    a gate that over-credits hides exactly the gaps it exists to find."""
    takes_value = takes_value or set()
    data = load_toml_or_json(path)
    covered: set[str] = set()
    for case in data.get("case", []):
        for tok in case.get("args", []):
            if not isinstance(tok, str) or len(tok) < 2:
                continue
            if tok.startswith("--"):
                continue
            if tok[0] in "-+":
                for ch in tok[1:]:
                    if not ch.isalnum():
                        break  # punctuation: the rest is a value
                    covered.add(f"opt:{ch}")
                    if ch in takes_value:
                        break  # the remainder is this option's argument
        for cid in case.get("covers", []):
            covered.add(str(cid))
    return covered


# ------------------------------------------------------------------------ gate


def run_gate(inventory_path: str, matrix_path: str, warn: bool, as_json: bool) -> int:
    required, waives, takes_value = load_inventory(inventory_path)
    covered = matrix_coverage(matrix_path, takes_value)
    waived_ids = {w["id"] for w in waives}
    stale_waives = sorted(waived_ids - required)
    uncovered = sorted(required - waived_ids - covered)
    report = {
        "required": len(required),
        "covered": len(required & covered),
        "waived": sorted(waived_ids & required),
        "stale_waives": stale_waives,
        "uncovered": uncovered,
    }
    if as_json:
        print(json.dumps(report, indent=2))
    else:
        for fid in uncovered:
            print(f"UNCOVERED {fid}  (no matrix case exercises it)")
        for w in waives:
            if w["id"] in required:
                print(f"waived    {w['id']}  — {w['reason']}")
        for fid in stale_waives:
            print(f"warn: stale waive {fid} (not in the inventory — curate it away)")
        print(
            f"\nfeatures: {len(required)}  covered: {report['covered']}"
            f"  waived: {len(report['waived'])}  UNCOVERED: {len(uncovered)}"
        )
    if uncovered and not warn:
        return 1
    return 0


def emit_inventory(options: set[str], types: set[str], takes_value: set[str]) -> str:
    lines = [
        "# feature-inventory — the C's enumerated surface, bootstrapped by",
        "#   coverage_gate.py --extract-options/--extract-types --emit-inventory",
        "# CURATE before gating: drop dialect-irrelevant entries, then add a",
        "# [[waive]] (with a reason) for anything deliberately out of scope.",
        "",
        "[features]",
        "options = [" + ", ".join(f'"{o}"' for o in sorted(options)) + "]",
        "# Options that consume a value: a matrix case's `-iTCP:80` counts as `i`",
        "# alone, so the value's characters aren't miscredited as coverage.",
        "takes_value = [" + ", ".join(f'"{o}"' for o in sorted(takes_value)) + "]",
        "types = [" + ", ".join(f'"{t}"' for t in sorted(types)) + "]",
        "",
        "# [[waive]]",
        '# id = "opt:X"          # or: ids = ["opt:X", "opt:Y"]',
        '# reason = "why this is out of the port\'s declared scope"',
    ]
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------- self-test

C_OPTSTRING_FIXTURE = r"""
/* mini main.c: lsof's built-optstring idiom (all #if branches present) */
static char options[128];
int setup() {
    (void)snpf(options, sizeof(options),
               "?ab:c:i:%st%s",
#if defined(HAS_K)
               "k:",
#else
               "",
#endif
#if defined(HAS_X)
               "X",
#else
               "",
#endif
    );
}
/* a direct-literal getopt elsewhere must also be found */
int other(int argc, char **argv) { return getopt(argc, argv, "qz:"); }
/* decoys the scanner must ignore */
void log_it() { snpf(msg, sizeof(msg), "no colon opts here"); }
"""

C_TYPES_FIXTURE = r"""
/* mini print.c: the print_file_type idiom */
void print_file_type(int t, char *buf, int buf_len) {
    switch (t) {
    case T_REG:  (void)snpf(buf, buf_len, "REG");  break;
    case T_DIR:  (void)snpf(buf, buf_len, "DIR");  break;
    case T_KEY:  (void)snpf(buf, buf_len, "KEY");  break;
    case T_OCT:  (void)snpf(buf, buf_len, "%04o"); break; /* format: skip */
    }
}
/* not the idiom (three args but literal has %) */
void fmt() { snpf(buf, len, "x=%d"); }
"""

INV_FIXTURE = {
    "features": {
        "options": ["a", "b", "i", "t", "C", "P", "T"],
        "takes_value": ["i"],
        "types": ["REG", "KEY"],
    },
    "waive": [
        {"id": "opt:t", "reason": "terse mode is out of the demo's scope"},
        {"id": "opt:Z", "reason": "stale: no longer in the inventory"},
        {"ids": ["opt:C", "opt:P", "opt:T"], "reason": "grouped waiver: Unix-only dialect flags"},
    ],
}

# The LESSONS #8 reproduction: a socket-only matrix — option coverage looks
# fine, but nothing declares `type:KEY`, so the gate must fail on it. The
# `-iTCP:80` case also guards the false-coverage bug: T/C/P are the *value*.
MATRIX_FIXTURE = {
    "case": [
        {"name": "sockets", "args": ["-iTCP:80", "-a"], "covers": ["type:REG"]},
        {"name": "grouped", "args": ["-ab"]},
        {"name": "long-and-bare", "args": ["--json", "-"]},
    ]
}


def self_test() -> int:
    import os
    import tempfile

    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + f"  {name}")
        ok = ok and cond

    with tempfile.TemporaryDirectory() as td:
        copt = os.path.join(td, "opt.c")
        ctyp = os.path.join(td, "typ.c")
        open(copt, "w").write(C_OPTSTRING_FIXTURE)
        open(ctyp, "w").write(C_TYPES_FIXTURE)

        opts, takes = extract_options([copt])
        check(
            "optstring union: format + all #if branches + direct getopt",
            opts == {"a", "b", "c", "i", "t", "k", "X", "q", "z"},
        )
        check("value-taking options detected from `x:`", takes == {"b", "c", "i", "k", "z"})
        types = extract_types([ctyp])
        check("TYPE literals extracted, %-formats skipped", types == {"REG", "DIR", "KEY"})

        inv = os.path.join(td, "inv.json")
        mat = os.path.join(td, "mat.json")
        json.dump(INV_FIXTURE, open(inv, "w"))
        json.dump(MATRIX_FIXTURE, open(mat, "w"))

        required, waives, takes_value = load_inventory(inv)
        covered = matrix_coverage(mat, takes_value)
        check("args infer short options incl. clusters", {"opt:a", "opt:b", "opt:i"} <= covered)
        check("--long and bare - are not option coverage", "opt:j" not in covered and "opt:-" not in covered)
        check("covers= declares fixture-borne TYPE coverage", "type:REG" in covered)
        check(
            "no false coverage: `-iTCP:80` is opt:i, not T/C/P",
            not ({"opt:T", "opt:C", "opt:P"} & covered),
        )
        check("grouped `ids = [...]` waiver expands", {"opt:C", "opt:P", "opt:T"} <= {w["id"] for w in waives})

        uncovered = sorted(required - {w["id"] for w in waives} - covered)
        check("LESSONS #8: the un-created TYPE is caught", uncovered == ["type:KEY"])
        check("waived option not reported uncovered", "opt:t" not in uncovered)

        rc = run_gate(inv, mat, warn=False, as_json=False)
        check("gate exits 1 on uncovered", rc == 1)
        rc = run_gate(inv, mat, warn=True, as_json=False)
        check("--warn exits 0", rc == 0)

        # a waive without a reason must be an infra error (exit 2 via sys.exit)
        bad = os.path.join(td, "bad.json")
        json.dump({"features": {"options": ["a"]}, "waive": [{"id": "opt:a"}]}, open(bad, "w"))
        try:
            load_inventory(bad)
            check("reasonless waive rejected", False)
        except SystemExit:
            check("reasonless waive rejected", True)

    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


# ------------------------------------------------------------------------ main


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--inventory", help="feature inventory (.toml or .json)")
    ap.add_argument("--matrix", help="differential input matrix (.toml or .json)")
    ap.add_argument("--extract-options", nargs="+", metavar="FILE.C", help="bootstrap: option letters from C source")
    ap.add_argument("--extract-types", nargs="+", metavar="FILE.C", help="bootstrap: TYPE literals from C source")
    ap.add_argument("--emit-inventory", action="store_true", help="print extraction as a curate-me TOML inventory")
    ap.add_argument("--warn", action="store_true", help="report but exit 0 (advisory mode)")
    ap.add_argument("--json", action="store_true", help="machine-readable gate report")
    ap.add_argument("--self-test", action="store_true", help="run the built-in fixture tests")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    if args.extract_options or args.extract_types:
        try:
            opts, takes = extract_options(args.extract_options or [])
            types = extract_types(args.extract_types or [])
        except OSError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        if args.emit_inventory:
            sys.stdout.write(emit_inventory(opts, types, takes))
        else:
            if opts:
                print("options:", " ".join(sorted(opts)))
                print("takes value:", " ".join(sorted(takes)))
            if types:
                print("types:", " ".join(sorted(types)))
        return 0

    if not (args.inventory and args.matrix):
        ap.print_usage(sys.stderr)
        print("error: need --inventory and --matrix (or an --extract-* / --self-test mode)", file=sys.stderr)
        return 2
    try:
        return run_gate(args.inventory, args.matrix, args.warn, args.json)
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
