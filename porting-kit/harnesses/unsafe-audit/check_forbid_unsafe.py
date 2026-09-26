#!/usr/bin/env python3
# KIT-IMPORT: from the c2rust-port lineage of this kit.
# Re-cited: #18->#039, #44->#060, #45->#064, #46->#065, #48->#069,
#          #50->#071.
"""Unsafe-containment gate — the `core` crate must FORBID `unsafe_code`, in a
form the compiler actually applies, on every target root it builds.

Why (LESSONS #065): `#![forbid(unsafe_code)]` on `core` is the first row of this
kit's non-negotiable control table, and RETROSPECTIVE-lsof.md calls it the single
highest-leverage line in a port. Nothing checked it. Deleting the line failed no
gate: the crate still compiled, `audit_unsafe.py` still passed — it checks that
`unsafe` is DOCUMENTED, not that it is absent — and any `unsafe` added afterwards
would have passed as well, given a `// SAFETY:` comment. control-coverage could
not see the gap either: the row named no harness, so until LESSONS #064 it was
dropped from the report without a word.

This is a separate script rather than a mode of `audit_unsafe.py` on purpose:
control-coverage recognises a control by its script's name, and `audit_unsafe.py`
is already invoked by every gate — a new mode on it would read as RUN in a gate
that never passes the flag.

What counts — only what rustc would enforce, on EVERY target root of the crate
(the library, `src/main.rs`, each `[[bin]]` and `src/bin/*` — each is its own
crate, and a `forbid` in lib.rs does nothing for a binary beside it):

  * an unconditional inner attribute `#![forbid(... unsafe_code ...)]` in the
    root's leading attribute block, which is where rustc reads crate attributes;
  * or the manifest lint `[lints.rust] unsafe_code = "forbid"` — directly, or
    inherited through `[lints] workspace = true` from `[workspace.lints.rust]`.

What does NOT count, each reported by what was found rather than as a bare
failure to match (a parser over a human-written format reports what it could
not accept — LESSONS #060, #064):

  * the attribute in a COMMENT or doc comment. The skeleton's core and
    `lsof-core` both quote the attribute in their `//!` header, so a grep finds that line and
    passes with the real attribute deleted. The verdict never comes from raw
    text: the crate head is tokenized as rustc reads it, and Rust block comments
    NEST — `/* a /* b */ #![forbid(unsafe_code)] */` is all comment.
  * `deny` / `warn` / `allow` / `expect`: `deny` yields to a local
    `#[allow(unsafe_code)]`; only `forbid` cannot be overridden.
  * `cfg_attr(pred, forbid(unsafe_code))`: wherever `pred` is false, unsafe is
    allowed.

Not covered: `tests/`, `examples/` and `benches/` are separate crates that do
not ship in `core`; the manifest form covers them, the attribute form does not.

Usage:  check_forbid_unsafe.py CRATE_DIR [CRATE_DIR ...] [--json]
        check_forbid_unsafe.py --self-test
Exit:   0 = every crate forbids unsafe_code on every target root
        1 = one does not
        2 = a path is not a crate, or a crate has no target root — a check over
            nothing proves nothing and must not pass (LESSONS #039)
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tomllib

LEVELS = ("forbid", "deny", "warn", "allow", "expect")
_CALL = re.compile(r"(\w+)\s*\((.*)\)\s*$", re.S)


# --- reading the crate head the way rustc does -------------------------------

def _skip_block_comment(text, i):
    """Index just past the block comment opening at `i`. Rust block comments
    NEST. Ending at the first `*/` — C's rule — would read an attribute
    commented out inside a nested comment as live, and pass a crate that rustc
    does not forbid."""
    depth, n = 0, len(text)
    while i < n:
        if text.startswith("/*", i):
            depth += 1
            i += 2
        elif text.startswith("*/", i):
            depth -= 1
            i += 2
            if depth == 0:
                return i
        else:
            i += 1
    return n


def _skip_string(text, i):
    """Index just past the string literal at `i`: `"…"` with escapes, or a raw
    `r"…"` / `r#"…"#` (a `b` prefix is an ordinary character before either)."""
    n = len(text)
    if text[i] == "r":
        j = i + 1
        while j < n and text[j] == "#":
            j += 1
        close = '"' + "#" * (j - i - 1)
        end = text.find(close, j + 1)
        return n if end < 0 else end + len(close)
    i += 1
    while i < n and text[i] != '"':
        i += 2 if text[i] == "\\" else 1
    return i + 1


def _raw_string_at(text, i):
    return (text[i] == "r" and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_"))
            and re.match(r'r#*"', text[i:]) is not None)


def _match_bracket(text, j):
    """Index of the `]` closing the `[` at `j`, or -1. Strings are skipped, so a
    `]` inside `#![doc = "a ] b"]` does not end the attribute."""
    depth, i, n = 0, j, len(text)
    while i < n:
        c = text[i]
        if c == '"' or _raw_string_at(text, i):
            i = _skip_string(text, i)
            continue
        if c == "[":
            depth += 1
        elif c == "]":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def inner_attributes(text):
    """[(content, line)] for each inner attribute in the crate head — the block
    rustc reads crate attributes from. Stops at the first token that is not
    whitespace, a comment, or `#![…]`: an inner attribute after an item is a
    compile error, so nothing past that point can apply to the crate."""
    i, n, out = 0, len(text), []
    if text.startswith("﻿"):
        i = 1
    if text.startswith("#!", i) and not text[i + 2:].lstrip(" \t").startswith("["):
        nl = text.find("\n", i)            # a shebang line, not an attribute
        i = n if nl < 0 else nl + 1
    while i < n:
        if text[i].isspace():
            i += 1
        elif text.startswith("//", i):
            nl = text.find("\n", i)
            i = n if nl < 0 else nl + 1
        elif text.startswith("/*", i):
            i = _skip_block_comment(text, i)
        elif text.startswith("#!", i):
            j = i + 2
            while j < n and text[j].isspace():
                j += 1
            end = _match_bracket(text, j) if j < n and text[j] == "[" else -1
            if end < 0:
                break
            out.append((text[j + 1:end], text.count("\n", 0, i) + 1))
            i = end + 1
        else:
            break
    return out


def _split_top(args):
    """Split an argument list at top-level commas (parens and strings respected)."""
    parts, depth, cur, i, n = [], 0, [], 0, len(args)
    while i < n:
        c = args[i]
        if c == '"' or _raw_string_at(args, i):
            j = _skip_string(args, i)
            cur.append(args[i:j])
            i = j
            continue
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        if c == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    if "".join(cur).strip():
        parts.append("".join(cur))
    return [p.strip() for p in parts]


def unsafe_code_levels(content, conditional=False):
    """[(level, conditional)] for every lint level one attribute sets on
    `unsafe_code`: `forbid(missing_docs, unsafe_code)`, `forbid(unsafe_code,
    reason = "…")`, `cfg_attr(pred, deny(unsafe_code), …)`."""
    m = _CALL.match(content.strip())
    if not m:
        return []
    name, args = m.group(1), _split_top(m.group(2))
    if name == "cfg_attr":
        out = []
        for a in args[1:]:
            out.extend(unsafe_code_levels(a, True))
        return out
    if name in LEVELS and "unsafe_code" in args:
        return [(name, conditional)]
    return []


def forbids(level, conditional):
    """THE VERDICT on one lint setting — kept as one predicate so gate-mutation
    can neutralize each half of it and the self-test must then go red."""
    return level == "forbid" and not conditional


# --- the manifest -------------------------------------------------------------

def _toml(path):
    with open(path, "rb") as fh:
        return tomllib.load(fh)


def _workspace_manifest(crate_dir):
    d = os.path.dirname(os.path.abspath(crate_dir))
    while True:
        p = os.path.join(d, "Cargo.toml")
        if os.path.isfile(p):
            doc = _toml(p)
            if "workspace" in doc:
                return p, doc
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent


def manifest_level(crate_dir, man):
    """(level, where) of `unsafe_code` from the manifest lint table, following
    `[lints] workspace = true` to the workspace root; (None, None) if unset."""
    lints = man.get("lints", {})
    if lints.get("workspace") is True:
        ws = _workspace_manifest(crate_dir)
        if ws is None:
            return None, None
        v = ws[1].get("workspace", {}).get("lints", {}).get("rust", {}).get("unsafe_code")
        where = f"{ws[0]} [workspace.lints.rust]"
    else:
        v = lints.get("rust", {}).get("unsafe_code")
        where = "Cargo.toml [lints.rust]"
    if isinstance(v, dict):
        v = v.get("level")
    return (v, where) if isinstance(v, str) else (None, None)


def crate_roots(crate_dir, man):
    """Every target root this crate builds that ships: the library and each
    binary. Each is its own crate for lint purposes."""
    roots = []
    lib = man.get("lib", {}).get("path")
    if lib is None and os.path.isfile(os.path.join(crate_dir, "src", "lib.rs")):
        lib = "src/lib.rs"
    if lib:
        roots.append(lib)
    roots.extend(b["path"] for b in man.get("bin", []) if b.get("path"))
    if man.get("package", {}).get("autobins", True):
        if os.path.isfile(os.path.join(crate_dir, "src", "main.rs")):
            roots.append("src/main.rs")
        bindir = os.path.join(crate_dir, "src", "bin")
        if os.path.isdir(bindir):
            for f in sorted(os.listdir(bindir)):
                if f.endswith(".rs"):
                    roots.append(f"src/bin/{f}")
                elif os.path.isfile(os.path.join(bindir, f, "main.rs")):
                    roots.append(f"src/bin/{f}/main.rs")
    return list(dict.fromkeys(roots))


# --- the gate -----------------------------------------------------------------

def check_crate(crate_dir):
    """(status, lines). status: 0 forbidden everywhere, 1 not, 2 not checkable."""
    man_path = os.path.join(crate_dir, "Cargo.toml")
    if not os.path.isfile(man_path):
        return 2, [f"ERROR  {crate_dir}: no Cargo.toml — not a crate"]
    man = _toml(man_path)
    roots = crate_roots(crate_dir, man)
    if not roots:
        return 2, [f"ERROR  {crate_dir}: no library or binary target root found — "
                   "a containment check over nothing proves nothing"]

    level, where = manifest_level(crate_dir, man)
    if level is not None and forbids(level, False):
        return 0, [f"FORBID  {crate_dir}  via {where}: unsafe_code = \"forbid\" "
                   f"({len(roots)} target root(s))"]

    status, lines = 0, []
    for rel in roots:
        path = os.path.join(crate_dir, rel)
        if not os.path.isfile(path):
            status = 1
            lines.append(f"NOT FORBIDDEN  {crate_dir}/{rel}: target root does not exist")
            continue
        text = open(path, encoding="utf-8").read()
        found = [(lvl, cond, ln) for content, ln in inner_attributes(text)
                 for lvl, cond in unsafe_code_levels(content)]
        good = [ln for lvl, cond, ln in found if forbids(lvl, cond)]
        if good:
            lines.append(f"FORBID  {crate_dir}/{rel}:{good[0]}  #![forbid(unsafe_code)]")
            continue
        status = 1
        why = [f"line {ln}: `{'cfg_attr(…, ' if cond else ''}{lvl}(unsafe_code)"
               f"{')' if cond else ''}` — "
               + ("conditional: unsafe is allowed wherever the predicate is false"
                  if cond and lvl == "forbid" else
                  f"`{lvl}` can be overridden by a local #[allow(unsafe_code)]; only `forbid` cannot")
               for lvl, cond, ln in found]
        if level is not None:
            why.append(f"{where}: unsafe_code = \"{level}\" — only \"forbid\" contains it")
        if not found and "forbid(unsafe_code)" in text:
            why.append("`forbid(unsafe_code)` appears in this file only in a comment, "
                       "or after the crate's first item — neither applies to the crate")
        if not why:
            why.append("no unsafe_code lint setting at all")
        lines.append(f"NOT FORBIDDEN  {crate_dir}/{rel}: " + "; ".join(why))
    return status, lines


def run(crate_dirs, as_json=False):
    if not crate_dirs:
        print("error: name at least one crate directory (e.g. crates/core)", file=sys.stderr)
        return 2
    worst, report = 0, {}
    for d in crate_dirs:
        if not os.path.isdir(d):
            st, lines = 2, [f"ERROR  {d}: no such directory"]
        else:
            st, lines = check_crate(d)
        worst = max(worst, st)
        report[d] = {"status": st, "lines": lines}
        if not as_json:
            for ln in lines:
                print(ln, file=sys.stderr if st else sys.stdout)
    if as_json:
        json.dump({"tool": "check-forbid-unsafe", "ok": worst == 0, "crates": report},
                  sys.stdout, indent=1)
        print()
    elif worst == 0:
        print(f"\nunsafe contained: {len(crate_dirs)} crate(s) forbid unsafe_code "
              "on every target root")
    else:
        print("\nunsafe NOT contained: a crate that must forbid unsafe_code does not. "
              "Restore `#![forbid(unsafe_code)]` at the top of its root — not in a "
              "comment, not `deny`, not under cfg_attr.", file=sys.stderr)
    return worst


# --- self-test ----------------------------------------------------------------

def _self_test():
    import tempfile
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + f"  {name}")
        ok = ok and cond

    FORBID = "#![forbid(unsafe_code)]\n"

    def crate(root, files, manifest='[package]\nname = "c"\nversion = "0.1.0"\n'):
        os.makedirs(root, exist_ok=True)
        with open(os.path.join(root, "Cargo.toml"), "w") as fh:
            fh.write(manifest)
        for rel, body in files.items():
            p = os.path.join(root, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as fh:
                fh.write(body)
        return root

    def st(root):
        return check_crate(root)[0]

    with tempfile.TemporaryDirectory() as t:
        c = lambda name, files, **kw: crate(os.path.join(t, name), files, **kw)

        check("the attribute at the crate root passes",
              st(c("ok", {"src/lib.rs": "//! doc\n" + FORBID + "pub mod m;\n"})) == 0)
        check("a combined lint list passes",
              st(c("list", {"src/lib.rs": "#![forbid(missing_docs, unsafe_code)]\n"})) == 0)
        check("a lint reason passes",
              st(c("reason", {"src/lib.rs": '#![forbid(unsafe_code, reason = "a ] in here")]\n'})) == 0)
        check("a `]` inside an earlier attribute's string does not end it early",
              st(c("str", {"src/lib.rs": '#![doc = "x ] y"]\n' + FORBID})) == 0)

        # NEGATIVE FIXTURES — each is a way the line can look present and not be.
        check("no attribute at all fails",
              st(c("none", {"src/lib.rs": "pub fn f() {}\n"})) == 1)
        # The shape of BOTH shipped core crates, with the real line deleted: the
        # attribute survives only in the `//!` header that quotes it.
        docq = c("docquote", {"src/lib.rs": "//! `#![forbid(unsafe_code)]` is the key line\npub mod m;\n"})
        check("the attribute quoted only in a doc comment FAILS", st(docq) == 1)
        check("...and the report says it was seen only in a comment",
              "only in a comment" in " ".join(check_crate(docq)[1]))
        check("a commented-out attribute fails",
              st(c("cmt", {"src/lib.rs": "// " + FORBID + "/* " + FORBID + "*/\n"})) == 1)
        check("block comments NEST: an attribute inside `/* /* */ … */` is not live",
              st(c("nest", {"src/lib.rs": "/* a /* b */ " + FORBID + " */\n"})) == 1)
        deny = c("deny", {"src/lib.rs": "#![deny(unsafe_code)]\n"})
        check("`deny(unsafe_code)` fails — a local #[allow] overrides it", st(deny) == 1)
        check("...and says why", "overridden" in " ".join(check_crate(deny)[1]))
        check("`cfg_attr(not(test), forbid(unsafe_code))` fails — conditional",
              st(c("cfg", {"src/lib.rs": "#![cfg_attr(not(test), forbid(unsafe_code))]\n"})) == 1)
        check("an attribute after the first item does not apply to the crate",
              st(c("late", {"src/lib.rs": "pub mod m;\n" + FORBID})) == 1)

        # Every target root is its own crate.
        check("a binary beside a forbidding library fails",
              st(c("bin", {"src/lib.rs": FORBID, "src/bin/tool.rs": "fn main() {}\n"})) == 1)
        check("...and passes once the binary forbids too",
              st(c("bin2", {"src/lib.rs": FORBID, "src/bin/tool.rs": FORBID + "fn main() {}\n"})) == 0)
        check("a `[lib] path` is honoured",
              st(c("libpath", {"src/core.rs": FORBID},
                   manifest='[package]\nname = "c"\nversion = "0.1.0"\n[lib]\npath = "src/core.rs"\n')) == 0)

        # The manifest form, and what it does not accept.
        pkg = '[package]\nname = "c"\nversion = "0.1.0"\n'
        check("`[lints.rust] unsafe_code = \"forbid\"` passes",
              st(c("man", {"src/lib.rs": ""}, manifest=pkg + '[lints.rust]\nunsafe_code = "forbid"\n')) == 0)
        check("the table form `{ level = \"forbid\" }` passes",
              st(c("mant", {"src/lib.rs": ""},
                   manifest=pkg + '[lints.rust]\nunsafe_code = { level = "forbid", priority = -1 }\n')) == 0)
        check("`unsafe_code = \"deny\"` in the manifest fails",
              st(c("mand", {"src/lib.rs": ""}, manifest=pkg + '[lints.rust]\nunsafe_code = "deny"\n')) == 1)
        ws = os.path.join(t, "ws")
        with_ws = crate(os.path.join(ws, "crates", "core"), {"src/lib.rs": ""},
                        manifest=pkg + "[lints]\nworkspace = true\n")
        with open(os.path.join(ws, "Cargo.toml"), "w") as fh:
            fh.write('[workspace]\nmembers = ["crates/*"]\n[workspace.lints.rust]\nunsafe_code = "forbid"\n')
        check("a workspace-inherited forbid passes", st(with_ws) == 0)

        # 0-of-0 and missing inputs are errors, not passes (LESSONS #039).
        check("a crate with no target root is an error",
              st(c("empty", {"README.md": "x"})) == 2)
        check("a directory with no Cargo.toml is an error",
              run([os.path.join(t, "nope")]) == 2)
        check("no crate named at all is an error", run([]) == 2)

        # LESSONS #069/#071's decision sweep: every test in _skip_block_comment could
        # be forced either way with this self-test green, because no fixture put
        # a block comment BEFORE a live attribute, none had a comment whose
        # close could be misread, and none left one unterminated.
        check("a block comment before a live attribute does not hide it",
              st(c("cbefore", {"src/lib.rs": "/* header */\n" + FORBID})) == 0)
        check("a comment's close is `*/` only: a forbid inside `/*xx…*/` is not live",
              st(c("cclose", {"src/lib.rs": "/*xx" + FORBID + "*/\n"})) == 1)
        check("an unterminated block comment hides the rest of the file",
              st(c("cunterm", {"src/lib.rs": "/* never closed\n" + FORBID})) == 1)
        bare = os.path.join(t, "bare")
        os.makedirs(bare)
        check("an existing directory with no Cargo.toml is an error, not a crash",
              st(bare) == 2)
        gone = c("gone", {}, manifest=pkg + '[lib]\npath = "src/missing.rs"\n')
        check("a target root that does not exist fails, naming it",
              st(gone) == 1 and "does not exist" in " ".join(check_crate(gone)[1]))
        # Each NOT FORBIDDEN names its own reason, and only its own.
        say = lambda root: " ".join(check_crate(root)[1])
        cfg = say(c("cfgw", {"src/lib.rs": "#![cfg_attr(not(test), forbid(unsafe_code))]\n"}))
        check("a conditional forbid is explained as conditional, not as a comment",
              "conditional" in cfg and "only in a comment" not in cfg)
        check("a conditional deny is explained as overridable",
              "overridden" in say(c("cfgd", {"src/lib.rs":
                                             "#![cfg_attr(not(test), deny(unsafe_code))]\n"})))
        none = say(c("nonew", {"src/lib.rs": "pub fn f() {}\n"}))
        check("no setting at all says exactly that",
              "no unsafe_code lint setting at all" in none and "comment" not in none)
        check("a manifest `deny` is explained from the manifest",
              'only "forbid" contains it' in say(c("mandw", {"src/lib.rs": ""},
                                              manifest=pkg + '[lints.rust]\nunsafe_code = "deny"\n')))
        check("a crate with a setting is not also told it has none",
              "no unsafe_code lint setting" not in say(deny))

    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("crates", nargs="*", help="crate directories that must forbid unsafe_code")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return _self_test()
    return run(a.crates, a.json)


if __name__ == "__main__":
    sys.exit(main())
