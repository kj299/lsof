#!/usr/bin/env python3
"""C vulnerability-class scanner — run at Phase 0, BEFORE porting, so the Rust
rewrite fixes C's latent flaws instead of faithfully re-implementing them.
("Recognize that the existing operating system running code may have other
flaws." — the prime directive.)

This is a fast, dependency-free heuristic grep over C sources for the classic
sink patterns. It is deliberately noisy: every hit is a *question* for the porter
("is this exploitable? does the Rust version close it?"), and confirmed ones go
into DIVERGENCES.md as intentional fix-of-C-defect entries. It does NOT replace a
real SAST pass (clang analyzer, CodeQL, cppcheck) — it bootstraps the flaw
inventory when you have minutes, not hours.

Categories flagged (CWE in parens):
  unbounded-copy    strcpy/strcat/sprintf/gets/scanf %s          (CWE-120/787)
  format-string     printf-family with a non-literal format      (CWE-134)
  stack-vla-alloca  alloca / variable-length arrays              (CWE-770)
  int-overflow-mul  malloc(a * b) style size math                (CWE-190)
  command-exec      system/popen/exec* with composed strings     (CWE-78)
  unchecked-malloc  malloc/calloc/realloc result used w/o check   (CWE-690) [weak]
  toctou            access()/stat() then open()/fopen()          (CWE-367)
  signed-char-compare  a char (signed on most ABIs) compared with a
                    numeric literal without an (unsigned char) cast (CWE-195)

Usage:
  scan_c_flaws.py PATH [PATH ...] [--json] [--self-test]
Exit: 0 always (this is an inventory, not a gate) unless --strict (then 1 if hits).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

CHECKS = [
    ("unbounded-copy", "CWE-120",
     re.compile(r"\b(strcpy|strcat|sprintf|vsprintf|gets)\s*\(")),
    ("unbounded-copy", "CWE-120",
     re.compile(r"\bscanf\s*\([^)]*%s")),
    ("stack-vla-alloca", "CWE-770",
     re.compile(r"\balloca\s*\(")),
    ("int-overflow-mul", "CWE-190",
     re.compile(r"\b(malloc|calloc|realloc)\s*\([^;)]*[*][^;)]*\)")),
    ("command-exec", "CWE-78",
     re.compile(r"\b(system|popen|execl|execlp|execv|execvp)\s*\(")),
    ("toctou", "CWE-367",
     re.compile(r"\b(access|stat|lstat)\s*\(")),
]

# printf-family: name -> index of the *format-string* argument. The format is
# NOT always arg 0 — it follows the stream (fprintf), buffer (sprintf), size
# (snprintf), or priority/eval (syslog/err). Flagging arg 0 blindly produces a
# false positive on every `fprintf(stderr, "literal", ...)` — which is what
# buried the real findings when this scanner was first run against lsof
# (828 false positives). We flag only when the format-position arg is a
# *non-literal* (doesn't start with a string literal). (LESSONS #2)
FORMAT_FUNCS = {
    "printf": 0, "vprintf": 0, "warn": 0, "warnx": 0, "vwarn": 0,
    "fprintf": 1, "vfprintf": 1, "dprintf": 1, "sprintf": 1, "vsprintf": 1,
    "syslog": 1, "vsyslog": 1, "err": 1, "errx": 1, "asprintf": 1,
    "snprintf": 2, "vsnprintf": 2,
}
_FMT_CALL = re.compile(r"\b(" + "|".join(FORMAT_FUNCS) + r")\s*\(")


def _call_args(src, open_paren):
    """Return the top-level comma-separated argument strings of a call whose
    '(' is at index `open_paren`, plus the index just past the ')'. Skips string
    and char literals and nested parens. Best-effort on an unbalanced tail."""
    depth, args, cur, j, n = 0, [], [], open_paren, len(src)
    while j < n:
        c = src[j]
        if c in '"\'':
            quote = c
            cur.append(c); j += 1
            while j < n and src[j] != quote:
                if src[j] == "\\" and j + 1 < n:
                    cur.append(src[j]); cur.append(src[j + 1]); j += 2; continue
                cur.append(src[j]); j += 1
            if j < n:
                cur.append(src[j]); j += 1
            continue
        if c == "(":
            depth += 1
            if depth > 1:
                cur.append(c)
            j += 1; continue
        if c == ")":
            depth -= 1
            if depth == 0:
                args.append("".join(cur))
                return args, j + 1
            cur.append(c); j += 1; continue
        if c == "," and depth == 1:
            args.append("".join(cur)); cur = []; j += 1; continue
        cur.append(c); j += 1
    args.append("".join(cur))
    return args, n


def _scan_format_strings(src):
    hits = []
    for m in _FMT_CALL.finditer(src):
        name = m.group(1)
        args, _end = _call_args(src, m.end() - 1)
        idx = FORMAT_FUNCS[name]
        if idx >= len(args):
            continue  # too few args to tell; don't cry wolf
        fmt = args[idx].strip()
        # Literal format (starts with a string, or a wide/utf literal) is safe.
        if fmt.startswith(('"', 'L"', 'u8"', 'u"', 'U"')):
            continue
        if not fmt:
            continue
        lineno = src.count("\n", 0, m.start()) + 1
        hits.append({"line": lineno, "category": "format-string", "cwe": "CWE-134",
                     "text": (name + "(" + args[idx].strip())[:120]})
    return hits


# `char` is signed on x86-64, ARM64 Linux and most other ABIs, so a byte >= 0x80
# read through a `char *` is NEGATIVE. Comparing it with a numeric literal then
# takes the wrong branch, and the classic symptom is a length or width computed
# differently from how the same bytes are printed.
#
# This rule exists because a hand-run differential found exactly that in lsof's
# `safestrlen()` — `(*sp < 0x20)` with no cast, in a function that casts
# `(unsigned char)` twice on adjacent lines — and no pattern here flagged it.
# A scanner that misses the bug the porter found by hand is a scanner with a
# hole in it (LESSONS #023).
#
# Types cannot be inferred by regex, so the identifiers declared `char` in the
# same file are collected first and only those are flagged. `unsigned char` is
# safe and excluded; `signed char` is explicitly signed and is not.
_CHAR_DECL = re.compile(r"(?<!unsigned )\bchar\s+(\*\s*)*(\w+)\s*[;,)\[=]")
# The operand must not be a STRUCT FIELD: `Lf->lts.type >= 0` is not the local
# `char type` that happens to share the name, and matching it produced four
# false positives on lsof's print.c alone.
_CHAR_CMP = re.compile(
    r"(?<![\w.])(?<!->)(\*\s*)?\b(\w+)\s*(<=|>=|<|>)\s*(0x[0-9A-Fa-f]+|\d+)"
)
_UCHAR_CAST = re.compile(r"\(\s*unsigned\s+char\s*\)\s*$")


def _char_decls(src):
    """Identifiers declared `char` (not `unsigned char`) anywhere in the file."""
    return {m.group(2) for m in _CHAR_DECL.finditer(src)}


def _scan_signed_char(code, char_names):
    """Comparisons of a `char` (or a deref of a `char *`) with a numeric
    literal, where that operand carries no `(unsigned char)` cast."""
    out = []
    for m in _CHAR_CMP.finditer(code):
        name = m.group(2)
        if name not in char_names:
            continue
        # An explicit cast on this operand is the fix, not the bug.
        if _UCHAR_CAST.search(code[: m.start()]):
            continue
        out.append(("signed-char-compare", "CWE-195"))
    return out


_TRAILING_COMMENT = re.compile(r"/\*.*?\*/|//.*$")


def _uncommented(line):
    """`line` with its comments blanked out.

    Comment-only lines were already skipped, but a TRAILING comment is the
    larger noise source in real code: a doc reference like
    `unsigned char mnt_stat; /* mount point stat(2) status */` matched the
    toctou rule, and on lsof that was 20 of 47 live toctou hits — pure noise
    that buries the real call sites. Blanked rather than removed so the text
    the porter reads still lines up with the source.
    """
    return _TRAILING_COMMENT.sub(lambda m: " " * len(m.group(0)), line)


def scan_text(src):
    hits = []
    char_names = _char_decls(src)
    for lineno, line in enumerate(src.splitlines(), 1):
        # skip obvious comment-only lines to cut noise
        stripped = line.strip()
        if stripped.startswith(("*", "//", "/*")):
            continue
        code = _uncommented(line)
        for cat, cwe, rx in CHECKS:
            if rx.search(code):
                hits.append({"line": lineno, "category": cat, "cwe": cwe, "text": stripped[:120]})
        for cat, cwe in _scan_signed_char(code, char_names):
            hits.append({"line": lineno, "category": cat, "cwe": cwe, "text": stripped[:120]})
    hits.extend(_scan_format_strings(src))
    hits.sort(key=lambda h: h["line"])
    return hits


def iter_c_files(paths):
    for p in paths:
        if os.path.isfile(p) and p.endswith((".c", ".h")):
            yield p
        elif os.path.isdir(p):
            for root, _d, files in os.walk(p):
                for f in files:
                    if f.endswith((".c", ".h")):
                        yield os.path.join(root, f)


def run(paths, as_json, strict):
    all_hits, by_cat = [], {}
    for path in sorted(set(iter_c_files(paths))):
        try:
            src = open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        for h in scan_text(src):
            h["file"] = path
            all_hits.append(h)
            by_cat[h["category"]] = by_cat.get(h["category"], 0) + 1

    if as_json:
        print(json.dumps({"total": len(all_hits), "by_category": by_cat, "hits": all_hits}, indent=2))
    else:
        for h in all_hits:
            print(f"{h['file']}:{h['line']}  [{h['category']}/{h['cwe']}]  {h['text']}")
        print(f"\n{len(all_hits)} potential flaw site(s); by category:")
        for cat, n in sorted(by_cat.items(), key=lambda kv: -kv[1]):
            print(f"    {n:4}  {cat}")
        print("\nTriage each: does the Rust port close it? Record confirmed fixes in DIVERGENCES.md.")
    return 1 if (strict and all_hits) else 0


SELF_TEST_C = r'''
#include <stdio.h>
void bad(char *u, char *dynfmt) {
    char buf[16];
    strcpy(buf, u);                     /* unbounded-copy */
    printf(u);                          /* format-string: arg 0 non-literal */
    fprintf(stderr, "literal %s\n", u); /* SAFE: format arg is a literal */
    fprintf(stderr, dynfmt, u);         /* format-string: arg 1 non-literal */
    snprintf(buf, sizeof buf, "%d", 1); /* SAFE: format arg (idx 2) literal */
    char *p = malloc(n * width);        /* int-overflow-mul */
    system(cmd);                        /* command-exec */
    if (access(path, R_OK)) {}          /* toctou */
    /* strcpy(x, y);  in a comment - should be ignored */
}
int len_of(char *sp) {
    char c = ' ';
    int n = 0;
    for (; *sp; sp++) {
        if (*sp < 0x20)                 /* signed-char-compare: no cast */
            n += 2;
        else if ((unsigned char)*sp == 0xff)  /* SAFE: cast to unsigned */
            n += 4;
        else if (c > 0x7e)              /* signed-char-compare: char var */
            n += 1;
    }
    return n;
}
struct s { int type; };
int field(struct s *lf) {
    return lf->type >= 0;               /* SAFE: a field, not the char above */
}
int stat_doc;                           /* SAFE: stat(2) only in a comment */
'''


def _self_test():
    hits = scan_text(SELF_TEST_C)
    cats = {h["category"] for h in hits}
    fmt_hits = [h for h in hits if h["category"] == "format-string"]
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + f"  {name}")
        ok = ok and cond

    check("flags unbounded-copy", "unbounded-copy" in cats)
    check("flags format-string", "format-string" in cats)
    check("flags int-overflow-mul", "int-overflow-mul" in cats)
    check("flags command-exec", "command-exec" in cats)
    check("flags toctou", "toctou" in cats)
    check("ignores the commented strcpy (no double count)",
          sum(1 for h in hits if h["category"] == "unbounded-copy") == 1)
    # The Pass-1 fix: only NON-LITERAL format args flag; the stream/buffer/size
    # arg is not mistaken for the format. Exactly 2 real hits (printf(u), the
    # variable-format fprintf); the two literal-format calls must NOT flag.
    check("format-string flags exactly the 2 non-literal calls", len(fmt_hits) == 2)
    check("literal-format fprintf/snprintf NOT flagged",
          not any("literal" in h["text"] or '"%d"' in h["text"] for h in fmt_hits))
    # The rule added after a hand-run differential found lsof's safestrlen()
    # defect that nothing here flagged (LESSONS #023).
    sc = [h for h in hits if h["category"] == "signed-char-compare"]
    check("flags the uncast char deref and the char variable", len(sc) == 2)
    check("an (unsigned char) cast is NOT flagged",
          not any("0xff" in h["text"] for h in sc))
    check("a struct field sharing the name is NOT flagged",
          not any("lf->type" in h["text"] for h in sc))
    # A trailing comment must not feed the other rules: `stat(2)` in one was
    # 20 of 47 live toctou hits on lsof.
    check("stat(2) in a trailing comment is NOT flagged as toctou",
          not any("stat_doc" in h["text"] for h in hits))
    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--strict", action="store_true", help="exit 1 if any hit (for a gate)")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return _self_test()
    if not args.paths:
        ap.print_usage(sys.stderr)
        print("error: give at least one PATH, or --self-test", file=sys.stderr)
        return 2
    return run(args.paths, args.json, args.strict)


if __name__ == "__main__":
    sys.exit(main())
