#!/usr/bin/env python3
"""Output normalization for differential testing — importable + CLI.

The C oracle and the Rust rewrite will differ in *nondeterministic* ways that are
not bugs: PIDs, timestamps, ephemeral ports, pointer/handle values, and sometimes
line ordering. If you diff raw output, that noise buries real regressions and
fakes false ones. These rules (learned from lsof-rs, where PIDs/timestamps/hex
handles all varied run-to-run) canonicalize both sides *identically* before the
diff, so only meaningful differences survive.

Rules are data (REGEX list + flags), so a new port tunes them without editing
logic. Keep them symmetric: whatever you erase from the oracle you erase from the
Rust, or you manufacture a divergence.

Per-project rules live in a file: `--rules FILE` (JSON/TOML — a list of objects
with `name`, `regex`, `replacement`) REPLACES the built-in defaults, so a port
masks its own tokens (session ids, request ids, temp paths) without editing this
harness. `--dump-default-rules` prints the built-ins as such a file, so you start
from them and tune rather than rewrite. No `--rules` → the defaults are the
fallback (back-compatible).

Usage:
  normalize.py [--sort] [--strip-blank] [--mask-numbers] [--rules FILE] [FILE]
  normalize.py --dump-default-rules
  normalize.py --self-test
"""
from __future__ import annotations

import argparse
import json
import re
import sys

# (name, compiled-regex, replacement). Ordered; applied to every line.
DEFAULT_RULES = [
    ("hex-ptr",     re.compile(r"0x[0-9a-fA-F]{6,16}"),                 "0xPTR"),
    ("iso-time",    re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?"), "<TIME>"),
    ("clock-time",  re.compile(r"\b\d{1,2}:\d{2}:\d{2}\b"),            "<TIME>"),
    # ephemeral ports (IANA 49152-65535) on an addr:port — mask the port only
    ("ephem-port",  re.compile(r"(?<=[:.])(4915[2-9]|491[6-9]\d|49[2-9]\d\d|5\d{4}|6[0-4]\d{3}|65[0-4]\d\d|655[0-2]\d|6553[0-5])\b"), "<EPORT>"),
    ("uuid",        re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"), "<UUID>"),
]

# Rules that need an explicit opt-in because they are lossy for some tools.
PID_RULE = ("pid-like", re.compile(r"\b\d{2,7}\b"), "<NUM>")


def load_rules(path):
    """Load normalization rules from a JSON or TOML file — a list of objects with
    `regex`, `replacement`, and (optionally) `name` — into the same
    [(name, compiled, replacement)] shape as DEFAULT_RULES. A malformed rule or a
    bad regex is a HARD error: a silently dropped rule would let real noise through
    and manufacture divergences, the one failure a normalizer must not have."""
    if path.endswith(".json"):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        raw = data["rule"] if isinstance(data, dict) and "rule" in data else data
    else:
        try:
            import tomllib
        except ModuleNotFoundError:
            sys.exit("error: TOML rules need Python 3.11+ (tomllib); use a .json file")
        with open(path, "rb") as f:
            data = tomllib.load(f)
        raw = data.get("rule", data if isinstance(data, list) else [])
    if not isinstance(raw, list):
        sys.exit(f"error: rules file {path} must be a list of {{name, regex, replacement}}")
    rules = []
    for i, r in enumerate(raw):
        if not isinstance(r, dict) or "regex" not in r or "replacement" not in r:
            sys.exit(f"error: rule {i} in {path} needs `regex` and `replacement`")
        try:
            rx = re.compile(r["regex"])
        except re.error as e:
            sys.exit(f"error: rule {r.get('name', i)!r} has a bad regex: {e}")
        rules.append((r.get("name", f"rule{i}"), rx, str(r["replacement"])))
    return rules


def dump_default_rules():
    """The built-in rules as a JSON rules file — a starting point to tune."""
    return json.dumps([{"name": n, "regex": rx.pattern, "replacement": repl}
                       for n, rx, repl in DEFAULT_RULES], indent=2)


def normalize_text(text, rules=DEFAULT_RULES, sort=False, strip_blank=False,
                   trim=True, mask_numbers=False):
    active = list(rules) + ([PID_RULE] if mask_numbers else [])
    out = []
    for line in text.splitlines():
        for _name, rx, repl in active:
            line = rx.sub(repl, line)
        if trim:
            line = line.rstrip()
            line = re.sub(r"[ \t]+", " ", line)
        if strip_blank and not line.strip():
            continue
        out.append(line)
    if sort:
        out.sort()
    return "\n".join(out) + ("\n" if out else "")


def _self_test():
    a = "pid 1234 conn 127.0.0.1:53621 at 2026-07-05 10:00:01 ptr 0xffffd48fe3cb"
    b = "pid 9999 conn 127.0.0.1:61000 at 2026-07-05 11:22:33 ptr 0x00007ffabc12"
    # PIDs are nondeterministic noise → compare with --mask-numbers on.
    na, nb = normalize_text(a, mask_numbers=True), normalize_text(b, mask_numbers=True)
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + f"  {name}")
        ok = ok and cond

    check("nondeterministic noise normalizes two runs to equal", na == nb)
    check("hex pointer masked", "0xPTR" in na)
    check("timestamp masked", "<TIME>" in na)
    check("ephemeral port masked", "<EPORT>" in na)
    # a REAL difference must survive
    c = normalize_text("state LISTEN")
    d = normalize_text("state CLOSED")
    check("a real difference is preserved", c != d)
    # sort makes order-independent
    check("sort canonicalizes order",
          normalize_text("b\na", sort=True) == normalize_text("a\nb", sort=True))

    # rules-as-data (--rules): a project-specific rule loaded from a file applies,
    # and REPLACES the defaults (so a default-only pattern is left untouched); the
    # dumped defaults round-trip back to the same behavior.
    import os
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        rf = os.path.join(td, "rules.json")
        open(rf, "w").write(json.dumps(
            [{"name": "token", "regex": "tok-[0-9a-f]+", "replacement": "<TOK>"}]))
        custom = load_rules(rf)
        check("a custom rule from a file masks a project-specific token",
              normalize_text("auth tok-9f3a done", rules=custom) == "auth <TOK> done\n")
        check("custom rules REPLACE the defaults (a default-only hex ptr is untouched)",
              "0xdeadbeef12" in normalize_text("p 0xdeadbeef12", rules=custom))
        check("a bad regex in a rules file is a hard error",
              _rules_error(td, '[{"name":"x","regex":"(","replacement":"y"}]'))
        rf2 = os.path.join(td, "defaults.json")
        open(rf2, "w").write(dump_default_rules())
        check("dumped defaults reload and still mask a hex pointer",
              "0xPTR" in normalize_text("p 0xdeadbeef12", rules=load_rules(rf2)))
    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def _rules_error(td, body):
    """True iff load_rules rejects `body` with a SystemExit (a bad rules file
    must fail loudly, never load a partial/empty rule set)."""
    import os
    p = os.path.join(td, "bad.json")
    open(p, "w").write(body)
    try:
        load_rules(p)
        return False
    except SystemExit:
        return True


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", nargs="?", help="input file (stdin if omitted)")
    ap.add_argument("--sort", action="store_true", help="sort lines (order-independent compare)")
    ap.add_argument("--strip-blank", action="store_true", help="drop blank lines")
    ap.add_argument("--mask-numbers", action="store_true", help="also mask bare 2-7 digit numbers (PIDs); lossy")
    ap.add_argument("--rules", help="per-project rules file (.json/.toml); replaces the built-in defaults")
    ap.add_argument("--dump-default-rules", action="store_true", help="print the built-in rules as a JSON rules file, then exit")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return _self_test()
    if args.dump_default_rules:
        print(dump_default_rules())
        return 0
    rules = load_rules(args.rules) if args.rules else DEFAULT_RULES
    text = open(args.file, encoding="utf-8", errors="replace").read() if args.file else sys.stdin.read()
    sys.stdout.write(normalize_text(text, rules=rules, sort=args.sort, strip_blank=args.strip_blank,
                                    mask_numbers=args.mask_numbers))
    return 0


if __name__ == "__main__":
    sys.exit(main())
