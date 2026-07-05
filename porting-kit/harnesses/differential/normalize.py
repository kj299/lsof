#!/usr/bin/env python3
"""Output normalization for differential testing — importable + CLI.

The C oracle and the Rust rewrite will differ in *nondeterministic* ways that are
not bugs: PIDs, timestamps, ephemeral ports, pointer/handle values, and sometimes
line ordering. If you diff raw output, that noise buries real regressions and
fakes false ones. These rules (learned from winlsof, where PIDs/timestamps/hex
handles all varied run-to-run) canonicalize both sides *identically* before the
diff, so only meaningful differences survive.

Rules are data (REGEX list + flags), so a new port tunes them without editing
logic. Keep them symmetric: whatever you erase from the oracle you erase from the
Rust, or you manufacture a divergence.

Usage:
  normalize.py [--sort] [--strip-blank] [FILE]      # stdin if no FILE
  normalize.py --self-test
"""
from __future__ import annotations

import argparse
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
    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", nargs="?", help="input file (stdin if omitted)")
    ap.add_argument("--sort", action="store_true", help="sort lines (order-independent compare)")
    ap.add_argument("--strip-blank", action="store_true", help="drop blank lines")
    ap.add_argument("--mask-numbers", action="store_true", help="also mask bare 2-7 digit numbers (PIDs); lossy")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return _self_test()
    text = open(args.file, encoding="utf-8", errors="replace").read() if args.file else sys.stdin.read()
    sys.stdout.write(normalize_text(text, sort=args.sort, strip_blank=args.strip_blank,
                                    mask_numbers=args.mask_numbers))
    return 0


if __name__ == "__main__":
    sys.exit(main())
