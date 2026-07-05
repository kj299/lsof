#!/usr/bin/env python3
"""Golden corpus manager — capture, version, and replay the oracle's output, and
flag when the *oracle itself* is nondeterministic (so you don't enshrine noise as
truth). Complements diff_run.py: golden is for when the reference binary can't run
in CI (capture once, replay the stored output forever) and for locking output
*format* when the reference can't run on the target at all.

  capture --oracle B --matrix M --corpus DIR [--repeats N]
      Run the oracle N times per case; if all N normalize-equal, store the golden
      output. If they differ, report the nondeterministic case (its unstable
      lines) so you can extend normalize.py rather than bake in flakiness.

  replay --rust B --matrix M --corpus DIR
      Run the Rust binary and compare to the stored golden. Missing golden = a
      case captured after the fact; run capture first.

Golden files are plain text under DIR/<case>.golden — diff-friendly, reviewable,
committed. Usage: golden.py {capture,replay,--self-test} ...
"""
from __future__ import annotations

import argparse
import os
import sys

_here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_here, "..", "differential"))
import normalize as N          # noqa: E402
import diff_run as D           # noqa: E402  (reuse run_one / load_matrix)


def capture(oracle, matrix_path, corpus, repeats, sort, mask_numbers):
    os.makedirs(corpus, exist_ok=True)
    matrix = D.load_matrix(matrix_path)
    norm = lambda t: N.normalize_text(t, sort=sort, strip_blank=True, mask_numbers=mask_numbers)
    nondet, stored = [], 0
    for case in matrix:
        name = case["name"]
        runs = [norm(D.run_one(oracle, case)[0]) for _ in range(repeats)]
        if len(set(runs)) == 1:
            open(os.path.join(corpus, name + ".golden"), "w", encoding="utf-8").write(runs[0])
            stored += 1
        else:
            unstable = _unstable_lines(runs)
            nondet.append((name, unstable))
    print(f"captured {stored} golden case(s) into {corpus}")
    for name, lines in nondet:
        print(f"NONDETERMINISTIC: {name} — varying lines (extend normalize.py):")
        for ln in lines[:8]:
            print(f"    {ln!r}")
    return 1 if nondet else 0


def _unstable_lines(runs):
    per = [r.splitlines() for r in runs]
    width = max(len(p) for p in per)
    out = []
    for i in range(width):
        vals = {p[i] if i < len(p) else "<absent>" for p in per}
        if len(vals) > 1:
            out.append(" | ".join(sorted(vals)))
    return out


def replay(rust, matrix_path, corpus, sort, mask_numbers):
    matrix = D.load_matrix(matrix_path)
    norm = lambda t: N.normalize_text(t, sort=sort, strip_blank=True, mask_numbers=mask_numbers)
    fails = missing = 0
    for case in matrix:
        name = case["name"]
        gpath = os.path.join(corpus, name + ".golden")
        if not os.path.exists(gpath):
            print(f"MISSING GOLDEN: {name} (run capture first)")
            missing += 1
            continue
        golden = open(gpath, encoding="utf-8").read()
        got = norm(D.run_one(rust, case)[0])
        if got == golden:
            print(f"[MATCH ] {name}")
        else:
            print(f"[FAIL  ] {name}")
            fails += 1
    print(f"\n{len(matrix)} cases, {fails} mismatch(es), {missing} missing golden")
    return 1 if (fails or missing) else 0


def _self_test():
    import tempfile
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + f"  {name}")
        ok = ok and cond

    echo = "/bin/echo" if os.path.exists("/bin/echo") else "echo"
    printf = "/usr/bin/printf" if os.path.exists("/usr/bin/printf") else "printf"
    with tempfile.TemporaryDirectory() as d:
        matrix = os.path.join(d, "m.json")
        # args chosen so echo and printf genuinely differ:
        # echo "%s" "hi" -> "%s hi"  ;  printf "%s" "hi" -> "hi"
        open(matrix, "w").write('[{"name": "fmt", "args": ["%s", "hi"]}]')
        corpus = os.path.join(d, "corpus")
        rc = capture(echo, matrix, corpus, repeats=3, sort=False, mask_numbers=False)
        check("stable oracle → captured, no nondeterminism", rc == 0 and
              os.path.exists(os.path.join(corpus, "fmt.golden")))
        check("replay same binary → match", replay(echo, matrix, corpus, False, False) == 0)
        check("replay divergent binary → fail", replay(printf, matrix, corpus, False, False) == 1)

        # nondeterministic oracle must be flagged, not stored
        nd = os.path.join(d, "nd.sh")
        open(nd, "w").write("#!/bin/sh\nawk 'BEGIN{srand(); print int(rand()*1e9)}'\n")
        os.chmod(nd, 0o755)
        ndm = os.path.join(d, "nd.json")
        open(ndm, "w").write('[{"name": "rng", "args": []}]')
        ndc = os.path.join(d, "ndcorpus")
        rc = capture(nd, ndm, ndc, repeats=5, sort=False, mask_numbers=False)
        check("nondeterministic oracle → flagged, not stored",
              rc == 1 and not os.path.exists(os.path.join(ndc, "rng.golden")))
    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd")
    for name in ("capture", "replay"):
        s = sub.add_parser(name)
        s.add_argument("--oracle" if name == "capture" else "--rust", required=True, dest="binary")
        s.add_argument("--matrix", required=True)
        s.add_argument("--corpus", required=True)
        s.add_argument("--sort", action="store_true")
        s.add_argument("--mask-numbers", action="store_true")
        if name == "capture":
            s.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()
    if args.cmd == "capture":
        return capture(args.binary, args.matrix, args.corpus, args.repeats, args.sort, args.mask_numbers)
    if args.cmd == "replay":
        return replay(args.binary, args.matrix, args.corpus, args.sort, args.mask_numbers)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
