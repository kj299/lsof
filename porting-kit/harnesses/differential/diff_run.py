#!/usr/bin/env python3
"""Differential harness — run the C oracle and the Rust rewrite over the same
input matrix, normalize both, and diff. Divergences are *triaged*, not blindly
failed: the C may itself be buggy (the prime directive), so a difference is a
question — "Rust bug, or intentional fix of a C defect?" — and the intentional
ones live in a ledger (DIVERGENCES.md) that suppresses them on future runs.

Two comparison modes:
  * same-binary-both-platforms: --oracle and --rust are real binaries.
  * oracle-substitution: when the reference can't run here, point --oracle at a
    wrapper that emits the captured golden output (see harnesses/golden).

Matrix (TOML or JSON): a list of cases, each with a name and argv, e.g.

  [[case]]
  name = "listen-sockets"
  args = ["-nP", "-iTCP"]
  # optional: stdin = "...", env = {FOO="bar"}, timeout = 10

Usage:
  diff_run.py --oracle PATH --rust PATH --matrix FILE [--ledger DIVERGENCES.md]
              [--sort] [--mask-numbers] [--update-ledger] [--json]
  diff_run.py --self-test

Exit: 0 = all match or all divergences are ledgered; 1 = unexplained divergence.
"""
from __future__ import annotations

import argparse
import difflib
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import normalize as N  # noqa: E402


def load_matrix(path):
    if path.endswith(".json"):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data["case"] if isinstance(data, dict) and "case" in data else data
    try:
        import tomllib
    except ModuleNotFoundError:
        sys.exit("error: TOML matrix needs Python 3.11+ (tomllib); use a .json matrix instead")
    with open(path, "rb") as f:
        data = tomllib.load(f)
    return data.get("case", data if isinstance(data, list) else [])


def load_ledger(path):
    """Case names marked as known-intentional divergences. The ledger is
    human-readable Markdown; we harvest lines like `- [x] case-name: reason`."""
    known = set()
    if path and os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            s = line.strip()
            if s.startswith(("- [x]", "* [x]")):
                body = s[5:].strip()
                name = body.split(":", 1)[0].strip().strip("`")
                if name:
                    known.add(name)
    return known


def run_one(binary, case, default_timeout=15):
    argv = [binary] + [str(a) for a in case.get("args", [])]
    env = dict(os.environ)
    env.update({k: str(v) for k, v in case.get("env", {}).items()})
    try:
        p = subprocess.run(
            argv,
            input=case.get("stdin", "").encode() if case.get("stdin") else None,
            capture_output=True,
            timeout=case.get("timeout", default_timeout),
            env=env,
        )
        return p.stdout.decode("utf-8", "replace"), p.returncode
    except subprocess.TimeoutExpired:
        return "<<TIMEOUT>>\n", 124
    except FileNotFoundError:
        sys.exit(f"error: binary not found: {binary}")


def compare(oracle_bin, rust_bin, matrix, ledger, sort, mask_numbers, ignore_exit=False):
    known = load_ledger(ledger)
    results = []
    for case in matrix:
        name = case["name"]
        o_out, o_rc = run_one(oracle_bin, case)
        r_out, r_rc = run_one(rust_bin, case)
        norm = lambda t: N.normalize_text(t, sort=sort, strip_blank=True, mask_numbers=mask_numbers)
        o_n, r_n = norm(o_out), norm(r_out)
        # Fidelity is stdout AND exit code: a rewrite that prints the right thing
        # but returns the wrong status (lsof exits 1 on no-match; scripts branch
        # on it) is NOT a match. Exit-code drift was a real winlsof bug.
        # (LESSONS #4). `--ignore-exit` opts out for tools without stable codes.
        stdout_match = o_n == r_n
        exit_match = ignore_exit or (o_rc == r_rc)
        if stdout_match and exit_match:
            verdict = "MATCH"
        elif name in known:
            verdict = "DIVERGE(ledgered)"
        else:
            verdict = "DIVERGE"
        note = "" if exit_match else f"exit code differs: oracle={o_rc} rust={r_rc}\n"
        body = "" if stdout_match else "".join(difflib.unified_diff(
            o_n.splitlines(keepends=True), r_n.splitlines(keepends=True),
            fromfile=f"oracle:{name}", tofile=f"rust:{name}"))
        results.append({
            "name": name, "verdict": verdict,
            "oracle_rc": o_rc, "rust_rc": r_rc, "exit_match": exit_match,
            "diff": None if verdict == "MATCH" else (note + body),
        })
    return results


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--oracle", help="path to the C reference binary (or golden-replay wrapper)")
    ap.add_argument("--rust", help="path to the Rust binary under test")
    ap.add_argument("--matrix", help="input matrix (.toml or .json)")
    ap.add_argument("--ledger", default="DIVERGENCES.md", help="known-intentional-divergence ledger")
    ap.add_argument("--sort", action="store_true", help="order-independent compare")
    ap.add_argument("--mask-numbers", action="store_true", help="mask bare numbers (PIDs) too")
    ap.add_argument("--ignore-exit", action="store_true", help="don't treat an exit-code difference as a divergence")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()
    if not (args.oracle and args.rust and args.matrix):
        ap.print_usage(sys.stderr)
        print("error: --oracle, --rust and --matrix are required", file=sys.stderr)
        return 2

    results = compare(args.oracle, args.rust, load_matrix(args.matrix),
                      args.ledger, args.sort, args.mask_numbers, args.ignore_exit)
    unexplained = [r for r in results if r["verdict"] == "DIVERGE"]
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print(f"[{r['verdict']:18}] {r['name']}")
            if r["verdict"] == "DIVERGE" and r["diff"]:
                sys.stdout.write(r["diff"])
        print(f"\n{len(results)} cases, {len(unexplained)} unexplained divergence(s)")
        if unexplained:
            print("Triage each: fix the Rust, OR record an intentional fix-of-C-defect in",
                  args.ledger, "as `- [x] <case>: <why>`.")
    return 1 if unexplained else 0


def _self_test():
    """Prove the harness detects both a match and an unexplained divergence,
    and that the ledger suppresses a known one — using /bin/echo as both sides."""
    import tempfile
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + f"  {name}")
        ok = ok and cond

    echo = "/bin/echo" if os.path.exists("/bin/echo") else "echo"
    same = [{"name": "identical", "args": ["hello"]}]
    res = compare(echo, echo, same, ledger=None, sort=False, mask_numbers=False)
    check("identical output → MATCH", res[0]["verdict"] == "MATCH")

    # echo vs printf genuinely diverge on a format-string arg:
    # echo "%s" "hi" → "%s hi"   ;   printf "%s" "hi" → "hi"
    printf = "/usr/bin/printf" if os.path.exists("/usr/bin/printf") else "printf"
    diff_case = [{"name": "diverging", "args": ["%s", "hi"]}]
    res = compare(echo, printf, diff_case, ledger=None, sort=False, mask_numbers=False)
    check("different output → DIVERGE", res[0]["verdict"] == "DIVERGE")

    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as f:
        f.write("- [x] diverging: printf drops the trailing newline; intentional\n")
        ledger_path = f.name
    res = compare(echo, printf, diff_case, ledger=ledger_path, sort=False, mask_numbers=False)
    check("ledgered divergence → suppressed", res[0]["verdict"] == "DIVERGE(ledgered)")
    os.unlink(ledger_path)

    # exit-code fidelity: same stdout, different exit status must DIVERGE.
    with tempfile.TemporaryDirectory() as d:
        o = os.path.join(d, "o.sh"); open(o, "w").write("#!/bin/sh\necho hi\n"); os.chmod(o, 0o755)
        r = os.path.join(d, "r.sh"); open(r, "w").write("#!/bin/sh\necho hi\nexit 3\n"); os.chmod(r, 0o755)
        ec = [{"name": "exitcode", "args": []}]
        res = compare(o, r, ec, ledger=None, sort=False, mask_numbers=False)
        check("same stdout + different exit code → DIVERGE", res[0]["verdict"] == "DIVERGE")
        check("divergence note names the exit codes", "exit code differs" in (res[0]["diff"] or ""))
        res = compare(o, r, ec, ledger=None, sort=False, mask_numbers=False, ignore_exit=True)
        check("--ignore-exit suppresses an exit-only divergence → MATCH", res[0]["verdict"] == "MATCH")

    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
