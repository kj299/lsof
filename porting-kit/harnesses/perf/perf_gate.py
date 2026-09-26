#!/usr/bin/env python3
# KIT-IMPORT: from the c2rust-port lineage of this kit.
# Re-cited: #48->#069, #50->#071.
"""Performance gate — a Rust port that is far slower than the C is a *specific
bug*, not "the cost of Rust": a needless copy, a missed `--release` build, bounds
checks in a hot loop, an accidental O(n^2). This gate measures the Rust rewrite
against the C oracle over the same input matrix and FAILS when a case exceeds a
ratio threshold (default 1.3x the C median). (PLAYBOOK Phase 4 / synthesis
"performance sanity"; the number that was prose until now.)

It reuses `diff_run.run_one`, so the spawn/stdin/env/timeout semantics — and the
fail-closed timeout handling (a hang is not "slow", it's a failure) — are exactly
the differential's. Timing is wall-clock around each run; the reported statistic
is the MEDIAN of `--repeats` runs (robust to a single scheduling hiccup), and the
ratio is rust_median / oracle_median per case.

Measurement honesty: a case whose oracle median is below `--floor-ms` (default 3)
is dominated by process-spawn overhead, not the work under test — its ratio is
noise, so it is reported as UNMEASURABLE (not a pass, not a fail) and you are told
to give it a bigger workload. Silent truncation reads as coverage; this doesn't.

Wall-clock honesty (the source lineage's kit audit, §6 item 5): this gate times wall
clock on whatever machine runs it, and a shared/noisy CI runner can push a real
1.0x case over the threshold (false SLOW) or hide a real regression under jitter.
Two controls:
  * NOISY — when a side's own repeats disagree with each other (spread
    `(max-min)/median` over `--noise`, default 0.5), the measurement cannot
    support a SLOW/OK verdict and says so. Like UNMEASURABLE it is a failure,
    not a pass: rerun on a quieter box or raise --repeats.
  * --warn — advisory mode: report everything, exit 0. This is the recommended
    mode on SHARED CI runners; run the hard gate on a quiet/dedicated machine
    (or locally) where the number means something. A wall-clock gate presented
    as always-blocking is a flaky gate, and a flaky gate gets deleted.

Usage:
  perf_gate.py --oracle PATH --rust PATH --matrix FILE
               [--repeats N] [--threshold R] [--floor-ms MS] [--noise S]
               [--warn] [--json]
  perf_gate.py --self-test
Exit: 0 = every measurable case within threshold (or --warn); 1 = a case over
threshold, a timeout, an unmeasurable or noisy case; 2 = usage.
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "differential"))
import diff_run as D          # noqa: E402  (reuse run_one / load_matrix)


def _median_time(binary, case, repeats):
    """Median wall-clock (seconds) over `repeats` runs, whether any run timed
    out, and the run-to-run SPREAD `(max-min)/median` (0.0 when the median is 0
    or repeats == 1 — no dispersion evidence either way). Times
    `diff_run.run_one` so spawn/stdin/env/timeout match the differential
    exactly; the tiny constant decode overhead cancels in the ratio."""
    times, timed_out = [], False
    for _ in range(repeats):
        t0 = time.perf_counter()
        _out, _rc, to, _err = D.run_one(binary, case)
        times.append(time.perf_counter() - t0)
        timed_out = timed_out or to
    med = statistics.median(times)
    spread = (max(times) - min(times)) / med if med > 0 and len(times) > 1 else 0.0
    return med, timed_out, spread


def measure(oracle_bin, rust_bin, matrix, repeats, threshold, floor_ms, noise=0.5):
    floor_s = floor_ms / 1000.0
    results = []
    for case in matrix:
        name = case["name"]
        o_med, o_to, o_spread = _median_time(oracle_bin, case, repeats)
        r_med, r_to, r_spread = _median_time(rust_bin, case, repeats)
        if o_to or r_to:
            verdict, ratio = "TIMEOUT", None
        elif o_med < floor_s:
            # Too fast to attribute to the code under test — spawn-dominated.
            verdict, ratio = "UNMEASURABLE", (r_med / o_med if o_med else None)
        else:
            ratio = r_med / o_med
            verdict = "OK" if ratio <= threshold else "SLOW"
            # A side whose own repeats disagree by more than --noise can't
            # support either OK or SLOW: the machine is drowning the signal.
            # NOISY, like UNMEASURABLE, is honest can't-measure — not a pass.
            if max(o_spread, r_spread) > noise:
                verdict = "NOISY"
        results.append({
            "name": name, "verdict": verdict,
            "oracle_median_ms": round(o_med * 1000, 3),
            "rust_median_ms": round(r_med * 1000, 3),
            "ratio": None if ratio is None else round(ratio, 3),
            "spread": round(max(o_spread, r_spread), 3),
            "threshold": threshold,
        })
    return results


def run(oracle_bin, rust_bin, matrix_path, repeats, threshold, floor_ms, as_json,
        noise=0.5, warn=False):
    results = measure(oracle_bin, rust_bin, D.load_matrix(matrix_path),
                      repeats, threshold, floor_ms, noise)
    bad = [r for r in results if r["verdict"] in ("SLOW", "TIMEOUT", "UNMEASURABLE", "NOISY")]
    if as_json:
        print(json.dumps({"threshold": threshold, "repeats": repeats, "noise": noise,
                          "advisory": warn, "results": results}, indent=2))
    else:
        for r in results:
            ratio = "  n/a" if r["ratio"] is None else f"{r['ratio']:.2f}x"
            print(f"[{r['verdict']:12}] {r['name']:24} "
                  f"C={r['oracle_median_ms']:.1f}ms  Rust={r['rust_median_ms']:.1f}ms  {ratio}"
                  f"  spread={r['spread']:.2f}")
        n_slow = sum(1 for r in results if r["verdict"] == "SLOW")
        n_to = sum(1 for r in results if r["verdict"] == "TIMEOUT")
        n_un = sum(1 for r in results if r["verdict"] == "UNMEASURABLE")
        n_noisy = sum(1 for r in results if r["verdict"] == "NOISY")
        print(f"\n{len(results)} cases  (threshold {threshold}x median, {repeats} repeats): "
              f"{n_slow} slow, {n_to} timeout, {n_un} unmeasurable, {n_noisy} noisy")
        if n_un:
            print("UNMEASURABLE: oracle ran below the floor — give the case a real "
                  "workload (bigger input) so the ratio measures the code, not spawn.")
        if n_noisy:
            print("NOISY: a side's own repeats disagree beyond --noise — this machine "
                  "can't support a verdict. Rerun on a quiet box or raise --repeats.")
        if n_slow:
            print("SLOW is a bug to find (a copy, a debug build, bounds checks in a hot "
                  "loop), not 'the cost of Rust' — profile the case.")
        if bad and warn:
            print("(--warn: advisory mode, exiting 0 — run the hard gate on a quiet "
                  "machine before cutover)")
    return 1 if bad and not warn else 0


def _self_test():
    import tempfile
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + f"  {name}")
        ok = ok and cond

    with tempfile.TemporaryDirectory() as d:
        # Sleep-based stand-ins with a wide separation so the verdict is robust
        # to timing noise: "slow" sleeps ~5x "fast". Floor is small; sleeps are
        # well above it. Identical binary vs itself → ratio ~1 → OK.
        fast = os.path.join(d, "fast.sh")
        open(fast, "w").write("#!/bin/sh\nsleep 0.03\n"); os.chmod(fast, 0o755)
        slow = os.path.join(d, "slow.sh")
        open(slow, "w").write("#!/bin/sh\nsleep 0.15\n"); os.chmod(slow, 0o755)
        tiny = os.path.join(d, "tiny.sh")
        open(tiny, "w").write("#!/bin/sh\nexit 0\n"); os.chmod(tiny, 0o755)
        matrix = [{"name": "c", "args": []}]

        res = measure(fast, fast, matrix, repeats=3, threshold=1.3, floor_ms=3)
        check("same binary → ratio ~1 → OK", res[0]["verdict"] == "OK")

        res = measure(fast, slow, matrix, repeats=3, threshold=1.3, floor_ms=3)
        check("rust ~5x slower → SLOW", res[0]["verdict"] == "SLOW")
        check("SLOW reports a ratio above threshold", res[0]["ratio"] > 1.3)

        res = measure(slow, fast, matrix, repeats=3, threshold=1.3, floor_ms=3)
        check("rust faster than C → OK", res[0]["verdict"] == "OK")

        # a run that exceeds its timeout is a failure, not "slow"
        hang = os.path.join(d, "hang.sh")
        open(hang, "w").write("#!/bin/sh\nsleep 5\n"); os.chmod(hang, 0o755)
        res = measure(fast, hang, [{"name": "h", "args": [], "timeout": 0.3}],
                      repeats=1, threshold=1.3, floor_ms=3)
        check("rust timeout → TIMEOUT (a hang is not 'slow')", res[0]["verdict"] == "TIMEOUT")
        # ...and an ORACLE timeout too. Its median is the timeout itself, so a
        # fast Rust looks fast beside it and would read OK. Only the Rust side
        # was pinned; LESSONS #069/#071's decision sweep forced `o_to` off unnoticed.
        res = measure(hang, fast, [{"name": "h", "args": [], "timeout": 0.3}],
                      repeats=1, threshold=1.3, floor_ms=3)
        check("oracle timeout → TIMEOUT (a hung C is not a fast Rust)",
              res[0]["verdict"] == "TIMEOUT")

        # spawn-dominated case is UNMEASURABLE, not a false OK
        res = measure(tiny, tiny, matrix, repeats=3, threshold=1.3, floor_ms=50)
        check("below the floor → UNMEASURABLE (not a false pass)",
              res[0]["verdict"] == "UNMEASURABLE")

        # NOISY (RETROSPECTIVE-kit-audit §6 item 5): a side whose own repeats
        # disagree can't support a verdict. The jitter script alternates
        # 0.02s/0.2s via a counter file → spread ≈ 1.6, far over --noise 0.5.
        cnt = os.path.join(d, "cnt")
        jitter = os.path.join(d, "jitter.sh")
        open(jitter, "w").write(
            "#!/bin/sh\n"
            f"n=$(cat {cnt} 2>/dev/null || echo 0); echo $((n+1)) > {cnt}\n"
            "if [ $((n % 2)) -eq 0 ]; then sleep 0.02; else sleep 0.2; fi\n")
        os.chmod(jitter, 0o755)
        res = measure(jitter, fast, matrix, repeats=4, threshold=1.3, floor_ms=3)
        check("jittery repeats → NOISY (can't support a verdict, not a false one)",
              res[0]["verdict"] == "NOISY" and res[0]["spread"] > 0.5)

        # --warn: advisory mode reports the failure but exits 0 (shared-CI mode);
        # without it the same SLOW case exits 1.
        mtx = os.path.join(d, "m.json")
        open(mtx, "w").write('[{"name": "c", "args": []}]')
        import contextlib, io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc_hard = run(fast, slow, mtx, 3, 1.3, 3, as_json=False)
            rc_warn = run(fast, slow, mtx, 3, 1.3, 3, as_json=False, warn=True)
        check("SLOW exits 1 in hard mode but 0 under --warn (advisory)",
              rc_hard == 1 and rc_warn == 0)
        check("--warn still REPORTS the slow case (advisory, not silent)",
              "[SLOW" in buf.getvalue() and "advisory mode" in buf.getvalue())

    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--oracle", help="C reference binary")
    ap.add_argument("--rust", help="Rust binary under test")
    ap.add_argument("--matrix", help="input matrix (.toml or .json), same format as diff_run")
    ap.add_argument("--repeats", type=int, default=5, help="runs per side; the median is used (default 5)")
    ap.add_argument("--threshold", type=float, default=1.3, help="max rust/oracle median ratio (default 1.3)")
    ap.add_argument("--floor-ms", type=float, default=3.0, help="oracle medians below this are UNMEASURABLE (default 3ms)")
    ap.add_argument("--noise", type=float, default=0.5,
                    help="max (max-min)/median run-to-run spread before a case is NOISY (default 0.5)")
    ap.add_argument("--warn", action="store_true",
                    help="advisory mode: report but exit 0 — the recommended mode on shared/noisy CI runners")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()
    if not (args.oracle and args.rust and args.matrix):
        ap.print_usage(sys.stderr)
        print("error: --oracle, --rust and --matrix are required (or --self-test)", file=sys.stderr)
        return 2
    return run(args.oracle, args.rust, args.matrix, args.repeats,
               args.threshold, args.floor_ms, args.json,
               noise=args.noise, warn=args.warn)


if __name__ == "__main__":
    sys.exit(main())
