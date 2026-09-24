#!/usr/bin/env python3
"""Resource gate — peak RSS and wall time against the C oracle, under a load
this gate creates, with a meter it validates first.

P5 of `docs/linux-l2-plan.md` asked for "peak RSS and wall time on a whole-host
scan, asserted against a ceiling. Nothing gates either today." Three things had
to be settled before such a gate could mean anything, and each is a control
here rather than a comment:

**1. The meter has to be validated at the LOW end, not just the high end.**
The number this port has been quoting — "RSS 5.4 MB both, identical" — came
from a `wait4`-based meter written in Python and validated against a known
200 MB allocation. It passed that check and was still wrong: a fork child
inherits its parent's RSS until it execs, so `ru_maxrss` for the child includes
the Python interpreter's image. Measured here: the same meter reports **8.68 MB
for `/bin/true`**, and 11.3 MB via `posix_spawn`. Every process it measured came
back at the interpreter's floor, which is why the two binaries looked identical.
A 200 MB fixture cannot detect a floor of 9; only a small fixture can. So the
meter below is a ~16 KB C program, and it is validated from BOTH ends — a
`/bin/true` that must read under 3 MB and a known 200 MB allocation that must
read near 200 — before any measurement is believed. Failing either is an error,
not a warning (LESSONS #036: a gate that cannot fail is not a gate; LESSONS
#061: a meter validated at one end has a floor at the other).

**2. The regression it exists to catch is invisible at CI scale.**
`-i` collects only sockets since P5; before that it walked every process's
`/proc/<pid>/maps`. On this 75-process host the difference is 0.13 MB and would
sit inside the noise of any ceiling anyone would dare to set. At 1075 processes
it is 14.27 MB against 4.65 MB. A gate that measured the ambient host would
pass whether or not the optimization existed — 0-of-0 wearing a green tick
(LESSONS #039). So the gate SPAWNS ITS OWN LOAD: `--procs` synthetic processes
holding `--fds` descriptors and a bound socket each, which is the axis the cost
scales on. The load is torn down in a `finally`, and a run that cannot reach
at least `--procs` processes is an error rather than a quiet measurement of
something smaller (LESSONS #062).

**3. Wall clock on a shared runner cannot support a blocking verdict, and RSS
can.** Peak RSS is a property of the program; wall time on a GitHub runner is a
property of whoever else is on the machine — this repository has a miri job
whose identical suite has measured 1216 s and 2594 s. Both halves are measured
and reported; `--warn-wall`, the CI mode, blocks on the RSS ceiling only. That
split is measured rather than cautious: against the pre-P5 binary the wall half
read 1.58x, 1.47x and 1.43x on a 1.60x ceiling across repeated runs and NEVER
caught the regression, while the RSS half read 2.34-2.44x on a 2.00x ceiling
and caught it every single time. The ratios
are taken against the C oracle measured in the SAME interleaved sweep, so a
slow machine moves both sides.

Ceilings are ratios of rust/C medians, and the defaults are measurement plus
headroom rather than aspiration — see CEILINGS.

Usage:
  resource_gate.py --oracle PATH --rust PATH [--procs N] [--fds M]
                   [--repeats R] [--warn] [--warn-wall] [--json]
  resource_gate.py --self-test
Exit: 0 = every case within its ceilings (or --warn); 1 = a ceiling exceeded,
or the meter, the load or a binary could not support a measurement; 2 = usage.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import time

# --- the two C helpers, embedded so the gate is one file and cannot drift ----

METER_C = r"""
/* Peak-RSS + wall meter whose own footprint is small enough to measure a 3 MB
 * process. A fork child inherits the parent's RSS until exec, so a meter
 * written in an interpreter reports the interpreter for every child. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/resource.h>
int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: meter PROG [ARGS...]\n"); return 2; }
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    pid_t pid = fork();
    if (pid < 0) return 3;
    if (pid == 0) {
        if (!freopen("/dev/null", "w", stdout)) _exit(126);
        if (!freopen("/dev/null", "w", stderr)) _exit(126);
        execv(argv[1], &argv[1]);
        _exit(127);
    }
    int st; struct rusage ru;
    if (wait4(pid, &st, 0, &ru) < 0) return 3;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double ms = (t1.tv_sec - t0.tv_sec) * 1e3 + (t1.tv_nsec - t0.tv_nsec) / 1e6;
    printf("%.3f %ld %d\n", ms, ru.ru_maxrss, WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    return 0;
}
"""

HOG_C = r"""
/* One synthetic process: M open regular fds and one bound TCP socket, then
 * sleep. Real fds and a real socket, because a fixture of empty processes
 * would measure /proc directory walking and nothing the port actually does. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
int main(int argc, char **argv) {
    int m = argc > 1 ? atoi(argv[1]) : 8;
    for (int i = 0; i < m; i++) if (open("/etc/hostname", O_RDONLY) < 0) break;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s >= 0) {
        struct sockaddr_in a;
        memset(&a, 0, sizeof a);
        a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = 0;
        if (bind(s, (struct sockaddr *)&a, sizeof a) == 0) listen(s, 1);
    }
    pause();
    return 0;
}
"""

ALLOC_PY = (
    "b = bytearray(200 * 1024 * 1024)\n"
    "for i in range(0, len(b), 4096):\n"
    "    b[i] = 1\n"
)

# Ratio ceilings, rust/C medians. Each is a measurement plus headroom, and the
# comment IS the measurement, so a later reader can tell a number that was taken
# from one that was hoped for.
#
# `-i` (P5). Measured at 1075 processes: 1.18x wall, 1.41x RSS; before P5's
# socket-only collection path, 1.87x wall and 4.34x RSS. Deleting that path puts
# the RSS half over.
#
# whole host (DIVERGENCES 30). Under this gate's own load (400 synthetic
# processes plus the ambient host), the RSS ratio of the final build and of each
# of its three fixes reverted on its own:
#
#   final (all three)                    0.85x
#   without the per-process trim         1.06x   pinned by a capacity==len test
#   without the boxed socket             1.00x   pinned by a size_of test
#   without the streaming table          1.89x   caught HERE
#   master before all three              2.33x   caught here
#
# 1.30x is the final build's 0.85x plus headroom for a runner — which read the
# same gate ~19% higher than this container in P5 — and it sits well under the
# 1.89x a reverted renderer produces. The two smaller fixes are ~0.15-0.2x each,
# inside what a shared runner can separate, so they are pinned by deterministic
# unit tests instead of by this ceiling. Before DIVERGENCES 30 closed, this
# ceiling was 3.50x and pinned a cost that grew with the host; the cost is now
# proportional (0.84x, 0.85x, 0.87x of the C at 76, 575 and 1075 processes).
CEILINGS = {
    "-i": {"wall": 1.60, "rss": 2.00},
    "whole-host": {"wall": 1.40, "rss": 1.30},
}
CASES = {"-i": ["-i"], "whole-host": []}

MIN_TRUE_MB, MAX_TRUE_MB = 0.2, 3.0      # /bin/true: a real floor, not a guess
MIN_ALLOC_MB, MAX_ALLOC_MB = 190.0, 260.0  # a known 200 MB allocation


class GateError(Exception):
    """A condition under which no verdict may be given."""


def _cc():
    for c in ("cc", "gcc", "clang"):
        if shutil.which(c):
            return c
    raise GateError("no C compiler (cc/gcc/clang): this gate's meter is a C "
                    "program because an interpreter-parented one measures the "
                    "interpreter. Refusing to measure with a meter it cannot build.")


def build_helpers(workdir):
    """Compile the meter and the load generator. Raises GateError."""
    cc = _cc()
    out = {}
    for name, src in (("meter", METER_C), ("hog", HOG_C)):
        cpath = os.path.join(workdir, name + ".c")
        bpath = os.path.join(workdir, name)
        with open(cpath, "w", encoding="utf-8") as fh:
            fh.write("#include <string.h>\n" + src)
        p = subprocess.run([cc, "-O2", "-o", bpath, cpath],
                           capture_output=True, text=True)
        if p.returncode != 0:
            raise GateError(f"could not compile the {name}: {p.stderr.strip()[:400]}")
        out[name] = bpath
    return out


def measure_once(meter, argv):
    """(wall_ms, peak_rss_bytes, exit_status) for one run of argv."""
    p = subprocess.run([meter] + argv, capture_output=True, text=True)
    if p.returncode != 0 or not p.stdout.strip():
        raise GateError(f"meter failed on {argv[0]}: rc={p.returncode} "
                        f"{p.stderr.strip()[:200]}")
    ms, kb, st = p.stdout.split()
    return float(ms), int(kb) * 1024, int(st)


def validate_meter(meter, workdir, report=print):
    """Both ends, because only the low end can detect a floor.

    The high-end check alone is what blessed the meter that reported 8.68 MB
    for `/bin/true` and made two binaries look identical.
    """
    _w, rss, st = measure_once(meter, ["/bin/true"])
    low_mb = rss / 1048576
    if st != 0:
        raise GateError("/bin/true did not exit 0 under the meter")
    if not (MIN_TRUE_MB <= low_mb <= MAX_TRUE_MB):
        raise GateError(
            f"meter floor check FAILED: /bin/true reads {low_mb:.2f} MB, "
            f"outside {MIN_TRUE_MB}-{MAX_TRUE_MB} MB. A meter whose floor sits "
            f"above the processes under test reports the floor for all of them.")

    alloc = os.path.join(workdir, "alloc.py")
    with open(alloc, "w", encoding="utf-8") as fh:
        fh.write(ALLOC_PY)
    _w, rss, st = measure_once(meter, [sys.executable, alloc])
    high_mb = rss / 1048576
    if st != 0 or not (MIN_ALLOC_MB <= high_mb <= MAX_ALLOC_MB):
        raise GateError(
            f"meter scale check FAILED: a known 200 MB allocation reads "
            f"{high_mb:.2f} MB (exit {st})")
    report(f"meter validated: /bin/true {low_mb:.2f} MB, "
           f"200 MB allocation {high_mb:.1f} MB")
    return low_mb, high_mb


def proc_count():
    return sum(1 for d in os.listdir("/proc") if d.isdigit())


def spawn_load(hog, n, fds):
    """Start n synthetic processes; returns their pids. Never partial: a load
    that did not reach n cannot support the measurement it exists to enable."""
    pids = []
    try:
        for _ in range(n):
            pids.append(subprocess.Popen(
                [hog, str(fds)], stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL).pid)
    except OSError as e:
        kill_load(pids)
        raise GateError(f"could not spawn {n} load processes ({e}); lower "
                        f"--procs or raise the process limit") from e
    # They must actually be alive and visible in /proc before anything is timed.
    deadline = time.time() + 10
    while time.time() < deadline:
        alive = sum(1 for p in pids if os.path.exists(f"/proc/{p}"))
        if alive >= n:
            return pids
        time.sleep(0.1)
    alive = sum(1 for p in pids if os.path.exists(f"/proc/{p}"))
    kill_load(pids)
    raise GateError(f"only {alive} of {n} load processes came up within 10s")


def kill_load(pids):
    for p in pids:
        try:
            os.kill(p, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    for p in pids:
        try:
            os.waitpid(p, 0)
        except (ChildProcessError, OSError):
            pass


def sweep(meter, oracle, rust, repeats, warmup=2):
    """Interleaved A/B over every case: a machine that drifts moves both sides."""
    acc = {name: {"C": {"w": [], "r": []}, "rust": {"w": [], "r": []}}
           for name in CASES}
    for _ in range(warmup):
        for args in CASES.values():
            measure_once(meter, [oracle] + args)
            measure_once(meter, [rust] + args)
    for _ in range(repeats):
        for name, args in CASES.items():
            for side, binary in (("C", oracle), ("rust", rust)):
                w, r, st = measure_once(meter, [binary] + args)
                if st not in (0, 1):
                    raise GateError(
                        f"{side} binary exited {st} on `{' '.join(args) or '(no args)'}` "
                        f"— measuring a run that failed is measuring nothing")
                acc[name][side]["w"].append(w)
                acc[name][side]["r"].append(r)
    return acc


def verdicts(acc, ceilings):
    out = []
    for name, sides in acc.items():
        cw = statistics.median(sides["C"]["w"])
        rw = statistics.median(sides["rust"]["w"])
        cr = statistics.median(sides["C"]["r"])
        rr = statistics.median(sides["rust"]["r"])
        ceil = ceilings[name]
        wall_ratio = rw / cw if cw else None
        rss_ratio = rr / cr if cr else None
        row = {
            "case": name,
            "c_wall_ms": round(cw, 2), "rust_wall_ms": round(rw, 2),
            "c_rss_mb": round(cr / 1048576, 2), "rust_rss_mb": round(rr / 1048576, 2),
            "wall_ratio": None if wall_ratio is None else round(wall_ratio, 3),
            "rss_ratio": None if rss_ratio is None else round(rss_ratio, 3),
            "wall_ceiling": ceil["wall"], "rss_ceiling": ceil["rss"],
        }
        row["wall_ok"] = wall_ratio is not None and wall_ratio <= ceil["wall"]
        row["rss_ok"] = rss_ratio is not None and rss_ratio <= ceil["rss"]
        out.append(row)
    return out


def run(oracle, rust, procs, fds, repeats, as_json, warn, ceilings=None,
        report=print, warn_wall=False):
    ceilings = ceilings or CEILINGS
    for label, path in (("oracle", oracle), ("rust", rust)):
        if not (path and os.path.isfile(path) and os.access(path, os.X_OK)):
            raise GateError(f"{label} binary not executable: {path}")
    with tempfile.TemporaryDirectory(prefix="resource-gate-") as work:
        helpers = build_helpers(work)
        validate_meter(helpers["meter"], work, report)
        before = proc_count()
        pids = spawn_load(helpers["hog"], procs, fds)
        try:
            during = proc_count()
            report(f"load: {procs} processes x {fds} fds "
                   f"(/proc {before} -> {during})")
            acc = sweep(helpers["meter"], oracle, rust, repeats)
        finally:
            kill_load(pids)
        rows = verdicts(acc, ceilings)

    # `--warn-wall` is the CI mode, and it is what the measurement supports
    # rather than a hedge: on the pre-P5 binary the wall half read 1.58x, 1.47x
    # and 1.43x against a 1.60x ceiling across runs and NEVER caught the very
    # regression this gate exists for, while the RSS half read 2.34-2.44x
    # against 2.00x and caught it every time. Peak RSS is a property of the
    # program; wall clock on a shared runner is a property of whoever else is
    # on the machine.
    blocking = [r for r in rows
                if not r["rss_ok"] or (not r["wall_ok"] and not warn_wall)]
    bad = [r for r in rows if not (r["wall_ok"] and r["rss_ok"])]
    if as_json:
        report(json.dumps({"procs": procs, "fds": fds, "repeats": repeats,
                           "advisory": warn, "results": rows}, indent=2))
    else:
        for r in rows:
            report(f"[{'OK  ' if r['wall_ok'] and r['rss_ok'] else 'OVER'}] "
                   f"{r['case']:11} "
                   f"wall C={r['c_wall_ms']:7.1f}ms rust={r['rust_wall_ms']:7.1f}ms "
                   f"{r['wall_ratio']:.2f}x/{r['wall_ceiling']:.2f}x   "
                   f"RSS C={r['c_rss_mb']:6.2f}M rust={r['rust_rss_mb']:6.2f}M "
                   f"{r['rss_ratio']:.2f}x/{r['rss_ceiling']:.2f}x")
        report(f"\n{len(rows)} case(s) at {procs} synthetic processes: "
               f"{len(bad)} over ceiling")
        for r in bad:
            if not r["rss_ok"]:
                report(f"  {r['case']}: peak RSS {r['rss_ratio']:.2f}x the C, "
                       f"ceiling {r['rss_ceiling']:.2f}x — memory that grows "
                       f"with the host is a retained-row bug, not a constant.")
            if not r["wall_ok"]:
                report(f"  {r['case']}: wall {r['wall_ratio']:.2f}x the C, "
                       f"ceiling {r['wall_ceiling']:.2f}x — on a shared runner "
                       f"confirm on a quiet machine before believing it.")
        if bad and warn:
            report("(--warn: advisory, exiting 0)")
        elif bad and not blocking:
            report("(--warn-wall: the wall half is advisory on a shared runner; "
                   "the RSS half is within its ceiling, so this does not block)")
    return 1 if blocking and not warn else 0


# ------------------------------------------------------------- self-test ----
def _self_test():
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + f"  {name}")
        ok = ok and cond

    quiet = lambda *a, **k: None

    with tempfile.TemporaryDirectory(prefix="resource-gate-st-") as work:
        try:
            helpers = build_helpers(work)
        except GateError as e:
            print(f"SKIP  no compiler available: {e}")
            return 0
        check("the meter and the load generator compile",
              all(os.path.isfile(v) for v in helpers.values()))

        # THE POINT OF THE WHOLE FILE: the low-end check must actually fire.
        low, high = validate_meter(helpers["meter"], work, quiet)
        check(f"meter reads /bin/true at {low:.2f} MB, under the {MAX_TRUE_MB} MB floor",
              low <= MAX_TRUE_MB)
        check(f"meter reads a known 200 MB allocation at {high:.1f} MB", high >= MIN_ALLOC_MB)

        # ...and a meter with a floor must be REJECTED. This is the fixture the
        # original Python meter would have failed: it reported 8.68 MB for
        # /bin/true. Simulated by a stand-in meter that always reports 9 MB.
        liar = os.path.join(work, "liar")
        with open(liar, "w", encoding="utf-8") as fh:
            fh.write("#!/bin/sh\necho '1.0 9216 0'\n")
        os.chmod(liar, 0o755)
        try:
            validate_meter(liar, work, quiet)
            caught = False
        except GateError as e:
            caught = "floor check FAILED" in str(e)
        check("a meter whose floor is 9 MB is REFUSED, not used", caught)

        # A meter that under-reports the 200 MB fixture is refused too, so the
        # low-end check cannot be satisfied by a meter that reports nothing.
        tiny = os.path.join(work, "tiny")
        with open(tiny, "w", encoding="utf-8") as fh:
            fh.write("#!/bin/sh\necho '1.0 512 0'\n")
        os.chmod(tiny, 0o755)
        try:
            validate_meter(tiny, work, quiet)
            caught = False
        except GateError as e:
            caught = "scale check FAILED" in str(e)
        check("a meter that reports 0.5 MB for a 200 MB allocation is REFUSED", caught)

        # The load must be real: spawn a few, see them in /proc, tear them down.
        before = proc_count()
        pids = spawn_load(helpers["hog"], 5, 4)
        try:
            check("the synthetic load actually appears in /proc",
                  proc_count() >= before + 5)
            check("each load process holds the fds it was asked for",
                  len(os.listdir(f"/proc/{pids[0]}/fd")) >= 4)
        finally:
            kill_load(pids)
        time.sleep(0.3)
        check("the load is torn down again",
              all(not os.path.exists(f"/proc/{p}/status") for p in pids))

        # The verdict itself: over a ceiling is OVER, under it is OK. Driven
        # from a synthetic accumulator so the test does not need two binaries.
        acc = {"-i": {"C": {"w": [10.0], "r": [2 * 1048576]},
                      "rust": {"w": [12.0], "r": [3 * 1048576]}},
               "whole-host": {"C": {"w": [10.0], "r": [2 * 1048576]},
                              "rust": {"w": [10.0], "r": [2 * 1048576]}}}
        rows = {r["case"]: r for r in verdicts(acc, CEILINGS)}
        check("a ratio under both ceilings is OK",
              rows["whole-host"]["wall_ok"] and rows["whole-host"]["rss_ok"])
        check("1.5x RSS against a 2.0x ceiling is still OK", rows["-i"]["rss_ok"])
        over = {"-i": {"wall": 1.6, "rss": 1.2}, "whole-host": {"wall": 1.4, "rss": 3.5}}
        rows = {r["case"]: r for r in verdicts(acc, over)}
        check("1.5x RSS against a 1.2x ceiling is OVER — the RSS half can fail",
              not rows["-i"]["rss_ok"] and rows["-i"]["wall_ok"])
        over = {"-i": {"wall": 1.1, "rss": 2.0}, "whole-host": {"wall": 1.4, "rss": 3.5}}
        rows = {r["case"]: r for r in verdicts(acc, over)}
        check("1.2x wall against a 1.1x ceiling is OVER — the wall half can fail too",
              not rows["-i"]["wall_ok"] and rows["-i"]["rss_ok"])

        # `--warn-wall` must block on RSS and NOT on wall, or it is just
        # `--warn` with a longer name. Driven through `run` with stand-in
        # binaries so the exit code itself is what is asserted.
        wall_over = {"-i": {"wall": 0.01, "rss": 99.0},
                     "whole-host": {"wall": 99.0, "rss": 99.0}}
        rss_over = {"-i": {"wall": 99.0, "rss": 0.01},
                    "whole-host": {"wall": 99.0, "rss": 99.0}}
        rc_wall = run("/bin/true", "/bin/true", 2, 2, 1, False, False,
                      ceilings=wall_over, report=quiet, warn_wall=True)
        rc_rss = run("/bin/true", "/bin/true", 2, 2, 1, False, False,
                     ceilings=rss_over, report=quiet, warn_wall=True)
        rc_both = run("/bin/true", "/bin/true", 2, 2, 1, False, True,
                      ceilings=rss_over, report=quiet)
        check("--warn-wall does not block on the wall ceiling", rc_wall == 0)
        check("--warn-wall STILL blocks on the RSS ceiling", rc_rss == 1)
        check("--warn is advisory for both halves", rc_both == 0)

        # A missing binary is an error, not a silent pass.
        try:
            run(os.path.join(work, "nope"), helpers["meter"], 2, 2, 1,
                False, False, report=quiet)
            caught = False
        except GateError as e:
            caught = "not executable" in str(e)
        check("a missing binary is refused, not measured", caught)

    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--oracle", help="the C lsof")
    ap.add_argument("--rust", help="the Rust lsof under test")
    ap.add_argument("--procs", type=int, default=400,
                    help="synthetic processes to spawn (default 400); the cost "
                         "this gate measures is invisible at ambient scale")
    ap.add_argument("--fds", type=int, default=8,
                    help="open fds per synthetic process (default 8)")
    ap.add_argument("--repeats", type=int, default=7,
                    help="interleaved runs per side; the median is used (default 7)")
    ap.add_argument("--warn", action="store_true",
                    help="advisory: report everything and exit 0")
    ap.add_argument("--warn-wall", action="store_true",
                    help="block on the RSS ceiling but not the wall one — the "
                         "CI mode: wall clock on a shared runner cannot support "
                         "a blocking verdict, and peak RSS can")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)

    if a.self_test:
        return _self_test()
    if not (a.oracle and a.rust):
        ap.print_usage(sys.stderr)
        print("error: --oracle and --rust are required (or --self-test)",
              file=sys.stderr)
        return 2
    try:
        return run(a.oracle, a.rust, a.procs, a.fds, a.repeats, a.json, a.warn,
                   warn_wall=a.warn_wall)
    except GateError as e:
        print(f"ERROR: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
