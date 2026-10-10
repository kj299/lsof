#!/usr/bin/env python3
"""walk_race.py -- run one lsof with a `+d`/`+D` entry swapped mid-walk.

A differential fixture for DIVERGENCES 111: what a walk makes of an entry
that is renamed between the listing and its `lstat`, or just after the
`lstat`, and of a directory renamed between its option's `stat` and its
listing. The C describes and identifies an entry by its one `lstat`
(`arg.c:1014,1077`), and the directory by the one `stat` its option made
(`arg.c:876,905,915`); a port that asked again, or took the type from
`d_type`, would see the swapped-in file. Python 3 standard library only.

USAGE (as linux_diff.py's case wrapper runs it, for one side of one case):

    walk_race.py --root DIR --secret FILE --side c|rs SCENARIO BINARY [ARGS...]

`--root` is fixture WRACE's directory: it holds `odir` (a directory the
fixture holds, with a held file `f`), and here the walked directory `V`
and a staging directory `stage` are made afresh for each run, so the C's
run and lsof-rs's start from the same state. `--secret` is a file the
fixture holds on another file system (`/dev/shm`).

SCENARIOS (the path, the delay, what is renamed in during it):

  reg-to-link-after      V/victim, a regular file; after its lstat, a link
                         to --secret takes its name (delay_exit)
  reg-to-link-before     the same, before its lstat (delay_enter)
  reg-to-hardlink-after  V/victim; after its lstat, a hard link to odir/f,
                         on the same file system, takes its name (delay_exit)
  reg-gone-after         V/victim; after its lstat, it is renamed away
                         (delay_exit)
  dir-to-file            V/e, a directory holding `in`; before its lstat, a
                         regular file takes its name (delay_enter)
  file-to-dir            V/e, a regular file; before its lstat, a directory
                         holding `hl`, a hard link to odir/f, takes its name
                         (delay_enter)
  dir-to-link            V/sub, a directory holding `in`; after its lstat, a
                         link to odir takes its name (delay_exit)
  top-to-link            V itself, holding `in`; before its listing is
                         opened, a link to odir takes its name (delay_enter)
  top-gone               V itself; before its listing is opened, it is
                         renamed away (delay_enter)

HOW: the binary runs under `strace -f`, so in lsof-rs's helper too, with
one call on the path (`-P`) delayed by --delay seconds. For an entry it is
the first call of the kind each makes for an `lstat` -- the C's
`newfstatat` (`lstatsafely()`, in its child), lsof-rs's `openat`
(`O_PATH|O_NOFOLLOW`, then a `statx` of the descriptor, which the rename
cannot change). For the directory it is the `openat` of its listing: the
C's first `openat` of it (its `stat` is a `newfstatat`, in its child), and
lsof-rs's second (the first is the `O_PATH` open of the option's `stat`),
as measured with strace. The swap is made when strace says the delay has
begun, never on a timer: `delay_enter` stops the call before it runs, and
strace has by then written the call's name and arguments
(`openat(AT_FDCWD, ".../victim", ...`); `delay_exit` stops it after it
returned, and strace has by then written the whole line, ending
`(DELAYED)`. Seeing a transient stop of the same call cannot be mistaken
for it: with `delay_exit` only the completed line counts, and with
`delay_enter` the Nth call on the path (`when=N`) IS the delayed one, and
the log is counted to it. The delay must be shorter than `-S` (15 seconds
unless a case says otherwise), or the call would time out instead.

A run whose swap did not land inside the delay is not a result: strace
never stopped the call, or this script saw the stop late (a host too
loaded to schedule it, or a stall) and renamed after the call had gone on,
or the run ended first. strace stamps each line with the time its call
began (`-ttt`), which is when the delay began, so the swap must be in place
within half the delay of that stamp, by the same clock. Otherwise this
prints `linux_diff: WRACE: ...` with the side's name and why to stdout and
exits 2, so the two sides differ and the case fails loudly rather than
MATCHing on two runs that raced nothing. Otherwise it exits as the binary
did, with its stdout and stderr untouched.
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import time

# The call each side makes for an entry's `lstat`, and which one on the
# path it is; and for the directory's listing (module doc).
LSTAT = {"c": ("newfstatat", 1), "rs": ("openat", 1)}
LISTING = {"c": ("openat", 1), "rs": ("openat", 2)}

# The path in V ("" for V itself), the delay mode, and the call delayed.
SCENARIOS = {
    "reg-to-link-after": ("victim", "exit", LSTAT),
    "reg-to-link-before": ("victim", "enter", LSTAT),
    "reg-to-hardlink-after": ("victim", "exit", LSTAT),
    "reg-gone-after": ("victim", "exit", LSTAT),
    "dir-to-file": ("e", "enter", LSTAT),
    "file-to-dir": ("e", "enter", LSTAT),
    "dir-to-link": ("sub", "exit", LSTAT),
    "top-to-link": ("", "enter", LISTING),
    "top-gone": ("", "enter", LISTING),
}


def prepare(scenario: str, v: str, stage: str, odir: str, secret: str) -> None:
    """`V` and `stage` as `scenario` starts them, from nothing."""
    # A `top-to-link` run leaves V a link, which rmtree will not remove.
    if os.path.islink(v):
        os.unlink(v)
    for d in (v, stage):
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)
    if scenario.startswith("reg-"):
        with open(os.path.join(v, "victim"), "w") as f:
            f.write("v\n")
    if scenario.startswith("reg-to-link"):
        os.symlink(secret, os.path.join(stage, "new"))
    elif scenario == "reg-to-hardlink-after":
        os.link(os.path.join(odir, "f"), os.path.join(stage, "new"))
    elif scenario == "dir-to-file":
        os.makedirs(os.path.join(v, "e"))
        with open(os.path.join(v, "e", "in"), "w") as f:
            f.write("in\n")
        with open(os.path.join(stage, "new"), "w") as f:
            f.write("f\n")
    elif scenario == "file-to-dir":
        with open(os.path.join(v, "e"), "w") as f:
            f.write("f\n")
        os.makedirs(os.path.join(stage, "new"))
        os.link(os.path.join(odir, "f"), os.path.join(stage, "new", "hl"))
    elif scenario == "dir-to-link":
        os.makedirs(os.path.join(v, "sub"))
        with open(os.path.join(v, "sub", "in"), "w") as f:
            f.write("s\n")
        os.symlink(odir, os.path.join(stage, "new"))
    elif scenario.startswith("top-"):
        with open(os.path.join(v, "in"), "w") as f:
            f.write("in\n")
        if scenario == "top-to-link":
            os.symlink(odir, os.path.join(stage, "new"))


def swap(scenario: str, path: str, stage: str) -> None:
    """Put the staged file where `path` was: one rename where the new file
    may replace the old (a file by a link), two where it may not (a
    directory moves aside first), and one alone where nothing replaces it."""
    new = os.path.join(stage, "new")
    if scenario.startswith(("reg-to-link", "reg-to-hardlink")):
        os.rename(new, path)
        return
    os.rename(path, os.path.join(stage, "old"))
    if os.path.lexists(new):
        os.rename(new, path)


# A line of `strace -f -ttt -o`: the pid, the time the call began, the call.
STAMPED = re.compile(rb"^\d+ +(\d+\.\d+) +(.*)$")


def delay_began(trace: str, path: str, mode: str, call: str, when: int = 1) -> float | None:
    """When the delayed call began, by strace's stamp, if strace's log says
    it is stopped (module doc); None while it does not. With `delay_exit`
    only the completed line counts, and its stamp is the call's entry, a
    moment before the delay; with `delay_enter` the `when`th call on the
    path is the delayed one, stamped as the delay begins."""
    try:
        with open(trace, "rb") as f:
            lines = f.read().splitlines()
    except OSError:
        return None
    seen = 0
    for line in lines:
        m = STAMPED.match(line)
        if m is None:
            continue
        text = m.group(2)
        if mode == "exit":
            if text.endswith(b"(DELAYED)"):
                return float(m.group(1))
        elif text.startswith(f"{call}(".encode()) and f'"{path}"'.encode() in text:
            seen += 1
            if seen == when:
                return float(m.group(1))
    return None


def missed(began: float, swapped: float, delay: float) -> str | None:
    """Why a swap in place at `swapped` raced nothing, or None if it landed
    in the first half of a `delay` that began at `began` (both wall-clock
    seconds). Measured from strace's stamp, not from when this script saw
    the stop: a swapper that saw it late renamed after the call went on."""
    late = swapped - began
    if late > delay / 2:
        return f"the swap was made {late:.2f}s into a {delay}s delay"
    return None


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", required=True)
    ap.add_argument("--secret", required=True)
    ap.add_argument("--side", required=True, choices=sorted(LSTAT))
    ap.add_argument("--delay", type=float, default=3.0)
    ap.add_argument("--strace", default="strace")
    ap.add_argument("scenario", choices=sorted(SCENARIOS))
    ap.add_argument("binary")
    ap.add_argument("args", nargs=argparse.REMAINDER)
    a = ap.parse_args(argv)
    v = os.path.join(a.root, "V")
    stage = os.path.join(a.root, "stage")
    odir = os.path.join(a.root, "odir")
    name, mode, calls = SCENARIOS[a.scenario]
    path = os.path.join(v, name) if name else v
    call, when = calls[a.side]
    trace = os.path.join(a.root, f"trace.{a.side}")
    prepare(a.scenario, v, stage, odir, a.secret)
    try:
        os.unlink(trace)
    except FileNotFoundError:
        pass
    delay_us = int(a.delay * 1_000_000)
    sys.stdout.flush()
    tracer = subprocess.Popen(
        [
            a.strace, "-f", "-qq", "-ttt", "-o", trace, "-P", path,
            "-e", "signal=none",
            "-e", f"trace={call}",
            "-e", f"inject={call}:delay_{mode}={delay_us}:when={when}",
            a.binary, *a.args,
        ]
    )
    why = None
    began = None
    while tracer.poll() is None:
        began = delay_began(trace, path, mode, call, when)
        if began is not None:
            swap(a.scenario, path, stage)
            why = missed(began, time.time(), a.delay)
            break
        time.sleep(0.002)
    rc = tracer.wait()
    if began is None:
        if delay_began(trace, path, mode, call, when) is None:
            why = f"strace never stopped the {call} of {path}"
        else:
            why = "the run ended before the swap was made"
    if why is not None:
        print(f"linux_diff: WRACE: {a.side}: {a.scenario}: {why}", flush=True)
        return 2
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
