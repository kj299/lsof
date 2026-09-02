#!/usr/bin/env python3
"""lsof-rs Linux differential — mode 1 of the porting kit: the real C oracle.

On Linux the reference implementation runs on the same host as the port, so
this is the differential the Windows side structurally cannot have: build the C
`lsof` from THIS tree (the exact source being ported), run it and lsof-rs
against one fixture process at the same instant, and diff through the kit's
`diff_run.py`. Every fidelity finding in phases L0 and L1 came from doing this
by hand; this makes it a gate.

Why a wrapper at all: the kit's runner has no per-case fixture hook (only argv,
stdin, env, timeout), and lsof's interesting behavior is about *which process*
it is pointed at. So this script stands up two self-owned fixture processes,
substitutes their PIDs into the matrix, and hands the rendered matrix to the kit
runner unchanged. Nothing here re-implements comparison, normalization, or the
ledger — those are the kit's, on purpose.

  fixture A  a sleeper with a known cwd and fds 3 (regular file, write),
             5 (directory, read) and 6 (FIFO, read/write); stdio on /dev/null
  fixture B  a listening TCP socket, a bound UDP socket and a listening
             AF_UNIX socket; stdio on /dev/null

Both are stable for the run's duration and hold nothing that changes size, so
the two binaries see identical state. Because PIDs, inodes and devices are
then identical on both sides, the kit's default normalization (whitespace only)
is all that is needed; `--mask-numbers` is deliberately NOT used — it would hide
exactly the cells this gate exists to compare.

Every case passes `-a`. lsof ORs its list options unless `-a` ANDs them
(Lsof.8: "list options that are specifically stated are ORed"); lsof-rs applies
file-level selectors unconditionally. That divergence is recorded in
DIVERGENCES.md and exercised by one deliberately un-`-a`'d case there; every
other case must mean the same thing to both binaries, so `-a` is not optional.

Exit contract (LESSONS #6 — a broken harness must never read as a port bug):
  0  every case MATCH or DIVERGE(ledgered)
  1  an unledgered divergence (the kit runner's verdict, passed through)
  2  infra: a binary missing or not runnable, a fixture that failed to come
     up, the kit runner not found — anything that is not the port's fault

Usage:
  linux_diff.py --oracle PATH --rust PATH [--matrix linux-matrix.toml]
                [--ledger ../DIVERGENCES.md] [--keep-fixtures] [--json]
  linux_diff.py --self-test
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
KIT_RUNNER = os.path.join(REPO, "porting-kit", "harnesses", "differential", "diff_run.py")

EXIT_INFRA = 2


def infra(msg: str) -> "NoReturn":  # type: ignore[name-defined]
    print(f"linux_diff: INFRA: {msg}", file=sys.stderr)
    sys.exit(EXIT_INFRA)


# ------------------------------------------------------------------ fixtures


class Fixture:
    """One self-owned process whose open files are the thing under test."""

    def __init__(self, name: str, argv: list[str], cwd: str, expect_fds: int):
        self.name = name
        self.argv = argv
        self.cwd = cwd
        self.expect_fds = expect_fds
        self.proc: subprocess.Popen | None = None

    @property
    def pid(self) -> int:
        assert self.proc is not None
        return self.proc.pid

    def start(self) -> None:
        self.proc = subprocess.Popen(
            self.argv,
            cwd=self.cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Wait until the kernel shows the fds we expect rather than sleeping and
        # hoping: a fixture that is not yet set up would make BOTH binaries
        # report a partial table, which still MATCHes — a false green.
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                infra(f"fixture {self.name} exited early (rc={self.proc.returncode})")
            if fd_count(self.pid) >= self.expect_fds:
                return
            time.sleep(0.02)
        infra(f"fixture {self.name} did not reach {self.expect_fds} fds within 3s")

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.send_signal(signal.SIGTERM)
                self.proc.wait(timeout=2)
            except Exception:
                self.proc.kill()


def fd_count(pid: int) -> int:
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        return 0


def make_fixtures(work: str) -> tuple[Fixture, Fixture]:
    fdir = os.path.join(work, "files")
    os.makedirs(os.path.join(fdir, "sub"))
    with open(os.path.join(fdir, "f.txt"), "w") as f:
        f.write("fixture data\n")
    os.mkfifo(os.path.join(fdir, "fifo"))
    # exec keeps the pid stable (no bash parent lingering as the "process"), and
    # <> on the FIFO opens it read/write so the open cannot block.
    a = Fixture(
        "A(files)",
        ["bash", "-c", "exec 3>f.txt 5<sub 6<>fifo && exec sleep 600"],
        cwd=fdir,
        expect_fds=6,  # 0,1,2 + 3,5,6
    )
    sdir = os.path.join(work, "sockets")
    os.makedirs(sdir)
    py = (
        "import socket,os,time\n"
        "t=socket.socket(); t.bind(('127.0.0.1',0)); t.listen(1)\n"
        "u=socket.socket(socket.AF_UNIX); u.bind(os.path.join(%r,'u.sock')); u.listen(1)\n"
        "g=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); g.bind(('127.0.0.1',0))\n"
        "time.sleep(600)\n" % sdir
    )
    b = Fixture("B(sockets)", [sys.executable, "-c", py], cwd=sdir, expect_fds=6)  # 0,1,2 + 3 sockets
    return a, b


# -------------------------------------------------------------------- matrix


def render_matrix(template_path: str, subs: dict[str, str]) -> list[dict]:
    """Load the TOML template and substitute {A}/{B} tokens in every arg."""
    try:
        import tomllib
    except ImportError:
        infra("Python 3.11+ is required (tomllib), same as the kit runner")
    with open(template_path, "rb") as f:
        data = tomllib.load(f)
    cases = data.get("case", [])
    if not cases:
        infra(f"no [[case]] entries in {template_path}")
    out = []
    for c in cases:
        args = [substitute(str(a), subs) for a in c.get("args", [])]
        rendered = dict(c)
        rendered["args"] = args
        out.append(rendered)
    return out


def substitute(s: str, subs: dict[str, str]) -> str:
    for k, v in subs.items():
        s = s.replace("{" + k + "}", v)
    return s


# ----------------------------------------------------------------- preflight


def preflight(binary: str, label: str) -> None:
    """A binary that cannot even print its version is infra, not a divergence."""
    if not (os.path.isfile(binary) and os.access(binary, os.X_OK)):
        infra(f"{label} binary missing or not executable: {binary}")
    try:
        p = subprocess.run([binary, "-v"], capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as e:
        infra(f"{label} binary failed to run -v: {e}")
    if p.returncode != 0:
        infra(f"{label} `-v` exited {p.returncode}: {p.stderr.decode(errors='replace')[:200]}")


# ---------------------------------------------------------------------- main


def run(args) -> int:
    if not os.path.isfile(KIT_RUNNER):
        infra(f"kit runner not found at {KIT_RUNNER}")
    preflight(args.oracle, "oracle (C lsof)")
    preflight(args.rust, "rust (lsof-rs)")

    work = tempfile.mkdtemp(prefix="lsof-rs-diff-")
    a, b = make_fixtures(work)
    try:
        a.start()
        b.start()
        cases = render_matrix(args.matrix, {"A": str(a.pid), "B": str(b.pid)})
        matrix_json = os.path.join(work, "matrix.json")
        with open(matrix_json, "w") as f:
            json.dump({"case": cases}, f, indent=1)
        cmd = [
            sys.executable, KIT_RUNNER,
            "--oracle", args.oracle,
            "--rust", args.rust,
            "--matrix", matrix_json,
            "--ledger", args.ledger,
        ]
        if args.json:
            cmd.append("--json")
        print(f"linux_diff: fixtures A={a.pid} (files, cwd {a.cwd}) B={b.pid} (sockets)")
        print(f"linux_diff: {len(cases)} cases -> {os.path.relpath(KIT_RUNNER, REPO)}")
        p = subprocess.run(cmd)
        if p.returncode not in (0, 1):
            # The kit runner sys.exit()s with a message on its own infra errors
            # (missing binary, unparseable matrix); those are not verdicts.
            infra(f"kit runner exited {p.returncode}")
        return p.returncode
    finally:
        a.stop()
        b.stop()
        if args.keep_fixtures:
            print(f"linux_diff: fixtures kept under {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)


def self_test() -> int:
    ok = True

    def check(name: str, cond: bool) -> None:
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name)
        ok = ok and cond

    check("substitute replaces every token, leaves the rest", substitute("-p {A} -x {B} {A}", {"A": "7", "B": "9"}) == "-p 7 -x 9 7")
    check("substitute is inert without tokens", substitute("-nP", {"A": "7"}) == "-nP")

    with tempfile.TemporaryDirectory() as td:
        tpl = os.path.join(td, "m.toml")
        with open(tpl, "w") as f:
            f.write('[[case]]\nname="x"\nargs=["-a","-p","{A}"]\n[[case]]\nname="y"\nargs=["-p","{B}"]\n')
        cases = render_matrix(tpl, {"A": "11", "B": "22"})
        check("render_matrix substitutes per case", [c["args"] for c in cases] == [["-a", "-p", "11"], ["-p", "22"]])
        check("render_matrix keeps names", [c["name"] for c in cases] == ["x", "y"])

        # A fixture that really comes up: fd_count sees the expected fds.
        fx = Fixture("t", ["bash", "-c", "exec 3</dev/null && exec sleep 5"], cwd=td, expect_fds=4)
        fx.start()
        check("fixture start waits for the expected fd count", fd_count(fx.pid) >= 4)
        fx.stop()
        check("fixture stop terminates it", fx.proc.poll() is not None)

        # Infra paths exit 2, never 0 or 1.
        for label, fn in [
            ("missing binary", lambda: preflight(os.path.join(td, "nope"), "t")),
            ("early-exit fixture", lambda: Fixture("t", ["bash", "-c", "exit 3"], cwd=td, expect_fds=9).start()),
        ]:
            try:
                fn()
                check(f"{label} -> exit 2", False)
            except SystemExit as e:
                check(f"{label} -> exit 2", e.code == EXIT_INFRA)

    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--oracle", help="the C lsof built from this tree")
    ap.add_argument("--rust", help="lsof-rs binary under test")
    ap.add_argument("--matrix", default=os.path.join(HERE, "linux-matrix.toml"))
    ap.add_argument("--ledger", default=os.path.join(HERE, "..", "DIVERGENCES.md"))
    ap.add_argument("--keep-fixtures", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    if not (a.oracle and a.rust):
        ap.error("--oracle and --rust are required (or --self-test)")
    if sys.platform != "linux":
        infra("this differential needs Linux (/proc and the C oracle)")
    return run(a)


if __name__ == "__main__":
    sys.exit(main())
