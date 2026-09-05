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
             4 (a file whose NAME holds one of every hostile character class,
             read), 5 (directory, read) and 6 (FIFO, read/write); stdio on
             /dev/null
  fixture B  a listening TCP socket, a bound UDP socket, and four AF_UNIX
             sockets covering every state lsof names — listening, the two
             halves of a connected pair, and one never connected; stdio on
             /dev/null
  fixture C  a sleeper whose COMMAND is hostile ASCII: an ANSI clear-screen,
             CR, space, backslash, DEL, TAB, ^A
  fixture D  the same plus é (printable) and U+009B (the 8-bit CSI) — the
             non-ASCII classes, which the C sizes differently from how it
             prints them (see the matrix)
  fixture E  a process holding one live mapped library and one that has been
             deleted while still mapped — the `mem` and `DEL` rows that come
             from /proc/<pid>/maps rather than from an fd
  fixture F  a process holding one of each lock character Linux can report:
             whole-file and partial, read and write (`R r W w`)
  fixture H  a sleeper whose command name is 15 characters, so the COMMAND
             column's default nine-character cap is visible at all
  fixture G  a process holding one of each anonymous-inode kind lsof names —
             eventpoll, eventfd, pidfd, inotify — which have no filesystem
             identity and are typed `a_inode`

C and D exist because COMMAND and NAME are the two cells a local user chooses
outright (a process names itself; anyone can name a file), and the C escapes
every byte isprint() rejects before printing them. lsof-rs printed them raw
until the `proc_status` fuzz target pointed at it (DIVERGENCES.md #10). The
comm comes from exec'ing a symlink to `sleep` whose basename is the hostile
string — the kernel takes comm from the exec'd file's name, so no prctl and no
helper binary are needed, and the string is passed as bytes so no locale is
consulted on the way in.

All four are stable for the run's duration and hold nothing that changes size,
so the two binaries see identical state. Because PIDs, inodes and devices are
then identical on both sides, the kit's default normalization (whitespace only)
is all that is needed; `--mask-numbers` is deliberately NOT used — it would hide
exactly the cells this gate exists to compare.

Both binaries run with LC_ALL=C.UTF-8. The C calls setlocale(LC_CTYPE, "") and
its safestrprt() passes a printable multibyte character through only in a
UTF-8 locale (in POSIX every byte >= 0x80 is printed as a hex escape); lsof-rs
is locale-independent and matches the UTF-8 behavior. The runner's default
locale is not part of the contract, so it is pinned here, and its absence is
infra.

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

    def __init__(self, name: str, argv: list, cwd: str, expect_fds: int, expect_comm: bytes | None = None):
        self.name = name
        self.argv = argv
        self.cwd = cwd
        self.expect_fds = expect_fds
        # A fixture that `exec`s its final image is two processes in turn under
        # one pid; fds 0-2 exist from the first instant, so an fd count alone
        # can declare a bash-that-has-not-exec'd-yet ready. When set, the comm
        # must match too.
        self.expect_comm = expect_comm
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
            if fd_count(self.pid) >= self.expect_fds and (
                self.expect_comm is None or comm(self.pid) == self.expect_comm
            ):
                return
            time.sleep(0.02)
        infra(
            f"fixture {self.name} did not reach {self.expect_fds} fds"
            + (f" as {self.expect_comm!r}" if self.expect_comm else "")
            + " within 3s"
        )

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


def comm(pid: int) -> bytes:
    """The raw comm: /proc/<pid>/comm is unescaped bytes plus one newline."""
    try:
        with open(f"/proc/{pid}/comm", "rb") as f:
            return f.read().removesuffix(b"\n")
    except OSError:
        return b""


# One of every character class the C's safepup() treats differently, in a
# comm (<= 15 bytes, TASK_COMM_LEN - 1) and in a file name. What the C prints
# for each is pinned byte for byte in lsof-core's golden tests
# (`hostile_names_are_escaped_the_way_the_c_prints_them`); this run checks the
# two binaries against each other on the live thing.
HOSTILE_ASCII_COMM = "h\x1b[2J\r \\\x7f\t\x01z"  # ESC-sequence CR space \ DEL TAB ^A
HOSTILE_UTF8_COMM = "h\x1b[2J\r \\\x7f\téz"  # + é (printable) + U+009B (C1 CSI)
HOSTILE_FILE = "n\x1b[31m\r\t \\\x7fé.txt"
LOCALE = "C.UTF-8"


def hostile_sleeper(name: str, work: str, comm: str) -> Fixture:
    """A `sleep` whose comm is `comm`: exec'd through a symlink of that name.

    Bytes, not str, on the way to the kernel: the string must arrive as UTF-8
    whatever Python decided the filesystem encoding is (a POSIX locale would
    otherwise reject the é). `bash -c CMD ARG0` makes ARG0 `$0`, so the
    quoting-hostile name never appears inside the shell text."""
    cdir = os.path.join(work, name)
    os.makedirs(cdir)
    link = os.path.join(cdir.encode(), comm.encode("utf-8"))
    os.symlink(shutil.which("sleep"), link)
    return Fixture(
        f"{name}(comm)",
        [b"bash", b"-c", b'exec "$0" 600', link],
        cwd=cdir,
        expect_fds=3,
        expect_comm=comm.encode("utf-8"),
    )


def mapping_holder(work: str) -> Fixture:
    """A process with one live mapped library and one deleted-but-mapped one.

    The deleted mapping is the `DEL` row -- lsof's canonical "who is still
    running against the old shared object after an upgrade" answer -- and it is
    the one maps row that cannot be stat'd, so it exercises the branch that
    takes its device and inode from the maps line instead. Both copies carry a
    space in the name, because a maps path is the rest of the line and must not
    be split on whitespace."""
    mdir = os.path.join(work, "maps")
    os.makedirs(mdir)
    live = os.path.join(mdir, "live lib.so")
    gone = os.path.join(mdir, "gone lib.so")
    shutil.copy("/usr/lib/x86_64-linux-gnu/libm.so.6", live)
    shutil.copy("/usr/lib/x86_64-linux-gnu/libc.so.6", gone)
    py = (
        "import ctypes,os,time\n"
        "a=ctypes.CDLL(%r)\n"
        "b=ctypes.CDLL(%r)\n"
        "os.unlink(%r)\n"
        "open(os.path.join(%r,'ready'),'w').close()\n"
        "time.sleep(600)\n" % (live, gone, gone, mdir)
    )
    return Fixture("E(mappings)", [sys.executable, "-c", py], cwd=mdir, expect_fds=3)


def lock_holder(work: str) -> Fixture:
    """A process holding one of each lock character lsof can print on Linux.

    /proc/locks reports only shared-vs-exclusive and the byte range, which is
    exactly the four characters `R`, `r`, `W`, `w` -- whole-file read, partial
    read, whole-file write, partial write. The partial locks are what separate
    the lower-case characters from the upper-case ones, so both are held."""
    ldir = os.path.join(work, "locks")
    os.makedirs(ldir)
    py = (
        "import fcntl,os,time\n"
        "def f(n):\n"
        "    h=open(os.path.join(%r,n),'w+'); h.write('x'*100); h.flush(); return h\n"
        "wf=f('write-full'); wp=f('write-part'); rf=f('read-full'); rp=f('read-part')\n"
        "fcntl.lockf(wf, fcntl.LOCK_EX)\n"
        "fcntl.lockf(wp, fcntl.LOCK_EX, 5, 10)\n"
        "fcntl.lockf(rf, fcntl.LOCK_SH)\n"
        "fcntl.lockf(rp, fcntl.LOCK_SH, 5, 10)\n"
        "open(os.path.join(%r,'ready'),'w').close()\n"
        "time.sleep(600)\n" % (ldir, ldir)
    )
    return Fixture("F(locks)", [sys.executable, "-c", py], cwd=ldir, expect_fds=7)


def anon_inode_holder(work: str) -> Fixture:
    """A process holding one of each anonymous-inode kind lsof names.

    The kernel gives these fds a link target of `anon_inode:<kind>` and no
    filesystem identity at all. lsof types them `a_inode` and prints the kind,
    substituting an identity from fdinfo for the three kinds that carry one:
    an eventpoll's watched fds, an eventfd's id, a pidfd's target pid. An
    `inotify` fd is here as the control: it has no identity and prints bare.

    Two epoll registrations, not one, because the C sorts the fd list and
    fdinfo lists it most-recent-first — with a single entry the sort would be
    untested."""
    adir = os.path.join(work, "anon")
    os.makedirs(adir)
    py = (
        "import ctypes,os,select,socket,time\n"
        "ep=select.epoll()\n"
        "a,_b=socket.socketpair(); c,_d=socket.socketpair()\n"
        "ep.register(a); ep.register(c)\n"
        "ev=os.eventfd(7)\n"
        "pf=os.pidfd_open(os.getpid())\n"
        "ino=ctypes.CDLL('libc.so.6').inotify_init()\n"
        "open(os.path.join(%r,'ready'),'w').close()\n"
        "time.sleep(600)\n" % adir
    )
    return Fixture("G(anon inodes)", [sys.executable, "-c", py], cwd=adir, expect_fds=3)


LONG_COMM = "abcdefghijklmno"  # 15 chars, the Linux comm ceiling


def long_command_holder(work: str) -> Fixture:
    """A sleeper whose command name is longer than the COMMAND column's cap.

    Every other fixture's command is `sleep`, `python3` or a hostile string, so
    none of them can show what a plain command does at the default width -- the
    first three are under the nine-character cap and the hostile ones are
    ledgered for a different reason. Removing the cap left the whole suite green
    until this fixture existed, which is the LESSONS #8 shape: a gate that
    cannot fail is not a gate."""
    cdir = os.path.join(work, "longcmd")
    os.makedirs(cdir)
    binary = os.path.join(cdir, LONG_COMM)
    shutil.copy("/bin/sleep", binary)
    return Fixture(
        "H(long command)",
        [binary.encode(), b"600"],
        cwd=cdir,
        expect_fds=3,  # 0,1,2
        expect_comm=LONG_COMM.encode(),
    )


def make_fixtures(
    work: str,
) -> tuple[
    Fixture, Fixture, Fixture, Fixture, Fixture, Fixture, Fixture, Fixture
]:
    fdir = os.path.join(work, "files")
    os.makedirs(os.path.join(fdir, "sub"))
    with open(os.path.join(fdir, "f.txt"), "w") as f:
        f.write("fixture data\n")
    os.mkfifo(os.path.join(fdir, "fifo"))
    hostile = os.path.join(fdir.encode(), HOSTILE_FILE.encode("utf-8"))
    with open(hostile, "wb") as f:
        f.write(b"x\n")
    # A second name for f.txt, deliberately OUTSIDE the fixture's own
    # directory. lsof matches a path argument by the file's identity, not its
    # name, so querying this link must find the fd opened under the other one
    # -- but leaving it inside `files/` would put two names for one inode into
    # the `+d`/`+D` expansions, where the C binds a row to whichever name it
    # matched first and reports the other as unlocated. That is its own
    # divergence (DIVERGENCES.md #17); keeping the link out of the tree lets
    # the `+d`/`+D` cases measure one-level-vs-recursive, which is their job.
    linkdir = os.path.join(work, "hardlink")
    os.makedirs(linkdir)
    os.link(os.path.join(fdir, "f.txt"), os.path.join(linkdir, "hard.txt"))
    # exec keeps the pid stable (no bash parent lingering as the "process"), and
    # <> on the FIFO opens it read/write so the open cannot block. The hostile
    # file name travels as `$1`, outside the shell text.
    a = Fixture(
        "A(files)",
        [b"bash", b"-c", b'exec 3>f.txt 4<"$1" 5<sub 6<>fifo && exec sleep 600', b"fixture-a", hostile],
        cwd=fdir,
        expect_fds=7,  # 0,1,2 + 3,4,5,6
        expect_comm=b"sleep",
    )
    sdir = os.path.join(work, "sockets")
    os.makedirs(sdir)
    # The TCP listener's port is written to a file so the matrix can name it
    # ({PORT}). An OR case is only deterministic when every one of its
    # selectors names a fixture, and "-iTCP:<port>" is the one file-level
    # selector that can (see linux-matrix.toml, or-semantics-*).
    # The AF_UNIX socket states lsof can report are LISTEN (SO_ACCEPTCON, not a
    # state at all), CONNECTED (the accepted pair) and UNCONNECTED (a socket
    # that was never connected) — one fd each, because the C reads them from
    # two different columns and a fixture with only a listener cannot tell a
    # correct mapping from one that always says LISTEN.
    py = (
        "import socket,os,time\n"
        "t=socket.socket(); t.bind(('127.0.0.1',0)); t.listen(1)\n"
        "open(os.path.join(%r,'port'),'w').write(str(t.getsockname()[1]))\n"
        "u=socket.socket(socket.AF_UNIX); u.bind(os.path.join(%r,'u.sock')); u.listen(1)\n"
        "cl=socket.socket(socket.AF_UNIX); cl.connect(os.path.join(%r,'u.sock'))\n"
        "acc,_ = u.accept()\n"
        "an=socket.socket(socket.AF_UNIX)\n"
        "g=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); g.bind(('127.0.0.1',0))\n"
        "time.sleep(600)\n" % (sdir, sdir, sdir)
    )
    # 0,1,2 + TCP listener, unix listener, unix client, unix accepted,
    # unix unconnected, UDP.
    b = Fixture("B(sockets)", [sys.executable, "-c", py], cwd=sdir, expect_fds=9)
    c = hostile_sleeper("C", work, HOSTILE_ASCII_COMM)
    d = hostile_sleeper("D", work, HOSTILE_UTF8_COMM)
    e = mapping_holder(work)
    f = lock_holder(work)
    g = anon_inode_holder(work)
    h = long_command_holder(work)
    return a, b, c, d, e, f, g, h


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


def preflight_locale() -> None:
    """The oracle's escaping of non-ASCII is locale-dependent; a runner without
    the pinned locale would make the C print `\\xc3\\xa9` for é and manufacture
    a divergence that is not the port's. That is infra, not a verdict."""
    try:
        p = subprocess.run(["locale", "-a"], capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as e:
        infra(f"cannot list locales: {e}")
    have = {ln.strip().lower().replace("-", "") for ln in p.stdout.decode(errors="replace").splitlines()}
    if LOCALE.lower().replace("-", "") not in have:
        infra(f"locale {LOCALE} is not installed (locale -a); the C oracle is compared under it")


# ---------------------------------------------------------------------- main


def run(args) -> int:
    if not os.path.isfile(KIT_RUNNER):
        infra(f"kit runner not found at {KIT_RUNNER}")
    preflight(args.oracle, "oracle (C lsof)")
    preflight(args.rust, "rust (lsof-rs)")
    preflight_locale()

    work = tempfile.mkdtemp(prefix="lsof-rs-diff-")
    fixtures = make_fixtures(work)
    a, b, c, d, e, lk, anon, longcmd = fixtures
    try:
        for fx in fixtures:
            fx.start()
        # E's mappings land after its fds do; it writes `ready` once both
        # libraries are loaded and one is unlinked. Waiting on the marker
        # keeps a half-loaded fixture from producing a matching-but-partial
        # table on both sides, which would be a false green (LESSONS #6).
        for fx in (e, lk, anon):
            ready = os.path.join(fx.cwd, "ready")
            deadline = time.monotonic() + 5.0
            while not os.path.exists(ready) and time.monotonic() < deadline:
                if fx.proc is not None and fx.proc.poll() is not None:
                    infra(f"fixture {fx.name} exited early (rc={fx.proc.returncode})")
                time.sleep(0.02)
            if not os.path.exists(ready):
                infra(f"fixture {fx.name} was not ready within 5s")
        # {FILE} is a path only fixture A holds; {PORT} is fixture B's
        # listener. Both name exactly one fixture, which is what makes the
        # un-`-a`ed OR cases deterministic.
        port_file = os.path.join(b.cwd, "port")
        deadline = time.monotonic() + 3.0
        while not os.path.exists(port_file) and time.monotonic() < deadline:
            time.sleep(0.02)
        try:
            with open(port_file) as f:
                port = f.read().strip()
        except OSError as e:
            infra(f"fixture B did not publish its listener port: {e}")
        if not port.isdigit():
            infra(f"fixture B published a non-numeric port: {port!r}")
        cases = render_matrix(
            args.matrix,
            {
                "A": str(a.pid),
                "B": str(b.pid),
                "C": str(c.pid),
                "D": str(d.pid),
                "E": str(e.pid),
                "F": str(lk.pid),
                "G": str(anon.pid),
                "H": str(longcmd.pid),
                "FILE": os.path.join(a.cwd, "f.txt"),
                "HARDLINK": os.path.join(work, "hardlink", "hard.txt"),
                "ADIR": a.cwd,
                "ASUB": os.path.join(a.cwd, "sub"),
                "PORT": port,
            },
        )
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
        print(
            f"linux_diff: fixtures A={a.pid} (files, cwd {a.cwd}) B={b.pid} (sockets) "
            f"C={c.pid} D={d.pid} (hostile comms); LC_ALL={LOCALE}"
        )
        print(f"linux_diff: {len(cases)} cases -> {os.path.relpath(KIT_RUNNER, REPO)}")
        # The kit runner hands its own environment to both binaries.
        p = subprocess.run(cmd, env={**os.environ, "LC_ALL": LOCALE})
        if p.returncode not in (0, 1):
            # The kit runner sys.exit()s with a message on its own infra errors
            # (missing binary, unparseable matrix); those are not verdicts.
            infra(f"kit runner exited {p.returncode}")
        return p.returncode
    finally:
        for fx in fixtures:
            fx.stop()
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

        # The hostile comm really reaches the kernel, byte for byte: the
        # symlink route gives a comm equal to the basename, and the kernel
        # escapes only `\n` and `\` in /proc/<pid>/status (`\` -> `\\`).
        for label, comm in [("ascii", HOSTILE_ASCII_COMM), ("utf8", HOSTILE_UTF8_COMM)]:
            check(f"{label} comm fits TASK_COMM_LEN", len(comm.encode("utf-8")) <= 15)
            hs = hostile_sleeper(label, td, comm)
            hs.start()
            with open(f"/proc/{hs.pid}/status", "rb") as f:
                name = f.readline()
            hs.stop()
            expect = b"Name:\t" + comm.encode("utf-8").replace(b"\\", b"\\\\") + b"\n"
            check(f"{label} comm is the fixture's comm", name == expect)

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
