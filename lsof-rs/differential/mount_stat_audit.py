#!/usr/bin/env python3
"""mount_stat_audit.py -- which mount directories each lsof `stat`s, traced.

DIVERGENCES 110: the C reads its mount table, and `stat`s each mount
directory in it, only on a run that needs it (`Selinet`, `dproc.c:670`), never
an `-e`/`+e` mount and never an `autofs` one (`dmnt.c`), and once each. The
differential compares what the two print; this compares what they ASK the
file system, which is what decides whether a mount that does not answer, or
an automount point, can cost a run anything. For each argument list below,
both binaries run under `strace -ff`, and it asserts:

  * the C and lsof-rs `stat` the same mount directories, each as many times:
    once, but for a directory the C cannot `stat`, which it tries again for
    each later row of it (`dmnt.c` records no row it could not `stat`), and
    lsof-rs with it, so a count above one is no fault where the C's is the
    same (two rows of `/dev/shm` the user cannot `stat`); and a path argument
    that is itself a mount point, `-f -- /`, is `stat`ed once more by both,
    as a file;
  * `-i` alone, `-Z`, and every run the C reads no table on, `stat`s none;
  * every lsof-rs `stat` of one is an `O_PATH` open (and a `statx` of the
    descriptor), which mounts no automount point (`safefs::stat_now`), never
    a `stat` by name;
  * the same prefixes of the directories are read through `readlink`, as a
    set, not as many times: lsof-rs reads a prefix again only past where a
    reading found a link (`lsof_core::readlink`), where the C reads every
    prefix again each time (each prefix of a private table's base, measured:
    98 readings by the C, 40 by lsof-rs; a link loop's parent, 22 and 2);
    and lsof-rs's helper, before a call on a path that may lead through
    `/proc/self` (one holding `..`), reads that path's prefixes itself, to
    name `/proc/self` as lsof's (DIVERGENCES 89): a mount source `rel/x ->
    ../blkdev` costs the C 2, 1 and 1 readings of `rel`, `rel/..` and
    `rel/../blkdev`, lsof-rs 4, 3 and 2. Neither changes what is printed,
    and each of lsof-rs's calls is bounded by `-S`.

A second part audits the per-file calls (DIVERGENCES 124). With an NFS
mount listed, the C makes every per-file `stat` -- a process's `cwd`,
`root` and `exe`, each fd's `lstat` and `stat`, each mapped file -- through
`statsafely()`, in its child, and lsof-rs through its helper; without one,
both make them in themselves. For each argument list in `NFS_CASES`, run in
a mount namespace of its own with a table that lists `srv:/export` on a
directory here bound over the `/proc/mounts` link (as the differential's
`LSOF_DIFF_MT=nfs` does), it asserts that the C's child and lsof-rs's helper
make the same per-file calls on the sleeper's `/proc/PID/` links and mapped
files, each as many times, that neither binary makes one in itself, and,
without the line, that lsof-rs's helper makes none (and that `-b` makes
none at all). Needs root and `unshare`, else that part is skipped, saying
so. Not compared: the C's `get_unix()` `stat`s the path of every bound
AF_UNIX socket `/proc/net/unix` lists, through its child, where lsof-rs
`stat`s a socket's path only when a path argument may find it by it, and
then through its helper; the sleeper holds no socket.

A call is counted as walk111's `a_walk_entry_is_stated_once` counts it: an
`O_PATH` `openat` is one `stat` (an `lstat` with `O_NOFOLLOW`), whether it
succeeds or not, matched by its exact path. The counts are of the processes
lsof starts to make them in, the C's child (`doinchild()`) and lsof-rs's
helper: the C's own process `stat`s `/dev` for `DEVDEV_PATH` (`main.c`)
and, through glibc's name service, `/`, on every run, neither a read of the
table. A `stat` by name is looked for in every process. The mount
directories are this process's `/proc/self/mounts`, decoded.

Usage:
  mount_stat_audit.py --oracle PATH --rust PATH
  mount_stat_audit.py --self-test
Exit: 0 = every assertion held, or no strace here to trace with (said, as a
skip); 1 = an assertion failed; 2 = usage, or a binary would not run.
"""
from __future__ import annotations

import argparse
import collections
import glob
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time

# The argument lists, `{P}` a sleeper this script starts in `/`. Every one
# carries `-n -P`, so the C asks the name service nothing (glibc's NSS
# `stat`s `/` on its way to `nsswitch.conf`), and `-w`, so a mount the user
# cannot `stat` costs no line. The ones marked False read no table in the C:
# `-i` alone, and `-Z` where SELinux is not enabled, which the C refuses at
# the option and lsof-rs decides from the table's types, read as text
# (`Backend::has_mount_type`): no table, no call.
CASES: list[tuple[list[str], bool]] = [
    (["-i", ":22"], False),
    (["-i"], False),
    (["-i", "-s", "TCP:LISTEN"], False),
    (["-t", "-i"], False),
    (["-a", "-i"], False),
    (["-i", "-p", "^1"], False),
    (["-a", "-d", "cwd", "-p", "{P}"], True),
    (["-U"], True),
    (["-N"], True),
    (["-t", "-a", "-d", "cwd", "-p", "{P}"], True),
    (["-i", "-a", "-p", "{P}"], True),
    (["-i", "-K"], True),
    (["-i", "-d", "3"], True),
    (["-i", "+L1"], True),
    (["-s", "TCP:LISTEN"], True),
    (["-e", "/dev/shm", "-a", "-d", "cwd", "-p", "{P}"], True),
    (["+e", "/dev/shm", "-a", "-d", "cwd", "-p", "{P}"], True),
    (["-i", "-e", "/dev/shm"], True),
    (["/"], True),
    (["-f", "--", "/"], True),
    (["+f", "--", "/dev"], True),
    (["-Z", "-a", "-d", "cwd", "-p", "{P}"], False),
]

# The per-file part's argument lists, run with an NFS mount listed and
# without; `{P}` is the sleeper, which holds `/etc/hostname` on fd 0 and a
# file in the listed directory on fd 3.
NFS_CASES: list[list[str]] = [
    ["-p", "{P}"],
    ["-a", "-d", "cwd,3", "-p", "{P}"],
    ["-b", "-p", "{P}"],
    ["-U", "-a", "-p", "{P}"],
    ["-F", "-p", "{P}"],
]

# What binds a table over the `/proc/mounts` link (the differential's
# `NFS_BIND`): an `O_PATH|O_NOFOLLOW` descriptor's `/proc/self/fd/N`.
NFS_BIND = (
    "import ctypes,os,sys\n"
    "libc=ctypes.CDLL(None,use_errno=True)\n"
    "fd=os.open('/proc/mounts',os.O_PATH|os.O_NOFOLLOW)\n"
    "r=libc.mount(sys.argv[1].encode(),('/proc/self/fd/%d'%fd).encode(),None,4096,None)\n"
    "sys.exit(0 if r==0 else 1)\n"
)

TRACE = "trace=execve,stat,lstat,newfstatat,statx,openat,readlink,readlinkat"

HERE = os.path.dirname(os.path.abspath(__file__))

# The argument lsof-rs's helper is re-executed with (`safefs::HELPER_ARG`).
HELPER_ARG = "--lsof-rs-bounded-fs-helper"

_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')


def unquote(s: str) -> str:
    """A path as strace prints it, `-xx` off: C escapes for what is not
    printable, octal for the rest."""
    return bytes(s, "utf-8").decode("unicode_escape").encode("latin-1").decode(
        "utf-8", "surrogateescape"
    )


def unescape_octal(field: str) -> str:
    """`/proc/self/mounts`'s `\\OOO` escapes, undone as the kernel made them."""
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8) & 0xFF), field)


def mount_dirs() -> tuple[set[str], set[str]]:
    """This process's mount directories, decoded, and their types."""
    dirs, types = set(), set()
    with open("/proc/self/mounts", encoding="utf-8", errors="surrogateescape") as f:
        for line in f:
            fields = line.split(" ")
            if len(fields) >= 3:
                dirs.add(unescape_octal(fields[1]))
                types.add(fields[2])
    return dirs, types


def calls(line: str) -> tuple[str, str, bool] | None:
    """One traced line as (kind, path, by_name): `stat`, `lstat` or
    `readlink` of `path`, and whether a `stat` named the path itself (not
    through an `O_PATH` descriptor). None for anything else."""
    m = re.match(r"(\w+)\((.*)", line)
    if not m:
        return None
    name, args = m.group(1), m.group(2)
    q = _QUOTED.search(args)
    if not q:
        return None
    path = unquote(q.group(1))
    if name == "openat":
        if "O_PATH" not in args:
            return None
        return ("lstat" if "O_NOFOLLOW" in args else "stat", path, False)
    if name in ("newfstatat", "statx", "stat", "lstat"):
        if path == "":
            return None  # the descriptor an `O_PATH` open gave
        nofollow = "AT_SYMLINK_NOFOLLOW" in args or name == "lstat"
        return ("lstat" if nofollow else "stat", path, True)
    if name in ("readlink", "readlinkat"):
        return ("readlink", path, True)
    return None


def trace(
    binary: str, argv: list[str], work: str, tag: str, wrap: list[str] | None = None
) -> list[tuple[str, str, bool, bool]]:
    """Every call of interest the run made, as `calls()` gives it, and
    whether lsof made it in its own process: the one whose first `execve`
    is the binary's and not a helper's (the C's child does not exec)."""
    prefix = os.path.join(work, tag)
    for old in glob.glob(prefix + ".*"):
        os.unlink(old)
    subprocess.run(
        [*(wrap or []), "timeout", "120", "strace", "-ff", "-qq", "-e", TRACE, "-o", prefix,
         binary, *argv],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    seen = []
    for path in glob.glob(prefix + ".*"):
        with open(path, encoding="utf-8", errors="surrogateescape") as f:
            lines = f.readlines()
        first_exec = next((l for l in lines if l.startswith("execve(")), "")
        own = first_exec != "" and HELPER_ARG not in first_exec
        for line in lines:
            c = calls(line)
            if c:
                seen.append((*c, own))
    return seen


def can_trace(work: str) -> str | None:
    """Why strace cannot be used here, or None."""
    if shutil.which("strace") is None:
        return "no strace"
    out = os.path.join(work, "probe")
    r = subprocess.run(
        ["strace", "-qq", "-e", "trace=openat", "-o", out, "true"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if r.returncode != 0 or not os.path.exists(out):
        return "strace cannot trace here"
    return None


def counted(reads_table: bool, c: collections.Counter, rs: collections.Counter) -> list[str]:
    """What is wrong with the mount directories each binary `stat`ed, as
    counted: lsof-rs's counts must be the C's, which is also what bounds
    them (a directory `stat`ed twice by both is one the C could not `stat`
    and tried again for its second row); a run the C reads no table on
    must `stat` none; and one it reads the table on must `stat` some."""
    problems = []
    if c != rs:
        problems.append(
            "stat counts differ: C only "
            + repr(dict(c - rs)) + ", lsof-rs only " + repr(dict(rs - c))
        )
    if not reads_table and (c or rs):
        problems.append(f"a run the C reads no table on stat()ed a mount: C {dict(c)}, lsof-rs {dict(rs)}")
    if reads_table and not rs:
        problems.append("no mount stat()ed: the table was not read")
    return problems


def per_file(pid: int, mapped: set[str], seen, own: bool) -> collections.Counter:
    """The per-file calls among `seen`, as `trace()` gives them, made in
    lsof's own process (`own`) or in the one it starts for its calls: a
    `stat` or `lstat` of one of the sleeper's `/proc/PID/` links (not the
    directory, nor `ns/mnt`, which both read in themselves to compare mount
    namespaces) or of a file it maps."""
    base = f"/proc/{pid}/"
    return collections.Counter(
        (k, p) for k, p, _, o in seen
        if k in ("stat", "lstat") and o == own
        and ((p.startswith(base) and p not in (base, base + "ns/mnt")) or p in mapped)
    )


def nfs_audit(oracle: str, rust: str, held: "Held") -> tuple[int, int]:
    """The per-file part (see the docstring): how many cases ran, and how
    many failed. Nothing when this host cannot make the namespace."""
    if os.geteuid() != 0 or shutil.which("unshare") is None:
        print("skip  per-file calls with an NFS mount listed (needs root and unshare)")
        return 0, 0
    work = held.work
    ndir = os.path.join(work, "nfs")
    os.makedirs(ndir, exist_ok=True)
    held_file = os.path.join(ndir, "f.txt")
    with open(held_file, "w") as f:
        f.write("x\n")
    pid = held.nfs_sleeper_pid(held_file)
    with open(f"/proc/{pid}/maps", encoding="utf-8", errors="surrogateescape") as f:
        mapped = {l.split(None, 5)[5].strip() for l in f if len(l.split(None, 5)) == 6}
    table = os.path.join(work, "nfs-mounts")
    with open("/proc/self/mounts", "rb") as src, open(table, "wb") as dst:
        dst.write(src.read() + f"srv:/export {ndir} nfs4 rw,relatime 0 0\n".encode())
    script = os.path.join(work, "nfs-wrap.sh")
    with open(script, "w") as f:
        f.write(
            "#!/bin/sh\n"
            f"{shlex_quote(sys.executable)} -I -c {shlex_quote(NFS_BIND)} {shlex_quote(table)} || exit 9\n"
            'exec "$@"\n'
        )
    listed = ["unshare", "-m", "--propagation", "private", "sh", script]
    plain = ["unshare", "-m", "--propagation", "private"]
    run = failed = 0
    for args in NFS_CASES:
        argv = ["-n", "-P", "-w", *[a.replace("{P}", str(pid)) for a in args]]
        label = "NFS " + " ".join(argv)
        run += 1
        problems = []
        got = {side: trace(b, argv, work, "nfs-" + side, listed)
               for side, b in (("c", oracle), ("rs", rust))}
        c_child, rs_helper = (per_file(pid, mapped, got[s], False) for s in ("c", "rs"))
        for side in ("c", "rs"):
            mine = per_file(pid, mapped, got[side], True)
            if mine:
                problems.append(f"{side} made per-file calls in itself: {sorted(mine)[:4]}")
        if c_child != rs_helper:
            problems.append("per-file calls differ: C only " + repr(sorted(c_child - rs_helper)[:4])
                            + ", lsof-rs only " + repr(sorted(rs_helper - c_child)[:4]))
        if "-b" in args and (c_child or rs_helper):
            problems.append("-b made a per-file call")
        if "-b" not in args and not rs_helper:
            problems.append("no per-file call was made: the line was not listed")
        unlisted = per_file(pid, mapped, trace(rust, argv, work, "nfs-plain", plain), False)
        if unlisted:
            problems.append(f"without the line lsof-rs's helper made per-file calls: {sorted(unlisted)[:4]}")
        if problems:
            failed += 1
            print(f"FAIL  {label}")
            for p in problems:
                print(f"      {p}")
        else:
            print(f"ok    {label}  ({sum(rs_helper.values())} per-file calls in each's child)")
    return run, failed


def shlex_quote(s: str) -> str:
    return shlex.quote(s)


def ended(signum, _frame):
    """SIGTERM or SIGHUP: end as an exception would, so what an audit holds
    is let go (`Held`); left to their default, they ended the script where
    it stood, and the sleeper and the work directory outlived it."""
    sys.exit(128 + signum)


class Held:
    """What an audit holds while it runs, both gone when it ends, however it
    ends: a work directory, and the sleeper `{P}` names, in `/`. The sleeper
    lives 120 s even so, should the audit be killed outright; one gone
    before the last case changes no count, as both binaries read the table
    before they look for it."""

    def __enter__(self) -> "Held":
        for sig in (signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, ended)
        self.work = tempfile.mkdtemp(prefix="lsof-rs-mount-audit-")
        self.sleeper: subprocess.Popen | None = None
        self.nfs_sleeper: subprocess.Popen | None = None
        return self

    def nfs_sleeper_pid(self, held: str) -> int:
        """A sleeper in `/` with `/etc/hostname` on fd 0 and `held` on fd 3,
        for the per-file part."""
        if self.nfs_sleeper is None:
            with open("/etc/hostname", "rb") as zero:
                self.nfs_sleeper = subprocess.Popen(
                    ["sh", "-c", 'exec sleep 120 3<"$1"', "sh", held],
                    cwd="/", stdin=zero, stdout=subprocess.DEVNULL,
                )
            # Read once it has exec'd: the shell's own maps are not its.
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    if os.readlink(f"/proc/{self.nfs_sleeper.pid}/fd/3") == held and \
                            os.readlink(f"/proc/{self.nfs_sleeper.pid}/exe").endswith("/sleep"):
                        break
                except OSError:
                    pass
                time.sleep(0.02)
        return self.nfs_sleeper.pid

    def sleeper_pid(self) -> int:
        if self.sleeper is None:
            self.sleeper = subprocess.Popen(["sleep", "120"], cwd="/")
        return self.sleeper.pid

    def __exit__(self, *_exc) -> bool:
        for sleeper in (self.sleeper, self.nfs_sleeper):
            if sleeper is not None:
                sleeper.kill()
                sleeper.wait()
        shutil.rmtree(self.work, ignore_errors=True)
        return False


def audit(oracle: str, rust: str) -> int:
    with Held() as held:
        work = held.work
        why = can_trace(work)
        if why:
            print(f"mount_stat_audit: SKIP ({why})")
            return 0
        pid = str(held.sleeper_pid())
        mounts, types = mount_dirs()
        failed = run = 0
        for args, reads_table in CASES:
            argv = ["-n", "-P", "-w", *[a.replace("{P}", pid) for a in args]]
            label = " ".join(argv)
            if "-Z" in args and "selinuxfs" in types:
                print(f"skip  {label}  (SELinux is enabled here: the C reads the table for -Z)")
                continue
            run += 1
            got = {}
            for side, binary in (("c", oracle), ("rs", rust)):
                got[side] = trace(binary, argv, work, side)
            def stats(side: str) -> collections.Counter:
                return collections.Counter(
                    p for k, p, _, own in got[side]
                    if k in ("stat", "lstat") and p in mounts and not own
                )

            def links(side: str) -> set[str]:
                # The prefixes of mount directories, as `Readlink()` reads them.
                return {
                    p for k, p, _, own in got[side]
                    if k == "readlink" and not own
                    and any(m == p or m.startswith(p + "/") for m in mounts)
                }
            c, rs = stats("c"), stats("rs")
            problems = counted(reads_table, c, rs)
            by_name = sorted(
                {p for k, p, n, _ in got["rs"] if n and k != "readlink" and p in mounts}
            )
            if by_name:
                problems.append(f"lsof-rs stat()ed a mount by name: {by_name[:5]}")
            if links("c") != links("rs"):
                problems.append(
                    "readlinks differ: C only " + repr(sorted(links("c") - links("rs"))[:5])
                    + ", lsof-rs only " + repr(sorted(links("rs") - links("c"))[:5])
                )
            if problems:
                failed += 1
                print(f"FAIL  {label}")
                for p in problems:
                    print(f"      {p}")
            else:
                print(f"ok    {label}  ({sum(rs.values())} mount stat()s)")
        nrun, nfailed = nfs_audit(oracle, rust, held)
        run, failed = run + nrun, failed + nfailed
        print(f"mount_stat_audit: {run - failed}/{run} held")
        return 1 if failed else 0


def self_test() -> int:
    ok = True

    def check(name: str, cond: bool) -> None:
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name)
        ok = ok and cond

    check("an O_PATH open is a stat",
          calls('openat(AT_FDCWD, "/dev/shm", O_RDONLY|O_CLOEXEC|O_PATH) = 3')
          == ("stat", "/dev/shm", False))
    check("with O_NOFOLLOW, an lstat",
          calls('openat(AT_FDCWD, "/x", O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_PATH) = -1 ENOENT')
          == ("lstat", "/x", False))
    check("a failed one counts too",
          calls('openat(AT_FDCWD, "/a", O_RDONLY|O_CLOEXEC|O_PATH) = -1 EACCES (Permission denied)')
          is not None)
    check("an open that is not O_PATH is not a stat",
          calls('openat(AT_FDCWD, "/proc/self/mounts", O_RDONLY|O_CLOEXEC) = 3') is None)
    check("the C's stat by name",
          calls('newfstatat(AT_FDCWD, "/dev/shm", {st_mode=S_IFDIR|01777}, 0) = 0')
          == ("stat", "/dev/shm", True))
    check("and its lstat",
          calls('newfstatat(AT_FDCWD, "/l", {st_mode=S_IFLNK}, AT_SYMLINK_NOFOLLOW) = 0')
          == ("lstat", "/l", True))
    check("the statx of a descriptor names nothing",
          calls('statx(3, "", AT_STATX_SYNC_AS_STAT|AT_EMPTY_PATH, STATX_ALL, {}) = 0') is None)
    check("a readlink",
          calls('readlink("/dev", 0x7ffd, 4096) = -1 EINVAL (Invalid argument)')
          == ("readlink", "/dev", True))
    check("an escaped path is decoded",
          calls(r'openat(AT_FDCWD, "/m/a\33[2J\nb", O_RDONLY|O_PATH) = 3')
          == ("stat", "/m/a\x1b[2J\nb", False))
    check("the mounts file's escapes are undone",
          unescape_octal(r"/mnt/a\040b\134c") == "/mnt/a b\\c")
    check("-i alone is the C's no-table case and listed so",
          all(not reads for a, reads in CASES if a and a[0] == "-i" and len(a) <= 3
              and not any(x in a for x in ("-a", "-K", "-d", "+L1", "-e", "-p") if x != "-p" or "{P}" in a)))
    check("...and -Z, which the C refuses at the option",
          any(a[:1] == ["-Z"] and not reads for a, reads in CASES))
    once, twice = collections.Counter({"/m": 1}), collections.Counter({"/m": 2})
    check("a mount both stat() twice is no fault: the C tries again a row of one it could not stat",
          counted(True, twice, twice) == [])
    check("...but lsof-rs stat()ing one more often than the C is", counted(True, once, twice) != [])
    check("...and so is less often", counted(True, twice, once) != [])
    check("a run the C reads no table on stat()s none", counted(False, collections.Counter(), once) != [])
    check("a run that reads the table stat()s some", counted(True, once, collections.Counter()) != [])
    seen = [
        ("stat", "/proc/7/cwd", False, False),
        ("lstat", "/proc/7/fd/3", False, False),
        ("stat", "/proc/7/fd/3", False, True),
        ("stat", "/proc/7/", True, True),
        ("stat", "/proc/7/ns/mnt", True, True),
        ("stat", "/usr/lib/libc.so.6", False, False),
        ("stat", "/usr/lib/other.so", False, False),
        ("readlink", "/proc/7/fd/3", True, True),
        ("stat", "/proc/77/cwd", False, False),
    ]
    check("the per-file calls are the sleeper's links and mapped files, by who made them",
          per_file(7, {"/usr/lib/libc.so.6"}, seen, False)
          == collections.Counter({("stat", "/proc/7/cwd"): 1, ("lstat", "/proc/7/fd/3"): 1,
                                  ("stat", "/usr/lib/libc.so.6"): 1}))
    check("...and lsof's own, not its directory nor its mount namespace, nor a readlink",
          per_file(7, set(), seen, True) == collections.Counter({("stat", "/proc/7/fd/3"): 1}))
    check("the NFS cases hold one -b case, which makes no call",
          sum("-b" in a for a in NFS_CASES) == 1 and all("{P}" in a for a in NFS_CASES))
    check("the table is bound over the /proc/mounts link itself",
          "O_NOFOLLOW" in NFS_BIND and "'/proc/mounts'" in NFS_BIND)
    # An audit ended by SIGTERM lets go of what it holds, as one that
    # finishes does.
    code = (
        "import sys, time\n"
        f"sys.path.insert(0, {HERE!r})\n"
        "import mount_stat_audit as m\n"
        "with m.Held() as h:\n"
        "    print(h.work, h.sleeper_pid(), flush=True)\n"
        "    time.sleep(60)\n"
    )
    child = subprocess.Popen([sys.executable, "-I", "-c", code], stdout=subprocess.PIPE, text=True)
    held = (child.stdout.readline() if child.stdout else "").split()
    child.terminate()
    child.wait(timeout=10)
    if len(held) == 2:
        work, pid = held[0], int(held[1])
        try:
            with open(f"/proc/{pid}/stat") as f:
                alive = f.read().rsplit(")", 1)[1].split()[0] != "Z"
        except OSError:
            alive = False
        if alive:
            os.kill(pid, signal.SIGKILL)
        check("SIGTERM ends an audit with its sleeper killed", not alive)
        check("...and its work directory removed", not os.path.exists(work))
        shutil.rmtree(work, ignore_errors=True)
    else:
        check("a held audit says what it holds", False)
    return 0 if ok else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--oracle")
    ap.add_argument("--rust")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    if not a.oracle or not a.rust:
        ap.error("--oracle and --rust are required")
    for b in (a.oracle, a.rust):
        if not (os.path.isfile(b) and os.access(b, os.X_OK)):
            print(f"mount_stat_audit: not runnable: {b}", file=sys.stderr)
            return 2
    return audit(os.path.abspath(a.oracle), os.path.abspath(a.rust))


if __name__ == "__main__":
    sys.exit(main())
