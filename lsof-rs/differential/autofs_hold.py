#!/usr/bin/env python3
"""autofs_hold.py -- an autofs direct mount whose daemon never answers.

Fixture AUTOFS of linux_diff.py (DIVERGENCES 110). It makes a pipe, mounts a
DIRECT autofs map on MOUNTPOINT with that pipe and its own process group as
the daemon's, says it is ready, and never reads the pipe: anything that
triggers the automount (a lookup that is not `stat(2)`'s, `std::fs::metadata`
among them, measured) sends a packet down the pipe and waits for an answer
that never comes. The C never `stat`s an `autofs` mount (`dmnt.c`), and
`stat(2)` of the mount point does not trigger it.

On SIGTERM it looks, without reading, whether a packet arrived, writes
`triggered` or `quiet` to STATE, and exits; the case's wrapper reads that and
fails the run on `triggered`. It must run in a session of its own (`setsid`):
autofs lets the daemon's own process group through, and lsof must not be in
it. It holds no cwd, root, descriptor or mapping on the mount. Root only.

It lives --lifetime seconds at most (default 120), as fixture FH's server
does: a case that times out has its wrapper killed, never this, which would
otherwise hold its mount namespace, the tmpfs under it and the autofs mount
for good. Then it writes `timeout` to STATE (which no wrapper takes for
`quiet`), and, as on SIGTERM, makes the mount catatonic before it goes, so
whatever still waits on the automount is answered (ENOENT) rather than left
waiting with nothing to answer it.

usage: autofs_hold.py MOUNTPOINT READY STATE [--lifetime SECS]
"""
import argparse
import fcntl
import os
import select
import signal
import subprocess
import sys

# `AUTOFS_IOC_CATATONIC`, `_IO(0x93, 0x62)` (`linux/auto_fs.h`): the daemon
# gives up the mount, and every wait on it ends.
AUTOFS_IOC_CATATONIC = 0x9362


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("mnt")
    ap.add_argument("ready")
    ap.add_argument("state")
    ap.add_argument("--lifetime", type=float, default=120.0)
    a = ap.parse_args()
    os.chdir("/")
    r, w = os.pipe()
    subprocess.run(
        ["mount", "-i", "-t", "autofs", "-o",
         "fd=%d,pgrp=%d,minproto=5,maxproto=5,direct" % (w, os.getpgid(0)),
         "lsof-rs-autofs", a.mnt],
        check=True,
        pass_fds=(w,),
    )
    os.close(w)

    def release():
        # The daemon's own process group opens the mount point without
        # triggering it.
        try:
            fd = os.open(a.mnt, os.O_RDONLY | os.O_DIRECTORY)
            try:
                fcntl.ioctl(fd, AUTOFS_IOC_CATATONIC)
            finally:
                os.close(fd)
        except OSError:
            pass

    def stop(_signum, _frame):
        readable, _, _ = select.select([r], [], [], 0)
        with open(a.state, "w") as f:
            f.write("triggered" if readable else "quiet")
        release()
        os._exit(0)

    def expire(_signum, _frame):
        with open(a.state, "w") as f:
            f.write("timeout")
        release()
        subprocess.run(["umount", "-l", a.mnt], stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os._exit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGALRM, expire)
    signal.setitimer(signal.ITIMER_REAL, a.lifetime)
    with open(a.ready, "w") as f:
        f.write(str(os.getpid()))
    while True:
        signal.pause()


if __name__ == "__main__":
    sys.exit(main())
