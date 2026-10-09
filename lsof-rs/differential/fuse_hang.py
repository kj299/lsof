#!/usr/bin/env python3
"""fuse_hang.py -- a FUSE file system whose root does not answer GETATTR.

A differential fixture for lsof's stat timeout (-S, -b, -O; DIVERGENCES 94
and 110). It speaks the raw /dev/fuse protocol, so it needs no libfuse and
no third-party module: Python 3 standard library only (ctypes for mount(2)).

USAGE (root, and ONLY inside a private mount namespace):

    unshare -m --propagation private bash -c '
        mount -t tmpfs none "$BASE"; mkdir "$BASE/fuse"
        python3 -I fuse_hang.py "$BASE/fuse" --ready "$BASE/ready" &
        while [ ! -e "$BASE/ready" ]; do sleep 0.1; done
        ... run lsof here; never cd into, open or map anything on the mount ...
        kill %1; wait; umount -l "$BASE"'

    fuse_hang.py MOUNTPOINT [--mode hold|stall|delay|serve] [--delay SECS]
                 [--answer-first N] [--ready FILE] [--log FILE]
                 [--lifetime SECS] [--subtype NAME]
                 [--symlink NAME=TARGET] [--hang-op getattr|readlink]

MODES (what happens to a GETATTR -- a stat(2) -- of the root):

  hold   (default) the server READS each GETATTR and never answers it. The
         caller sleeps in the kernel's request_wait_answer(); a caught or
         ignored signal does not end the wait, and once a FATAL signal
         (SIGKILL, or SIGINT/SIGTERM with the default action) arrives the
         caller waits UNINTERRUPTIBLY (state D) -- unkillable until the
         request is answered or the connection aborted. This is the worst
         case: a FUSE daemon that is alive but stuck.
  stall  the server answers INIT and then stops reading /dev/fuse. Requests
         stay queued (never sent to user space), so a fatal signal removes
         them and the caller dies -- like a hard NFS mount whose server is
         down (TASK_KILLABLE).
  delay  every GETATTR is answered after --delay seconds (default 20).
  serve  every GETATTR is answered at once (a control).

  --answer-first N   answer the first N GETATTRs at once, then apply --mode
                     (not in stall mode, which stops reading after INIT).
  --symlink NAME=TARGET   the root holds one entry, a symbolic link NAME -> TARGET
                     (LOOKUP of NAME answers it; every other name is ENOENT).
  --hang-op OP       which request the mode applies to: getattr (default; a
                     stat(2) of the root) or readlink (READLINK of the
                     --symlink entry; GETATTRs are then answered at once).
  --lifetime SECS    the server exits on its own after SECS (default 900):
                     a safety net, so a forgotten fixture cannot hang the
                     namespace forever.

The root's attributes are never cached (attr_valid 0), so every stat(2) of
the root asks the server again. LOOKUP of any name but --symlink's answers
ENOENT (and is not cached either); READDIR
of the root is empty; STATFS answers zeros.

TEARDOWN: SIGTERM or SIGINT. The server closes /dev/fuse, which ABORTS the
connection -- every caller still waiting gets ENOTCONN and is released, even
one in state D -- and then detaches the mount (umount2 MNT_DETACH). The log
(--log, default stderr) has one line per request: time, opcode, pid, action.

KERNEL: measured on Linux 6.18 with /proc/sys/fs/fuse/default_request_timeout
and max_request_timeout 0 (no limit). Where either is set (6.14+), the kernel
aborts the connection itself once a request is that old, so "hold" lasts at
most that long; check them before reading a hang as lsof's.

Sizes and opcodes are from include/uapi/linux/fuse.h (protocol 7.x).
"""

import argparse
import ctypes
import errno
import os
import select
import signal
import struct
import sys
import time

FUSE_LOOKUP, FUSE_FORGET, FUSE_GETATTR = 1, 2, 3
FUSE_READLINK = 5
FUSE_STATFS = 17
FUSE_GETXATTR = 22
FUSE_INIT = 26
FUSE_OPENDIR, FUSE_READDIR, FUSE_RELEASEDIR = 27, 28, 29
FUSE_ACCESS = 34
FUSE_INTERRUPT = 36
FUSE_DESTROY = 38
FUSE_BATCH_FORGET = 42
FUSE_READDIRPLUS = 44
FUSE_STATX = 52

NAMES = {1: "LOOKUP", 2: "FORGET", 3: "GETATTR", 5: "READLINK", 17: "STATFS", 22: "GETXATTR",
         26: "INIT", 27: "OPENDIR", 28: "READDIR", 29: "RELEASEDIR",
         34: "ACCESS", 36: "INTERRUPT", 38: "DESTROY", 42: "BATCH_FORGET",
         44: "READDIRPLUS", 52: "STATX"}
NO_REPLY = {FUSE_FORGET, FUSE_BATCH_FORGET, FUSE_INTERRUPT}

IN_HDR = struct.Struct("<IIQQIIIHH")      # fuse_in_header, 40 bytes
OUT_HDR = struct.Struct("<IiQ")           # fuse_out_header, 16 bytes
INIT_IN = struct.Struct("<IIII")          # major, minor, max_readahead, flags
INIT_OUT = struct.Struct("<IIIIHHIIHHII6I")  # fuse_init_out, 64 bytes
ATTR = struct.Struct("<QQQQQQIIIIIIIIII")  # fuse_attr, 88 bytes
ATTR_OUT_HEAD = struct.Struct("<QII")      # attr_valid, nsec, dummy
ENTRY_OUT_HEAD = struct.Struct("<QQQQII")  # nodeid, generation, entry/attr valid
OPEN_OUT = struct.Struct("<QIi")           # fuse_open_out, 16 bytes
STATFS_OUT = struct.Struct("<QQQQQIIII6I")  # fuse_kstatfs, 80 bytes

MS_NOSUID, MS_NODEV = 2, 4
MNT_DETACH = 2

T0 = time.monotonic()
LOG = sys.stderr


def log(msg):
    LOG.write("t=%.3f %s\n" % (time.monotonic() - T0, msg))
    LOG.flush()


def reply(fd, unique, err=0, payload=b""):
    try:
        os.write(fd, OUT_HDR.pack(OUT_HDR.size + len(payload), err, unique) + payload)
    except OSError as e:          # the caller was interrupted and gave up
        log("reply unique=%d failed: %s" % (unique, e))


def attr_of(node, target=b""):
    now = int(time.time())
    if node == 1:
        return ATTR.pack(1, 0, 0, now, now, now, 0, 0, 0,
                         0o40755, 2, 0, 0, 0, 4096, 0)
    return ATTR.pack(node, len(target), 0, now, now, now, 0, 0, 0,
                     0o120777, 1, 0, 0, 0, 4096, 0)


def root_attr(node=1, target=b""):
    # attr_valid 0: never cached, so every stat(2) asks again
    return ATTR_OUT_HEAD.pack(0, 0, 0) + attr_of(node, target)


def main():
    global LOG
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("mountpoint")
    ap.add_argument("--mode", choices=("hold", "stall", "delay", "serve"),
                    default="hold")
    ap.add_argument("--delay", type=float, default=20.0)
    ap.add_argument("--answer-first", type=int, default=0)
    ap.add_argument("--ready")
    ap.add_argument("--log")
    ap.add_argument("--lifetime", type=float, default=900.0)
    ap.add_argument("--subtype", default="hang")
    ap.add_argument("--symlink")
    ap.add_argument("--hang-op", choices=("getattr", "readlink"), default="getattr")
    a = ap.parse_args()
    if a.log:
        LOG = open(a.log, "a", buffering=1)

    mnt = os.path.abspath(a.mountpoint)
    link_name, link_target = None, b""
    if a.symlink:
        n, _, t = a.symlink.partition("=")
        link_name, link_target = n.encode(), t.encode()
    fd = os.open("/dev/fuse", os.O_RDWR | os.O_CLOEXEC)
    libc = ctypes.CDLL(None, use_errno=True)
    opts = "fd=%d,rootmode=40000,user_id=0,group_id=0,allow_other" % fd
    if libc.mount(b"fuse_hang", mnt.encode(), ("fuse." + a.subtype).encode(),
                  MS_NOSUID | MS_NODEV, opts.encode()) != 0:
        e = ctypes.get_errno()
        sys.exit("fuse_hang: mount %s: %s" % (mnt, os.strerror(e)))
    log("mounted %s mode=%s pid=%d" % (mnt, a.mode, os.getpid()))

    def finish(*_):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, finish)
    signal.signal(signal.SIGINT, finish)
    signal.signal(signal.SIGALRM, finish)
    signal.setitimer(signal.ITIMER_REAL, a.lifetime)

    held = []          # uniques read and never answered (mode hold)
    due = []           # (time, unique, payload) to answer later (mode delay)
    getattrs = 0
    stalled = False
    try:
        while True:
            if stalled:
                signal.pause()
                continue
            timeout = None
            if due:
                timeout = max(0.0, min(d[0] for d in due) - time.monotonic())
            r, _, _ = select.select([fd], [], [], timeout)
            now = time.monotonic()
            for d in [d for d in due if d[0] <= now]:
                due.remove(d)
                log("unique=%d answered after delay" % d[1])
                reply(fd, d[1], 0, d[2])
            if not r:
                continue
            try:
                buf = os.read(fd, (1 << 20) + 4096)
            except OSError as e:
                if e.errno in (errno.EINTR, errno.EAGAIN, errno.ENOENT):
                    continue          # ENOENT: the request was interrupted
                if e.errno == errno.ENODEV:
                    log("connection gone (unmounted)")
                    break
                raise
            length, op, unique, nodeid, uid, gid, pid, _, _ = IN_HDR.unpack_from(buf)
            body = buf[IN_HDR.size:length]
            name = NAMES.get(op, str(op))
            if op == FUSE_INIT:
                major, minor, readahead, flags = INIT_IN.unpack_from(body)
                out = INIT_OUT.pack(7, min(minor, 31), readahead, 0, 16, 12,
                                    131072, 1, 0, 0, 0, 0, *([0] * 6))
                reply(fd, unique, 0, out)
                log("INIT kernel=%d.%d answered 7.%d" % (major, minor, min(minor, 31)))
                if a.ready:
                    open(a.ready, "w").close()
                if a.mode == "stall":
                    log("stalling: /dev/fuse is no longer read")
                    stalled = True
                continue
            if op == FUSE_STATX:              # not negotiated; 7.31 has none
                reply(fd, unique, -errno.ENOSYS)
                continue
            if op == FUSE_GETATTR and (a.hang_op != "getattr" or nodeid != 1):
                log("GETATTR unique=%d node=%d pid=%d answered (not the hang op)" % (unique, nodeid, pid))
                reply(fd, unique, 0, root_attr(nodeid, link_target))
                continue
            if op == FUSE_READLINK and a.hang_op != "readlink":
                log("READLINK unique=%d node=%d pid=%d answered" % (unique, nodeid, pid))
                reply(fd, unique, 0, link_target)
                continue
            if op == FUSE_GETATTR or op == FUSE_READLINK:
                getattrs += 1
                answer = root_attr() if op == FUSE_GETATTR else link_target
                if a.mode == "serve" or getattrs <= a.answer_first:
                    log("%s unique=%d node=%d pid=%d answered" % (name, unique, nodeid, pid))
                    reply(fd, unique, 0, answer)
                elif a.mode == "delay":
                    log("%s unique=%d node=%d pid=%d delayed %.1fs" % (name, unique, nodeid, pid, a.delay))
                    due.append((now + a.delay, unique, answer))
                else:
                    log("%s unique=%d node=%d pid=%d HELD" % (name, unique, nodeid, pid))
                    held.append(unique)
                    if a.mode == "stall":
                        stalled = True
                continue
            if op in NO_REPLY:
                log("%s unique=%d pid=%d (no reply)" % (name, unique, pid))
                continue
            log("%s unique=%d node=%d pid=%d" % (name, unique, nodeid, pid))
            if op == FUSE_LOOKUP:
                if link_name is not None and nodeid == 1 and body.rstrip(b"\0") == link_name:
                    reply(fd, unique, 0, ENTRY_OUT_HEAD.pack(2, 0, 0, 0, 0, 0) + attr_of(2, link_target))
                else:
                    reply(fd, unique, -errno.ENOENT)
            elif op == FUSE_STATFS:
                reply(fd, unique, 0, STATFS_OUT.pack(0, 0, 0, 0, 0, 4096, 255, 4096, 0, *([0] * 6)))
            elif op == FUSE_OPENDIR:
                reply(fd, unique, 0, OPEN_OUT.pack(1, 0, 0))
            elif op in (FUSE_READDIR, FUSE_READDIRPLUS):
                reply(fd, unique, 0, b"")
            elif op in (FUSE_RELEASEDIR, FUSE_ACCESS, FUSE_DESTROY):
                reply(fd, unique, 0)
            else:
                reply(fd, unique, -errno.ENOSYS)
    except SystemExit:
        pass
    finally:
        log("teardown: %d GETATTR(s) held; closing /dev/fuse (aborts the "
            "connection) and detaching %s" % (len(held), mnt))
        os.close(fd)
        if libc.umount2(mnt.encode(), MNT_DETACH) != 0:
            log("umount2: %s" % os.strerror(ctypes.get_errno()))


if __name__ == "__main__":
    main()
