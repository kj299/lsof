//! The byte layouts of the kernel records this backend reads, and the numbers
//! that go with them.
//!
//! Every offset here was measured, not transcribed: a probe file
//! `offsetof()`s each field, and clang compiles it to LLVM IR against the
//! FreeBSD source tree's own headers (`-target x86_64-unknown-freebsd14` and
//! `i686-…`, `-nostdinc`, `sys/` and `include/` of `releng/14.5` and
//! `releng/15.1`), where each offset is a constant to read. Every record but
//! `kinfo_proc` is laid out the same on all four (amd64 and i386, 14.5 and
//! 15.1): they are built of fixed-width integers and 64-bit `kvaddr_t`s for
//! exactly that reason. `kinfo_proc` holds pointers and `long`s, so it has one
//! layout per architecture, and the kernel says which one it wrote in
//! `ki_structsize`, which [`ProcLayout`] checks.
//!
//! FreeBSD 14 and 15 only. The records are the same back to 12 but for the
//! socket DEVICE cell, which the C takes from `kf_sock_pcb` from 14.0 on
//! (`__FreeBSD_version >= 1400074`) and from `kf_sock_inpcb` before; 13 is
//! past its end of life (2026-04-30), so this port reads the 14 way.

/// `CTL_KERN`, and the `kern.*` numbers under it (`sys/sysctl.h`).
pub const CTL_KERN: i32 = 1;
pub const KERN_PROC: i32 = 14;
pub const KERN_PROC_PROC: i32 = 8;
pub const KERN_PROC_FILEDESC: i32 = 33;
pub const KERN_LOCKF: i32 = 39;
pub const KERN_FILE: i32 = 15;

/// `getfsstat(2)`'s `MNT_NOWAIT`: the cached statistics, never a wait on a
/// file system that does not answer. The C's `getmntinfo(…, MNT_NOWAIT)`.
pub const MNT_NOWAIT: i32 = 2;

/// Where each field of a `struct kinfo_proc` is, on one architecture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcLayout {
    /// `sizeof(struct kinfo_proc)`, `KINFO_PROC_SIZE`, which every record's
    /// `ki_structsize` must equal.
    pub size: usize,
    pub pid: usize,
    pub ppid: usize,
    pub pgid: usize,
    /// `ki_uid`, the effective user ID, which is the one the C keeps.
    pub uid: usize,
    pub stat: usize,
    /// `ki_comm[COMMLEN + 1]`.
    pub comm: usize,
}

/// amd64: 1088 bytes.
pub const PROC_AMD64: ProcLayout = ProcLayout {
    size: 1088,
    pid: 72,
    ppid: 76,
    pgid: 80,
    uid: 168,
    stat: 388,
    comm: 447,
};

/// i386: 768 bytes.
pub const PROC_I386: ProcLayout = ProcLayout {
    size: 768,
    pid: 40,
    ppid: 44,
    pgid: 48,
    uid: 136,
    stat: 308,
    comm: 367,
};

/// The layout of the architecture this binary was built for. Anything but
/// x86 has none measured, and then nothing is read: [`crate::kinfo::procs`]
/// refuses a record it has no layout for rather than guess.
pub const PROC_HOST: Option<ProcLayout> = if cfg!(target_arch = "x86_64") {
    Some(PROC_AMD64)
} else if cfg!(target_arch = "x86") {
    Some(PROC_I386)
} else {
    None
};

/// `COMMLEN`: `ki_comm` holds this many bytes and a NUL.
pub const COMMLEN: usize = 19;

/// `ki_stat` values (`sys/proc.h`): the C skips a process whose state is 0
/// or `SZOMB`.
pub const SZOMB: u8 = 5;

/// `struct kinfo_file` (`sys/user.h`). The kernel packs the records it
/// returns from `kern.proc.filedesc`: each is `kf_structsize` bytes, the
/// fixed part and the path up to its NUL, rounded up to 8.
pub mod kf {
    pub const MAX_SIZE: usize = 1392;
    pub const STRUCTSIZE: usize = 0;
    pub const TYPE: usize = 4;
    pub const FD: usize = 8;
    pub const REF_COUNT: usize = 12;
    pub const FLAGS: usize = 16;
    pub const OFFSET: usize = 24;
    /// The API-compatibility view, which overlays the union.
    pub const VNODE_TYPE: usize = 32;
    pub const SOCK_DOMAIN: usize = 36;
    pub const SOCK_TYPE: usize = 40;
    pub const SOCK_PROTOCOL: usize = 44;
    pub const SA_LOCAL: usize = 48;
    pub const SA_PEER: usize = 176;
    /// `sockaddr_storage`.
    pub const SA_LEN: usize = 128;
    pub const SOCK_SENDQ: usize = 32;
    pub const SOCK_PCB: usize = 304;
    pub const SOCK_UNPCONN: usize = 320;
    pub const SOCK_SND_SB_STATE: usize = 328;
    pub const SOCK_RCV_SB_STATE: usize = 330;
    pub const SOCK_RECVQ: usize = 332;
    pub const FILE_NLINK: usize = 280;
    pub const FILE_FSID: usize = 288;
    pub const FILE_RDEV: usize = 296;
    pub const FILE_FILEID: usize = 304;
    pub const FILE_SIZE: usize = 312;
    pub const PIPE_ADDR: usize = 304;
    pub const PIPE_PEER: usize = 312;
    pub const PIPE_CNT: usize = 320;
    pub const PIPE_IN: usize = 324;
    pub const PIPE_OUT: usize = 328;
    pub const PIPE_SIZE: usize = 332;
    pub const PTS_DEV: usize = 312;
    pub const PROC_PID: usize = 304;
    pub const KQ_ADDR: usize = 32;
    pub const KQ_COUNT: usize = 40;
    pub const KQ_STATE: usize = 44;
    pub const EFD_VALUE: usize = 32;
    pub const EFD_FLAGS: usize = 40;
    pub const EFD_ADDR: usize = 56;
    pub const PATH: usize = 368;
    /// `PATH_MAX`, the size of `kf_path`.
    pub const PATH_LEN: usize = 1024;

    pub const TYPE_VNODE: i32 = 1;
    pub const TYPE_SOCKET: i32 = 2;
    pub const TYPE_PIPE: i32 = 3;
    pub const TYPE_FIFO: i32 = 4;
    pub const TYPE_KQUEUE: i32 = 5;
    pub const TYPE_SHM: i32 = 8;
    pub const TYPE_PTS: i32 = 10;
    pub const TYPE_PROCDESC: i32 = 11;
    pub const TYPE_EVENTFD: i32 = 13;

    pub const VTYPE_VNON: i32 = 0;
    pub const VTYPE_VREG: i32 = 1;
    pub const VTYPE_VDIR: i32 = 2;
    pub const VTYPE_VBLK: i32 = 3;
    pub const VTYPE_VCHR: i32 = 4;
    pub const VTYPE_VLNK: i32 = 5;
    pub const VTYPE_VSOCK: i32 = 6;
    pub const VTYPE_VFIFO: i32 = 7;
    pub const VTYPE_VBAD: i32 = 8;

    pub const FD_CWD: i32 = -1;
    pub const FD_ROOT: i32 = -2;
    pub const FD_JAIL: i32 = -3;
    pub const FD_TEXT: i32 = -5;
    pub const FD_CTTY: i32 = -6;

    pub const FLAG_READ: i32 = 0x1;
    pub const FLAG_WRITE: i32 = 0x2;
}

/// The socket numbers (`sys/socket.h`, `netinet/in.h`, `sys/sockbuf.h`).
pub mod sock {
    pub const AF_UNIX: i32 = 1;
    pub const AF_INET: i32 = 2;
    pub const AF_ROUTE: i32 = 17;
    pub const AF_INET6: i32 = 28;
    pub const SOCK_STREAM: i32 = 1;
    pub const SOCK_DGRAM: i32 = 2;
    pub const SOCK_SEQPACKET: i32 = 5;
    pub const SBS_CANTSENDMORE: u16 = 0x10;
    pub const SBS_CANTRCVMORE: u16 = 0x20;
    /// `sizeof(struct sockaddr_un)`'s path, `sun_path[104]`, at offset 2.
    pub const SUN_PATH: usize = 2;
    pub const SUN_PATH_LEN: usize = 104;
}

/// One kind of `struct xinpgen`-framed list from a `*.pcblist` sysctl:
/// how long each record is, and where in it the fields lsof reads are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PcbLayout {
    /// The record's `*_len`, which the C loops on: records continue while
    /// the length read is this one, and the trailing `xinpgen` (64 bytes, or
    /// a 32-byte `xunpgen`) ends the list.
    pub len: u64,
    /// The record's socket's `so_pcb`, which `kf_sock_pcb` is.
    pub so_pcb: usize,
    /// `xso_so`, the socket's own address.
    pub xso_so: usize,
    /// `t_state`, for TCP alone.
    pub t_state: Option<usize>,
}

/// `net.inet.tcp.pcblist`: `struct xtcpcb`, 744 bytes.
pub const XTCPCB: PcbLayout = PcbLayout {
    len: 744,
    so_pcb: 32,
    xso_so: 24,
    t_state: Some(568),
};

/// `net.inet.udp.pcblist`: `struct xinpcb`, 400 bytes.
pub const XINPCB: PcbLayout = PcbLayout {
    len: 400,
    so_pcb: 24,
    xso_so: 16,
    t_state: None,
};

/// `net.local.{stream,dgram,seqpacket}.pcblist`: `struct xunpcb`, 904 bytes.
pub const XUNPCB: PcbLayout = PcbLayout {
    len: 904,
    so_pcb: 680,
    xso_so: 672,
    t_state: None,
};

/// `struct kinfo_lockf` (`sys/user.h`), from `kern.lockf`: fixed-size
/// records, 1088 bytes each.
pub mod kl {
    pub const SIZE: usize = 1088;
    pub const STRUCTSIZE: usize = 0;
    pub const RW: usize = 4;
    pub const PID: usize = 12;
    pub const SYSID: usize = 16;
    pub const FILE_FSID: usize = 24;
    pub const FILE_FILEID: usize = 40;
    pub const START: usize = 48;
    pub const LEN: usize = 56;
    pub const RW_READ: i32 = 1;
    pub const RW_WRITE: i32 = 2;
}

/// `struct xfile` (`sys/file.h`), from `kern.file`: 128 bytes each.
pub mod xf {
    pub const SIZE: usize = 128;
    pub const PID: usize = 8;
    pub const FD: usize = 16;
    pub const FILE: usize = 24;
}

/// `struct statfs` (`sys/mount.h`): 2344 bytes, the same on every target.
pub mod sf {
    pub const SIZE: usize = 2344;
    pub const TYPE: usize = 4;
    pub const FSID: usize = 192;
    pub const FSTYPENAME: usize = 280;
    pub const FSTYPENAME_LEN: usize = 16;
    pub const MNTFROMNAME: usize = 296;
    pub const MNTONNAME: usize = 1320;
    pub const MNAMELEN: usize = 1024;
}

/// `VNOVAL` (`sys/vnode.h`), `-1`, as a `uint64_t` field holds it: what the
/// kernel puts where it has no file ID or file-system ID to give.
pub const VNOVAL: u64 = u64::MAX;
