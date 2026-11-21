//! The platform-agnostic data model.
//!
//! [`Process`] is the analog of lsof's `struct lproc` and [`OpenFile`] of
//! `struct lfile` (see the C sources `lib/common.h` and `include/lsof.h`),
//! trimmed to the Windows MVP surface. Windows concepts are mapped onto lsof's
//! vocabulary: a Windows *handle* is an FD, the process *image* is the command,
//! the owning *SID*'s account name is the user, and so on.

use std::net::SocketAddr;

/// What kind of slot an [`OpenFile`] occupies — lsof's "FD" column.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum FdType {
    /// A concrete handle with a numeric value (the Windows `HANDLE` value).
    Handle(u64),
    /// Current working directory.
    Cwd,
    /// Root directory.
    Root,
    /// Program image / executable text (`txt`).
    Txt,
    /// Memory-mapped module (`mem`).
    Mem,
    /// A file that is still mapped but has been deleted (`DEL`). lsof's
    /// canonical use: after a package upgrade, `lsof | grep DEL` finds the
    /// processes still running against the replaced shared objects.
    Deleted,
    /// A thread (`task`) row emitted under `-K`. The TID lives in
    /// [`OpenFile::node`] and the thread state / start in `name`.
    Task,
    /// `NOFD`: the process's fd directory could not be opened, so its fds
    /// could not be listed. The C makes one row of it, naming the directory
    /// and the reason (`/proc/1/fd (opendir: Permission denied)`), and `-d
    /// NOFD` selects it like any other FD name.
    NoFd,
    /// The controlling terminal (`ctty`): FreeBSD's `KF_FD_TYPE_CTTY` row,
    /// which no other backend makes. `-d ctty` selects it.
    Ctty,
    /// A jailed process's jail root (`jld`): FreeBSD's `KF_FD_TYPE_JAIL`.
    /// The C prints `jld` but its `-d` knows the kind as `jd.` (`arg.c`), so
    /// `-d jd.` selects it and `-d jld` is refused, there and here.
    Jail,
    /// Type could not be determined.
    Unknown,
}

impl FdType {
    /// The short code shown in the FD column, e.g. `"3"`, `"cwd"`, `"txt"`.
    pub fn code(&self) -> String {
        match self {
            FdType::Handle(n) => n.to_string(),
            FdType::Cwd => "cwd".to_string(),
            FdType::Root => "rtd".to_string(),
            FdType::Txt => "txt".to_string(),
            FdType::Mem => "mem".to_string(),
            FdType::Deleted => "DEL".to_string(),
            FdType::Task => "task".to_string(),
            FdType::NoFd => "NOFD".to_string(),
            FdType::Ctty => "ctty".to_string(),
            FdType::Jail => "jld".to_string(),
            FdType::Unknown => "unk".to_string(),
        }
    }

    /// The FD as the table's column and the `-E` holder text print it, the
    /// C's `fd_to_string()` (`lib/proc.c:1322-1331`): a descriptor of 10000
    /// or more is `*` and its last three digits, `*%03d` of `fd % 1000`, to
    /// keep the column to the width of `TYPE`; `-F f` and JSON print the
    /// number whole, as the C's do (measured: fd 10000 is `*000u` in the
    /// column and `PID,cmd,*000u` in a peer's NAME, `f10000` under `-F`).
    /// Not on Windows, which has no C to follow and whose handle values run
    /// past 10000 as a matter of course: there it is [`FdType::code`].
    pub fn column_code(&self) -> String {
        match self {
            FdType::Handle(n) if *n >= 10_000 && !cfg!(windows) => format!("*{:03}", n % 1000),
            _ => self.code(),
        }
    }
}

/// Access mode of an open file (lsof appends this to the FD column: `3u`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessMode {
    Read,
    Write,
    ReadWrite,
    Unknown,
}

impl AccessMode {
    /// lsof access letter: `r`, `w`, `u` (read+write), or `-` when unknown.
    pub fn code(self) -> char {
        match self {
            AccessMode::Read => 'r',
            AccessMode::Write => 'w',
            AccessMode::ReadWrite => 'u',
            AccessMode::Unknown => '-',
        }
    }
}

/// A byte-range or whole-file lock held on an open file — the character lsof
/// appends to the FD column, so `8u` becomes `8uW`.
///
/// Linux reports only shared/exclusive in `/proc/locks`, which is these four.
/// The C also knows `u`/`U` (read *and* write, from systems whose lock tables
/// distinguish it) and `x`/`X` (Xenix); neither is reachable on Linux, and
/// Windows cannot enumerate another process's locks at all
/// (`docs/known-limitations.md`), so they are deliberately absent rather than
/// defined and never produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockKind {
    /// `r` — read (shared) lock on part of the file.
    ReadPartial,
    /// `R` — read (shared) lock on the whole file.
    ReadFull,
    /// `w` — write (exclusive) lock on part of the file.
    WritePartial,
    /// `W` — write (exclusive) lock on the whole file.
    WriteFull,
}

impl LockKind {
    /// The character lsof appends to the FD cell.
    pub fn code(self) -> char {
        match self {
            LockKind::ReadPartial => 'r',
            LockKind::ReadFull => 'R',
            LockKind::WritePartial => 'w',
            LockKind::WriteFull => 'W',
        }
    }

    /// Classify a lock from the two facts `/proc/locks` gives: whether it is a
    /// write lock, and whether it covers the whole file (`0` to `EOF`).
    pub fn new(write: bool, whole_file: bool) -> Self {
        match (write, whole_file) {
            (true, true) => LockKind::WriteFull,
            (true, false) => LockKind::WritePartial,
            (false, true) => LockKind::ReadFull,
            (false, false) => LockKind::ReadPartial,
        }
    }
}

/// The kind of object an open file refers to — lsof's "TYPE" column.
///
/// Windows has ~40–60 kernel object types; the common ones a Windows lsof
/// surfaces get a named variant, and every other type is carried by
/// [`FileType::Other`] holding its short display code, so the all-handle scan
/// can classify anything without an exhaustive enum. (Not `Copy` because of the
/// owned `String`; it stays cheap to clone.)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileType {
    Regular,
    Dir,
    Chr,
    /// Block device. Unix-only — Windows has no analog, so the Windows backend
    /// never produces this.
    Block,
    Fifo,
    Pipe,
    Ipv4,
    Ipv6,
    Unix,
    // Native Windows kernel object types surfaced by the all-handle scan.
    Key,
    Event,
    Mutant,
    Section,
    Process,
    Thread,
    Token,
    /// Any other Windows object type, carrying its short TYPE code (e.g. `SEM`,
    /// `JOB`, `IOCP`, `ALPC`, or an uppercased/truncated type name).
    Other(String),
    /// `unknown`: a file that is there but could not be examined — its link
    /// could not be read, or what it names could not be `stat`ed. The C's
    /// `LSOF_FILE_UNKNOWN_STAT`.
    Unknown,
    /// `UNKN<kind>` (`UNKNfd`, `UNKNcwd`, `UNKNrtd`, `UNKNtxt`, `UNKNmem`,
    /// `UNKNdel`): a file on a file system `-e` exempted, so never `stat`ed.
    /// The C builds the row without `process_proc_node()`, so no path or
    /// file-system argument and no `-N` ever selects it, whatever device and
    /// inode it shows (see [`OpenFile::is_exempt`]).
    Exempt(&'static str),
    /// A socket that is no Internet, AF_UNIX or packet socket to the C, with
    /// its TYPE code: `sock`, the C's `LSOF_FILE_SOCKET` (a protocol the
    /// owner's namespace names, or `can't identify protocol`); `SOCK`, where
    /// lsof-rs still types a socket by its `stat` and the C says `sock`
    /// (DIVERGENCES 22, 126); or `raw` and `raw6`, the C's `LSOF_FILE_RAW`
    /// and `LSOF_FILE_RAW6`, a raw socket `/proc/net/raw` or `raw6` lists,
    /// named from that table's text and never selected by `-i` (DIVERGENCES
    /// 108). The C hands
    /// every socket to `process_proc_sock()` before `is_file_named()`
    /// (`dnode.c`), so no path, `+d`/`+D` entry or file-system argument
    /// finds one by its own device and inode, whatever they are (see
    /// [`OpenFile::is_socket`]).
    Socket(&'static str),
    /// No type was ever set: the C's `LSOF_FILE_NONE`, which only its `NOFD`
    /// row carries. The table prints what the C's fallback formats for it —
    /// the raw type number in octal, `%04o`, so `0000` — and `-F` omits the
    /// `t` field altogether (measured), which [`FileType::has_code`] says.
    NoType,
}

impl FileType {
    /// lsof-style TYPE code.
    pub fn code(&self) -> String {
        match self {
            FileType::Regular => "REG".into(),
            FileType::Dir => "DIR".into(),
            FileType::Chr => "CHR".into(),
            FileType::Block => "BLK".into(),
            FileType::Fifo => "FIFO".into(),
            FileType::Pipe => "PIPE".into(),
            FileType::Ipv4 => "IPv4".into(),
            FileType::Ipv6 => "IPv6".into(),
            FileType::Unix => "unix".into(),
            FileType::Key => "KEY".into(),
            FileType::Event => "EVT".into(),
            FileType::Mutant => "MUT".into(),
            FileType::Section => "SECT".into(),
            FileType::Process => "PROC".into(),
            FileType::Thread => "THRD".into(),
            FileType::Token => "TOKN".into(),
            FileType::Other(code) => code.clone(),
            FileType::Exempt(kind) => format!("UNKN{kind}"),
            FileType::Socket(code) => (*code).into(),
            FileType::Unknown => "unknown".into(),
            FileType::NoType => "0000".into(),
        }
    }

    /// Whether `-F` prints a `t` field for this type. Every type but
    /// [`FileType::NoType`] does; the C writes `t` only for a row whose type
    /// was set.
    pub fn has_code(&self) -> bool {
        !matches!(self, FileType::NoType)
    }
}

/// Transport protocol for a network socket. `Other(name)` carries a static
/// upper-case protocol name (e.g. "ICMP", "ICMPV6", "RAW", "AF_UNIX") for
/// non-TCP/UDP sockets surfaced from sources beyond IP Helper (currently the
/// ETW backend, when `--etw` is on).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    /// UDP-Lite (`IPPROTO_UDPLITE`), from Linux's `/proc/net/udplite` and
    /// `udplite6`: the third protocol the C's `-i` names, and the third it
    /// reads those tables for (`dsock.c` `get_tcpudp(…, 2, …)`). Its own
    /// variant rather than an `Other` name, because the C treats it as UDP's
    /// sibling: an Internet socket, with queues and a state number `-s TCP:`
    /// tests, but never a state it prints (measured; see
    /// [`SocketInfo::shown_state`]).
    UdpLite,
    Other(&'static str),
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Tcp => "TCP",
            Protocol::Udp => "UDP",
            Protocol::UdpLite => "UDPLITE",
            Protocol::Other(s) => s,
        }
    }
}

/// TCP connection state, by the name the platform's own lsof uses for it.
///
/// Windows' names are `MIB_TCP_STATE`'s. Linux's are the C's
/// (`build_IPstates()`, `lib/dialects/linux/dsock.c`), which differ in two:
/// the kernel's `TCP_CLOSE` is `CLOSE` and `TCP_SYN_RECV` is `SYN_RECV`, where
/// Windows says `CLOSED` and `SYN_RCVD`. Both spellings are variants here, and
/// each backend produces only its own; `-s TCP:` accepts exactly the names of
/// [`tcp_state_table`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    DeleteTcb,
    /// Linux's `TCP_CLOSE` (7) — also the state the kernel gives an
    /// unconnected UDP socket, which is why `-s TCP:CLOSE` selects those.
    Close,
    /// Linux's `TCP_SYN_RECV` (3).
    SynRecv,
    /// FreeBSD's `TCPS_FIN_WAIT_1` (6), which its `tcpstates[]`
    /// (`netinet/tcp_fsm.h`) spells `FIN_WAIT_1`, with the underscore Linux
    /// and Windows leave out.
    FinWaitOne,
    /// FreeBSD's `TCPS_FIN_WAIT_2` (9): `FIN_WAIT_2`.
    FinWaitTwo,
    Unknown,
}

impl TcpState {
    /// lsof-style state name shown in the NAME column, e.g. `LISTEN`.
    pub fn as_str(self) -> &'static str {
        match self {
            TcpState::Closed => "CLOSED",
            TcpState::Listen => "LISTEN",
            TcpState::SynSent => "SYN_SENT",
            TcpState::SynReceived => "SYN_RCVD",
            TcpState::Established => "ESTABLISHED",
            TcpState::FinWait1 => "FIN_WAIT1",
            TcpState::FinWait2 => "FIN_WAIT2",
            TcpState::CloseWait => "CLOSE_WAIT",
            TcpState::Closing => "CLOSING",
            TcpState::LastAck => "LAST_ACK",
            TcpState::TimeWait => "TIME_WAIT",
            TcpState::DeleteTcb => "DELETE_TCB",
            TcpState::Close => "CLOSE",
            TcpState::SynRecv => "SYN_RECV",
            TcpState::FinWaitOne => "FIN_WAIT_1",
            TcpState::FinWaitTwo => "FIN_WAIT_2",
            TcpState::Unknown => "UNKNOWN",
        }
    }
}

/// The TCP state names `-s TCP:` accepts on Linux, in the C's table order:
/// `build_IPstates()` enters each under the kernel's own number, `TCP_CLOSE`
/// through `TCP_CLOSING`, with 0 named `CLOSED` — a number `/proc/net/tcp`
/// never shows, so `-s TCP:CLOSED` is accepted and never located. The order
/// matters: it is the order the C reports unlocated states in.
pub const LINUX_TCP_STATES: [TcpState; 12] = [
    TcpState::Closed,
    TcpState::Established,
    TcpState::SynSent,
    TcpState::SynRecv,
    TcpState::FinWait1,
    TcpState::FinWait2,
    TcpState::TimeWait,
    TcpState::Close,
    TcpState::CloseWait,
    TcpState::LastAck,
    TcpState::Listen,
    TcpState::Closing,
];

/// The same for Windows: the states a Windows row can show, in
/// `MIB_TCP_STATE`'s numbering (`CLOSED` = 1 … `DELETE_TCB` = 12).
pub const WINDOWS_TCP_STATES: [TcpState; 12] = [
    TcpState::Closed,
    TcpState::Listen,
    TcpState::SynSent,
    TcpState::SynReceived,
    TcpState::Established,
    TcpState::FinWait1,
    TcpState::FinWait2,
    TcpState::CloseWait,
    TcpState::Closing,
    TcpState::LastAck,
    TcpState::TimeWait,
    TcpState::DeleteTcb,
];

/// The same for FreeBSD: `tcpstates[]` of `netinet/tcp_fsm.h`, which the C
/// takes whole (`src/ptti.c`, `TCPSTATES`), indexed by `t_state` from
/// `TCPS_CLOSED` (0) to `TCPS_TIME_WAIT` (10). Eleven names, and two of them
/// spelt as no other platform spells them: `FIN_WAIT_1` and `FIN_WAIT_2`.
pub const FREEBSD_TCP_STATES: [TcpState; 11] = [
    TcpState::Closed,
    TcpState::Listen,
    TcpState::SynSent,
    TcpState::SynReceived,
    TcpState::Established,
    TcpState::CloseWait,
    TcpState::FinWaitOne,
    TcpState::Closing,
    TcpState::LastAck,
    TcpState::FinWaitTwo,
    TcpState::TimeWait,
];

/// The state table of the platform this binary was built for — the names its
/// rows print, so the only names `-s TCP:` can mean. Windows and FreeBSD have
/// their own; anything else takes Linux's, the C's own.
pub fn tcp_state_table() -> &'static [TcpState] {
    if cfg!(windows) {
        &WINDOWS_TCP_STATES
    } else if cfg!(target_os = "freebsd") {
        &FREEBSD_TCP_STATES
    } else {
        &LINUX_TCP_STATES
    }
}

/// The state lsof reports for a socket row.
///
/// It is a tagged union because the C's is: `print_tcptpi()` branches on the
/// row's file type and looks the number up in a *different* table per family —
/// TCP's connection states, or an AF_UNIX socket's `socket_state`. Renderers
/// only ever need the name, so [`SockState::as_str`] is the common exit; the
/// tag matters to the one caller that must know a connection is established
/// before asking Windows for its per-connection statistics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SockState {
    Tcp(TcpState),
    Unix(UnixState),
}

impl SockState {
    /// lsof-style state name, e.g. `LISTEN` or `UNCONNECTED`.
    pub fn as_str(self) -> &'static str {
        match self {
            SockState::Tcp(s) => s.as_str(),
            SockState::Unix(s) => s.as_str(),
        }
    }
}

impl From<TcpState> for SockState {
    fn from(s: TcpState) -> Self {
        SockState::Tcp(s)
    }
}

impl From<UnixState> for SockState {
    fn from(s: UnixState) -> Self {
        SockState::Unix(s)
    }
}

/// An AF_UNIX socket's state — the kernel's `socket_state` enum, as the `St`
/// column of `/proc/net/unix` spells it, plus lsof's `LISTEN`, which is not a
/// state at all: a listening socket sits in `SS_UNCONNECTED` and is told apart
/// only by `SO_ACCEPTCON` in the `Flags` column.
///
/// Unlike TCP, *every* AF_UNIX row has one — a number lsof cannot place comes
/// out as `UNKNOWN`, not as "no state".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnixState {
    Listen,
    Unconnected,
    Connecting,
    Connected,
    Disconnecting,
    Unknown,
}

impl UnixState {
    pub fn as_str(self) -> &'static str {
        match self {
            UnixState::Listen => "LISTEN",
            UnixState::Unconnected => "UNCONNECTED",
            UnixState::Connecting => "CONNECTING",
            UnixState::Connected => "CONNECTED",
            UnixState::Disconnecting => "DISCONNECTING",
            UnixState::Unknown => "UNKNOWN",
        }
    }
}

/// Network details for a socket-backed [`OpenFile`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SocketInfo {
    pub protocol: Protocol,
    pub local: Option<SocketAddr>,
    pub remote: Option<SocketAddr>,
    /// `Some` for every TCP and AF_UNIX socket. A UDP socket has one where the
    /// platform numbers it: Linux gives UDP the TCP numbering — `CLOSE` for
    /// the usual unconnected socket, `ESTABLISHED` for a connected one — and
    /// `-s TCP:` filters on it, though only `ESTABLISHED` is ever printed (see
    /// [`SocketInfo::shown_state`]). Windows has no UDP state: `None`.
    pub state: Option<SockState>,
    /// `-T q/w` extended TCP info. A backend populates this only when the run
    /// requested it and the per-connection stats were readable; `None`
    /// otherwise, so renderers emit nothing extra on a plain run.
    pub tcp: Option<TcpExtInfo>,
    /// What a path argument can find an AF_UNIX socket by. A backend fills
    /// it only when the run named a path, since nothing else reads it; boxed
    /// so a socket row pays one pointer for it otherwise.
    pub bound: Option<Box<BoundPath>>,
}

/// The path an AF_UNIX socket is bound to: the only thing the C finds a
/// socket by (`dsock.c:3726-3750`), never the row's own identity
/// ([`OpenFile::is_socket`]). A path argument finds the socket when it names
/// the socket file at that path, or, failing that, when it is the path itself
/// as typed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundPath {
    /// The bound path, as the kernel reports it: what a path argument typed
    /// exactly as it finds the socket by. `None` when it is not UTF-8, which
    /// no argument can be, so that its U+FFFD form cannot pass for another
    /// socket's path that really holds U+FFFD.
    pub path: Option<String>,
    /// The identity of the socket file at `path` (its `st_dev` and inode, as
    /// `dsock.c` keeps `sb_dev` and `sb_ino`), when it is a socket file:
    /// what a path argument's own identity is compared with. `None` when
    /// the path is not absolute, cannot be stat'ed, or is no longer a
    /// socket (a file put in its place after the bind).
    pub id: Option<FileId>,
}

/// What a file is, as the C's `is_file_named()` compares it (`dfile.c`):
/// the device of the file system holding it, `st_dev`, and its inode —
/// `Lf->dev` and `Lf->inode`, which `-F D` and `-F i` print.
///
/// A device node's is the node's own, on the file system that holds it, and
/// never the device it names (`st_rdev`, which the DEVICE cell shows):
/// `/dev/zero` is `(0,6, 4)` on this host's devtmpfs, not `1,5`. lsof-rs had
/// keyed on the DEVICE cell, which missed a mapping of the node the C finds
/// by its maps line (`mem REG 0,6 4 /dev/zero`), and found a node in another
/// file system whose device number and inode equalled another file's: the
/// same pty index in another devpts instance, a container's `/dev/null`
/// (DIVERGENCES 101).
///
/// A path argument, a `+d`/`+D` entry and an AF_UNIX socket's bound path
/// each get one from a `stat` ([`crate::Backend::identify_stat`]); a row
/// carries one in [`OpenFile::fs_device`] and [`OpenFile::node`]
/// ([`OpenFile::file_id`]). Plain numbers, so that a platform whose files
/// are told apart by another pair (a volume serial and a file index) can
/// fill it too.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FileId {
    /// `st_dev`: the file system the file is on.
    pub dev: u64,
    /// `st_ino`.
    pub ino: u64,
}

/// Extended per-connection TCP statistics for `-T` (Windows EStats). Each
/// member is present only if its sub-flag was requested (`q` → queues, `w` →
/// window) and the kernel returned it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TcpExtInfo {
    /// Receive window currently advertised, in bytes (`-Tw`; lsof's `WR=`).
    pub recv_window: Option<u32>,
    /// Bytes queued for the application to read (`-Tq`; lsof's `QR=`).
    pub recv_queue: Option<u64>,
    /// Bytes queued to send (`-Tq`; lsof's `QS=`).
    pub send_queue: Option<u64>,
    /// What FreeBSD's pcblists say of the socket, for `-T f` and for where
    /// the C prints its TCP/TPI facts at all (DIVERGENCES 147). `None` on
    /// every other platform.
    pub bsd: Option<BsdSocket>,
}

/// A FreeBSD socket's `-T` record, as the C's `process_socket()` fills
/// `Lf->lts` from the `kinfo_file` and the socket's `xsocket` and `xtcpcb`
/// (`dsock.c:404-430`, `:558-572`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BsdSocket {
    /// `Lf->lts.type >= 0`: a TCP socket whose `xtcpcb` was found. Only such
    /// a row has its facts printed in `-F` and JSON, and in the table unless
    /// `-T q` (whose queues every FreeBSD socket has) is asked for.
    pub record: bool,
    /// The socket's `xsocket`, where its pcblist entry was found.
    pub xsocket: Option<BsdXSocket>,
    /// `kf_sock_rcv_sb_state` and `kf_sock_snd_sb_state`.
    pub sbs_rcv: u16,
    pub sbs_snd: u16,
    /// A TCP socket's `t_flags` and `t_maxseg`, where its `xtcpcb` was found.
    pub tcp: Option<(u32, u32)>,
}

/// What `-T f` prints of a FreeBSD `struct xsocket` (`sys/socketvar.h`):
/// the fields as the kernel holds them, signed where it holds them signed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BsdXSocket {
    pub options: i16,
    pub linger: i16,
    pub state: i16,
    pub qlen: u32,
    pub incqlen: u32,
    pub qlimit: u32,
    pub rcv_mbmax: u32,
    pub snd_mbmax: u32,
}

/// A FreeBSD numbered descriptor's `struct file` values, which `+f c`, `+f f`
/// and `+f n` show (DIVERGENCES 142): the C's `Lf->fct`, `Lf->fsa` and
/// `Lf->fna`, each `None` where its `Lf->fsv` bit is not set. Kept per
/// process ([`Process::file_structs`]), not per row: only FreeBSD has them,
/// and a row on every host would pay for them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileStruct {
    /// `kf_ref_count` (FCT).
    pub count: Option<i64>,
    /// `xf_file` (FILE-ADDR), as wide as the C's `KA_T`.
    pub addr: Option<u64>,
    /// `xf_data`, or a vnode's `xf_vnode` (NODE-ID).
    pub node: Option<u64>,
}

impl SocketInfo {
    /// The state lsof prints for this socket. A UDP socket shows one only when
    /// it is `ESTABLISHED`: the C's UDP state table on Linux registers that
    /// one name (`build_IPstates()`), so an unconnected socket — whose
    /// [`SocketInfo::state`] is `CLOSE` — prints none. A UDP-Lite socket
    /// shows none at all: the C has no state table for it, and a connected
    /// one prints no `(ESTABLISHED)` and no `TST=` (measured). Every renderer
    /// asks this, never the field.
    pub fn shown_state(&self) -> Option<SockState> {
        match (self.protocol, self.state) {
            (Protocol::UdpLite, _) => None,
            (Protocol::Udp, Some(SockState::Tcp(t))) if t != TcpState::Established => None,
            (_, state) => state,
        }
    }

    /// The state `-s TCP:` tests this socket by, if it is one it tests at all.
    ///
    /// The C on Linux runs one path for every socket it finds in the TCP and
    /// UDP tables (`process_proc_sock()`), and that path checks the TCP lists
    /// against the kernel's number — so a UDP socket is included or excluded
    /// by its reused TCP state, measured: `-s TCP:CLOSE` lists the unconnected
    /// UDP socket and `-s TCP:LISTEN` drops it. Everything else — an AF_UNIX,
    /// raw or ICMP socket, a regular file, a Windows UDP socket (no state) —
    /// is never touched by `-s`.
    pub fn filter_state(&self) -> Option<TcpState> {
        match self.state {
            Some(SockState::Tcp(t)) => Some(t),
            _ => None,
        }
    }

    /// Whether this is a FreeBSD row's socket: the one backend that fills
    /// [`TcpExtInfo::bsd`], and fills it for every socket row it makes.
    pub fn is_bsd(&self) -> bool {
        self.tcp.is_some_and(|t| t.bsd.is_some())
    }

    /// The two ends the C entered for the socket (`ent_inaddr()`), local
    /// then foreign: what NAME prints (`printinaddr()`) and what `-i`'s
    /// address specifications are compared with, an end at a time
    /// (`is_nw_addr()`).
    ///
    /// On Linux an end whose address is unspecified and whose port is 0 is
    /// none (`dsock.c`: `if (tp->faddr || tp->fport) fa = …; else fa = NULL`).
    /// A FreeBSD row's ends are the ones its backend recorded, as they are:
    /// that dialect enters the local end of every Internet socket it finds a
    /// PCB for, and the foreign end of every IPv4 one, unspecified or not
    /// (DIVERGENCES 180), so `0.0.0.0:0` is an end there, printed `*:*` and
    /// matched by `-i :0`.
    pub fn entered_ends(&self) -> [Option<SocketAddr>; 2] {
        if self.is_bsd() {
            return [self.local, self.remote];
        }
        let end = |a: Option<SocketAddr>| a.filter(|a| !is_unspecified(a));
        [end(self.local), end(self.remote)]
    }

    /// Render the lsof NAME field for a socket, honoring name/port resolution
    /// suppression. With both `numeric_*` flags set the output is purely
    /// numeric (the `-n -P` behavior).
    ///
    /// Examples: `*:445 (LISTEN)`, `127.0.0.1:51000->127.0.0.1:445 (ESTABLISHED)`.
    pub fn display_name(&self, _numeric_host: bool, _numeric_port: bool) -> String {
        // Host/port name resolution is a backend concern; the core always
        // renders the numeric form it is given. The flags are accepted here so
        // renderers have a single call site if resolution is added later.
        let mut s = match &self.local {
            Some(a) => fmt_addr(a),
            None => "*:*".to_string(),
        };
        if let Some(r) = &self.remote {
            if !is_unspecified(r) {
                s.push_str("->");
                s.push_str(&fmt_addr(r));
            }
        }
        s
    }
}

fn is_unspecified(a: &SocketAddr) -> bool {
    a.ip().is_unspecified() && a.port() == 0
}

/// Format an address the lsof way: a wildcard IP becomes `*`, and IPv6
/// literals are bracketed.
fn fmt_addr(a: &SocketAddr) -> String {
    let host = if a.ip().is_unspecified() {
        "*".to_string()
    } else {
        match a {
            SocketAddr::V4(v4) => v4.ip().to_string(),
            SocketAddr::V6(v6) => format!("[{}]", v6.ip()),
        }
    };
    format!("{host}:{}", a.port())
}

/// A single open file / handle held by a process — analog of `struct lfile`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenFile {
    pub fd: FdType,
    pub access: AccessMode,
    pub file_type: FileType,
    /// Resolved path, object name, or socket display string (the NAME column).
    pub name: String,
    /// DEVICE column (volume / drive), if known.
    pub device: Option<String>,
    /// File size in bytes (SIZE/OFF column), if known.
    pub size: Option<u64>,
    /// Current file offset, if known (rarely available on Windows).
    pub offset: Option<u64>,
    /// NODE column — the file-index (inode analog) for files, or the protocol
    /// (`TCP`/`UDP`) for sockets.
    pub node: Option<String>,
    /// Hard-link count from `BY_HANDLE_FILE_INFORMATION.nNumberOfLinks`, when
    /// known. Surfaced as the NLINK column under `-L` and used by `+L count`
    /// to filter to files with fewer than `count` links (e.g. `+L1` for
    /// unlinked-but-still-open files — a security-interesting case).
    pub links: Option<u32>,
    /// A lock held on this file, shown as a suffix on the FD cell (`8uW`).
    /// `None` means no lock, or a platform that cannot enumerate them.
    pub lock: Option<LockKind>,
    /// The **filesystem** device the file lives on (`st_dev`), which is not
    /// always what [`OpenFile::device`] displays: for a character or block
    /// special, that cell shows the device the node *names* (`st_rdev`)
    /// instead. lsof keeps them apart too — `-F D` reports this one and `-F r`
    /// the raw one — and the mount-point rule (`lsof /mnt` selecting a whole
    /// filesystem) needs this one as well. `None` where the platform does not
    /// supply it.
    pub fs_device: Option<u64>,
    /// The device a character or block special *names*: `st_rdev` as the
    /// kernel encodes it, which `-F r` prints in hex (`r0x103` for
    /// `/dev/null`). `None` on every other row, and on Windows, which has no
    /// such number. It is a `NonZeroU32` so the row keeps its size, the niche
    /// fitting the padding: Linux encodes a 12-bit major and a 20-bit minor in
    /// 32 bits, and the one number that cannot be carried is 0 — device 0,0,
    /// which no driver answers, so only an `O_PATH` fd could hold it.
    pub rdev: Option<std::num::NonZeroU32>,
    /// The open file's flags, as the kernel reports them (`O_RDWR`,
    /// `O_CLOEXEC`, …). lsof's `-F G` field prints them in hex. `None` where
    /// unknown.
    pub file_flags: Option<u32>,
    /// Present iff this is a network socket.
    ///
    /// Boxed because it is the largest field by far and absent from almost
    /// every row: inline, a `SocketInfo` is 136 bytes carried by each of the
    /// ~18,000 rows of a 1079-process host, of which about a thousand are
    /// sockets. Every row is held until the whole host has been walked (the C
    /// does that too), so the row's size is paid per row for the whole run.
    /// Boxing took `OpenFile` from 320 bytes to 192 (DIVERGENCES 30).
    pub socket: Option<Box<SocketInfo>>,
    /// How many bytes at the end of [`OpenFile::name`] are an addition rather
    /// than the name itself — the C's `Lf->nma` beside its `Lf->nm`: the
    /// `(readlink: …)`, `(stat: …)`, `(opendir: …)`, `(-e FS)` or `(path …)`
    /// a backend appends, with the one space that joins it. The table and
    /// `-F n` print the whole; JSON prints only [`OpenFile::base_name`], as
    /// the C's `json_print_file()` prints `Lf->nm` alone (`print.c:1991`).
    /// Set only through [`OpenFile::add_name_addition`] (and, for text
    /// already in printed form, the core's `-E` naming). Eight bytes, in the
    /// padding the row already had: it stays 192 (`a_row_stays_small`).
    pub name_addition: Option<NameAddition>,
}

/// [`OpenFile::name_addition`]: where NAME's base ends and its addition
/// begins, and whether that addition is already in printed form.
///
/// The base's length is recorded, not the addition's: a base is a path or an
/// object's name, bounded by `PATH_MAX` (a path argument longer than that
/// names no file), so 14 bits hold it (16,382 bytes, four times Linux's
/// 4096), where an addition is not. `-E` names every other holder of a pipe in one row, and
/// 4,000 processes sharing one make an addition of 131,000 bytes, which a
/// `u16` addition length had dropped, leaking all but the last holder into
/// JSON's `name` (DIVERGENCES 56).
///
/// Printed form is for `-E`'s `PID,cmd,FDmode`, whose command the C cuts to
/// `+c` *bytes* and prints through `safestrprt()`, so a cut inside a
/// character prints the bytes it kept as `\xNN` (`\xc3`). A `String` cannot
/// hold such a byte, so that text is stored as it is printed, and the
/// renderer does not escape it again ([`OpenFile::printed_name`]).
///
/// A base that is shown, not the row's own name, is the text the C's
/// `printname()` makes up for a row whose `Lf->nm` is empty — FreeBSD's
/// device name from `/dev`, or a file system's `dir (fsname)` (DIVERGENCES
/// 146): the table and `-F n` print it, JSON's `name`, which is `Lf->nm`,
/// does not, and a path argument that renames the row replaces it, as the
/// C's `Lf->nm` then hides it ([`OpenFile::set_shown_name`]). Two
/// bytes, with the `Option` in its niche, in the padding the row already
/// had: it stays 192 (`a_row_stays_small`, which three bytes fail).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NameAddition(std::num::NonZeroU16);

impl NameAddition {
    const PRINTED: u16 = 0x8000;
    const SHOWN: u16 = 0x4000;

    /// NAME's first `base` bytes are its base, the rest an addition in plain
    /// text; `None` for a base too long to record (16,382 bytes).
    pub fn new(base: u32) -> Option<NameAddition> {
        Self::with(base, false, false)
    }

    fn with(base: u32, printed: bool, shown: bool) -> Option<NameAddition> {
        let stored = u16::try_from(base)
            .ok()?
            .checked_add(1)
            .filter(|&v| v < Self::SHOWN)?;
        let flag = if printed { Self::PRINTED } else { 0 } | if shown { Self::SHOWN } else { 0 };
        std::num::NonZeroU16::new(stored | flag).map(NameAddition)
    }

    fn at(base: usize, printed: bool, shown: bool) -> Option<NameAddition> {
        Self::with(u32::try_from(base).ok()?, printed, shown)
    }

    /// How many bytes of NAME are its base.
    pub fn base(self) -> u32 {
        u32::from((self.0.get() & !(Self::PRINTED | Self::SHOWN)).saturating_sub(1))
    }

    /// Whether the addition is printed text ([`OpenFile::printed_name`]).
    pub fn printed(self) -> bool {
        self.0.get() & Self::PRINTED != 0
    }

    /// Whether the base is shown text, not the row's name
    /// ([`OpenFile::set_shown_name`]).
    pub fn shown(self) -> bool {
        self.0.get() & Self::SHOWN != 0
    }
}

impl OpenFile {
    /// NAME without its addition: the C's `Lf->nm`, which JSON's `name` is.
    /// `None` when that is empty, as the C's is NULL for a `NOFD` row, whose
    /// whole NAME is the addition. An addition longer than the name, or one
    /// that would split a character, is no addition at all: the whole name,
    /// never a panic.
    ///
    /// `None` too for a base that is only shown ([`OpenFile::set_shown_name`]).
    pub fn base_name(&self) -> Option<&str> {
        if self.name_addition.is_some_and(NameAddition::shown) {
            return None;
        }
        let base = self.base_text();
        (!base.is_empty()).then_some(base)
    }

    /// NAME's base, shown or not: what an addition follows.
    fn base_text(&self) -> &str {
        self.name_addition
            .and_then(|a| self.name.get(..a.base() as usize))
            .unwrap_or(&self.name)
    }

    /// Give a row whose NAME is empty the text the C's `printname()` prints
    /// for it, where the C's `Lf->nm` is empty (FreeBSD's device name, a
    /// file system's `dir (fsname)`): the table and `-F n` print it as NAME,
    /// JSON's `name` is still none ([`OpenFile::base_name`]), and a path
    /// argument's name replaces it ([`OpenFile::set_base_name`]). An
    /// addition stays after it. Nothing is done to a row that has a base,
    /// or for a text too long to record (16,382 bytes).
    pub fn set_shown_name(&mut self, text: &str) {
        if text.is_empty() || !self.base_text().is_empty() {
            return;
        }
        let printed = self.name_addition.is_some_and(NameAddition::printed);
        let Some(shown) = NameAddition::at(text.len(), printed, true) else {
            return;
        };
        self.set_base_name(text);
        self.name_addition = Some(shown);
    }

    /// NAME as the table and `-F n` print it: escaped by `esc`, except an
    /// addition that is already printed text ([`NameAddition::printed`]).
    /// That is checked rather than trusted: one holding anything a terminal
    /// would act on, or a length that does not fall on a character
    /// boundary, is escaped like the rest.
    pub fn printed_name(&self, esc: &crate::render::escape::Escaper) -> std::borrow::Cow<'_, str> {
        let split = self
            .name_addition
            .filter(|a| a.printed())
            .map(|a| a.base() as usize)
            .filter(|&at| self.name.is_char_boundary(at));
        let Some(at) = split else {
            return esc.text(&self.name);
        };
        let (text, tail) = self.name.split_at(at);
        if tail
            .chars()
            .any(crate::render::escape::is_unprintable_unicode)
        {
            return esc.text(&self.name);
        }
        let mut out = esc.text(text).into_owned();
        out.push_str(tail);
        std::borrow::Cow::Owned(out)
    }

    /// [`OpenFile::printed_name`] into `out` a call at a time, as the C's
    /// `printname()` prints it: `safestrprt()`'s `putc()`s and `fputs()`s,
    /// the addition kept printed cut by [`crate::render::Calls::printed`].
    pub fn printed_name_calls(
        &self,
        esc: &crate::render::escape::Escaper,
        out: &mut crate::render::Calls,
    ) {
        let split = self
            .name_addition
            .filter(|a| a.printed())
            .map(|a| a.base() as usize)
            .filter(|&at| self.name.is_char_boundary(at));
        let Some(at) = split else {
            esc.text_calls(&self.name, out);
            return;
        };
        let (text, tail) = self.name.split_at(at);
        if tail
            .chars()
            .any(crate::render::escape::is_unprintable_unicode)
        {
            esc.text_calls(&self.name, out);
            return;
        }
        esc.text_calls(text, out);
        out.printed(tail);
    }

    /// Append `text` to NAME as an addition (the C's `Lf->nma`), after one
    /// space, or alone on an empty NAME. Where the base ends is recorded so
    /// JSON can leave the addition out ([`OpenFile::base_name`]); a base too
    /// long to record (16,382 bytes) leaves none recorded. After printed text,
    /// `text` is escaped into it, so the addition stays one piece.
    pub fn add_name_addition(&mut self, text: &str) {
        if self.name_addition.is_some_and(NameAddition::printed) {
            let printed = crate::render::escape::Escaper::for_host()
                .text(text)
                .into_owned();
            self.push_addition(&printed, true);
        } else {
            self.push_addition(text, false);
        }
    }

    /// [`OpenFile::add_name_addition`] for `printed`, text already in the
    /// form the table and `-F n` print it in. An addition in plain text
    /// before it is escaped now, as the renderer would have, so that the
    /// whole addition is printed text ([`NameAddition::printed`]).
    pub(crate) fn add_printed_addition(&mut self, printed: &str) {
        if let Some(a) = self.name_addition.filter(|a| !a.printed()) {
            let at = a.base() as usize;
            if let Some(plain) = self.name.get(at..) {
                let escaped = crate::render::escape::Escaper::for_host()
                    .text(plain)
                    .into_owned();
                self.name.truncate(at);
                self.name.push_str(&escaped);
                self.name_addition = NameAddition::at(at, true, a.shown());
            }
        }
        self.push_addition(printed, true);
    }

    fn push_addition(&mut self, text: &str, printed: bool) {
        let (base, shown) = match self.name_addition {
            Some(a) if (a.base() as usize) <= self.name.len() => (a.base() as usize, a.shown()),
            _ => (self.name.len(), false),
        };
        if !self.name.is_empty() {
            self.name.push(' ');
        }
        self.name.push_str(text);
        self.name_addition = NameAddition::at(base, printed, shown);
    }

    /// Replace NAME's base, the C's `Lf->nm`, with `base`, keeping its
    /// addition, the C's `Lf->nma`: what a path argument does to a row it
    /// locates ([`crate::selection::PathItem::row_name`]). An addition that
    /// stood alone, on an empty name, is joined to the new one by a space,
    /// as [`OpenFile::add_name_addition`] would have joined it.
    ///
    /// A base that was only shown ([`OpenFile::set_shown_name`]) is replaced
    /// as a base is: the C's `printname()` prints `Lf->nm` once it is set,
    /// and makes nothing up.
    pub fn set_base_name(&mut self, base: &str) {
        let old = self.base_text().len();
        // `base_name` gives the whole name back for a base it cannot use, so
        // the tail is then empty and nothing is recorded as an addition.
        let tail = self.name.get(old..).unwrap_or_default().to_string();
        let printed = self.name_addition.is_some_and(NameAddition::printed);
        self.name.clear();
        self.name.push_str(base);
        self.name_addition = None;
        if !tail.is_empty() {
            if old == 0 {
                // The addition alone: no joining space was recorded.
                self.push_addition(&tail, printed);
            } else {
                self.name.push_str(&tail);
                self.name_addition = NameAddition::at(base.len(), printed, false);
            }
        }
    }

    /// True if this file is an Internet (IPv4/IPv6) socket — the `-i` predicate.
    pub fn is_internet(&self) -> bool {
        self.socket.is_some() && matches!(self.file_type, FileType::Ipv4 | FileType::Ipv6)
    }

    /// True for a row `-e` exempted ([`FileType::Exempt`]). Its DEVICE and
    /// NODE are only what a maps line said, never a `stat`: a path argument,
    /// a file-system argument and `-N` pass it by, and it is never located,
    /// as the C's `isefsys()` rows never reach `is_file_named()`. Measured:
    /// `lsof -e MNT MNT/f`, where `f` is mapped and on nothing else, prints
    /// nothing and exits 1.
    pub fn is_exempt(&self) -> bool {
        matches!(self.file_type, FileType::Exempt(_))
    }

    /// True for a socket's row: one a table describes ([`OpenFile::socket`])
    /// and one none does ([`FileType::Socket`]). The C hands every `S_IFSOCK`
    /// to `process_proc_sock()` and returns (`dnode.c:700-705`), which never
    /// asks `is_file_named()` about the socket's own device and inode; only
    /// an AF_UNIX socket's bound path is compared (`dsock.c:3726-3750`,
    /// [`BoundPath`]). So none is found by its own identity or file system:
    /// measured, the C passes by a TCP socket no table lists under `-x l +d
    /// /proc/PID/fd`, and an `O_PATH` descriptor on a socket file under that
    /// file's path and under its file system (DIVERGENCES 101).
    pub fn is_socket(&self) -> bool {
        self.socket.is_some() || matches!(self.file_type, FileType::Socket(_))
    }

    /// The file system a file-system argument finds this row on:
    /// [`OpenFile::fs_device`], the C's `Lf->dev` as `is_file_named()`
    /// compares it with a mount's (`dfile.c:242-276`). `None` for a row the
    /// C never asks about: one `-e` exempted, never `stat`ed (`isefsys()`),
    /// and a socket ([`OpenFile::is_socket`]), whose `fs_device` `-F D` still
    /// prints.
    pub fn searched_fs_device(&self) -> Option<u64> {
        if self.is_exempt() || self.is_socket() {
            return None;
        }
        self.fs_device
    }

    /// What a path argument finds this row by: [`OpenFile::fs_device`] and
    /// the inode in [`OpenFile::node`], the C's `Lf->dev` and `Lf->inode`
    /// (`dnode.c`), which `-F D` and `-F i` print. For a mapping the C could
    /// not `stat` they are the maps line's, and that row is found too.
    ///
    /// `None` where [`OpenFile::searched_fs_device`] is (an `-e` row, a
    /// socket, whether or not a table names it), and for a row with no
    /// device or no numeric inode: a file that could not be read.
    pub fn file_id(&self) -> Option<FileId> {
        Some(FileId {
            dev: self.searched_fs_device()?,
            ino: self.node.as_deref()?.parse().ok()?,
        })
    }
}

/// A process's files: a list a copy of the process shares until one of
/// them changes it (`Arc::make_mut`). Under `-K` every thread of a process
/// is an entry of its own with the process's files (the C reads them again
/// for each, `dproc.c:432-477`); shared, they are held once a process
/// however many threads it has, where a copy each made the run's memory the
/// threads times the files (DIVERGENCES 141). It reads as a
/// `Vec<OpenFile>`, and a change to it is made to the entry's own copy.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Files(std::sync::Arc<Vec<OpenFile>>);

impl Files {
    /// Whether `self` and `other` are one list, not two copies.
    pub fn shares(&self, other: &Files) -> bool {
        std::sync::Arc::ptr_eq(&self.0, &other.0)
    }
}

impl std::ops::Deref for Files {
    type Target = Vec<OpenFile>;

    fn deref(&self) -> &Vec<OpenFile> {
        &self.0
    }
}

impl std::ops::DerefMut for Files {
    /// The entry's own list, copied first where another entry shares it.
    fn deref_mut(&mut self) -> &mut Vec<OpenFile> {
        std::sync::Arc::make_mut(&mut self.0)
    }
}

impl From<Vec<OpenFile>> for Files {
    fn from(files: Vec<OpenFile>) -> Self {
        Files(std::sync::Arc::new(files))
    }
}

impl FromIterator<OpenFile> for Files {
    fn from_iter<I: IntoIterator<Item = OpenFile>>(iter: I) -> Self {
        Files::from(iter.into_iter().collect::<Vec<_>>())
    }
}

impl IntoIterator for Files {
    type Item = OpenFile;
    type IntoIter = std::vec::IntoIter<OpenFile>;

    fn into_iter(self) -> Self::IntoIter {
        std::sync::Arc::unwrap_or_clone(self.0).into_iter()
    }
}

impl<'a> IntoIterator for &'a Files {
    type Item = &'a OpenFile;
    type IntoIter = std::slice::Iter<'a, OpenFile>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'a> IntoIterator for &'a mut Files {
    type Item = &'a mut OpenFile;
    type IntoIter = std::slice::IterMut<'a, OpenFile>;

    fn into_iter(self) -> Self::IntoIter {
        std::sync::Arc::make_mut(&mut self.0).iter_mut()
    }
}

impl PartialEq<Vec<OpenFile>> for Files {
    fn eq(&self, other: &Vec<OpenFile>) -> bool {
        *self.0 == *other
    }
}

/// A process and the files it has open — analog of `struct lproc`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Process {
    pub pid: u32,
    pub ppid: Option<u32>,
    /// The process image name (lsof "COMMAND").
    pub command: String,
    /// The owning account's name (lsof "USER"), e.g. `alice` or
    /// `DOMAIN\\user`. `None` where there is no name to show — on Linux under
    /// `-l`, or for a UID no account has — and then the USER column shows
    /// [`Process::uid`] as the C does, and `-F` writes no `L` field.
    pub user: Option<String>,
    /// `-K`: the thread id, when this entry is a **task** rather than the
    /// process itself. lsof models a task as its own process — it repeats the
    /// whole file set, because a Linux thread can hold its own cwd, root and
    /// fd table (`CLONE_FS`/`CLONE_FILES` are optional) — so a task is another
    /// `Process` with the same `pid` and this set. `None` for the main thread,
    /// which is listed as the process and shows a blank TID cell.
    pub tid: Option<u32>,
    /// `-K`: the task's own `comm`, shown in the TASKCMD column and the `-F`
    /// `M` field. `None` whenever [`Process::tid`] is.
    pub task_command: Option<String>,
    /// Numeric owner id, for lsof's `-F u` field. The USER column shows
    /// [`Process::user`]; scripts asking for `u` want the number.
    pub uid: Option<u32>,
    /// Process group ID, for lsof's `-F g` field. `None` on platforms without
    /// process groups (Windows).
    pub pgid: Option<u32>,
    pub files: Files,
    /// `+E`: set by a backend when this process is in the result only because
    /// it is the peer endpoint of a selected process's pipe. The selection
    /// engine keeps such a process (its pipe rows only) even though it matches
    /// no process selector — lsof's "endpoint files are also displayed".
    pub endpoint_peer: bool,
    /// Set by a backend that read this process and has no file to show for it,
    /// on a platform where — as in the C — a process is listed only through
    /// its files. It gets no line, not a bare one; it is still *found*, so a
    /// `-p` naming it is located. On Linux that is a process whose every file
    /// is unreadable under `-w` or `-t` (which sets `-w`): the C makes no row
    /// for a file it cannot read then (DIVERGENCES 37). Windows never sets it,
    /// and keeps the bare line for a process whose handles it could not read.
    pub unlisted: bool,
    /// The process's names as bytes, where a [`String`] could not hold them
    /// ([`RawNames`]); `None`, the common case, where both are UTF-8 (or the
    /// platform's names are text).
    pub raw_names: Option<Box<RawNames>>,
    /// FreeBSD: each numbered descriptor's [`FileStruct`], by descriptor
    /// number, sorted; `None` where none was asked for (no `+f c`/`f`/`n`)
    /// and on every other platform.
    pub file_structs: Option<std::sync::Arc<[(u64, FileStruct)]>>,
}

/// A command, login or thread name that is not UTF-8, kept as the bytes it
/// is, for what the C does with bytes: `-c` compares the command's bytes,
/// COMMAND and `-F c` print each byte that is not text as `\xNN`, USER and
/// `-F L` the login's (DIVERGENCES 92, 70), and TASKCMD the thread name's
/// (DIVERGENCES 93). [`Process::command`], [`Process::user`] and
/// [`Process::task_command`] still hold them decoded lossily, for JSON,
/// which must be UTF-8, for `-F M`, and for whatever reads them as text.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RawNames {
    /// The command's bytes, where they are not UTF-8.
    pub command: Option<Box<[u8]>>,
    /// The login's bytes (cut to the C's 32), where they are not UTF-8.
    pub login: Option<Box<[u8]>>,
    /// A task's own name's bytes ([`Process::task_command`]), where they
    /// are not UTF-8.
    pub task_command: Option<Box<[u8]>>,
}

impl Process {
    /// The [`FileStruct`] of `f`, one of this process's rows: a numbered
    /// descriptor's, where the backend recorded one.
    pub fn file_struct(&self, f: &OpenFile) -> Option<&FileStruct> {
        let FdType::Handle(n) = f.fd else {
            return None;
        };
        let all = self.file_structs.as_deref()?;
        all.binary_search_by_key(&n, |(fd, _)| *fd)
            .ok()
            .and_then(|i| all.get(i))
            .map(|(_, s)| s)
    }

    /// The command as bytes: [`RawNames::command`], or [`Process::command`].
    pub fn command_bytes(&self) -> &[u8] {
        self.raw_names
            .as_deref()
            .and_then(|r| r.command.as_deref())
            .unwrap_or(self.command.as_bytes())
    }

    /// A task's name as bytes: [`RawNames::task_command`], or
    /// [`Process::task_command`]. `None` for an entry that is no task.
    pub fn task_command_bytes(&self) -> Option<&[u8]> {
        let text = self.task_command.as_deref()?;
        Some(
            self.raw_names
                .as_deref()
                .and_then(|r| r.task_command.as_deref())
                .unwrap_or(text.as_bytes()),
        )
    }

    /// The login as bytes: [`RawNames::login`], or [`Process::user`].
    pub fn login_bytes(&self) -> Option<&[u8]> {
        self.raw_names
            .as_deref()
            .and_then(|r| r.login.as_deref())
            .or(self.user.as_deref().map(str::as_bytes))
    }

    /// Give the process its login, `login`'s bytes: [`Process::user`]
    /// decoded (lossily), and [`RawNames::login`] where it is not UTF-8.
    pub fn set_login(&mut self, login: Box<[u8]>) {
        self.user = Some(String::from_utf8_lossy(&login).into_owned());
        if std::str::from_utf8(&login).is_err() {
            self.raw_names.get_or_insert_with(Box::default).login = Some(login);
        }
    }
}

#[cfg(test)]
mod login_tests {
    use super::*;

    /// A login is the process's user as text, and its bytes where they are
    /// not UTF-8, beside a command's that are kept already.
    #[test]
    fn a_login_is_set_as_text_and_as_bytes_where_it_is_not_utf8() {
        let mut p = crate::mock::sample_processes().remove(0);
        p.user = None;
        p.raw_names = None;
        p.set_login(b"root"[..].into());
        assert_eq!(
            (p.user.as_deref(), p.raw_names.as_ref()),
            (Some("root"), None)
        );
        p.raw_names = Some(Box::new(RawNames {
            command: Some(b"c\xff"[..].into()),
            login: None,
            task_command: None,
        }));
        p.set_login(b"ab\xffcd"[..].into());
        assert_eq!(p.user.as_deref(), Some("ab\u{fffd}cd"));
        assert_eq!(p.login_bytes(), Some(&b"ab\xffcd"[..]));
        assert_eq!(p.command_bytes(), b"c\xff");
    }
}

#[cfg(test)]
mod size_tests {
    use super::OpenFile;

    #[test]
    fn a_row_stays_small() {
        // Every row of every process is held until the whole host has been
        // walked, so this size is paid per row for the entire run. Boxing the
        // socket took it from 320 bytes to 192 (DIVERGENCES 30); the resource
        // gate cannot see a regression this small on a shared runner — an
        // unboxed socket reads 1.00x the C against 0.85x, inside a runner's
        // noise — so the size itself is the control. `<=`, because a 32-bit
        // target is smaller still.
        assert!(
            std::mem::size_of::<OpenFile>() <= 192,
            "OpenFile grew to {} bytes; a field added inline is paid by every \
             row on the host — box it if most rows leave it empty",
            std::mem::size_of::<OpenFile>()
        );
    }
}

#[cfg(test)]
mod name_addition_tests {
    use super::{AccessMode, FdType, FileType, OpenFile};

    fn row(name: &str) -> OpenFile {
        OpenFile {
            fd: FdType::Cwd,
            access: AccessMode::Unknown,
            file_type: FileType::Unknown,
            name: name.to_string(),
            device: None,
            size: None,
            offset: None,
            node: None,
            links: None,
            lock: None,
            fs_device: None,
            rdev: None,
            file_flags: None,
            socket: None,
            name_addition: None,
        }
    }

    /// The table's NAME is the whole; JSON's is the C's `Lf->nm`, the part
    /// before the joining space.
    #[test]
    fn an_addition_joins_with_one_space_and_is_not_the_base() {
        let mut f = row("/proc/1/cwd");
        f.add_name_addition("(readlink: Permission denied)");
        assert_eq!(f.name, "/proc/1/cwd (readlink: Permission denied)");
        assert_eq!(f.base_name(), Some("/proc/1/cwd"));
        // A second addition extends the first: the base stays where it was.
        f.add_name_addition("(stat: x)");
        assert_eq!(f.base_name(), Some("/proc/1/cwd"));
        assert_eq!(
            f.name,
            "/proc/1/cwd (readlink: Permission denied) (stat: x)"
        );
    }

    /// NOFD's whole NAME is the addition, so it has no base: the C's NULL
    /// `Lf->nm`, which JSON leaves out.
    #[test]
    fn an_addition_to_an_empty_name_is_the_whole_name() {
        let mut f = row("");
        f.add_name_addition("/proc/1/fd (opendir: Permission denied)");
        assert_eq!(f.name, "/proc/1/fd (opendir: Permission denied)");
        assert_eq!(f.base_name(), None);
        assert_eq!(row("").base_name(), None);
        assert_eq!(row("/a").base_name(), Some("/a"));
    }

    /// A path argument's name replaces the base and keeps the addition
    /// (DIVERGENCES 139): `alias (path dev=0,41, inode=2)`, measured. An
    /// addition that stood alone is joined by a space; a length that did not
    /// fit is no addition, and the whole name is replaced.
    #[test]
    fn a_new_base_keeps_the_addition() {
        let mut f = row("/w/shadow/s");
        f.add_name_addition("(path dev=0,41, inode=2)");
        f.set_base_name("alias");
        assert_eq!(f.name, "alias (path dev=0,41, inode=2)");
        assert_eq!(f.base_name(), Some("alias"));
        let mut g = row("/w/del.txt (deleted)");
        g.set_base_name("keep.txt");
        assert_eq!((g.name.as_str(), g.name_addition), ("keep.txt", None));
        let mut h = row("");
        h.add_name_addition("(stat: x)");
        h.set_base_name("y");
        assert_eq!(h.name, "y (stat: x)");
        assert_eq!(h.base_name(), Some("y"));
        let mut i = row("/a");
        i.name_addition = super::NameAddition::new(9);
        i.set_base_name("b");
        assert_eq!((i.name.as_str(), i.name_addition), ("b", None));
    }

    /// A recorded length past the name or inside a character gives the whole
    /// name back, never a panic.
    #[test]
    fn a_length_that_does_not_fit_is_no_addition() {
        let mut g = row("é");
        g.name_addition = super::NameAddition::new(1);
        assert_eq!(g.base_name(), Some("é"));
        g.name_addition = super::NameAddition::new(9);
        assert_eq!(g.base_name(), Some("é"));
    }

    /// A name only shown (FreeBSD's `printname()` text, DIVERGENCES 146) is
    /// printed with its additions, is no base for JSON, keeps a printed
    /// addition printed, is replaced by a path argument's name, and is not
    /// set over a row's own name. The longest base recorded is 16,382 bytes.
    #[test]
    fn a_name_only_shown_is_printed_and_is_no_base() {
        let mut f = row("");
        f.set_shown_name("/dev/pts/0");
        assert_eq!((f.name.as_str(), f.base_name()), ("/dev/pts/0", None));
        f.add_name_addition("(like character special /dev/x)");
        assert_eq!(f.name, "/dev/pts/0 (like character special /dev/x)");
        assert_eq!(f.base_name(), None);
        f.add_printed_addition("1,a\\xc3,3r");
        assert_eq!(f.base_name(), None, "still shown after printed text");
        assert!(f.name_addition.is_some_and(super::NameAddition::printed));
        f.set_base_name("/arg");
        assert_eq!(f.base_name(), Some("/arg"));
        assert!(f.name.starts_with("/arg (like character special /dev/x) "));
        // An addition first, the shown text before it.
        let mut g = row("");
        g.add_name_addition("(like character special /dev/x)");
        g.set_shown_name("/ (zfs)");
        assert_eq!(g.name, "/ (zfs) (like character special /dev/x)");
        assert_eq!(g.base_name(), None);
        // Never over a name, nor an empty text.
        let mut h = row("/a");
        h.set_shown_name("/b");
        assert_eq!((h.name.as_str(), h.base_name()), ("/a", Some("/a")));
        let mut e = row("");
        e.set_shown_name("");
        assert_eq!((e.name.as_str(), e.name_addition), ("", None));
        // The bound: 16,382 bytes recorded, one more not.
        let mut long = row("");
        long.set_shown_name(&"x".repeat(16_382));
        assert_eq!(long.base_name(), None);
        let mut longer = row("");
        longer.set_shown_name(&"x".repeat(16_383));
        assert_eq!((longer.name.as_str(), longer.name_addition), ("", None));
        assert!(super::NameAddition::new(16_382).is_some());
        assert!(super::NameAddition::new(16_383).is_none());
        assert!(!super::NameAddition::new(5).unwrap().shown());
    }

    /// `-E` names every other holder of a pipe, one addition each: past
    /// 65,535 bytes of them (a `u16` had dropped the length there and the
    /// next one had taken the whole NAME for its base), the base is still
    /// the C's `Lf->nm`, which is all JSON prints.
    #[test]
    fn additions_past_65535_bytes_keep_the_base() {
        let mut f = row("pipe");
        let n = if cfg!(miri) { 40 } else { 8_000 };
        for i in 0..n {
            f.add_name_addition(&format!("{},python3,{}r", 100_000 + i, 3 + i % 2));
        }
        assert!(cfg!(miri) || f.name.len() > 65_535);
        assert_eq!(f.base_name(), Some("pipe"));
        let mut g = row("pipe");
        g.add_name_addition(&"x".repeat(if cfg!(miri) { 70 } else { 70_000 }));
        g.add_name_addition("1,a,3r");
        assert_eq!(g.base_name(), Some("pipe"));
    }

    /// Printed text at NAME's end is not escaped again; the rest is, and an
    /// addition after it is escaped into it. A tail that would reach a
    /// terminal raw is escaped after all.
    #[test]
    fn a_printed_tail_is_printed_as_it_stands() {
        use crate::render::escape::Escaper;
        let esc = Escaper::UNIX;
        let mut f = row("a\\b");
        f.add_printed_addition("1,aaaaaaaa\\xc3,3r");
        assert_eq!(f.printed_name(&esc), "a\\\\b 1,aaaaaaaa\\xc3,3r");
        assert_eq!(f.base_name(), Some("a\\b"));
        f.add_name_addition("(x\u{1b})");
        assert_eq!(f.printed_name(&esc), "a\\\\b 1,aaaaaaaa\\xc3,3r (x^[)");
        assert_eq!(f.base_name(), Some("a\\b"));
        // A new base keeps the printed tail.
        f.set_base_name("n\\m");
        assert_eq!(f.printed_name(&esc), "n\\\\m 1,aaaaaaaa\\xc3,3r (x^[)");
        // Forged: an ESC in the tail is escaped with the rest.
        let mut g = row("p");
        g.add_printed_addition("\u{1b}]0;x\u{7}");
        assert_eq!(g.printed_name(&esc), "p ^[]0;x^G");
        // Plain text is escaped as ever.
        let mut h = row("p");
        h.add_name_addition("a\\b");
        assert_eq!(h.printed_name(&esc), "p a\\\\b");
        assert_eq!(row("").printed_name(&esc), "");
        // An addition alone on an empty name keeps its printed part.
        let mut k = row("");
        k.add_printed_addition("1,c\\xc3,3r");
        k.set_base_name("b");
        assert_eq!(k.printed_name(&esc), "b 1,c\\xc3,3r");
    }
}
