//! The platform-agnostic data model.
//!
//! [`Process`] is the analog of lsof's `struct lproc` and [`OpenFile`] of
//! `struct lfile` (see the C sources `lib/common.h` and `include/lsof.h`),
//! trimmed to the Windows MVP surface. Windows concepts are mapped onto lsof's
//! vocabulary: a Windows *handle* is an FD, the process *image* is the command,
//! the owning *SID*'s account name is the user, and so on.

use std::net::SocketAddr;

/// What kind of slot an [`OpenFile`] occupies — lsof's "FD" column.
#[derive(Clone, Debug, PartialEq, Eq)]
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
            FdType::Unknown => "unk".to_string(),
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Other(&'static str),
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Tcp => "TCP",
            Protocol::Udp => "UDP",
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

/// The state table of the platform this binary was built for — the names its
/// rows print, so the only names `-s TCP:` can mean. Anything but Windows
/// takes Linux's, the C's own.
pub fn tcp_state_table() -> &'static [TcpState] {
    if cfg!(windows) {
        &WINDOWS_TCP_STATES
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
}

impl SocketInfo {
    /// The state lsof prints for this socket. A UDP socket shows one only when
    /// it is `ESTABLISHED`: the C's UDP state table on Linux registers that
    /// one name (`build_IPstates()`), so an unconnected socket — whose
    /// [`SocketInfo::state`] is `CLOSE` — prints none. Every renderer asks this,
    /// never the field.
    pub fn shown_state(&self) -> Option<SockState> {
        match (self.protocol, self.state) {
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
}

impl OpenFile {
    /// True if this file is an Internet (IPv4/IPv6) socket — the `-i` predicate.
    pub fn is_internet(&self) -> bool {
        self.socket.is_some() && matches!(self.file_type, FileType::Ipv4 | FileType::Ipv6)
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
    pub files: Vec<OpenFile>,
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
