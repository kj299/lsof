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
    Unknown,
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
        }
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

/// TCP connection state (mirrors `MIB_TCP_STATE` / lsof's state names).
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
            TcpState::Unknown => "UNKNOWN",
        }
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
    /// `None` for connectionless protocols (UDP); always `Some` for AF_UNIX.
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
    pub socket: Option<SocketInfo>,
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
    /// Owning account, e.g. `DOMAIN\\user` (lsof "USER").
    pub user: Option<String>,
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
}
