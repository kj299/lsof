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

/// The kind of object an open file refers to — lsof's "TYPE" column.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileType {
    Regular,
    Dir,
    Chr,
    Fifo,
    Pipe,
    Ipv4,
    Ipv6,
    Unix,
    // Native Windows object types (shown when all-handle enumeration is enabled).
    Key,
    Event,
    Mutant,
    Section,
    Process,
    Thread,
    Token,
    Unknown,
}

impl FileType {
    /// lsof-style TYPE code.
    pub fn code(self) -> &'static str {
        match self {
            FileType::Regular => "REG",
            FileType::Dir => "DIR",
            FileType::Chr => "CHR",
            FileType::Fifo => "FIFO",
            FileType::Pipe => "PIPE",
            FileType::Ipv4 => "IPv4",
            FileType::Ipv6 => "IPv6",
            FileType::Unix => "unix",
            FileType::Key => "KEY",
            FileType::Event => "EVT",
            FileType::Mutant => "MUT",
            FileType::Section => "SECT",
            FileType::Process => "PROC",
            FileType::Thread => "THRD",
            FileType::Token => "TOKN",
            FileType::Unknown => "unknown",
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

/// Network details for a socket-backed [`OpenFile`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SocketInfo {
    pub protocol: Protocol,
    pub local: Option<SocketAddr>,
    pub remote: Option<SocketAddr>,
    /// `None` for connectionless protocols (UDP).
    pub state: Option<TcpState>,
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
        if let Some(st) = self.state {
            s.push_str(" (");
            s.push_str(st.as_str());
            s.push(')');
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
    pub files: Vec<OpenFile>,
}
