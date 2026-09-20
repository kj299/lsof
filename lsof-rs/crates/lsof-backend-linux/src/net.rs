//! Socket classification from `/proc/net/*`, joined to fds by inode.
//!
//! An fd that is a socket has a link target of `socket:[12345]` and nothing
//! else — no address, no protocol, not even a family. The number is the socket's
//! inode, and it is the join key: `/proc/net/tcp` and its siblings list every
//! socket in the network namespace with its inode in a column. Read those once,
//! index by inode, and every socket fd can be resolved by lookup.
//!
//! # Namespaces
//!
//! `/proc/net` resolves to the *calling* process's network namespace, so a
//! process inside a container has its sockets in tables this one cannot see.
//! [`NetnsTables`] is the fallback: for an inode the main table misses, it
//! reads the owning process's own `/proc/<pid>/net/*` and caches the result by
//! namespace, so the cost is one extra table read per distinct namespace that
//! actually holds an unresolved socket — nothing at all on a host with one.
//!
//! What it recovers is the **protocol name**, not the address, because that is
//! all the C shows: `sock … protocol: TCP`. The C gets it from the
//! `system.sockprotoname` extended attribute rather than from any table
//! (`dsock.c`), which is why it can name families that have no `/proc/net`
//! file at all — see the ledger entry on AF_VSOCK. Reading the namespace's
//! table gives this port the same answer for every family that has one, in
//! safe dependency-free Rust, and it deliberately does not print the address
//! it happens to learn on the way: matching the C is the contract.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use lsof_core::model::{FileType, Protocol, SocketInfo, TcpExtInfo, TcpState, UnixState};

/// One resolved socket: what the fd row becomes once the inode is matched.
pub struct SocketEntry {
    pub file_type: FileType,
    pub info: SocketInfo,
    /// The bound path of an AF_UNIX socket, when it has one. An unbound
    /// (anonymous) socket has none, and lsof then shows only the `type=` suffix.
    pub path: Option<String>,
    /// The DEVICE cell. lsof fills it differently per family: an internet
    /// socket shows its inode, an AF_UNIX socket the kernel's socket pointer
    /// (the leading `Num` column of `/proc/net/unix`, printed as `0x…`).
    pub device: String,
    /// The NODE cell — the protocol name (`TCP`/`UDP`) for internet sockets,
    /// the inode for AF_UNIX. Again lsof's own split, not ours.
    pub node: String,
    /// The `type=…` tail lsof puts in NAME, for the two families that have
    /// one: AF_UNIX's ` type=STREAM` and AF_PACKET's `type=SOCK_RAW`. For a
    /// unix row the state is **not** part of it — the C keeps that in
    /// `Lf->lts` and prints it from `print_tcptpi()`, the same place a TCP
    /// row's state comes from, so it lands in `info.state` here and reaches
    /// `-F` as a `TST=` token. A packet socket has no state at all.
    pub type_suffix: Option<String>,
    /// The name the kernel would answer for this socket's
    /// `system.sockprotoname` extended attribute — the *only* thing the C
    /// prints for a socket its own `/proc/net` tables missed, which is what
    /// [`NetnsTables::protocol_for`] reproduces (`sock … protocol: TCP`).
    ///
    /// It is deliberately not `info.protocol`, because for two families the
    /// two differ, and both were measured against the C on sockets held inside
    /// a foreign network namespace:
    ///
    /// | family | `system.sockprotoname` | `info.protocol` |
    /// |---|---|---|
    /// | AF_UNIX, `SOCK_STREAM` | `UNIX-STREAM` | `unix` |
    /// | AF_UNIX, dgram or seqpacket | `UNIX` | `unix` |
    /// | AF_PACKET | `PACKET` | `packet` |
    ///
    /// The kernel names these after the `struct proto` the socket uses rather
    /// than after its family — `unix_stream_proto` and `unix_dgram_proto` —
    /// which is why `SOCK_SEQPACKET` reports `UNIX` and not `UNIX-SEQPACKET`.
    pub kernel_proto: &'static str,
}

#[derive(Default)]
pub struct SocketTable {
    by_inode: HashMap<u64, SocketEntry>,
}

impl SocketTable {
    /// Read every `/proc/net` table once.
    ///
    /// `want_queues` mirrors `-T q`: the send/receive queue depths sit in the
    /// same line we are already parsing, so they cost nothing to read — but
    /// the table renderer emits a `(QR=…) (QS=…)` suffix whenever the field is
    /// present, not when `-T` was asked for. Populating it unconditionally
    /// would therefore change the output of a plain `lsof -i`, so it stays
    /// gated on the flag.
    pub fn load(want_queues: bool) -> Self {
        let mut t = SocketTable::default();
        // Absent files are normal, not an error: a host built without IPv6 has
        // no /proc/net/tcp6 at all.
        t.load_inet("/proc/net/tcp", Protocol::Tcp, false, want_queues);
        t.load_inet("/proc/net/tcp6", Protocol::Tcp, true, want_queues);
        t.load_inet("/proc/net/udp", Protocol::Udp, false, want_queues);
        t.load_inet("/proc/net/udp6", Protocol::Udp, true, want_queues);
        t.load_raw("/proc/net/raw", false);
        t.load_raw("/proc/net/raw6", true);
        t.load_packet("/proc/net/packet");
        t.load_unix("/proc/net/unix");
        t
    }

    /// The same tables, read through `/proc/<pid>/net/` — that process's own
    /// network namespace rather than this one's.
    ///
    /// `None` when the directory yields nothing at all (the process exited, or
    /// its `/proc/<pid>/net` is unreadable), so the caller can cache the
    /// failure instead of retrying per fd. Queue columns are never wanted
    /// here: `-T` reports on sockets this process can see, and one it cannot
    /// resolve has no queue to show.
    pub fn load_for_pid(pid: u32) -> Option<Self> {
        let base = format!("/proc/{pid}/net");
        if std::fs::metadata(&base).is_err() {
            return None;
        }
        let mut t = SocketTable::default();
        t.load_inet(&format!("{base}/tcp"), Protocol::Tcp, false, false);
        t.load_inet(&format!("{base}/tcp6"), Protocol::Tcp, true, false);
        t.load_inet(&format!("{base}/udp"), Protocol::Udp, false, false);
        t.load_inet(&format!("{base}/udp6"), Protocol::Udp, true, false);
        t.load_raw(&format!("{base}/raw"), false);
        t.load_raw(&format!("{base}/raw6"), true);
        t.load_packet(&format!("{base}/packet"));
        t.load_unix(&format!("{base}/unix"));
        Some(t)
    }

    pub fn get(&self, inode: u64) -> Option<&SocketEntry> {
        self.by_inode.get(&inode)
    }

    fn load_inet(&mut self, path: &str, proto: Protocol, v6: bool, queues: bool) {
        if let Ok(text) = std::fs::read_to_string(path) {
            self.parse_inet(&text, proto, v6, queues);
        }
    }

    /// The parsing half of [`Self::load_inet`], over a whole `/proc/net/{tcp,udp}
    /// {,6}` table. Pure; the fuzz target drives it with arbitrary bytes and it
    /// must never panic. Malformed lines are skipped, never guessed at.
    pub fn parse_inet(&mut self, text: &str, proto: Protocol, v6: bool, queues: bool) {
        for line in text.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < INET_INODE + 1 {
                continue;
            }
            let Some(inode) = f[INET_INODE].parse::<u64>().ok() else {
                continue;
            };
            let local = parse_addr(f[INET_LOCAL], v6);
            let remote = parse_addr(f[INET_REMOTE], v6);
            // Linux's `/proc/net/udp` reuses the TCP state numbers, but lsof
            // registers exactly one name for UDP — `ESTABLISHED` (1), for a
            // connected socket. Every other value, `TCP_CLOSE` (7) for the
            // usual unconnected socket included, prints no state at all. That
            // one-entry table is `build_IPstates()` verbatim, not a
            // simplification.
            let state = match proto {
                Protocol::Tcp => Some(tcp_state(f[INET_STATE]).into()),
                Protocol::Udp => (u32::from_str_radix(f[INET_STATE], 16) == Ok(0x01))
                    .then(|| TcpState::Established.into()),
                _ => None,
            };
            // Both tables carry `tx_queue:rx_queue`, and lsof reports the
            // queues for UDP just as it does for TCP.
            let tcp = if queues && matches!(proto, Protocol::Tcp | Protocol::Udp) {
                parse_queues(f[INET_QUEUES])
            } else {
                None
            };
            self.by_inode.insert(
                inode,
                SocketEntry {
                    file_type: if v6 { FileType::Ipv6 } else { FileType::Ipv4 },
                    info: SocketInfo {
                        protocol: proto,
                        local,
                        remote,
                        state,
                        tcp,
                    },
                    path: None,
                    device: inode.to_string(),
                    node: proto.as_str().to_string(),
                    type_suffix: None,
                    kernel_proto: proto.as_str(),
                },
            );
        }
    }

    /// `/proc/net/raw` shares the inet layout with one difference that matters:
    /// the local address's second half is **not** a port, it is the IP protocol
    /// number. That is how ICMP is identified — there is no `/proc/net/icmp`.
    fn load_raw(&mut self, path: &str, v6: bool) {
        if let Ok(text) = std::fs::read_to_string(path) {
            self.parse_raw(&text, v6);
        }
    }

    /// The parsing half of [`Self::load_raw`]. Pure; must never panic.
    pub fn parse_raw(&mut self, text: &str, v6: bool) {
        for line in text.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < INET_INODE + 1 {
                continue;
            }
            let Some(inode) = f[INET_INODE].parse::<u64>().ok() else {
                continue;
            };
            let protocol = match f[INET_LOCAL]
                .split_once(':')
                .and_then(|(_, p)| u16::from_str_radix(p, 16).ok())
            {
                Some(1) => Protocol::Other("ICMP"),
                Some(58) => Protocol::Other("ICMPV6"),
                _ => Protocol::Other("RAW"),
            };
            // Zero the "port", which is the protocol number here — reporting it
            // as a port would make `-i :1` match every ICMP socket.
            let local = parse_addr(f[INET_LOCAL], v6).map(|a| SocketAddr::new(a.ip(), 0));
            let remote = parse_addr(f[INET_REMOTE], v6).map(|a| SocketAddr::new(a.ip(), 0));
            self.by_inode.insert(
                inode,
                SocketEntry {
                    file_type: if v6 { FileType::Ipv6 } else { FileType::Ipv4 },
                    info: SocketInfo {
                        protocol,
                        local,
                        remote,
                        state: None,
                        tcp: None,
                    },
                    path: None,
                    device: inode.to_string(),
                    node: protocol.as_str().to_string(),
                    type_suffix: None,
                    kernel_proto: protocol.as_str(),
                },
            );
        }
    }

    /// `/proc/net/packet` — AF_PACKET sockets, the ones `tcpdump` opens.
    ///
    /// Unlike every other table here this one carries no address at all: a
    /// packet socket is bound to an interface and an ethernet protocol, not to
    /// an endpoint. lsof spends its three cells accordingly (`dsock.c:3622`):
    /// the **inode** goes in DEVICE, the **ethernet protocol name** in NODE,
    /// and NAME is only `type=SOCK_RAW`.
    fn load_packet(&mut self, path: &str) {
        if let Ok(text) = std::fs::read_to_string(path) {
            self.parse_packet(&text);
        }
    }

    /// The parsing half of [`Self::load_packet`]. Pure; must never panic.
    ///
    /// The header line is **checked, not skipped**. The C reads this table by
    /// fixed column index and guards that with the labels (`get_pack()`), and
    /// a kernel that reordered the columns would otherwise be silently read as
    /// if it had not: a `Proto` value landing in the `Type` slot is still a
    /// number, so it parses, and the row comes out wrong rather than absent.
    /// A mismatch drops the whole table, which is what the C does too — minus
    /// its `WARNING: unsupported format` on stderr, which this port has no
    /// channel for from inside a backend table read.
    pub fn parse_packet(&mut self, text: &str) {
        let mut lines = text.lines();
        match lines.next() {
            Some(h) => {
                let f: Vec<&str> = h.split_whitespace().collect();
                if f.len() < PACKET_INODE + 1
                    || f[PACKET_TYPE] != "Type"
                    || f[PACKET_PROTO] != "Proto"
                    || f[PACKET_INODE] != "Inode"
                {
                    return;
                }
            }
            None => return,
        }
        for line in lines {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < PACKET_INODE + 1 {
                continue;
            }
            let Ok(inode) = f[PACKET_INODE].parse::<u64>() else {
                continue;
            };
            // `Proto` is hex and `Type` is decimal, exactly as the kernel
            // writes them (`%04x` and `%u`). An unreadable protocol drops the
            // row, matching the C's `strtoul` guard; an unreadable type does
            // not, because the C reads that one with `atoi()`, which cannot
            // fail and yields 0 — a value no socket type has, so the row still
            // prints, as `type=unknown`.
            let Ok(proto) = u32::from_str_radix(f[PACKET_PROTO], 16) else {
                continue;
            };
            let ty = leading_u32(f[PACKET_TYPE]);
            self.by_inode.insert(
                inode,
                SocketEntry {
                    // The C's LSOF_FILE_PACKET. Lowercase, like `unix` and
                    // `sock` and unlike `IPv4` — lsof's own casing.
                    file_type: FileType::Other("pack".into()),
                    info: SocketInfo {
                        // The family, not the ethernet protocol: the latter is
                        // the NODE cell, and `-F P` reads it from there. Same
                        // split `parse_unix` makes with `Protocol::Other`.
                        protocol: Protocol::Other("packet"),
                        local: None,
                        remote: None,
                        state: None,
                        tcp: None,
                    },
                    path: None,
                    device: inode.to_string(),
                    node: packet_node(proto),
                    type_suffix: Some(socket_type_suffix(ty)),
                    kernel_proto: "PACKET",
                },
            );
        }
    }

    fn load_unix(&mut self, path: &str) {
        if let Ok(text) = std::fs::read_to_string(path) {
            self.parse_unix(&text);
        }
    }

    /// The parsing half of [`Self::load_unix`]. Pure; must never panic — the
    /// path column is arbitrary bytes chosen by whoever bound the socket.
    pub fn parse_unix(&mut self, text: &str) {
        for line in text.lines().skip(1) {
            // The path is the last field and may itself contain spaces, so the
            // tail is taken verbatim rather than whitespace-split.
            let f = fields_with_rest(line, UNIX_PATH + 1);
            if f.len() < UNIX_INODE + 1 {
                continue;
            }
            let Some(inode) = f[UNIX_INODE].parse::<u64>().ok() else {
                continue;
            };
            // The leading `Num` column is the kernel's socket address, and it
            // is what lsof shows as DEVICE for an AF_UNIX row — printed `0x…`
            // and zero-padded to 16, exactly as the kernel wrote it.
            let device = format!("0x{}", f[0].trim_end_matches(':'));
            self.by_inode.insert(
                inode,
                SocketEntry {
                    file_type: FileType::Unix,
                    info: SocketInfo {
                        protocol: Protocol::Other("unix"),
                        local: None,
                        remote: None,
                        state: Some(unix_state(f[UNIX_FLAGS], f[UNIX_STATE]).into()),
                        tcp: None,
                    },
                    path: f.get(UNIX_PATH).map(|s| s.to_string()),
                    device,
                    node: inode.to_string(),
                    type_suffix: Some(unix_suffix(f[UNIX_TYPE])),
                    kernel_proto: unix_kernel_proto(f[UNIX_TYPE]),
                },
            );
        }
    }
}

/// What the kernel calls an AF_UNIX socket in `system.sockprotoname`, read
/// from the same `Type` column as [`unix_suffix`].
///
/// `UNIX-STREAM` for a stream socket and `UNIX` for everything else, including
/// `SOCK_SEQPACKET`: the name comes from the `struct proto` the socket uses,
/// and seqpacket shares `unix_dgram_proto`. Measured against the C, which
/// printed `protocol: UNIX-STREAM`, `protocol: UNIX` and `protocol: UNIX` for
/// stream, dgram and seqpacket sockets held in a foreign namespace.
pub fn unix_kernel_proto(ty: &str) -> &'static str {
    match u32::from_str_radix(ty, 16) {
        Ok(1) => "UNIX-STREAM",
        _ => "UNIX",
    }
}

/// lsof's ` type=STREAM` NAME tail for an AF_UNIX row, from the `Type` column
/// of `/proc/net/unix`. The state is deliberately not here — see [`unix_state`].
pub fn unix_suffix(ty: &str) -> String {
    let kind = match u32::from_str_radix(ty, 16) {
        Ok(1) => "STREAM",
        Ok(2) => "DGRAM",
        Ok(5) => "SEQPACKET",
        _ => "UNKNOWN",
    };
    format!("type={kind}")
}

/// The state lsof shows for an AF_UNIX row, from the `Flags` and `St` columns.
///
/// It is not simply `St`: a listening socket sits in `SS_UNCONNECTED` and is
/// told apart only by `SO_ACCEPTCON` in the flags. The C tests that with
/// `Lf->lts.opt == __SO_ACCEPTCON` — **equality**, not a bit test — so a socket
/// carrying any other flag alongside it is reported by its `St` instead; that
/// is reproduced here rather than "fixed", because a consumer diffing the two
/// binaries would see the difference.
///
/// Every row gets a state: a column that will not parse, or a number outside
/// the kernel's `socket_state` enum, is `UNKNOWN` — which is what the C prints
/// once its own `strtoul` failure has left the value at 0 (`SS_FREE`).
pub fn unix_state(flags: &str, st: &str) -> UnixState {
    const SO_ACCEPTCON: u32 = 0x0001_0000;
    if u32::from_str_radix(flags, 16) == Ok(SO_ACCEPTCON) {
        return UnixState::Listen;
    }
    match u32::from_str_radix(st, 16) {
        Ok(0x01) => UnixState::Unconnected,
        Ok(0x02) => UnixState::Connecting,
        Ok(0x03) => UnixState::Connected,
        Ok(0x04) => UnixState::Disconnecting,
        _ => UnixState::Unknown,
    }
}

// Column indices, from the header lines the kernel writes:
//   sl local_address rem_address st tx_queue:rx_queue tr tm->when retrnsmt uid timeout inode
const INET_LOCAL: usize = 1;
const INET_REMOTE: usize = 2;
const INET_STATE: usize = 3;
const INET_QUEUES: usize = 4;
const INET_INODE: usize = 9;
//   Num RefCount Protocol Flags Type St Inode Path
const PACKET_TYPE: usize = 2;
const PACKET_PROTO: usize = 3;
const PACKET_INODE: usize = 8;

/// The NODE cell's width for a packet row — see [`packet_node`].
const IPROTO_MAX: usize = 7;

const UNIX_FLAGS: usize = 3;
const UNIX_TYPE: usize = 4;
const UNIX_STATE: usize = 5;
const UNIX_INODE: usize = 6;
const UNIX_PATH: usize = 7;

/// Split into at most `n` whitespace-separated fields, the last of which is the
/// untouched remainder of the line. An AF_UNIX socket may be bound to a path
/// containing spaces, and plain `split_whitespace` would truncate it.
pub fn fields_with_rest(line: &str, n: usize) -> Vec<&str> {
    let mut out = Vec::with_capacity(n);
    let mut rest = line.trim_start();
    while out.len() + 1 < n {
        match rest.find(char::is_whitespace) {
            Some(i) => {
                out.push(&rest[..i]);
                rest = rest[i..].trim_start();
            }
            None => break,
        }
    }
    if !rest.is_empty() {
        out.push(rest);
    }
    out
}

/// Decode one `HEX:HEX` address column.
///
/// The kernel prints the address words as host-order `%08X` of the bytes as
/// they sit in memory, so the decode is "hex -> u32 -> native-endian bytes":
/// on a little-endian machine `0100007F` yields the bytes 7F 00 00 01, i.e.
/// 127.0.0.1. Going through `to_ne_bytes` rather than a byte-swap keeps that
/// correct on a big-endian host too, where the kernel would have printed
/// `7F000001` for the same address.
pub fn parse_addr(s: &str, v6: bool) -> Option<SocketAddr> {
    let (host, port) = s.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    if v6 {
        // `len()` counts bytes, and the slices below are byte ranges: a 32-byte
        // host made of multi-byte characters would be sliced mid-character and
        // panic. Hex digits are ASCII, so anything else is malformed — reject
        // it here rather than index into it. Found by the proc_net fuzz target
        // within seconds of its first run.
        if host.len() != 32 || !host.is_ascii() {
            return None;
        }
        let mut b = [0u8; 16];
        for i in 0..4 {
            let w = u32::from_str_radix(&host[i * 8..(i + 1) * 8], 16).ok()?;
            b[i * 4..(i + 1) * 4].copy_from_slice(&w.to_ne_bytes());
        }
        Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(b)), port))
    } else {
        if host.len() != 8 {
            return None;
        }
        let w = u32::from_str_radix(host, 16).ok()?;
        Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(w.to_ne_bytes())),
            port,
        ))
    }
}

/// The `st` column's hex code. These are the kernel's `TCP_*` enum values, not
/// the wire states, so the mapping is fixed by include/net/tcp_states.h.
pub fn tcp_state(hex: &str) -> TcpState {
    match u8::from_str_radix(hex, 16) {
        Ok(0x01) => TcpState::Established,
        Ok(0x02) => TcpState::SynSent,
        Ok(0x03) => TcpState::SynReceived,
        Ok(0x04) => TcpState::FinWait1,
        Ok(0x05) => TcpState::FinWait2,
        Ok(0x06) => TcpState::TimeWait,
        Ok(0x07) => TcpState::Closed,
        Ok(0x08) => TcpState::CloseWait,
        Ok(0x09) => TcpState::LastAck,
        Ok(0x0a) => TcpState::Listen,
        Ok(0x0b) => TcpState::Closing,
        _ => TcpState::Unknown,
    }
}

/// `tx_queue:rx_queue`, both hex. lsof's `QS=` is the send queue and `QR=` the
/// receive queue.
pub fn parse_queues(s: &str) -> Option<TcpExtInfo> {
    let (tx, rx) = s.split_once(':')?;
    Some(TcpExtInfo {
        recv_window: None,
        send_queue: u64::from_str_radix(tx, 16).ok(),
        recv_queue: u64::from_str_radix(rx, 16).ok(),
    })
}

/// The inode inside an fd link target of the form `socket:[12345]`.
pub fn socket_inode(target: &str) -> Option<u64> {
    target
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// The per-namespace fallback for sockets the main table cannot see.
///
/// Keyed by the namespace itself (`readlink /proc/<pid>/ns/net`, e.g.
/// `net:[4026532259]`) and not by pid, so a hundred processes sharing one
/// container's namespace read its tables once. Built lazily: a host where
/// every socket resolves from `/proc/net` never opens a single extra file.
#[derive(Default)]
pub struct NetnsTables {
    /// `None` for a namespace whose tables could not be read at all — cached
    /// so a permission error is paid once rather than per fd.
    by_ns: std::cell::RefCell<HashMap<String, Option<SocketTable>>>,
    /// pid -> its namespace, so a process holding many unresolved sockets
    /// costs one `readlink` rather than one per fd. A proxy inside a container
    /// is exactly that shape.
    by_pid: std::cell::RefCell<HashMap<u32, Option<String>>>,
    /// The calling process's own namespace. Its sockets are already in the
    /// main table, so a process sharing it is skipped without any work.
    own: Option<String>,
}

impl NetnsTables {
    pub fn new() -> Self {
        Self {
            by_ns: std::cell::RefCell::new(HashMap::new()),
            by_pid: std::cell::RefCell::new(HashMap::new()),
            own: netns_of("self"),
        }
    }

    /// The protocol name for `inode` as `pid`'s own namespace sees it —
    /// `TCP`, `UDP`, `RAW`, `UNIX` — or `None` when this port cannot tell.
    ///
    /// `None` is not the same as "no such socket": a family with no
    /// `/proc/net` table (AF_VSOCK, netlink, packet) lands here too, and the C
    /// still names it from an xattr this crate has no safe way to read.
    pub fn protocol_for(&self, pid: u32, inode: u64) -> Option<String> {
        let ns = self
            .by_pid
            .borrow_mut()
            .entry(pid)
            .or_insert_with(|| netns_of(&pid.to_string()))
            .clone()?;
        // Same namespace as ours: the main table already had its chance, and
        // re-reading the identical files would only cost time.
        if self.own.as_deref() == Some(ns.as_str()) {
            return None;
        }
        let mut cache = self.by_ns.borrow_mut();
        let table = cache
            .entry(ns)
            .or_insert_with(|| SocketTable::load_for_pid(pid));
        let e = table.as_ref()?.get(inode)?;
        // The PROTOCOL name, which is what the C shows here -- never the
        // address, and never `node`, which is the protocol only for internet
        // sockets. The C reads this from `system.sockprotoname`, so what has
        // to be reproduced is the KERNEL's name for the socket, which is not
        // always the port's own `info.protocol`: see `kernel_proto`.
        Some(e.kernel_proto.to_string())
    }
}

/// `readlink /proc/<who>/ns/net`, the namespace's identity as a string.
fn netns_of(who: &str) -> Option<String> {
    std::fs::read_link(format!("/proc/{who}/ns/net"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// The NODE cell of an AF_PACKET row: the ethernet protocol's name, or its
/// number when the table below has none.
///
/// **Seven bytes, not eight.** The C copies this into `Lf->iproto`, which is
/// `char[IPROTOL]` with `IPROTOL == 8` (`lib/common.h:323`), through
/// `snpf(…, "%.*s", IPROTOL - 1, cp)`. Its own table breaks the "should not
/// exceed 7 characters" comment above `ethernet_proto_to_str()` exactly once —
/// `ETH_P_LOOPBACK` is `"LOOPBACK"` — and the oracle prints `LOOPBAC`.
///
/// Both branches are ASCII by construction (a literal from the table, or
/// decimal digits), so the byte truncation can never split a character.
pub fn packet_node(proto: u32) -> String {
    let mut s = match ethernet_proto(proto) {
        Some(name) => name.to_string(),
        None => proto.to_string(),
    };
    s.truncate(IPROTO_MAX);
    s
}

/// The NAME cell of an AF_PACKET row — the whole of it, since a packet socket
/// has no address to print. `type=SOCK_RAW` for the types the kernel defines,
/// `type=unknown` for anything else: the C drops the `SOCK_` prefix in that
/// branch rather than printing `SOCK_unknown` (`dsock.c:3631`).
pub fn socket_type_suffix(ty: u32) -> String {
    match socket_type(ty) {
        Some(name) => format!("type=SOCK_{name}"),
        None => "type=unknown".to_string(),
    }
}

/// `<sys/socket.h>`'s `SOCK_*`, as `socket_type_to_str()` names them.
fn socket_type(ty: u32) -> Option<&'static str> {
    Some(match ty {
        1 => "STREAM",
        2 => "DGRAM",
        3 => "RAW",
        4 => "RDM",
        5 => "SEQPACKET",
        6 => "DCCP",
        10 => "PACKET",
        _ => return None,
    })
}

/// `<linux/if_ether.h>`'s `ETH_P_*`, as `ethernet_proto_to_str()` names them.
///
/// Transcribed from that function and then **verified against the compiled
/// oracle**: a fixture opened one `AF_PACKET` socket per protocol below, plus
/// seven values absent from it, and every NODE cell the C printed for the
/// resulting 100 rows matched this table — truncation, the digits-only
/// fallback, and `ETH_P_PPP_MP`'s embedded space included.
///
/// The C's arms are each `#if defined(…)`, so its table is whatever the build
/// host's headers carried; this one is fixed. These are UAPI constants and do
/// not change value, but a C built against headers older than a given protocol
/// prints that protocol's *number* where this prints its name.
fn ethernet_proto(proto: u32) -> Option<&'static str> {
    Some(match proto {
        1 => "802.3",        // ETH_P_802_3
        2 => "AX25",         // ETH_P_AX25
        3 => "ALL",          // ETH_P_ALL
        4 => "802.2",        // ETH_P_802_2
        5 => "SNAP",         // ETH_P_SNAP
        6 => "DDCMP",        // ETH_P_DDCMP
        7 => "WAN_PPP",      // ETH_P_WAN_PPP
        8 => "PPP MP",       // ETH_P_PPP_MP
        9 => "LCLTALK",      // ETH_P_LOCALTALK
        12 => "CAN",         // ETH_P_CAN
        13 => "CANFD",       // ETH_P_CANFD
        16 => "PPPTALK",     // ETH_P_PPPTALK
        17 => "802.2",       // ETH_P_TR_802_2
        21 => "MOBITEX",     // ETH_P_MOBITEX
        22 => "CONTROL",     // ETH_P_CONTROL
        23 => "IRDA",        // ETH_P_IRDA
        24 => "ECONET",      // ETH_P_ECONET
        25 => "HDLC",        // ETH_P_HDLC
        26 => "ARCNET",      // ETH_P_ARCNET
        27 => "DSA",         // ETH_P_DSA
        28 => "TRAILER",     // ETH_P_TRAILER
        96 => "LOOP",        // ETH_P_LOOP
        245 => "PHONET",     // ETH_P_PHONET
        246 => "802154",     // ETH_P_IEEE802154
        247 => "CAIF",       // ETH_P_CAIF
        248 => "XDSA",       // ETH_P_XDSA
        249 => "MAP",        // ETH_P_MAP
        512 => "PUP",        // ETH_P_PUP
        513 => "PUPAT",      // ETH_P_PUPAT
        2048 => "IP",        // ETH_P_IP
        2053 => "X25",       // ETH_P_X25
        2054 => "ARP",       // ETH_P_ARP
        2303 => "BPQ",       // ETH_P_BPQ
        2560 => "I3EPUP",    // ETH_P_IEEEPUP
        2561 => "I3EPUPA",   // ETH_P_IEEEPUPAT
        8939 => "ERSPAN2",   // ETH_P_ERSPAN2
        8944 => "TSN",       // ETH_P_TSN
        17157 => "BATMAN",   // ETH_P_BATMAN
        24576 => "DEC",      // ETH_P_DEC
        24577 => "DNA_DL",   // ETH_P_DNA_DL
        24578 => "DNA_RC",   // ETH_P_DNA_RC
        24579 => "DNA_RT",   // ETH_P_DNA_RT
        24580 => "LAT",      // ETH_P_LAT
        24581 => "DIAG",     // ETH_P_DIAG
        24582 => "CUST",     // ETH_P_CUST
        24583 => "SCA",      // ETH_P_SCA
        25944 => "TEB",      // ETH_P_TEB
        32821 => "RARP",     // ETH_P_RARP
        32923 => "ATALK",    // ETH_P_ATALK
        33011 => "AARP",     // ETH_P_AARP
        33024 => "8021Q",    // ETH_P_8021Q
        33079 => "IPX",      // ETH_P_IPX
        34525 => "IPV6",     // ETH_P_IPV6
        34824 => "PAUSE",    // ETH_P_PAUSE
        34825 => "SLOW",     // ETH_P_SLOW
        34878 => "WCCP",     // ETH_P_WCCP
        34887 => "MPLS_UC",  // ETH_P_MPLS_UC
        34888 => "MPLS_MC",  // ETH_P_MPLS_MC
        34892 => "ATMMPOA",  // ETH_P_ATMMPOA
        34915 => "PPP_DIS",  // ETH_P_PPP_DISC
        34916 => "PPP_SES",  // ETH_P_PPP_SES
        34924 => "LINKCTL",  // ETH_P_LINK_CTL
        34948 => "ATMFATE",  // ETH_P_ATMFATE
        34958 => "PAE",      // ETH_P_PAE
        34978 => "AOE",      // ETH_P_AOE
        34984 => "8021AD",   // ETH_P_8021AD
        34997 => "802_EX1",  // ETH_P_802_EX1
        35006 => "ERSPAN",   // ETH_P_ERSPAN
        35015 => "PREAUTH",  // ETH_P_PREAUTH
        35018 => "TIPC",     // ETH_P_TIPC
        35020 => "LLDP",     // ETH_P_LLDP
        35043 => "MRP",      // ETH_P_MRP
        35045 => "MACSEC",   // ETH_P_MACSEC
        35047 => "8021AH",   // ETH_P_8021AH
        35061 => "MVRP",     // ETH_P_MVRP
        35063 => "1588",     // ETH_P_1588
        35064 => "NCSI",     // ETH_P_NCSI
        35067 => "PRP",      // ETH_P_PRP
        35078 => "FCOE",     // ETH_P_FCOE
        35085 => "TDLS",     // ETH_P_TDLS
        35092 => "FIP",      // ETH_P_FIP
        35093 => "IBOE",     // ETH_P_IBOE
        35095 => "802.21",   // ETH_P_80221
        35119 => "HSR",      // ETH_P_HSR
        35151 => "NSH",      // ETH_P_NSH
        36864 => "LOOPBACK", // ETH_P_LOOPBACK
        37120 => "QINQ1",    // ETH_P_QINQ1
        37376 => "QINQ2",    // ETH_P_QINQ2
        37632 => "QINQ3",    // ETH_P_QINQ3
        56026 => "EDSA",     // ETH_P_EDSA
        56027 => "DSAD1Q",   // ETH_P_DSA_8021Q
        60734 => "IFE",      // ETH_P_IFE
        64507 => "AF_IUCV",  // ETH_P_AF_IUCV
        _ => return None,
    })
}

/// C's `atoi()` on the `Type` column: leading digits, and 0 for anything else.
///
/// The C reads that column with `atoi()`, which has no failure to report, so a
/// garbage value there still produces a row — one whose type is 0, which no
/// socket has, so it prints `type=unknown`. Rejecting the line instead would
/// drop a row the C emits. A `-` sign is not handled because `atoi` would make
/// it negative and `socket_type_to_str()` takes a `uint32_t`: every negative
/// value lands in the same `unknown` branch that 0 does.
fn leading_u32(s: &str) -> u32 {
    let digits = s.strip_prefix('+').unwrap_or(s);
    let end = digits
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(digits.len());
    digits[..end].parse().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_address_decodes_little_endian() {
        // The exact bytes /proc/net/tcp prints for 127.0.0.1:43831 on this host.
        let a = parse_addr("0100007F:AB37", false).expect("parses");
        assert_eq!(a.ip().to_string(), "127.0.0.1");
        assert_eq!(a.port(), 43831);
        // The all-zero wildcard, which lsof renders as `*`.
        let w = parse_addr("00000000:0000", false).expect("parses");
        assert!(w.ip().is_unspecified());
        assert_eq!(w.port(), 0);
        // 8.8.8.8:53 — asymmetric in every byte, so a wrong byte order shows.
        let d = parse_addr("08080808:0035", false).expect("parses");
        assert_eq!(d.ip().to_string(), "8.8.8.8");
        assert_eq!(d.port(), 53);
        let x = parse_addr("0100000A:0050", false).expect("parses");
        assert_eq!(x.ip().to_string(), "10.0.0.1");
    }

    #[test]
    fn v6_address_decodes_per_word() {
        // ::1 — the loopback, written as four words with only the last set.
        let a = parse_addr("00000000000000000000000001000000:0016", true).expect("parses");
        assert_eq!(a.ip().to_string(), "::1");
        assert_eq!(a.port(), 22);
        // The v6 wildcard.
        let w = parse_addr("00000000000000000000000000000000:1F90", true).expect("parses");
        assert!(w.ip().is_unspecified());
        assert_eq!(w.port(), 8080);
        // 2001:db8::1 — spans two words, so per-word byte order is exercised.
        let g = parse_addr("B80D0120000000000000000001000000:0050", true).expect("parses");
        assert_eq!(g.ip().to_string(), "2001:db8::1");
    }

    #[test]
    fn malformed_addresses_are_rejected_not_guessed() {
        assert!(parse_addr("nonsense", false).is_none());
        assert!(parse_addr("0100007F", false).is_none(), "no port half");
        assert!(parse_addr("0100007:0035", false).is_none(), "short v4 host");
        assert!(parse_addr("0100007F:ZZZZ", false).is_none(), "bad port");
        assert!(parse_addr("0100007F:0035", true).is_none(), "v4 host as v6");
        // Regression, found by the proc_net fuzz target on its first run: a
        // 32-BYTE host built from multi-byte characters passes the length check
        // and then gets sliced at byte offsets that fall inside a character.
        // "a" + 15×"é" + "b" is 1 + 30 + 1 = 32 bytes with byte 8 mid-"é".
        let misaligned = format!("a{}b:0050", "é".repeat(15));
        assert_eq!(misaligned.len(), 37, "32-byte host + ':0050'");
        assert!(
            parse_addr(&misaligned, true).is_none(),
            "non-ASCII host must be rejected, not indexed into"
        );
        // And the lossy-UTF-8 shape the fuzzer actually produced.
        let replacement = format!(
            "{}:0016",
            "\u{FFFD}".repeat(10).chars().take(10).collect::<String>() + "ab"
        );
        assert!(parse_addr(&replacement, true).is_none());
    }

    #[test]
    fn tcp_states_map_to_lsof_names() {
        assert_eq!(tcp_state("0A").as_str(), "LISTEN");
        assert_eq!(tcp_state("01").as_str(), "ESTABLISHED");
        assert_eq!(tcp_state("06").as_str(), "TIME_WAIT");
        assert_eq!(tcp_state("08").as_str(), "CLOSE_WAIT");
        // Lowercase is what the kernel actually writes for 0x0a in some files.
        assert_eq!(tcp_state("0a").as_str(), "LISTEN");
        assert_eq!(tcp_state("ff").as_str(), "UNKNOWN");
        assert_eq!(tcp_state("").as_str(), "UNKNOWN");
    }

    #[test]
    fn queues_split_send_from_receive() {
        // tx_queue:rx_queue — tx is what lsof calls QS.
        let q = parse_queues("0000000C:00000005").expect("parses");
        assert_eq!(q.send_queue, Some(12));
        assert_eq!(q.recv_queue, Some(5));
        assert_eq!(q.recv_window, None, "window has no /proc source");
        assert!(parse_queues("nocolon").is_none());
    }

    #[test]
    fn socket_inode_extracted_from_link_target() {
        assert_eq!(socket_inode("socket:[3485]"), Some(3485));
        assert_eq!(socket_inode("pipe:[3485]"), None);
        assert_eq!(socket_inode("/etc/passwd"), None);
        assert_eq!(socket_inode("socket:[]"), None);
        assert_eq!(socket_inode("socket:[abc]"), None);
    }

    #[test]
    fn unix_path_with_spaces_survives_field_splitting() {
        // The reason fields_with_rest exists: an AF_UNIX socket can be bound to
        // a path containing spaces, and split_whitespace would truncate it.
        let line = "0000: 00000002 00000000 00010000 0001 01 184 /tmp/my sock/x.sock";
        let f = fields_with_rest(line, UNIX_PATH + 1);
        assert_eq!(f[UNIX_INODE], "184");
        assert_eq!(f[UNIX_PATH], "/tmp/my sock/x.sock");
    }

    #[test]
    fn unix_line_without_a_path_is_anonymous_not_malformed() {
        let line = "0000: 00000003 00000000 00000000 0001 03  1181";
        let f = fields_with_rest(line, UNIX_PATH + 1);
        assert_eq!(f.len(), UNIX_PATH, "seven fields, no path");
        assert_eq!(f[UNIX_INODE], "1181");
        assert!(f.get(UNIX_PATH).is_none());
    }

    #[test]
    fn reads_this_hosts_real_proc_net() {
        // Parses whatever this kernel actually has. Asserting a specific socket
        // exists would be host-dependent; asserting the parse survives the real
        // file is not, and it is what catches a format drift.
        let t = SocketTable::load(false);
        for e in t.by_inode.values() {
            match &e.file_type {
                FileType::Ipv4 | FileType::Ipv6 | FileType::Unix => {}
                FileType::Other(c) if c == "pack" => {}
                other => panic!("unexpected socket file type {other:?}"),
            }
        }
        // /proc/net/unix is present on every Linux and always has at least the
        // sockets systemd/journald or the container runtime hold open, so an
        // empty table would mean the parse silently dropped everything.
        assert!(
            !t.by_inode.is_empty(),
            "expected at least one socket on a live host"
        );
    }

    #[test]
    fn unix_suffix_is_the_type_alone() {
        // Byte-for-byte the NAME tail `lsof -U` prints. The state is not part
        // of it — see `unix_state_matches_the_c`.
        assert_eq!(unix_suffix("0001"), "type=STREAM");
        assert_eq!(unix_suffix("0002"), "type=DGRAM");
        assert_eq!(unix_suffix("0005"), "type=SEQPACKET");
        assert_eq!(unix_suffix("zz"), "type=UNKNOWN");
        assert_eq!(unix_suffix(""), "type=UNKNOWN");
    }

    #[test]
    fn unix_state_matches_the_c() {
        // A listening socket sits in St=01 (unconnected) and is identified only
        // by SO_ACCEPTCON, so the flags column — not the state column — is what
        // makes it LISTEN.
        assert_eq!(unix_state("00010000", "01"), UnixState::Listen);
        assert_eq!(unix_state("00000000", "03"), UnixState::Connected);
        // The case a state-only mapping gets wrong: both listening and
        // "connected". The flag wins.
        assert_eq!(unix_state("00010000", "03"), UnixState::Listen);
        // Every other socket_state value, spelled the way the kernel does.
        assert_eq!(unix_state("00000000", "01"), UnixState::Unconnected);
        assert_eq!(unix_state("00000000", "02"), UnixState::Connecting);
        assert_eq!(unix_state("00000000", "04"), UnixState::Disconnecting);
        // SS_FREE (0), an out-of-range number, and unparsable columns are all
        // UNKNOWN — never "no state", which is what a socket with a state the
        // C cannot name still prints.
        assert_eq!(unix_state("00000000", "00"), UnixState::Unknown);
        assert_eq!(unix_state("00000000", "7f"), UnixState::Unknown);
        assert_eq!(unix_state("zz", "zz"), UnixState::Unknown);
        assert_eq!(unix_state("", ""), UnixState::Unknown);
        // The C tests `Lf->lts.opt == __SO_ACCEPTCON` — equality, not a bit
        // test — so SO_ACCEPTCON alongside any other flag is *not* LISTEN.
        // Faithful to the oracle, deliberately, so a diff of the two binaries
        // stays clean.
        assert_eq!(unix_state("00010001", "03"), UnixState::Connected);
    }

    #[test]
    fn device_and_node_follow_lsofs_per_family_split() {
        // lsof fills these two cells differently per family, and getting them
        // backwards is invisible without a real diff against the C:
        //   inet  DEVICE = inode, NODE = protocol
        //   unix  DEVICE = kernel socket pointer, NODE = inode
        let t = SocketTable::load(false);
        for e in t.by_inode.values() {
            match &e.file_type {
                FileType::Ipv4 | FileType::Ipv6 => {
                    assert!(
                        e.device.parse::<u64>().is_ok(),
                        "inet DEVICE should be the inode, got {:?}",
                        e.device
                    );
                    assert!(
                        ["TCP", "UDP", "RAW", "ICMP", "ICMPV6"].contains(&e.node.as_str()),
                        "inet NODE should be the protocol, got {:?}",
                        e.node
                    );
                }
                FileType::Unix => {
                    assert!(
                        e.device.starts_with("0x"),
                        "unix DEVICE should be the kernel pointer, got {:?}",
                        e.device
                    );
                    assert!(
                        e.node.parse::<u64>().is_ok(),
                        "unix NODE should be the inode, got {:?}",
                        e.node
                    );
                    assert!(e.type_suffix.is_some(), "unix rows carry a type= tail");
                }
                FileType::Other(c) if c == "pack" => {
                    // pack  DEVICE = inode, NODE = ethernet protocol
                    assert!(
                        e.device.parse::<u64>().is_ok(),
                        "pack DEVICE should be the inode, got {:?}",
                        e.device
                    );
                    assert!(
                        !e.node.is_empty() && e.node.len() <= IPROTO_MAX,
                        "pack NODE should be a <=7-byte protocol, got {:?}",
                        e.node
                    );
                    assert!(
                        e.type_suffix
                            .as_deref()
                            .is_some_and(|t| t.starts_with("type=")),
                        "pack rows carry a type= tail"
                    );
                }
                other => panic!("unexpected socket file type {other:?}"),
            }
        }
    }

    #[test]
    fn queues_are_absent_unless_asked_for() {
        // The renderer emits a (QR=)(QS=) suffix whenever the field is present,
        // so a plain run must not populate it.
        let t = SocketTable::load(false);
        assert!(
            t.by_inode.values().all(|e| e.info.tcp.is_none()),
            "load(false) must leave TcpExtInfo unset"
        );
    }

    /// A `/proc/net/packet` exactly as this kernel writes it, with the header
    /// the C validates. Column widths are the kernel's `%-*s`/`%04x`/`%u`.
    const PACKET_TABLE: &str = "\
sk               RefCnt Type Proto  Iface R Rmem   User   Inode
0000000087b466aa 3      3    0003   0     1 16640  0      1399
00000000bc7dcc98 3      2    0800   0     1 8320   0      1400
00000000cddcb89a 3      3    9000   0     1 0      0      1401
000000007573c627 3      3    1234   0     1 0      0      1403
0000000052657e45 3      10   0003   0     1 16640  0      1406
";

    #[test]
    fn packet_rows_spend_their_cells_the_way_lsof_does() {
        // Measured against the C on a fixture holding these exact sockets:
        //   python3 835 root 3u pack 1399 0t0 ALL type=SOCK_RAW
        // DEVICE is the inode, NODE is the ethernet protocol, and NAME is only
        // the type — a packet socket has no address to print.
        let mut t = SocketTable::default();
        t.parse_packet(PACKET_TABLE);
        let e = t.get(1399).expect("inode 1399");
        assert_eq!(e.file_type.code(), "pack");
        assert_eq!(e.device, "1399", "DEVICE is the inode");
        assert_eq!(e.node, "ALL", "NODE is the ethernet protocol");
        assert_eq!(e.type_suffix.as_deref(), Some("type=SOCK_RAW"));
        assert!(e.path.is_none(), "a packet socket is never bound to a path");
        assert!(e.info.state.is_none(), "and has no state to print");
        assert_eq!(t.get(1400).unwrap().node, "IP");
        assert_eq!(
            t.get(1400).unwrap().type_suffix.as_deref(),
            Some("type=SOCK_DGRAM")
        );
        assert_eq!(
            t.get(1406).unwrap().type_suffix.as_deref(),
            Some("type=SOCK_PACKET"),
            "SOCK_PACKET is 10, not a gap in the enum"
        );
    }

    #[test]
    fn a_protocol_name_is_truncated_to_seven_bytes() {
        // `Lf->iproto` is char[8] and the C writes it with "%.*s", IPROTOL - 1.
        // ETH_P_LOOPBACK is the one name in the C's own table that exceeds the
        // 7 characters its comment promises, and the oracle prints LOOPBAC.
        let mut t = SocketTable::default();
        t.parse_packet(PACKET_TABLE);
        assert_eq!(t.get(1401).expect("inode 1401").node, "LOOPBAC");
        assert_eq!(packet_node(0x9000), "LOOPBAC");
        // Nothing shorter is touched.
        assert_eq!(packet_node(0x0806), "ARP");
        assert_eq!(packet_node(0x8847), "MPLS_UC", "exactly 7 fits whole");
    }

    #[test]
    fn an_unnamed_ethernet_protocol_prints_its_number_in_decimal() {
        // The table column is hex; the cell the C prints is not.
        let mut t = SocketTable::default();
        t.parse_packet(PACKET_TABLE);
        assert_eq!(t.get(1403).expect("inode 1403").node, "4660");
        assert_eq!(packet_node(0), "0", "no ETH_P_* is zero");
        assert_eq!(packet_node(0xFFFF), "65535");
    }

    #[test]
    fn a_socket_type_with_no_name_drops_the_sock_prefix() {
        // "type=unknown", not "type=SOCK_unknown": the C picks the prefix on
        // the same flag that picks the word.
        assert_eq!(socket_type_suffix(0), "type=unknown");
        assert_eq!(socket_type_suffix(7), "type=unknown");
        assert_eq!(socket_type_suffix(u32::MAX), "type=unknown");
        for (ty, want) in [
            (1, "type=SOCK_STREAM"),
            (2, "type=SOCK_DGRAM"),
            (3, "type=SOCK_RAW"),
            (4, "type=SOCK_RDM"),
            (5, "type=SOCK_SEQPACKET"),
            (6, "type=SOCK_DCCP"),
            (10, "type=SOCK_PACKET"),
        ] {
            assert_eq!(socket_type_suffix(ty), want);
        }
    }

    #[test]
    fn an_unreadable_type_column_still_yields_a_row() {
        // The C reads Type with atoi(), which cannot fail: garbage becomes 0
        // and the row prints as type=unknown. Rejecting the line would lose a
        // row the C emits. Proto is different — a bad one drops the line, as
        // the C's strtoul guard does.
        let mut t = SocketTable::default();
        t.parse_packet(
            "sk               RefCnt Type Proto  Iface R Rmem   User   Inode\n\
             0000000087b466aa 3      xyz  0003   0     1 0      0      21\n\
             0000000087b466aa 3      3    zzzz   0     1 0      0      22\n",
        );
        assert_eq!(
            t.get(21).expect("a bad Type keeps the row").type_suffix,
            Some("type=unknown".to_string())
        );
        assert!(t.get(22).is_none(), "a bad Proto drops the row");
    }

    #[test]
    fn a_packet_table_whose_columns_moved_is_dropped_whole() {
        // This table is read by fixed index, so the C checks the labels before
        // trusting them (get_pack). Without that a reordered kernel format
        // parses cleanly into wrong cells, because Proto in the Type slot is
        // still a number.
        let reordered = PACKET_TABLE.replacen(
            "sk               RefCnt Type Proto  Iface R Rmem   User   Inode",
            "sk               RefCnt Proto Type  Iface R Rmem   User   Inode",
            1,
        );
        let mut t = SocketTable::default();
        t.parse_packet(&reordered);
        assert!(
            t.by_inode.is_empty(),
            "wrong labels means no rows, not bad rows"
        );

        // Same for a table with no header at all, or one truncated mid-header.
        for text in ["", "sk RefCnt Type\n", "0000 3 3 0003 0 1 0 0 99\n"] {
            let mut t = SocketTable::default();
            t.parse_packet(text);
            assert!(t.by_inode.is_empty(), "accepted {text:?}");
        }
    }
    #[test]
    fn the_kernels_protocol_name_is_not_always_this_ports_protocol() {
        // What `protocol_for` reproduces is the C reading
        // `system.sockprotoname`, and for two families that name is neither
        // `info.protocol` nor the NODE cell. Measured against the C on five
        // sockets held inside a foreign network namespace, where the main
        // table misses them and this is the only path that answers:
        //
        //   3u sock … protocol: PACKET        4u sock … protocol: UNIX-STREAM
        //   5u sock … protocol: TCP           6u sock … protocol: UDP
        //
        // A seqpacket AF_UNIX socket reports UNIX, not UNIX-SEQPACKET.
        assert_eq!(unix_kernel_proto("0001"), "UNIX-STREAM");
        assert_eq!(unix_kernel_proto("0002"), "UNIX");
        assert_eq!(unix_kernel_proto("0005"), "UNIX", "seqpacket shares dgram");
        assert_eq!(unix_kernel_proto("zz"), "UNIX", "unreadable is still UNIX");

        let mut t = SocketTable::default();
        t.parse_packet(PACKET_TABLE);
        assert_eq!(
            t.get(1399).unwrap().kernel_proto,
            "PACKET",
            "uppercase, and not the ethernet protocol in NODE"
        );
        assert_eq!(t.get(1399).unwrap().node, "ALL", "NODE is unaffected");

        let mut t = SocketTable::default();
        t.parse_unix(
            "Num RefCount Protocol Flags Type St Inode Path\n\
                      0000: 00000002 00000000 00010000 0001 01 184 /tmp/s\n\
                      0000: 00000002 00000000 00000000 0002 01 185 /tmp/d\n",
        );
        assert_eq!(t.get(184).unwrap().kernel_proto, "UNIX-STREAM");
        assert_eq!(t.get(185).unwrap().kernel_proto, "UNIX");

        let mut t = SocketTable::default();
        t.parse_inet(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4242 1 0000 100 0 0 10 0\n",
            Protocol::Tcp,
            false,
            false,
        );
        assert_eq!(
            t.get(4242).unwrap().kernel_proto,
            "TCP",
            "for an internet socket the two names do agree"
        );
    }
}
