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
//! `/proc/net` resolves to the *calling* process's network namespace. A process
//! inside a container has its sockets in a different namespace, so its inodes
//! will not be found here. That is not a silent wrong answer: an unresolved
//! inode falls back to the phase-L0 row (`SOCK` with the `socket:[inode]` name),
//! which is exactly what shipped before this module existed. Reading
//! `/proc/<pid>/net/*` per namespace is deferred to L2.

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
    /// AF_UNIX only: the ` type=STREAM` tail lsof appends to NAME. The state
    /// is **not** part of it — the C keeps that in `Lf->lts` and prints it from
    /// `print_tcptpi()`, the same place a TCP row's state comes from, so it
    /// lands in `info.state` here and reaches `-F` as a `TST=` token.
    pub unix_suffix: Option<String>,
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
        t.load_unix("/proc/net/unix");
        t
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
                    unix_suffix: None,
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
                    unix_suffix: None,
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
                    unix_suffix: Some(unix_suffix(f[UNIX_TYPE])),
                },
            );
        }
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
                    assert!(e.unix_suffix.is_some(), "unix rows carry a type= tail");
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
}
