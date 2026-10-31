//! Socket classification from `/proc/net/*`, joined to fds by inode.
//!
//! An fd that is a socket has a link target of `socket:[12345]` and nothing
//! else — no address, no protocol, not even a family. The number is the socket's
//! inode, and it is the join key: `/proc/net/tcp` and its siblings list every
//! socket in the network namespace with its inode in a column. Read those once,
//! index by inode, and every socket fd can be resolved by lookup.
//!
//! # What no table lists
//!
//! `/proc/net` resolves to the *calling* process's network namespace, so a
//! process inside a container has its sockets in tables this one cannot see;
//! and some sockets are in no table at all — AF_VSOCK, which has none, and a
//! UDP, UDP-Lite, TCP or netlink socket never bound. The C reads only its own
//! namespace's tables and names every such socket from the
//! `system.sockprotoname` extended attribute (`dsock.c`): `sock … protocol:
//! TCP`, the kernel's name for the socket's `struct proto`, never an
//! address. [`SockProtoNames`] does the same (DIVERGENCES 22): the one call
//! std has no API for is made through `rustix`, on a descriptor pinned
//! `O_PATH` first ([`sock_proto_name`]). Until 2026-10-30 this module read
//! the owner's own `/proc/<pid>/net` instead, which named only families
//! with a table.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

use lsof_core::model::{FileType, Protocol, SocketInfo, TcpExtInfo, TcpState, UnixState};

/// One resolved socket: what the fd row becomes once the inode is matched.
pub struct SocketEntry {
    pub file_type: FileType,
    /// What the row's socket is to the selection and the TCP/TPI columns.
    /// `None` for a raw socket, which the C types `raw` and keeps no Internet
    /// record for (`dsock.c:3530-3580`): no address, protocol, state or
    /// queue, so `-i`, `-s` and `-T` never see it (DIVERGENCES 108).
    pub info: Option<SocketInfo>,
    /// The bound path of an AF_UNIX socket, when it has one. An unbound
    /// (anonymous) socket has none, and lsof then shows only the `type=` suffix.
    pub path: Option<String>,
    /// The DEVICE cell. lsof fills it differently per family: an internet
    /// socket shows its inode, an AF_UNIX socket the kernel's socket pointer
    /// (the leading `Num` column of `/proc/net/unix`, printed as `0x…`), and
    /// a raw socket nothing.
    pub device: Option<String>,
    /// The NODE cell — the protocol name (`TCP`/`UDP`) for internet sockets,
    /// the inode for AF_UNIX and raw sockets. Again lsof's own split, not
    /// ours.
    pub node: String,
    /// The NAME cell, for the one family whose NAME is the table's own text:
    /// a raw socket's `local->remote st=NN` (`dsock.c:3542-3575`). `None`
    /// for the rest, which build theirs from `info` and the `type=` tail.
    pub name: Option<String>,
    /// The `type=…` tail lsof puts in NAME, for the two families that have
    /// one: AF_UNIX's ` type=STREAM` and AF_PACKET's `type=SOCK_RAW`. For a
    /// unix row the state is **not** part of it — the C keeps that in
    /// `Lf->lts` and prints it from `print_tcptpi()`, the same place a TCP
    /// row's state comes from, so it lands in `info.state` here and reaches
    /// `-F` as a `TST=` token. A packet socket has no state at all.
    pub type_suffix: Option<String>,
}

#[derive(Default)]
pub struct SocketTable {
    by_inode: HashMap<u64, SocketEntry>,
    /// The bound path's own bytes, by inode, for each AF_UNIX socket whose
    /// path is not UTF-8: `SocketEntry::path` then shows U+FFFD for each stray
    /// byte, which names no file, and a `stat` of the socket file there needs
    /// the real name (DIVERGENCES 60). Rare, so kept beside the entries.
    raw_paths: HashMap<u64, Box<[u8]>>,
    /// The identity of the socket file at each bound path, by inode, found
    /// the first time a row asks and kept: every fd that holds the socket, in
    /// every process and task, asks the same question, which the C asks once
    /// per `/proc/net/unix` line. Empty unless the run names a path.
    bound_ids: std::cell::RefCell<HashMap<u64, Option<lsof_core::FileId>>>,
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
    pub fn load(want_queues: bool, skip_inet: bool) -> Self {
        let mut t = SocketTable::default();
        // `-X`. Which tables it actually gates was measured, not read from the
        // man page, which says "skip the reporting of information on all open
        // TCP and UDP files" — the rows are still reported, just unresolved.
        // `dsock.c` guards tcp, tcp6, udp, udp6 and **raw6** with `Fxopt`, and
        // leaves `/proc/net/raw`, `/proc/net/packet` and `/proc/net/unix`
        // alone. The v4/v6 raw split is the C's, not a transcription slip:
        // `:3530` has no guard where `:3761` does, and a live IPv4 raw socket
        // does keep its `raw` row under `-X`.
        if !skip_inet {
            // Absent files are normal, not an error: a host built without IPv6
            // has no /proc/net/tcp6 at all, and one without UDP-Lite no
            // /proc/net/udplite.
            t.load_inet("/proc/net/tcp", Protocol::Tcp, false, want_queues);
            t.load_inet("/proc/net/tcp6", Protocol::Tcp, true, want_queues);
            t.load_inet("/proc/net/udp", Protocol::Udp, false, want_queues);
            t.load_inet("/proc/net/udp6", Protocol::Udp, true, want_queues);
            // `dsock.c:3838-3843, 3946-3951`, gated by `Fxopt` as UDP is.
            t.load_inet("/proc/net/udplite", Protocol::UdpLite, false, want_queues);
            t.load_inet("/proc/net/udplite6", Protocol::UdpLite, true, want_queues);
            t.load_raw("/proc/net/raw6", true);
        }
        t.load_raw("/proc/net/raw", false);
        // Not gated by `-X` either: the C reads it unconditionally
        // (`dsock.c:3590`), and a bound netlink socket keeps its `netlink`
        // row under `-X` (measured).
        t.load_netlink("/proc/net/netlink");
        t.load_packet("/proc/net/packet");
        t.load_unix("/proc/net/unix");
        t
    }

    pub fn get(&self, inode: u64) -> Option<&SocketEntry> {
        self.by_inode.get(&inode)
    }

    /// The bytes of `inode`'s bound path, when they are not UTF-8.
    pub fn raw_path(&self, inode: u64) -> Option<&[u8]> {
        self.raw_paths.get(&inode).map(|b| &**b)
    }

    /// The identity of the socket file at `inode`'s bound path: `find`'s
    /// answer, asked once a run.
    pub fn bound_id(
        &self,
        inode: u64,
        find: impl FnOnce() -> Option<lsof_core::FileId>,
    ) -> Option<lsof_core::FileId> {
        if let Some(id) = self.bound_ids.borrow().get(&inode) {
            return *id;
        }
        let id = find();
        self.bound_ids.borrow_mut().insert(inode, id);
        id
    }

    fn load_inet(&mut self, path: &str, proto: Protocol, v6: bool, queues: bool) {
        if let Some(text) = crate::text::read_lossy(path) {
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
            // Linux's `/proc/net/udp` reuses the TCP state numbers — 1,
            // `ESTABLISHED`, for a connected socket, 7, `CLOSE`, for the usual
            // unconnected one — and the C keeps that number for UDP too: `-s
            // TCP:` filters a UDP socket by it. What it PRINTS is another
            // table, which for UDP registers `ESTABLISHED` alone
            // (`build_IPstates()`), so the model holds the number and
            // `SocketInfo::shown_state` hides every value but that one.
            // UDP-Lite's tables are UDP's, and the C reads them alike
            // (`get_tcpudp(…, 2, …)`): `-s TCP:` tests its number too
            // (measured: a connected one is `-s TCP:ESTABLISHED`'s), though
            // it never prints one (`SocketInfo::shown_state`).
            let udp_like = matches!(proto, Protocol::Udp | Protocol::UdpLite);
            let numbered = proto == Protocol::Tcp || udp_like;
            let state = numbered.then(|| tcp_state(f[INET_STATE]).into());
            // Both tables carry `tx_queue:rx_queue`, and lsof reports the
            // queues for UDP and UDP-Lite just as it does for TCP.
            let tcp = if queues && numbered {
                parse_queues(f[INET_QUEUES])
            } else {
                None
            };
            self.by_inode.insert(
                inode,
                SocketEntry {
                    file_type: if v6 { FileType::Ipv6 } else { FileType::Ipv4 },
                    info: Some(SocketInfo {
                        bound: None,
                        protocol: proto,
                        local,
                        remote,
                        state,
                        tcp,
                    }),
                    path: None,
                    device: Some(inode.to_string()),
                    node: proto.as_str().to_string(),
                    name: None,
                    type_suffix: None,
                },
            );
        }
    }

    /// `/proc/net/raw` and `raw6`: raw sockets, `IPPROTO_ICMP` and
    /// `IPPROTO_RAW` alike. The table shares the inet layout, but the C reads
    /// no address from it: it types the row `raw` (`raw6`), puts the inode in
    /// NODE, leaves DEVICE blank, and names it with the table's own text,
    /// `local_address->rem_address st=st` (`get_raw()`, `dsock.c:3530-3580`;
    /// measured `00000000:0001->00000000:0000 st=07` for a raw ICMP socket).
    /// It is no Internet file to the C, so no `-i` selects it, and `-F` gives
    /// its NODE as `i` (DIVERGENCES 108). (`/proc/net/icmp` lists ping
    /// sockets; the C reads it and this backend does not: DIVERGENCES 22.)
    fn load_raw(&mut self, path: &str, v6: bool) {
        if let Some(text) = crate::text::read_lossy(path) {
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
            let name = format!("{}->{} st={}", f[INET_LOCAL], f[INET_REMOTE], f[INET_STATE]);
            self.by_inode.insert(
                inode,
                SocketEntry {
                    // The C's LSOF_FILE_RAW and LSOF_FILE_RAW6.
                    file_type: FileType::Socket(if v6 { "raw6" } else { "raw" }),
                    info: None,
                    path: None,
                    device: None,
                    node: inode.to_string(),
                    name: Some(name),
                    type_suffix: None,
                },
            );
        }
    }

    /// `/proc/net/netlink` — the netlink sockets the kernel has bound, which
    /// the C types `netlink` and names by protocol (`get_netlink()`,
    /// `dsock.c:3595-3611`, DIVERGENCES 109). An unbound netlink socket is
    /// not listed here (its inode column is that of no socket yet), and is
    /// named from `system.sockprotoname` instead: `sock … protocol: NETLINK`.
    fn load_netlink(&mut self, path: &str) {
        if let Some(text) = crate::text::read_lossy(path) {
            self.parse_netlink(&text);
        }
    }

    /// The parsing half of [`Self::load_netlink`]. Pure; must never panic.
    ///
    /// As the C reads it: a line of fewer than ten fields is skipped, header
    /// included; the header must say `Eth` in its second column and `Inode`
    /// in its tenth, or the whole table is dropped (the C warns
    /// `unsupported format` and stops reading); the inode is the tenth
    /// column, and a line whose inode is already recorded keeps the first;
    /// the protocol is the `Eth` column through `atoi()`, so a value that is
    /// no number is protocol 0. A row is TYPE `netlink`, no DEVICE, SIZE/OFF
    /// `0t0`, NODE the inode and NAME the protocol's name, or `unknown
    /// protocol: N` (measured: `ROUTE`, `KOBJECT_UEVENT`, `GENERIC`).
    pub fn parse_netlink(&mut self, text: &str) {
        let mut lines = text
            .lines()
            .filter(|l| l.split_whitespace().nth(9).is_some());
        match lines.next() {
            Some(h) => {
                let f: Vec<&str> = h.split_whitespace().collect();
                if f.get(NETLINK_ETH) != Some(&"Eth") || f.get(NETLINK_INODE) != Some(&"Inode") {
                    return;
                }
            }
            None => return,
        }
        for line in lines {
            let f: Vec<&str> = line.split_whitespace().collect();
            let (Some(eth), Some(ino)) = (f.get(NETLINK_ETH), f.get(NETLINK_INODE)) else {
                continue;
            };
            let Ok(inode) = ino.parse::<u64>() else {
                continue;
            };
            let proto = leading_u32(eth);
            self.by_inode.entry(inode).or_insert_with(|| SocketEntry {
                // The C's LSOF_FILE_NETLINK.
                file_type: FileType::Socket("netlink"),
                info: None,
                path: None,
                device: None,
                node: inode.to_string(),
                name: Some(netlink_name(proto)),
                type_suffix: None,
            });
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
        if let Some(text) = crate::text::read_lossy(path) {
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
                    info: Some(SocketInfo {
                        bound: None,
                        // The family, not the ethernet protocol: the latter is
                        // the NODE cell, and `-F P` reads it from there. Same
                        // split `parse_unix` makes with `Protocol::Other`.
                        protocol: Protocol::Other("packet"),
                        local: None,
                        remote: None,
                        state: None,
                        tcp: None,
                    }),
                    path: None,
                    device: Some(inode.to_string()),
                    node: packet_node(proto),
                    name: None,
                    type_suffix: Some(socket_type_suffix(ty)),
                },
            );
        }
    }

    fn load_unix(&mut self, path: &str) {
        let Ok(bytes) = std::fs::read(path) else {
            return;
        };
        self.parse_unix_bytes(bytes);
    }

    /// The parsing half of [`Self::load_unix`], over the file's bytes: the
    /// text, and for a path that is not UTF-8 its raw bytes as well. Pure;
    /// must never panic, and fuzzed (`proc_net`), because the raw path is
    /// reached only from here.
    pub fn parse_unix_bytes(&mut self, bytes: Vec<u8>) {
        match String::from_utf8(bytes) {
            Ok(text) => self.parse_unix(&text),
            // A stray byte costs that byte's display, never the table (see
            // `text::read_lossy`), and the path keeps its bytes for a `stat`.
            Err(e) => {
                let raw = e.into_bytes();
                self.parse_unix(&String::from_utf8_lossy(&raw));
                self.keep_raw_unix_paths(&raw);
            }
        }
    }

    /// Give each socket whose bound path is not UTF-8 the path's own bytes.
    /// Every column before the path is ASCII, so the decoded line and the raw
    /// one agree up to it: the path starts at the same offset in both. A line
    /// where that does not hold is left alone rather than cut in the wrong
    /// place.
    fn keep_raw_unix_paths(&mut self, raw: &[u8]) {
        for line in raw.split(|&b| b == b'\n').skip(1) {
            if std::str::from_utf8(line).is_ok() {
                continue;
            }
            let shown = String::from_utf8_lossy(line);
            let f = fields_with_rest(&shown, UNIX_PATH + 1);
            let (Some(inode), Some(path)) = (
                f.get(UNIX_INODE).and_then(|s| s.parse::<u64>().ok()),
                f.get(UNIX_PATH),
            ) else {
                continue;
            };
            // The path is the last field, so it runs to the end of the line.
            // Checked although `path` is a tail of `shown`: the bytes are a
            // name whoever bound the socket chose, and the release build
            // panics on an underflow.
            let Some(start) = shown.len().checked_sub(path.len()) else {
                continue;
            };
            if !line.get(..start).is_some_and(<[u8]>::is_ascii) {
                continue;
            }
            if self.by_inode.contains_key(&inode) {
                self.raw_paths.insert(inode, line[start..].into());
            }
        }
    }

    /// The text half of [`Self::parse_unix_bytes`]. Pure; must never panic —
    /// the path column is arbitrary bytes chosen by whoever bound the socket.
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
                    info: Some(SocketInfo {
                        bound: None,
                        protocol: Protocol::Other("unix"),
                        local: None,
                        remote: None,
                        state: Some(unix_state(f[UNIX_FLAGS], f[UNIX_STATE]).into()),
                        tcp: None,
                    }),
                    path: f.get(UNIX_PATH).map(|s| s.to_string()),
                    device: Some(device),
                    node: inode.to_string(),
                    name: None,
                    type_suffix: Some(unix_suffix(f[UNIX_TYPE])),
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
/// `/proc/net/netlink`'s columns as the C indexes them (`get_netlink()`).
const NETLINK_ETH: usize = 1;
const NETLINK_INODE: usize = 9;
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
/// the wire states, so the mapping is fixed by include/net/tcp_states.h — and
/// the names are the C's for them (`build_IPstates()`), which call 3
/// `SYN_RECV` and 7 `CLOSE` where Windows says `SYN_RCVD` and `CLOSED`. A
/// number past `TCP_CLOSING` (`NEW_SYN_RECV`, `BOUND_INACTIVE`) is outside
/// the C's table: `UNKNOWN`, and never filtered by `-s`.
pub fn tcp_state(hex: &str) -> TcpState {
    match u8::from_str_radix(hex, 16) {
        Ok(0x01) => TcpState::Established,
        Ok(0x02) => TcpState::SynSent,
        Ok(0x03) => TcpState::SynRecv,
        Ok(0x04) => TcpState::FinWait1,
        Ok(0x05) => TcpState::FinWait2,
        Ok(0x06) => TcpState::TimeWait,
        Ok(0x07) => TcpState::Close,
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

/// What names a socket this namespace's `/proc/net` tables do not list, as
/// the C names it (`process_proc_sock()`, `dsock.c:4145-4166`, DIVERGENCES
/// 22): the `system.sockprotoname` extended attribute the kernel gives every
/// socket, read through the fd's link, `sock … protocol: UDP`. That covers a
/// family with no table at all (AF_VSOCK), a socket no table lists yet (an
/// unbound UDP, UDP-Lite or netlink socket, a TCP socket bound and never
/// listening, a ping socket) and a socket in another network namespace,
/// which the C's tables, read from its own `/proc/net`, never list: each is
/// named by the kernel's `struct proto` name (`TCP`, `UDP-Lite`, `RAW`,
/// `UNIX-STREAM`, `PACKET`, `NETLINK`, `AF_VSOCK`, `PING`, all measured).
/// Under `-X` the C does not look, and says so.
pub struct SockProtoNames {
    /// `-X`. The C reads `system.sockprotoname` in exactly the branch this
    /// type stands in for, and `-X` replaces that read with a fixed string
    /// (`dsock.c:4155`) — so under it there is nothing to look up.
    skip_inet: bool,
}

impl SockProtoNames {
    pub fn new(skip_inet: bool) -> Self {
        Self { skip_inet }
    }

    /// The NAME cell for socket `inode`, held by the fd whose magic link is
    /// `link` (`/proc/PID/fd/N`), which no table lists: `protocol: TCP`,
    /// `can't identify protocol` when the attribute cannot be read, and
    /// under `-X` the fixed `can't identify protocol (-X specified)`, which
    /// the C emits *instead of* reading it.
    pub fn unlisted_name(&self, link: &Path, inode: u64) -> String {
        if self.skip_inet {
            return self.unidentified().to_string();
        }
        match sock_proto_name(link, inode) {
            Some(proto) => format!("protocol: {proto}"),
            None => self.unidentified().to_string(),
        }
    }

    /// NAME for a socket the C cannot name: what `process_proc_sock()`
    /// prints when no table knows it and its `getxattr()` fails, or under
    /// `-X`, where it does not look.
    pub fn unidentified(&self) -> &'static str {
        if self.skip_inet {
            "can't identify protocol (-X specified)"
        } else {
            "can't identify protocol"
        }
    }
}

/// The `system.sockprotoname` extended attribute of socket `inode`, through
/// the fd link `link` that holds it — what the C's `getxattr(pbr,
/// "system.sockprotoname", …)` reads, with `pbr` the same `/proc/PID/fd/N`
/// (measured with strace). The value is the kernel's protocol name with its
/// NUL; what precedes the first NUL is the name.
///
/// The C asks through the link itself, so a descriptor its owner replaced
/// between the C's `stat` and this call is asked instead — and a file on a
/// FUSE file system that does not answer would hold the run, since FUSE
/// sends `system.*` attributes to its daemon. Here the link is first opened
/// `O_PATH`, which makes no file system call on a local or FUSE file. The
/// pinned descriptor's own link, `/proc/self/fd/K`, is then read: the kernel
/// spells it from the dentry (`d_path`), asking no file system, and only a
/// sockfs inode spells `socket:[N]`. Only when it is `socket:[inode]` is the
/// attribute read, through that same `/proc/self/fd/K`, so the call reaches
/// sockfs, whose handler only copies a name, whatever the owner does
/// meanwhile. (An `fstat` of the pinned descriptor had been the check, and
/// FUSE answers that one: a swapped-in file on a hung FUSE mount held it,
/// measured with `fuse_hang.py`.) What remains: the `O_PATH` open follows
/// the link, and a file system that revalidates a dentry on open
/// (`d_weak_revalidate`, NFS) may be asked then; the C's own `stat` of the
/// same link, made before, asks every file system anyway.
///
/// `None` when any step fails, which the C prints as `can't identify
/// protocol`. The descriptor is closed on return.
pub fn sock_proto_name(link: &Path, inode: u64) -> Option<String> {
    // miri implements neither `O_PATH` nor `getxattr`; under it the row is
    // the one a failed `getxattr()` gives.
    if cfg!(miri) {
        return None;
    }
    use std::os::unix::fs::OpenOptionsExt;
    let pinned = std::fs::OpenOptions::new()
        .read(true)
        // The architecture's own `O_PATH` (it is not one number on all).
        .custom_flags(i32::try_from(rustix::fs::OFlags::PATH.bits()).ok()?)
        .open(link)
        .ok()?;
    let through = format!("/proc/self/fd/{}", std::os::fd::AsRawFd::as_raw_fd(&pinned));
    let names = std::fs::read_link(&through).ok()?;
    if !is_socket_link(names.as_os_str().as_encoded_bytes(), inode) {
        return None;
    }
    read_proto_name(|value| {
        rustix::fs::getxattr(through.as_str(), "system.sockprotoname", value).ok()
    })
}

/// Whether a descriptor's `/proc` link text names socket `inode`: exactly
/// `socket:[inode]`, as sockfs spells it (`sockfs_dname()`).
fn is_socket_link(text: &[u8], inode: u64) -> bool {
    text == format!("socket:[{inode}]").as_bytes()
}

/// The protocol name `get` reads into a [`SOCKPROTONAME_MAX`]-byte buffer,
/// which it fills as `getxattr(2)` does and says how many bytes it wrote:
/// what precedes the first NUL, decoded lossily (the kernel chooses it, and
/// NAME escaping prints it). `None` when `get` fails (`ERANGE` for a buffer
/// too small, `ENODATA`, …) or claims more than the buffer.
fn read_proto_name(get: impl FnOnce(&mut [u8]) -> Option<usize>) -> Option<String> {
    let mut value = [0u8; SOCKPROTONAME_MAX];
    let len = get(&mut value[..])?;
    let value = value.get(..len)?;
    let name = value.split(|&b| b == 0).next().unwrap_or_default();
    Some(String::from_utf8_lossy(name).into_owned())
}

/// Room for a `system.sockprotoname` value: the kernel's `struct proto` names
/// it from a `char name[32]`, NUL included, and `sockfs_getxattr()` copies
/// `strlen + 1` bytes or fails with `ERANGE`, which is `can't identify
/// protocol` (the C's buffer is the rest of its NAME buffer, so it would
/// print a longer one; no kernel has one). Real names reach 18 bytes with the
/// NUL (`IEEE-802.15.4-MAC`), past any this host's fixtures make.
const SOCKPROTONAME_MAX: usize = 32;

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

/// A netlink socket's NAME: its protocol's name from the C's
/// `netlink_proto_to_str()` (`dsock.c:4291-4427`), every `NETLINK_*` the
/// oracle's headers define, or `unknown protocol: N` for a number it has no
/// name for (`dsock.c:3606`). The numbers are the kernel's ABI
/// (`linux/netlink.h`); 4 is `NETLINK_SOCK_DIAG`, which the C names by its
/// older alias, `INET_DIAG`, and 17 has no name.
pub fn netlink_name(proto: u32) -> String {
    let name = match proto {
        0 => "ROUTE",
        1 => "UNUSED",
        2 => "USERSOCK",
        3 => "FIREWALL",
        4 => "INET_DIAG",
        5 => "NFLOG",
        6 => "XFRM",
        7 => "SELINUX",
        8 => "ISCSI",
        9 => "AUDIT",
        10 => "FIB_LOOKUP",
        11 => "CONNECTOR",
        12 => "NETFILTER",
        13 => "IP6_FW",
        14 => "DNRTMSG",
        15 => "KOBJECT_UEVENT",
        16 => "GENERIC",
        18 => "SCSITRANSPORT",
        19 => "ECRYPTFS",
        20 => "RDMA",
        21 => "CRYPTO",
        22 => "SMC",
        // `%d` of the C's `int`: a number past `INT_MAX` prints negative.
        _ => return format!("unknown protocol: {}", proto as i32),
    };
    name.to_string()
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
        // The two the C names differently from Windows (`build_IPstates()`):
        // lsof-rs printed `SYN_RCVD` and `CLOSED` here, and `-s TCP:CLOSE`
        // could not have matched anything.
        assert_eq!(tcp_state("03").as_str(), "SYN_RECV");
        assert_eq!(tcp_state("07").as_str(), "CLOSE");
        // Every number the C's table has, and only those, is a -s state.
        for n in 1..=11u8 {
            let st = tcp_state(&format!("{n:02X}"));
            assert!(
                lsof_core::model::LINUX_TCP_STATES.contains(&st),
                "state {n} ({}) must be one -s can name",
                st.as_str()
            );
        }
        // Past TCP_CLOSING the C's table ends: NEW_SYN_RECV is 0x0c.
        assert_eq!(tcp_state("0C").as_str(), "UNKNOWN");
        // Lowercase is what the kernel actually writes for 0x0a in some files.
        assert_eq!(tcp_state("0a").as_str(), "LISTEN");
        assert_eq!(tcp_state("ff").as_str(), "UNKNOWN");
        assert_eq!(tcp_state("").as_str(), "UNKNOWN");
    }

    /// `/proc/net/udplite` as the kernel wrote it for a bound and a connected
    /// UDP-Lite socket (measured 2026-10-10), read as the C reads it: an
    /// IPv4 row with NODE `UDPLITE`, the state number kept for `-s TCP:` and
    /// never shown, the queues under `-T q`, and `UDP-Lite` for the
    /// kernel's name of it.
    #[test]
    fn a_udplite_socket_is_udps_sibling_and_shows_no_state() {
        let text = "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops            \n\
 7429: 0100007F:A3E8 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 390777 2 0000000076cf7996 0        \n\
 7525: 0100007F:8448 0100007F:A3E8 01 00000000:00000000 00:00000000 00000000     0        0 390780 2 00000000c3d7de0c 0        \n";
        let mut t = SocketTable::default();
        t.parse_inet(text, Protocol::UdpLite, false, true);
        let bound = t.get(390777).expect("bound");
        assert_eq!(bound.file_type, FileType::Ipv4);
        assert_eq!(bound.node, "UDPLITE");
        assert_eq!(bound.device.as_deref(), Some("390777"));
        let info = bound.info.as_ref().unwrap();
        assert_eq!(info.display_name(false, false), "127.0.0.1:41960");
        assert_eq!(info.filter_state(), Some(TcpState::Close));
        assert_eq!(info.shown_state(), None);
        assert!(info.tcp.is_some(), "the queues, under -T q");
        let conn = t.get(390780).expect("connected").info.as_ref().unwrap();
        assert_eq!(
            conn.display_name(false, false),
            "127.0.0.1:33864->127.0.0.1:41960"
        );
        assert_eq!(conn.filter_state(), Some(TcpState::Established));
        assert_eq!(conn.shown_state(), None, "no (ESTABLISHED), measured");
    }

    /// `/proc/net/raw` as the kernel wrote it for a raw ICMP and a raw
    /// `IPPROTO_RAW` socket (measured 2026-10-10): typed `raw`, DEVICE blank,
    /// the inode in NODE, the table's own text for NAME, no `SocketInfo`, and
    /// `RAW` for the kernel's name of either (DIVERGENCES 108).
    #[test]
    fn a_raw_socket_is_named_from_its_table_line() {
        let text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n\
  85: 00000000:0001 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 390778 2 00000000400092a3 0\n\
 246: 00000000:00FF 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 390779 2 000000005c481855 0\n\
 247: short line\n";
        let mut t = SocketTable::default();
        t.parse_raw(text, false);
        assert_eq!(t.by_inode.len(), 2);
        for (inode, name) in [
            (390778, "00000000:0001->00000000:0000 st=07"),
            (390779, "00000000:00FF->00000000:0000 st=07"),
        ] {
            let e = t.get(inode).unwrap();
            assert_eq!(e.file_type, FileType::Socket("raw"));
            assert_eq!(e.name.as_deref(), Some(name));
            assert_eq!(e.node, inode.to_string());
            assert!(e.device.is_none() && e.info.is_none());
        }
        let mut t6 = SocketTable::default();
        t6.parse_raw(text, true);
        let e = t6.get(390778).unwrap();
        assert_eq!(e.file_type, FileType::Socket("raw6"));
    }

    #[test]
    fn a_udp_socket_keeps_its_state_for_dash_s_and_shows_only_established() {
        // Measured against the C: an unconnected UDP socket (st 07) prints no
        // state but is listed by `-sTCP:CLOSE` and dropped by `-sTCP:LISTEN`;
        // a connected one (st 01) prints `(ESTABLISHED)` and is listed by
        // `-sTCP:ESTABLISHED`. lsof-rs had kept no state for the first, so
        // no `-s` could tell it from a TCP socket in any state.
        let mut t = SocketTable::default();
        t.parse_inet(
            "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n\
   1: 0100007F:DF0A 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 5101 2 0000000000000000 0\n\
   2: 0100007F:9164 0100007F:DF0A 01 00000000:00000000 00:00000000 00000000     0        0 5102 2 0000000000000000 0\n",
            Protocol::Udp,
            false,
            false,
        );
        let idle = t.get(5101).expect("unconnected").info.as_ref().unwrap();
        assert_eq!(idle.filter_state(), Some(TcpState::Close));
        assert_eq!(idle.shown_state(), None, "prints no state");
        let conn = t.get(5102).expect("connected").info.as_ref().unwrap();
        assert_eq!(conn.filter_state(), Some(TcpState::Established));
        assert_eq!(conn.shown_state().map(|s| s.as_str()), Some("ESTABLISHED"));
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
    fn a_unix_path_that_is_not_utf8_keeps_its_bytes_for_the_stat() {
        // DIVERGENCES 60: the path is shown with U+FFFD, which names no file,
        // so a `stat` of the socket file there needs the path's own bytes.
        let raw = b"Num RefCount Protocol Flags Type St Inode Path\n\
0000: 00000002 00000000 00010000 0001 01 184 /tmp/s\xffock\n\
0000: 00000002 00000000 00010000 0001 01 185 /tmp/plain.sock\n\
0000: 0000\xfe02 00000000 00010000 0001 01 186 /tmp/t\xffo\n";
        let path = std::env::temp_dir().join(format!("lsof-rs-unix-{}", std::process::id()));
        std::fs::write(&path, raw).unwrap();
        let mut t = SocketTable::default();
        t.load_unix(path.to_str().unwrap());
        let _ = std::fs::remove_file(&path);
        let odd = t.get(184).unwrap();
        assert_eq!(odd.path.as_deref(), Some("/tmp/s\u{FFFD}ock"));
        assert_eq!(t.raw_path(184), Some(&b"/tmp/s\xffock"[..]));
        // A path that is UTF-8 keeps nothing extra.
        assert!(t.get(185).is_some());
        assert_eq!(t.raw_path(185), None);
        // A stray byte BEFORE the path moves it in the decoded line, so its
        // bytes cannot be found by offset there, and none are kept.
        assert!(t.get(186).is_some());
        assert_eq!(t.raw_path(186), None);
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
        let t = SocketTable::load(false, false);
        for e in t.by_inode.values() {
            match &e.file_type {
                FileType::Ipv4 | FileType::Ipv6 | FileType::Unix => {}
                FileType::Other(c) if c == "pack" => {}
                FileType::Socket("raw" | "raw6" | "netlink") => {}
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
        //   raw   DEVICE blank, NODE = inode
        let t = SocketTable::load(false, false);
        for e in t.by_inode.values() {
            let device = e.device.as_deref().unwrap_or_default();
            match &e.file_type {
                FileType::Ipv4 | FileType::Ipv6 => {
                    assert!(
                        device.parse::<u64>().is_ok(),
                        "inet DEVICE should be the inode, got {:?}",
                        device
                    );
                    assert!(
                        ["TCP", "UDP", "UDPLITE"].contains(&e.node.as_str()),
                        "inet NODE should be the protocol, got {:?}",
                        e.node
                    );
                }
                FileType::Unix => {
                    assert!(
                        device.starts_with("0x"),
                        "unix DEVICE should be the kernel pointer, got {:?}",
                        device
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
                        device.parse::<u64>().is_ok(),
                        "pack DEVICE should be the inode, got {:?}",
                        device
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
                FileType::Socket("raw" | "raw6") => {
                    assert!(e.device.is_none(), "a raw DEVICE is blank");
                    assert!(
                        e.node.parse::<u64>().is_ok(),
                        "raw NODE should be the inode, got {:?}",
                        e.node
                    );
                    assert!(e.info.is_none(), "a raw row is no Internet file");
                }
                FileType::Socket("netlink") => {
                    // netlink  DEVICE blank, NODE = inode, NAME = protocol
                    assert!(e.device.is_none(), "a netlink DEVICE is blank");
                    assert!(e.node.parse::<u64>().is_ok(), "{:?}", e.node);
                    assert!(e.name.as_deref().is_some_and(|n| !n.is_empty()));
                    assert!(e.info.is_none(), "a netlink row is no Internet file");
                }
                other => panic!("unexpected socket file type {other:?}"),
            }
        }
    }

    /// One unix socket bound to a path that is not UTF-8, anywhere on the
    /// host, made `/proc/net/unix` unreadable as a `String` — and lsof-rs
    /// resolved **no** unix socket at all: `lsof -U` printed nothing for any
    /// process, where the C listed every one. Binding such a path needs no
    /// privilege (see `crate::text`).
    #[test]
    #[cfg_attr(
        miri,
        ignore = "miri's socket shim allows only AF_INET and AF_INET6 (measured: `socket: domain 0x1 is unsupported`); this test needs an AF_UNIX socket"
    )]
    fn a_non_utf8_socket_path_does_not_blind_the_unix_table() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::net::UnixListener;
        let dir = std::env::temp_dir().join(format!("lsof-rs-sock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let plain_path = dir.join("plain");
        let hostile_path = dir.join(std::ffi::OsStr::from_bytes(b"sock\xff"));
        let plain = UnixListener::bind(&plain_path).expect("bind plain");
        let hostile = UnixListener::bind(&hostile_path).expect("bind hostile");
        let inode_of = |l: &UnixListener| -> u64 {
            use std::os::fd::AsRawFd;
            let link = std::fs::read_link(format!("/proc/self/fd/{}", l.as_raw_fd())).unwrap();
            socket_inode(&link.to_string_lossy()).expect("a socket:[inode] link")
        };
        let (plain_ino, hostile_ino) = (inode_of(&plain), inode_of(&hostile));
        let strict = std::fs::read_to_string("/proc/net/unix");
        let t = SocketTable::load(false, false);
        drop((plain, hostile));
        std::fs::remove_dir_all(&dir).ok();
        assert!(
            strict.is_err(),
            "control: the strict read must fail while the hostile path is bound"
        );
        assert!(
            t.get(plain_ino).is_some(),
            "the ordinary socket must still resolve"
        );
        let e = t.get(hostile_ino).expect("and so must the hostile one");
        assert!(
            e.path
                .as_deref()
                .is_some_and(|p| p.ends_with("sock\u{FFFD}")),
            "its path keeps everything but the undecodable byte: {:?}",
            e.path
        );
    }

    #[test]
    fn queues_are_absent_unless_asked_for() {
        // The renderer emits a (QR=)(QS=) suffix whenever the field is present,
        // so a plain run must not populate it.
        let t = SocketTable::load(false, false);
        assert!(
            t.by_inode
                .values()
                .all(|e| e.info.as_ref().is_none_or(|i| i.tcp.is_none())),
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
        assert_eq!(e.device.as_deref(), Some("1399"), "DEVICE is the inode");
        assert_eq!(e.node, "ALL", "NODE is the ethernet protocol");
        assert_eq!(e.type_suffix.as_deref(), Some("type=SOCK_RAW"));
        assert!(e.path.is_none(), "a packet socket is never bound to a path");
        assert!(
            e.info.as_ref().unwrap().state.is_none(),
            "and has no state to print"
        );
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
    /// The buffer the attribute is read into holds the longest name a
    /// kernel `struct proto` can have, 31 bytes and its NUL: a smaller one
    /// is the kernel's `ERANGE`, `can't identify protocol` for a socket the C
    /// names (`IEEE-802.15.4-MAC`, 18 bytes, has no fixture on this host).
    #[test]
    fn the_attribute_buffer_holds_any_struct_proto_name() {
        // `getxattr(2)` as sockfs answers it: the name and its NUL, or
        // `ERANGE` (`None`) into a buffer too small.
        let kernel = |name: &'static [u8]| {
            move |buf: &mut [u8]| {
                let value = [name, b"\0"].concat();
                let room = buf.get_mut(..value.len())?;
                room.copy_from_slice(&value);
                Some(value.len())
            }
        };
        let longest: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ01234";
        assert_eq!(longest.len(), 31);
        assert_eq!(
            read_proto_name(kernel(longest)).as_deref(),
            Some("ABCDEFGHIJKLMNOPQRSTUVWXYZ01234")
        );
        assert_eq!(
            read_proto_name(kernel(b"IEEE-802.15.4-MAC")).as_deref(),
            Some("IEEE-802.15.4-MAC")
        );
        assert_eq!(read_proto_name(kernel(b"UDP")).as_deref(), Some("UDP"));
        // What follows the first NUL is not the name; a failed call and a
        // length past the buffer are no name at all.
        assert_eq!(
            read_proto_name(|b: &mut [u8]| {
                b[..6].copy_from_slice(b"TCP\0xy");
                Some(6)
            })
            .as_deref(),
            Some("TCP")
        );
        assert_eq!(read_proto_name(|_: &mut [u8]| None), None);
        assert_eq!(read_proto_name(|b: &mut [u8]| Some(b.len() + 1)), None);
        // Not UTF-8: decoded lossily, never refused.
        assert_eq!(
            read_proto_name(|b: &mut [u8]| {
                b[..2].copy_from_slice(b"\xff\0");
                Some(2)
            })
            .as_deref(),
            Some("\u{fffd}")
        );
    }

    /// Only a descriptor whose link sockfs spells `socket:[inode]` is asked.
    #[test]
    fn only_the_socket_the_link_named_is_asked() {
        assert!(is_socket_link(b"socket:[12345]", 12345));
        assert!(is_socket_link(
            format!("socket:[{}]", u64::MAX).as_bytes(),
            u64::MAX
        ));
        for other in [
            &b"socket:[12346]"[..],
            b"socket:[012345]",
            b"socket:[12345]x",
            b"socket:[12345",
            b"pipe:[12345]",
            b"/tmp/socket:[12345]",
            b"",
        ] {
            assert!(!is_socket_link(other, 12345), "{other:?}");
        }
    }

    /// The inner half of [`a_swapped_in_fuse_file_is_never_asked`]: a no-op
    /// unless that test runs this binary in its mount namespace, with a FUSE
    /// server that never answers mounted at `LSOF_RS_HUNG_FUSE`. There the
    /// state after a descriptor swap is made — an `O_PATH` descriptor on the
    /// mount's root, which asks the server nothing — and `sock_proto_name`
    /// is asked about it through `/proc/self/fd/K`.
    #[test]
    #[cfg_attr(miri, ignore = "miri implements neither O_PATH nor getxattr")]
    fn sock_proto_name_on_a_hung_fuse_file() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;
        let Some(root) = std::env::var_os("LSOF_RS_HUNG_FUSE") else {
            return;
        };
        let pinned = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(i32::try_from(rustix::fs::OFlags::PATH.bits()).unwrap())
            .open(root)
            .unwrap();
        println!("inner_pid={}", std::process::id());
        let link = format!("/proc/self/fd/{}", pinned.as_raw_fd());
        assert_eq!(sock_proto_name(Path::new(&link), 1), None);
        println!("inner_done=1");
    }

    /// DIVERGENCES 22: `sock_proto_name` asks no file system but sockfs. A
    /// descriptor its owner swapped onto a file on a FUSE mount whose server
    /// never answers is refused at once, and the server is asked nothing: the
    /// identity check is the readlink of the pinned descriptor, which the
    /// kernel answers from the dentry. The `fstat` it replaced was a GETATTR
    /// the server held (measured). Root only, in a private mount namespace,
    /// with `differential/fuse_hang.py`; skipped, saying why, elsewhere.
    #[test]
    #[cfg_attr(miri, ignore = "miri cannot spawn a process")]
    fn a_swapped_in_fuse_file_is_never_asked() {
        use std::process::Command;
        let works = |argv: &[&str]| {
            Command::new(argv[0])
                .args(&argv[1..])
                .output()
                .is_ok_and(|o| o.status.success())
        };
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        let root = status
            .lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|l| l.split_whitespace().nth(1))
            == Some("0");
        let timeouts_off = ["default_request_timeout", "max_request_timeout"]
            .iter()
            .all(|n| {
                let v =
                    std::fs::read_to_string(format!("/proc/sys/fs/fuse/{n}")).unwrap_or_default();
                matches!(v.trim(), "" | "0")
            });
        if !root
            || !Path::new("/dev/fuse").exists()
            || !timeouts_off
            || !works(&["unshare", "-m", "--propagation", "private", "true"])
            || !works(&["python3", "-c", "pass"])
        {
            eprintln!("skipped: needs root, a working /dev/fuse with no request timeout, unshare -m and python3");
            return;
        }
        let tmp = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let dir = tmp.join(format!("lsof-rs-xattr-fuse-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("fuse")).unwrap();
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../differential/fuse_hang.py");
        let script = format!(
            r#"set -u
cd /
python3 -I '{fixture}' '{fuse}' --mode hold --ready '{dir}/ready' --log '{dir}/log' --lifetime 60 &
srv=$!
i=0
while [ ! -e '{dir}/ready' ]; do
    i=$((i+1))
    if [ $i -gt 200 ] || ! kill -0 $srv 2>/dev/null; then
        echo error=no-fuse; kill $srv 2>/dev/null; exit 0
    fi
    sleep 0.05
done
LSOF_RS_HUNG_FUSE='{fuse}' '{bin}' --exact net::tests::sock_proto_name_on_a_hung_fuse_file --nocapture --test-threads 1 >'{dir}/inner' 2>&1 &
t=$!
i=0
while kill -0 $t 2>/dev/null && [ $i -lt 100 ]; do i=$((i+1)); sleep 0.05; done
if kill -0 $t 2>/dev/null; then echo hung=1; else echo hung=0; fi
kill $srv; wait $srv
wait $t; echo inner_rc=$?
"#,
            fixture = fixture.display(),
            fuse = dir.join("fuse").display(),
            dir = dir.display(),
            bin = std::env::current_exe().unwrap().display(),
        );
        let out = Command::new("unshare")
            .args(["-m", "--propagation", "private", "sh", "-c", &script])
            .output()
            .unwrap();
        let said = String::from_utf8_lossy(&out.stdout).into_owned();
        let inner = std::fs::read_to_string(dir.join("inner")).unwrap_or_default();
        let log = std::fs::read_to_string(dir.join("log")).unwrap_or_default();
        let _ = std::fs::remove_dir_all(&dir);
        if said.contains("error=no-fuse") {
            eprintln!("skipped: /dev/fuse could not be mounted");
            return;
        }
        assert!(said.contains("hung=0"), "{said}\n{inner}\n{log}");
        assert!(said.contains("inner_rc=0"), "{said}\n{inner}\n{log}");
        assert!(inner.contains("inner_done=1"), "{inner}");
        let pid = inner
            .lines()
            .find_map(|l| l.split("inner_pid=").nth(1))
            .map(|rest| {
                rest.split(|c: char| !c.is_ascii_digit())
                    .next()
                    .unwrap_or("")
            })
            .filter(|pid| !pid.is_empty())
            .expect("the inner test's pid");
        let asked: Vec<&str> = log
            .lines()
            .filter(|l| l.contains(&format!(" pid={pid} ")) || l.ends_with(&format!(" pid={pid}")))
            .collect();
        assert!(asked.is_empty(), "the server was asked: {asked:?}\n{log}");
    }

    #[test]
    #[cfg_attr(miri, ignore = "miri implements neither O_PATH nor getxattr")]
    fn the_kernel_names_a_socket_by_its_struct_proto() {
        // `system.sockprotoname`, read as `sock_proto_name` reads it, through
        // the fd's link, for sockets std can make: the kernel's `struct proto`
        // name, which for AF_UNIX is not the family (`unix`) but the proto a
        // socket uses, so a stream socket is UNIX-STREAM and a datagram one
        // UNIX. Measured against the C, which printed the same names for
        // sockets in a foreign network namespace (fixtures L, NSRAW, J).
        use std::os::fd::AsRawFd;
        let name = |fd: &dyn AsRawFd| {
            let link = format!("/proc/self/fd/{}", fd.as_raw_fd());
            let ino = std::os::unix::fs::MetadataExt::ino(&std::fs::metadata(&link).unwrap());
            sock_proto_name(Path::new(&link), ino)
        };
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        assert_eq!(name(&a).as_deref(), Some("UNIX-STREAM"));
        let d = std::os::unix::net::UnixDatagram::unbound().unwrap();
        assert_eq!(name(&d).as_deref(), Some("UNIX"));
        let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        assert_eq!(name(&u).as_deref(), Some("UDP"));
        let t = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        assert_eq!(name(&t).as_deref(), Some("TCP"));
        // The inode the link named must be the one that answers: a
        // descriptor replaced in between is not asked (`None`, the C's
        // `can't identify protocol`), and neither is a file that is no
        // socket, which a FUSE daemon could otherwise be asked about.
        let link = format!("/proc/self/fd/{}", u.as_raw_fd());
        assert_eq!(sock_proto_name(Path::new(&link), u64::MAX), None);
        let f = std::fs::File::open("/proc/self/status").unwrap();
        let link = format!("/proc/self/fd/{}", f.as_raw_fd());
        let ino = std::os::unix::fs::MetadataExt::ino(&std::fs::metadata(&link).unwrap());
        assert_eq!(sock_proto_name(Path::new(&link), ino), None);
        assert_eq!(sock_proto_name(Path::new("/nonexistent/lsof-rs"), 1), None);
        // And the NAME cell around it.
        let names = SockProtoNames::new(false);
        let link = format!("/proc/self/fd/{}", t.as_raw_fd());
        let ino = std::os::unix::fs::MetadataExt::ino(&std::fs::metadata(&link).unwrap());
        assert_eq!(names.unlisted_name(Path::new(&link), ino), "protocol: TCP");
        assert_eq!(
            names.unlisted_name(Path::new("/nonexistent/lsof-rs"), 1),
            "can't identify protocol"
        );
    }
    /// `/proc/net/netlink` as this kernel wrote it (2026-10-30) for a bound
    /// `NETLINK_ROUTE` socket and the kernel's own, read as the C's
    /// `get_netlink()` reads it (DIVERGENCES 109): TYPE `netlink`, no DEVICE,
    /// NODE the inode, NAME the protocol by name or number.
    #[test]
    fn a_bound_netlink_socket_is_named_by_its_protocol() {
        let text = "sk               Eth Pid        Groups   Rmem     Wmem     Dump  Locks    Drops    Inode\n\
000000000a2cfcbb 0   7884       00000000 0        0        0     2        0        13110   \n\
000000003d480def 4   0          00000000 0        0        0     2        0        3880    \n\
00000000aaaaaaaa 15  1          00000001 0        0        0     2        0        13112   \n\
00000000bbbbbbbb 17  1          00000001 0        0        0     2        0        13113   \n\
00000000cccccccc x7  1          00000001 0        0        0     2        0        13114   \n\
00000000dddddddd 16  1          00000001 0        0        0     2        0        13110   \n\
short line 1 2\n\
00000000eeeeeeee 0   1          00000001 0        0        0     2        0        notanum \n";
        let mut t = SocketTable::default();
        t.parse_netlink(text);
        assert_eq!(t.by_inode.len(), 5);
        for (inode, name) in [
            (13110, "ROUTE"), // the first line for an inode is the one kept
            (3880, "INET_DIAG"),
            (13112, "KOBJECT_UEVENT"),
            (13113, "unknown protocol: 17"),
            (13114, "ROUTE"), // `atoi("x7")` is 0
        ] {
            let e = t.get(inode).unwrap();
            assert_eq!(e.file_type, FileType::Socket("netlink"));
            assert_eq!(e.name.as_deref(), Some(name), "{inode}");
            assert_eq!(e.node, inode.to_string());
            assert!(e.device.is_none() && e.info.is_none() && e.type_suffix.is_none());
        }
        // Columns that moved drop the table, as the C's label check does.
        for header in [
            "sk Proto Pid Groups Rmem Wmem Dump Locks Drops Inode\n",
            "sk Eth Pid Groups Rmem Wmem Dump Locks Drops Ino\n",
            "",
        ] {
            let mut t = SocketTable::default();
            t.parse_netlink(&format!("{header}0 0 1 0 0 0 0 2 0 99\n"));
            assert!(t.by_inode.is_empty(), "{header:?}");
        }
        assert_eq!(netlink_name(22), "SMC");
        assert_eq!(netlink_name(23), "unknown protocol: 23");
        assert_eq!(netlink_name(u32::MAX), "unknown protocol: -1");
    }

    #[test]
    fn dash_x_replaces_the_lookup_rather_than_performing_it() {
        // `dsock.c:4155` is an if/else: under -X the C enters the fixed string
        // INSTEAD of calling getxattr. So this must answer without consulting
        // any namespace — a pid that cannot exist still gets the string.
        let x = SockProtoNames::new(true);
        assert_eq!(
            x.unlisted_name(Path::new("/nonexistent/lsof-rs"), 1),
            "can't identify protocol (-X specified)"
        );
        // And without -X the same impossible link is the C's failed
        // `getxattr()`.
        let plain = SockProtoNames::new(false);
        assert_eq!(
            plain.unlisted_name(Path::new("/nonexistent/lsof-rs"), 1),
            "can't identify protocol"
        );
    }

    #[test]
    fn dash_x_gates_the_inet_tables_and_spares_the_rest() {
        // Measured against the C: with -X a TCP row degrades to
        // `sock … can't identify protocol (-X specified)` while `pack`, `unix`
        // and — the asymmetry — IPv4 `raw` keep resolving.
        let t = SocketTable::load(false, true);
        for e in t.by_inode.values() {
            match &e.file_type {
                // `raw` survives, from /proc/net/raw, which -X does not gate
                // (dsock.c:3530 has no guard where :3761 does). `raw6` must
                // not: raw6 IS gated, and tcp/tcp6/udp/udp6/udplite/udplite6
                // are never loaded here.
                FileType::Socket("raw") => {}
                FileType::Socket("raw6") => panic!("-X must gate /proc/net/raw6"),
                FileType::Ipv4 | FileType::Ipv6 => panic!("-X must gate every inet table"),
                FileType::Unix => {}
                // /proc/net/netlink is read whatever -X says (`dsock.c:3590`).
                FileType::Socket("netlink") => {}
                FileType::Other(c) if c == "pack" => {}
                other => panic!("unexpected socket file type under -X: {other:?}"),
            }
        }
    }
}
