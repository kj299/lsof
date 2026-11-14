//! An Internet socket's NAME with host and service names, composed as the
//! C's `printinaddr()` composes it (`print.c`), with the C's caches:
//! `gethostnm()`'s, which keeps every address's answer for the run, and
//! `lkup_port()`'s and `lkup_svcnam()`'s, which keep every service name
//! found and the first ports none was found for, and change how they look
//! after ten lookups (DIVERGENCES 154).
//!
//! The lookups themselves are a [`NameService`]'s: on Linux glibc's rules
//! read off the files and the DNS client (`netnames`, `dns`), in a test a
//! table. A lookup is made only where the C makes one: for a row that is
//! printed, in print order, the local end before the remote, the host before
//! the port, and never again for an address already asked.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::model::{Protocol, SocketInfo};

/// The C's `Namech` is `MAXPATHLEN + 1` bytes, and `printinaddr()` writes
/// into all but one of them: a NAME that does not fit is none at all.
pub const NAME_ROOM: usize = 4096;

/// `PORTTABTHRESH`: how many `getservbyport()` calls the C makes before it
/// reads the whole services database instead.
pub const PORTTABTHRESH: usize = 10;

/// What the C asks the C library for a socket's names.
pub trait NameService {
    /// `gethostbyaddr()`: the host's name, as bytes (a hosts file's may be
    /// any), or `None`.
    fn host_by_addr(&mut self, ip: IpAddr) -> Option<Vec<u8>>;
    /// `getservbyport(htons(port), protocol)`, `protocol` `tcp` or `udp`.
    fn service_by_port(&mut self, port: u16, protocol: &[u8]) -> Option<Vec<u8>>;
    /// A `getservent()` scan, every entry in order, each handed to `each`
    /// (its name, its port, its protocol as written) and not kept: what
    /// the scan keeps is `PortNames::fill`'s, one name a port and
    /// protocol, whatever the database holds.
    fn for_each_service(&mut self, each: &mut crate::netnames::ServiceVisitor<'_>);
}

/// A [`NameService`] that knows no name: every host numeric, every port a
/// number. What a platform without the C's lookups answers.
pub struct NoNames;

impl NameService for NoNames {
    fn host_by_addr(&mut self, _: IpAddr) -> Option<Vec<u8>> {
        None
    }
    fn service_by_port(&mut self, _: u16, _: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn for_each_service(&mut self, _: &mut crate::netnames::ServiceVisitor<'_>) {}
}

/// Text for a name that need not be UTF-8: a byte that is no character is
/// U+FFFD, as everywhere in NAME (DIVERGENCES 93).
fn text(name: &[u8]) -> String {
    String::from_utf8_lossy(name).into_owned()
}

/// The C's `inet_ntop(AF_INET6, …)` (glibc's `inet_ntop6()`): the longest
/// run of two zero words or more, the first of equal ones, as `::`, and an
/// address whose first six words are zero (but `::` and `::1`), or whose
/// first five are and sixth is `ffff`, with its last 32 bits as an IPv4
/// address. Rust's `Display` writes `::1.2.3.4` as `::102:304`.
pub fn inet_ntop6(addr: &Ipv6Addr) -> String {
    let words = addr.segments();
    let (mut best_base, mut best_len) = (None::<usize>, 0usize);
    let (mut cur_base, mut cur_len) = (None::<usize>, 0usize);
    for (i, &w) in words.iter().enumerate() {
        if w == 0 {
            if cur_base.is_none() {
                cur_base = Some(i);
                cur_len = 1;
            } else {
                cur_len = cur_len.saturating_add(1);
            }
        } else if let Some(base) = cur_base.take() {
            if best_base.is_none() || cur_len > best_len {
                best_base = Some(base);
                best_len = cur_len;
            }
        }
    }
    if let Some(base) = cur_base {
        if best_base.is_none() || cur_len > best_len {
            best_base = Some(base);
            best_len = cur_len;
        }
    }
    if best_len < 2 {
        best_base = None;
    }
    let mut out = String::with_capacity(41);
    let mut i = 0usize;
    while i < words.len() {
        if let Some(base) = best_base {
            if i >= base && i < base.saturating_add(best_len) {
                if i == base {
                    out.push(':');
                }
                i = i.saturating_add(1);
                continue;
            }
        }
        if i != 0 {
            out.push(':');
        }
        let embedded = i == 6
            && best_base == Some(0)
            && (best_len == 6 || (best_len == 5 && words.get(5) == Some(&0xffff)));
        if embedded {
            let o = addr.octets();
            if let Some(v4) = o.get(12..16).and_then(|b| <[u8; 4]>::try_from(b).ok()) {
                out.push_str(&Ipv4Addr::from(v4).to_string());
            }
            return out;
        }
        out.push_str(&format!("{:x}", words.get(i).copied().unwrap_or(0)));
        i = i.saturating_add(1);
    }
    if best_base.is_some_and(|base| base.saturating_add(best_len) == words.len()) {
        out.push(':');
    }
    out
}

/// The C's numeric host (`gethostnm()` with no name): dotted for IPv4,
/// `inet_ntop()` in brackets for IPv6.
pub fn numeric_host(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{}]", inet_ntop6(&v6)),
    }
}

/// The two ends the C records for a socket (`dsock.c:3895-3911`,
/// `ent_inaddr()`): an end whose address is unspecified and whose port is 0
/// is none; and where either end is an IPv4-mapped IPv6 address, both are
/// read as IPv4, the last four bytes of each.
pub fn c_ends(info: &SocketInfo) -> [Option<SocketAddr>; 2] {
    let end = |a: Option<SocketAddr>| a.filter(|a| !(a.ip().is_unspecified() && a.port() == 0));
    let (local, remote) = (end(info.local), end(info.remote));
    let mapped = |a: &Option<SocketAddr>| matches!(a, Some(SocketAddr::V6(v6)) if v6.ip().to_ipv4_mapped().is_some());
    if !(mapped(&local) || mapped(&remote)) {
        return [local, remote];
    }
    let to_v4 = |a: Option<SocketAddr>| {
        a.map(|a| match a {
            SocketAddr::V6(v6) => {
                let o = v6.ip().octets();
                let v4 = [o[12], o[13], o[14], o[15]];
                SocketAddr::new(IpAddr::V4(Ipv4Addr::from(v4)), v6.port())
            }
            v4 => v4,
        })
    };
    [to_v4(local), to_v4(remote)]
}

/// `lkup_port()`'s and `lkup_svcnam()`'s state: the names found, kept by
/// protocol; the ports looked up and not found, by port alone (so a port
/// TCP has no name for has none for UDP either until the scan: measured,
/// `x 7001/udp` and a TCP socket on 7001 listed first leave the UDP one
/// `7001`); how many `getservbyport()` calls were made; whether the whole
/// database was read.
#[derive(Debug, Default)]
struct PortNames {
    named: [HashMap<u16, Vec<u8>>; 2],
    failed: Vec<u16>,
    calls: usize,
    filled: bool,
}

impl PortNames {
    /// The name the C prints for `port` (non-zero) of `proto` (0 TCP, 1
    /// UDP), if any.
    fn lookup(&mut self, port: u16, proto: usize, ns: &mut dyn NameService) -> Option<Vec<u8>> {
        if let Some(name) = self.named.get(proto).and_then(|m| m.get(&port)) {
            return Some(name.clone());
        }
        let found = if self.filled {
            None
        } else if self.calls < PORTTABTHRESH {
            if self.failed.contains(&port) {
                None
            } else {
                self.calls = self.calls.saturating_add(1);
                let protocol: &[u8] = if proto == 0 { b"tcp" } else { b"udp" };
                let found = ns.service_by_port(port, protocol);
                if found.is_none() && self.failed.len() < PORTTABTHRESH {
                    self.failed.push(port);
                }
                found
            }
        } else {
            self.fill(ns);
            self.named.get(proto).and_then(|m| m.get(&port)).cloned()
        };
        let found = found.filter(|name| !name.is_empty())?;
        if let Some(m) = self.named.get_mut(proto) {
            m.entry(port).or_insert_with(|| found.clone());
        }
        Some(found)
    }

    /// `fill_porttab()`: every entry of the database whose protocol is TCP
    /// or UDP in any case and whose name is not empty, the first for each
    /// port kept, alongside what was found already.
    ///
    /// Each entry is taken as the scan reads it, as the C's `getservent()`
    /// loop takes it, so what is kept is at most one name a port and
    /// protocol whatever the file's size (2 x 65,536 names of at most 4,097
    /// bytes).
    fn fill(&mut self, ns: &mut dyn NameService) {
        self.filled = true;
        let named = &mut self.named;
        ns.for_each_service(&mut |name, port, protocol| {
            let proto = if protocol.eq_ignore_ascii_case(b"tcp") {
                0
            } else if protocol.eq_ignore_ascii_case(b"udp") {
                1
            } else {
                return;
            };
            if name.is_empty() {
                return;
            }
            if let Some(m) = named.get_mut(proto) {
                m.entry(port).or_insert_with(|| name.to_vec());
            }
        });
    }
}

/// The names of a run's sockets: the C's caches and its `-n`/`-P` state,
/// kept from the first row printed to the last cycle of `-r`.
#[derive(Debug)]
pub struct SocketNames {
    /// `Fhost`: host names (`+n`, the default), or numbers (`-n`).
    pub hosts: bool,
    /// `Fport`: service names (`+P`, the default), or numbers (`-P`).
    pub ports: bool,
    host_cache: HashMap<IpAddr, Vec<u8>>,
    port_names: PortNames,
}

impl SocketNames {
    pub fn new(hosts: bool, ports: bool) -> Self {
        SocketNames {
            hosts,
            ports,
            host_cache: HashMap::new(),
            port_names: PortNames::default(),
        }
    }

    /// `gethostnm()`: the name kept for `ip`, or the one looked up now, or
    /// the number; looked up only under `+n`, and kept either way.
    fn host(&mut self, ip: IpAddr, ns: &mut dyn NameService) -> Vec<u8> {
        if let Some(name) = self.host_cache.get(&ip) {
            return name.clone();
        }
        let name = self
            .hosts
            .then(|| ns.host_by_addr(ip))
            .flatten()
            .unwrap_or_else(|| numeric_host(ip).into_bytes());
        self.host_cache.insert(ip, name.clone());
        name
    }

    /// The port as `printinaddr()` writes it: `*` for 0; under `+P` the
    /// service name of a TCP or UDP port ([`PortNames`]); else the number.
    fn port(&mut self, port: u16, protocol: Protocol, ns: &mut dyn NameService) -> Vec<u8> {
        if port == 0 {
            return b"*".to_vec();
        }
        let proto = match protocol {
            Protocol::Tcp => Some(0),
            Protocol::Udp => Some(1),
            _ => None,
        };
        self.ports
            .then_some(proto)
            .flatten()
            .and_then(|proto| self.port_names.lookup(port, proto, ns))
            .unwrap_or_else(|| port.to_string().into_bytes())
    }

    /// The socket's NAME as `printinaddr()` composes it: each end the C
    /// records ([`c_ends`]) as `host:port`, `*` for an unspecified host, the
    /// remote after `->`; each part looked up as it is reached. Where the
    /// whole would not fit the C's buffer ([`NAME_ROOM`]), the C prints
    /// nothing for it, and nor does this; its sums are the C's, `nl -= len
    /// - 1` after a port included.
    pub fn name(&mut self, info: &SocketInfo, ns: &mut dyn NameService) -> String {
        let mut out: Vec<u8> = Vec::new();
        let mut room = i64::try_from(NAME_ROOM).unwrap_or(i64::MAX);
        let len = |b: &[u8]| i64::try_from(b.len()).unwrap_or(i64::MAX);
        for (i, end) in c_ends(info).into_iter().enumerate() {
            let Some(end) = end else {
                continue;
            };
            if i == 1 {
                if room < 2 {
                    return String::new();
                }
                out.extend_from_slice(b"->");
                room = room.saturating_sub(2);
            }
            let host = if end.ip().is_unspecified() {
                b"*".to_vec()
            } else {
                self.host(end.ip(), ns)
            };
            let port = self.port(end.port(), info.protocol, ns);
            if len(&host) > room {
                return String::new();
            }
            out.extend_from_slice(&host);
            room = room.saturating_sub(len(&host));
            if len(&port).saturating_add(1) >= room {
                return String::new();
            }
            out.push(b':');
            out.extend_from_slice(&port);
            room = room.saturating_sub(len(&port).saturating_sub(1));
        }
        text(&out)
    }

    /// The NAME with every lookup off (`-n -P`): what the backend wrote
    /// before names were looked up, which a row's name is compared with to
    /// tell it is this composition and nothing else.
    pub fn numeric(info: &SocketInfo) -> String {
        SocketNames::new(false, false).name(info, &mut NoNames)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{SockState, TcpState};
    use crate::netnames::ServiceEntry;

    /// A name service out of tables, counting its calls.
    #[derive(Default)]
    struct Table {
        hosts: Vec<(IpAddr, String)>,
        services: Vec<ServiceEntry>,
        host_calls: Vec<IpAddr>,
        port_calls: Vec<(u16, Vec<u8>)>,
        scans: usize,
    }

    impl NameService for Table {
        fn host_by_addr(&mut self, ip: IpAddr) -> Option<Vec<u8>> {
            self.host_calls.push(ip);
            self.hosts
                .iter()
                .find(|(a, _)| *a == ip)
                .map(|(_, n)| n.as_bytes().to_vec())
        }
        fn service_by_port(&mut self, port: u16, protocol: &[u8]) -> Option<Vec<u8>> {
            self.port_calls.push((port, protocol.to_vec()));
            self.services
                .iter()
                .find(|e| e.port == port && e.protocol == protocol)
                .map(|e| e.name.clone())
        }
        fn for_each_service(&mut self, each: &mut crate::netnames::ServiceVisitor<'_>) {
            self.scans += 1;
            for e in &self.services {
                each(&e.name, e.port, &e.protocol);
            }
        }
    }

    fn svc(name: &str, port: u16, proto: &str) -> ServiceEntry {
        ServiceEntry {
            name: name.into(),
            port,
            protocol: proto.into(),
        }
    }

    fn sock(proto: Protocol, local: &str, remote: Option<&str>) -> SocketInfo {
        SocketInfo {
            protocol: proto,
            local: Some(local.parse().unwrap()),
            remote: remote.map(|r| r.parse().unwrap()),
            state: Some(SockState::Tcp(TcpState::Listen)),
            tcp: None,
            bound: None,
        }
    }

    #[test]
    fn hosts_and_ports_are_named_as_the_c_names_them() {
        let mut t = Table {
            hosts: vec![
                ("127.0.0.1".parse().unwrap(), "localhost".to_string()),
                ("127.0.0.7".parse().unwrap(), String::new()),
            ],
            services: vec![
                svc("svcboth", 4001, "tcp"),
                svc("svcboth", 4001, "udp"),
                svc("udponly", 4003, "udp"),
            ],
            ..Table::default()
        };
        let mut n = SocketNames::new(true, true);
        assert_eq!(
            n.name(&sock(Protocol::Tcp, "127.0.0.1:4001", None), &mut t),
            "localhost:svcboth"
        );
        assert_eq!(
            n.name(&sock(Protocol::Udp, "0.0.0.0:4003", None), &mut t),
            "*:udponly"
        );
        // An empty name is no host at all (measured `:4006`).
        assert_eq!(
            n.name(&sock(Protocol::Tcp, "127.0.0.7:4006", None), &mut t),
            ":4006"
        );
        assert_eq!(
            n.name(
                &sock(Protocol::Udp, "127.0.0.1:4001", Some("127.0.0.3:4002")),
                &mut t
            ),
            "localhost:svcboth->127.0.0.3:4002"
        );
        // UDP-Lite has no service names; port 0 is `*`.
        assert_eq!(
            n.name(&sock(Protocol::UdpLite, "127.0.0.1:4003", None), &mut t),
            "localhost:4003"
        );
        assert_eq!(
            n.name(&sock(Protocol::Udp, "127.0.0.1:0", None), &mut t),
            "localhost:*"
        );
        // Each address asked once, whatever the rows.
        let hosts: Vec<String> = t.host_calls.iter().map(|h| h.to_string()).collect();
        assert_eq!(hosts, ["127.0.0.1", "127.0.0.7", "127.0.0.3"]);
        // `-n`, `-P`: nothing asked.
        let mut t = Table::default();
        let mut n = SocketNames::new(false, false);
        assert_eq!(
            n.name(
                &sock(Protocol::Tcp, "127.0.0.1:4001", Some("10.0.0.1:80")),
                &mut t
            ),
            "127.0.0.1:4001->10.0.0.1:80"
        );
        assert!(t.host_calls.is_empty() && t.port_calls.is_empty());
    }

    #[test]
    fn the_failure_list_and_the_scan_are_the_cs() {
        // Measured: TCP 7001 has no name, so UDP 7001 is a number although
        // the file names it for UDP; after ten calls the scan finds it, and
        // it compares protocols in any case.
        let mut t = Table {
            services: vec![
                svc("x", 7001, "udp"),
                svc("late", 7011, "tcp"),
                svc("upper", 7012, "TCP"),
                svc("first", 7013, "tcp"),
                svc("second", 7013, "tcp"),
            ],
            ..Table::default()
        };
        let mut n = SocketNames::new(false, true);
        let port = |n: &mut SocketNames, t: &mut Table, proto, p: u16| {
            n.name(&sock(proto, &format!("127.0.0.1:{p}"), None), t)
        };
        assert_eq!(port(&mut n, &mut t, Protocol::Tcp, 7001), "127.0.0.1:7001");
        assert_eq!(port(&mut n, &mut t, Protocol::Udp, 7001), "127.0.0.1:7001");
        for p in 7002..7011 {
            assert_eq!(
                port(&mut n, &mut t, Protocol::Tcp, p),
                format!("127.0.0.1:{p}")
            );
        }
        assert_eq!(t.port_calls.len(), 10);
        assert_eq!(t.scans, 0);
        // The 11th lookup: no call, the scan.
        assert_eq!(port(&mut n, &mut t, Protocol::Tcp, 7011), "127.0.0.1:late");
        assert_eq!((t.port_calls.len(), t.scans), (10, 1));
        assert_eq!(port(&mut n, &mut t, Protocol::Udp, 7001), "127.0.0.1:x");
        assert_eq!(port(&mut n, &mut t, Protocol::Tcp, 7012), "127.0.0.1:upper");
        // The scan keeps a port's first entry (`fill_porttab()`).
        assert_eq!(port(&mut n, &mut t, Protocol::Tcp, 7013), "127.0.0.1:first");
        assert_eq!(port(&mut n, &mut t, Protocol::Tcp, 9999), "127.0.0.1:9999");
        assert_eq!(t.scans, 1);
        // Measured the other way round: UDP first finds it.
        let mut t = Table {
            services: vec![svc("x", 7001, "udp")],
            ..Table::default()
        };
        let mut n = SocketNames::new(false, true);
        assert_eq!(port(&mut n, &mut t, Protocol::Udp, 7001), "127.0.0.1:x");
        assert_eq!(port(&mut n, &mut t, Protocol::Tcp, 7001), "127.0.0.1:7001");
    }

    #[test]
    fn a_name_past_the_cs_buffer_is_no_name() {
        let long = "h".repeat(4200);
        let edge = "e".repeat(NAME_ROOM - 4);
        let mut t = Table {
            hosts: vec![
                ("127.0.0.250".parse().unwrap(), long),
                ("127.0.0.251".parse().unwrap(), edge),
            ],
            ..Table::default()
        };
        let mut n = SocketNames::new(true, false);
        assert_eq!(
            n.name(
                &sock(Protocol::Udp, "127.0.0.1:5000", Some("127.0.0.250:9")),
                &mut t
            ),
            ""
        );
        // host (4092) + ":" + "9": `1 + 1 >= 4096 - 4092` is false: fits.
        let fits = n.name(&sock(Protocol::Udp, "127.0.0.251:9", None), &mut t);
        assert_eq!(fits.len(), NAME_ROOM - 2);
        let mut n = SocketNames::new(true, false);
        let over = n.name(&sock(Protocol::Udp, "127.0.0.251:999", None), &mut t);
        assert_eq!(over, "");
    }

    #[test]
    fn ends_are_the_cs() {
        let s = sock(
            Protocol::Tcp,
            "[::ffff:127.0.0.1]:80",
            Some("[::ffff:10.0.0.2]:9"),
        );
        let [l, r] = c_ends(&s);
        assert_eq!(
            (l.unwrap().to_string(), r.unwrap().to_string()),
            ("127.0.0.1:80".into(), "10.0.0.2:9".into())
        );
        // Either end mapped makes both IPv4.
        let s = sock(Protocol::Tcp, "[::ffff:127.0.0.1]:80", Some("[::1]:9"));
        assert_eq!(c_ends(&s)[1].unwrap().to_string(), "0.0.0.1:9");
        // An unspecified address with port 0 is no end.
        let s = sock(Protocol::Tcp, "0.0.0.0:0", Some("0.0.0.0:0"));
        assert_eq!(c_ends(&s), [None, None]);
        let s = sock(Protocol::Tcp, "[::]:22", None);
        assert_eq!(SocketNames::numeric(&s), "*:22");
        let s = sock(Protocol::Tcp, "[::1]:22", Some("[fe80::1]:5"));
        assert_eq!(SocketNames::numeric(&s), "[::1]:22->[fe80::1]:5");
    }

    #[test]
    fn inet_ntop6_is_glibcs() {
        let t = |s: &str| inet_ntop6(&s.parse().unwrap());
        assert_eq!(t("::"), "::");
        assert_eq!(t("::1"), "::1");
        assert_eq!(t("::1.2.3.4"), "::1.2.3.4");
        assert_eq!(t("::ffff:1.2.3.4"), "::ffff:1.2.3.4");
        assert_eq!(t("1:0:0:2:0:0:0:3"), "1:0:0:2::3");
        assert_eq!(t("1:0:0:2:0:0:3:4"), "1::2:0:0:3:4");
        assert_eq!(t("2001:db8::"), "2001:db8::");
        assert_eq!(t("2001:db8:0:1:1:1:1:1"), "2001:db8:0:1:1:1:1:1");
        assert_eq!(t("fe80::1"), "fe80::1");
        assert_eq!(t("::ffff:0:1.2.3.4"), "::ffff:0:102:304");
    }

    /// The scan keeps one name a port and protocol as it reads, whatever
    /// the database holds, as the C's `fill_porttab()` does over
    /// `getservent()`: a million entries that name nothing kept (an empty
    /// protocol, which glibc accepts), and one that does.
    #[test]
    fn the_scan_keeps_only_what_it_names() {
        struct Many {
            entries: usize,
        }
        impl NameService for Many {
            fn host_by_addr(&mut self, _: IpAddr) -> Option<Vec<u8>> {
                None
            }
            fn service_by_port(&mut self, _: u16, _: &[u8]) -> Option<Vec<u8>> {
                None
            }
            fn for_each_service(&mut self, each: &mut crate::netnames::ServiceVisitor<'_>) {
                for i in 0..self.entries {
                    each(b"a", (i % 65_536) as u16, b"");
                }
                each(b"x", 7, b"TCP");
                each(b"y", 7, b"tcp");
            }
        }
        let entries = if cfg!(miri) { 1_000 } else { 1_000_000 };
        let mut ports = PortNames::default();
        ports.fill(&mut Many { entries });
        assert_eq!(ports.named[0].len(), 1);
        assert_eq!(ports.named[0].get(&7).map(Vec::as_slice), Some(&b"x"[..]));
        assert!(ports.named[1].is_empty());
    }
}
