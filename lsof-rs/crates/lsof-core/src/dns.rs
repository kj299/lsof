//! Reverse DNS for a socket's NAME: the PTR query glibc 2.39's stub resolver
//! makes for the C's `gethostbyaddr(3)` (`print.c`, `gethostnm()`), in safe
//! Rust and bounded.
//!
//! `std` has no reverse lookup, and the three `forbid(unsafe_code)` crates
//! cannot call `getnameinfo(3)`, so this module does what glibc's `dns`
//! source does for one address: it reads `/etc/resolv.conf` and
//! `RES_OPTIONS` as `res_init()` reads them ([`ResolvConf`]), builds the query
//! `res_nmkquery()` builds ([`ptr_query`]), asks each name server in turn as
//! `__res_context_send()` asks it ([`query_ptr`], over a [`Transport`] the
//! backend makes of `std::net`), takes a reply only where `send_dg()` takes
//! it ([`udp_verdict`]), and reads the name out of it as `getanswer_ptr()`
//! does ([`answer_name`]). Every rule was measured against the C in a network
//! namespace of its own whose only name servers were the measurement's
//! (DIVERGENCES 154).
//!
//! A reply is bytes from the network, chosen by whoever answers: everything
//! here that reads one is a parser over a slice that never panics, never
//! recurses, never allocates more than the reply's size, and never loops
//! longer than the reply is long. A compression pointer may point anywhere in
//! the message, so the name reader counts what it has read, as glibc's
//! `ns_name_unpack()` does, and gives up past the message's length.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;

use crate::netnames::NssAnswer;

/// `MAXNS`: the name servers glibc asks, the first three it can read.
pub const MAXNS: usize = 3;
/// `RES_TIMEOUT`: `timeout` where `resolv.conf` sets none, seconds.
pub const RES_TIMEOUT: i64 = 5;
/// `RES_MAXRETRANS`: the most `timeout:` may set.
pub const RES_MAXRETRANS: i64 = 30;
/// `RES_DFLRETRY`: `attempts` where `resolv.conf` sets none.
pub const RES_DFLRETRY: i64 = 2;
/// `RES_MAXRETRY`: the most `attempts:` may set.
pub const RES_MAXRETRY: i64 = 5;
/// The longest message read, over UDP or TCP: glibc's `MAXPACKET` buffer
/// holds 65,536 bytes, and a TCP message's length is 16 bits.
pub const MAX_MESSAGE: usize = 65_535;
/// The longest host name glibc gives back, in text: its PTR reader writes
/// the name into `char hname[MAXHOSTNAMELEN + 1]`, where the resolver's
/// own `MAXHOSTNAMELEN` is 256 (measured: a name of 256 characters, its
/// escapes counted, is the host's; one of 257 is no name).
pub const MAX_NAME_TEXT: usize = 256;
/// `NS_MAXCDNAME`: the longest name in wire form, its last zero counted.
pub const MAX_WIRE_NAME: usize = 255;
/// The most of `/etc/resolv.conf` that is read: far more than any holds.
pub const RESOLV_CONF_LIMIT: u64 = 1 << 20;
/// The most TCP messages read in one exchange before the server is given
/// up on: glibc reads on while the id does not match, which a server that
/// sends nothing but strangers' replies could make it do until its time is
/// up; here it is that, or this many, whichever comes first.
pub const MAX_TCP_MESSAGES: usize = 64;

const T_PTR: u16 = 12;
const T_CNAME: u16 = 5;
const C_IN: u16 = 1;
const NOERROR: u8 = 0;
const SERVFAIL: u8 = 2;
const NOTIMP: u8 = 4;
const REFUSED: u8 = 5;
/// The header's length, `HFIXEDSZ`.
const HEADER: usize = 12;

/// What glibc's `res_init()` makes of `/etc/resolv.conf` and `RES_OPTIONS`,
/// as far as a PTR query reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvConf {
    /// The name servers, at most [`MAXNS`], in the file's order; 127.0.0.1
    /// where the file names none it can read.
    pub servers: Vec<SocketAddr>,
    /// `timeout:` (`retrans`): as `atoi()` read it, at most 30; zero and
    /// below wait the one second glibc's floor gives.
    pub retrans: i64,
    /// `attempts:` (`retry`), at most 5: zero or below asks no server at all.
    pub retry: i64,
    /// `rotate`: start each query at the next server.
    pub rotate: bool,
    /// `use-vc`: TCP from the start.
    pub use_vc: bool,
    /// `edns0`: an OPT record in the query.
    pub edns0: bool,
    /// `trust-ad`: the AD bit in the query.
    pub trust_ad: bool,
}

impl Default for ResolvConf {
    fn default() -> Self {
        ResolvConf {
            servers: Vec::new(),
            retrans: RES_TIMEOUT,
            retry: RES_DFLRETRY,
            rotate: false,
            use_vc: false,
            edns0: false,
            trust_ad: false,
        }
    }
}

/// `atoi()`: blanks, a sign, digits, as `strtol()` reads them into a `long`
/// (saturating), then kept to an `int` as the cast keeps it.
fn atoi(s: &[u8]) -> i64 {
    let mut i = s
        .iter()
        .take_while(|&&b| matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r'))
        .count();
    let negative = match s.get(i) {
        Some(b'-') => {
            i = i.saturating_add(1);
            true
        }
        Some(b'+') => {
            i = i.saturating_add(1);
            false
        }
        _ => false,
    };
    let mut value: i64 = 0;
    for &b in s.get(i..).unwrap_or_default() {
        if !b.is_ascii_digit() {
            break;
        }
        let d = i64::from(b - b'0');
        value = if negative {
            value.saturating_mul(10).saturating_sub(d)
        } else {
            value.saturating_mul(10).saturating_add(d)
        };
    }
    // `(int) strtol(…)`: the low 32 bits, as a signed number.
    i64::from(value as i32)
}

/// The options `res_setoptions()` knows past `ndots:`, `timeout:` and
/// `attempts:`, each matched as a prefix of the word, as glibc matches it.
const FLAGS: [&[u8]; 10] = [
    b"rotate",
    b"edns0",
    b"single-request-reopen",
    b"single-request",
    b"no_tld_query",
    b"no-tld-query",
    b"no-reload",
    b"use-vc",
    b"trust-ad",
    b"no-aaaa",
];

impl ResolvConf {
    /// `res_setoptions()`: the words of an `options` line, or of
    /// `RES_OPTIONS`.
    fn options(&mut self, text: &[u8]) {
        let text = text.split(|&b| b == 0).next().unwrap_or_default();
        let mut rest = text;
        while !rest.is_empty() {
            let skip = rest
                .iter()
                .take_while(|&&b| b == b' ' || b == b'\t')
                .count();
            rest = rest.get(skip..).unwrap_or_default();
            if let Some(v) = rest.strip_prefix(b"timeout:") {
                self.retrans = atoi(v).min(RES_MAXRETRANS);
            } else if let Some(v) = rest.strip_prefix(b"attempts:") {
                self.retry = atoi(v).min(RES_MAXRETRY);
            } else if rest.starts_with(b"ndots:") {
                // Search domains are never asked for a PTR name.
            } else if let Some(flag) = FLAGS.iter().find(|f| rest.starts_with(f)) {
                match *flag {
                    b"rotate" => self.rotate = true,
                    b"use-vc" => self.use_vc = true,
                    b"edns0" => self.edns0 = true,
                    b"trust-ad" => self.trust_ad = true,
                    _ => {}
                }
            }
            let word = rest
                .iter()
                .take_while(|&&b| b != b' ' && b != b'\t')
                .count();
            rest = rest.get(word..).unwrap_or_default();
        }
    }

    /// A `nameserver` line's address (`res_vinit_1()`): the word after the
    /// keyword, up to a blank or the line's end; an IPv4 address in any form
    /// `inet_aton()` reads (`127.1`), or an IPv6 one with an optional
    /// `%scope`, which `scope_index` turns into an index where it names an
    /// interface (a link-local address) and which may be a number. A word
    /// that is neither is no server, and does not count towards [`MAXNS`].
    fn nameserver(word: &[u8], scope_index: &dyn Fn(&[u8]) -> Option<u32>) -> Option<SocketAddr> {
        if word.is_empty() {
            return None;
        }
        if let Some(v4) = crate::netnames::inet_aton(word, true) {
            return Some(SocketAddr::V4(SocketAddrV4::new(v4, 53)));
        }
        let (addr, scope) = match word.iter().position(|&b| b == b'%') {
            Some(at) => (word.get(..at)?, word.get(at.saturating_add(1)..)),
            None => (word, None),
        };
        let v6: std::net::Ipv6Addr = std::str::from_utf8(addr).ok()?.parse().ok()?;
        let mut scope_id = 0;
        if let Some(scope) = scope {
            let link_local = v6.segments().first().is_some_and(|&s| s & 0xffc0 == 0xfe80)
                || v6.octets().first() == Some(&0xff)
                    && v6
                        .octets()
                        .get(1)
                        .is_some_and(|&b| b & 0x0f == 1 || b & 0x0f == 2);
            let named = link_local.then(|| scope_index(scope)).flatten();
            scope_id = named
                .or_else(|| {
                    if !scope.first().is_some_and(u8::is_ascii_digit) {
                        return None;
                    }
                    std::str::from_utf8(scope).ok()?.parse::<u32>().ok()
                })
                .unwrap_or(0);
        }
        Some(SocketAddr::V6(SocketAddrV6::new(v6, 53, 0, scope_id)))
    }

    /// `/etc/resolv.conf`'s bytes (`file`, `None` where it cannot be read)
    /// and `RES_OPTIONS` (`env`), as glibc 2.39 reads them:
    ///
    /// * a line is read to its `\n` (the last one, with none, too), and to
    ///   a NUL; one that opens with `;` or `#` is a comment;
    /// * a keyword counts only at the line's start and followed by a blank:
    ///   ` nameserver x` is no server (measured);
    /// * `nameserver`: see [`ResolvConf::nameserver`]; past the third it is
    ///   not read;
    /// * `options`: `timeout:N` (at most 30), `attempts:N` (at most 5),
    ///   `rotate`, `use-vc`, `edns0`, `trust-ad`, each a prefix of its word,
    ///   every line read in turn, the last value winning;
    /// * with no server, 127.0.0.1;
    /// * then `RES_OPTIONS`, read as an `options` line, after the file.
    pub fn parse(
        file: Option<&[u8]>,
        env: Option<&[u8]>,
        scope_index: &dyn Fn(&[u8]) -> Option<u32>,
    ) -> ResolvConf {
        let mut conf = ResolvConf::default();
        let keyword = |line: &[u8], word: &[u8]| -> Option<usize> {
            (line.starts_with(word) && matches!(line.get(word.len()), Some(b' ') | Some(b'\t')))
                .then_some(word.len())
        };
        for line in file.unwrap_or_default().split(|&b| b == b'\n') {
            let line = line.split(|&b| b == 0).next().unwrap_or_default();
            if matches!(line.first(), Some(b';') | Some(b'#')) {
                continue;
            }
            if let Some(at) = keyword(line, b"nameserver") {
                if conf.servers.len() >= MAXNS {
                    continue;
                }
                let rest = line.get(at..).unwrap_or_default();
                let skip = rest
                    .iter()
                    .take_while(|&&b| b == b' ' || b == b'\t')
                    .count();
                let rest = rest.get(skip..).unwrap_or_default();
                let end = rest
                    .iter()
                    .position(|&b| matches!(b, b' ' | b'\t' | b'\n'))
                    .unwrap_or(rest.len());
                if let Some(server) =
                    Self::nameserver(rest.get(..end).unwrap_or_default(), scope_index)
                {
                    conf.servers.push(server);
                }
            } else if let Some(at) = keyword(line, b"options") {
                conf.options(line.get(at..).unwrap_or_default());
            }
        }
        if conf.servers.is_empty() {
            conf.servers
                .push(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53)));
        }
        if let Some(env) = env {
            conf.options(env);
        }
        conf
    }

    /// How long server `ns` (its index in [`ResolvConf::servers`]) is
    /// waited for in one attempt (`send_dg()`): `timeout << ns`, divided by
    /// the servers' count but for the first, and one second at least
    /// (measured: three servers at `timeout:2` wait 2, 1 and 2 seconds).
    pub fn wait(&self, ns: usize) -> Duration {
        let count = i64::try_from(self.servers.len()).unwrap_or(1).max(1);
        let shift = u32::try_from(ns).unwrap_or(u32::MAX).min(8);
        let mut seconds = self.retrans.checked_shl(shift).unwrap_or(i64::MAX);
        if ns > 0 {
            seconds /= count;
        }
        Duration::from_secs(u64::try_from(seconds.max(1)).unwrap_or(1))
    }

    /// The longest one query can take: every attempt of every server, each
    /// waited for its [`ResolvConf::wait`] (and the TCP exchange a truncated
    /// reply leads to within it). The C's own worst case, which it has no
    /// bound past: 450 s at `timeout:30 attempts:5` with three servers.
    pub fn worst_case(&self) -> Duration {
        let round: Duration = (0..self.servers.len()).map(|ns| self.wait(ns)).sum();
        round
            .checked_mul(u32::try_from(self.retry.max(0)).unwrap_or(0))
            .unwrap_or(Duration::MAX)
    }
}

/// Where `rotate` starts each query: glibc picks a random server for the
/// run's first and the next one for each after it (`nameserver_offset()`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rotation(Option<usize>);

impl Rotation {
    fn next(&mut self, conf: &ResolvConf, random: u16) -> usize {
        let count = conf.servers.len();
        if !conf.rotate || count <= 1 {
            return 0;
        }
        let at = self.0.unwrap_or(usize::from(random));
        self.0 = Some(at.wrapping_add(1));
        at % count
    }
}

/// The address the query names, as `_nss_dns_gethostbyaddr2_r()` takes it:
/// an IPv4-mapped IPv6 address, and an IPv4-compatible one other than `::1`
/// and `::`, as the IPv4 address inside.
fn query_address(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            let o = v6.octets();
            let head = o.get(..12).unwrap_or_default();
            let tail = o.get(12..).unwrap_or_default();
            let mapped = head.get(..10).is_some_and(|z| z.iter().all(|&b| b == 0))
                && head.get(10..) == Some(&[0xff, 0xff][..]);
            let compat =
                head.iter().all(|&b| b == 0) && tail != [0, 0, 0, 1] && tail != [0, 0, 0, 0];
            match <[u8; 4]>::try_from(tail) {
                Ok(v4) if mapped || compat => IpAddr::V4(Ipv4Addr::from(v4)),
                _ => ip,
            }
        }
        IpAddr::V4(_) => ip,
    }
}

/// The PTR name for `ip`, in wire form: `d.c.b.a.in-addr.arpa.`, or the 32
/// nibbles of an IPv6 address, lowest first, under `ip6.arpa.`.
pub fn ptr_name(ip: IpAddr) -> Vec<u8> {
    let mut labels: Vec<Vec<u8>> = Vec::new();
    match query_address(ip) {
        IpAddr::V4(v4) => {
            for b in v4.octets().iter().rev() {
                labels.push(b.to_string().into_bytes());
            }
            labels.push(b"in-addr".to_vec());
        }
        IpAddr::V6(v6) => {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            for b in v6.octets().iter().rev() {
                labels.push(vec![HEX[usize::from(b & 0xf)]]);
                labels.push(vec![HEX[usize::from(b >> 4)]]);
            }
            labels.push(b"ip6".to_vec());
        }
    }
    labels.push(b"arpa".to_vec());
    let mut wire = Vec::with_capacity(80);
    for label in labels {
        wire.push(u8::try_from(label.len()).unwrap_or(0));
        wire.extend_from_slice(&label);
    }
    wire.push(0);
    wire
}

/// The query `res_nmkquery()` makes for `ip`'s PTR name: id `id`, one
/// question, recursion desired, the AD bit under `trust-ad` and an OPT
/// record under `edns0` (its UDP size 1200, as glibc's `__res_nopt()`
/// gives it for a reply buffer larger than that).
pub fn ptr_query(id: u16, ip: IpAddr, conf: &ResolvConf) -> Vec<u8> {
    let name = ptr_name(ip);
    let mut q = Vec::with_capacity(HEADER + name.len() + 4 + 11);
    q.extend_from_slice(&id.to_be_bytes());
    q.push(0x01); // RD
    q.push(if conf.trust_ad { 0x20 } else { 0 });
    q.extend_from_slice(&[0, 1, 0, 0, 0, 0]);
    q.extend_from_slice(&[0, u8::from(conf.edns0)]);
    q.extend_from_slice(&name);
    q.extend_from_slice(&T_PTR.to_be_bytes());
    q.extend_from_slice(&C_IN.to_be_bytes());
    if conf.edns0 {
        q.extend_from_slice(&[0, 0, 41, 0x04, 0xb0, 0, 0, 0, 0, 0, 0]);
    }
    q
}

/// A 16-bit big-endian field at `at`.
fn be16(msg: &[u8], at: usize) -> Option<u16> {
    let bytes = msg.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([*bytes.first()?, *bytes.get(1)?]))
}

/// `ns_name_unpack()`: the name at `at` in `msg`, its compression pointers
/// followed, in wire form (at most [`MAX_WIRE_NAME`] bytes, its last zero
/// counted), and how many bytes it took at `at`. `None` for what glibc
/// refuses: a label that runs past the message or past 255 bytes, a pointer
/// past the message, a label type other than a length or a pointer, or more
/// bytes read than the message has, which is how glibc finds a pointer loop
/// (`checked`).
pub fn unpack_name(msg: &[u8], at: usize) -> Option<(Vec<u8>, usize)> {
    if at >= msg.len() {
        return None;
    }
    let mut out = Vec::with_capacity(64);
    let mut src = at;
    let mut used: Option<usize> = None;
    let mut checked = 0usize;
    loop {
        let n = *msg.get(src)?;
        src = src.checked_add(1)?;
        if n == 0 {
            break;
        }
        match n & 0xc0 {
            0 => {
                let len = usize::from(n);
                // The label, its length byte, and the zero that ends the
                // name, within 255 bytes (measured: a name of 255 in wire
                // form is the host's, one of 256 none); and the label, and
                // a byte after it, inside the message.
                let room = MAX_WIRE_NAME.checked_sub(1)?.checked_sub(out.len())?;
                if len >= room || len >= msg.len().checked_sub(src)? {
                    return None;
                }
                checked = checked.checked_add(len)?.checked_add(1)?;
                out.push(n);
                out.extend_from_slice(msg.get(src..src.checked_add(len)?)?);
                src = src.checked_add(len)?;
            }
            0xc0 => {
                let low = *msg.get(src)?;
                if used.is_none() {
                    used = Some(src.checked_add(1)?.checked_sub(at)?);
                }
                let target = (usize::from(n & 0x3f) << 8) | usize::from(low);
                if target >= msg.len() {
                    return None;
                }
                src = target;
                checked = checked.checked_add(2)?;
                if checked >= msg.len() {
                    return None;
                }
            }
            _ => return None,
        }
    }
    out.push(0);
    let used = match used {
        Some(used) => used,
        None => src.checked_sub(at)?,
    };
    Some((out, used))
}

/// `ns_name_ntop()` into `size` bytes, its NUL counted: the name as text,
/// labels joined by dots, each of `"`, `.`, `;`, `\`, `(`, `)`, `@` and `$`
/// after a backslash, every other byte that is no printable ASCII (a space
/// included) as `\DDD`, and the root as `.`. `None` where it does not fit.
pub fn name_text(wire: &[u8], size: usize) -> Option<String> {
    let mut out = String::with_capacity(wire.len().saturating_mul(2));
    let mut at = 0usize;
    let fits = |out: &String, more: usize| out.len().checked_add(more).is_some_and(|n| n < size);
    loop {
        let len = usize::from(*wire.get(at)?);
        at = at.checked_add(1)?;
        if len == 0 {
            break;
        }
        if len >= 64 {
            return None;
        }
        if !out.is_empty() {
            if !fits(&out, 1) {
                return None;
            }
            out.push('.');
        }
        for &c in wire.get(at..at.checked_add(len)?)? {
            if matches!(c, b'"' | b'.' | b';' | b'\\' | b'(' | b')' | b'@' | b'$') {
                if !fits(&out, 2) {
                    return None;
                }
                out.push('\\');
                out.push(char::from(c));
            } else if c <= 0x20 || c >= 0x7f {
                if !fits(&out, 4) {
                    return None;
                }
                out.push('\\');
                out.push(char::from(b'0' + c / 100));
                out.push(char::from(b'0' + (c % 100) / 10));
                out.push(char::from(b'0' + c % 10));
            } else {
                if !fits(&out, 1) {
                    return None;
                }
                out.push(char::from(c));
            }
        }
        at = at.checked_add(len)?;
    }
    if out.is_empty() {
        if !fits(&out, 1) {
            return None;
        }
        out.push('.');
    }
    fits(&out, 0).then_some(out)
}

/// `__ns_samebinaryname()`: two names in wire form, equal but for ASCII case.
fn same_name(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

/// What `send_dg()` makes of a datagram that came back for `query`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Not this query's (another id or question): waited past, as if it had
    /// not come.
    Spurious,
    /// Too short, or `SERVFAIL`, `NOTIMP` or `REFUSED`, or `NOERROR` with
    /// no answer and neither `AA` nor `RA` nor an additional record: the
    /// next server is asked.
    NextServer,
    /// `TC`: asked again over TCP, of the same server.
    Truncated,
    /// The answer, whatever its rcode.
    Answer,
}

/// `__libc_res_queriesmatch()`, for one question: the reply's question
/// count is the query's, and its question is the query's name (but for
/// case), type and class. A question glibc cannot read — a name it cannot
/// unpack, a type or class cut off — counts as a match: its reader's `-1`
/// is true where it is tested (`if (!__libc_res_nameinquery(…))`).
fn question_matches(query: &[u8], reply: &[u8]) -> bool {
    if reply.get(4..6) != query.get(4..6) {
        return false;
    }
    let Some((ours, used)) = unpack_name(query, HEADER) else {
        return true;
    };
    let ours_end = HEADER.saturating_add(used);
    let (Some(qtype), Some(qclass)) = (
        be16(query, ours_end),
        be16(query, ours_end.saturating_add(2)),
    ) else {
        return true;
    };
    let Some((theirs, used)) = unpack_name(reply, HEADER) else {
        return true;
    };
    let end = HEADER.saturating_add(used);
    let (Some(rtype), Some(rclass)) = (be16(reply, end), be16(reply, end.saturating_add(2))) else {
        return true;
    };
    rtype == qtype && rclass == qclass && same_name(&theirs, &ours)
}

/// What `send_dg()` makes of `reply`, a datagram from the server `query`
/// was sent to (the socket is connected: the kernel drops what comes from
/// anywhere else). Measured: a reply without `QR`, or with another opcode,
/// is taken; another id or question is waited past; `REFUSED`, `SERVFAIL`
/// and an empty unauthoritative `NOERROR` move to the next server at once.
pub fn udp_verdict(query: &[u8], reply: &[u8]) -> Verdict {
    if reply.len() < HEADER {
        return Verdict::NextServer;
    }
    if reply.get(..2) != query.get(..2) || !question_matches(query, reply) {
        return Verdict::Spurious;
    }
    let flags1 = reply.get(2).copied().unwrap_or(0);
    let flags2 = reply.get(3).copied().unwrap_or(0);
    let rcode = flags2 & 0x0f;
    if matches!(rcode, SERVFAIL | NOTIMP | REFUSED) {
        return Verdict::NextServer;
    }
    let aa = flags1 & 0x04 != 0;
    let tc = flags1 & 0x02 != 0;
    let ra = flags2 & 0x80 != 0;
    let ancount = be16(reply, 6).unwrap_or(0);
    let arcount = be16(reply, 10).unwrap_or(0);
    if rcode == NOERROR && ancount == 0 && !aa && !ra && arcount == 0 {
        return Verdict::NextServer;
    }
    if tc {
        return Verdict::Truncated;
    }
    Verdict::Answer
}

/// The host name in `reply`, an answer [`udp_verdict`] took or one that
/// came over TCP with the query's id: `__res_context_query()`'s test of its
/// rcode and count, then `getanswer_ptr()`:
///
/// * an rcode other than `NOERROR`, or no answer: not found;
/// * the question must be one name, uncompressed, with its type and class,
///   or the reply is unreadable (`UNAVAIL`);
/// * each answer is read in turn, a malformed one making the reply
///   unreadable; one of another class is passed over; a `CNAME`, whatever
///   its owner, makes its target the name looked for next (its data must
///   unpack; what follows the name in it is not looked at); a PTR record
///   whose owner is the name looked for, but for case, gives the host: its
///   target unpacked and written as text ([`name_text`]), within
///   [`MAX_NAME_TEXT`] (unreadable if it does not fit); anything else is
///   passed over;
/// * no such PTR record: not found.
///
/// Nothing checks that the name is a host name: measured, a target with a
/// space, an ESC, a `/` or a leading `-` is the host, in its escaped form,
/// and so is a CNAME's target that has one.
pub fn answer_name(reply: &[u8]) -> NssAnswer<String> {
    if reply.len() < HEADER {
        return NssAnswer::Unavail;
    }
    let rcode = reply.get(3).copied().unwrap_or(0) & 0x0f;
    let ancount = be16(reply, 6).unwrap_or(0);
    if rcode != NOERROR || ancount == 0 {
        return NssAnswer::NotFound;
    }
    // `__ns_rr_cursor_init()`: one question, its name uncompressed.
    if reply.get(4..6) != Some(&[0, 1][..]) {
        return NssAnswer::Unavail;
    }
    let mut at = HEADER;
    loop {
        let Some(&len) = reply.get(at) else {
            return NssAnswer::Unavail;
        };
        at = match at.checked_add(1) {
            Some(next) => next,
            None => return NssAnswer::Unavail,
        };
        if len == 0 {
            break;
        }
        if len > 63 {
            return NssAnswer::Unavail;
        }
        let Some(next) = at
            .checked_add(usize::from(len))
            .filter(|&n| n <= reply.len())
        else {
            return NssAnswer::Unavail;
        };
        at = next;
    }
    if at.saturating_sub(HEADER) > MAX_WIRE_NAME {
        return NssAnswer::Unavail;
    }
    let Some(qname) = reply.get(HEADER..at).map(<[u8]>::to_vec) else {
        return NssAnswer::Unavail;
    };
    let Some(mut cursor) = at.checked_add(4).filter(|&c| c <= reply.len()) else {
        return NssAnswer::Unavail;
    };
    let mut expected = qname;
    for _ in 0..ancount {
        let Some((owner, used)) = unpack_name(reply, cursor) else {
            return NssAnswer::Unavail;
        };
        cursor = cursor.saturating_add(used);
        let (Some(rtype), Some(rclass), Some(rdlength)) = (
            be16(reply, cursor),
            be16(reply, cursor.saturating_add(2)),
            be16(reply, cursor.saturating_add(8)),
        ) else {
            return NssAnswer::Unavail;
        };
        let rdata = cursor.saturating_add(10);
        let Some(end) = rdata
            .checked_add(usize::from(rdlength))
            .filter(|&e| e <= reply.len())
        else {
            return NssAnswer::Unavail;
        };
        cursor = end;
        if rclass != C_IN {
            continue;
        }
        if rtype == T_CNAME {
            match unpack_name(reply, rdata) {
                Some((target, _)) => expected = target,
                None => return NssAnswer::Unavail,
            }
        } else if rtype == T_PTR && same_name(&owner, &expected) {
            return match unpack_name(reply, rdata)
                .and_then(|(target, _)| name_text(&target, MAX_NAME_TEXT.saturating_add(1)))
            {
                Some(name) => NssAnswer::Success(name),
                None => NssAnswer::Unavail,
            };
        }
    }
    NssAnswer::NotFound
}

/// What one datagram read gave.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Received {
    /// A datagram of this many bytes, now at the front of the buffer.
    Datagram(usize),
    /// The server's port is closed (an ICMP error, `ECONNREFUSED`).
    Refused,
    /// Nothing came before the deadline.
    TimedOut,
    /// Any other error.
    Failed,
}

/// How a datagram socket to a server came up.
pub enum Opened<S> {
    Socket(S),
    /// `socket(2)` failed: glibc gives up the whole query.
    NoSocket,
    /// `connect(2)` failed: the next server is asked.
    NotConnected,
}

/// What the query loop needs of the network and the clock: `std::net` and
/// `Instant` in the backend, a script in the tests. Every wait it makes
/// ends at a deadline the loop gives it, measured on [`Transport::now`].
pub trait Transport {
    type Udp;
    type Tcp;
    /// Time since an arbitrary start, monotonic.
    fn now(&mut self) -> Duration;
    /// 16 random bits: a query's id, `rotate`'s first server.
    fn random(&mut self) -> u16;
    /// A datagram socket connected to `server`.
    fn udp(&mut self, server: SocketAddr) -> Opened<Self::Udp>;
    /// Send `message` on it; `false` where that failed.
    fn udp_send(&mut self, sock: &mut Self::Udp, message: &[u8]) -> bool;
    /// The next datagram on it, into `buf` (at least [`MAX_MESSAGE`] bytes),
    /// waited for until `deadline`.
    fn udp_recv(&mut self, sock: &mut Self::Udp, buf: &mut [u8], deadline: Duration) -> Received;
    /// A TCP connection to `server`, made by `deadline`; `None` where it
    /// cannot be.
    fn tcp(&mut self, server: SocketAddr, deadline: Duration) -> Option<Self::Tcp>;
    /// Send `message` on it, its 16-bit length before it, by `deadline`.
    fn tcp_send(&mut self, conn: &mut Self::Tcp, message: &[u8], deadline: Duration) -> bool;
    /// Read one message (a length, then that many bytes) by `deadline` into
    /// `buf`: its length, or `None` where the connection failed or ended.
    fn tcp_recv(
        &mut self,
        conn: &mut Self::Tcp,
        buf: &mut [u8],
        deadline: Duration,
    ) -> Option<usize>;
}

/// What one exchange with a server came to.
enum Exchange {
    Answer(Vec<u8>),
    Next,
    Truncated,
    GiveUp,
}

/// One attempt over UDP with server `ns` (`send_dg()`).
fn udp_attempt<T: Transport>(
    t: &mut T,
    socks: &mut [Option<T::Udp>],
    ns: usize,
    server: SocketAddr,
    query: &[u8],
    wait: Duration,
    buf: &mut [u8],
) -> Exchange {
    let Some(slot) = socks.get_mut(ns) else {
        return Exchange::Next;
    };
    if slot.is_none() {
        match t.udp(server) {
            Opened::Socket(s) => *slot = Some(s),
            Opened::NoSocket => return Exchange::GiveUp,
            Opened::NotConnected => return Exchange::Next,
        }
    }
    let deadline = t.now().saturating_add(wait);
    let close_all = |socks: &mut [Option<T::Udp>]| socks.iter_mut().for_each(|s| *s = None);
    let sent = match socks.get_mut(ns).and_then(Option::as_mut) {
        Some(sock) => t.udp_send(sock, query),
        None => false,
    };
    if !sent {
        close_all(socks);
        return Exchange::Next;
    }
    loop {
        let got = match socks.get_mut(ns).and_then(Option::as_mut) {
            Some(sock) => t.udp_recv(sock, buf, deadline),
            None => Received::Failed,
        };
        match got {
            // The socket stays open: a reply that comes late is read at
            // this server's next attempt, as glibc's stays and reads it.
            Received::TimedOut => return Exchange::Next,
            Received::Refused | Received::Failed => {
                close_all(socks);
                return Exchange::Next;
            }
            Received::Datagram(len) => {
                let reply = buf.get(..len.min(buf.len())).unwrap_or_default();
                match udp_verdict(query, reply) {
                    Verdict::Spurious => continue,
                    Verdict::NextServer => {
                        close_all(socks);
                        return Exchange::Next;
                    }
                    Verdict::Truncated => {
                        close_all(socks);
                        return Exchange::Truncated;
                    }
                    Verdict::Answer => return Exchange::Answer(reply.to_vec()),
                }
            }
        }
    }
}

/// One exchange over TCP with server `ns` (`send_vc()`): connect, send, and
/// read messages until one has the query's id. glibc waits on each step
/// without a limit; here the whole exchange has `wait`, the time an attempt
/// over UDP with this server has, and at most [`MAX_TCP_MESSAGES`] messages.
/// A connection reset before the first reply is tried once more, as glibc
/// tries it.
fn tcp_attempt<T: Transport>(
    t: &mut T,
    server: SocketAddr,
    query: &[u8],
    wait: Duration,
    buf: &mut [u8],
) -> Exchange {
    let deadline = t.now().saturating_add(wait);
    let Some(mut conn) = t.tcp(server, deadline) else {
        return Exchange::Next;
    };
    if !t.tcp_send(&mut conn, query, deadline) {
        return Exchange::Next;
    }
    for _ in 0..MAX_TCP_MESSAGES {
        let Some(len) = t.tcp_recv(&mut conn, buf, deadline) else {
            return Exchange::Next;
        };
        let reply = buf.get(..len.min(buf.len())).unwrap_or_default();
        if reply.len() < HEADER {
            return Exchange::Next;
        }
        if reply.get(..2) == query.get(..2) {
            return Exchange::Answer(reply.to_vec());
        }
    }
    Exchange::Next
}

/// `ip`'s PTR name, asked of the servers of `conf` as glibc's
/// `__res_context_send()` asks them, and read as `getanswer_ptr()` reads
/// the answer ([`answer_name`]):
///
/// * `attempts` rounds; in each, every server in turn, from the first or,
///   under `rotate`, from [`Rotation`]'s; each waited for its
///   [`ResolvConf::wait`];
/// * a server that does not answer in time, refuses (`REFUSED`,
///   `SERVFAIL`, `NOTIMP`, a closed port), or sends an empty
///   unauthoritative `NOERROR` or a datagram too short to be one: the
///   next server;
/// * a datagram that is not this query's: waited past;
/// * `TC`: the same server over TCP, and from then on every server over
///   TCP, with no round after this one (as from the start under `use-vc`);
/// * any other answer ends the query, whatever it says.
///
/// `NotFound` where no server gave an answer, as glibc's `dns` source says
/// whatever went wrong (its `ECONNREFUSED` test reads an `errno` it has
/// just restored, so `UNAVAIL` never comes of it).
pub fn query_ptr<T: Transport>(
    conf: &ResolvConf,
    ip: IpAddr,
    t: &mut T,
    rotation: &mut Rotation,
) -> NssAnswer<String> {
    let id = t.random();
    let offset = rotation.next(conf, t.random());
    let query = ptr_query(id, ip, conf);
    let count = conf.servers.len();
    let mut socks: Vec<Option<T::Udp>> = (0..count).map(|_| None).collect();
    let mut buf = vec![0u8; MAX_MESSAGE];
    let mut vc = conf.use_vc;
    let mut round = 0i64;
    while round < conf.retry {
        for shift in 0..count {
            let ns = shift.checked_add(offset).map_or(0, |n| n % count.max(1));
            let Some(&server) = conf.servers.get(ns) else {
                continue;
            };
            let wait = conf.wait(ns);
            let mut exchange = if vc {
                round = conf.retry;
                tcp_attempt(t, server, &query, wait, &mut buf)
            } else {
                udp_attempt(t, &mut socks, ns, server, &query, wait, &mut buf)
            };
            if matches!(exchange, Exchange::Truncated) {
                vc = true;
                round = conf.retry;
                exchange = tcp_attempt(t, server, &query, wait, &mut buf);
            }
            match exchange {
                Exchange::Answer(reply) => return answer_name(&reply),
                Exchange::GiveUp => return NssAnswer::NotFound,
                Exchange::Next | Exchange::Truncated => {}
            }
        }
        round = round.saturating_add(1);
    }
    NssAnswer::NotFound
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::net::Ipv6Addr;

    fn no_scope(_: &[u8]) -> Option<u32> {
        None
    }

    fn conf(text: &str) -> ResolvConf {
        ResolvConf::parse(Some(text.as_bytes()), None, &no_scope)
    }

    fn v4(s: &str) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(s.parse().unwrap(), 53))
    }

    #[test]
    fn resolv_conf_is_read_as_glibc_reads_it() {
        let c =
            conf("nameserver 127.0.0.53\nnameserver 127.0.0.54\noptions timeout:1 attempts:1\n");
        assert_eq!(c.servers, vec![v4("127.0.0.53"), v4("127.0.0.54")]);
        assert_eq!((c.retrans, c.retry), (1, 1));
        // Defaults, and the loopback where no server is named.
        let c = conf("");
        assert_eq!(
            (c.servers.clone(), c.retrans, c.retry),
            (vec![v4("127.0.0.1")], 5, 2)
        );
        // inet_aton's forms, a tab, what follows the address, and a line
        // that a blank opens (no server: the loopback).
        assert_eq!(
            conf("nameserver 127.0.54\n").servers,
            vec![v4("127.0.0.54")]
        );
        assert_eq!(
            conf("nameserver\t0x7f000035\n").servers,
            vec![v4("127.0.0.53")]
        );
        assert_eq!(
            conf("nameserver 127.0.0.54 junk here\n").servers,
            vec![v4("127.0.0.54")]
        );
        assert_eq!(
            conf(" nameserver 127.0.0.54\n").servers,
            vec![v4("127.0.0.1")]
        );
        assert_eq!(
            conf("nameserver127.0.0.54\n").servers,
            vec![v4("127.0.0.1")]
        );
        // Comments, a NUL, and no newline at the end.
        assert_eq!(
            conf("# nameserver 1.1.1.1\n;x\nnameserver 127.0.0.54").servers,
            vec![v4("127.0.0.54")]
        );
        assert_eq!(
            conf("nameserver 127.0.0.54\0garbage\n").servers,
            vec![v4("127.0.0.54")]
        );
        // A word that is no address does not count towards the three.
        let c = conf("nameserver bogus\nnameserver 10.0.0.1\nnameserver 10.0.0.2\nnameserver 10.0.0.3\nnameserver 10.0.0.4\n");
        assert_eq!(
            c.servers,
            vec![v4("10.0.0.1"), v4("10.0.0.2"), v4("10.0.0.3")]
        );
        // IPv6, with a numeric scope.
        let c = conf("nameserver ::1\nnameserver fe80::1%7\n");
        assert_eq!(c.servers.len(), 2);
        assert!(matches!(c.servers[1], SocketAddr::V6(a) if a.scope_id() == 7));
    }

    #[test]
    fn options_are_prefixes_bounded_and_read_in_turn() {
        let c = conf("options timeout:3\nnameserver 1.2.3.4\noptions attempts:1 timeout:1\n");
        assert_eq!((c.retrans, c.retry), (1, 1));
        let c = conf("options timeout:99 attempts:9 rotatexyz use-vc edns0 trust-ad\n");
        assert_eq!((c.retrans, c.retry), (30, 5));
        assert!(c.rotate && c.use_vc && c.edns0 && c.trust_ad);
        assert_eq!(conf("options timeout:-3\n").retrans, -3);
        assert_eq!(conf("options attempts:0\n").retry, 0);
        // `atoi()` on a value past an `int`: strtol saturates, the cast
        // keeps the low bits.
        assert_eq!(conf("options timeout:99999999999999999999\n").retrans, -1);
        // RES_OPTIONS after the file.
        let c = ResolvConf::parse(
            Some(b"options timeout:1\n"),
            Some(b"timeout:2 attempts:0"),
            &no_scope,
        );
        assert_eq!((c.retrans, c.retry), (2, 0));
    }

    #[test]
    fn each_server_waits_as_send_dg_computes_it() {
        let secs = |c: &ResolvConf| {
            (0..c.servers.len())
                .map(|n| c.wait(n).as_secs())
                .collect::<Vec<_>>()
        };
        let three = "nameserver 1.1.1.1\nnameserver 1.1.1.2\nnameserver 1.1.1.3\n";
        assert_eq!(
            secs(&conf(&format!("{three}options timeout:2\n"))),
            vec![2, 1, 2]
        );
        assert_eq!(
            secs(&conf(&format!("{three}options timeout:1\n"))),
            vec![1, 1, 1]
        );
        assert_eq!(
            secs(&conf(&format!("{three}options timeout:30\n"))),
            vec![30, 20, 40]
        );
        assert_eq!(
            secs(&conf(
                "nameserver 1.1.1.1\nnameserver 1.1.1.2\noptions timeout:1\n"
            )),
            vec![1, 1]
        );
        // Zero and below: a second.
        assert_eq!(
            secs(&conf("nameserver 1.1.1.1\noptions timeout:0\n")),
            vec![1]
        );
        assert_eq!(
            secs(&conf("nameserver 1.1.1.1\noptions timeout:-3\n")),
            vec![1]
        );
        // The C's worst case: 5 rounds of 30 + 20 + 40.
        let worst = conf(&format!("{three}options timeout:30 attempts:5\n")).worst_case();
        assert_eq!(worst.as_secs(), 450);
        assert_eq!(conf("options attempts:0\n").worst_case(), Duration::ZERO);
    }

    #[test]
    fn ptr_names_are_glibcs() {
        let text = |ip: &str| name_text(&ptr_name(ip.parse().unwrap()), 1025).unwrap();
        assert_eq!(text("127.0.0.7"), "7.0.0.127.in-addr.arpa");
        assert_eq!(text("::ffff:10.1.2.3"), "3.2.1.10.in-addr.arpa");
        assert_eq!(text("::10.1.2.3"), "3.2.1.10.in-addr.arpa");
        assert_eq!(
            text("::1"),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa"
        );
        assert_eq!(
            text("2001:db8::ab"),
            "b.a.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
        let q = ptr_query(0x1234, "127.0.0.7".parse().unwrap(), &ResolvConf::default());
        assert_eq!(q.len(), 40);
        assert_eq!(&q[..12], &[0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        let c = ResolvConf {
            edns0: true,
            trust_ad: true,
            ..ResolvConf::default()
        };
        let q = ptr_query(1, "127.0.0.7".parse().unwrap(), &c);
        // Measured: the edns0 query is 51 bytes.
        assert_eq!((q.len(), q[3], q[11]), (51, 0x20, 1));
    }

    fn lab(labels: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for l in labels {
            out.push(l.len() as u8);
            out.extend_from_slice(l);
        }
        out.push(0);
        out
    }

    fn rr(owner: &[u8], rtype: u16, rdata: &[u8], class: u16) -> Vec<u8> {
        let mut out = owner.to_vec();
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&class.to_be_bytes());
        out.extend_from_slice(&60u32.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(rdata);
        out
    }

    /// A reply to `query`: its id and question, `flags`, the records.
    fn reply(query: &[u8], flags: [u8; 2], ancount: u16, records: &[Vec<u8>]) -> Vec<u8> {
        let end = HEADER + unpack_name(query, HEADER).unwrap().1 + 4;
        let mut out = query[..2].to_vec();
        out.extend_from_slice(&flags);
        out.extend_from_slice(&query[4..6]);
        out.extend_from_slice(&ancount.to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(&query[HEADER..end]);
        for r in records {
            out.extend_from_slice(r);
        }
        out
    }

    fn query7() -> Vec<u8> {
        ptr_query(0xbeef, "127.0.0.7".parse().unwrap(), &ResolvConf::default())
    }

    const PTR_OWNER: &[u8] = b"\xc0\x0c";
    const OK: [u8; 2] = [0x81, 0x80];

    fn name_of(r: &[u8]) -> NssAnswer<String> {
        answer_name(r)
    }

    #[test]
    fn a_ptr_answer_names_the_host_as_glibc_writes_it() {
        let q = query7();
        let good = lab(&[b"good", b"example"]);
        let one = |rd: &[u8]| reply(&q, OK, 1, &[rr(PTR_OWNER, 12, rd, 1)]);
        assert_eq!(
            name_of(&one(&good)),
            NssAnswer::Success("good.example".into())
        );
        // Escapes (measured through the C: `sp\032ace`, `esc\027[31m`,
        // `a\.b`, `tab\009here`, `h\195\169`), and the root.
        assert_eq!(
            name_of(&one(&lab(&[b"sp ace", b"x"]))),
            NssAnswer::Success("sp\\032ace.x".into())
        );
        assert_eq!(
            name_of(&one(&lab(&[b"esc\x1b[31m", b"x"]))),
            NssAnswer::Success("esc\\027[31m.x".into())
        );
        assert_eq!(
            name_of(&one(&lab(&[b"a.b", b"x"]))),
            NssAnswer::Success("a\\.b.x".into())
        );
        assert_eq!(
            name_of(&one(&lab(&[b"h\xc3\xa9", b"x"]))),
            NssAnswer::Success("h\\195\\169.x".into())
        );
        assert_eq!(name_of(&one(&[0])), NssAnswer::Success(".".into()));
        // Case kept; no host-name check (`-lead`, `a/b`, `a*b`).
        assert_eq!(
            name_of(&one(&lab(&[b"-lead", b"Ex"]))),
            NssAnswer::Success("-lead.Ex".into())
        );
        // Junk after the name in the data, and after the message: taken.
        let mut junk = good.clone();
        junk.extend_from_slice(b"junk");
        assert_eq!(
            name_of(&one(&junk)),
            NssAnswer::Success("good.example".into())
        );
        let mut trailing = one(&good);
        trailing.extend_from_slice(b"trailing");
        assert_eq!(
            name_of(&trailing),
            NssAnswer::Success("good.example".into())
        );
        // The first of two.
        let two = reply(
            &q,
            OK,
            2,
            &[
                rr(PTR_OWNER, 12, &lab(&[b"first"]), 1),
                rr(PTR_OWNER, 12, &lab(&[b"second"]), 1),
            ],
        );
        assert_eq!(name_of(&two), NssAnswer::Success("first".into()));
        // A count past the records: the PTR is found first.
        assert_eq!(
            name_of(&reply(&q, OK, 5, &[rr(PTR_OWNER, 12, &good, 1)])),
            NssAnswer::Success("good.example".into())
        );
    }

    #[test]
    fn names_past_the_limits_are_no_names() {
        let q = query7();
        let one = |rd: &[u8]| reply(&q, OK, 1, &[rr(PTR_OWNER, 12, rd, 1)]);
        // 255 bytes in wire form: the longest.
        let longest = lab(&[&[b'x'; 63], &[b'y'; 63], &[b'z'; 63], &[b'w'; 61]]);
        assert!(matches!(name_of(&one(&longest)), NssAnswer::Success(n) if n.len() == 253));
        let over = lab(&[&[b'x'; 63], &[b'y'; 63], &[b'z'; 63], &[b'w'; 62]]);
        assert_eq!(name_of(&one(&over)), NssAnswer::Unavail);
        // 256 characters of text, escapes counted, fit; 257 do not
        // (measured).
        // Each 0x80 byte is four characters (`\128`).
        let e = |n: usize| vec![0x80u8; n];
        let names: [(usize, Vec<u8>, bool); 4] = [
            (250, lab(&[&e(62), b"a"]), true),
            (256, lab(&[&e(63), b"aaa"]), true),
            (257, lab(&[&e(63), b"aaaa"]), false),
            (300, lab(&[&e(63), &e(11), b"aa"]), false),
        ];
        for (text, wire, ok) in names {
            match name_of(&one(&wire)) {
                NssAnswer::Success(n) => assert!(ok && n.len() == text, "{text}: {}", n.len()),
                other => assert!(!ok, "{text}: {other:?}"),
            }
        }
    }

    #[test]
    fn cnames_classes_and_owners_are_followed_as_glibc_follows_them() {
        let q = query7();
        let good = lab(&[b"good", b"example"]);
        let cn = lab(&[b"cn", b"example"]);
        // A chain.
        let r = reply(
            &q,
            OK,
            2,
            &[rr(PTR_OWNER, 5, &cn, 1), rr(&cn, 12, &good, 1)],
        );
        assert_eq!(name_of(&r), NssAnswer::Success("good.example".into()));
        // A CNAME's owner is not checked; its target need not be a host
        // name; what follows it in its data is not looked at.
        let bad = lab(&[b"bad name", b"x"]);
        let r = reply(
            &q,
            OK,
            2,
            &[rr(&lab(&[b"zz"]), 5, &bad, 1), rr(&bad, 12, &good, 1)],
        );
        assert_eq!(name_of(&r), NssAnswer::Success("good.example".into()));
        let mut cn_junk = cn.clone();
        cn_junk.push(b'x');
        let r = reply(
            &q,
            OK,
            2,
            &[rr(PTR_OWNER, 5, &cn_junk, 1), rr(&cn, 12, &good, 1)],
        );
        assert_eq!(name_of(&r), NssAnswer::Success("good.example".into()));
        // A PTR at the first owner once a CNAME has moved the name on.
        let r = reply(
            &q,
            OK,
            2,
            &[rr(PTR_OWNER, 5, &cn, 1), rr(PTR_OWNER, 12, &good, 1)],
        );
        assert_eq!(name_of(&r), NssAnswer::NotFound);
        // Another class is passed over, the case of the owner is not.
        let r = reply(
            &q,
            OK,
            2,
            &[
                rr(PTR_OWNER, 12, &lab(&[b"chaos"]), 3),
                rr(PTR_OWNER, 12, &good, 1),
            ],
        );
        assert_eq!(name_of(&r), NssAnswer::Success("good.example".into()));
        let upper = lab(&[b"7", b"0", b"0", b"127", b"IN-ADDR", b"ARPA"]);
        assert_eq!(
            name_of(&reply(&q, OK, 1, &[rr(&upper, 12, &good, 1)])),
            NssAnswer::Success("good.example".into())
        );
        // Another owner, another type: passed over.
        assert_eq!(
            name_of(&reply(
                &q,
                OK,
                1,
                &[rr(&lab(&[b"other", b"arpa"]), 12, &good, 1)]
            )),
            NssAnswer::NotFound
        );
        let r = reply(
            &q,
            OK,
            2,
            &[
                rr(PTR_OWNER, 1, b"\x01\x02\x03\x04", 1),
                rr(PTR_OWNER, 12, &good, 1),
            ],
        );
        assert_eq!(name_of(&r), NssAnswer::Success("good.example".into()));
        // A CNAME whose data loops: unreadable.
        let looped = reply(&q, OK, 1, &[rr(PTR_OWNER, 5, b"\xc0\x00", 1)]);
        let at = looped.len() - 2;
        let mut looped = looped;
        looped[at + 1] = u8::try_from(at).unwrap();
        assert_eq!(name_of(&looped), NssAnswer::Unavail);
    }

    #[test]
    fn rcodes_counts_and_malformed_replies() {
        let q = query7();
        let good = lab(&[b"good", b"example"]);
        let one = |flags: [u8; 2]| reply(&q, flags, 1, &[rr(PTR_OWNER, 12, &good, 1)]);
        // NXDOMAIN or SERVFAIL with an answer, FORMERR: no name.
        assert_eq!(name_of(&one([0x81, 0x83])), NssAnswer::NotFound);
        assert_eq!(name_of(&one([0x81, 0x82])), NssAnswer::NotFound);
        assert_eq!(name_of(&one([0x81, 0x81])), NssAnswer::NotFound);
        // No QR, an opcode: taken.
        assert_eq!(
            name_of(&one([0x01, 0x80])),
            NssAnswer::Success("good.example".into())
        );
        assert_eq!(
            name_of(&one([0x89, 0x80])),
            NssAnswer::Success("good.example".into())
        );
        // A count of zero with a record.
        assert_eq!(
            name_of(&reply(&q, OK, 0, &[rr(PTR_OWNER, 12, &good, 1)])),
            NssAnswer::NotFound
        );
        // Cut short; a pointer into itself; a label type that is neither.
        let full = one(OK);
        assert_eq!(name_of(&full[..full.len() - 3]), NssAnswer::Unavail);
        assert_eq!(
            name_of(&reply(&q, OK, 1, &[rr(PTR_OWNER, 12, b"\x40ab\0", 1)])),
            NssAnswer::Unavail
        );
        // A pointer to the question is the question's name (measured).
        assert_eq!(
            name_of(&reply(&q, OK, 1, &[rr(PTR_OWNER, 12, b"\xc0\x0c", 1)])),
            NssAnswer::Success("7.0.0.127.in-addr.arpa".into())
        );
        // A first record cut off after a good A: unreadable.
        let mut r = reply(&q, OK, 2, &[rr(PTR_OWNER, 1, b"1234", 1)]);
        r.push(0xc0);
        assert_eq!(name_of(&r), NssAnswer::Unavail);
        // Every prefix of a good reply, and every byte flipped: no panic.
        for n in 0..full.len() {
            let _ = name_of(&full[..n]);
            let _ = udp_verdict(&q, &full[..n]);
            let mut flipped = full.clone();
            flipped[n] ^= 0xff;
            let _ = name_of(&flipped);
            let _ = udp_verdict(&q, &flipped);
        }
    }

    #[test]
    fn send_dg_takes_waits_past_or_moves_on() {
        let q = query7();
        let good = lab(&[b"good", b"example"]);
        let r = |flags: [u8; 2], an: u16| reply(&q, flags, an, &[rr(PTR_OWNER, 12, &good, 1)]);
        assert_eq!(udp_verdict(&q, &r(OK, 1)), Verdict::Answer);
        assert_eq!(udp_verdict(&q, &r([0x81, 0x83], 0)), Verdict::Answer);
        assert_eq!(udp_verdict(&q, &r([0x81, 0x85], 0)), Verdict::NextServer);
        assert_eq!(udp_verdict(&q, &r([0x81, 0x82], 1)), Verdict::NextServer);
        assert_eq!(udp_verdict(&q, &r([0x81, 0x84], 1)), Verdict::NextServer);
        // Empty: lame unless AA or RA says otherwise.
        assert_eq!(
            udp_verdict(&q, &reply(&q, [0x81, 0x00], 0, &[])),
            Verdict::NextServer
        );
        assert_eq!(
            udp_verdict(&q, &reply(&q, [0x81, 0x80], 0, &[])),
            Verdict::Answer
        );
        assert_eq!(
            udp_verdict(&q, &reply(&q, [0x85, 0x00], 0, &[])),
            Verdict::Answer
        );
        assert_eq!(udp_verdict(&q, &r([0x83, 0x80], 0)), Verdict::Truncated);
        assert_eq!(udp_verdict(&q, &q[..11]), Verdict::NextServer);
        // Another id, question count, type, class or name: spurious.
        let mut other = r(OK, 1);
        other[0] ^= 1;
        assert_eq!(udp_verdict(&q, &other), Verdict::Spurious);
        let mut zero = r(OK, 1);
        zero[5] = 0;
        assert_eq!(udp_verdict(&q, &zero[..12]), Verdict::Spurious);
        let mut class = r(OK, 1);
        let at = HEADER + 22 + 3;
        class[at] = 3;
        assert_eq!(udp_verdict(&q, &class), Verdict::Spurious);
        let mut name = r(OK, 1);
        name[HEADER + 1] = b'9';
        assert_eq!(udp_verdict(&q, &name), Verdict::Spurious);
        // The question's case is not looked at; one that cannot be read
        // counts as a match.
        let mut case = r(OK, 1);
        let at = HEADER + 1 + 1 + 2 + 2 + 4 + 1;
        case[at] = b'I';
        assert_eq!(udp_verdict(&q, &case), Verdict::Answer);
        let mut cut = q[..14].to_vec();
        cut[2] = 0x81;
        cut[3] = 0x80;
        assert_eq!(udp_verdict(&q, &cut), Verdict::Answer);
    }

    /// A transport scripted per server, on a clock that moves only when a
    /// wait would.
    #[derive(Default)]
    struct Script {
        now: Duration,
        /// Per server: what each datagram sent gets, in order.
        udp: std::collections::HashMap<SocketAddr, VecDeque<Vec<Reply>>>,
        tcp: std::collections::HashMap<SocketAddr, Vec<u8>>,
        log: Vec<(u64, SocketAddr, &'static str)>,
        pending: VecDeque<Reply>,
    }

    #[derive(Clone)]
    enum Reply {
        /// A datagram this long after the query, made of it.
        After(u64, fn(&[u8]) -> Vec<u8>),
        Refused,
    }

    impl Transport for Script {
        type Udp = SocketAddr;
        type Tcp = SocketAddr;
        fn now(&mut self) -> Duration {
            self.now
        }
        fn random(&mut self) -> u16 {
            0x4242
        }
        fn udp(&mut self, server: SocketAddr) -> Opened<SocketAddr> {
            Opened::Socket(server)
        }
        fn udp_send(&mut self, sock: &mut SocketAddr, message: &[u8]) -> bool {
            self.log.push((self.now.as_secs(), *sock, "udp"));
            let replies = self
                .udp
                .get_mut(sock)
                .and_then(VecDeque::pop_front)
                .unwrap_or_default();
            self.pending = replies.into();
            self.pending
                .iter_mut()
                .for_each(|r| if let Reply::After(_, _) = r {});
            let _ = message;
            true
        }
        fn udp_recv(&mut self, _: &mut SocketAddr, buf: &mut [u8], deadline: Duration) -> Received {
            match self.pending.pop_front() {
                Some(Reply::After(secs, make))
                    if self.now + Duration::from_secs(secs) < deadline =>
                {
                    self.now += Duration::from_secs(secs);
                    let q = ptr_query(0x4242, "127.0.0.7".parse().unwrap(), &ResolvConf::default());
                    let r = make(&q);
                    buf[..r.len()].copy_from_slice(&r);
                    Received::Datagram(r.len())
                }
                Some(Reply::Refused) => Received::Refused,
                _ => {
                    self.now = deadline;
                    Received::TimedOut
                }
            }
        }
        fn tcp(&mut self, server: SocketAddr, _: Duration) -> Option<SocketAddr> {
            self.tcp.contains_key(&server).then_some(server)
        }
        fn tcp_send(&mut self, conn: &mut SocketAddr, _: &[u8], _: Duration) -> bool {
            self.log.push((self.now.as_secs(), *conn, "tcp"));
            true
        }
        fn tcp_recv(
            &mut self,
            conn: &mut SocketAddr,
            buf: &mut [u8],
            _: Duration,
        ) -> Option<usize> {
            let r = self.tcp.get(conn)?.clone();
            buf[..r.len()].copy_from_slice(&r);
            Some(r.len())
        }
    }

    fn good_reply(q: &[u8]) -> Vec<u8> {
        reply(q, OK, 1, &[rr(PTR_OWNER, 12, &lab(&[b"good"]), 1)])
    }

    fn refused_reply(q: &[u8]) -> Vec<u8> {
        reply(q, [0x81, 0x85], 0, &[])
    }

    fn spurious_reply(q: &[u8]) -> Vec<u8> {
        let mut r = good_reply(q);
        r[1] ^= 1;
        r
    }

    fn tc_reply(q: &[u8]) -> Vec<u8> {
        reply(q, [0x83, 0x80], 0, &[])
    }

    fn run(text: &str, script: &mut Script) -> NssAnswer<String> {
        let c = conf(text);
        query_ptr(
            &c,
            "127.0.0.7".parse().unwrap(),
            script,
            &mut Rotation::default(),
        )
    }

    #[test]
    fn the_send_loop_follows_glibcs_rounds_and_waits() {
        let (a, b, c) = (v4("127.0.0.53"), v4("127.0.0.54"), v4("127.0.0.55"));
        // Two silent servers, two rounds: 4 s (measured 4.05 s).
        let mut s = Script::default();
        let got = run(
            "nameserver 127.0.0.53\nnameserver 127.0.0.54\noptions timeout:1 attempts:2\n",
            &mut s,
        );
        assert_eq!(got, NssAnswer::NotFound);
        assert_eq!(s.now.as_secs(), 4);
        assert_eq!(
            s.log.iter().map(|l| (l.0, l.1)).collect::<Vec<_>>(),
            vec![(0, a), (1, b), (2, a), (3, b)]
        );
        // Three at timeout:2: 2 + 1 + 2 a round (measured 10.04 s).
        let mut s = Script::default();
        run("nameserver 127.0.0.53\nnameserver 127.0.0.54\nnameserver 127.0.0.55\noptions timeout:2 attempts:2\n", &mut s);
        assert_eq!(s.now.as_secs(), 10);
        assert_eq!(
            s.log.iter().map(|l| l.0).collect::<Vec<_>>(),
            vec![0, 2, 3, 5, 7, 8]
        );
        // A refusal moves on at once; the answer of the next is taken.
        let mut s = Script::default();
        s.udp.insert(a, VecDeque::from([vec![Reply::Refused]]));
        s.udp
            .insert(b, VecDeque::from([vec![Reply::After(0, good_reply)]]));
        let got = run(
            "nameserver 127.0.0.53\nnameserver 127.0.0.54\noptions timeout:1 attempts:2\n",
            &mut s,
        );
        assert_eq!(
            (got, s.now.as_secs()),
            (NssAnswer::Success("good".into()), 0)
        );
        // REFUSED as a reply, too; a stranger's reply is waited past.
        let mut s = Script::default();
        s.udp
            .insert(a, VecDeque::from([vec![Reply::After(0, refused_reply)]]));
        s.udp
            .insert(b, VecDeque::from([vec![Reply::After(0, spurious_reply)]]));
        s.udp
            .insert(c, VecDeque::from([vec![Reply::After(0, good_reply)]]));
        let got = run("nameserver 127.0.0.53\nnameserver 127.0.0.54\nnameserver 127.0.0.55\noptions timeout:1 attempts:1\n", &mut s);
        assert_eq!(
            (got, s.now.as_secs()),
            (NssAnswer::Success("good".into()), 1)
        );
        // No attempts: nothing asked.
        let mut s = Script::default();
        assert_eq!(
            run("nameserver 127.0.0.53\noptions attempts:0\n", &mut s),
            NssAnswer::NotFound
        );
        assert!(s.log.is_empty());
    }

    #[test]
    fn a_truncated_reply_moves_every_later_server_to_tcp() {
        let (a, b) = (v4("127.0.0.53"), v4("127.0.0.54"));
        // TC from the first, which takes no TCP: the second over TCP, and
        // no second round (measured).
        let mut s = Script::default();
        s.udp
            .insert(a, VecDeque::from([vec![Reply::After(0, tc_reply)]]));
        let q = ptr_query(0x4242, "127.0.0.7".parse().unwrap(), &ResolvConf::default());
        s.tcp.insert(b, good_reply(&q));
        let got = run(
            "nameserver 127.0.0.53\nnameserver 127.0.0.54\noptions timeout:1 attempts:2\n",
            &mut s,
        );
        assert_eq!(got, NssAnswer::Success("good".into()));
        assert_eq!(s.log, vec![(0, a, "udp"), (0, b, "tcp")]);
        // use-vc: TCP from the start, one round.
        let mut s = Script::default();
        let got = run(
            "nameserver 127.0.0.53\nnameserver 127.0.0.54\noptions timeout:1 attempts:3 use-vc\n",
            &mut s,
        );
        assert_eq!(got, NssAnswer::NotFound);
        assert!(s.log.is_empty());
        // A TCP reply with another id is read past, up to the cap.
        let mut s = Script::default();
        let mut other = good_reply(&q);
        other[0] ^= 1;
        s.tcp.insert(a, other);
        let got = run(
            "nameserver 127.0.0.53\noptions timeout:1 attempts:1 use-vc\n",
            &mut s,
        );
        assert_eq!(got, NssAnswer::NotFound);
    }

    #[test]
    fn rotate_starts_at_a_random_server_then_the_next() {
        let c =
            conf("nameserver 1.1.1.1\nnameserver 1.1.1.2\nnameserver 1.1.1.3\noptions rotate\n");
        let mut r = Rotation::default();
        assert_eq!([r.next(&c, 7), r.next(&c, 0), r.next(&c, 0)], [1, 2, 0]);
        let plain = conf("nameserver 1.1.1.1\nnameserver 1.1.1.2\n");
        assert_eq!(Rotation::default().next(&plain, 7), 0);
    }

    #[test]
    fn unpack_names_bounds_every_pointer() {
        // A pointer to itself, a chain of pointers through the whole
        // message, labels that run off the end: none, and no panic.
        assert_eq!(unpack_name(b"\xc0\x00", 0), None);
        let mut chain: Vec<u8> = Vec::new();
        for i in 0..100u8 {
            chain.extend_from_slice(&[0xc0, (i * 2).wrapping_add(2)]);
        }
        assert_eq!(unpack_name(&chain, 0), None);
        assert_eq!(unpack_name(b"\x05ab", 0), None);
        assert_eq!(unpack_name(b"", 0), None);
        assert_eq!(unpack_name(b"\x01a\0", 3), None);
        assert_eq!(unpack_name(b"\x01a\0", 0), Some((b"\x01a\0".to_vec(), 3)));
        assert_eq!(
            unpack_name(b"\x01a\0\x01b\xc0\x00", 3),
            Some((b"\x01b\x01a\0".to_vec(), 4))
        );
        let _ = Ipv6Addr::LOCALHOST;
    }
}
