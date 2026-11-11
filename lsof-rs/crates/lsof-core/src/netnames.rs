//! Host and service names for `-i`, read as glibc reads them (DIVERGENCES 38).
//!
//! The C resolves a host name with `gethostbyname2(3)`, one address family
//! at a time, and a service name with `getservbyname(3)` (`arg.c`,
//! `lkup_hostnm()` and `enter_network_address()`). Neither is in safe Rust,
//! so this module reads what glibc's `files` service reads, by its rules
//! (`nss/nss_files/files-hosts.c`, `files-service.c` and their
//! `LINE_PARSER`; `resolv/res_hconf.c` for `multi`; `nss/digits_dots.c` and
//! `resolv/inet_addr.c` for a name that is a number), each measured against
//! the C over files bound over `/etc` in a mount namespace. A host name the
//! file does not hold goes to the system's resolver through `std`
//! ([`system_addresses`], `getaddrinfo(3)`), which is what reaches DNS and
//! every other NSS source; a service name has no such route, so a service
//! only another NSS source knows is unknown here.
//!
//! Everything here is a parser over bytes that never panics, but
//! [`system_addresses`] and the readers of files, which the backends call.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The most addresses one lookup keeps: past the C's `MAXNWAD` (100), where
/// `-i` refuses the specification, so that a hosts file of any size is read
/// in bounded memory.
pub const MAX_ADDRESSES: usize = 128;

/// `isspace()` in the C locale.
fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// A line as `__nss_readline()` and `LINE_PARSER` leave it: blanks before
/// it dropped, ended at its `\n`, at a NUL (a C string) or at a `#`; `None`
/// for an empty line or a comment.
///
/// One thing glibc 2.39 does is not done: where blanks open a line that
/// no `\n` ends (a file's last line, or one cut at a NUL), its
/// `__nss_readline()` moves the line over them without its terminator, so
/// the line's last bytes, as many as there were blanks, are read twice
/// (` 127.0.0.1 host` at a file's end names `hostt`; measured). That is a
/// defect of the C library's, and the line is read as written here
/// (DIVERGENCES 38).
fn files_line(line: &[u8]) -> Option<&[u8]> {
    let line = line
        .split(|&b| b == b'\n' || b == 0)
        .next()
        .unwrap_or_default();
    let start = line.iter().position(|&b| !is_space(b))?;
    let line = line.get(start..)?;
    let line = line.split(|&b| b == b'#').next().unwrap_or_default();
    (!line.is_empty()).then_some(line)
}

/// `STRING_FIELD(…, isspace, 1)`: the field up to a blank, and the rest
/// after every blank that follows it.
fn string_field(line: &[u8]) -> (&[u8], &[u8]) {
    let end = line.iter().position(|&b| is_space(b)).unwrap_or(line.len());
    let (field, rest) = line.split_at(end);
    let skip = rest
        .iter()
        .position(|&b| !is_space(b))
        .unwrap_or(rest.len());
    (field, rest.get(skip..).unwrap_or_default())
}

/// The words of a trailing list (`TRAILING_LIST_PARSER`).
fn words(rest: &[u8]) -> impl Iterator<Item = &[u8]> {
    rest.split(|&b| is_space(b)).filter(|w| !w.is_empty())
}

/// One line of a hosts file as glibc's `files` service reads it for a
/// lookup of one family: its address in that family, and the rest of the
/// line (the name, then the aliases).
///
/// For IPv6 a line must hold an IPv6 address. For IPv4 it may hold an IPv4
/// address, a v4-mapped IPv6 one (its IPv4 address) or the IPv6 loopback,
/// which is read as 127.0.0.1: measured, `::1 six` makes `-i @six` list
/// `127.0.0.1`'s sockets.
fn hosts_line(line: &[u8], v6: bool) -> Option<(IpAddr, &[u8])> {
    let line = files_line(line)?;
    let (addr, rest) = string_field(line);
    let addr = std::str::from_utf8(addr).ok()?;
    let ip = if v6 {
        IpAddr::V6(addr.parse::<Ipv6Addr>().ok()?)
    } else if let Ok(v4) = addr.parse::<Ipv4Addr>() {
        IpAddr::V4(v4)
    } else {
        let v6 = addr.parse::<Ipv6Addr>().ok()?;
        match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None if v6 == Ipv6Addr::LOCALHOST => IpAddr::V4(Ipv4Addr::LOCALHOST),
            None => return None,
        }
    };
    Some((ip, rest))
}

/// A search of a hosts file for one name in one family, a line at a time:
/// `_nss_files_gethostbyname3_r()`.
#[derive(Debug)]
pub struct HostsSearch<'a> {
    name: &'a [u8],
    v6: bool,
    multi: bool,
    found: Vec<IpAddr>,
}

impl<'a> HostsSearch<'a> {
    /// A search for `name`, compared as `strcasecmp()` compares it. With
    /// `multi` (`multi on` in `/etc/host.conf`) every line that names it
    /// gives an address; without, only the first.
    pub fn new(name: &'a [u8], v6: bool, multi: bool) -> Self {
        Self {
            name,
            v6,
            multi,
            found: Vec::new(),
        }
    }

    /// Whether the search needs no more lines.
    pub fn done(&self) -> bool {
        (!self.multi && !self.found.is_empty()) || self.found.len() >= MAX_ADDRESSES
    }

    /// Read one line.
    pub fn line(&mut self, line: &[u8]) {
        if self.done() {
            return;
        }
        if let Some((ip, names)) = hosts_line(line, self.v6) {
            // A line with an address alone names the empty name, which no
            // `-i` asks for.
            if words(names).any(|n| n.eq_ignore_ascii_case(self.name)) {
                self.found.push(ip);
            }
        }
    }

    /// The addresses found, in the file's order, a repeat kept as glibc
    /// keeps it.
    pub fn finish(self) -> Vec<IpAddr> {
        self.found
    }
}

/// [`HostsSearch`] over a whole file's bytes.
pub fn hosts_lookup(text: &[u8], name: &[u8], v6: bool, multi: bool) -> Vec<IpAddr> {
    let mut search = HostsSearch::new(name, v6, multi);
    for line in text.split(|&b| b == b'\n') {
        search.line(line);
    }
    search.finish()
}

/// `multi` as `/etc/host.conf` sets it (`res_hconf.c`, `parse_line()` and
/// `arg_bool()`): the last `multi on` or `multi off` line, keyword and value
/// in any case, the value read by its first letters (`multi only` is on).
/// Off when no line sets it.
pub fn host_conf_multi(text: &[u8]) -> bool {
    let mut multi = false;
    for line in text.split(|&b| b == b'\n') {
        let line = line.split(|&b| b == 0).next().unwrap_or_default();
        let start = line
            .iter()
            .position(|&b| !is_space(b))
            .unwrap_or(line.len());
        let line = line.get(start..).unwrap_or_default();
        // `skip_string()`: the keyword ends at a blank, a `#` or a `,`.
        let end = line
            .iter()
            .position(|&b| is_space(b) || b == b'#' || b == b',')
            .unwrap_or(line.len());
        let (keyword, rest) = line.split_at(end);
        if !keyword.eq_ignore_ascii_case(b"multi") {
            continue;
        }
        let skip = rest
            .iter()
            .position(|&b| !is_space(b))
            .unwrap_or(rest.len());
        if let Some(value) = bool_arg(rest.get(skip..).unwrap_or_default()) {
            multi = value;
        }
    }
    multi
}

/// `arg_bool()`: `on` or `off` by its first letters, in any case. Also how
/// `RESOLV_MULTI` in the environment is read, which overrides the file.
pub fn bool_arg(value: &[u8]) -> Option<bool> {
    let starts = |word: &[u8]| {
        value
            .get(..word.len())
            .is_some_and(|v| v.eq_ignore_ascii_case(word))
    };
    if starts(b"on") {
        Some(true)
    } else if starts(b"off") {
        Some(false)
    } else {
        None
    }
}

/// What `/etc/nsswitch.conf` says of a database, as far as this module
/// follows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FilesFirst {
    /// `files` is the first source: the file is read first, by this
    /// module's rules.
    pub first: bool,
    /// `[NOTFOUND=return]` follows it: a name the file does not hold is
    /// looked up nowhere else.
    pub only: bool,
}

/// The sources `text`, an nsswitch.conf, lists for `database`, each word
/// after its `database:` as written (a `[STATUS=action]` among them); `None`
/// when no line gives it, or there is no file at all (`text` empty), where
/// glibc takes its default. The last line for a database is the one it
/// keeps.
pub fn nsswitch_sources<'a>(text: &'a [u8], database: &[u8]) -> Option<Vec<&'a [u8]>> {
    let mut found = None;
    for line in text.split(|&b| b == b'\n') {
        let line = line
            .split(|&b| b == b'#' || b == 0)
            .next()
            .unwrap_or_default();
        let start = line
            .iter()
            .position(|&b| !is_space(b))
            .unwrap_or(line.len());
        let line = line.get(start..).unwrap_or_default();
        let Some(rest) = line.strip_prefix(database) else {
            continue;
        };
        let skip = rest
            .iter()
            .position(|&b| !is_space(b))
            .unwrap_or(rest.len());
        let Some(rest) = rest.get(skip..).and_then(|r| r.strip_prefix(b":")) else {
            continue;
        };
        found = Some(words(rest).collect());
    }
    found
}

/// Whether `files` is the first source `text`, an nsswitch.conf, gives
/// `database`, and whether the search ends there. With no line for it (and
/// for no file at all) glibc's default for hosts is `dns [!UNAVAIL=return]
/// files`, where `files` is not first.
pub fn nsswitch_files_first(text: &[u8], database: &[u8]) -> FilesFirst {
    let sources = nsswitch_sources(text, database).unwrap_or_default();
    let first = sources.first() == Some(&b"files".as_slice());
    let only = first
        && sources.get(1).is_some_and(|action| {
            let action = action.to_ascii_lowercase();
            action.starts_with(b"[")
                && action
                    .windows(b"notfound=return".len())
                    .any(|w| w == b"notfound=return")
                && !action
                    .windows(b"!notfound".len())
                    .any(|w| w == b"!notfound")
        });
    FilesFirst { first, only }
}

/// Whether glibc reads the password file at all for `passwd`: a source of
/// `text`'s `passwd:` line is `files`, or `compat`, which reads it too; and
/// with no line, or no nsswitch.conf, its default is `files`. Measured
/// through `-u name` (DIVERGENCES 39): under `passwd: sss` the C knows no
/// login `/etc/passwd` holds.
pub fn nsswitch_reads_passwd_file(text: &[u8]) -> bool {
    match nsswitch_sources(text, b"passwd") {
        None => true,
        // A line that opens with an action names no source glibc takes.
        Some(sources) => {
            !sources.first().is_some_and(|s| s.starts_with(b"["))
                && sources
                    .iter()
                    .any(|s| *s == b"files".as_slice() || *s == b"compat".as_slice())
        }
    }
}

/// `__inet_aton_exact()`: an IPv4 address in the forms `inet_aton(3)`
/// reads, one to four numbers between dots, each decimal, octal (a leading
/// `0`) or, with `hex`, hexadecimal (`0x`); every number but the last at
/// most 255, and the last filling the bytes that are left (`127.1` is
/// 127.0.0.1, `2130706433` too).
pub fn inet_aton(text: &[u8], hex: bool) -> Option<Ipv4Addr> {
    let mut parts = [0u32; 4];
    let mut count = 0usize;
    let mut rest = text;
    loop {
        let (value, used) = number(rest, hex)?;
        rest = rest.get(used..)?;
        match rest.split_first() {
            Some((b'.', after)) => {
                // Three numbers at most before the last, each a byte.
                if count >= 3 || value > 0xff {
                    return None;
                }
                *parts.get_mut(count)? = value;
                count = count.saturating_add(1);
                rest = after;
            }
            Some(_) => return None,
            None => {
                let max = [0xffff_ffffu32, 0x00ff_ffff, 0xffff, 0xff];
                if value > *max.get(count)? {
                    return None;
                }
                let mut word = value;
                for (i, part) in parts.iter().take(count).enumerate() {
                    let shift = 24u32.checked_sub(u32::try_from(i).ok()?.checked_mul(8)?)?;
                    word |= part.checked_shl(shift)?;
                }
                return Some(Ipv4Addr::from(word));
            }
        }
    }
}

/// `strtoul(text, &end, 0)` where `text` opens with a digit: the value, at
/// most `u32::MAX`, and how many bytes it took.
fn number(text: &[u8], hex: bool) -> Option<(u32, usize)> {
    let first = *text.first()?;
    if !first.is_ascii_digit() {
        return None;
    }
    let is_hex = |b: &u8| b.is_ascii_hexdigit();
    let (radix, skip) = match text {
        [b'0', b'x' | b'X', d, ..] if hex && is_hex(d) => (16u32, 2usize),
        [b'0', ..] => (8, 0),
        _ => (10, 0),
    };
    let digits = text.get(skip..)?;
    let len = digits
        .iter()
        .take_while(|&&b| char::from(b).is_digit(radix))
        .count();
    let mut value = 0u32;
    for &b in digits.get(..len)? {
        value = value
            .checked_mul(radix)?
            .checked_add(char::from(b).to_digit(radix)?)?;
    }
    Some((value, skip.saturating_add(len)))
}

/// A name glibc answers before it asks any NSS source
/// (`__nss_hostname_digits_dots()`): one that opens with a digit, holds
/// digits and dots alone and does not end in a dot. `Some` is the answer:
/// for IPv4 the address `inet_aton()` reads (no hexadecimal: an `x` is no
/// digit), for IPv6 none, since such a name is no IPv6 address. `None` is a
/// name to look up.
pub fn numeric_host(name: &[u8], v6: bool) -> Option<Option<IpAddr>> {
    let numeric = name.first().is_some_and(u8::is_ascii_digit)
        && name.iter().all(|&b| b.is_ascii_digit() || b == b'.')
        && name.last() != Some(&b'.');
    if !numeric {
        return None;
    }
    Some(if v6 {
        None
    } else {
        inet_aton(name, false).map(IpAddr::V4)
    })
}

/// One line of a services file as glibc's `files` service reads it: the
/// port, if the line gives `name` (its name or an alias, compared exactly)
/// for `protocol`.
///
/// The port is read by `strtoul()` in any base C writes a number in
/// (`0x50/tcp` is 80, `010/tcp` 8) and kept to 16 bits, as `htons()` keeps
/// it (`65616/tcp` is 80); a line with no number, with one past 32 bits, or
/// with anything but a `/` or the line's end after it, is skipped. Each
/// measured against glibc 2.39's `getservbyname()`.
fn services_line(line: &[u8], name: &[u8], protocol: &[u8]) -> Option<u16> {
    let line = files_line(line)?;
    let (first, rest) = string_field(line);
    let (value, used) = strtoul0(rest)?;
    let rest = rest.get(used..)?;
    let rest = match rest.first() {
        Some(b'/') => {
            let skip = rest.iter().position(|&b| b != b'/').unwrap_or(rest.len());
            rest.get(skip..)?
        }
        Some(_) => return None,
        None => rest,
    };
    let (proto, aliases) = string_field(rest);
    if proto != protocol {
        return None;
    }
    if first != name && !words(aliases).any(|a| a == name) {
        return None;
    }
    // Past 32 bits the line is refused (`-1` too, which `strtoul()` wraps);
    // within them the port is the low 16, as `htons()` keeps it.
    if value > u64::from(u32::MAX) {
        return None;
    }
    u16::try_from(value & 0xffff).ok()
}

/// `strtoul(s, &end, 0)` on a 64-bit `long`: the value and how many bytes
/// it read, `None` when it read no digit. Blanks first, then a sign, then
/// a number in base 16 (`0x`), 8 (a leading `0`) or 10; past `ULONG_MAX` it
/// is `ULONG_MAX`, and a minus negates modulo 2^64.
fn strtoul0(s: &[u8]) -> Option<(u64, usize)> {
    let mut i = s.iter().take_while(|&&b| is_space(b)).count();
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
    let body = s.get(i..)?;
    let is_hex = |b: &u8| b.is_ascii_hexdigit();
    let (radix, skip) = match body {
        [b'0', b'x' | b'X', d, ..] if is_hex(d) => (16u32, 2usize),
        [b'0', ..] => (8, 0),
        _ => (10, 0),
    };
    let digits = body.get(skip..)?;
    let len = digits
        .iter()
        .take_while(|&&b| char::from(b).is_digit(radix))
        .count();
    if len == 0 {
        return None;
    }
    let mut value = Some(0u64);
    for &b in digits.get(..len)? {
        let d = u64::from(char::from(b).to_digit(radix)?);
        value = value
            .and_then(|v| v.checked_mul(u64::from(radix)))
            .and_then(|v| v.checked_add(d));
    }
    let value = match value {
        None => u64::MAX,
        Some(v) if negative => v.wrapping_neg(),
        Some(v) => v,
    };
    Some((value, i.saturating_add(skip).saturating_add(len)))
}

/// A search of a services file for one name and protocol, a line at a time:
/// `_nss_files_getservbyname_r()`, the first line that gives it.
#[derive(Debug)]
pub struct ServicesSearch<'a> {
    name: &'a [u8],
    protocol: &'a [u8],
    found: Option<u16>,
}

impl<'a> ServicesSearch<'a> {
    pub fn new(name: &'a [u8], protocol: &'a [u8]) -> Self {
        Self {
            name,
            protocol,
            found: None,
        }
    }

    /// Whether the search needs no more lines.
    pub fn done(&self) -> bool {
        self.found.is_some()
    }

    /// Read one line.
    pub fn line(&mut self, line: &[u8]) {
        if self.found.is_none() {
            self.found = services_line(line, self.name, self.protocol);
        }
    }

    /// The port found.
    pub fn finish(self) -> Option<u16> {
        self.found
    }
}

/// [`ServicesSearch`] over a whole file's bytes.
pub fn services_lookup(text: &[u8], name: &[u8], protocol: &[u8]) -> Option<u16> {
    let mut search = ServicesSearch::new(name, protocol);
    for line in text.split(|&b| b == b'\n') {
        search.line(line);
    }
    search.finish()
}

/// Every line of the file at `path`, fed to `each` until it says it is
/// done, as glibc's `__nss_readline()` reads them: up to each `\n`, as
/// bytes. Nothing when it cannot be opened: then it names nothing.
pub fn file_lines(path: &std::path::Path, mut each: impl FnMut(&[u8]) -> bool) {
    use std::io::BufRead;
    let Ok(file) = std::fs::File::open(path) else {
        return;
    };
    let mut reader = std::io::BufReader::new(file);
    let mut line = Vec::new();
    loop {
        line.clear();
        match reader.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {
                if each(&line) {
                    return;
                }
            }
        }
    }
}

/// The whole of a small configuration file, or nothing: at most `limit`
/// bytes of it.
pub fn small_file(path: &std::path::Path, limit: u64) -> Vec<u8> {
    use std::io::Read;
    let mut text = Vec::new();
    if let Ok(file) = std::fs::File::open(path) {
        let _ = file.take(limit).read_to_end(&mut text);
    }
    text
}

/// `name`'s port for `protocol` in the services file at `path`.
pub fn service_in_file(path: &std::path::Path, name: &[u8], protocol: &[u8]) -> Option<u16> {
    let mut search = ServicesSearch::new(name, protocol);
    file_lines(path, |line| {
        search.line(line);
        search.done()
    });
    search.finish()
}

/// `name`'s addresses of one family in the hosts file at `path`.
pub fn hosts_in_file(path: &std::path::Path, name: &[u8], v6: bool, multi: bool) -> Vec<IpAddr> {
    let mut search = HostsSearch::new(name, v6, multi);
    file_lines(path, |line| {
        search.line(line);
        search.done()
    });
    search.finish()
}

/// `name`'s addresses, of both families, from the system's resolver:
/// `getaddrinfo(3)` through `std`, which follows `/etc/nsswitch.conf` to
/// DNS and to every other source, under `/etc/resolv.conf`'s timeouts. In
/// the order it gives them, each once, at most [`MAX_ADDRESSES`]. None for a
/// name it does not resolve, and none under miri, which has no resolver.
pub fn system_addresses(name: &str) -> Vec<IpAddr> {
    let mut found: Vec<IpAddr> = Vec::new();
    if cfg!(miri) || name.is_empty() || name.contains('\0') {
        return found;
    }
    use std::net::ToSocketAddrs;
    if let Ok(addrs) = (name, 0u16).to_socket_addrs() {
        for addr in addrs {
            let ip = addr.ip();
            if !found.contains(&ip) && found.len() < MAX_ADDRESSES {
                found.push(ip);
            }
        }
    }
    found
}

/// `name`'s addresses of one family from the system's resolver alone
/// ([`system_addresses`]): what a backend with no rules of its own for the
/// platform's files answers `-i @name` with. A name that is not UTF-8 names
/// nothing.
pub fn system_host(name: &[u8], v6: bool) -> Vec<IpAddr> {
    let Ok(text) = std::str::from_utf8(name) else {
        return Vec::new();
    };
    system_addresses(text)
        .into_iter()
        .filter(|ip| ip.is_ipv6() == v6)
        .collect()
}

/// The files glibc's host lookup reads.
#[derive(Clone, Copy, Debug)]
pub struct GlibcFiles<'a> {
    pub hosts: &'a std::path::Path,
    pub host_conf: &'a std::path::Path,
    pub nsswitch: &'a std::path::Path,
}

/// A host name's addresses of one family, as glibc's `gethostbyname2()`
/// gives them where this module can follow it:
///
/// 1. a name that is a number is answered as one ([`numeric_host`]);
/// 2. where `/etc/nsswitch.conf` puts `files` first for `hosts`, the hosts
///    file is searched by its rules ([`HostsSearch`]), under `multi` as
///    `/etc/host.conf` and then `multi_env` (`RESOLV_MULTI`) set it;
/// 3. a name not found there goes to `system` ([`system_addresses`]), and
///    its addresses of the family asked for are the answer, unless
///    `getaddrinfo()` would read the name as a number where
///    `gethostbyname2()` does not (`0x7f.1`): that one is unknown.
pub fn glibc_host(
    name: &[u8],
    v6: bool,
    files: &GlibcFiles<'_>,
    multi_env: Option<&[u8]>,
    system: &mut dyn FnMut(&str) -> Vec<IpAddr>,
) -> Vec<IpAddr> {
    if let Some(answer) = numeric_host(name, v6) {
        return answer.into_iter().collect();
    }
    /// Far more than a configuration file holds.
    const CONF_LIMIT: u64 = 1 << 20;
    let order = nsswitch_files_first(&small_file(files.nsswitch, CONF_LIMIT), b"hosts");
    if order.first {
        let multi = multi_env
            .and_then(bool_arg)
            .unwrap_or_else(|| host_conf_multi(&small_file(files.host_conf, CONF_LIMIT)));
        let found = hosts_in_file(files.hosts, name, v6, multi);
        if !found.is_empty() || order.only {
            return found;
        }
    }
    if inet_aton(name, true).is_some() {
        return Vec::new();
    }
    let Ok(text) = std::str::from_utf8(name) else {
        return Vec::new();
    };
    system(text)
        .into_iter()
        .filter(|ip| ip.is_ipv6() == v6)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ips(all: &[&str]) -> Vec<IpAddr> {
        all.iter().map(|ip| ip.parse().unwrap()).collect()
    }

    /// The hosts file the C was measured over (bound over `/etc/hosts`,
    /// `hosts: files dns` with no name server answering), and what its
    /// `gethostbyname2()` gave each name in each family, with `multi on`
    /// and with `multi off`: counted through `-i`'s address limit, and
    /// listed through the sockets `-i @name` selected.
    const HOSTS: &[u8] = b"127.0.0.1 localhost
::1 localhost ip6-localhost ip6-loopback
127.0.0.2 two alias2
127.0.0.3 multi
127.0.0.1 multi
::1 six
127.0.0.2 dual
::1 dual
::ffff:127.0.0.3 mapped
0.0.0.0 zero
::1 six2
::2 six2
fe80::1 six3
127.0.0.9 v4first
::9 v4first
1.2.3.4 UPPER.Example.COM upper
::5 sixz
";

    #[test]
    fn a_hosts_file_is_searched_as_glibc_searches_it() {
        for (name, v6, multi, want) in [
            // The IPv6 loopback is 127.0.0.1 to an IPv4 lookup, and a
            // repeat is kept.
            ("localhost", false, true, &["127.0.0.1", "127.0.0.1"][..]),
            ("localhost", false, false, &["127.0.0.1"]),
            ("localhost", true, true, &["::1"]),
            ("two", false, true, &["127.0.0.2"]),
            ("two", true, true, &[]),
            ("alias2", false, false, &["127.0.0.2"]),
            ("multi", false, true, &["127.0.0.3", "127.0.0.1"]),
            ("multi", false, false, &["127.0.0.3"]),
            ("multi", true, true, &[]),
            ("six", false, false, &["127.0.0.1"]),
            ("six", true, false, &["::1"]),
            ("dual", false, true, &["127.0.0.2", "127.0.0.1"]),
            ("dual", false, false, &["127.0.0.2"]),
            ("dual", true, true, &["::1"]),
            // A v4-mapped address is its IPv4 address to an IPv4 lookup.
            ("mapped", false, true, &["127.0.0.3"]),
            ("mapped", true, true, &["::ffff:127.0.0.3"]),
            ("zero", false, true, &["0.0.0.0"]),
            // Any other IPv6 address is none to an IPv4 lookup.
            ("six2", false, true, &["127.0.0.1"]),
            ("six2", true, true, &["::1", "::2"]),
            ("six2", true, false, &["::1"]),
            ("six3", false, true, &[]),
            ("six3", true, true, &["fe80::1"]),
            ("v4first", true, true, &["::9"]),
            ("v4first", false, true, &["127.0.0.9"]),
            // In any case, and by every name on the line; a name with a
            // dot after it is another name.
            ("LOCALHOST", true, false, &["::1"]),
            ("upper", false, false, &["1.2.3.4"]),
            ("UPPER", false, false, &["1.2.3.4"]),
            ("upper.example.com", false, false, &["1.2.3.4"]),
            ("upper.example.com.", false, false, &[]),
            ("ip6-loopback", true, false, &["::1"]),
            ("nosuch", false, true, &[]),
            ("", false, true, &[]),
        ] {
            assert_eq!(
                hosts_lookup(HOSTS, name.as_bytes(), v6, multi),
                ips(want),
                "{name} v6={v6} multi={multi}"
            );
        }
    }

    /// A line's shape, as glibc's `LINE_PARSER` takes it (each measured
    /// against `gethostbyname2()`, 13,800 lookups over generated files
    /// agreeing).
    #[test]
    fn a_hosts_line_is_read_by_the_files_rules() {
        let v4 = |text: &[u8], name: &str| hosts_lookup(text, name.as_bytes(), false, true);
        // Blanks of every kind part the fields and may open the line.
        assert_eq!(
            v4(b"\t 10.0.0.1\x0bh\x0calias\rlast \n", "h"),
            ips(&["10.0.0.1"])
        );
        assert_eq!(
            v4(b"10.0.0.1\x0bh\x0calias\rlast \n", "alias"),
            ips(&["10.0.0.1"])
        );
        assert_eq!(
            v4(b"10.0.0.1\x0bh\x0calias\rlast \n", "last"),
            ips(&["10.0.0.1"])
        );
        // A comment ends the line, and may open it.
        assert_eq!(v4(b"10.0.0.1 h # alias\n", "alias"), ips(&[]));
        assert_eq!(v4(b"10.0.0.1 h#x alias\n", "h"), ips(&["10.0.0.1"]));
        assert_eq!(v4(b"#10.0.0.1 h\n  # 10.0.0.2 h\n", "h"), ips(&[]));
        // So does a NUL, as it ends a C string.
        assert_eq!(v4(b"10.0.0.1 h\0 alias\n", "alias"), ips(&[]));
        assert_eq!(v4(b"10.0.0.1 h\0 alias\n", "h"), ips(&["10.0.0.1"]));
        // The last line needs no newline.
        assert_eq!(v4(b"10.0.0.1 h", "h"), ips(&["10.0.0.1"]));
        // A name twice on a line is one address.
        assert_eq!(v4(b"10.0.0.1 h h\n", "h"), ips(&["10.0.0.1"]));
        // What `inet_pton()` refuses is no line: a short form, a leading
        // zero, a scope, a fifth number, an octet past 255, no address.
        for bad in [
            "1.2.3",
            "01.2.3.4",
            "1.2.3.4.5",
            "256.1.1.1",
            "fe80::1%lo",
            "1::2::3",
            "127.0.0.1x",
            "0x7f.0.0.1",
            "\u{e9}",
        ] {
            assert_eq!(v4(format!("{bad} h\n").as_bytes(), "h"), ips(&[]), "{bad}");
        }
        assert_eq!(v4(b"h\n", "h"), ips(&[]));
        assert_eq!(v4(b"\xff h\n", "h"), ips(&[]));
        assert_eq!(v4(b"::0.0.0.1 h\n", "h"), ips(&["127.0.0.1"]));
        assert_eq!(v4(b"::1.2.3.4 h\n", "h"), ips(&[]));
        assert_eq!(v4(b"::ffff:0.0.0.0 h\n", "h"), ips(&["0.0.0.0"]));
        // A name is compared as bytes, ASCII letters in any case.
        assert_eq!(v4(b"10.0.0.1 n\xc3\xa9\n", "n\u{e9}"), ips(&["10.0.0.1"]));
        assert_eq!(v4(b"10.0.0.1 n\xc3\x89\n", "n\u{e9}"), ips(&[]));
    }

    #[test]
    fn a_search_keeps_a_bounded_number_of_addresses() {
        let mut text = Vec::new();
        for i in 0..1000 {
            text.extend_from_slice(format!("10.0.{}.{} many\n", i / 256, i % 256).as_bytes());
        }
        let found = hosts_lookup(&text, b"many", false, true);
        assert_eq!(found.len(), MAX_ADDRESSES);
        assert_eq!(found.first(), Some(&"10.0.0.0".parse().unwrap()));
        assert_eq!(hosts_lookup(&text, b"many", false, false).len(), 1);
        let mut search = HostsSearch::new(b"many", false, false);
        assert!(!search.done());
        search.line(b"10.0.0.1 many\n");
        assert!(search.done());
        search.line(b"10.0.0.2 many\n");
        assert_eq!(search.finish(), ips(&["10.0.0.1"]));
    }

    #[test]
    fn multi_is_read_as_res_hconf_reads_it() {
        for (text, want) in [
            (&b""[..], false),
            (b"multi on\n", true),
            (b"multi off\n", false),
            (b"order hosts,bind\nmulti on\n", true),
            (b"  MULTI   ON\n", true),
            (b"multi only\n", true),
            (b"multi offer\n", false),
            (b"multi on\nmulti off\n", false),
            (b"multi off\nmulti on # yes\n", true),
            (b"# multi on\n", false),
            (b"multion\n", false),
            (b"multi\n", false),
            (b"multi yes\n", false),
            (b"multi on\nmulti yes\n", true),
            (b"multi\ton", true),
            (b"multi,on\n", false),
            (b"nomulti on\n", false),
        ] {
            assert_eq!(
                host_conf_multi(text),
                want,
                "{:?}",
                String::from_utf8_lossy(text)
            );
        }
        assert_eq!(bool_arg(b"on"), Some(true));
        assert_eq!(bool_arg(b"OFF"), Some(false));
        assert_eq!(bool_arg(b"only"), Some(true));
        assert_eq!(bool_arg(b"o"), None);
        assert_eq!(bool_arg(b""), None);
        assert_eq!(bool_arg(b"yes"), None);
    }

    #[test]
    fn nsswitch_says_whether_files_comes_first() {
        let order = |text: &[u8]| {
            let o = nsswitch_files_first(text, b"hosts");
            (o.first, o.only)
        };
        assert_eq!(order(b""), (false, false));
        assert_eq!(order(b"passwd: files\n"), (false, false));
        assert_eq!(order(b"hosts: files dns\n"), (true, false));
        assert_eq!(order(b"hosts:files\n"), (true, false));
        assert_eq!(order(b"  hosts :\tfiles\n"), (true, false));
        assert_eq!(order(b"hosts: dns files\n"), (false, false));
        assert_eq!(order(b"hosts: files [NOTFOUND=return] dns\n"), (true, true));
        assert_eq!(order(b"hosts: files [notfound=RETURN] dns\n"), (true, true));
        assert_eq!(
            order(b"hosts: files [!NOTFOUND=return] dns\n"),
            (true, false)
        );
        assert_eq!(order(b"hosts: files [UNAVAIL=return] dns\n"), (true, false));
        assert_eq!(order(b"hosts: mymachines files\n"), (false, false));
        assert_eq!(order(b"#hosts: files\n"), (false, false));
        assert_eq!(order(b"hosts: files # dns\n"), (true, false));
        assert_eq!(order(b"hostsx: files\n"), (false, false));
        assert_eq!(order(b"hosts files\n"), (false, false));
        // The last line for a database is the one kept.
        assert_eq!(order(b"hosts: files\nhosts: dns\n"), (false, false));
        assert_eq!(order(b"hosts: dns\nhosts: files\n"), (true, false));
        assert!(!nsswitch_files_first(b"services: db files\n", b"services").first);
        assert_eq!(
            nsswitch_sources(b"hosts:\tfiles [NOTFOUND=return] dns # x\n", b"hosts"),
            Some(vec![&b"files"[..], b"[NOTFOUND=return]", b"dns"])
        );
        assert_eq!(nsswitch_sources(b"hosts:\n", b"hosts"), Some(vec![]));
        assert_eq!(nsswitch_sources(b"group: files\n", b"hosts"), None);
    }

    /// Whether the password file is read at all, as `-u name` shows the C
    /// reading it (DIVERGENCES 39; each line measured).
    #[test]
    fn nsswitch_says_whether_the_password_file_is_read() {
        for (text, want) in [
            (&b""[..], true),
            (b"hosts: files\n", true),
            (b"passwd: files\n", true),
            (b"passwd: files systemd\n", true),
            (b"passwd: db files\n", true),
            (b"passwd: sss files\n", true),
            (b"passwd: sss [NOTFOUND=return] files\n", true),
            (b"passwd: compat\n", true),
            (b"passwd: sss\n", false),
            (b"passwd: dns\n", false),
            (b"passwd:\n", false),
            (b"passwd: files\npasswd: sss\n", false),
            (b"passwd: sss\npasswd: files\n", true),
            (b"passwd: nosuchsource files\n", true),
            (b"passwd: FILES\n", false),
            (b"passwd: [NOTFOUND=return] files\n", false),
            (b"#passwd: sss\n", true),
        ] {
            assert_eq!(
                nsswitch_reads_passwd_file(text),
                want,
                "{:?}",
                String::from_utf8_lossy(text)
            );
        }
    }

    /// `inet_aton()`'s forms and `__nss_hostname_digits_dots()`'s rule, each
    /// measured against `gethostbyname2()` (4,354 names agreeing) and
    /// through `-i @name`.
    #[test]
    fn a_name_that_is_a_number_is_answered_as_one() {
        let v4 = |name: &str| numeric_host(name.as_bytes(), false);
        let is = |ip: &str| Some(Some(ip.parse::<IpAddr>().unwrap()));
        assert_eq!(v4("127.1"), is("127.0.0.1"));
        assert_eq!(v4("1.2.3"), is("1.2.0.3"));
        assert_eq!(v4("2130706433"), is("127.0.0.1"));
        assert_eq!(v4("4294967295"), is("255.255.255.255"));
        assert_eq!(v4("0177.1"), is("127.0.0.1"));
        assert_eq!(v4("00.1"), is("0.0.0.1"));
        assert_eq!(v4("0"), is("0.0.0.0"));
        assert_eq!(v4("1.2.3.04"), is("1.2.3.4"));
        assert_eq!(v4("127.1.65535"), is("127.1.255.255"));
        assert_eq!(v4("127.16777215"), is("127.255.255.255"));
        // A number, and not an address: unknown, with no source asked.
        for name in [
            "4294967296",
            "256.1",
            "1.256.1",
            "127.65536.1",
            "127.1.65536",
            "127.16777216",
            "1.2.3.256",
            "1.2.3.4.5",
            "08.1",
            "1..2",
            "4294967297.0.0.1",
            "99999999999999999999.1",
        ] {
            assert_eq!(v4(name), Some(None), "{name}");
        }
        // No IPv6 address is digits and dots.
        assert_eq!(numeric_host(b"127.1", true), Some(None));
        // A name to look up: a letter in it (an `x` too), a dot at its
        // end, no digit at its start.
        for name in [
            "0x7f.1",
            "127.1.",
            "1a",
            "a1",
            ".1",
            "localhost",
            "",
            "1.2.3.4x",
        ] {
            assert_eq!(v4(name), None, "{name}");
            assert_eq!(numeric_host(name.as_bytes(), true), None, "{name}");
        }
        // `getaddrinfo()` reads hexadecimal too, which is why such a name
        // is not handed to it.
        assert_eq!(inet_aton(b"0x7f.1", true), Some(Ipv4Addr::LOCALHOST));
        assert_eq!(inet_aton(b"0X7F.0.0.1", true), Some(Ipv4Addr::LOCALHOST));
        assert_eq!(inet_aton(b"0x7f.1", false), None);
        assert_eq!(inet_aton(b"0x", true), None);
        assert_eq!(inet_aton(b"0xg", true), None);
        assert_eq!(inet_aton(b"0x100000000", true), None);
        assert_eq!(inet_aton(b"", true), None);
        assert_eq!(inet_aton(b"1.2.3.4.", true), None);
        assert_eq!(inet_aton(b"localhost", true), None);
    }

    /// A services file, as `getservbyname()` reads it (measured, with the
    /// hosts lines).
    #[test]
    fn a_services_file_is_searched_as_glibc_searches_it() {
        let text = b"# comment
svc\t18080/tcp\tweb alt # c
svc 18080/udp
both 18081/tcp
both 18082/udp
da-sh 18083/tcp
hex 0x50/tcp
oct 010/tcp
wide 65616/tcp
max 4294967295/tcp
past 4294967296/tcp
neg -1/tcp
zero -0/tcp
plus +81/tcp
none 10
bare 11/
two 12//tcp
odd 13/tcp/x
bad8 08/tcp
badx 0x/tcp
gap 14 /tcp
gap2 15/ tcp
sp  16/tcp
  lead 17/tcp
nul 18/tcp\0 hidden
last 19/tcp";
        let port =
            |name: &str, proto: &str| services_lookup(text, name.as_bytes(), proto.as_bytes());
        for (name, proto, want) in [
            ("svc", "tcp", Some(18080)),
            ("svc", "udp", Some(18080)),
            ("svc", "udplite", None),
            ("web", "tcp", Some(18080)),
            ("alt", "tcp", Some(18080)),
            ("web", "udp", None),
            ("c", "tcp", None),
            ("SVC", "tcp", None),
            ("svc", "TCP", None),
            ("both", "tcp", Some(18081)),
            ("both", "udp", Some(18082)),
            ("da-sh", "tcp", Some(18083)),
            ("hex", "tcp", Some(80)),
            ("oct", "tcp", Some(8)),
            ("wide", "tcp", Some(80)),
            ("max", "tcp", Some(65535)),
            ("past", "tcp", None),
            ("neg", "tcp", None),
            ("zero", "tcp", Some(0)),
            ("plus", "tcp", Some(81)),
            ("none", "tcp", None),
            ("none", "", Some(10)),
            ("bare", "", Some(11)),
            ("two", "tcp", Some(12)),
            ("odd", "tcp", None),
            ("odd", "tcp/x", Some(13)),
            ("bad8", "tcp", None),
            ("badx", "tcp", None),
            ("gap", "tcp", None),
            ("gap2", "tcp", None),
            ("gap2", "", Some(15)),
            ("sp", "tcp", Some(16)),
            ("lead", "tcp", Some(17)),
            ("nul", "tcp", Some(18)),
            ("hidden", "tcp", None),
            ("last", "tcp", Some(19)),
            ("nosuch", "tcp", None),
        ] {
            assert_eq!(port(name, proto), want, "{name}/{proto}");
        }
        // The first line that gives the name wins.
        assert_eq!(
            services_lookup(b"a 1/tcp\nb 2/tcp a\na 3/tcp\n", b"a", b"tcp"),
            Some(1)
        );
        let mut search = ServicesSearch::new(b"a", b"tcp");
        assert!(!search.done());
        search.line(b"b 2/tcp a\n");
        assert!(search.done());
        search.line(b"a 3/tcp\n");
        assert_eq!(search.finish(), Some(2));
    }

    /// The whole lookup over files of its own, with a resolver that records
    /// what it is asked (no test asks the system's).
    #[test]
    #[cfg_attr(miri, ignore = "it writes and reads files, slowly under miri")]
    fn a_host_is_looked_up_in_the_files_and_then_by_the_system() {
        let dir = std::env::temp_dir().join(format!("lsof-rs-netnames-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (hosts, conf, nss) = (
            dir.join("hosts"),
            dir.join("host.conf"),
            dir.join("nsswitch.conf"),
        );
        std::fs::write(&hosts, HOSTS).unwrap();
        let files = GlibcFiles {
            hosts: &hosts,
            host_conf: &conf,
            nsswitch: &nss,
        };
        let asked = std::cell::RefCell::new(Vec::new());
        let lookup = |name: &str, v6: bool, env: Option<&[u8]>| {
            let mut system = |n: &str| {
                asked.borrow_mut().push(n.to_string());
                ips(&["10.9.9.9", "fd00::9", "10.9.9.8"])
            };
            glibc_host(name.as_bytes(), v6, &files, env, &mut system)
        };
        let take = || std::mem::take(&mut *asked.borrow_mut());

        // `files` first: the file answers, under `multi` as host.conf and
        // then the environment set it, and the system is not asked.
        std::fs::write(&nss, "hosts: files dns\n").unwrap();
        std::fs::write(&conf, "multi on\n").unwrap();
        assert_eq!(
            lookup("multi", false, None),
            ips(&["127.0.0.3", "127.0.0.1"])
        );
        assert_eq!(lookup("multi", false, Some(b"off")), ips(&["127.0.0.3"]));
        assert_eq!(
            lookup("multi", false, Some(b"bad")),
            ips(&["127.0.0.3", "127.0.0.1"])
        );
        std::fs::write(&conf, "multi off\n").unwrap();
        assert_eq!(lookup("multi", false, None), ips(&["127.0.0.3"]));
        assert_eq!(
            lookup("multi", false, Some(b"on")),
            ips(&["127.0.0.3", "127.0.0.1"])
        );
        std::fs::remove_file(&conf).unwrap();
        assert_eq!(lookup("multi", false, None), ips(&["127.0.0.3"]));
        assert_eq!(take(), Vec::<String>::new());
        // A name the file lacks in that family goes to the system, whose
        // addresses of the family are the answer, in its order.
        assert_eq!(lookup("two", true, None), ips(&["fd00::9"]));
        assert_eq!(
            lookup("elsewhere", false, None),
            ips(&["10.9.9.9", "10.9.9.8"])
        );
        assert_eq!(take(), ["two", "elsewhere"]);
        // Unless nsswitch.conf ends the search at the file.
        std::fs::write(&nss, "hosts: files [NOTFOUND=return] dns\n").unwrap();
        assert_eq!(lookup("elsewhere", false, None), ips(&[]));
        assert_eq!(lookup("two", false, None), ips(&["127.0.0.2"]));
        assert_eq!(take(), Vec::<String>::new());
        // A number is answered before anything is read or asked.
        assert_eq!(lookup("127.1", false, None), ips(&["127.0.0.1"]));
        assert_eq!(lookup("127.1", true, None), ips(&[]));
        assert_eq!(lookup("256.1", false, None), ips(&[]));
        std::fs::write(&nss, "hosts: files dns\n").unwrap();
        // What `getaddrinfo()` alone reads as a number is no name to ask
        // it, nor is one that is not UTF-8.
        assert_eq!(lookup("0x7f.1", false, None), ips(&[]));
        assert_eq!(
            glibc_host(b"h\xff", false, &files, None, &mut |_| ips(&["10.9.9.9"])),
            ips(&[])
        );
        assert_eq!(take(), Vec::<String>::new());
        // `files` not first, or no nsswitch.conf at all: the system's
        // resolver answers, which reads the file in its own way.
        std::fs::write(&nss, "hosts: dns files\n").unwrap();
        assert_eq!(lookup("two", false, None), ips(&["10.9.9.9", "10.9.9.8"]));
        std::fs::remove_file(&nss).unwrap();
        assert_eq!(lookup("two", false, None), ips(&["10.9.9.9", "10.9.9.8"]));
        assert_eq!(take(), ["two", "two"]);
        // The files' readers.
        assert_eq!(
            hosts_in_file(&hosts, b"dual", false, true),
            ips(&["127.0.0.2", "127.0.0.1"])
        );
        assert_eq!(
            hosts_in_file(&dir.join("nosuch"), b"dual", false, true),
            ips(&[])
        );
        std::fs::write(&conf, "x 7/tcp\ny 8/tcp\n").unwrap();
        assert_eq!(service_in_file(&conf, b"y", b"tcp"), Some(8));
        assert_eq!(service_in_file(&dir.join("nosuch"), b"y", b"tcp"), None);
        assert_eq!(small_file(&conf, 3), b"x 7");
        assert_eq!(small_file(&dir.join("nosuch"), 3), b"");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The system's resolver is asked nothing for what is no name, and
    /// nothing at all under miri.
    #[test]
    fn the_system_is_not_asked_for_what_is_no_name() {
        assert_eq!(system_addresses(""), ips(&[]));
        assert_eq!(system_addresses("a\0b"), ips(&[]));
        assert_eq!(system_host(b"\xff", false), ips(&[]));
    }
}
