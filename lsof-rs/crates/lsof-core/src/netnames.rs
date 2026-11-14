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

/// `multi` as `/etc/host.conf` sets it (`res_hconf.c`, `_res_hconf_init()`,
/// `parse_line()` and `arg_bool()`): the last `multi on` or `multi off`
/// line, keyword and value in any case, the value read by its first letters
/// (`multi only` is on). Off when no line sets it.
///
/// glibc reads the file with `fgets()` into 256 bytes, so what it takes
/// for a line is at most 255 bytes of one: the rest of a longer line is the
/// next (a comment of 255 bytes with `multi on` after it on its line turns
/// `multi` on; measured).
///
/// Its keyword also ends at a `#` or a `,`, and its line at a NUL; neither
/// is looked for here, because neither changes the answer: what follows
/// the keyword must open with `on` or `off` to count.
pub fn host_conf_multi(text: &[u8]) -> bool {
    /// What one `fgets(buf, 256, fp)` reads at most.
    const FGETS: usize = 255;
    let mut multi = false;
    let mut rest = text;
    while !rest.is_empty() {
        let window = rest.get(..FGETS).unwrap_or(rest);
        let (line, len) = match window.iter().position(|&b| b == b'\n') {
            Some(at) => (window.get(..at).unwrap_or_default(), at.saturating_add(1)),
            None => (window, window.len()),
        };
        rest = rest.get(len..).unwrap_or_default();
        let (keyword, value) = nss_word(skip_spaces(line), is_space);
        if keyword.eq_ignore_ascii_case(b"multi") {
            if let Some(value) = bool_arg(skip_spaces(value)) {
                multi = value;
            }
        }
    }
    multi
}

/// `TRIMDOMAINS_MAX`: the most domains `trim` lines and the environment
/// keep, all together; glibc warns of one past it and keeps none of the
/// rest of its list.
pub const TRIMDOMAINS_MAX: usize = 4;

/// What one `fgets(buf, 256, fp)` of `/etc/host.conf` reads at most.
const HOST_CONF_FGETS: usize = 255;

/// The domains `trim` lines of `/etc/host.conf` (`text`) give, as glibc
/// 2.39's `_res_hconf_init()` reads them (`parse_line()`,
/// `arg_trimdomain_list()`), each rule measured through the C:
///
/// * a line is what one `fgets()` into 256 bytes reads (as for
///   [`host_conf_multi`]), to its `\n` or a NUL;
/// * its keyword, after blanks, ends at a blank, a `#` or a `,`, and is
///   `trim` in any case;
/// * each domain ends at a blank, a `#` or a `,`; blanks after it, then one
///   of `,` `;` `:` and blanks, separate it from the next (so `.a;.b` is one
///   domain, `.a ;.b` two), and a `#` ends the list;
/// * at most [`TRIMDOMAINS_MAX`] are kept, every line's together.
pub fn host_conf_trim(text: &[u8]) -> Vec<Vec<u8>> {
    let mut domains = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        let window = rest.get(..HOST_CONF_FGETS).unwrap_or(rest);
        let (line, len) = match window.iter().position(|&b| b == b'\n') {
            Some(at) => (window.get(..at).unwrap_or_default(), at.saturating_add(1)),
            None => (window, window.len()),
        };
        rest = rest.get(len..).unwrap_or_default();
        let line = line.split(|&b| b == 0).next().unwrap_or_default();
        let line = skip_spaces(line);
        if line.first().is_none_or(|&b| b == b'#') {
            continue;
        }
        let (keyword, args) = nss_word(line, ends_a_hconf_string);
        if keyword.eq_ignore_ascii_case(b"trim") {
            trim_domain_list(&mut domains, skip_spaces(args));
        }
    }
    domains
}

/// `skip_string()`'s end of a word: a blank, a `#` or a `,`.
fn ends_a_hconf_string(b: u8) -> bool {
    is_space(b) || b == b'#' || b == b','
}

/// `arg_trimdomain_list()`: the domains of `args` added to `domains`,
/// within [`TRIMDOMAINS_MAX`].
fn trim_domain_list(domains: &mut Vec<Vec<u8>>, args: &[u8]) {
    let mut rest = args.split(|&b| b == 0).next().unwrap_or_default();
    loop {
        let (domain, after) = nss_word(rest, ends_a_hconf_string);
        if domains.len() >= TRIMDOMAINS_MAX {
            return;
        }
        domains.push(domain.to_vec());
        rest = skip_spaces(after);
        if let Some((b',' | b';' | b':', after)) = rest.split_first() {
            rest = skip_spaces(after);
            if rest.first().is_none_or(|&b| b == b'#') {
                return;
            }
        }
        if rest.first().is_none_or(|&b| b == b'#') {
            return;
        }
    }
}

/// The trim domains a run uses: `/etc/host.conf`'s (`file`), then
/// `RESOLV_ADD_TRIM_DOMAINS` (`add`) after them, then
/// `RESOLV_OVERRIDE_TRIM_DOMAINS` (`replace`) in their place, as glibc's
/// `_res_hconf_init()` reads them, in that order (measured with both set:
/// the second's alone). glibc's loader leaves both variables in a
/// set-user-ID program's environment.
pub fn trim_domains(file: &[u8], add: Option<&[u8]>, replace: Option<&[u8]>) -> Vec<Vec<u8>> {
    let mut domains = host_conf_trim(file);
    if let Some(add) = add {
        trim_domain_list(&mut domains, add);
    }
    if let Some(replace) = replace {
        domains.clear();
        trim_domain_list(&mut domains, replace);
    }
    domains
}

/// `_res_hconf_trim_domain()`: `name` cut at the first of `domains` that
/// ends it, compared in any case, where the name is longer than the
/// domain; no dot is added or taken (`trim example.com` makes
/// `a.example.com` `a.`).
pub fn trim_domain(name: &mut Vec<u8>, domains: &[Vec<u8>]) {
    for domain in domains {
        if name.len() > domain.len() {
            let at = name.len() - domain.len();
            if name
                .get(at..)
                .is_some_and(|tail| tail.eq_ignore_ascii_case(domain))
            {
                name.truncate(at);
                return;
            }
        }
    }
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

/// What glibc does where a source answered with a status
/// (`nss/nsswitch.h`, `lookup_actions`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NssAction {
    Return,
    Continue,
    Merge,
}

/// How a source answers a lookup (`enum nss_status`, but for
/// `NSS_STATUS_RETURN`, which no lookup here gives).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NssStatus {
    Success,
    NotFound,
    Unavail,
    TryAgain,
}

/// One source of a database's line in nsswitch.conf, and its
/// `[STATUS=action]` items: `return` on success and `continue` otherwise
/// where the line says nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NssSource<'a> {
    /// The source's name as written (`files`, `dns`, `sss`): glibc loads
    /// `libnss_NAME.so.2` for it, so its case matters.
    pub module: &'a [u8],
    actions: [NssAction; 4],
}

impl<'a> NssSource<'a> {
    fn new(module: &'a [u8]) -> Self {
        let mut actions = [NssAction::Continue; 4];
        if let Some(a) = actions.first_mut() {
            *a = NssAction::Return;
        }
        Self { module, actions }
    }

    fn slot(status: NssStatus) -> usize {
        match status {
            NssStatus::Success => 0,
            NssStatus::NotFound => 1,
            NssStatus::Unavail => 2,
            NssStatus::TryAgain => 3,
        }
    }

    /// What follows `status` from this source.
    pub fn on(&self, status: NssStatus) -> NssAction {
        self.actions
            .get(Self::slot(status))
            .copied()
            .unwrap_or(NssAction::Continue)
    }

    fn set(&mut self, status: NssStatus, action: NssAction) {
        if let Some(a) = self.actions.get_mut(Self::slot(status)) {
            *a = action;
        }
    }
}

/// The databases glibc 2.39 reads from nsswitch.conf
/// (`nss/databases.def`): a line for any other name is not looked at.
const NSS_DATABASES: [&[u8]; 17] = [
    b"aliases",
    b"ethers",
    b"group",
    b"group_compat",
    b"gshadow",
    b"hosts",
    b"initgroups",
    b"netgroup",
    b"networks",
    b"passwd",
    b"passwd_compat",
    b"protocols",
    b"publickey",
    b"rpc",
    b"services",
    b"shadow",
    b"shadow_compat",
];

fn skip_spaces(line: &[u8]) -> &[u8] {
    let skip = line
        .iter()
        .position(|&b| !is_space(b))
        .unwrap_or(line.len());
    line.get(skip..).unwrap_or_default()
}

/// The word that opens `line`, up to a byte `ends` takes, and the rest.
fn nss_word(line: &[u8], ends: impl Fn(u8) -> bool) -> (&[u8], &[u8]) {
    let end = line.iter().position(|&b| ends(b)).unwrap_or(line.len());
    line.split_at(end)
}

/// glibc's `nss_action_parse()`: the sources a database's line lists, each
/// with the actions a `[STATUS=action …]` after it sets (`!STATUS` sets
/// every other status). `None` for a line it refuses: a status or an action
/// it does not know, a `[` that nothing closes. There is no comment: a `#`
/// is a source's name like any other word (measured: under `passwd: sss #
/// files` the password file is read). What follows a `[` that no source
/// precedes is not read.
fn nss_action_parse(mut line: &[u8], keep: bool) -> Option<Vec<NssSource<'_>>> {
    let mut sources = Vec::new();
    loop {
        line = skip_spaces(line);
        let (module, rest) = nss_word(line, |b| is_space(b) || b == b'[');
        if module.is_empty() {
            return Some(sources);
        }
        let mut source = NssSource::new(module);
        line = skip_spaces(rest);
        if let Some(rest) = line.strip_prefix(b"[") {
            line = skip_spaces(rest);
            loop {
                let not = line.first() == Some(&b'!');
                if not {
                    line = line.get(1..).unwrap_or_default();
                }
                let ends = |b: u8| is_space(b) || b == b'=' || b == b']';
                let (name, rest) = nss_word(line, ends);
                let status = [
                    (&b"SUCCESS"[..], NssStatus::Success),
                    (b"UNAVAIL", NssStatus::Unavail),
                    (b"NOTFOUND", NssStatus::NotFound),
                    (b"TRYAGAIN", NssStatus::TryAgain),
                ]
                .into_iter()
                .find(|(word, _)| name.eq_ignore_ascii_case(word))?
                .1;
                line = skip_spaces(skip_spaces(rest).strip_prefix(b"=")?);
                let (name, rest) = nss_word(line, ends);
                let action = [
                    (&b"RETURN"[..], NssAction::Return),
                    (b"CONTINUE", NssAction::Continue),
                    (b"MERGE", NssAction::Merge),
                ]
                .into_iter()
                .find(|(word, _)| name.eq_ignore_ascii_case(word))?
                .1;
                if not {
                    let kept = source.on(status);
                    source.actions = [action; 4];
                    source.set(status, kept);
                } else {
                    source.set(status, action);
                }
                line = skip_spaces(rest);
                if let Some(rest) = line.strip_prefix(b"]") {
                    line = rest;
                    break;
                }
            }
        }
        if keep {
            sources.push(source);
        }
    }
}

/// A configuration file as it was found ([`conf_file`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Conf {
    /// No file, or none that can be opened.
    Missing,
    /// It is there and cannot be read: a directory, or anything else that
    /// is no regular file but the null device (which is an empty file).
    Unreadable,
    /// Its bytes.
    Text(Vec<u8>),
}

/// The sources nsswitch.conf gives `database`, in its order, as glibc 2.39
/// reads the file (`nss/nss_database.c`; each rule measured through
/// `getent` and through the C, DIVERGENCES 38 and 39):
///
/// * with no file, and for a database no line names, `default`: what glibc
///   has built in for it;
/// * a line is read to its `\n`, or to a NUL; one that no `\n` ends (a
///   file's last) is not read at all; blanks may open it; the database's
///   name ends at a blank or a `:`, and any run of blanks and `:` may
///   follow it; the name is matched as written (`PASSWD:` is no database);
/// * the last line for a database is the one kept;
/// * the sources are `nss_action_parse()`'s.
///
/// `None` where glibc refuses the whole file, and with it every lookup of
/// every database: a line it cannot parse for any database it knows
/// (`hosts: files [`: then the C knows no login, no host and no service),
/// or a file it cannot read.
pub fn nsswitch_database<'a>(
    conf: &'a Conf,
    database: &[u8],
    default: &'a [u8],
) -> Option<Vec<NssSource<'a>>> {
    let text = match conf {
        Conf::Missing => return nss_action_parse(default, true),
        Conf::Unreadable => return None,
        Conf::Text(text) => text.as_slice(),
    };
    let mut found = None;
    let mut lines = text.split(|&b| b == b'\n').peekable();
    while let Some(line) = lines.next() {
        // What follows the last `\n` is no line.
        if lines.peek().is_none() {
            break;
        }
        let line = line.split(|&b| b == 0).next().unwrap_or_default();
        let (name, rest) = nss_word(skip_spaces(line), |b| is_space(b) || b == b':');
        if name.is_empty() || rest.is_empty() || !NSS_DATABASES.contains(&name) {
            continue;
        }
        let skip = rest
            .iter()
            .position(|&b| !is_space(b) && b != b':')
            .unwrap_or(rest.len());
        let keep = name == database;
        let sources = nss_action_parse(rest.get(skip..).unwrap_or_default(), keep)?;
        if keep {
            found = Some(sources);
        }
    }
    match found {
        Some(sources) => Some(sources),
        None => nss_action_parse(default, true),
    }
}

/// What a source lsof-rs can ask answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NssAnswer<T> {
    /// `NSS_STATUS_SUCCESS`, and what it found.
    Success(T),
    /// `NSS_STATUS_NOTFOUND`.
    NotFound,
    /// `NSS_STATUS_UNAVAIL`: its file cannot be opened; or, from DNS, an
    /// answer that cannot be read.
    Unavail,
    /// `NSS_STATUS_TRYAGAIN`: from DNS, an answer whose records hold no PTR
    /// at the name asked for (measured: `[TRYAGAIN=return]` ends the walk
    /// there, `[NOTFOUND=return]` does not).
    TryAgain,
}

impl<T> NssAnswer<T> {
    /// What was found, if anything was.
    pub fn found(self) -> Option<T> {
        match self {
            NssAnswer::Success(found) => Some(found),
            NssAnswer::NotFound | NssAnswer::Unavail | NssAnswer::TryAgain => None,
        }
    }
}

/// One lookup through `sources`, as glibc's `__nss_lookup()`,
/// `__nss_next2()` and the loop of `getXXbyYY_r()` walk them. `ask` asks a
/// source by its name and is `None` for one lsof-rs cannot ask, which is
/// every source but the files' readers.
///
/// A source that cannot be asked is taken as glibc takes one whose library
/// is not there, or has no function for the database: the walk steps over
/// it where its `UNAVAIL` action is `continue`, and ends where it is
/// anything else. That is exact where the source is not installed
/// (measured with `sss`, and with `dns` and `hesiod` for `passwd`), and
/// lsof-rs's reading of it where it is and would have answered
/// (DIVERGENCES 39).
///
/// A source that was asked ends the walk where its status's action is
/// `return`, or it is the last; otherwise the next one's answer replaces
/// it. No sources at all is no answer, where the C dies in glibc (SIGSEGV).
///
/// `SUCCESS=merge` is glibc's for a database with no merge function, which
/// is every one read here (hosts, services, passwd: `__copy_einval`): the
/// answer is kept aside and the status taken as `UNAVAIL`, whose action
/// says whether the walk goes on. The next source asked that does not
/// succeed gives the kept answer back as its own `SUCCESS`, whose action
/// then decides; one that succeeds fails the merge, `UNAVAIL` and no
/// answer. With no later source asked there is no answer (measured: under
/// `hosts: files [SUCCESS=merge] dns` the C names an address from the hosts
/// file where DNS says NXDOMAIN, and none where DNS names it).
pub fn nss_walk<T: Clone>(
    sources: &[NssSource<'_>],
    mut ask: impl FnMut(&[u8]) -> Option<NssAnswer<T>>,
) -> Option<T> {
    let mut result = None;
    // `do_merge` and `mergegrp`: the answer a `SUCCESS=merge` kept aside.
    let mut merging: Option<T> = None;
    for (i, source) in sources.iter().enumerate() {
        let last = i.saturating_add(1) == sources.len();
        let Some(answer) = ask(source.module) else {
            if source.on(NssStatus::Unavail) != NssAction::Continue {
                break;
            }
            continue;
        };
        let (mut status, mut found) = match answer {
            NssAnswer::Success(found) => (NssStatus::Success, Some(found)),
            NssAnswer::NotFound => (NssStatus::NotFound, None),
            NssAnswer::Unavail => (NssStatus::Unavail, None),
            NssAnswer::TryAgain => (NssStatus::TryAgain, None),
        };
        if let Some(kept) = merging.as_ref() {
            if status == NssStatus::Success {
                // `MERGE_FN` fails: no answer, and nothing kept any more.
                status = NssStatus::Unavail;
                found = None;
                merging = None;
            } else {
                // `DEEPCOPY_FN` fails, and the kept answer is the status's.
                status = NssStatus::Success;
                found = Some(kept.clone());
            }
        }
        if status == NssStatus::Success && source.on(status) == NssAction::Merge {
            status = NssStatus::Unavail;
            merging = found.take();
        }
        result = found;
        if source.on(status) == NssAction::Return || last {
            break;
        }
    }
    result
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
    let (first, port, proto, aliases) = services_fields(line)?;
    if proto != protocol {
        return None;
    }
    if first != name && !words(aliases).any(|a| a == name) {
        return None;
    }
    Some(port)
}

/// A services line as glibc's parser reads it: its name, port, protocol
/// and the rest (its aliases).
type ServicesFields<'a> = (&'a [u8], u16, &'a [u8], &'a [u8]);

/// A services line's fields ([`ServicesFields`]), by [`services_line`]'s
/// rules: `None` for a line glibc's parser skips.
fn services_fields(line: &[u8]) -> Option<ServicesFields<'_>> {
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
    // Past 32 bits the line is refused (`-1` too, which `strtoul()` wraps);
    // within them the port is the low 16, as `htons()` keeps it.
    if value > u64::from(u32::MAX) {
        return None;
    }
    let port = u16::try_from(value & 0xffff).ok()?;
    let (proto, aliases) = string_field(rest);
    Some((first, port, proto, aliases))
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

/// The longest line of a hosts, services or password file that is read,
/// its `\n` apart. glibc reads a line of any length, into memory it grows
/// until it has it or there is none left; a longer line is skipped here, as
/// one that names nothing, so that a file is read in bounded memory
/// whatever is in it (DIVERGENCES 38).
pub const LINE_LIMIT: usize = 1 << 20;

/// The most of a hosts, services or password file that is read: what
/// follows is not, so that the reading ends whatever the file is (glibc
/// reads on while there is anything to read).
pub const FILE_LIMIT: u64 = 1 << 28;

/// The most of `/etc/nsswitch.conf` or `/etc/host.conf` that is read: far
/// more than a configuration file holds.
const CONF_LIMIT: u64 = 1 << 20;

/// Whether the file at `path` is one that would hold whoever reads it as a
/// file: there, and neither a regular file nor a directory (a FIFO holds
/// `open(2)` until it has a writer, a device such as `/dev/zero` never
/// ends). The C library reads its configuration with no such care, so a
/// backend looks before it hands it a lookup ([`system_addresses`]).
pub fn would_hold_a_reader(path: &std::path::Path) -> bool {
    std::fs::metadata(path).is_ok_and(|meta| !meta.is_file() && !meta.is_dir())
}

/// Whether `meta` is the null device's (`/dev/null`, a character device
/// 1:3): glibc reads it as an empty file, which is how it is read here,
/// with no `open(2)` (measured: nsswitch.conf, resolv.conf, hosts and
/// host.conf there are each the empty file to the C; DIVERGENCES 38, 154).
pub fn is_null_device(meta: &std::fs::Metadata) -> bool {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        meta.file_type().is_char_device() && meta.rdev() == 0x103
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = meta;
        false
    }
}

/// Whether the file at `path` is one glibc's reader would wait on or read
/// for ever, where the C library reads it with no care: a FIFO (its
/// `fopen()` waits for a writer) or a device other than the null device
/// (`/dev/zero` never ends, `/dev/urandom` neither). A directory, a socket
/// and the null device each give glibc an answer at once, and are not.
pub fn holds_glibcs_reader(path: &std::path::Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        std::fs::metadata(path).is_ok_and(|meta| {
            let kind = meta.file_type();
            (kind.is_fifo() || kind.is_char_device() || kind.is_block_device())
                && !is_null_device(&meta)
        })
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

/// The file at `path` opened for reading, if it is a regular file. A FIFO
/// there would hold `open(2)` until something writes to it (it holds the C,
/// measured), and a device has no end, so neither is read: what is no
/// regular file is read as no file. Looked at before it is opened, and
/// again once it is; opened without blocking, so that a FIFO put in its
/// place between the two cannot hold the open, and is then refused.
fn open_regular(path: &std::path::Path) -> Option<std::fs::File> {
    if !std::fs::metadata(path).ok()?.is_file() {
        return None;
    }
    open_nonblocking_regular(path)
}

/// The open and the second look of [`open_regular`]: the file at `path`
/// opened without blocking, if what was opened is a regular file.
fn open_nonblocking_regular(path: &std::path::Path) -> Option<std::fs::File> {
    let mut open = std::fs::OpenOptions::new();
    open.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut open, crate::safefs::NONBLOCK);
    let file = open.open(path).ok()?;
    file.metadata().ok()?.is_file().then_some(file)
}

/// Every line of `source`, fed to `each` until it says it is done, as
/// glibc's `__nss_readline()` reads them: up to each `\n`, as bytes. A
/// line longer than `line_limit` is passed over, and nothing past
/// `file_limit` bytes is read.
pub fn read_lines(
    source: impl std::io::Read,
    line_limit: usize,
    file_limit: u64,
    mut each: impl FnMut(&[u8]) -> bool,
) {
    use std::io::{BufRead, Read};
    let mut reader = std::io::BufReader::new(source.take(file_limit));
    let most = u64::try_from(line_limit)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut line = Vec::new();
    loop {
        line.clear();
        match reader.by_ref().take(most).read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        if line.len() > line_limit && line.last() != Some(&b'\n') {
            // Too long: on to where it ends.
            loop {
                let (used, ended) = match reader.fill_buf() {
                    Ok([]) | Err(_) => return,
                    Ok(buffer) => match buffer.iter().position(|&b| b == b'\n') {
                        Some(at) => (at.saturating_add(1), true),
                        None => (buffer.len(), false),
                    },
                };
                reader.consume(used);
                if ended {
                    break;
                }
            }
            continue;
        }
        if each(&line) {
            return;
        }
    }
}

/// [`read_lines`] over the file at `path`, within [`LINE_LIMIT`] and
/// [`FILE_LIMIT`]. Whether there was a file to read: where there is none
/// (or none that is a regular file) glibc's `files` service is unavailable.
pub fn file_lines(path: &std::path::Path, each: impl FnMut(&[u8]) -> bool) -> bool {
    // The null device is a file with no line, as glibc reads it: `files`
    // answers NOTFOUND there, not UNAVAIL (measured under
    // `[NOTFOUND=return]`).
    if std::fs::metadata(path).is_ok_and(|meta| is_null_device(&meta)) {
        return true;
    }
    let Some(file) = open_regular(path) else {
        return false;
    };
    read_lines(file, LINE_LIMIT, FILE_LIMIT, each);
    true
}

/// `/etc/nsswitch.conf`, the file at `path`: at most `CONF_LIMIT` (1 MiB) of it.
pub fn nsswitch_conf(path: &std::path::Path) -> Conf {
    conf_file(path, CONF_LIMIT)
}

/// A configuration file, at most `limit` bytes of it.
pub fn conf_file(path: &std::path::Path, limit: u64) -> Conf {
    use std::io::Read;
    // What is there and is no regular file cannot be read as one: a
    // directory fails glibc's read, a device has no end to read to (glibc
    // reads `/dev/zero` until it has no memory left, and then refuses the
    // file), and a FIFO would hold `open(2)`, as it holds the C. The null
    // device is the exception: glibc reads it as the empty file it is.
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_file() => {}
        Ok(meta) if is_null_device(&meta) => return Conf::Text(Vec::new()),
        Ok(_) => return Conf::Unreadable,
        Err(_) => return Conf::Missing,
    }
    let Some(file) = open_regular(path) else {
        return Conf::Missing;
    };
    let mut text = Vec::new();
    match file.take(limit).read_to_end(&mut text) {
        Ok(_) => Conf::Text(text),
        Err(_) => Conf::Unreadable,
    }
}

/// The whole of a small configuration file, or nothing: at most `limit`
/// bytes of it.
pub fn small_file(path: &std::path::Path, limit: u64) -> Vec<u8> {
    match conf_file(path, limit) {
        Conf::Text(text) => text,
        Conf::Missing | Conf::Unreadable => Vec::new(),
    }
}

/// `name`'s port for `protocol` in the services file at `path`, as glibc's
/// `files` service answers.
pub fn service_in_file(path: &std::path::Path, name: &[u8], protocol: &[u8]) -> NssAnswer<u16> {
    let mut search = ServicesSearch::new(name, protocol);
    let read = file_lines(path, |line| {
        search.line(line);
        search.done()
    });
    match search.finish() {
        Some(port) => NssAnswer::Success(port),
        None if read => NssAnswer::NotFound,
        None => NssAnswer::Unavail,
    }
}

/// `name`'s addresses of one family in the hosts file at `path`: none
/// found is `NotFound`.
pub fn hosts_in_file(
    path: &std::path::Path,
    name: &[u8],
    v6: bool,
    multi: bool,
) -> NssAnswer<Vec<IpAddr>> {
    let mut search = HostsSearch::new(name, v6, multi);
    let read = file_lines(path, |line| {
        search.line(line);
        search.done()
    });
    let found = search.finish();
    if !found.is_empty() {
        NssAnswer::Success(found)
    } else if read {
        NssAnswer::NotFound
    } else {
        NssAnswer::Unavail
    }
}

/// Addresses in the order given, each once, at most [`MAX_ADDRESSES`].
pub fn distinct_addresses(addresses: impl Iterator<Item = IpAddr>) -> Vec<IpAddr> {
    let mut found: Vec<IpAddr> = Vec::new();
    for ip in addresses {
        if found.len() >= MAX_ADDRESSES {
            break;
        }
        if !found.contains(&ip) {
            found.push(ip);
        }
    }
    found
}

/// `name`'s addresses, of both families, from the system's resolver:
/// `getaddrinfo(3)` through `std`, which follows `/etc/nsswitch.conf` to
/// DNS and to every other source, under `/etc/resolv.conf`'s timeouts. In
/// the order it gives them, each once, at most [`MAX_ADDRESSES`]. None for a
/// name it does not resolve, and none under miri, which has no resolver.
pub fn system_addresses(name: &str) -> Vec<IpAddr> {
    if cfg!(miri) || name.is_empty() || name.contains('\0') {
        return Vec::new();
    }
    use std::net::ToSocketAddrs;
    match (name, 0u16).to_socket_addrs() {
        Ok(addrs) => distinct_addresses(addrs.map(|addr| addr.ip())),
        Err(_) => Vec::new(),
    }
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

/// glibc's built-in sources for `hosts` where nsswitch.conf gives none: no
/// file, or no `hosts:` line. This is the C library's of Debian and Ubuntu,
/// measured (glibc 2.39-0ubuntu8: with no nsswitch.conf the C finds a name
/// `/etc/hosts` holds and asks DNS for one it lacks). glibc as its authors
/// ship it has `dns [!UNAVAIL=return] files` there, which lsof-rs cannot
/// tell from this one at run time (DIVERGENCES 38).
pub const HOSTS_DEFAULT: &[u8] = b"files dns";

/// glibc's built-in sources for `services` and for `passwd`.
pub const FILES_DEFAULT: &[u8] = b"files";

/// A host name's addresses of one family, as glibc's `gethostbyname2()`
/// gives them where this module can follow it:
///
/// 1. a name that is a number is answered as one ([`numeric_host`]);
/// 2. a nsswitch.conf glibc refuses names no host
///    ([`nsswitch_database`]), and neither does a `hosts:` line with no
///    source (there the C dies in glibc);
/// 3. where `files` is the first source for `hosts`, the hosts file is
///    searched by its rules ([`HostsSearch`]), under `multi` as
///    `host_conf` and then `multi_env` (`RESOLV_MULTI`) set it, and what
///    it finds is the answer, unless the line has `files [SUCCESS=merge]`
///    (no answer) or `[SUCCESS=continue]` and a source after it (the next
///    step's answer, as glibc lets a later source replace it);
/// 4. a name not found there, where the line reads on (`files` is not the
///    last source and its `NOTFOUND` action is not `return`), and every
///    name where `files` is not first, goes to `system`
///    ([`system_addresses`]), and its addresses of the family asked for
///    are the answer, unless `getaddrinfo()` would read the name as a
///    number where `gethostbyname2()` does not (`0x7f.1`): that one is
///    unknown.
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
    let conf = nsswitch_conf(files.nsswitch);
    let Some(sources) = nsswitch_database(&conf, b"hosts", HOSTS_DEFAULT) else {
        return Vec::new();
    };
    let Some(first) = sources.first() else {
        return Vec::new();
    };
    if first.module == b"files" {
        let more = sources.len() > 1;
        let multi = multi_env
            .and_then(bool_arg)
            .unwrap_or_else(|| host_conf_multi(&small_file(files.host_conf, CONF_LIMIT)));
        let (status, found) = match hosts_in_file(files.hosts, name, v6, multi) {
            NssAnswer::Success(found) => (NssStatus::Success, found),
            NssAnswer::NotFound => (NssStatus::NotFound, Vec::new()),
            NssAnswer::Unavail => (NssStatus::Unavail, Vec::new()),
            NssAnswer::TryAgain => (NssStatus::TryAgain, Vec::new()),
        };
        match (status, first.on(status)) {
            (NssStatus::Success, NssAction::Merge) => return Vec::new(),
            (NssStatus::Success, NssAction::Continue) if more => {}
            (NssStatus::Success, _) => return found,
            (_, NssAction::Return) => return Vec::new(),
            _ if !more => return Vec::new(),
            _ => {}
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

/// A service name's port for a protocol, as glibc's `getservbyname()`
/// gives it where this module can follow it: the sources nsswitch.conf
/// lists for `services` are walked ([`nss_walk`]), and `files` is the
/// services file at `services`, searched by its rules
/// ([`ServicesSearch`]). No other source can be asked (DIVERGENCES 38).
pub fn glibc_service(
    name: &[u8],
    protocol: &[u8],
    services: &std::path::Path,
    nsswitch: &std::path::Path,
) -> Option<u16> {
    let conf = nsswitch_conf(nsswitch);
    let sources = nsswitch_database(&conf, b"services", FILES_DEFAULT)?;
    nss_walk(&sources, |module| {
        (module == b"files").then(|| service_in_file(services, name, protocol))
    })
}

// ------------------------------------------------- names for an address

/// The most of a name a reverse lookup keeps: past what the C's NAME buffer
/// can hold (`Namech`, `MAXPATHLEN + 1`), so that a longer name is still
/// known to be longer, and prints as the C prints one, while a hosts or
/// services file of any size keeps a bounded copy of each.
pub const NAME_KEPT: usize = 4097;

/// `name`, at most [`NAME_KEPT`] bytes of it.
fn kept(name: &[u8]) -> Vec<u8> {
    name.get(..name.len().min(NAME_KEPT))
        .unwrap_or_default()
        .to_vec()
}

/// One line of a hosts file as `_nss_files_gethostbyaddr2_r()` reads it for
/// `ip`: the line's first name where its address, read for `ip`'s family
/// ([`hosts_line`]), is `ip`. A line that gives an address and no name
/// gives the empty name, which the C prints as no host at all (`:4006`,
/// measured).
fn hosts_line_name(line: &[u8], ip: IpAddr) -> Option<&[u8]> {
    let (addr, rest) = hosts_line(line, ip.is_ipv6())?;
    (addr == ip).then(|| string_field(rest).0)
}

/// `ip`'s name in the hosts file at `path`: the first line that gives it
/// (`hosts_line_name`), at most [`NAME_KEPT`] bytes of it.
pub fn host_by_addr_in_file(path: &std::path::Path, ip: IpAddr) -> NssAnswer<Vec<u8>> {
    let mut found = None;
    let read = file_lines(path, |line| {
        found = hosts_line_name(line, ip).map(kept);
        found.is_some()
    });
    match found {
        Some(name) => NssAnswer::Success(name),
        None if read => NssAnswer::NotFound,
        None => NssAnswer::Unavail,
    }
}

/// What a services scan hands each entry to: its name, its port, its
/// protocol as written ([`services_in_file`]).
pub type ServiceVisitor<'a> = dyn FnMut(&[u8], u16, &[u8]) + 'a;

/// One entry of a services file: what `getservent()` gives for a line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceEntry {
    /// The line's first field, at most [`NAME_KEPT`] bytes of it.
    pub name: Vec<u8>,
    /// The port, kept to 16 bits as `htons()` keeps it.
    pub port: u16,
    /// The protocol as written.
    pub protocol: Vec<u8>,
}

/// One line of a services file read by glibc's `files` parser, whatever
/// it names: [`services_line`]'s rules.
fn services_entry(line: &[u8]) -> Option<(&[u8], u16, &[u8])> {
    services_fields(line).map(|(name, port, protocol, _)| (name, port, protocol))
}

/// `getservbyport(htons(port), protocol)` of the services file at `path`:
/// the first line that gives `port` for `protocol`, compared exactly
/// (`_nss_files_getservbyport_r()`: `strcmp`, so `TCP` is not `tcp`).
pub fn service_by_port_in_file(
    path: &std::path::Path,
    port: u16,
    protocol: &[u8],
) -> NssAnswer<Vec<u8>> {
    let mut found = None;
    let read = file_lines(path, |line| {
        found = services_entry(line)
            .filter(|&(_, p, proto)| p == port && proto == protocol)
            .map(|(name, _, _)| kept(name));
        found.is_some()
    });
    match found {
        Some(name) => NssAnswer::Success(name),
        None if read => NssAnswer::NotFound,
        None => NssAnswer::Unavail,
    }
}

/// Every entry of the services file at `path`, in its order, as a
/// `getservent()` scan gives them, handed to `each` (its name at most
/// [`NAME_KEPT`] bytes of it, its port, its protocol as written) as its
/// line is read, nothing kept; `false` where there is no file to read.
/// The C's `fill_porttab()` reads `getservent()` the same way, keeping
/// what it needs as it goes.
pub fn services_in_file(path: &std::path::Path, each: &mut ServiceVisitor<'_>) -> bool {
    file_lines(path, |line| {
        if let Some((name, port, protocol)) = services_entry(line) {
            each(
                name.get(..name.len().min(NAME_KEPT)).unwrap_or_default(),
                port,
                protocol,
            );
        }
        false
    })
}

/// `gethostbyaddr()`'s answer for `ip` where this module can follow it: the
/// sources nsswitch.conf gives `hosts` walked by glibc's rules
/// ([`nss_walk`]), `files` being the hosts file at `files.hosts`
/// ([`host_by_addr_in_file`]) and `dns` the resolver, `dns`. Any other
/// source is taken as not installed (DIVERGENCES 38, 154). `None`: no name.
///
/// A hosts file glibc's reader would wait on or read for ever
/// ([`holds_glibcs_reader`]: a FIFO, `/dev/zero`) ends the lookup where the
/// walk reaches it, with no name and no later source asked: the C never
/// gets past it (it waits on a FIFO, and its buffer grows on `/dev/zero`
/// until `gethostbyaddr()` fails, `ENOMEM`), and asks no name server.
///
/// The name found, from any source, is cut by `trim` ([`trim_domain`]), as
/// glibc's `gethostbyaddr_r()` cuts every answer (`POSTPROCESS`).
pub fn glibc_host_by_addr(
    ip: IpAddr,
    files: &GlibcFiles<'_>,
    trim: &[Vec<u8>],
    dns: &mut dyn FnMut(IpAddr) -> NssAnswer<String>,
) -> Option<Vec<u8>> {
    let conf = nsswitch_conf(files.nsswitch);
    let sources = nsswitch_database(&conf, b"hosts", HOSTS_DEFAULT)?;
    let mut held = false;
    let mut name = nss_walk(&sources, |module| {
        if held {
            return None;
        }
        match module {
            b"files" if holds_glibcs_reader(files.hosts) => {
                held = true;
                Some(NssAnswer::Unavail)
            }
            b"files" => Some(host_by_addr_in_file(files.hosts, ip)),
            b"dns" => Some(match dns(ip) {
                NssAnswer::Success(name) => NssAnswer::Success(name.into_bytes()),
                NssAnswer::NotFound => NssAnswer::NotFound,
                NssAnswer::Unavail => NssAnswer::Unavail,
                NssAnswer::TryAgain => NssAnswer::TryAgain,
            }),
            _ => None,
        }
    })
    .filter(|_| !held)?;
    trim_domain(&mut name, trim);
    Some(name)
}

/// `getservbyport(htons(port), protocol)` where this module can follow it:
/// the `services` sources walked, `files` the services file.
pub fn glibc_service_by_port(
    port: u16,
    protocol: &[u8],
    services: &std::path::Path,
    nsswitch: &std::path::Path,
) -> Option<Vec<u8>> {
    let conf = nsswitch_conf(nsswitch);
    let sources = nsswitch_database(&conf, b"services", FILES_DEFAULT)?;
    nss_walk(&sources, |module| {
        (module == b"files").then(|| service_by_port_in_file(services, port, protocol))
    })
}

/// A `getservent()` scan where this module can follow it: the services
/// file's entries, each handed to `each` as it is read
/// ([`services_in_file`]), where the walk of the `services` sources reaches
/// `files` (sources before it that cannot be asked passed over where their
/// `UNAVAIL` action is `continue`), and none otherwise.
pub fn glibc_services(
    services: &std::path::Path,
    nsswitch: &std::path::Path,
    each: &mut ServiceVisitor<'_>,
) {
    let conf = nsswitch_conf(nsswitch);
    let Some(sources) = nsswitch_database(&conf, b"services", FILES_DEFAULT) else {
        return;
    };
    for source in &sources {
        if source.module == b"files" {
            services_in_file(services, each);
            return;
        }
        if source.on(NssStatus::Unavail) != NssAction::Continue {
            return;
        }
    }
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
            (b"multi#on\n", false),
            (b"multi #on\n", false),
            (b"multi, on\n", false),
            (b"nomulti on\n", false),
            (b"multi on\0\n", true),
            (b"multi\0 on\n", false),
            (b"multi \0on\n", false),
            (b"\0multi on\n", false),
        ] {
            assert_eq!(
                host_conf_multi(text),
                want,
                "{:?}",
                String::from_utf8_lossy(text)
            );
        }
        // glibc reads 255 bytes of a line at a time: what is left of a
        // longer one is a line of its own.
        let long = |lead: usize, tail: &str| {
            let mut text = vec![b'#'; lead];
            text.extend_from_slice(tail.as_bytes());
            text
        };
        assert!(host_conf_multi(&long(255, "multi on\n")));
        assert!(!host_conf_multi(&long(254, "multi on\n")));
        assert!(!host_conf_multi(&long(256, "multi on\n")));
        assert!(host_conf_multi(&long(510, "multi on\n")));
        assert!(host_conf_multi(&long(254, "\nmulti on\n")));
        assert!(host_conf_multi(&long(255, "\nmulti on")));
        assert!(!host_conf_multi(&long(250, " multi on\n")));
        assert_eq!(bool_arg(b"on"), Some(true));
        assert_eq!(bool_arg(b"OFF"), Some(false));
        assert_eq!(bool_arg(b"only"), Some(true));
        assert_eq!(bool_arg(b"o"), None);
        assert_eq!(bool_arg(b""), None);
        assert_eq!(bool_arg(b"yes"), None);
    }

    fn text(conf: &[u8]) -> Conf {
        Conf::Text(conf.to_vec())
    }

    /// The sources of `database` in `conf`, written back: each source's
    /// name and its four actions (success, notfound, unavail, tryagain) by
    /// their first letters; `None` where glibc refuses the file.
    fn sources(conf: &[u8], database: &str, default: &[u8]) -> Option<String> {
        let conf = text(conf);
        let sources = nsswitch_database(&conf, database.as_bytes(), default)?;
        let letter = |a| match a {
            NssAction::Return => 'r',
            NssAction::Continue => 'c',
            NssAction::Merge => 'm',
        };
        Some(
            sources
                .iter()
                .map(|s| {
                    let mut out = String::from_utf8_lossy(s.module).into_owned();
                    out.push('/');
                    for status in [
                        NssStatus::Success,
                        NssStatus::NotFound,
                        NssStatus::Unavail,
                        NssStatus::TryAgain,
                    ] {
                        out.push(letter(s.on(status)));
                    }
                    out
                })
                .collect::<Vec<_>>()
                .join(" "),
        )
    }

    /// nsswitch.conf as glibc 2.39 reads it: every line here was measured
    /// through `getent passwd`, `getent hosts` and `getent services` over a
    /// file bound on `/etc/nsswitch.conf`, and the ones that decide
    /// something through the C (DIVERGENCES 38 and 39).
    #[test]
    fn nsswitch_is_read_as_glibc_reads_it() {
        let hosts = |conf: &[u8]| sources(conf, "hosts", HOSTS_DEFAULT);
        let some = |s: &str| Some(s.to_string());
        // No file, an empty one, and one with no line for the database:
        // glibc's built-in sources.
        assert_eq!(
            nsswitch_database(&Conf::Missing, b"hosts", HOSTS_DEFAULT).map(|s| s.len()),
            Some(2)
        );
        assert_eq!(hosts(b""), some("files/rccc dns/rccc"));
        assert_eq!(hosts(b"\n"), some("files/rccc dns/rccc"));
        assert_eq!(hosts(b"passwd: files\n"), some("files/rccc dns/rccc"));
        assert_eq!(
            sources(b"hosts: dns\n", "passwd", FILES_DEFAULT),
            some("files/rccc")
        );
        assert_eq!(HOSTS_DEFAULT, b"files dns");
        assert_eq!(FILES_DEFAULT, b"files");
        // A file that cannot be read is refused whole.
        assert_eq!(
            nsswitch_database(&Conf::Unreadable, b"hosts", HOSTS_DEFAULT),
            None
        );
        // The line: blanks before it, the name to a blank or a colon, any
        // run of blanks and colons after it.
        assert_eq!(hosts(b"hosts: dns files\n"), some("dns/rccc files/rccc"));
        assert_eq!(hosts(b"hosts:files\n"), some("files/rccc"));
        assert_eq!(hosts(b"  hosts :\tfiles\n"), some("files/rccc"));
        assert_eq!(hosts(b"hosts ::: files\n"), some("files/rccc"));
        assert_eq!(hosts(b"hosts files\n"), some("files/rccc"));
        assert_eq!(hosts(b"hosts:\tfiles\r\n"), some("files/rccc"));
        // A name alone on its line is no line, nor is another name.
        assert_eq!(hosts(b"hosts\n"), some("files/rccc dns/rccc"));
        assert_eq!(hosts(b"hostsx: sss\n"), some("files/rccc dns/rccc"));
        assert_eq!(hosts(b"HOSTS: sss\n"), some("files/rccc dns/rccc"));
        assert_eq!(hosts(b"#hosts: sss\n"), some("files/rccc dns/rccc"));
        assert_eq!(hosts(b": sss\n"), some("files/rccc dns/rccc"));
        // The last line for a database is the one kept.
        assert_eq!(hosts(b"hosts: files\nhosts: dns\n"), some("dns/rccc"));
        assert_eq!(hosts(b"hosts: dns\nhosts: files\n"), some("files/rccc"));
        // A line no `\n` ends is not read at all.
        assert_eq!(hosts(b"hosts: sss"), some("files/rccc dns/rccc"));
        assert_eq!(hosts(b"hosts: sss\nhosts: files"), some("sss/rccc"));
        // A line ends at a NUL.
        assert_eq!(hosts(b"hosts: files\0sss\n"), some("files/rccc"));
        assert_eq!(hosts(b"hosts: sss\n\0hosts: files\n"), some("sss/rccc"));
        assert_eq!(hosts(b"hosts: files\0 [\n"), some("files/rccc"));
        // No sources: an empty list (the C dies in glibc there).
        assert_eq!(hosts(b"hosts:\n"), some(""));
        assert_eq!(hosts(b"hosts: [NOTFOUND=return] files\n"), some(""));
        // There is no comment after the sources: a `#` is one of them.
        assert_eq!(
            hosts(b"hosts: sss # files\n"),
            some("sss/rccc #/rccc files/rccc")
        );
        assert_eq!(hosts(b"hosts: sss#files\n"), some("sss#files/rccc"));
        // A source's name is as written.
        assert_eq!(hosts(b"hosts: FILES\n"), some("FILES/rccc"));
        // Actions: a status, `=`, an action, in any case; blanks anywhere;
        // several in one pair of brackets; the later of two wins.
        assert_eq!(
            hosts(b"hosts: files [NOTFOUND=return] dns\n"),
            some("files/rrcc dns/rccc")
        );
        assert_eq!(
            hosts(b"hosts: files [notfound=RETURN] dns\n"),
            some("files/rrcc dns/rccc")
        );
        assert_eq!(
            hosts(b"hosts: sss[NOTFOUND=return]files\n"),
            some("sss/rrcc files/rccc")
        );
        assert_eq!(
            hosts(b"hosts: sss [ UNAVAIL = return  TRYAGAIN=merge ] files\n"),
            some("sss/rcrm files/rccc")
        );
        assert_eq!(
            hosts(b"hosts: files [SUCCESS=continue]\n"),
            some("files/cccc")
        );
        assert_eq!(hosts(b"hosts: files [SUCCESS=merge]\n"), some("files/mccc"));
        assert_eq!(
            hosts(b"hosts: sss [UNAVAIL=return UNAVAIL=continue] files\n"),
            some("sss/rccc files/rccc")
        );
        // `!STATUS` sets every other status.
        assert_eq!(
            hosts(b"hosts: files [!NOTFOUND=return] dns\n"),
            some("files/rcrr dns/rccc")
        );
        assert_eq!(
            hosts(b"hosts: dns [!UNAVAIL=return] files\n"),
            some("dns/rrcr files/rccc")
        );
        assert_eq!(hosts(b"hosts: sss [!SUCCESS=continue]\n"), some("sss/rccc"));
        // What glibc cannot parse it refuses, and the whole file with it,
        // whichever database the line is for; but not a line for a
        // database it does not know.
        for bad in [
            &b"hosts: sss [NOTFOUND] files\n"[..],
            b"hosts: sss [] files\n",
            b"hosts: sss [!] files\n",
            b"hosts: sss [NOTFOUND=return files\n",
            b"hosts: files sss [\n",
            b"hosts: files [x=y] sss\n",
            b"hosts: files [NOTFOUND=bogus]\n",
            b"hosts: files [NOTFOUN=return]\n",
            b"hosts: files [NOTFOUNDS=return]\n",
            b"hosts: files [NOTFOUND=returns]\n",
            b"hosts: files [NOTFOUND return]\n",
            b"hosts: files\npasswd: sss [\n",
            b"netgroup: files [\nhosts: files\n",
            b"shadow_compat: files [\nhosts: files\n",
        ] {
            assert_eq!(hosts(bad), None, "{:?}", String::from_utf8_lossy(bad));
        }
        // What follows a `[` no source precedes is not read at all.
        assert_eq!(
            hosts(b"hosts: files [NOTFOUND=return][UNAVAIL\n"),
            some("files/rrcc")
        );
        assert_eq!(hosts(b"bogus: files [\nhosts: files\n"), some("files/rccc"));
        assert_eq!(
            hosts(b"sudoers: files [\nhosts: files\n"),
            some("files/rccc")
        );
        // The bad line unread (no `\n`), the file stands.
        assert_eq!(hosts(b"hosts: files\npasswd: sss ["), some("files/rccc"));
    }

    /// The walk through a database's sources, as the C's lookups came out
    /// under each line (`getent` and the C, glibc 2.39; `sss` is not
    /// installed where it was measured, `files` holds the name or not).
    #[test]
    fn a_lookup_walks_the_sources_as_glibc_walks_them() {
        let walk = |line: &str, in_file: Option<bool>| {
            let conf = text(format!("passwd: {line}\n").as_bytes());
            let sources = nsswitch_database(&conf, b"passwd", FILES_DEFAULT).unwrap();
            let mut asked = 0u32;
            let found = nss_walk(&sources, |module| {
                (module == b"files" || module == b"compat").then(|| {
                    asked += 1;
                    match in_file {
                        Some(true) => NssAnswer::Success(asked),
                        Some(false) => NssAnswer::NotFound,
                        None => NssAnswer::Unavail,
                    }
                })
            });
            (found, asked)
        };
        let found = |line: &str| walk(line, Some(true)).0.is_some();
        for (line, want) in [
            ("files", true),
            ("files sss", true),
            ("sss files", true),
            ("db files", true),
            ("compat", true),
            ("sss", false),
            ("FILES", false),
            ("sss # files", true),
            ("sss#files", false),
            ("files # sss", true),
            // A source that is not there is stepped over where its
            // UNAVAIL action is `continue`, and ends the walk otherwise.
            ("sss [UNAVAIL=return] files", false),
            ("sss [NOTFOUND=return] files", true),
            ("sss [TRYAGAIN=return] files", true),
            ("sss [!UNAVAIL=return] files", true),
            ("sss [!NOTFOUND=return] files", false),
            ("sss [!SUCCESS=return] files", false),
            ("sss [!TRYAGAIN=return] files", false),
            ("sss [unavail=continue] files", true),
            ("sss [UNAVAIL=return UNAVAIL=continue] files", true),
            ("sss [UNAVAIL=merge] files", false),
            ("sss [UNAVAIL=return] [UNAVAIL=continue] files", false),
            ("sss sss sss files", true),
            ("sss [UNAVAIL=return] sss files", false),
            ("sss sss [UNAVAIL=return] files", false),
            // What `files` found stands where nothing after it can be
            // asked, whatever its SUCCESS action; but not a merge.
            ("files [NOTFOUND=return] sss", true),
            ("files [SUCCESS=continue] sss", true),
            ("files [SUCCESS=continue] sss [UNAVAIL=return]", true),
            ("files [SUCCESS=continue]", true),
            ("files [SUCCESS=merge] sss", false),
            ("files [SUCCESS=merge]", false),
            // No source at all.
            ("", false),
            ("[NOTFOUND=return] files", false),
        ] {
            assert_eq!(found(line), want, "passwd: {line}");
            // A name the file lacks is found nowhere.
            assert_eq!(walk(line, Some(false)).0, None, "passwd: {line}");
            assert_eq!(walk(line, None).0, None, "passwd: {line}");
        }
        // How many sources are asked, and whose answer is kept: the first
        // that returns ends it, and a later one's replaces an earlier's.
        assert_eq!(walk("files compat", Some(true)), (Some(1), 1));
        assert_eq!(walk("files compat", Some(false)), (None, 2));
        assert_eq!(
            walk("files [NOTFOUND=return] compat", Some(false)),
            (None, 1)
        );
        assert_eq!(
            walk("files [SUCCESS=continue] compat", Some(true)),
            (Some(2), 2)
        );
        assert_eq!(walk("files [UNAVAIL=return] compat", None), (None, 1));
        assert_eq!(walk("files compat", None), (None, 2));
        assert_eq!(walk("files sss compat", Some(false)), (None, 2));
        assert_eq!(
            walk("files sss [UNAVAIL=return] compat", Some(false)),
            (None, 1)
        );
        assert_eq!(walk("sss [UNAVAIL=return] files", Some(true)), (None, 0));
        // A later source's answer replaces an earlier one's, a miss too.
        let conf = text(b"passwd: files [SUCCESS=continue] compat\n");
        let sources = nsswitch_database(&conf, b"passwd", FILES_DEFAULT).unwrap();
        let by = |files, compat| {
            nss_walk(&sources, |module| {
                Some(if module == b"files" { files } else { compat })
            })
        };
        assert_eq!(by(NssAnswer::Success(1), NssAnswer::NotFound), None);
        assert_eq!(by(NssAnswer::Success(1), NssAnswer::Unavail), None);
        assert_eq!(by(NssAnswer::NotFound, NssAnswer::Success(2)), Some(2));
        assert_eq!(by(NssAnswer::Success(1), NssAnswer::Success(2)), Some(2));
        assert_eq!(NssAnswer::Success(7).found(), Some(7));
        assert_eq!(NssAnswer::<u8>::NotFound.found(), None);
        assert_eq!(NssAnswer::<u8>::Unavail.found(), None);
    }

    /// A file is read a line at a time within its two bounds, whatever is
    /// in it: a line past the first is passed over, and nothing past the
    /// second is read.
    #[test]
    fn a_file_is_read_in_bounded_lines() {
        let lines = |text: &[u8], line_limit: usize, file_limit: u64| {
            let mut seen = Vec::new();
            read_lines(text, line_limit, file_limit, |line| {
                seen.push(String::from_utf8_lossy(line).into_owned());
                false
            });
            seen
        };
        assert_eq!(lines(b"a\nbb\n\nccc", 8, 100), ["a\n", "bb\n", "\n", "ccc"]);
        // A line of exactly the limit is read, with its `\n` or at the
        // file's end; one byte more and it is not.
        assert_eq!(lines(b"abcd\nef\n", 4, 100), ["abcd\n", "ef\n"]);
        assert_eq!(lines(b"abcde\nef\n", 4, 100), ["ef\n"]);
        assert_eq!(lines(b"ab\nabcdefghij\nef\n", 4, 100), ["ab\n", "ef\n"]);
        assert_eq!(lines(b"ab\nabcd", 4, 100), ["ab\n", "abcd"]);
        assert_eq!(lines(b"ab\nabcde", 4, 100), ["ab\n"]);
        assert_eq!(lines(b"abcdefghij", 4, 100), Vec::<String>::new());
        // The file's bound cuts it where it falls.
        assert_eq!(lines(b"ab\ncd\nef\n", 4, 5), ["ab\n", "cd"]);
        assert_eq!(lines(b"ab\ncd\nef\n", 4, 0), Vec::<String>::new());
        // `each` ends the reading.
        let mut count = 0;
        read_lines(&b"a\nb\nc\n"[..], 4, 100, |_| {
            count += 1;
            count == 2
        });
        assert_eq!(count, 2);
        // A source with no end and no line (`/dev/zero`), and one that is
        // all lines: read to the file's bound and no further, a line's
        // bound of memory at a time.
        // (Fewer bytes under miri, which interprets each.)
        let scale = if cfg!(miri) { 4 } else { 0 };
        let mut seen = 0u64;
        read_lines(std::io::repeat(0), 64, (1 << 16) >> scale, |_| {
            seen += 1;
            false
        });
        assert_eq!(seen, 0);
        read_lines(std::io::repeat(b'\n'), 64, (1 << 12) >> scale, |line| {
            assert_eq!(line, b"\n");
            seen += 1;
            false
        });
        assert_eq!(seen, (1 << 12) >> scale);
        // A source that fails is read as far as it went.
        struct Fails(u8);
        impl std::io::Read for Fails {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                self.0 += 1;
                match (self.0, buffer.first_mut()) {
                    (1, Some(b)) => {
                        *b = b'\n';
                        Ok(1)
                    }
                    _ => Err(std::io::Error::other("no more")),
                }
            }
        }
        seen = 0;
        read_lines(Fails(0), 64, 100, |_| {
            seen += 1;
            false
        });
        assert_eq!(seen, 1);
        // The bounds themselves: a megabyte a line, and what a hosts file
        // of any use is far inside.
        assert_eq!(LINE_LIMIT, 1 << 20);
        assert_eq!(FILE_LIMIT, 1 << 28);
        assert_eq!(CONF_LIMIT, 1 << 20);
    }

    #[test]
    fn addresses_are_kept_once_each_and_bounded() {
        let v4 = |n: u32| IpAddr::V4(Ipv4Addr::from(n));
        assert_eq!(
            distinct_addresses([v4(1), v4(2), v4(1), v4(3), v4(2)].into_iter()),
            [v4(1), v4(2), v4(3)]
        );
        let count = if cfg!(miri) { 300 } else { 1000 };
        let many = distinct_addresses((0..count).map(v4));
        assert_eq!(many.len(), MAX_ADDRESSES);
        assert_eq!(many.last(), Some(&v4(127)));
        // Repeats do not count against the bound.
        let repeats = distinct_addresses((0..count).map(|n| v4(n % 200)));
        assert_eq!(repeats.len(), MAX_ADDRESSES);
        assert_eq!(repeats.last(), Some(&v4(127)));
        assert_eq!(MAX_ADDRESSES, 128);
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
junk 20tcp
junk2 21 tcp
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
            ("junk", "tcp", None),
            ("junk2", "tcp", None),
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
        // `files` not first: the system's resolver answers, which reads
        // the file in its own way.
        std::fs::write(&nss, "hosts: dns files\n").unwrap();
        assert_eq!(lookup("two", false, None), ips(&["10.9.9.9", "10.9.9.8"]));
        assert_eq!(take(), ["two"]);
        // No nsswitch.conf at all, or none with a line for hosts: glibc's
        // own `files dns` (measured: the C finds the file's name with no
        // query, and asks DNS for one the file lacks).
        std::fs::remove_file(&nss).unwrap();
        assert_eq!(lookup("two", false, None), ips(&["127.0.0.2"]));
        assert_eq!(lookup("six", true, None), ips(&["::1"]));
        std::fs::write(&nss, "passwd: files\n").unwrap();
        assert_eq!(lookup("two", false, None), ips(&["127.0.0.2"]));
        assert_eq!(take(), Vec::<String>::new());
        assert_eq!(lookup("elsewhere", true, None), ips(&["fd00::9"]));
        assert_eq!(take(), ["elsewhere"]);
        // A line no `\n` ends is no line.
        std::fs::write(&nss, "hosts: dns").unwrap();
        assert_eq!(lookup("two", false, None), ips(&["127.0.0.2"]));
        // A nsswitch.conf glibc refuses names no host, nor does a line
        // with no source, nor a file that is a directory; a number is one
        // all the same.
        for refused in ["passwd: files [\n", "hosts:\n", "hosts: [x] files\n"] {
            std::fs::write(&nss, refused).unwrap();
            assert_eq!(lookup("two", false, None), ips(&[]), "{refused:?}");
            assert_eq!(lookup("elsewhere", false, None), ips(&[]), "{refused:?}");
            assert_eq!(lookup("127.1", false, None), ips(&["127.0.0.1"]));
        }
        let directory = GlibcFiles {
            nsswitch: &dir,
            ..files
        };
        assert_eq!(
            glibc_host(b"two", false, &directory, None, &mut |_| ips(&["10.9.9.9"])),
            ips(&[])
        );
        assert_eq!(take(), Vec::<String>::new());
        // What the file found is the answer unless the line says to merge
        // it (no answer) or to read on, where the next source's replaces
        // it; alone, `continue` changes nothing.
        std::fs::write(&nss, "hosts: files [SUCCESS=merge] dns\n").unwrap();
        assert_eq!(lookup("two", false, None), ips(&[]));
        assert_eq!(take(), Vec::<String>::new());
        std::fs::write(&nss, "hosts: files [SUCCESS=continue] dns\n").unwrap();
        assert_eq!(lookup("two", false, None), ips(&["10.9.9.9", "10.9.9.8"]));
        assert_eq!(take(), ["two"]);
        std::fs::write(&nss, "hosts: files [SUCCESS=continue]\n").unwrap();
        assert_eq!(lookup("two", false, None), ips(&["127.0.0.2"]));
        // A name the file lacks is asked of the system where the line
        // reads on: not where `files` is alone, nor past a `return`.
        std::fs::write(&nss, "hosts: files\n").unwrap();
        assert_eq!(lookup("elsewhere", false, None), ips(&[]));
        std::fs::write(&nss, "hosts: files [!SUCCESS=return] dns\n").unwrap();
        assert_eq!(lookup("elsewhere", false, None), ips(&[]));
        assert_eq!(take(), Vec::<String>::new());
        std::fs::write(&nss, "hosts: files [NOTFOUND=merge] dns\n").unwrap();
        assert_eq!(lookup("elsewhere", true, None), ips(&["fd00::9"]));
        assert_eq!(take(), ["elsewhere"]);
        // No hosts file: `files` is unavailable, which is its own status.
        let no_hosts = GlibcFiles {
            hosts: &dir.join("nosuch"),
            ..files
        };
        let mut system = |_: &str| ips(&["10.9.9.9"]);
        std::fs::write(&nss, "hosts: files [NOTFOUND=return] dns\n").unwrap();
        assert_eq!(
            glibc_host(b"two", false, &no_hosts, None, &mut system),
            ips(&["10.9.9.9"])
        );
        std::fs::write(&nss, "hosts: files [UNAVAIL=return] dns\n").unwrap();
        assert_eq!(
            glibc_host(b"two", false, &no_hosts, None, &mut system),
            ips(&[])
        );
        assert_eq!(lookup("elsewhere", false, None).len(), 2);
        take();
        // Only so much of nsswitch.conf is read: a line past the bound is
        // not there.
        let mut long = vec![b'#'; usize::try_from(CONF_LIMIT).unwrap()];
        long.extend_from_slice(b"\nhosts: dns\n");
        std::fs::write(&nss, &long).unwrap();
        assert_eq!(
            nsswitch_conf(&nss),
            Conf::Text(long[..long.len() - 12].to_vec())
        );
        assert_eq!(lookup("two", false, None), ips(&["127.0.0.2"]));
        assert_eq!(take(), Vec::<String>::new());
        std::fs::write(&nss, "hosts: files dns\n").unwrap();
        // The files' readers.
        assert_eq!(
            hosts_in_file(&hosts, b"dual", false, true),
            NssAnswer::Success(ips(&["127.0.0.2", "127.0.0.1"]))
        );
        assert_eq!(
            hosts_in_file(&hosts, b"nobody", false, true),
            NssAnswer::NotFound
        );
        assert_eq!(
            hosts_in_file(&dir.join("nosuch"), b"dual", false, true),
            NssAnswer::Unavail
        );
        // What is no regular file is no file: a directory here (a FIFO
        // would hold the C until something wrote to it).
        assert_eq!(
            hosts_in_file(&dir, b"dual", false, true),
            NssAnswer::Unavail
        );
        assert!(!file_lines(&dir, |_| false));
        assert!(file_lines(&hosts, |_| true));
        assert_eq!(conf_file(&dir, 100), Conf::Unreadable);
        assert_eq!(conf_file(&dir.join("nosuch"), 100), Conf::Missing);
        assert_eq!(small_file(&dir, 100), b"");
        std::fs::write(&conf, "x 7/tcp\ny 8/tcp\n").unwrap();
        assert_eq!(service_in_file(&conf, b"y", b"tcp"), NssAnswer::Success(8));
        assert_eq!(service_in_file(&conf, b"z", b"tcp"), NssAnswer::NotFound);
        assert_eq!(
            service_in_file(&dir.join("nosuch"), b"y", b"tcp"),
            NssAnswer::Unavail
        );
        assert_eq!(small_file(&conf, 3), b"x 7");
        assert_eq!(conf_file(&conf, 3), Conf::Text(b"x 7".to_vec()));
        assert_eq!(small_file(&dir.join("nosuch"), 3), b"");
        // A service, by the sources nsswitch.conf gives `services`
        // (measured through the C: `-i TCP:name` under each line).
        for (line, want) in [
            (None, Some(8)),
            (Some("hosts: files\n"), Some(8)),
            (Some("services: files\n"), Some(8)),
            (Some("services: db files\n"), Some(8)),
            (Some("services: db\n"), None),
            (Some("services: db [UNAVAIL=return] files\n"), None),
            (Some("services: files [SUCCESS=merge]\n"), None),
            (Some("services:\n"), None),
            (Some("passwd: files [\n"), None),
            (Some("services: db"), Some(8)),
        ] {
            match line {
                Some(line) => std::fs::write(&nss, line).unwrap(),
                None => std::fs::remove_file(&nss).unwrap(),
            }
            assert_eq!(glibc_service(b"y", b"tcp", &conf, &nss), want, "{line:?}");
            assert_eq!(glibc_service(b"z", b"tcp", &conf, &nss), None, "{line:?}");
        }
        std::fs::write(&nss, "services: files [NOTFOUND=return]\n").unwrap();
        assert_eq!(glibc_service(b"y", b"tcp", &dir.join("nosuch"), &nss), None);
        // A line past the line's bound is passed over, and the next read.
        let mut long = vec![b'x'; LINE_LIMIT + 1];
        long.extend_from_slice(b" 9/tcp\ny 8/tcp\n");
        std::fs::write(&conf, &long).unwrap();
        assert_eq!(service_in_file(&conf, b"y", b"tcp"), NssAnswer::Success(8));
        let name = vec![b'x'; LINE_LIMIT + 1];
        assert_eq!(service_in_file(&conf, &name, b"tcp"), NssAnswer::NotFound);
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

    /// `gethostbyaddr()` and `getservbyport()` read off the files by glibc's
    /// rules (DIVERGENCES 154), each measured through the C: the first line
    /// that gives the address, its first name, empty where it has none, an
    /// IPv6 loopback or v4-mapped line naming the IPv4 address; a service by
    /// port and protocol, compared exactly; the whole file for the scan.
    #[test]
    fn names_for_addresses_and_ports_are_read_as_glibc_reads_them() {
        let name = |line: &str, ip: &str| {
            hosts_line_name(line.as_bytes(), ip.parse().unwrap())
                .map(|n| String::from_utf8_lossy(n).into_owned())
        };
        assert_eq!(
            name("127.0.0.1 localhost x", "127.0.0.1").as_deref(),
            Some("localhost")
        );
        assert_eq!(name("127.0.0.7", "127.0.0.7").as_deref(), Some(""));
        assert_eq!(name("127.0.0.7 # c", "127.0.0.7").as_deref(), Some(""));
        assert_eq!(
            name("127.0.0.4\tfour\ttab", "127.0.0.4").as_deref(),
            Some("four")
        );
        assert_eq!(
            name(" 127.0.0.8 lead", "127.0.0.8").as_deref(),
            Some("lead")
        );
        assert_eq!(name("#127.0.0.3 c", "127.0.0.3"), None);
        assert_eq!(name("::1 six", "127.0.0.1").as_deref(), Some("six"));
        assert_eq!(
            name("::ffff:127.0.0.9 m", "127.0.0.9").as_deref(),
            Some("m")
        );
        assert_eq!(name("::1 six", "::1").as_deref(), Some("six"));
        assert_eq!(name("127.0.0.1 four", "::1"), None);
        assert_eq!(name("127.0.0.01 z", "127.0.0.1"), None);
        let entry = |line: &str| {
            services_entry(line.as_bytes()).map(|(n, p, pr)| {
                (
                    String::from_utf8_lossy(n).into_owned(),
                    p,
                    String::from_utf8_lossy(pr).into_owned(),
                )
            })
        };
        assert_eq!(
            entry("http 80/tcp www # web"),
            Some(("http".into(), 80, "tcp".into()))
        );
        assert_eq!(entry("x 0x50/udp"), Some(("x".into(), 80, "udp".into())));
        assert_eq!(entry("x 65616/TCP"), Some(("x".into(), 80, "TCP".into())));
        assert_eq!(entry("x 80"), Some(("x".into(), 80, "".into())));
        assert_eq!(entry("x 80x/tcp"), None);
        assert_eq!(entry("x 99999999999/tcp"), None);
        assert_eq!(entry("# x 80/tcp"), None);
    }

    #[test]
    #[cfg_attr(miri, ignore = "it writes and reads files, slowly under miri")]
    fn reverse_lookups_walk_nsswitch_over_files_of_their_own() {
        let dir = std::env::temp_dir().join(format!("lsof-rs-rnames-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (hosts, conf, nss, svc) = (
            dir.join("hosts"),
            dir.join("host.conf"),
            dir.join("nsswitch.conf"),
            dir.join("services"),
        );
        std::fs::write(
            &hosts,
            "127.0.0.1 localhost\n127.0.0.2 two\n127.0.0.2 dup\n",
        )
        .unwrap();
        std::fs::write(&svc, "s1 4001/tcp\nU 4005/TCP\nu1 4002/udp\n").unwrap();
        let files = GlibcFiles {
            hosts: &hosts,
            host_conf: &conf,
            nsswitch: &nss,
        };
        let asked = std::cell::RefCell::new(Vec::new());
        let by_addr = |ip: &str, answer: NssAnswer<String>| {
            let mut dns = |ip: IpAddr| {
                asked.borrow_mut().push(ip);
                answer.clone()
            };
            glibc_host_by_addr(ip.parse().unwrap(), &files, &[], &mut dns)
                .map(|n| String::from_utf8_lossy(&n).into_owned())
        };
        let found = || NssAnswer::Success("dns.example".to_string());
        std::fs::write(&nss, "hosts: files dns\n").unwrap();
        assert_eq!(by_addr("127.0.0.2", found()).as_deref(), Some("two"));
        assert_eq!(
            by_addr("127.0.0.3", found()).as_deref(),
            Some("dns.example")
        );
        assert_eq!(by_addr("127.0.0.3", NssAnswer::NotFound), None);
        assert_eq!(asked.borrow().len(), 2);
        std::fs::write(&nss, "hosts: dns files\n").unwrap();
        assert_eq!(
            by_addr("127.0.0.2", NssAnswer::NotFound).as_deref(),
            Some("two")
        );
        std::fs::write(&nss, "hosts: dns [NOTFOUND=return] files\n").unwrap();
        assert_eq!(by_addr("127.0.0.2", NssAnswer::NotFound), None);
        // DNS's TRYAGAIN and UNAVAIL go on to the file there (measured).
        for answer in [NssAnswer::TryAgain, NssAnswer::Unavail] {
            assert_eq!(by_addr("127.0.0.2", answer).as_deref(), Some("two"));
        }
        std::fs::write(&nss, "hosts: dns [TRYAGAIN=return] files\n").unwrap();
        assert_eq!(by_addr("127.0.0.2", NssAnswer::TryAgain), None);
        assert_eq!(
            by_addr("127.0.0.2", NssAnswer::Unavail).as_deref(),
            Some("two")
        );
        std::fs::write(&nss, "hosts: files\n").unwrap();
        asked.borrow_mut().clear();
        assert_eq!(by_addr("127.0.0.3", found()), None);
        assert!(asked.borrow().is_empty());
        // No file: glibc's built-in `files dns`.
        std::fs::remove_file(&nss).unwrap();
        assert_eq!(by_addr("127.0.0.1", found()).as_deref(), Some("localhost"));
        // Services.
        assert_eq!(
            glibc_service_by_port(4001, b"tcp", &svc, &nss),
            Some(b"s1".to_vec())
        );
        assert_eq!(glibc_service_by_port(4001, b"udp", &svc, &nss), None);
        assert_eq!(glibc_service_by_port(4005, b"tcp", &svc, &nss), None);
        let scan = |svc: &std::path::Path, nss: &std::path::Path| {
            let mut n = 0usize;
            glibc_services(svc, nss, &mut |_, _, _| n += 1);
            n
        };
        assert_eq!(scan(&svc, &nss), 3);
        std::fs::write(&nss, "services: db files\n").unwrap();
        assert_eq!(scan(&svc, &nss), 3);
        std::fs::write(&nss, "services: db [UNAVAIL=return] files\n").unwrap();
        assert_eq!(scan(&svc, &nss), 0);
        assert_eq!(glibc_service_by_port(4001, b"tcp", &svc, &nss), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// `SUCCESS=merge`, for a database with no merge function (every one
    /// here): the answer kept aside, the walk on by `UNAVAIL`'s action, the
    /// next source asked giving it back where it does not succeed and
    /// failing it where it does (glibc 2.39's `getXXbyYY_r()`; measured
    /// through the C under `hosts: files [SUCCESS=merge] dns`).
    #[test]
    fn a_merge_keeps_the_answer_where_the_next_source_fails() {
        let walk = |line: &str, dns: Option<NssAnswer<u8>>| {
            let sources = nss_action_parse(line.as_bytes(), true).unwrap();
            let mut asked = Vec::new();
            let got = nss_walk(&sources, |module| {
                asked.push(String::from_utf8_lossy(module).into_owned());
                match module {
                    b"files" => Some(NssAnswer::Success(1u8)),
                    b"dns" => dns,
                    _ => None,
                }
            });
            (got, asked.join(" "))
        };
        let merge = "files [SUCCESS=merge] dns";
        assert_eq!(
            walk(merge, Some(NssAnswer::NotFound)),
            (Some(1), "files dns".into())
        );
        assert_eq!(
            walk(merge, Some(NssAnswer::Unavail)),
            (Some(1), "files dns".into())
        );
        assert_eq!(
            walk(merge, Some(NssAnswer::TryAgain)),
            (Some(1), "files dns".into())
        );
        assert_eq!(
            walk(merge, Some(NssAnswer::Success(2))),
            (None, "files dns".into())
        );
        // A later source that cannot be asked is stepped over: nothing
        // gives the answer back.
        assert_eq!(
            walk("files [SUCCESS=merge] sss", None),
            (None, "files sss".into())
        );
        assert_eq!(walk("files [SUCCESS=merge]", None), (None, "files".into()));
        // `UNAVAIL=return` ends the walk at the merge.
        assert_eq!(
            walk(
                "files [SUCCESS=merge UNAVAIL=return] dns",
                Some(NssAnswer::NotFound)
            ),
            (None, "files".into())
        );
        // The answer given back is the next source's SUCCESS, whose action
        // then decides: `continue` reads on, still merging (glibc leaves
        // `do_merge` set), so a third source that fails gives it back
        // again, and one that succeeds fails the merge.
        assert_eq!(
            walk(
                "files [SUCCESS=merge] dns [SUCCESS=continue] dns",
                Some(NssAnswer::NotFound)
            ),
            (Some(1), "files dns dns".into())
        );
        assert_eq!(
            walk(
                "files [SUCCESS=merge] dns [SUCCESS=continue] files",
                Some(NssAnswer::NotFound)
            ),
            (None, "files dns files".into())
        );
    }

    /// host.conf's `trim` as glibc's `_res_hconf_init()` reads it (each
    /// rule measured through the C, `trim` variants of 2026-11-14).
    #[test]
    fn trim_domains_are_read_and_cut_as_glibc_does() {
        let t = |text: &str| -> Vec<String> {
            host_conf_trim(text.as_bytes())
                .iter()
                .map(|d| String::from_utf8_lossy(d).into_owned())
                .collect()
        };
        assert_eq!(t("trim .a.com\n"), [".a.com"]);
        assert_eq!(t("trim .bb;.cc\n"), [".bb;.cc"]);
        assert_eq!(t("trim .bb ;.cc\n"), [".bb", ".cc"]);
        assert_eq!(t("trim .bb :.cc\n"), [".bb", ".cc"]);
        assert_eq!(t("trim .bb,.cc\n"), [".bb", ".cc"]);
        assert_eq!(t("trim .bb#.cc\n"), [".bb"]);
        assert_eq!(t("trim .bb, \n"), [".bb"]);
        assert_eq!(t("TRIM .BB\n"), [".BB"]);
        assert_eq!(t("  # x\n\ttrim\t.bb\n"), [".bb"]);
        assert_eq!(t("trim .bb\0 .cc\n"), [".bb"]);
        assert_eq!(t("trim\ntrim .bb\n"), ["", ".bb"]);
        assert_eq!(t("multi on\nnospoof off\n"), Vec::<String>::new());
        // At most four, every line's together.
        assert_eq!(t("trim .a .b .c .d .e\n"), [".a", ".b", ".c", ".d"]);
        assert_eq!(t("trim .a .b .c\ntrim .d .e\n"), [".a", ".b", ".c", ".d"]);
        // A line is what one fgets() into 256 bytes reads.
        let long = format!("{}trim .bb\ntrim .cc\n", "#".repeat(250));
        assert_eq!(t(&long), [".cc"]);
        // The environment: added after the file's, then in their place.
        let d = |file: &str, add: Option<&str>, replace: Option<&str>| -> Vec<String> {
            trim_domains(
                file.as_bytes(),
                add.map(str::as_bytes),
                replace.map(str::as_bytes),
            )
            .iter()
            .map(|d| String::from_utf8_lossy(d).into_owned())
            .collect()
        };
        assert_eq!(d("trim .aa\n", Some(".bb"), None), [".aa", ".bb"]);
        assert_eq!(d("trim .aa\n", Some(".bb"), Some(".cc")), [".cc"]);
        assert_eq!(
            d("trim .a .b .c\n", Some(".d .e"), None),
            [".a", ".b", ".c", ".d"]
        );
        // The cut: the first domain that ends a longer name, in any case.
        let cut = |name: &str, domains: &[&str]| {
            let mut n = name.as_bytes().to_vec();
            let domains: Vec<Vec<u8>> = domains.iter().map(|d| d.as_bytes().to_vec()).collect();
            trim_domain(&mut n, &domains);
            String::from_utf8(n).unwrap()
        };
        assert_eq!(cut("two.EXAMPLE", &[".example"]), "two");
        assert_eq!(cut("good.example.com", &["example.com"]), "good.");
        assert_eq!(cut("example", &["example"]), "example");
        assert_eq!(cut("x.other", &[".example"]), "x.other");
        assert_eq!(cut("two.bb", &["", ".bb"]), "two.bb");
        assert_eq!(cut("a.b.c", &[".c", ".b.c"]), "a.b");
    }

    /// A hosts file glibc would wait on or read for ever ends the lookup
    /// with no name and no query; one that answers at once (a directory,
    /// the null device, none) does not, and the name is trimmed.
    #[test]
    #[cfg(unix)]
    #[cfg_attr(miri, ignore = "it makes files and a FIFO")]
    fn a_hosts_file_that_holds_glibc_ends_the_lookup() {
        let dir = std::env::temp_dir().join(format!("lsof-rs-held-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let nss = dir.join("nsswitch.conf");
        std::fs::write(&nss, "hosts: files dns\n").unwrap();
        let lookup = |hosts: &std::path::Path, nss: &std::path::Path| {
            let files = GlibcFiles {
                hosts,
                host_conf: hosts,
                nsswitch: nss,
            };
            let mut calls = 0;
            let mut dns = |_: IpAddr| {
                calls += 1;
                NssAnswer::Success("dns.example".to_string())
            };
            let trim = [b".example".to_vec()];
            let got = glibc_host_by_addr("127.0.0.1".parse().unwrap(), &files, &trim, &mut dns);
            (got.map(|n| String::from_utf8(n).unwrap()), calls)
        };
        let fifo = dir.join("fifo");
        let made = std::process::Command::new("mkfifo").arg(&fifo).status();
        if made.is_ok_and(|s| s.success()) {
            assert_eq!(lookup(&fifo, &nss), (None, 0), "a FIFO");
            // DNS first: answered before the hosts file is reached.
            std::fs::write(dir.join("dnsfirst"), "hosts: dns files\n").unwrap();
            assert_eq!(
                lookup(&fifo, &dir.join("dnsfirst")),
                (Some("dns".into()), 1)
            );
        }
        #[cfg(target_os = "linux")]
        {
            assert_eq!(lookup(std::path::Path::new("/dev/zero"), &nss), (None, 0));
            assert_eq!(
                lookup(std::path::Path::new("/dev/null"), &nss),
                (Some("dns".into()), 1)
            );
            // The null device is a file with no line: NOTFOUND, which
            // `[NOTFOUND=return]` ends the walk at.
            std::fs::write(dir.join("nfret"), "hosts: files [NOTFOUND=return] dns\n").unwrap();
            assert_eq!(
                lookup(std::path::Path::new("/dev/null"), &dir.join("nfret")),
                (None, 0)
            );
            assert!(file_lines(std::path::Path::new("/dev/null"), |_| false));
            assert_eq!(
                conf_file(std::path::Path::new("/dev/null"), 100),
                Conf::Text(Vec::new())
            );
            // glibc's built-in sources for an empty nsswitch.conf.
            let null = nsswitch_conf(std::path::Path::new("/dev/null"));
            let hosts = nsswitch_database(&null, b"hosts", HOSTS_DEFAULT).unwrap();
            let modules: Vec<&[u8]> = hosts.iter().map(|s| s.module).collect();
            assert_eq!(modules, [&b"files"[..], b"dns"]);
        }
        assert_eq!(lookup(&dir, &nss), (Some("dns".into()), 1), "a directory");
        // A `hosts:` line with no source names nothing and asks nothing,
        // where the C dies in glibc in some runs (DIVERGENCES 154).
        std::fs::write(dir.join("nosource"), "hosts:\n").unwrap();
        assert_eq!(lookup(&dir.join("hosts"), &dir.join("nosource")), (None, 0));
        assert_eq!(lookup(&dir.join("nosuch"), &nss), (Some("dns".into()), 1));
        std::fs::write(dir.join("hosts"), "127.0.0.1 local.EXAMPLE\n").unwrap();
        assert_eq!(lookup(&dir.join("hosts"), &nss), (Some("local".into()), 0));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A FIFO put where a regular file was looked at cannot hold the open:
    /// it is opened without blocking and refused.
    #[test]
    #[cfg(unix)]
    #[cfg_attr(miri, ignore = "miri cannot make a FIFO")]
    fn an_open_of_a_fifo_that_raced_in_returns_no_file() {
        let dir = std::env::temp_dir().join(format!("lsof-rs-race-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let fifo = dir.join("fifo");
        let made = std::process::Command::new("mkfifo").arg(&fifo).status();
        if made.is_ok_and(|s| s.success()) {
            let (tx, rx) = std::sync::mpsc::channel();
            let path = fifo.clone();
            std::thread::spawn(move || {
                let _ = tx.send(open_nonblocking_regular(&path).is_none());
            });
            let got = rx.recv_timeout(std::time::Duration::from_secs(30));
            if got.is_err() {
                // Let the stuck open go before failing.
                let mut w = std::fs::OpenOptions::new();
                w.write(true);
                std::os::unix::fs::OpenOptionsExt::custom_flags(&mut w, crate::safefs::NONBLOCK);
                let _ = w.open(&fifo);
            }
            assert_eq!(got, Ok(true));
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
