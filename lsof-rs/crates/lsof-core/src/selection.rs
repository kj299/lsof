//! The selection / filtering engine — the portable equivalent of the option
//! handling in lsof's `src/arg.c` + `src/main.c`.
//!
//! lsof's selection rule, which this reproduces exactly, is a set membership
//! test rather than a chain of filters (`lib/proc.c:is_file_sel`, seven lines
//! that decide everything):
//!
//! * Each **list option** is a *kind* of selector ([`SelKinds`], the C's `SEL*`
//!   bits). [`Selection::specified`] is the set of kinds this run gave — the
//!   C's `Selflags`.
//! * Every file accumulates the set of kinds *it* matched. A file starts with
//!   the set its **process** matched (`lib/proc.c:178`, `Lf->sf = Lp->sf`) and
//!   then ORs in the file-level kinds it matches itself.
//! * With no `-a`, a file is listed when that set is **non-empty** — matching
//!   any one specified selector is enough. This is lsof's documented
//!   OR-by-default ("list options that are specifically stated are ORed").
//! * With `-a`, the set must **contain every specified kind**.
//! * With no selectors at all, everything is listed (the C's `AllProc`).
//!
//! The consequence that surprises everyone, verified against the C: without
//! `-a`, `lsof -d ^mem -p PID` lists the whole host, *including* that PID's
//! `mem` rows — they inherit the PID kind from their process even though the
//! fd selector excluded them. Adding `-a` gives the intersection everyone
//! expected. lsof-rs got this wrong until it was measured (DIVERGENCES.md #4).
//!
//! `-s` is deliberately **not** a list option: the C has no `SEL*` bit for
//! socket state, so it can only veto a row, never select one. Same for the
//! `-s` exclusion form, which is the C's `SELEXCLF` — an absolute veto that
//! outranks the OR.

use crate::backend::MountEntry;
use crate::model::{tcp_state_table, FdType, FileType, OpenFile, Process, Protocol, TcpState};

/// A set of selector *kinds* — lsof's "list options", the ones that take part
/// in its OR-by-default / `-a`-ANDs rule. Mirrors the C's `SEL*` bits and their
/// `SELPROC` / `SELFILE` / `SELNW` groupings (`lib/common.h:536-580`).
///
/// A tiny hand-rolled bitset rather than a dependency: `lsof-core` is zero-dep
/// by policy, and this needs six operations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SelKinds(u16);

impl SelKinds {
    /// No kinds — the C's `Selflags == 0` (before it defaults to `SelAll`).
    pub const NONE: Self = Self(0);
    /// `-p`, the C's `SELPID`.
    pub const PID: Self = Self(1 << 0);
    /// `-u`, the C's `SELUID`.
    pub const UID: Self = Self(1 << 1);
    /// `-c`, the C's `SELCMD`.
    pub const CMD: Self = Self(1 << 2);
    /// `-g`, the C's `SELPGID`.
    pub const PGID: Self = Self(1 << 3);
    /// `-d`, the C's `SELFD`.
    pub const FD: Self = Self(1 << 4);
    /// `-i`, the C's `SELNET`.
    pub const NET: Self = Self(1 << 5);
    /// `-U`, the C's `SELUNX`.
    pub const UNX: Self = Self(1 << 6);
    /// A path / `+d` / `+D` argument, the C's `SELNM`.
    pub const NM: Self = Self(1 << 7);
    /// `+L`, the C's `SELNLINK`.
    pub const NLINK: Self = Self(1 << 8);
    /// `-K`, the C's `SELTASK`. Unlike every other kind this one is asymmetric:
    /// it takes part in the OR, so a bare `lsof -K` lists tasks and nothing
    /// else, but it is dropped from the `-a` requirement, so `lsof -K -a -p N`
    /// still shows that process's own rows alongside its tasks. Measured, not
    /// derived — see `Selection::apply`.
    pub const TASK: Self = Self(1 << 9);
    /// `-N`, the C's `SELNFS`.
    pub const NFS: Self = Self(1 << 10);
    /// An `-i` address specification (`-iTCP`, `-i:80`), the C's `SELNA` —
    /// a kind of its own, apart from [`SelKinds::NET`] (a bare `-i`). Under
    /// `-a` the two are separate requirements: `lsof -a -p P -i -i:9` lists
    /// only P's Internet files on port 9, measured, where one shared kind
    /// listed every Internet file of P.
    pub const NA: Self = Self(1 << 11);

    /// The process selecters — the C's `SELPROC`. A file inherits these from
    /// its process; the rest it must match itself.
    pub const PROC: Self = Self(Self::PID.0 | Self::UID.0 | Self::CMD.0 | Self::PGID.0);
    /// The file and network selecters — the C's `SELFILE | SELNW`.
    ///
    /// This mask is what decides that a process with no surviving rows is not
    /// a result. Leaving a file-level kind out of it is silent: `-N` selected
    /// correctly and still printed a bare `unk unknown` line for every process
    /// on the host, because the emptiness rule did not know `-N` was a file
    /// selecter. Any new kind added below belongs here too.
    pub const FILE: Self = Self(
        Self::FD.0
            | Self::NET.0
            | Self::NA.0
            | Self::UNX.0
            | Self::NM.0
            | Self::NLINK.0
            | Self::NFS.0,
    );

    /// No selector of any kind — the run selects everything (`AllProc`).
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
    /// Every kind in `other` is present. The `-a` test.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
    /// At least one kind in `other` is present.
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }
    /// The kinds present in both.
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }
    /// The kinds present in either.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
    /// This set with `other`'s kinds removed.
    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
    /// How many kinds are present.
    pub const fn count(self) -> u32 {
        self.0.count_ones()
    }
    fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

/// Parsed `-i` Internet filter.
/// Everything `-i` asked for — which is two different kinds of thing, and
/// the C keeps them apart (`main.c`, `arg.c`):
///
/// * a bare `-i`, `-i4` or `-i6` selects **every** Internet file (of one IP
///   version, or both). It is one search item, `Fnet`: the run exits 1 unless
///   such a file is *listed*, and `-V` says `no Internet files located`.
/// * each address specification — `-iTCP`, `-i:80`, `-i@10.0.0.1:22` — is
///   its **own** search item, `Nwad`, ORed with the others: `-V` names the
///   one nobody matched (`Internet address not located: :80`).
///
/// lsof-rs had one set of fields that every `-i` overwrote, so
/// `lsof -i :80 -i :443` selected port 443 alone, and every unmatched spec
/// was reported as `no Internet files located`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InetFilter {
    /// `-i` was given in any form.
    pub enabled: bool,
    /// A bare `-i`, `-i4` or `-i6` was given — the C's `Fnet`.
    pub all: bool,
    /// Which IP version the bare form selects — the C's `FnetTy`: `Some(4)`,
    /// `Some(6)`, or `None` for both. See [`InetFilter::add_all`] for how
    /// repeated forms combine.
    pub all_family: Option<u8>,
    /// The address specifications, in the order given.
    pub specs: Vec<InetSpec>,
}

/// One `-i` address specification: `[46][proto][@host][:ports]`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InetSpec {
    /// The specification as given, for `-V`.
    pub text: String,
    /// Restrict to one protocol.
    pub proto: Option<Protocol>,
    /// Restrict to IP version `4` or `6`.
    pub family: Option<u8>,
    /// Restrict to these port ranges (inclusive), local or remote; empty is
    /// any port. `:22,80` and `:1-1024` are both lists of ranges here, as in
    /// the C's `sport`/`eport`.
    pub ports: Vec<(u16, u16)>,
    /// Restrict to this address, local or remote. The C compares the address
    /// bytes, so this is an exact comparison — never a substring match, which
    /// let `@127.0.0.1` match `127.0.0.10`.
    pub host: Option<std::net::IpAddr>,
}

impl InetFilter {
    /// True when a requested protocol is only visible through the ETW AFD
    /// capture — RAW and ICMP have no IP Helper table — so `-iRAW`/`-iICMP`
    /// must imply the (Administrator-only) capture the way `-U` does, or the
    /// filter would silently match nothing.
    pub fn needs_etw(&self) -> bool {
        self.specs
            .iter()
            .any(|s| matches!(s.proto, Some(Protocol::Other(_))))
    }

    /// A bare `-i` (`family` `None`), `-i4` or `-i6`. The C's rule for
    /// combining them (`arg.c`, `enter_network_address()`), which is not
    /// symmetric: a bare `-i` resets to both versions, while a `-i4` or `-i6`
    /// after it narrows to that version, and two different versions widen
    /// back to both. So `-i4 -i6` and `-i4 -i` select both, `-i -i4` IPv4.
    pub fn add_all(&mut self, family: Option<u8>) {
        self.enabled = true;
        match family {
            None => self.all_family = None,
            Some(ft) if !self.all => self.all_family = Some(ft),
            Some(ft) => match self.all_family {
                Some(cur) if cur != ft => self.all_family = None,
                Some(_) => {}
                None => self.all_family = Some(ft),
            },
        }
        self.all = true;
    }

    /// Whether the bare form is in effect: given as such, or — for a filter
    /// built by hand as `InetFilter { enabled: true, .. }`, which is what
    /// `enabled` alone meant before specifications were a list — implied by
    /// `-i` with no specification at all.
    pub fn bare(&self) -> bool {
        self.all || (self.enabled && self.specs.is_empty())
    }

    /// Whether `f` is selected by the bare form.
    pub fn all_matches(&self, f: &OpenFile) -> bool {
        self.bare() && f.is_internet() && family_matches(self.all_family, f)
    }
}

impl InetSpec {
    /// Whether `f` satisfies this specification (`lib/misc.c`, `is_nw_addr()`).
    pub fn matches(&self, f: &OpenFile) -> bool {
        let Some(sock) = &f.socket else {
            return false;
        };
        if !f.is_internet() || !family_matches(self.family, f) {
            return false;
        }
        // Protocol names are family-agnostic (like TCP/UDP): `-iICMP` matches
        // both the v4 `ICMP` and v6 `ICMPV6` codes, with the `[46]` prefix as
        // the family narrower.
        let proto_ok = match self.proto {
            None => true,
            Some(p) if p == sock.protocol => true,
            Some(Protocol::Other("ICMP")) => sock.protocol == Protocol::Other("ICMPV6"),
            Some(_) => false,
        };
        if !proto_ok {
            return false;
        }
        // The C tests each end of the connection in turn, and the address and
        // the port must match on the SAME end (`is_nw_addr()` per address).
        let end_matches = |a: Option<std::net::SocketAddr>| -> bool {
            let Some(a) = a else { return false };
            if let Some(h) = self.host {
                if a.ip() != h {
                    return false;
                }
            }
            self.ports.is_empty()
                || self
                    .ports
                    .iter()
                    .any(|&(lo, hi)| (lo..=hi).contains(&a.port()))
        };
        if self.host.is_none() && self.ports.is_empty() {
            return true;
        }
        end_matches(sock.local) || end_matches(sock.remote)
    }
}

/// `-i4`/`-i6` narrowing: `None` is either version.
fn family_matches(family: Option<u8>, f: &OpenFile) -> bool {
    match family {
        None => true,
        Some(fam) => (fam == 6) == (f.file_type == crate::model::FileType::Ipv6),
    }
}

/// `-E` (Info) vs `+E` (Files) pipe-endpoint display modes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointMode {
    /// `-E`: annotate pipe rows with peer endpoint info (server/client PID
    /// and command).
    Info,
    /// `+E`: annotate, and also display the peer processes' own pipe rows
    /// even when those processes match no selector.
    Files,
}

/// `-T [fqsw]`: which TCP/TPI facts a socket row shows.
///
/// These **select**, they do not add. The C keeps one bitset (`Ftcptpi`) and
/// `-T<letters>` clears it before ORing in each letter, so `-T q` shows the
/// queues and *not* the state — the state is what `s` asks for, and it is the
/// default only because nothing else was said. A bare `-T` selects nothing at
/// all (`main.c`: `Ftcptpi = (GOp == '-') ? 0 : TCPTPI_STATE`), which is how
/// lsof is told to stop annotating socket rows; `+T` is the way back to the
/// default. [`TcpInfoFlags::default`] is therefore all-false — "show nothing" —
/// and the absence of any `-T` is [`TcpInfoFlags::DEFAULT`], state alone.
///
/// `f` is the socket's **options** (`SO=ACCEPTCON,…`), not "follow": the C's
/// `TCPTPI_FLAGS`. Its Linux dialect fills `lts.opt` only for AF_UNIX rows,
/// whose printer ignores everything but the state, so `-T f` there selects
/// something that never prints. Accepted and carried; nothing renders it yet.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TcpInfoFlags {
    pub state: bool,
    pub queue: bool,
    pub window: bool,
    /// `f`: socket options. Parsed and stored; no renderer emits them.
    pub options: bool,
}

impl TcpInfoFlags {
    /// What a run with no `-T` at all shows: the connection state.
    pub const DEFAULT: Self = Self {
        state: true,
        queue: false,
        window: false,
        options: false,
    };

    /// Whether anything at all is selected — the C's `Ftcptpi` being non-zero.
    pub fn any(self) -> bool {
        self.state || self.queue || self.window || self.options
    }
}

/// `-K` / `-K i`: whether a process's other threads are listed as entries of
/// their own.
///
/// The C does not have a boolean here. Tasks are a *selector kind* (`SELTASK`),
/// and `Selflags` defaults to `SelAll` — every kind — but only when no selector
/// was given at all (`main.c`: `Selflags = SelAll`). So a bare `lsof` lists
/// threads and `lsof -p 123` does not, without either being a special case:
/// naming any selector replaces the "everything" set with that selector's bits,
/// and `SELTASK` is not among them. `-K` puts it back explicitly; `-K i` takes
/// it out of `SelAll` so even a bare run omits it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TaskMode {
    /// No `-K`: tasks are listed only when nothing else was selected.
    #[default]
    WhenUnselected,
    /// `-K`: list tasks, whatever else was selected.
    Always,
    /// `-K i`: never list tasks.
    Never,
}

/// `-f` / `+f`: how a path argument is read.
///
/// Lsof.8: "Normally a path name argument is taken to be a file system name if
/// it matches a mounted\-on directory name reported by `mount(8)`, or if it
/// represents a block device, named in the `mount` output and associated with a
/// mounted directory name." The two flags force the question either way.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FilesystemArgs {
    /// No flag: a mounted-on directory, or a **block-device** mount source, is
    /// a file system; anything else is a plain file.
    #[default]
    Auto,
    /// `-f`: every path argument is a plain file. `lsof -f -- /` looks for open
    /// files *named* `/`, not for everything on the root filesystem.
    NeverFilesystem,
    /// `+f`: every path argument is a file system, and any source name is
    /// accepted, not just a block device — "useful, for example, when the file
    /// system name (mounted-on device) isn't a block device". lsof complains
    /// and exits 1 for an argument that names no mount.
    AlwaysFilesystem,
}

/// The devices of every mounted filesystem that `path` names, under `mode`.
///
/// lsof's rule, from `arg.c`'s `ck_file_arg`: the path names a file system when
/// it equals a mount's mounted-on **directory**, or — when the mount's source
/// is a block device, or `+f` widened the test to any source — the mount's
/// **source**. Empty means "not a file system", and the caller then reads the
/// argument as a plain file (or, under `+f`, refuses it).
///
/// **Every** match, not the first: one argument can name several mounts (`+f --
/// tmpfs` names all of them), the C makes a separate search item of each, and
/// a run that finds files on one and nothing on the others still exits 1.
pub fn filesystems_named(mounts: &[MountEntry], path: &str, mode: FilesystemArgs) -> Vec<u64> {
    if mode == FilesystemArgs::NeverFilesystem {
        return Vec::new();
    }
    let any_source = mode == FilesystemArgs::AlwaysFilesystem;
    let mut devs: Vec<u64> = mounts
        .iter()
        .filter(|m| {
            m.dir == path
                || ((any_source || m.source_is_block) && m.source.as_deref() == Some(path))
        })
        .map(|m| m.device)
        .collect();
    devs.sort_unstable();
    devs.dedup();
    devs
}

/// The C's `CMDL`: characters of the command name the COMMAND column shows
/// when `+c` says nothing (`lib/common.h`, applied at `lsof.c:110`). Not
/// dialect-specific — the same nine on every platform the C builds for.
pub const DEFAULT_COMMAND_WIDTH: usize = 9;

/// `+c <n>`: how much of the command name the COMMAND column shows — the C's
/// `CmdLim`.
///
/// Three states, not an `Option<usize>`, because `+c 0` and "no `+c` at all"
/// are different answers and both would otherwise be `None`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CommandWidth {
    /// No `+c` given: [`DEFAULT_COMMAND_WIDTH`].
    #[default]
    Standard,
    /// `+c 0` — Lsof.8: "If w is zero (0), all command characters are printed."
    /// The C tests `CmdLim && len > CmdLim`, so zero is no cap rather than a
    /// cap of nothing.
    Unlimited,
    /// `+c <n>`.
    Chars(usize),
}

impl CommandWidth {
    /// The cap in printed characters; `None` for no cap.
    pub fn cap(self) -> Option<usize> {
        match self {
            CommandWidth::Standard => Some(DEFAULT_COMMAND_WIDTH),
            CommandWidth::Unlimited => None,
            CommandWidth::Chars(n) => Some(n),
        }
    }
}

/// Parsed `-s [proto:state[,state]]` selector. Includes/excludes apply to
/// TCP/UDP sockets only; rows without a recognized state are passed through
/// when only TCP filters are set. Multiple includes are OR-ed; an exclude
/// kills the row even if it also matches an include.
/// `-s TCP:<states>`: the C's `TcpStI` and `TcpStX` — every state any `-s`
/// named, each list kept once, in the order given.
///
/// There is one filter, not one per `-s`: the C's tables are global, so
/// `-sTCP:LISTEN -sTCP:ESTABLISHED` is one inclusion list of two (lsof-rs kept
/// only the last `-s` until 2026-09-25). It is a TCP filter only — `-s UDP:`
/// is refused where the C crashes (DIVERGENCES 32) — but on Linux it filters
/// UDP sockets too, by the TCP number the kernel reuses for them (see
/// [`SocketInfo::filter_state`](crate::model::SocketInfo::filter_state)).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StateFilter {
    /// States a TCP or UDP socket must be in to be listed at all — and each
    /// one is a **search item**: a state no examined socket was in makes the
    /// run exit 1, and `-V` says `TCP state not located: <STATE>`.
    pub include: Vec<TcpState>,
    /// States that exclude a socket absolutely, before any other selection.
    pub exclude: Vec<TcpState>,
}

impl StateFilter {
    /// Whether `-s` lets `f` through. Only a socket carrying a TCP state is
    /// tested; every other file passes. A state outside the platform's table
    /// passes too — the C checks `i < TcpNstates` before either list — which
    /// on Linux is a kernel state newer than the C's table (`NEW_SYN_RECV`).
    pub fn admits(&self, f: &OpenFile) -> bool {
        let Some(state) = f.socket.as_ref().and_then(|s| s.filter_state()) else {
            return true;
        };
        if !tcp_state_table().contains(&state) {
            return true;
        }
        if self.exclude.contains(&state) {
            return false;
        }
        self.include.is_empty() || self.include.contains(&state)
    }
}

/// A `-d` file-descriptor filter: which FD slots to include / exclude.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FdFilter {
    pub include: Vec<FdSpec>,
    pub exclude: Vec<FdSpec>,
}

/// One `-d` term.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FdSpec {
    /// A special FD kind (`cwd`, `rtd`, `txt`, `mem`).
    Named(FdKind),
    /// A single numeric handle value.
    Num(u64),
    /// An inclusive numeric handle-value range.
    Range(u64, u64),
}

/// The named FD kinds selectable with `-d`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FdKind {
    Cwd,
    Rtd,
    Txt,
    Mem,
    /// `DEL`: a mapped file that has been deleted.
    Del,
    /// `NOFD`: the row for an fd directory that could not be opened.
    NoFd,
}

impl FdSpec {
    fn matches(&self, fd: &FdType) -> bool {
        match (self, fd) {
            (FdSpec::Named(FdKind::Cwd), FdType::Cwd) => true,
            (FdSpec::Named(FdKind::Rtd), FdType::Root) => true,
            (FdSpec::Named(FdKind::Txt), FdType::Txt) => true,
            (FdSpec::Named(FdKind::Mem), FdType::Mem) => true,
            (FdSpec::Named(FdKind::Del), FdType::Deleted) => true,
            (FdSpec::Named(FdKind::NoFd), FdType::NoFd) => true,
            (FdSpec::Num(n), FdType::Handle(h)) => h == n,
            (FdSpec::Range(a, b), FdType::Handle(h)) => h >= a && h <= b,
            _ => false,
        }
    }
}

impl FdFilter {
    /// Whether `fd` passes the filter (exclusions win; an empty include = all).
    fn matches(&self, fd: &FdType) -> bool {
        if self.exclude.iter().any(|s| s.matches(fd)) {
            return false;
        }
        self.include.is_empty() || self.include.iter().any(|s| s.matches(fd))
    }
}

/// How `-c` compares its value with a command name.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CommandMatch {
    /// The C's rule, and the default: the value is a **case-sensitive
    /// prefix** of the command — `is_cmd_excl()`'s `strncmp(sp->str, cmd,
    /// sp->len)`. So `-c py` finds `python3`, while `-c ytho` and `-c PYTHON`
    /// find nothing. lsof-rs had matched case-insensitively and by substring
    /// on every platform, so on Linux both of those listed `python3` where the
    /// C exited 1.
    #[default]
    Prefix,
    /// The Windows port's rule: case-insensitive, and a substring counts.
    /// Image names are case-insensitive there (`Explorer.EXE`) and carry an
    /// extension, so the C's rule would be a poorer fit; there is no oracle
    /// to hold it to either way.
    Forgiving,
}

/// One `-u` value the platform resolved to a numeric user ID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UidSel {
    pub uid: u32,
    /// The login name it was given as, if it was given as one — `-V` reports
    /// the two differently: `login name (UID 1000) not located: alice`
    /// against `user ID not located: 1000`.
    pub login: Option<String>,
}

/// Which process-level search items some process located — each vector
/// parallel to the [`Selection`] list of the same name. See
/// [`Selection::locate`] for the rules.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Located {
    pub pids: Vec<bool>,
    pub pgids: Vec<bool>,
    pub uids: Vec<bool>,
    pub users: Vec<bool>,
    pub commands: Vec<bool>,
    /// Parallel to `sel.inet.specs`.
    pub inet: Vec<bool>,
    /// The bare `-i`/`-i4`/`-i6` item (the C's `Fnet == 2`).
    pub inet_all: bool,
    /// The `-N` item (the C's `Fnfs == 2`).
    pub nfs: bool,
    /// Parallel to `sel.state_filter`'s `include` (the C's `TcpStI[i] == 2`).
    pub states: Vec<bool>,
}

/// The full set of user-specified filters for one run.
#[derive(Clone, Debug, Default)]
pub struct Selection {
    pub pids: Vec<u32>,
    /// `-p ^pid`: never list this process. An absolute exclusion like the
    /// other `^` forms, and not a search item — the C reports only the PIDs
    /// it was asked to *include* (`if (Spid[i].f || Spid[i].x) continue`).
    pub pid_excludes: Vec<u32>,
    /// `-g pgid`, on a platform with process groups: select by process group
    /// (the C's `SELPGID`). Windows has none and reads `-g` as
    /// [`Selection::ppid_filter`] instead.
    pub pgids: Vec<u32>,
    /// `-g ^pgid`: never list a process in this group.
    pub pgid_excludes: Vec<u32>,
    /// `-u` values matched by **name** — the Windows port's way, where an
    /// account is a SID and the comparison is against the rendered
    /// `DOMAIN\user`. On Linux every value is resolved to a numeric ID
    /// instead and lands in [`Selection::uids`].
    pub users: Vec<String>,
    /// `-u` values resolved to user IDs, as the C resolves them while it
    /// parses: a number is the ID, a name goes through the password file. The
    /// process's real UID is what is compared, so `-u 0` and `-u root` are the
    /// same selection — `-u 0` had matched nothing on Linux, because it was
    /// compared with the name `root`.
    pub uids: Vec<UidSel>,
    /// `-u ^value`, resolved the same way.
    pub uid_excludes: Vec<u32>,
    pub commands: Vec<String>,
    /// How [`Selection::commands`] and [`Selection::command_excludes`]
    /// compare — the C's case-sensitive prefix unless the CLI says otherwise.
    pub command_match: CommandMatch,
    /// `-u ^name` / `-u ^uid`: accounts whose processes are never listed.
    ///
    /// Lsof.8: "A negated login name or user ID selection is neither ANDed nor
    /// ORed with other selections; it is applied before all other selections
    /// and absolutely excludes the listing of the files of the process." So
    /// this is not a [`SelKinds`] kind at all — it cannot select anything, and
    /// it outranks every selector that could, `-a` or no `-a`.
    pub user_excludes: Vec<String>,
    /// `-c ^name`: commands whose processes are never listed. The same
    /// absolute exclusion as [`Selection::user_excludes`] (Lsof.8 `-c`: "then
    /// the following characters specify a command name whose processes are to
    /// be ignored").
    pub command_excludes: Vec<String>,
    pub inet: InetFilter,
    /// `-a`: AND together the specified process selectors.
    pub and_mode: bool,
    /// `-n`: do not resolve host names.
    pub no_host_resolve: bool,
    /// `-P`: do not resolve port names.
    pub no_port_resolve: bool,
    /// `-t`: terse output (PIDs only).
    pub terse: bool,
    /// `-V`: verbose — report inaccessible processes and unmatched search items.
    pub verbose: bool,
    /// Bare path arguments: report files whose name equals one of these
    /// (resolved efficiently via Restart Manager when possible).
    pub paths: Vec<String>,
    /// `+D` / `+d` directory arguments: report files whose name is under one of
    /// these directory prefixes (requires full enumeration).
    pub dir_trees: Vec<String>,
    /// `+d <dir>`: report files in this directory, **one level only** — the
    /// directory itself and its immediate entries, not the tree beneath it.
    /// lsof distinguishes this from `+D`; conflating them both misses and
    /// invents rows.
    pub dirs_one_level: Vec<String>,
    /// The `(DEVICE, NODE)` identities named by the path arguments, resolved
    /// once at startup through [`Backend::identify_path`](crate::Backend) and
    /// expanded for `+d`/`+D`.
    ///
    /// lsof matches a path argument by **what the file is, not what it is
    /// called** — which is why it finds a file queried through a hard link and
    /// why naming a directory does not drag in everything under it. Empty when
    /// no path was given, or when the backend cannot identify paths; in the
    /// latter case selection falls back to matching names, which is what the
    /// Windows backend still does.
    pub path_ids: std::collections::HashSet<(String, String)>,
    /// `-d`: file-descriptor filter.
    pub fd_filter: Option<FdFilter>,
    /// `-s TCP:<states>`: the socket state filter, e.g. `TCP:LISTEN`,
    /// `TCP:^TIME_WAIT`, `TCP:LISTEN,ESTABLISHED`. Only sockets carrying a TCP
    /// state are tested; every other row is unaffected. `None` when no `-s`
    /// named a state.
    pub state_filter: Option<StateFilter>,
    /// `-g <ppid>[,<ppid>...]`: Windows-extension semantics — select
    /// processes whose PPID is in this list (the closest analog to lsof's
    /// `-g` PGID filter, since Windows has no process groups).
    pub ppid_filter: Vec<u32>,
    /// `-l`: render numeric IDs (raw SID string) instead of the resolved
    /// account name in the USER column.
    pub numeric_ids: bool,
    /// `-Q`: mute every search failure, **status included**.
    ///
    /// The C clears `ErrStat` under it and never sets `LSOF_SEARCH_FAILURE`,
    /// so `lsof -Q /nope`, `lsof -Q /an/unopened/file` and
    /// `lsof -Q -p 999999` all exit 0, and an argument set where nothing could
    /// be `stat()`ed stops being fatal. Suppressing the message alone — which
    /// this did — leaves the half that `if lsof -Q …; then` branches on.
    pub quiet: bool,
    /// `-w` sets this, `+w` clears it (default `false` — warnings on):
    /// suppresses the privilege-hint and other non-fatal stderr warnings.
    pub suppress_warnings: bool,
    /// The C's `Fwarn` as it bears on ROWS: set by `-w` and by `-t` (the C's
    /// `-t` sets `Fwarn` too), cleared by `+w`, the last one winning —
    /// measured: `-t +w` lists an unreadable process and `+w -t` does not.
    ///
    /// When set, a backend makes no row for a file it cannot read, where it
    /// would otherwise report it with the reason (`/proc/1/cwd (readlink:
    /// Permission denied)`) — and a process left with none is not listed
    /// (DIVERGENCES 37). Kept apart from [`Selection::suppress_warnings`]
    /// because `-t` must not silence the Windows privilege hint: that hint is
    /// on stderr, and `kill $(lsof -t …)` reads stdout.
    pub omit_unreadable: bool,
    /// `-f` / `+f`: whether a path argument may name a file system.
    pub filesystem_args: FilesystemArgs,
    /// Whether the backend identifies paths by `(device, node)`
    /// ([`Backend::identifies_paths`](crate::backend::Backend::identifies_paths)).
    /// When it does not, path selection compares names instead.
    pub paths_identified: bool,
    /// Devices of the filesystems named by path arguments. A file whose
    /// [`OpenFile::fs_device`] is in here matches the `SELNM` kind, which is
    /// how naming a mount point selects everything open on it.
    pub path_fs_devices: std::collections::HashSet<u64>,
    /// `+c <n>`: how much of the command name the COMMAND column shows.
    /// Defaults to [`CommandWidth::Standard`] — a plain `lsof` run caps it.
    pub command_width: CommandWidth,
    /// `--unicode`: enable UTF-8 output (banner / future Unicode glyphs) and
    /// switch the Windows console to CP 65001 at startup. Default (false) is
    /// pure ASCII output, which is the safe choice for legacy terminals like
    /// PowerShell 5.1 / cmd.exe whose default code page is Windows-1252.
    pub unicode_output: bool,
    /// `-L`: add the NLINK (link count) column to table output. Implies the
    /// renderer pulls `OpenFile::links` into a new column.
    pub show_links: bool,
    /// `-Z [context]`: SELinux security contexts.
    ///
    /// `None` when not given; `Some(list)` when it was, with the optional
    /// context arguments (the C globs them with `fnmatch`). The list being
    /// empty means a bare `-Z`.
    ///
    /// The C gates the whole option on `is_selinux_enabled()`, which asks
    /// whether **selinuxfs is mounted** — not whether `/sys/fs/selinux`
    /// exists. That distinction is load-bearing: on this port's test host the
    /// directory is there and empty while the file system is not mounted, so a
    /// presence check would answer "enabled" where the C answers "disabled".
    pub selinux: Option<Vec<String>>,
    /// `-N`: select files on an NFS file system.
    ///
    /// A **search item**, exactly like `-i`: `main.c` holds `Fnfs` at 1 until
    /// a saved row carries `SELNFS` and `if (Fnfs && Fnfs < 2)` at the end is
    /// a search failure. Measured — on a host with no NFS mount, `lsof -N`
    /// prints nothing and exits **1**, `lsof -a -N -p P` prints nothing and
    /// exits 1, and `lsof -N -p P` prints all of P's files and still exits 1,
    /// because the `-N` item was never located. `-V` says
    /// `lsof: no NFS files located`.
    pub nfs_only: bool,
    /// Devices of the NFS file systems in the mount table, filled by the CLI
    /// from [`Backend::mounts`](crate::backend::Backend::mounts). A file whose
    /// [`OpenFile::fs_device`] is in here is an NFS file.
    pub nfs_devices: std::collections::HashSet<u64>,
    /// `-e <fs>` / `+e <fs>`: mount points whose files must **not** be
    /// `stat(2)`ed. The C's reason is a hung NFS server; the consequence is a
    /// row built from the link target and fdinfo alone.
    ///
    /// Membership is decided by **path prefix**, never by a stat — that is the
    /// point of the option. Measured against the C, an exempted row loses
    /// every cell that comes from `stat`:
    ///
    /// ```text
    ///   without        with -e /
    ///   a r            a            (blank)
    ///   t REG          t UNKNfd
    ///   D 0xfe00       d UNKNOWN
    ///   s 5            -            (no size)
    ///   i 1908935      -            (no inode)
    ///   k 1            -            (no link count)
    ///   o 0t0          o 0t0        (fdinfo, kept)
    ///   n <path>       n <path> (-e /)
    /// ```
    pub exempt_fs: Vec<String>,
    /// `-x f` (and bare `-x`): let a `+d`/`+D` expansion cross file-system
    /// mount points. Default off — `arg.c:1029` skips an entry whose `st_dev`
    /// differs from the directory's.
    pub cross_filesystems: bool,
    /// `-x l` (and bare `-x`): let a `+d`/`+D` expansion follow a symbolic
    /// link. Default off, and this is the half lsof-rs had **backwards**: it
    /// resolved every entry through `metadata()`, so `+d DIR` selected a file
    /// that only a symlink inside DIR pointed at, where the C skips the link
    /// entirely (`arg.c:1038` — "Otherwise skip symbolic links").
    pub cross_symlinks: bool,
    /// `-X`: do not read the inet socket tables.
    ///
    /// The man page calls this "skip the reporting of information on all open
    /// TCP and UDP files", and **that is not what it does** — measured against
    /// the C, the rows are still printed, degraded:
    ///
    /// ```text
    /// 6u IPv4 14197 0t0 TCP 127.0.0.1:58679 (LISTEN)     without
    /// 6u sock  0,9  0t0 14197 can't identify protocol (-X specified)   with
    /// ```
    ///
    /// So it suppresses the *lookup*, not the row. `dsock.c` gates
    /// `/proc/net/{tcp,tcp6,udp,udp6,raw6}` on it — and, measured, **not**
    /// `/proc/net/raw`, `/proc/net/packet` or `/proc/net/unix`, which keep
    /// resolving. The IPv4/IPv6 raw split is an asymmetry in the C
    /// (`dsock.c:3530` has no guard where `:3761` does); see DIVERGENCES.
    pub skip_inet_tables: bool,
    /// `-H`: render the SIZE cell as a human-readable byte count in the table.
    /// A pure formatting flag — it selects nothing, and the C applies it to the
    /// table alone, leaving `-F` and JSON in raw bytes.
    pub human_size: bool,
    /// `-K` / `-K i`: whether thread entries are listed. See [`TaskMode`] —
    /// the default is not "off", it is "on when nothing else was selected",
    /// which is the C's rule and not an approximation of it.
    pub tasks: TaskMode,
    /// `-T [fqsw]`: which TCP/TPI facts socket rows show. `None` means no `-T`
    /// was given, which is **not** the same as `-T` with no letters — see
    /// [`TcpInfoFlags`] — so ask [`Selection::tcp_info`] rather than reading
    /// this directly. `q` (queue) and `w` (window) come from per-connection
    /// extended TCP stats (`GetPerTcpConnectionEStats` on Windows), which
    /// require elevation. See `docs/feature-parity-plan.md` Phase 5B.
    pub tcp_info_opt: Option<TcpInfoFlags>,
    /// `-U`: list UNIX-domain (AF_UNIX) sockets. On Windows these surface only
    /// via the ETW AFD path, so `-U` implies the (Administrator-only) ETW
    /// capture and restricts socket output to the AF_UNIX family.
    pub unix_only: bool,
    /// `-E` / `+E`: pipe endpoint info. On Windows the peer PIDs come from the
    /// documented `GetNamedPipe{Server,Client}ProcessId` APIs, queried on the
    /// already-duplicated pipe handle during enumeration. `Info` annotates
    /// pipe rows; `Files` additionally shows the peer processes' pipe rows
    /// (see [`Process::endpoint_peer`]).
    pub endpoints: Option<EndpointMode>,
    /// `+L <count>`: keep only files whose link count is **less than** `count`
    /// (lsof convention). `+L 1` keeps link-count-zero files — the
    /// "unlinked but still open" security case. Files with unknown links
    /// (sockets, non-disk handles) pass through.
    pub max_links: Option<u32>,
    /// `--etw`: opt-in ETW realtime capture for socket families IP Helper
    /// doesn't enumerate (raw/ICMP/AF_UNIX). Off by default; needs elevation.
    /// See `docs/research-roadmap.md` §5.
    pub use_etw: bool,
}

impl Selection {
    /// Whether tasks should be listed on this run, resolving the C's rule:
    /// `SELTASK` is in the default "everything" set, so a run with **no
    /// selector at all** lists them, and naming any selector drops them unless
    /// `-K` asks explicitly.
    pub fn lists_tasks(&self) -> bool {
        match self.tasks {
            TaskMode::Always => true,
            TaskMode::Never => false,
            TaskMode::WhenUnselected => self.specified().is_empty() && !self.has_path_filter(),
        }
    }

    /// Which TCP/TPI facts to show, resolving "no `-T` given" to the default.
    ///
    /// The distinction the `Option` carries is real: `None` is "the user said
    /// nothing", which shows the state, while `Some(TcpInfoFlags::default())`
    /// is a bare `-T`, which shows nothing.
    pub fn tcp_info(&self) -> TcpInfoFlags {
        self.tcp_info_opt.unwrap_or(TcpInfoFlags::DEFAULT)
    }

    /// Which process selecters `p` matches — the C's `lp->sf`
    /// (`lib/proc.c:is_proc_excl`). A kind absent from
    /// [`Selection::specified`] can never appear here.
    fn proc_kinds(&self, p: &Process) -> SelKinds {
        let mut k = SelKinds::NONE;
        // A task entry matches the `-K` kind; the process's own entry does not.
        if p.tid.is_some() {
            k.insert(SelKinds::TASK);
        }
        if !self.pids.is_empty() && self.pids.contains(&p.pid) {
            k.insert(SelKinds::PID);
        }
        if self.users_match(p) {
            k.insert(SelKinds::UID);
        }
        if self
            .commands
            .iter()
            .any(|c| self.command_matches(c, &p.command))
        {
            k.insert(SelKinds::CMD);
        }
        if p.pgid.is_some_and(|g| self.pgids.contains(&g)) {
            k.insert(SelKinds::PGID);
        }
        // `-g` Windows extension: select processes whose parent is in the PPID
        // list (the closest analog to PGID selection on Unix).
        if !self.ppid_filter.is_empty() && p.ppid.is_some_and(|pp| self.ppid_filter.contains(&pp)) {
            k.insert(SelKinds::PGID);
        }
        k
    }

    /// Which file selecters `f` matches — the bits the C ORs into `lf->sf`
    /// (`lib/proc.c:219`, `:420`, and the dialect code). Note `-d ^mem` is an
    /// *inclusion* here exactly as in the C: a file the exclusion does not name
    /// matches the fd selecter and can be listed on that basis alone
    /// (`lib/proc.c:223`, `if (fds != 1) Lf->sf |= SELFD`).
    fn file_kinds(&self, f: &OpenFile) -> SelKinds {
        let mut k = SelKinds::NONE;
        if let Some(fd) = &self.fd_filter {
            if fd.matches(&f.fd) {
                k.insert(SelKinds::FD);
            }
        }
        if self.unix_only && f.file_type == FileType::Unix {
            k.insert(SelKinds::UNX);
        }
        if self.nfs_only && f.fs_device.is_some_and(|d| self.nfs_devices.contains(&d)) {
            k.insert(SelKinds::NFS);
        }
        if self.inet.all_matches(f) {
            k.insert(SelKinds::NET);
        }
        if self.inet.specs.iter().any(|s| s.matches(f)) {
            k.insert(SelKinds::NA);
        }
        if self.has_path_filter() && self.path_matches(f) {
            k.insert(SelKinds::NM);
        }
        if let Some(max) = self.max_links {
            // `+L count`: keep links < count. Unknown links (sockets etc.)
            // pass, as they always have.
            if !matches!(f.links, Some(n) if n >= max) {
                k.insert(SelKinds::NLINK);
            }
        }
        k
    }

    /// Whether `f`'s name is one of the path arguments or under one of the
    /// `+d`/`+D` trees. Only called when such an argument was given.
    fn path_matches(&self, f: &OpenFile) -> bool {
        // A path argument that named a FILE SYSTEM matches every file on it —
        // the C's `HbyFsd` branch in `is_file_named()`, a plain `s->dev ==
        // Lf->dev`. It is tested first and independently: the argument has no
        // identity of its own, and this must hold for a row the backend could
        // not otherwise identify.
        //
        // The comparison is against the FILESYSTEM device, never the DEVICE
        // cell: that cell shows `st_rdev` for a device node, so keying on it
        // made `lsof /` match every character device on the host. This is why
        // the rule waited for `OpenFile::fs_device` to exist.
        if !self.path_fs_devices.is_empty() {
            if let Some(dev) = f.fs_device {
                if self.path_fs_devices.contains(&dev) {
                    return true;
                }
            }
        }
        // Identity next: a path argument names a *file*, and lsof matches the
        // file it names however that file is reached. `+d`/`+D` were already
        // expanded into this set, so a directory tree is just more identities.
        if self.paths_identified {
            if let (Some(dev), Some(node)) = (f.device.as_deref(), f.node.as_deref()) {
                if self.path_ids.contains(&(dev.to_string(), node.to_string())) {
                    return true;
                }
            }
            // A row with no identity (a socket, a row the backend could not
            // stat) can still be named exactly — `lsof /run/x.sock` should find
            // the AF_UNIX socket bound there, which has a name but no inode of
            // its own on this row.
            return self.paths.contains(&f.name);
        }
        // The backend cannot identify a path, so fall back to matching names.
        // This is the Windows path today, and it is a fallback rather than a
        // second rule: the C has no name-prefix matching for a bare path
        // argument at all.
        let name = f.name.to_ascii_lowercase();
        let exact = self.paths.iter().any(|p| {
            let p = p.to_ascii_lowercase();
            name == p || name.starts_with(&p)
        });
        exact
            || self
                .dir_trees
                .iter()
                .any(|d| under_dir(&name, &d.to_ascii_lowercase()))
            || self
                .dirs_one_level
                .iter()
                .any(|d| directly_in_dir(&name, &d.to_ascii_lowercase()))
    }

    /// Whether `f` survives `-s`. An exclusion, applied before every other
    /// selection rule and never ORed or ANDed (Lsof.8's list of `^` items) —
    /// see [`StateFilter::admits`].
    fn state_matches(&self, f: &OpenFile) -> bool {
        self.state_filter
            .as_ref()
            .is_none_or(|filter| filter.admits(f))
    }

    /// Whether `p` is absolutely excluded by a `^` negation on `-u`, `-c`,
    /// `-g` or `-p`.
    ///
    /// Applied before everything else and never ORed or ANDed, per Lsof.8.
    /// Verified against the C: `lsof -c ^sleep -p <a sleep's pid>` prints
    /// nothing, with or without `-a`, even though `-p` names that very
    /// process.
    pub fn excludes_process(&self, p: &Process) -> bool {
        self.command_excludes
            .iter()
            .any(|c| self.command_matches(c, &p.command))
            || self
                .user_excludes
                .iter()
                .any(|u| user_matches(u, p.user.as_deref()))
            || p.uid.is_some_and(|u| self.uid_excludes.contains(&u))
            || self.pid_excludes.contains(&p.pid)
            || p.pgid.is_some_and(|g| self.pgid_excludes.contains(&g))
    }

    /// Whether `p`'s owner is one of the `-u` inclusions, by name or by ID.
    fn users_match(&self, p: &Process) -> bool {
        self.users
            .iter()
            .any(|u| user_matches(u, p.user.as_deref()))
            || p.uid.is_some_and(|u| self.uids.iter().any(|s| s.uid == u))
    }

    /// `-c`'s comparison, under this run's [`CommandMatch`].
    fn command_matches(&self, needle: &str, command: &str) -> bool {
        match self.command_match {
            CommandMatch::Prefix => command.starts_with(needle),
            CommandMatch::Forgiving => {
                let c = command.to_ascii_lowercase();
                let n = needle.to_ascii_lowercase();
                c.starts_with(&n) || c.contains(&n)
            }
        }
    }

    /// Which `-p`, `-g`, `-u` and `-c` values some process **located** — the
    /// C's search-item marks (`Spid[i].f`, `Spgid[i].f`, `Suid[i].f`,
    /// `str->f`), from the processes the backend gathered, before any file is
    /// selected: `lsof -a -p P -d 999` lists nothing and still exits 0.
    ///
    /// * A process an exclusion drops locates nothing. The C tests the
    ///   `-u ^`/`-g ^`/`-p ^` exclusions before it marks anything; it tests
    ///   `-c ^` *after* marking `-p`/`-g`/`-u`, so there `-c ^sleep -p <a
    ///   sleep>` does count the pid as located. lsof-rs does not follow that
    ///   ordering artefact, and loses nothing by it: under the C the same run
    ///   exits 1 anyway, because a `-c ^` value is itself never marked
    ///   (DIVERGENCES 13).
    /// * `-p`, `-g` and `-u` are located by a matching process whatever else
    ///   the run asked for — under `-a` too (`is_proc_excl()` marks each list
    ///   in turn before it decides the AND).
    /// * `-c` is located only by a process that got as far as the command
    ///   test: under `-a`, one that also matched every `-p`/`-g`/`-u` kind the
    ///   run specified (`dproc.c`: `is_proc_excl(…) || is_cmd_excl(…)`).
    /// * **Every** matching `-c` value is located, not only the first. The C
    ///   stops at the first match (`sp->f = 1; return (0);`), so `lsof -c py
    ///   -c python` exits 1 with `command not located: py` although python3
    ///   matched both — and `-c x -c x` can never succeed. That is ledgered as
    ///   a C defect and not reproduced (DIVERGENCES 13).
    /// * An `-i` address specification is located by a matching file of any
    ///   process that got past the process tests — a file-level selector that
    ///   later drops the row does not undo it (`is_nw_addr()` marks while the
    ///   file is being built). Every matching specification, again, where the
    ///   C marks only the first (`n->f = 1; return (1);`): `-i:80 -iTCP` on a
    ///   TCP port-80 socket exits 1 there.
    /// * The bare `-i` and `-N` items the same way: the C sets `Fnet = 2` and
    ///   `Fnfs = 2` in `link_lfile()`, for every file it keeps while building
    ///   the process, and `-a` is only applied at print time. So `lsof -a -p P
    ///   -i -d 3` lists nothing and exits **0** when P has a socket on another
    ///   fd — measured; judging by the listed rows had made it 1.
    /// * A socket that `-s` vetoes locates nothing: the C drops it by state
    ///   before it is linked or matched (`-a -p P -i:80 -s TCP:ESTABLISHED`
    ///   on a listener exits 1 with `Internet address not located: :80`).
    pub fn locate(&self, gathered: &[Process]) -> Located {
        let mut found = Located {
            pids: vec![false; self.pids.len()],
            pgids: vec![false; self.pgids.len()],
            uids: vec![false; self.uids.len()],
            users: vec![false; self.users.len()],
            commands: vec![false; self.commands.len()],
            inet: vec![false; self.inet.specs.len()],
            inet_all: false,
            nfs: false,
            states: vec![false; self.state_filter.as_ref().map_or(0, |f| f.include.len())],
        };
        let and_kinds = self
            .specified()
            .intersection(SelKinds::PID.union(SelKinds::UID).union(SelKinds::PGID));
        for p in gathered {
            if self.excludes_process(p) {
                continue;
            }
            for (hit, &pid) in found.pids.iter_mut().zip(&self.pids) {
                *hit |= p.pid == pid;
            }
            for (hit, &g) in found.pgids.iter_mut().zip(&self.pgids) {
                *hit |= p.pgid == Some(g);
            }
            for (hit, s) in found.uids.iter_mut().zip(&self.uids) {
                *hit |= p.uid == Some(s.uid);
            }
            for (hit, u) in found.users.iter_mut().zip(&self.users) {
                *hit |= user_matches(u, p.user.as_deref());
            }
            if self.and_mode && !self.proc_kinds(p).contains(and_kinds) {
                continue;
            }
            for (hit, c) in found.commands.iter_mut().zip(&self.commands) {
                *hit |= self.command_matches(c, &p.command);
            }
            // Its files are examined only if the process passed the command
            // test as well.
            if self.and_mode && !self.proc_selected(self.proc_kinds(p)) {
                continue;
            }
            // A state is located by a socket in it, whatever else happens to
            // the row: the C marks `TcpStI` while it reads the socket, before
            // `-d`, `-i` or `-a` have had a say — measured, `lsof -a -p P -d
            // 10 -sTCP:LISTEN` exits 0 on a P whose listener is fd 4.
            if let Some(filter) = &self.state_filter {
                for f in &p.files {
                    if let Some(state) = f.socket.as_ref().and_then(|s| s.filter_state()) {
                        for (hit, want) in found.states.iter_mut().zip(&filter.include) {
                            *hit |= state == *want;
                        }
                    }
                }
            }
            for f in p.files.iter().filter(|f| self.state_matches(f)) {
                for (hit, spec) in found.inet.iter_mut().zip(&self.inet.specs) {
                    *hit = *hit || spec.matches(f);
                }
                found.inet_all |= self.inet.all_matches(f);
                found.nfs |=
                    self.nfs_only && f.fs_device.is_some_and(|d| self.nfs_devices.contains(&d));
            }
        }
        found
    }

    /// The set of selector kinds this run specified — the C's `Selflags`
    /// (`src/main.c:1199-1240`). Empty means "no selectors at all", the C's
    /// `AllProc`: everything is listed.
    pub fn specified(&self) -> SelKinds {
        let mut k = SelKinds::NONE;
        if !self.pids.is_empty() {
            k.insert(SelKinds::PID);
        }
        if !self.users.is_empty() || !self.uids.is_empty() {
            k.insert(SelKinds::UID);
        }
        if !self.commands.is_empty() {
            k.insert(SelKinds::CMD);
        }
        if !self.pgids.is_empty() || !self.ppid_filter.is_empty() {
            k.insert(SelKinds::PGID);
        }
        if self.fd_filter.is_some() {
            k.insert(SelKinds::FD);
        }
        if self.inet.bare() {
            k.insert(SelKinds::NET);
        }
        if !self.inet.specs.is_empty() {
            k.insert(SelKinds::NA);
        }
        if self.unix_only {
            k.insert(SelKinds::UNX);
        }
        if self.nfs_only {
            k.insert(SelKinds::NFS);
        }
        // Only an explicit `-K` specifies the kind. `TaskMode::WhenUnselected`
        // is the *absence* of a selector — it lists tasks precisely because
        // nothing was specified — so adding it here would turn every bare run
        // into a selected one.
        if self.tasks == TaskMode::Always {
            k.insert(SelKinds::TASK);
        }
        if self.has_path_filter() {
            k.insert(SelKinds::NM);
        }
        if self.max_links.is_some() {
            k.insert(SelKinds::NLINK);
        }
        k
    }

    /// Whether a backend must enumerate `p` at all — the only safe way to skip
    /// work, now that selection ORs.
    ///
    /// This is *not* "is `p` selected": under the OR rule a file selecter can
    /// select a file of a process that matches no process selecter, so
    /// `lsof -d 3 -p PID` has to walk every process on the host. Skipping is
    /// therefore allowed only when no file selecter was given (so nothing but
    /// the process selecters can bring a row in), or under `-a`, where a
    /// process failing any specified process selecter can contribute nothing.
    /// The C gets the same effect from `is_proc_excl`'s `Selflags == SELPID`
    /// equality tests (`lib/proc.c:684-720`) — "is this the *only* selecter".
    ///
    /// One case walks more than it needs to print, because the C does and a
    /// search item can see it: with two or more process selecters and no
    /// `-a`, `is_proc_excl` skips nothing (only `Selflags == SELPID` and its
    /// like skip), so the C reads every process — and a `-s` state is located
    /// by a socket in ANY process it read. Measured: `lsof -p P -u X
    /// -sTCP:LISTEN` exits 0 on a host with a listener elsewhere, where
    /// `-p P` or `-u X` alone exits 1. Nothing else a walk locates can differ
    /// there, so the wider walk is taken only when `-s` names a state.
    pub fn selects_process(&self, p: &Process) -> bool {
        if self.excludes_process(p) {
            return false;
        }
        let specified = self.specified();
        if specified.is_empty() {
            return true;
        }
        if !self.and_mode && specified.intersects(SelKinds::FILE) {
            return true;
        }
        let locates_states = self
            .state_filter
            .as_ref()
            .is_some_and(|f| !f.include.is_empty());
        // `-K` is one of `is_proc_excl`'s kinds too: `-K -p P` reads every
        // process in the C, not P and the other processes' threads.
        let walked_kinds = specified.intersection(SelKinds::PROC.union(SelKinds::TASK));
        if locates_states && !self.and_mode && walked_kinds.count() > 1 {
            return true;
        }
        self.proc_selected(self.proc_kinds(p))
    }

    /// Whether the process *itself* satisfied the process-level selecters,
    /// under this run's OR/AND rule. A file's fate is decided by its own kind
    /// set, not by this; the two things that still ask are the bare
    /// process-row case in [`Selection::apply`] and the backend fast path.
    fn proc_selected(&self, kinds: SelKinds) -> bool {
        let spec = self.specified().intersection(SelKinds::PROC);
        if spec.is_empty() {
            return true;
        }
        if self.and_mode {
            kinds.contains(spec)
        } else {
            !kinds.is_empty()
        }
    }

    /// Whether any process-level selector (`-p` / `-u` / `-c` / `-g`) was given.
    pub fn has_process_selector(&self) -> bool {
        self.specified().intersects(SelKinds::PROC)
    }

    /// Whether the only rows this run can print are sockets — so a backend may
    /// skip collecting everything else instead of collecting it to be dropped.
    ///
    /// Derived from [`Selection::apply`]'s rule, not guessed at: a row survives
    /// when `inherited ∪ file_kinds(f)` is non-empty. A socket satisfies `-i`
    /// and `-U`; a mapped file, a cwd, a root, an executable and a plain fd
    /// satisfy neither, and can only come back through one of the other kinds.
    /// So every one of these has to be absent:
    ///
    /// * a **process** selecter (`-p`/`-u`/`-c`/`-g`) — a process it matches
    ///   contributes `inherited`, which selects *every* file it holds. This is
    ///   the OR rule, measured in P4: `lsof -N -p P` prints all of P's files.
    /// * `-d` (FD), a path/`+d`/`+D` argument (NM), `+L` (NLINK), `-N` (NFS) —
    ///   each is a file kind a non-socket row can match.
    /// * `-K` (TASK) — a task entry inherits it and brings its whole file set.
    /// * `-E`/`+E`, which is not a `SelKinds` at all: a peer process's **pipe**
    ///   rows are force-selected past the OR (`Lf->sf = Selflags`), so pipes
    ///   survive a run that specified only `-i`.
    ///
    /// An empty specified set is `AllProc` — everything prints — so it is not
    /// socket-only either. `-a` only makes the test stricter, so it needs no
    /// clause: anything this predicate allows to be skipped under the OR is
    /// still dropped under the AND.
    pub fn socket_rows_only(&self) -> bool {
        let spec = self.specified();
        !spec.is_empty()
            && spec
                .without(SelKinds::NET.union(SelKinds::NA).union(SelKinds::UNX))
                .is_empty()
            && self.endpoints.is_none()
    }

    /// Whether any path / directory-tree filter was given.
    pub fn has_path_filter(&self) -> bool {
        !self.paths.is_empty()
            || !self.dir_trees.is_empty()
            || !self.dirs_one_level.is_empty()
            || !self.path_fs_devices.is_empty()
    }

    /// Whether a `+D`/`+d` directory filter was given — which forces full
    /// enumeration rather than the Restart Manager fast path.
    pub fn has_dir_trees(&self) -> bool {
        !self.dir_trees.is_empty() || !self.dirs_one_level.is_empty()
    }

    /// Apply the full selection to a backend's raw output, returning the
    /// processes to display with their files already filtered.
    ///
    /// This is `lib/proc.c:is_file_sel` with the same structure: build the set
    /// of selecters each file matched, then test that set against the
    /// specified set — non-empty for the OR, complete for `-a`.
    pub fn apply(&self, procs: Vec<Process>) -> Vec<Process> {
        let specified = self.specified();
        let mut out = Vec::new();
        for mut p in procs {
            if self.excludes_process(&p) {
                continue; // any `^` negation: before all other selection
            }
            // The kinds this process matched. A file inherits them only if the
            // process matched something, the C's `PS_PRI` gate on
            // `Lf->sf = Lp->sf` (`lib/proc.c:178`).
            let inherited = self.proc_kinds(&p);
            let peer_only = p.endpoint_peer && inherited.is_empty();
            p.files.retain(|f| {
                // `-s` is not a list option: it can only veto. Its exclusion
                // form is the C's `SELEXCLF`, which outranks even the OR
                // (`lib/proc.c:572`).
                if !self.state_matches(f) {
                    return false;
                }
                if specified.is_empty() {
                    return true; // AllProc
                }
                // `+E`: a pipe row of a process pulled in only as an endpoint
                // peer is force-selected, exactly as the C does it
                // (`Lf->sf = Selflags`, `lib/proc.c:958`), so it survives both
                // the OR and the `-a` test.
                let sf = if peer_only {
                    if f.file_type != FileType::Pipe {
                        return false;
                    }
                    specified
                } else {
                    inherited.union(self.file_kinds(f))
                };
                if sf.is_empty() {
                    return false;
                }
                // `-a` requires every specified kind EXCEPT `-K`'s. Measured:
                // `lsof -K -a -p N` shows that process's own rows as well as
                // its tasks, so TASK cannot be part of the AND requirement —
                // while `lsof -K` alone shows tasks and nothing else, so it
                // must still be part of the OR. Both hold only if it is
                // dropped here and nowhere else.
                !self.and_mode || sf.contains(specified.without(SelKinds::TASK))
            });
            if p.files.is_empty() {
                // A process with no rows left is a result only when it was
                // itself selected and no file selecter was given — the case
                // where the renderer prints a bare process line.
                // `-K` adds one more way to have no result: a run that
                // specified tasks, on an entry that is not one and matched
                // nothing else, is not selected at all — `lsof -K` prints the
                // tasks and no line for the process. This lives here rather
                // than in `proc_selected` because that predicate also scopes
                // the backend's fd walk, and the process's own files still
                // have to be read: `lsof -K -a -p N` shows them.
                let task_only_miss = specified.contains(SelKinds::TASK) && inherited.is_empty();
                // And a process its backend read and found nothing to show
                // in is not a bare line either: where the C lists a process
                // only through its files, it has no line at all.
                if p.unlisted
                    || !self.proc_selected(inherited)
                    || specified.intersects(SelKinds::FILE)
                    || peer_only
                    || task_only_miss
                {
                    continue;
                }
            }
            out.push(p);
        }
        out
    }
}

/// Whether `name` is `dir` itself or an entry *directly* in it — `+d`, one
/// level, with nothing deeper. Used only by the name-matching fallback; where
/// the backend can identify paths, `+d` is expanded into identities instead.
fn directly_in_dir(name: &str, dir: &str) -> bool {
    if !under_dir(name, dir) {
        return false;
    }
    let dir = dir.trim_end_matches('\\');
    match name.len() > dir.len() {
        // `dir\a` is in it; `dir\a\b` is a level too deep.
        true => !name[dir.len() + 1..].contains('\\'),
        false => true, // the directory itself
    }
}

/// Whether `name` is `dir` itself or a path beneath it (matching on a `\`
/// boundary so `C:\foo` does not match `C:\foobar`).
fn under_dir(name: &str, dir: &str) -> bool {
    if name == dir {
        return true;
    }
    let dir = dir.trim_end_matches('\\');
    name.starts_with(dir) && name.as_bytes().get(dir.len()) == Some(&b'\\')
}

/// `-u` match: case-insensitive, against either the full `DOMAIN\user` string
/// or just the account name after the backslash.
fn user_matches(needle: &str, user: Option<&str>) -> bool {
    let Some(user) = user else { return false };
    let u = user.to_ascii_lowercase();
    let n = needle.to_ascii_lowercase();
    if u == n {
        return true;
    }
    matches!(u.rsplit('\\').next(), Some(tail) if tail == n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock;

    #[test]
    fn no_selectors_lists_all() {
        let sel = Selection::default();
        let got = sel.apply(mock::sample_processes());
        assert_eq!(got.len(), mock::sample_processes().len());
    }

    #[test]
    fn pid_selector() {
        let sel = Selection {
            pids: vec![1000],
            ..Default::default()
        };
        let got = sel.apply(mock::sample_processes());
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].pid, 1000);
    }

    #[test]
    fn user_selector() {
        // `-u` matches the bare account name or the full DOMAIN\user, either
        // case, and selects nothing when the user doesn't exist.
        for needle in ["alice", "ALICE", "EXAMPLE\\alice", "example\\ALICE"] {
            let sel = Selection {
                users: vec![needle.to_string()],
                ..Default::default()
            };
            let got = sel.apply(mock::sample_processes());
            assert!(!got.is_empty(), "-u {needle} matched nothing");
            assert!(got
                .iter()
                .all(|p| p.user.as_deref() == Some("EXAMPLE\\alice")));
        }
        let sel = Selection {
            users: vec!["nobody".to_string()],
            ..Default::default()
        };
        assert!(sel.apply(mock::sample_processes()).is_empty());
        // A domain-qualified needle must not match a different domain.
        let sel = Selection {
            users: vec!["OTHER\\alice".to_string()],
            ..Default::default()
        };
        assert!(sel.apply(mock::sample_processes()).is_empty());
    }

    #[test]
    fn inet_only_keeps_socket_files() {
        let mut sel = Selection::default();
        sel.inet.enabled = true;
        let got = sel.apply(mock::sample_processes());
        assert!(got.iter().all(|p| p.files.iter().all(|f| f.is_internet())));
        assert!(got.iter().all(|p| !p.files.is_empty()));
    }

    #[test]
    fn unix_only_keeps_af_unix_rows_and_drops_processes_without_any() {
        // `-U` was never enforced here: the Windows ETW path happened to yield
        // only AF_UNIX rows, so nothing noticed. A backend that returns every
        // open file (Linux /proc) made `-U` list the whole system.
        let sel = Selection {
            unix_only: true,
            ..Default::default()
        };
        let got = sel.apply(mock::sample_processes());
        assert!(
            got.iter()
                .all(|p| p.files.iter().all(|f| f.file_type == FileType::Unix)),
            "-U must keep only AF_UNIX rows"
        );
        assert!(
            got.iter().all(|p| !p.files.is_empty()),
            "a process with no AF_UNIX socket is not a -U result row"
        );
    }

    #[test]
    fn inet_port_filter() {
        let mut sel = Selection::default();
        sel.inet.enabled = true;
        sel.inet.specs.push(InetSpec {
            text: ":445".into(),
            ports: vec![(445, 445)],
            ..Default::default()
        });
        let got = sel.apply(mock::sample_processes());
        assert!(got.iter().flat_map(|p| &p.files).all(|f| {
            f.socket
                .as_ref()
                .map(|s| {
                    s.local.map(|a| a.port()) == Some(445)
                        || s.remote.map(|a| a.port()) == Some(445)
                })
                .unwrap_or(false)
        }));
    }

    #[test]
    fn inet_etw_family_filters_icmp_raw() {
        use crate::model::{AccessMode, FdType, FileType, OpenFile, Protocol, SocketInfo};
        // ETW-shaped rows: what etw::to_open_file emits for the families IP
        // Helper can't see (v4 ICMP, v6 ICMP, v4 RAW) plus a normal TCP row.
        // "matches -i" is now "contributes the NET selecter kind" — the bit the
        // OR/AND rule then tests.
        let sock_row = |ft: FileType, proto: Protocol| OpenFile {
            fs_device: None,
            file_flags: None,
            lock: None,
            fd: FdType::Unknown,
            access: AccessMode::ReadWrite,
            file_type: ft,
            name: "*:*->127.0.0.1:0".to_string(),
            device: None,
            size: None,
            offset: None,
            node: Some(proto.as_str().to_string()),
            links: None,
            socket: Some(Box::new(SocketInfo {
                protocol: proto,
                local: None,
                remote: Some("127.0.0.1:0".parse().unwrap()),
                state: None,
                tcp: None,
            })),
        };
        let icmp4 = sock_row(FileType::Ipv4, Protocol::Other("ICMP"));
        let icmp6 = sock_row(FileType::Ipv6, Protocol::Other("ICMPV6"));
        let raw4 = sock_row(FileType::Ipv4, Protocol::Other("RAW"));
        let tcp4 = sock_row(FileType::Ipv4, Protocol::Tcp);

        let filt = |proto: Option<Protocol>, family: Option<u8>| {
            let mut sel = Selection::default();
            if proto.is_none() && family.is_none() {
                sel.inet.add_all(None);
            } else {
                sel.inet.enabled = true;
                sel.inet.specs.push(InetSpec {
                    proto,
                    family,
                    ..Default::default()
                });
            }
            sel
        };
        // A spec is the NA kind, the bare form NET; either counts as "matches -i".
        let net = SelKinds::NET.union(SelKinds::NA);

        // -iICMP matches both the v4 and v6 ICMP codes, nothing else.
        let icmp = filt(Some(Protocol::Other("ICMP")), None);
        assert!(icmp.file_kinds(&icmp4).intersects(net));
        assert!(icmp.file_kinds(&icmp6).intersects(net));
        assert!(!icmp.file_kinds(&raw4).intersects(net));
        assert!(!icmp.file_kinds(&tcp4).intersects(net));

        // -i6ICMP narrows by family.
        let icmp_v6 = filt(Some(Protocol::Other("ICMP")), Some(6));
        assert!(!icmp_v6.file_kinds(&icmp4).intersects(net));
        assert!(icmp_v6.file_kinds(&icmp6).intersects(net));

        // -iRAW matches RAW only — never ICMP (exact, not substring/prefix).
        let raw = filt(Some(Protocol::Other("RAW")), None);
        assert!(raw.file_kinds(&raw4).intersects(net));
        assert!(!raw.file_kinds(&icmp4).intersects(net));
        assert!(!raw.file_kinds(&tcp4).intersects(net));

        // Plain -i still matches every internet family.
        let any = filt(None, None);
        for r in [&icmp4, &icmp6, &raw4, &tcp4] {
            assert!(any.file_kinds(r).intersects(net));
        }
    }

    #[test]
    fn socket_rows_only_needs_every_clause() {
        // One row per clause, each asserted on its own line: a single fixture
        // carrying all of them would pin only their union, and any one clause
        // could then be deleted silently (LESSONS #050).
        let inet = InetFilter {
            enabled: true,
            ..Default::default()
        };
        let base = Selection {
            inet: inet.clone(),
            ..Default::default()
        };

        assert!(base.socket_rows_only(), "-i alone: only sockets can print");
        assert!(
            Selection {
                unix_only: true,
                ..Default::default()
            }
            .socket_rows_only(),
            "-U alone: only sockets can print"
        );
        assert!(
            Selection {
                inet: inet.clone(),
                unix_only: true,
                ..Default::default()
            }
            .socket_rows_only(),
            "-i -U: both kinds are socket kinds"
        );

        // Nothing specified is AllProc: every row prints, so nothing may be
        // skipped. This is the degenerate case a "subset of {NET,UNX}" test
        // passes by accident if it forgets that the empty set is a subset.
        assert!(
            !Selection::default().socket_rows_only(),
            "no selecter at all is AllProc, not socket-only"
        );

        // A process selecter makes every file of a matching process selected
        // (the OR rule), so non-socket rows come back.
        for (what, sel) in [
            (
                "-p",
                Selection {
                    pids: vec![1],
                    ..base.clone()
                },
            ),
            (
                "-u",
                Selection {
                    users: vec!["root".into()],
                    ..base.clone()
                },
            ),
            (
                "-c",
                Selection {
                    commands: vec!["x".into()],
                    ..base.clone()
                },
            ),
            (
                "-g",
                Selection {
                    ppid_filter: vec![1],
                    ..base.clone()
                },
            ),
        ] {
            assert!(
                !sel.socket_rows_only(),
                "{what} with -i: its processes contribute every file they hold"
            );
        }

        // Each remaining file kind is one a NON-socket row can match.
        assert!(
            !Selection {
                fd_filter: Some(FdFilter {
                    include: vec![FdSpec::Named(FdKind::Mem)],
                    exclude: vec![],
                }),
                ..base.clone()
            }
            .socket_rows_only(),
            "-d with -i: a mapped file matches FD"
        );
        assert!(
            !Selection {
                paths: vec!["/etc".into()],
                ..base.clone()
            }
            .socket_rows_only(),
            "a path argument with -i: a regular file matches NM"
        );
        assert!(
            !Selection {
                max_links: Some(1),
                ..base.clone()
            }
            .socket_rows_only(),
            "+L with -i: a regular file matches NLINK"
        );
        assert!(
            !Selection {
                nfs_only: true,
                ..base.clone()
            }
            .socket_rows_only(),
            "-N with -i: a file on NFS matches NFS"
        );
        assert!(
            !Selection {
                tasks: TaskMode::Always,
                ..base.clone()
            }
            .socket_rows_only(),
            "-K with -i: a task entry inherits TASK and brings its whole file set"
        );

        // `+E`/`-E` is not a SelKinds at all, which is exactly why it needs its
        // own clause: a peer process's PIPE rows are force-selected past the OR.
        for mode in [EndpointMode::Info, EndpointMode::Files] {
            assert!(
                !Selection {
                    endpoints: Some(mode),
                    ..base.clone()
                }
                .socket_rows_only(),
                "endpoint mode with -i: peer pipe rows survive the OR"
            );
        }
    }

    #[test]
    fn selects_process_proc_level_only() {
        let procs = mock::sample_processes();
        let sel = Selection {
            commands: vec!["server".into()],
            ..Default::default()
        };
        assert!(sel.has_process_selector());
        let matched: Vec<u32> = procs
            .iter()
            .filter(|p| sel.selects_process(p))
            .map(|p| p.pid)
            .collect();
        assert_eq!(matched, vec![1500]);
        assert!(!Selection::default().has_process_selector());
    }

    #[test]
    fn list_options_or_by_default_across_kinds() {
        // The rule this port got wrong until it was measured against the C:
        // `-p 1000 -i` is a UNION. Process 1000 has no sockets, yet all of its
        // files are listed (they inherit the PID match); process 1500 matches
        // no process selecter, yet its sockets are listed (they match `-i`).
        let mut sel = Selection {
            pids: vec![1000],
            ..Default::default()
        };
        sel.inet.enabled = true;
        let got = sel.apply(mock::sample_processes());
        assert_eq!(got.len(), 2, "both processes: {got:#?}");
        let p1000 = got.iter().find(|p| p.pid == 1000).expect("1000 listed");
        assert_eq!(p1000.files.len(), 2, "every file of the selected process");
        assert!(
            p1000.files.iter().all(|f| f.socket.is_none()),
            "including the ones `-i` does not match"
        );
        let p1500 = got.iter().find(|p| p.pid == 1500).expect("1500 listed");
        assert_eq!(p1500.files.len(), 3, "its sockets match `-i` on their own");
    }

    #[test]
    fn dash_a_ands_across_kinds() {
        // The same two selecters under `-a`: no file is both "belongs to 1000"
        // and "is an Internet socket", so the result is empty.
        let mut sel = Selection {
            pids: vec![1000],
            and_mode: true,
            ..Default::default()
        };
        sel.inet.enabled = true;
        assert!(sel.apply(mock::sample_processes()).is_empty());
    }

    #[test]
    fn an_fd_exclusion_selects_what_it_does_not_exclude() {
        // `-d ^cwd` is an *inclusion* of everything else, exactly as in the C
        // (`lib/proc.c:223`, `if (fds != 1) Lf->sf |= SELFD`) — so on its own it
        // lists the whole system minus cwd rows, rather than filtering some
        // other selecter's result.
        let sel = Selection {
            fd_filter: Some(FdFilter {
                include: vec![],
                exclude: vec![FdSpec::Named(FdKind::Cwd)],
            }),
            ..Default::default()
        };
        let got = sel.apply(mock::sample_processes());
        assert_eq!(got.len(), 2, "every process still appears");
        let files: usize = got.iter().map(|p| p.files.len()).sum();
        assert_eq!(files, 4, "5 files less the one cwd row");
        assert!(got
            .iter()
            .flat_map(|p| &p.files)
            .all(|f| f.fd != FdType::Cwd));
    }

    #[test]
    fn a_state_filter_can_only_veto_never_select() {
        // `-s` has no `SEL*` bit in the C, so it is not a list option: it
        // cannot bring a row in, only drop one. With `-s` as the only argument
        // the run still selects everything, minus the sockets it vetoes.
        let sel = Selection {
            state_filter: Some(StateFilter {
                include: vec![TcpState::Listen],
                exclude: vec![],
            }),
            ..Default::default()
        };
        assert!(sel.specified().is_empty(), "-s is not a specified kind");
        let got = sel.apply(mock::sample_processes());
        assert_eq!(got.len(), 2, "non-socket rows are untouched");
        let sockets: Vec<&str> = got
            .iter()
            .flat_map(|p| &p.files)
            .filter_map(|f| f.socket.as_ref())
            .map(|s| s.protocol.as_str())
            .collect();
        // The ESTABLISHED socket is vetoed. The sample's UDP socket carries
        // no state — Windows' shape — so no TCP state list can touch it.
        assert_eq!(
            sockets,
            ["TCP", "UDP"],
            "the LISTEN socket and the stateless UDP one"
        );
    }

    #[test]
    fn a_backend_may_not_skip_a_process_when_a_file_selecter_can_reach_it() {
        // The scoping predicate backends use to avoid work. Under the OR rule a
        // file selecter can select a file of a process that matches no process
        // selecter, so nothing may be skipped; under `-a` it may.
        let procs = mock::sample_processes();
        let other = procs.iter().find(|p| p.pid == 1500).unwrap();
        let mut sel = Selection {
            pids: vec![1000],
            ..Default::default()
        };
        assert!(!sel.selects_process(other), "-p alone can skip");
        sel.inet.enabled = true;
        assert!(
            sel.selects_process(other),
            "`-p 1000 -i` must still walk 1500 — its sockets match `-i`"
        );
        sel.and_mode = true;
        assert!(
            !sel.selects_process(other),
            "under -a a process failing -p can contribute nothing"
        );
    }

    #[test]
    fn a_file_system_argument_names_every_mount_it_matches() {
        // The C loops the whole mount table and makes a search item of each
        // match. Taking only the first is invisible on a host whose mount
        // table has no duplicate source, which is why this is a unit test and
        // not only a differential case: two tmpfs mounts cannot be created on
        // a CI runner without privileges.
        let mount = |dir: &str, source: &str, block: bool, device: u64| MountEntry {
            dir: dir.into(),
            source: Some(source.into()),
            source_is_block: block,
            device,
            fstype: String::new(),
        };
        let table = vec![
            mount("/", "/dev/vda", true, 100),
            mount("/dev", "devtmpfs", false, 6),
            mount("/a", "tmpfs", false, 40),
            mount("/b", "tmpfs", false, 41),
            // A duplicate row for one mount, as /proc/self/mounts really does
            // emit for /dev/shm and /dev/pts: one device, not two items.
            mount("/dev/shm", "tmpfs", false, 42),
            mount("/dev/shm", "tmpfs", false, 42),
        ];
        use FilesystemArgs::*;
        // A mounted-on directory, under any mode that allows the reading.
        assert_eq!(filesystems_named(&table, "/dev", Auto), vec![6]);
        assert_eq!(filesystems_named(&table, "/dev", AlwaysFilesystem), vec![6]);
        // `-f` refuses the reading outright.
        assert_eq!(
            filesystems_named(&table, "/dev", NeverFilesystem),
            Vec::<u64>::new()
        );
        // A BLOCK-device source names its filesystem by default...
        assert_eq!(filesystems_named(&table, "/dev/vda", Auto), vec![100]);
        // ...a non-block source does not, until `+f` widens the test.
        assert_eq!(
            filesystems_named(&table, "devtmpfs", Auto),
            Vec::<u64>::new()
        );
        assert_eq!(
            filesystems_named(&table, "devtmpfs", AlwaysFilesystem),
            vec![6]
        );
        // One source, several mounts: EVERY device, deduplicated.
        assert_eq!(
            filesystems_named(&table, "tmpfs", AlwaysFilesystem),
            vec![40, 41, 42]
        );
        // Not a mount at all.
        assert_eq!(
            filesystems_named(&table, "/etc/passwd", Auto),
            Vec::<u64>::new()
        );
        assert_eq!(
            filesystems_named(&[], "/", AlwaysFilesystem),
            Vec::<u64>::new()
        );
    }

    #[test]
    fn a_file_system_argument_matches_by_device_and_nothing_by_name() {
        // DIVERGENCES #15. Naming a mount point selects every file on that
        // filesystem — the C's `s->dev == Lf->dev`. The trap this guards is
        // the one that made the first attempt over-report: a file-system
        // argument resolves NO identity, so a rule that fell back to name
        // matching whenever the identity set was empty matched every absolute
        // path against `/`.
        use crate::model::{AccessMode, FdType, FileType, OpenFile, Process};
        let row = |name: &str, fs_device: u64| OpenFile {
            fs_device: Some(fs_device),
            file_flags: None,
            lock: None,
            fd: FdType::Handle(3),
            access: AccessMode::Read,
            file_type: FileType::Regular,
            name: name.into(),
            device: Some("0,42".into()),
            size: None,
            offset: None,
            node: Some("7".into()),
            links: None,
            socket: None,
        };
        let mut sel = Selection {
            paths: vec!["/".into()],
            paths_identified: true,
            ..Default::default()
        };
        sel.path_fs_devices.insert(65024); // the root filesystem
        let p = Process {
            tid: None,
            task_command: None,
            uid: None,
            pgid: None,
            pid: 7,
            ppid: None,
            command: "x".into(),
            user: None,
            endpoint_peer: false,
            unlisted: false,
            files: vec![
                row("/usr/bin/python3", 65024), // on the named filesystem
                row("/dev/null", 6),            // NOT on it — a different mount
            ],
        };
        let got = sel.apply(vec![p]);
        assert_eq!(got.len(), 1);
        let names: Vec<&str> = got[0].files.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec!["/usr/bin/python3"], "{got:#?}");
    }

    #[test]
    fn a_path_argument_matches_identity_not_a_name_prefix() {
        // lsof matches a path by what the file IS. The identity set is filled
        // by the CLI from the backend, so here it stands in directly: a row
        // whose (DEVICE, NODE) is in the set matches whatever it is called,
        // and a row merely *named* under the query does not.
        use crate::model::{AccessMode, FdType, FileType, OpenFile, Process};
        let row = |name: &str, dev: &str, node: &str| OpenFile {
            fs_device: None,
            file_flags: None,
            lock: None,
            fd: FdType::Handle(3),
            access: AccessMode::Read,
            file_type: FileType::Regular,
            name: name.into(),
            device: Some(dev.into()),
            size: None,
            offset: None,
            node: Some(node.into()),
            links: None,
            socket: None,
        };
        let mut sel = Selection {
            paths: vec!["C:\\dir".into()],
            // The backend identifies paths, so identity is authoritative and
            // the name fallback is off. Stating it is the point: inferring it
            // from a non-empty identity set is what broke `lsof /`.
            paths_identified: true,
            ..Default::default()
        };
        sel.path_ids.insert(("C:".into(), "42".into()));
        let p = Process {
            tid: None,
            task_command: None,
            uid: None,
            pgid: None,
            pid: 7,
            ppid: None,
            command: "x".into(),
            user: None,
            endpoint_peer: false,
            unlisted: false,
            files: vec![
                // The file itself, open under a DIFFERENT name (a hard link).
                row("C:\\other\\name.txt", "C:", "42"),
                // Named under the query, but a different file: the old
                // prefix match invented this row.
                row("C:\\dir\\inside.txt", "C:", "99"),
            ],
        };
        let got = sel.apply(vec![p]);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].files.len(), 1, "only the identity match: {got:#?}");
        assert_eq!(got[0].files[0].node.as_deref(), Some("42"));
    }

    #[test]
    fn plus_d_is_one_level_where_only_names_are_available() {
        // The fallback used when a backend cannot identify paths (Windows).
        // `+d` must still mean one level, or it silently becomes `+D`.
        assert!(directly_in_dir("c:\\dir", "c:\\dir"));
        assert!(directly_in_dir("c:\\dir\\a.txt", "c:\\dir"));
        assert!(!directly_in_dir("c:\\dir\\sub\\a.txt", "c:\\dir"));
        assert!(!directly_in_dir("c:\\dirother\\a.txt", "c:\\dir"));
        // `+D` still descends.
        assert!(under_dir("c:\\dir\\sub\\a.txt", "c:\\dir"));
    }

    #[test]
    fn a_negation_excludes_absolutely_and_is_not_a_list_option() {
        // Lsof.8: "A negated login name or user ID selection is neither ANDed
        // nor ORed with other selections; it is applied before all other
        // selections and absolutely excludes the listing of the files of the
        // process." Verified against the C: `-c ^sleep -p <a sleep>` prints
        // nothing, with or without `-a`, though `-p` names that process.
        for and_mode in [false, true] {
            let sel = Selection {
                pids: vec![1000],
                command_excludes: vec!["explorer".into()],
                and_mode,
                ..Default::default()
            };
            assert!(
                sel.specified().intersects(SelKinds::PID),
                "-p is still a specified kind"
            );
            assert_eq!(
                sel.specified().0.count_ones(),
                1,
                "the negation adds no kind of its own"
            );
            let got = sel.apply(mock::sample_processes());
            assert!(
                !got.iter().any(|p| p.pid == 1000),
                "and_mode={and_mode}: the negation outranks -p"
            );
        }
        // It also stops the process from being walked at all, so a backend
        // does no work for it and `-p` does not count it as located.
        let sel = Selection {
            user_excludes: vec!["alice".into()],
            ..Default::default()
        };
        let procs = mock::sample_processes();
        assert!(!sel.selects_process(&procs[0]));
        assert!(sel.excludes_process(&procs[0]));
        assert!(sel.apply(procs).is_empty(), "every mock process is alice's");
    }

    #[test]
    fn command_and_mode() {
        // AND of a matching pid and a non-matching command yields nothing.
        let sel = Selection {
            pids: vec![1000],
            commands: vec!["does-not-exist".into()],
            and_mode: true,
            ..Default::default()
        };
        assert!(sel.apply(mock::sample_processes()).is_empty());
    }

    #[test]
    fn path_filter_keeps_only_matching_files() {
        let sel = Selection {
            paths: vec!["C:\\Users\\alice".into()],
            ..Default::default()
        };
        let got = sel.apply(mock::sample_processes());
        // Only the explorer cwd row matches that path prefix.
        assert_eq!(got.len(), 1);
        assert!(got[0]
            .files
            .iter()
            .all(|f| f.name.starts_with("C:\\Users\\alice")));
    }

    #[test]
    fn dir_tree_matches_on_boundary() {
        let sel = Selection {
            dir_trees: vec!["C:\\Users".into()],
            ..Default::default()
        };
        let got = sel.apply(mock::sample_processes());
        // C:\Users\alice is under C:\Users; C:\Windows\... is not.
        assert_eq!(got.len(), 1);
        assert!(got[0].files.iter().all(|f| f.name.starts_with("C:\\Users")));
        // Boundary: a sibling prefix must not match.
        assert!(!under_dir("c:\\usersdata\\x", "c:\\users"));
        assert!(under_dir("c:\\users\\x", "c:\\users"));
        assert!(under_dir("c:\\users", "c:\\users"));
    }

    #[test]
    fn endpoint_peer_kept_with_pipe_rows_only() {
        use crate::model::{AccessMode, FdType, OpenFile};
        let pipe = OpenFile {
            fs_device: None,
            file_flags: None,
            lock: None,
            fd: FdType::Handle(64),
            access: AccessMode::ReadWrite,
            file_type: FileType::Pipe,
            name: "\\\\.\\pipe\\x (server=1000,a.exe client=9999,b.exe)".into(),
            device: None,
            size: None,
            offset: None,
            node: None,
            links: None,
            socket: None,
        };
        let reg = OpenFile {
            fs_device: None,
            file_flags: None,
            lock: None,
            file_type: FileType::Regular,
            name: "C:\\peer\\data.txt".into(),
            ..pipe.clone()
        };
        // 9999 matches no selector but was marked by the backend as a `+E`
        // endpoint peer: it must survive apply() with ONLY its pipe rows.
        let peer = Process {
            tid: None,
            task_command: None,
            uid: None,
            pgid: None,
            pid: 9999,
            ppid: None,
            command: "b.exe".into(),
            user: None,
            endpoint_peer: true,
            unlisted: false,
            files: vec![pipe.clone(), reg.clone()],
        };
        // 8888 matches no selector and is no peer: dropped as usual.
        let stranger = Process {
            tid: None,
            task_command: None,
            uid: None,
            pgid: None,
            pid: 8888,
            ppid: None,
            command: "c.exe".into(),
            user: None,
            endpoint_peer: false,
            unlisted: false,
            files: vec![pipe, reg],
        };
        let sel = Selection {
            pids: vec![1000],
            ..Default::default()
        };
        let got = sel.apply(vec![peer, stranger]);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].pid, 9999);
        assert_eq!(got[0].files.len(), 1);
        assert_eq!(got[0].files[0].file_type, FileType::Pipe);
    }

    #[test]
    fn fd_filter_includes_and_excludes() {
        use crate::model::FdType;
        // Include only cwd.
        let sel = Selection {
            fd_filter: Some(FdFilter {
                include: vec![FdSpec::Named(FdKind::Cwd)],
                exclude: vec![],
            }),
            ..Default::default()
        };
        let got = sel.apply(mock::sample_processes());
        assert!(got
            .iter()
            .flat_map(|p| &p.files)
            .all(|f| f.fd == FdType::Cwd));
        // Exclude a numeric handle.
        let sel = Selection {
            fd_filter: Some(FdFilter {
                include: vec![],
                exclude: vec![FdSpec::Num(72)],
            }),
            ..Default::default()
        };
        let got = sel.apply(mock::sample_processes());
        assert!(got
            .iter()
            .flat_map(|p| &p.files)
            .all(|f| f.fd != FdType::Handle(72)));
    }
    #[test]
    fn nfs_is_a_file_selecter_and_a_search_item() {
        // The bug the oracle caught: `-N` selected correctly but every process
        // on the host still printed a bare `unk unknown` line, because the
        // emptiness rule reads SelKinds::FILE and NFS was not in it.
        assert!(
            SelKinds::FILE.contains(SelKinds::NFS),
            "a fileless process must be dropped under -N, as it is under -U"
        );
        // And it is a kind of its own, not an alias for another selecter.
        for other in [
            SelKinds::FD,
            SelKinds::NET,
            SelKinds::NA,
            SelKinds::UNX,
            SelKinds::NM,
        ] {
            assert!(
                !other.contains(SelKinds::NFS),
                "NFS collides with {other:?}"
            );
        }
    }

    /// A process with the identity fields `locate` and the `^` exclusions read.
    fn who(pid: u32, command: &str, uid: u32, pgid: u32) -> Process {
        Process {
            tid: None,
            task_command: None,
            uid: Some(uid),
            pgid: Some(pgid),
            pid,
            ppid: Some(1),
            command: command.into(),
            user: Some(format!("u{uid}")),
            files: Vec::new(),
            endpoint_peer: false,
            unlisted: false,
        }
    }

    #[test]
    fn the_cs_command_match_is_a_case_sensitive_prefix() {
        // Measured: `-c py` finds python3; `-c ytho`, `-c PYTHON` and
        // `-c python3.11` find nothing and exit 1.
        let procs = [who(10, "python3", 0, 10)];
        let hits = |c: &str, m: CommandMatch| {
            Selection {
                commands: vec![c.into()],
                command_match: m,
                ..Default::default()
            }
            .locate(&procs)
            .commands[0]
        };
        assert!(hits("py", CommandMatch::Prefix));
        assert!(hits("python3", CommandMatch::Prefix));
        for miss in ["ytho", "PYTHON", "python3.11"] {
            assert!(!hits(miss, CommandMatch::Prefix), "{miss}");
        }
        // The Windows port's rule, kept there on purpose.
        assert!(hits("ytho", CommandMatch::Forgiving));
        assert!(hits("PYTHON", CommandMatch::Forgiving));
        assert_eq!(CommandMatch::default(), CommandMatch::Prefix);
    }

    #[test]
    fn every_matching_command_is_located_not_only_the_first() {
        // The C marks the first match only, so `-c py -c python` exits 1 with
        // `command not located: py` — ledgered as a defect (DIVERGENCES 13).
        let sel = Selection {
            commands: vec!["py".into(), "python".into(), "py".into()],
            ..Default::default()
        };
        assert_eq!(
            sel.locate(&[who(10, "python3", 0, 10)]).commands,
            [true, true, true]
        );
    }

    #[test]
    fn pid_pgid_and_uid_are_located_by_any_matching_process() {
        let sel = Selection {
            pids: vec![10, 99],
            pgids: vec![7, 98],
            uids: vec![
                UidSel {
                    uid: 1000,
                    login: Some("alice".into()),
                },
                UidSel {
                    uid: 97,
                    login: None,
                },
            ],
            ..Default::default()
        };
        let found = sel.locate(&[who(10, "a", 0, 1), who(11, "b", 1000, 7)]);
        assert_eq!(found.pids, [true, false]);
        assert_eq!(found.pgids, [true, false]);
        assert_eq!(found.uids, [true, false]);
        // And selection agrees: -g and numeric -u select the same processes.
        assert!(sel.selects_process(&who(12, "c", 1000, 3)));
        assert!(sel.selects_process(&who(13, "d", 5, 7)));
        assert!(!sel.selects_process(&who(14, "e", 5, 3)));
    }

    #[test]
    fn under_and_a_command_is_located_only_past_the_other_process_kinds() {
        // `is_proc_excl() || is_cmd_excl()`: under -a, a process failing the
        // -p part never reaches the command test — while -p itself is marked
        // by a process whatever its command.
        let sel = Selection {
            pids: vec![10],
            commands: vec!["foo".into()],
            and_mode: true,
            ..Default::default()
        };
        let found = sel.locate(&[who(10, "bar", 0, 1), who(11, "foo", 0, 1)]);
        assert_eq!(found.pids, [true]);
        assert_eq!(found.commands, [false]);
        // Without -a both are located, by different processes.
        let or = Selection {
            and_mode: false,
            ..sel
        };
        assert_eq!(
            or.locate(&[who(10, "bar", 0, 1), who(11, "foo", 0, 1)])
                .commands,
            [true]
        );
    }

    #[test]
    fn an_excluded_process_locates_nothing() {
        for sel in [
            Selection {
                command_excludes: vec!["sle".into()],
                ..Default::default()
            },
            Selection {
                uid_excludes: vec![1000],
                ..Default::default()
            },
            Selection {
                pgid_excludes: vec![7],
                ..Default::default()
            },
            Selection {
                pid_excludes: vec![10],
                ..Default::default()
            },
        ] {
            let sel = Selection {
                pids: vec![10],
                commands: vec!["sleep".into()],
                ..sel
            };
            let p = who(10, "sleep", 1000, 7);
            assert!(sel.excludes_process(&p), "{sel:?}");
            let found = sel.locate(&[p]);
            assert_eq!(
                (found.pids[0], found.commands[0]),
                (false, false),
                "{sel:?}"
            );
        }
    }

    /// A TCP socket row, local `127.0.0.1:<lport>`, remote `<raddr>` if any.
    fn tcp(fd: u64, lport: u16, remote: Option<&str>, state: crate::TcpState) -> OpenFile {
        use crate::model::{AccessMode, SockState, SocketInfo};
        OpenFile {
            fs_device: None,
            file_flags: None,
            lock: None,
            fd: FdType::Handle(fd),
            access: AccessMode::ReadWrite,
            file_type: FileType::Ipv4,
            name: String::new(),
            device: None,
            size: None,
            offset: Some(0),
            node: Some("TCP".into()),
            links: None,
            socket: Some(Box::new(SocketInfo {
                protocol: Protocol::Tcp,
                local: Some(format!("127.0.0.1:{lport}").parse().unwrap()),
                remote: remote.map(|r| r.parse().unwrap()),
                state: Some(SockState::Tcp(state)),
                tcp: None,
            })),
        }
    }

    fn spec(text: &str, ports: &[(u16, u16)], host: Option<&str>) -> InetSpec {
        InetSpec {
            text: text.into(),
            ports: ports.to_vec(),
            host: host.map(|h| h.parse().unwrap()),
            ..Default::default()
        }
    }

    #[test]
    fn inet_specs_are_ored_and_each_is_its_own_search_item() {
        // `-i :80 -i :443 -i :9`: the first two each match a file, the third
        // nothing. lsof-rs had kept only the LAST spec, so :80 selected
        // nothing at all.
        let mut sel = Selection::default();
        sel.inet.enabled = true;
        sel.inet.specs = vec![
            spec(":80", &[(80, 80)], None),
            spec(":443", &[(443, 443)], None),
            spec(":9", &[(9, 9)], None),
        ];
        let mut p = who(10, "srv", 0, 10);
        p.files = vec![
            tcp(3, 80, None, crate::TcpState::Listen),
            tcp(4, 443, None, crate::TcpState::Listen),
            tcp(5, 5000, None, crate::TcpState::Listen),
        ];
        assert_eq!(
            sel.locate(std::slice::from_ref(&p)).inet,
            [true, true, false]
        );
        let kept: Vec<u16> = sel
            .apply(vec![p])
            .iter()
            .flat_map(|p| &p.files)
            .map(|f| f.socket.as_ref().unwrap().local.unwrap().port())
            .collect();
        assert_eq!(kept, [80, 443]);
        assert!(!sel.inet.bare(), "specs only: no `no Internet files` item");
    }

    #[test]
    fn a_host_and_port_must_match_on_the_same_end() {
        // Local 127.0.0.1:5000, remote 10.0.0.1:80. `@127.0.0.1:80` names an
        // end that does not exist; `is_nw_addr()` tests each end whole.
        let f = tcp(3, 5000, Some("10.0.0.1:80"), crate::TcpState::Established);
        assert!(!spec("@127.0.0.1:80", &[(80, 80)], Some("127.0.0.1")).matches(&f));
        assert!(spec("@10.0.0.1:80", &[(80, 80)], Some("10.0.0.1")).matches(&f));
        assert!(spec("@127.0.0.1", &[], Some("127.0.0.1")).matches(&f));
        // Exact, never a substring: 127.0.0.1 is not 127.0.0.10.
        assert!(!spec("@127.0.0.10", &[], Some("127.0.0.10")).matches(&f));
        assert!(
            spec(":1-100", &[(1, 100)], None).matches(&f),
            "the remote end is in range"
        );
    }

    #[test]
    fn under_and_a_bare_i_and_a_spec_are_separate_requirements() {
        // The C's SELNET and SELNA: `-a -p P -i -i:9` needs both, so P's
        // Internet file on another port is not listed — measured.
        let mut sel = Selection {
            pids: vec![10],
            and_mode: true,
            ..Default::default()
        };
        sel.inet.add_all(None);
        sel.inet.specs.push(spec(":9", &[(9, 9)], None));
        let mut p = who(10, "srv", 0, 10);
        p.files = vec![
            tcp(3, 5000, None, crate::TcpState::Listen),
            tcp(4, 9, None, crate::TcpState::Listen),
        ];
        let kept: Vec<u16> = sel
            .apply(vec![p])
            .iter()
            .flat_map(|p| &p.files)
            .map(|f| f.socket.as_ref().unwrap().local.unwrap().port())
            .collect();
        assert_eq!(kept, [9]);
    }

    #[test]
    fn a_kept_file_locates_even_when_a_file_selector_hides_it() {
        // `-a -p P -i -d 3`, P's only socket on fd 9: nothing is listed and
        // the C exits 0 — Fnet is set when the file is linked, -a is applied
        // at print time. And a socket `-s` vetoes locates nothing.
        let mut sel = Selection {
            pids: vec![10],
            and_mode: true,
            fd_filter: Some(FdFilter {
                include: vec![FdSpec::Num(3)],
                exclude: vec![],
            }),
            ..Default::default()
        };
        sel.inet.add_all(None);
        let mut p = who(10, "srv", 0, 10);
        p.files = vec![tcp(9, 5000, None, crate::TcpState::Listen)];
        assert!(sel.locate(std::slice::from_ref(&p)).inet_all);
        assert!(sel
            .apply(vec![p.clone()])
            .iter()
            .all(|q| q.files.is_empty()));
        let vetoed = Selection {
            state_filter: Some(StateFilter {
                include: vec![TcpState::Established],
                exclude: vec![],
            }),
            ..sel
        };
        assert!(!vetoed.locate(&[p]).inet_all);
    }
    fn udp(fd: u64, lport: u16, state: Option<TcpState>) -> OpenFile {
        use crate::model::{SockState, SocketInfo};
        let mut f = tcp(fd, lport, None, TcpState::Listen);
        f.node = Some("UDP".into());
        f.socket = Some(Box::new(SocketInfo {
            protocol: Protocol::Udp,
            local: Some(format!("127.0.0.1:{lport}").parse().unwrap()),
            remote: None,
            state: state.map(SockState::Tcp),
            tcp: None,
        }));
        f
    }

    fn states(include: &[TcpState], exclude: &[TcpState]) -> Selection {
        Selection {
            state_filter: Some(StateFilter {
                include: include.to_vec(),
                exclude: exclude.to_vec(),
            }),
            ..Default::default()
        }
    }

    // Linux's rule, on Linux's table: `CLOSE` is not a Windows state name, and
    // the Windows backend gives UDP no state, so on Windows the unconnected
    // socket here would be outside the table and pass. The platform-neutral
    // half — a TCP list vetoes TCP sockets and nothing else — is
    // `a_state_filter_can_only_veto_never_select`.
    #[test]
    #[cfg(not(windows))]
    fn a_tcp_state_list_filters_udp_by_its_reused_state_and_nothing_else() {
        // Measured against the C on a process holding every shape: a TCP
        // listener, an established TCP socket, an unconnected UDP socket
        // (kernel state 7, CLOSE), a connected one (1, ESTABLISHED), a unix
        // socket and a regular file. lsof-rs had applied `-sTCP:` to TCP
        // sockets alone and dropped every other socket outright — the unix
        // socket included, which the C keeps.
        use crate::model::{SockState, SocketInfo, UnixState};
        let mut unix = tcp(9, 1, None, TcpState::Listen);
        unix.file_type = FileType::Unix;
        unix.socket = Some(Box::new(SocketInfo {
            protocol: Protocol::Other("unix"),
            local: None,
            remote: None,
            state: Some(SockState::Unix(UnixState::Listen)),
            tcp: None,
        }));
        let mut file = tcp(10, 1, None, TcpState::Listen);
        file.socket = None;
        file.file_type = FileType::Regular;
        let files = [
            tcp(4, 80, None, TcpState::Listen),
            tcp(5, 81, Some("127.0.0.1:9"), TcpState::Established),
            udp(7, 82, Some(TcpState::Close)),
            udp(8, 83, Some(TcpState::Established)),
            unix,
            file,
        ];
        let kept = |sel: Selection| -> Vec<u64> {
            let mut p = who(10, "srv", 0, 10);
            p.files = files.to_vec();
            sel.apply(vec![p])
                .iter()
                .flat_map(|p| &p.files)
                .map(|f| match f.fd {
                    FdType::Handle(n) => n,
                    _ => unreachable!(),
                })
                .collect()
        };
        assert_eq!(kept(states(&[TcpState::Listen], &[])), [4, 9, 10]);
        assert_eq!(kept(states(&[TcpState::Close], &[])), [7, 9, 10]);
        assert_eq!(kept(states(&[TcpState::Established], &[])), [5, 8, 9, 10]);
        assert_eq!(kept(states(&[], &[TcpState::Close])), [4, 5, 8, 9, 10]);
        assert_eq!(
            kept(states(&[TcpState::Listen], &[TcpState::Established])),
            [4, 9, 10]
        );
    }

    #[test]
    fn a_state_outside_the_table_is_never_filtered() {
        // The C checks `i < TcpNstates` before either list, so a kernel state
        // newer than its table is neither required nor excluded.
        let sel = states(&[TcpState::Listen], &[]);
        let mut p = who(10, "srv", 0, 10);
        p.files = vec![tcp(4, 80, None, TcpState::Unknown)];
        assert_eq!(sel.apply(vec![p])[0].files.len(), 1);
    }

    #[test]
    fn a_state_is_located_by_any_socket_in_it_whatever_hides_the_row() {
        // `lsof -a -p P -d 10 -sTCP:SYN_SENT,CLOSED,LISTEN`, P's listener on
        // fd 4: the C marks LISTEN while it reads the socket, before `-d` or
        // `-a` decide the row, and reports the other two — measured.
        let mut sel = states(
            &[TcpState::SynSent, TcpState::Closed, TcpState::Listen],
            &[],
        );
        sel.pids = vec![10];
        sel.and_mode = true;
        sel.fd_filter = Some(FdFilter {
            include: vec![FdSpec::Num(10)],
            exclude: vec![],
        });
        let mut p = who(10, "srv", 0, 10);
        p.files = vec![tcp(4, 80, None, TcpState::Listen)];
        assert_eq!(sel.locate(&[p]).states, [false, false, true]);
        // An unconnected UDP socket locates CLOSE, as it is filtered by it.
        let sel = states(&[TcpState::Close], &[]);
        let mut p = who(10, "srv", 0, 10);
        p.files = vec![udp(7, 82, Some(TcpState::Close))];
        assert_eq!(sel.locate(&[p]).states, [true]);
    }

    #[test]
    fn two_process_selecters_without_dash_a_walk_every_process_for_states() {
        // `lsof -p P -c nosuch -sTCP:LISTEN`: the C reads every process when
        // more than one process selecter is given and there is no `-a`, so a
        // listener anywhere locates LISTEN — measured, `-V` names only the
        // command. With one selecter, or `-a`, it reads the selected alone.
        let other = who(20, "other", 0, 20);
        let mut sel = states(&[TcpState::Listen], &[]);
        sel.pids = vec![10];
        assert!(!sel.selects_process(&other), "-p alone reads P alone");
        sel.commands = vec!["nosuch".into()];
        assert!(sel.selects_process(&other), "-p and -c read everything");
        sel.and_mode = true;
        assert!(!sel.selects_process(&other), "-a reads what passes both");
        // Without a state to locate, the wider walk would only cost.
        let mut plain = Selection {
            pids: vec![10],
            commands: vec!["nosuch".into()],
            ..Default::default()
        };
        assert!(!plain.selects_process(&other));
        // `-K` counts among the C's process kinds.
        plain = states(&[TcpState::Listen], &[]);
        plain.pids = vec![10];
        plain.tasks = TaskMode::Always;
        assert!(plain.selects_process(&other), "-K -p reads everything");
    }

    #[test]
    fn an_unlisted_process_has_no_line_but_is_still_located() {
        // `lsof -w -p P` on a P nothing of which can be read: the C prints
        // nothing and exits 0 — P was found, it just has no row. Windows'
        // bare line for a fileless process is untouched: `unlisted` is set
        // only by a backend that lists processes through their files.
        let sel = Selection {
            pids: vec![10],
            ..Default::default()
        };
        let mut p = who(10, "srv", 0, 10);
        assert_eq!(sel.apply(vec![p.clone()]).len(), 1, "the bare line");
        p.unlisted = true;
        assert!(sel.apply(vec![p.clone()]).is_empty(), "no line at all");
        assert_eq!(sel.locate(&[p]).pids, [true], "and still located");
    }

    #[test]
    fn nofd_and_del_are_fd_names_dash_d_selects() {
        // The C compares a `-d` name with the FD cell, so both select the
        // rows that print them.
        let nofd = FdSpec::Named(FdKind::NoFd);
        let del = FdSpec::Named(FdKind::Del);
        assert!(nofd.matches(&FdType::NoFd) && !nofd.matches(&FdType::Handle(0)));
        assert!(del.matches(&FdType::Deleted) && !del.matches(&FdType::Mem));
        assert_eq!(FdType::NoFd.code(), "NOFD");
    }
}
