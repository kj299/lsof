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

use crate::model::{FdType, FileType, OpenFile, Process, Protocol};

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

    /// The process selecters — the C's `SELPROC`. A file inherits these from
    /// its process; the rest it must match itself.
    pub const PROC: Self = Self(Self::PID.0 | Self::UID.0 | Self::CMD.0 | Self::PGID.0);
    /// The file and network selecters — the C's `SELFILE | SELNW`.
    pub const FILE: Self =
        Self(Self::FD.0 | Self::NET.0 | Self::UNX.0 | Self::NM.0 | Self::NLINK.0);

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
    fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

/// Parsed `-i` Internet filter.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InetFilter {
    /// `-i` was given (with or without further narrowing).
    pub enabled: bool,
    /// Restrict to TCP or UDP.
    pub proto: Option<Protocol>,
    /// Restrict to IP version: `Some(4)` or `Some(6)`.
    pub family: Option<u8>,
    /// Restrict to a port (local or remote).
    pub port: Option<u16>,
    /// Restrict to a host substring (matched against the numeric address text).
    pub host: Option<String>,
}

impl InetFilter {
    /// True when the requested protocol is only visible through the ETW AFD
    /// capture — RAW and ICMP have no IP Helper table — so `-iRAW`/`-iICMP`
    /// must imply the (Administrator-only) capture the way `-U` does, or the
    /// filter would silently match nothing.
    pub fn needs_etw(&self) -> bool {
        matches!(self.proto, Some(Protocol::Other(_)))
    }

    /// Protocol test for `-i`. Protocol names are family-agnostic (like
    /// TCP/UDP): `-iICMP` matches both the v4 `ICMP` and v6 `ICMPV6` codes,
    /// with the `[46]` prefix as the family narrower.
    fn proto_matches(&self, actual: Protocol) -> bool {
        match self.proto {
            None => true,
            Some(p) if p == actual => true,
            Some(Protocol::Other("ICMP")) => actual == Protocol::Other("ICMPV6"),
            Some(_) => false,
        }
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

/// `-T [fqsw]` sub-flags. `f` (follow/repeat) is accepted but a no-op for a
/// snapshot tool. `s` (state) is shown already; `q` (queue) and `w` (window)
/// drive the extended-TCP-stats lookup.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TcpInfoFlags {
    pub state: bool,
    pub queue: bool,
    pub window: bool,
}

/// Parsed `-s [proto:state[,state]]` selector. Includes/excludes apply to
/// TCP/UDP sockets only; rows without a recognized state are passed through
/// when only TCP filters are set. Multiple includes are OR-ed; an exclude
/// kills the row even if it also matches an include.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StateFilter {
    /// Restrict to one protocol, e.g. `TCP`. `None` if `-s` was given without
    /// a `proto:` prefix (which we treat as "any socket protocol").
    pub proto: Option<Protocol>,
    /// State names to include (case-insensitive match against
    /// `TcpState::as_str`). Empty means "any state for this proto".
    pub include: Vec<String>,
    /// State names to exclude (the `^` prefix in lsof's syntax).
    pub exclude: Vec<String>,
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
}

impl FdSpec {
    fn matches(&self, fd: &FdType) -> bool {
        match (self, fd) {
            (FdSpec::Named(FdKind::Cwd), FdType::Cwd) => true,
            (FdSpec::Named(FdKind::Rtd), FdType::Root) => true,
            (FdSpec::Named(FdKind::Txt), FdType::Txt) => true,
            (FdSpec::Named(FdKind::Mem), FdType::Mem) => true,
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

/// The full set of user-specified filters for one run.
#[derive(Clone, Debug, Default)]
pub struct Selection {
    pub pids: Vec<u32>,
    pub users: Vec<String>,
    pub commands: Vec<String>,
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
    /// `-s [proto:state[,state]]`: TCP socket state filter, e.g.
    /// `TCP:LISTEN`, `TCP:^TIME_WAIT`, `TCP:LISTEN,ESTABLISHED`. Applies
    /// only to sockets; non-socket rows are unaffected.
    pub state_filter: Option<StateFilter>,
    /// `-g <ppid>[,<ppid>...]`: Windows-extension semantics — select
    /// processes whose PPID is in this list (the closest analog to lsof's
    /// `-g` PGID filter, since Windows has no process groups).
    pub ppid_filter: Vec<u32>,
    /// `-l`: render numeric IDs (raw SID string) instead of the resolved
    /// account name in the USER column.
    pub numeric_ids: bool,
    /// `-Q`: suppress "no matching open files" stderr and treat an empty
    /// result set as success.
    pub quiet: bool,
    /// `-w` sets this, `+w` clears it (default `false` — warnings on):
    /// suppresses the privilege-hint and other non-fatal stderr warnings.
    pub suppress_warnings: bool,
    /// `+c <n>`: max width of the COMMAND column (truncate long names).
    /// `None` means no cap (current behavior).
    pub command_width: Option<usize>,
    /// `--unicode`: enable UTF-8 output (banner / future Unicode glyphs) and
    /// switch the Windows console to CP 65001 at startup. Default (false) is
    /// pure ASCII output, which is the safe choice for legacy terminals like
    /// PowerShell 5.1 / cmd.exe whose default code page is Windows-1252.
    pub unicode_output: bool,
    /// `-L`: add the NLINK (link count) column to table output. Implies the
    /// renderer pulls `OpenFile::links` into a new column.
    pub show_links: bool,
    /// `-K`: list each in-scope process's threads as additional rows
    /// (FD = `task`, TYPE = `THRD`, NODE = TID). Lsof's `-K` takes an
    /// optional argument (`-Ki` for selection mode); the parser accepts
    /// any value but the backend always emits all threads of in-scope
    /// processes.
    pub list_tasks: bool,
    /// `-T [fqsw]`: TCP/TPI info to append to socket rows. `None` = no `-T`.
    /// `s` (state) is already shown; `q` (queue) and `w` (window) come from
    /// per-connection extended TCP stats (`GetPerTcpConnectionEStats`), which
    /// require elevation. See `docs/feature-parity-plan.md` Phase 5B.
    pub tcp_info: Option<TcpInfoFlags>,
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
    /// Which process selecters `p` matches — the C's `lp->sf`
    /// (`lib/proc.c:is_proc_excl`). A kind absent from
    /// [`Selection::specified`] can never appear here.
    fn proc_kinds(&self, p: &Process) -> SelKinds {
        let mut k = SelKinds::NONE;
        if !self.pids.is_empty() && self.pids.contains(&p.pid) {
            k.insert(SelKinds::PID);
        }
        if !self.users.is_empty()
            && self
                .users
                .iter()
                .any(|u| user_matches(u, p.user.as_deref()))
        {
            k.insert(SelKinds::UID);
        }
        if !self.commands.is_empty() && self.commands.iter().any(|c| command_matches(c, &p.command))
        {
            k.insert(SelKinds::CMD);
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
        if self.inet.enabled && self.inet_matches(f) {
            k.insert(SelKinds::NET);
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

    /// Whether `f` satisfies the `-i` narrowing (protocol / family / port /
    /// host). Only called when `-i` was given.
    fn inet_matches(&self, f: &OpenFile) -> bool {
        let Some(sock) = &f.socket else {
            return false;
        };
        if !f.is_internet() {
            return false;
        }
        let i = &self.inet;
        if !i.proto_matches(sock.protocol) {
            return false;
        }
        if let Some(fam) = i.family {
            let is_v6 = f.file_type == crate::model::FileType::Ipv6;
            if (fam == 6) != is_v6 {
                return false;
            }
        }
        if let Some(port) = i.port {
            let lp = sock.local.map(|a| a.port());
            let rp = sock.remote.map(|a| a.port());
            if lp != Some(port) && rp != Some(port) {
                return false;
            }
        }
        if let Some(host) = &i.host {
            let l = sock.local.map(|a| a.ip().to_string()).unwrap_or_default();
            let r = sock.remote.map(|a| a.ip().to_string()).unwrap_or_default();
            if !l.contains(host.as_str()) && !r.contains(host.as_str()) {
                return false;
            }
        }
        true
    }

    /// Whether `f`'s name is one of the path arguments or under one of the
    /// `+d`/`+D` trees. Only called when such an argument was given.
    fn path_matches(&self, f: &OpenFile) -> bool {
        // Identity first: a path argument names a *file*, and lsof matches the
        // file it names however that file is reached. `+d`/`+D` were already
        // expanded into this set, so a directory tree is just more identities.
        if !self.path_ids.is_empty() {
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
        // No identities: the backend cannot resolve paths, so fall back to
        // matching names. This is the Windows path today.
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

    /// Whether `f`'s socket state matches the `-s [proto:state]` filter.
    /// Non-sockets and "no `-s`" always pass; sockets with `^excluded`
    /// states are always dropped; positive states act as a whitelist.
    fn state_matches(&self, f: &OpenFile) -> bool {
        let Some(filter) = &self.state_filter else {
            return true;
        };
        let Some(sock) = &f.socket else {
            // Non-sockets are passed through unchanged — `-s` is socket-only.
            return true;
        };
        if let Some(proto) = filter.proto {
            if sock.protocol != proto {
                return false;
            }
        }
        let state_name = sock
            .state
            .map(|s| s.as_str().to_string())
            .unwrap_or_default();
        if filter
            .exclude
            .iter()
            .any(|e| state_name.eq_ignore_ascii_case(e))
        {
            return false;
        }
        filter.include.is_empty()
            || filter
                .include
                .iter()
                .any(|i| state_name.eq_ignore_ascii_case(i))
    }

    /// Whether `p` is absolutely excluded by a `^` negation on `-u` or `-c`.
    ///
    /// Applied before everything else and never ORed or ANDed, per Lsof.8.
    /// Verified against the C: `lsof -c ^sleep -p <a sleep's pid>` prints
    /// nothing, with or without `-a`, even though `-p` names that very
    /// process.
    pub fn excludes_process(&self, p: &Process) -> bool {
        self.command_excludes
            .iter()
            .any(|c| command_matches(c, &p.command))
            || self
                .user_excludes
                .iter()
                .any(|u| user_matches(u, p.user.as_deref()))
    }

    /// The set of selector kinds this run specified — the C's `Selflags`
    /// (`src/main.c:1199-1240`). Empty means "no selectors at all", the C's
    /// `AllProc`: everything is listed.
    pub fn specified(&self) -> SelKinds {
        let mut k = SelKinds::NONE;
        if !self.pids.is_empty() {
            k.insert(SelKinds::PID);
        }
        if !self.users.is_empty() {
            k.insert(SelKinds::UID);
        }
        if !self.commands.is_empty() {
            k.insert(SelKinds::CMD);
        }
        if !self.ppid_filter.is_empty() {
            k.insert(SelKinds::PGID);
        }
        if self.fd_filter.is_some() {
            k.insert(SelKinds::FD);
        }
        if self.inet.enabled {
            k.insert(SelKinds::NET);
        }
        if self.unix_only {
            k.insert(SelKinds::UNX);
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

    /// Whether any process-level selector    /// Whether any process-level selector (`-p` / `-u` / `-c`) was given.
    pub fn has_process_selector(&self) -> bool {
        self.specified().intersects(SelKinds::PROC)
    }

    /// Whether any path / directory-tree filter was given.
    pub fn has_path_filter(&self) -> bool {
        !self.paths.is_empty() || !self.dir_trees.is_empty() || !self.dirs_one_level.is_empty()
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
                continue; // `-u ^root` / `-c ^name`: before all other selection
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
                !self.and_mode || sf.contains(specified)
            });
            if p.files.is_empty() {
                // A process with no rows left is a result only when it was
                // itself selected and no file selecter was given — the case
                // where the renderer prints a bare process line.
                if !self.proc_selected(inherited)
                    || specified.intersects(SelKinds::FILE)
                    || peer_only
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

/// `-c` match: case-insensitive prefix or substring (lsof matches a leading
/// substring; we accept either to be forgiving).
fn command_matches(needle: &str, command: &str) -> bool {
    let c = command.to_ascii_lowercase();
    let n = needle.to_ascii_lowercase();
    c.starts_with(&n) || c.contains(&n)
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
        sel.inet.port = Some(445);
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
            socket: Some(SocketInfo {
                protocol: proto,
                local: None,
                remote: Some("127.0.0.1:0".parse().unwrap()),
                state: None,
                tcp: None,
            }),
        };
        let icmp4 = sock_row(FileType::Ipv4, Protocol::Other("ICMP"));
        let icmp6 = sock_row(FileType::Ipv6, Protocol::Other("ICMPV6"));
        let raw4 = sock_row(FileType::Ipv4, Protocol::Other("RAW"));
        let tcp4 = sock_row(FileType::Ipv4, Protocol::Tcp);

        let filt = |proto: Option<Protocol>, family: Option<u8>| {
            let mut sel = Selection::default();
            sel.inet.enabled = true;
            sel.inet.proto = proto;
            sel.inet.family = family;
            sel
        };

        // -iICMP matches both the v4 and v6 ICMP codes, nothing else.
        let icmp = filt(Some(Protocol::Other("ICMP")), None);
        assert!(icmp.file_kinds(&icmp4).intersects(SelKinds::NET));
        assert!(icmp.file_kinds(&icmp6).intersects(SelKinds::NET));
        assert!(!icmp.file_kinds(&raw4).intersects(SelKinds::NET));
        assert!(!icmp.file_kinds(&tcp4).intersects(SelKinds::NET));

        // -i6ICMP narrows by family.
        let icmp_v6 = filt(Some(Protocol::Other("ICMP")), Some(6));
        assert!(!icmp_v6.file_kinds(&icmp4).intersects(SelKinds::NET));
        assert!(icmp_v6.file_kinds(&icmp6).intersects(SelKinds::NET));

        // -iRAW matches RAW only — never ICMP (exact, not substring/prefix).
        let raw = filt(Some(Protocol::Other("RAW")), None);
        assert!(raw.file_kinds(&raw4).intersects(SelKinds::NET));
        assert!(!raw.file_kinds(&icmp4).intersects(SelKinds::NET));
        assert!(!raw.file_kinds(&tcp4).intersects(SelKinds::NET));

        // Plain -i still matches every internet family.
        let any = filt(None, None);
        for r in [&icmp4, &icmp6, &raw4, &tcp4] {
            assert!(any.file_kinds(r).intersects(SelKinds::NET));
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
                proto: None,
                include: vec!["LISTEN".into()],
                exclude: vec![],
            }),
            ..Default::default()
        };
        assert!(sel.specified().is_empty(), "-s is not a specified kind");
        let got = sel.apply(mock::sample_processes());
        assert_eq!(got.len(), 2, "non-socket rows are untouched");
        let states: usize = got
            .iter()
            .flat_map(|p| &p.files)
            .filter(|f| f.socket.is_some())
            .count();
        assert_eq!(states, 1, "only the LISTEN socket survives");
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
            ..Default::default()
        };
        sel.path_ids.insert(("C:".into(), "42".into()));
        let p = Process {
            uid: None,
            pgid: None,
            pid: 7,
            ppid: None,
            command: "x".into(),
            user: None,
            endpoint_peer: false,
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
            uid: None,
            pgid: None,
            pid: 9999,
            ppid: None,
            command: "b.exe".into(),
            user: None,
            endpoint_peer: true,
            files: vec![pipe.clone(), reg.clone()],
        };
        // 8888 matches no selector and is no peer: dropped as usual.
        let stranger = Process {
            uid: None,
            pgid: None,
            pid: 8888,
            ppid: None,
            command: "c.exe".into(),
            user: None,
            endpoint_peer: false,
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
}
