//! The selection / filtering engine — the portable equivalent of the option
//! handling in lsof's `src/arg.c` + `src/main.c`.
//!
//! MVP semantics (documented deliberately, since lsof's full AND/OR matrix is
//! intricate):
//!
//! * Process selectors `-p` / `-u` / `-c` choose processes. Among the selectors
//!   that are actually specified, they combine with OR by default and with AND
//!   when `-a` ([`Selection::and_mode`]) is set.
//! * `-i` is always an additional constraint: when present, only Internet
//!   sockets are shown, optionally narrowed by protocol / port / host / family,
//!   and a process with no matching socket is dropped. (This favors the common
//!   intent of `lsof -i ...`; see README for the deviation from classic OR.)
//! * With no selectors at all, every process and file is listed.

use crate::model::{FdType, OpenFile, Process, Protocol};

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
    /// True if any process-level selector was specified.
    fn has_proc_selector(&self) -> bool {
        !self.pids.is_empty()
            || !self.users.is_empty()
            || !self.commands.is_empty()
            || !self.ppid_filter.is_empty()
    }

    /// Whether this process matches the specified process-level selectors,
    /// combining them per the AND/OR rule. Returns `true` if none specified.
    fn proc_matches(&self, p: &Process) -> bool {
        if !self.has_proc_selector() {
            return true;
        }
        let mut results: Vec<bool> = Vec::new();
        if !self.pids.is_empty() {
            results.push(self.pids.contains(&p.pid));
        }
        if !self.users.is_empty() {
            results.push(
                self.users
                    .iter()
                    .any(|u| user_matches(u, p.user.as_deref())),
            );
        }
        if !self.commands.is_empty() {
            results.push(self.commands.iter().any(|c| command_matches(c, &p.command)));
        }
        if !self.ppid_filter.is_empty() {
            // `-g` Windows extension: select processes whose parent is in the
            // PPID list (the closest analog to PGID selection on Unix).
            results.push(p.ppid.is_some_and(|pp| self.ppid_filter.contains(&pp)));
        }
        if self.and_mode {
            results.iter().all(|&b| b)
        } else {
            results.iter().any(|&b| b)
        }
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

    /// Whether `p` passes the process-level selectors (`-p` / `-u` / `-c`),
    /// ignoring file-level filters. Backends use this to scope expensive
    /// per-process work to the processes that could be selected.
    pub fn selects_process(&self, p: &Process) -> bool {
        self.proc_matches(p)
    }

    /// Whether any process-level selector (`-p` / `-u` / `-c`) was given.
    pub fn has_process_selector(&self) -> bool {
        self.has_proc_selector()
    }

    /// Whether any path / directory-tree filter was given.
    pub fn has_path_filter(&self) -> bool {
        !self.paths.is_empty() || !self.dir_trees.is_empty()
    }

    /// Whether a `+D`/`+d` directory filter was given — which forces full
    /// enumeration rather than the Restart Manager fast path.
    pub fn has_dir_trees(&self) -> bool {
        !self.dir_trees.is_empty()
    }

    /// Whether a single file passes the file-level filters (`-d`, `-i`, `-s`,
    /// and path / directory matching). Kept when no file-level filter is
    /// active.
    fn file_matches(&self, f: &OpenFile) -> bool {
        if !self.state_matches(f) {
            return false;
        }
        if let Some(max) = self.max_links {
            // `+L count`: keep links < count; drop if we know links and it's
            // not under the threshold. Unknown links (sockets etc.) pass.
            if let Some(n) = f.links {
                if n >= max {
                    return false;
                }
            }
        }
        if let Some(fd) = &self.fd_filter {
            if !fd.matches(&f.fd) {
                return false;
            }
        }
        if self.has_path_filter() {
            let name = f.name.to_ascii_lowercase();
            let exact = self.paths.iter().any(|p| {
                let p = p.to_ascii_lowercase();
                name == p || name.starts_with(&p)
            });
            let under = self
                .dir_trees
                .iter()
                .any(|d| under_dir(&name, &d.to_ascii_lowercase()));
            if !(exact || under) {
                return false;
            }
        }
        if !self.inet.enabled {
            return true;
        }
        let Some(sock) = &f.socket else {
            return false;
        };
        if !f.is_internet() {
            return false;
        }
        let i = &self.inet;
        if let Some(proto) = i.proto {
            if sock.protocol != proto {
                return false;
            }
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

    /// Apply the full selection to a backend's raw output, returning the
    /// processes to display with their files already filtered.
    pub fn apply(&self, procs: Vec<Process>) -> Vec<Process> {
        let mut out = Vec::new();
        for mut p in procs {
            if !self.proc_matches(&p) {
                continue;
            }
            p.files.retain(|f| self.file_matches(f));
            let needs_file =
                self.inet.enabled || self.has_path_filter() || self.fd_filter.is_some();
            if needs_file && p.files.is_empty() {
                // `-i`, `-d`, and path lookups require at least one matching file.
                continue;
            }
            out.push(p);
        }
        out
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
    fn inet_only_keeps_socket_files() {
        let mut sel = Selection::default();
        sel.inet.enabled = true;
        let got = sel.apply(mock::sample_processes());
        assert!(got.iter().all(|p| p.files.iter().all(|f| f.is_internet())));
        assert!(got.iter().all(|p| !p.files.is_empty()));
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
