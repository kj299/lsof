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

use crate::model::{OpenFile, Process, Protocol};

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
    /// Bare path arguments / `+D` / `+d`: report only files whose name matches
    /// one of these paths (used for "who has this file open" lookups).
    pub paths: Vec<String>,
}

impl Selection {
    /// True if any process-level selector was specified.
    fn has_proc_selector(&self) -> bool {
        !self.pids.is_empty() || !self.users.is_empty() || !self.commands.is_empty()
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
        if self.and_mode {
            results.iter().all(|&b| b)
        } else {
            results.iter().any(|&b| b)
        }
    }

    /// Whether a single file passes the file-level filters (`-i` and path
    /// matching). Kept when no file-level filter is active.
    fn file_matches(&self, f: &OpenFile) -> bool {
        if !self.paths.is_empty() {
            let name = f.name.to_ascii_lowercase();
            let hit = self.paths.iter().any(|p| {
                let p = p.to_ascii_lowercase();
                name == p || name.starts_with(&p)
            });
            if !hit {
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
            if (self.inet.enabled || !self.paths.is_empty()) && p.files.is_empty() {
                // `-i` and path lookups require at least one matching file.
                continue;
            }
            out.push(p);
        }
        out
    }
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
}
