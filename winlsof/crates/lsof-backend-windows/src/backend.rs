//! The Windows [`Backend`] implementation: enumerate processes, then attach the
//! sockets (and, in Phase 3, the file handles) they own.

use std::collections::{HashMap, HashSet};

use lsof_core::backend::{Backend, BackendError};
use lsof_core::model::{OpenFile, Process};
use lsof_core::selection::Selection;

use crate::{handles, modules, peb, privilege, process, restart, sockets};

/// winlsof's native Windows data source.
pub struct WindowsBackend {
    elevated: bool,
}

impl WindowsBackend {
    pub fn new() -> Self {
        Self {
            elevated: privilege::is_elevated(),
        }
    }

    /// Whether this process holds an elevated (Administrator) token. The CLI
    /// uses this to decide whether to print the "run as Administrator for a
    /// system-wide view" hint.
    pub fn is_elevated(&self) -> bool {
        self.elevated
    }
}

impl Default for WindowsBackend {
    fn default() -> Self {
        Self::new()
    }
}

/// Attach a file to its owning process, creating a placeholder process if the
/// owner isn't in the snapshot (e.g. it exited during enumeration).
fn attach(procs: &mut Vec<Process>, idx: &mut HashMap<u32, usize>, pid: u32, file: OpenFile) {
    if let Some(&i) = idx.get(&pid) {
        procs[i].files.push(file);
    } else {
        let i = procs.len();
        procs.push(Process {
            pid,
            ppid: None,
            command: "<unknown>".to_string(),
            user: None,
            files: vec![file],
        });
        idx.insert(pid, i);
    }
}

impl Backend for WindowsBackend {
    fn name(&self) -> &str {
        "windows"
    }

    fn gather(&self, sel: &Selection) -> Result<Vec<Process>, BackendError> {
        let mut procs = process::enumerate();

        // Bare-file path lookup via Restart Manager (unprivileged, exact) — but
        // a `+D`/`+d` directory tree needs full enumeration, so it falls through.
        if !sel.paths.is_empty() && !sel.has_dir_trees() {
            let by_pid: HashMap<u32, Process> = procs.into_iter().map(|p| (p.pid, p)).collect();
            return Ok(restart::lookup(&sel.paths, &by_pid));
        }

        // Scope the expensive per-process work (handle duplication, module/PEB
        // snapshots) to the processes the process-level selectors can match, so
        // `lsof -p/-c/-u …` doesn't enumerate the whole system. `None` means no
        // process selector was given — inspect everything.
        let restrict: Option<HashSet<u32>> = if sel.has_process_selector() {
            Some(
                procs
                    .iter()
                    .filter(|p| sel.selects_process(p))
                    .map(|p| p.pid)
                    .collect(),
            )
        } else {
            None
        };
        let wanted = |pid: u32| restrict.as_ref().is_none_or(|s| s.contains(&pid));

        let mut idx: HashMap<u32, usize> = HashMap::with_capacity(procs.len());
        for (i, p) in procs.iter().enumerate() {
            idx.insert(p.pid, i);
        }

        // `-i` is a network-only query: gather only sockets, which need no
        // elevation — preserving the least-privilege guarantee.
        let inet_only = sel.inet.enabled;

        if !inet_only {
            // cwd + txt/mem for each in-scope process.
            for p in procs.iter_mut() {
                if !wanted(p.pid) {
                    continue;
                }
                if let Some(cwd) = peb::cwd(p.pid) {
                    p.files.push(cwd);
                }
                p.files.extend(modules::enumerate(p.pid));
            }
        }

        for (pid, file) in sockets::collect(sel.no_host_resolve, sel.no_port_resolve) {
            if wanted(pid) {
                attach(&mut procs, &mut idx, pid, file);
            }
        }

        if !inet_only {
            for (pid, file) in handles::enumerate(self.elevated, restrict.as_ref(), sel.verbose) {
                attach(&mut procs, &mut idx, pid, file);
            }
        }

        Ok(procs)
    }
}
