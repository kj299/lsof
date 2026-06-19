//! The Windows [`Backend`] implementation: enumerate processes, then attach the
//! sockets (and, in Phase 3, the file handles) they own.

use std::collections::{HashMap, HashSet};

use lsof_core::backend::{Backend, BackendError};
use lsof_core::model::{OpenFile, Process};
use lsof_core::selection::Selection;

use crate::util::trace;
use crate::{handles, mapped, modules, peb, privilege, process, restart, sockets};

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
        trace("gather: process::enumerate start");
        let mut procs = process::enumerate();
        trace(&format!(
            "gather: process::enumerate done ({} procs)",
            procs.len()
        ));

        // Bare-file path lookup via Restart Manager (unprivileged, exact) — but
        // a `+D`/`+d` directory tree needs full enumeration, so it falls through.
        if !sel.paths.is_empty() && !sel.has_dir_trees() {
            trace("gather: restart::lookup (bare path) start");
            let by_pid: HashMap<u32, Process> = procs.into_iter().map(|p| (p.pid, p)).collect();
            let r = restart::lookup(&sel.paths, &by_pid);
            trace("gather: restart::lookup done");
            return Ok(r);
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
            // cwd + txt/mem (modules) + mapped data files, for each in-scope process.
            trace("gather: build_dos_map start");
            let dos_map = handles::build_dos_map();
            trace(&format!(
                "gather: build_dos_map done ({} volumes)",
                dos_map.len()
            ));
            trace("gather: per-process (cwd/modules/mapped) start");
            for p in procs.iter_mut() {
                if !wanted(p.pid) {
                    continue;
                }
                trace(&format!("  cwd pid={}", p.pid));
                if let Some(cwd) = peb::cwd(p.pid) {
                    p.files.push(cwd);
                }
                trace(&format!("  modules pid={}", p.pid));
                p.files.extend(modules::enumerate(p.pid));
                trace(&format!("  mapped pid={}", p.pid));
                p.files.extend(mapped::enumerate(p.pid, &dos_map));
            }
            trace("gather: per-process done");
        }

        trace("gather: sockets::collect start");
        let socks = sockets::collect(sel.no_host_resolve, sel.no_port_resolve);
        trace(&format!(
            "gather: sockets::collect done ({} endpoints)",
            socks.len()
        ));
        for (pid, file) in socks {
            if wanted(pid) {
                attach(&mut procs, &mut idx, pid, file);
            }
        }

        if !inet_only {
            trace("gather: handles::enumerate start");
            let hs = handles::enumerate(self.elevated, restrict.as_ref(), sel.verbose);
            trace(&format!(
                "gather: handles::enumerate done ({} handles)",
                hs.len()
            ));
            for (pid, file) in hs {
                attach(&mut procs, &mut idx, pid, file);
            }
        }

        trace("gather: done");
        Ok(procs)
    }
}
