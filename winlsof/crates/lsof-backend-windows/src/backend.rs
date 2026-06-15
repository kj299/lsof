//! The Windows [`Backend`] implementation: enumerate processes, then attach the
//! sockets (and, in Phase 3, the file handles) they own.

use std::collections::HashMap;

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

        // Path lookup mode (bare path / `+D`): Restart Manager finds the
        // processes holding each path open, and works without elevation.
        if !sel.paths.is_empty() {
            let by_pid: HashMap<u32, Process> = procs.into_iter().map(|p| (p.pid, p)).collect();
            return Ok(restart::lookup(&sel.paths, &by_pid));
        }

        let mut idx: HashMap<u32, usize> = HashMap::with_capacity(procs.len());
        for (i, p) in procs.iter().enumerate() {
            idx.insert(p.pid, i);
        }

        // `-i` is a network-only query: gather only sockets, which need no
        // elevation. Skipping cwd/modules/handle enumeration preserves the
        // least-privilege guarantee (no SeDebugPrivilege for `-i`) and avoids
        // needless work.
        let inet_only = sel.inet.enabled;

        if !inet_only {
            // cwd + txt/mem for each process.
            for p in procs.iter_mut() {
                if let Some(cwd) = peb::cwd(p.pid) {
                    p.files.push(cwd);
                }
                p.files.extend(modules::enumerate(p.pid));
            }
        }

        for (pid, file) in sockets::collect() {
            attach(&mut procs, &mut idx, pid, file);
        }

        if !inet_only {
            for (pid, file) in handles::enumerate(self.elevated) {
                attach(&mut procs, &mut idx, pid, file);
            }
        }

        Ok(procs)
    }
}
