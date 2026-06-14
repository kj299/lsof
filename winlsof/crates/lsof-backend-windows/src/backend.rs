//! The Windows [`Backend`] implementation: enumerate processes, then attach the
//! sockets (and, in Phase 3, the file handles) they own.

use std::collections::HashMap;

use lsof_core::backend::{Backend, BackendError};
use lsof_core::model::{OpenFile, Process};
use lsof_core::selection::Selection;

use crate::{handles, modules, privilege, process, sockets};

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

    fn gather(&self, _sel: &Selection) -> Result<Vec<Process>, BackendError> {
        let mut procs = process::enumerate();
        let mut idx: HashMap<u32, usize> = HashMap::with_capacity(procs.len());
        for (i, p) in procs.iter().enumerate() {
            idx.insert(p.pid, i);
        }

        // txt/mem: the loaded image and libraries for each process.
        for p in procs.iter_mut() {
            let mods = modules::enumerate(p.pid);
            p.files.extend(mods);
        }

        for (pid, file) in sockets::collect() {
            attach(&mut procs, &mut idx, pid, file);
        }
        for (pid, file) in handles::enumerate(self.elevated) {
            attach(&mut procs, &mut idx, pid, file);
        }

        Ok(procs)
    }
}
