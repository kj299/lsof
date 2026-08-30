//! The Linux [`Backend`] implementation: enumerate processes from `/proc`, then
//! attach the files each one has open.

use std::collections::HashSet;

use lsof_core::backend::{Backend, BackendError};
use lsof_core::model::Process;
use lsof_core::selection::Selection;

use crate::{files, process};

/// winlsof's native Linux data source.
pub struct LinuxBackend {
    root: bool,
}

impl LinuxBackend {
    pub fn new() -> Self {
        Self {
            root: process::is_root(),
        }
    }

    /// Whether this process is running as root. The CLI uses it the way the
    /// Windows backend uses its elevation check: to decide whether to suggest a
    /// system-wide re-run.
    pub fn is_root(&self) -> bool {
        self.root
    }
}

impl Default for LinuxBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for LinuxBackend {
    fn name(&self) -> &str {
        "linux"
    }

    fn gather(&self, sel: &Selection) -> Result<Vec<Process>, BackendError> {
        let mut procs = process::enumerate(sel.numeric_ids);

        // `-t` prints PIDs only, and the renderer emits a process's PID whether
        // or not it has files. When no file-level filter needs per-file data,
        // skip the entire fd walk — identical output, none of the work. Mirrors
        // the Windows backend's terse fast-path.
        if sel.terse && !sel.inet.enabled && sel.fd_filter.is_none() && !sel.has_path_filter() {
            return Ok(procs);
        }

        // Scope the fd walk to processes a process-level selector can still
        // match, so `lsof -p/-c/-u …` doesn't read every process's fd table.
        // `None` means no such selector was given — inspect everything.
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

        for p in procs.iter_mut() {
            if restrict.as_ref().is_some_and(|s| !s.contains(&p.pid)) {
                continue;
            }
            // `None` here is a process we cannot read: it exited during the
            // scan, or it belongs to another user and we are not root. Both are
            // ordinary; the process still appears, just without its files.
            if let Some(files) = files::for_pid(p.pid) {
                p.files = files;
            }
        }

        Ok(procs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gathers_this_host_and_includes_self() {
        let sel = Selection::default();
        let procs = LinuxBackend::new().gather(&sel).expect("gather succeeds");
        assert!(!procs.is_empty(), "/proc should list at least this process");

        let me: u32 = std::fs::read_to_string("/proc/self/stat")
            .unwrap()
            .split(' ')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let mine = procs
            .iter()
            .find(|p| p.pid == me)
            .expect("this process appears in the gather");
        assert!(!mine.command.is_empty(), "own command name is populated");
        assert!(!mine.files.is_empty(), "own files are readable");
    }

    #[test]
    fn terse_fast_path_skips_file_enumeration() {
        // -t asks for PIDs only; proving no fds were walked is what keeps the
        // optimization honest.
        let sel = Selection {
            terse: true,
            ..Default::default()
        };
        let procs = LinuxBackend::new().gather(&sel).unwrap();
        assert!(!procs.is_empty());
        assert!(
            procs.iter().all(|p| p.files.is_empty()),
            "terse gather must not populate files"
        );
    }

    #[test]
    fn process_selector_scopes_the_fd_walk() {
        let me: u32 = std::fs::read_to_string("/proc/self/stat")
            .unwrap()
            .split(' ')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let sel = Selection {
            pids: vec![me],
            ..Default::default()
        };
        let procs = LinuxBackend::new().gather(&sel).unwrap();

        // Every process is still listed (selection filters later), but only the
        // selected one paid for an fd walk.
        let with_files: Vec<u32> = procs
            .iter()
            .filter(|p| !p.files.is_empty())
            .map(|p| p.pid)
            .collect();
        assert_eq!(with_files, vec![me]);
    }
}
