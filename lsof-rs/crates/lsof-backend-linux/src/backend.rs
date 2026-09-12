//! The Linux [`Backend`] implementation: enumerate processes from `/proc`, then
//! attach the files each one has open.

use std::collections::HashSet;

use lsof_core::backend::{Backend, BackendError};
use lsof_core::model::Process;
use lsof_core::selection::Selection;

use std::os::unix::fs::MetadataExt;

use crate::net::SocketTable;
use crate::{files, mounts, process};

/// lsof-rs's native Linux data source.
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

    fn identify_path(&self, path: &str) -> Option<(String, String)> {
        // The same two cells a row carries, produced by the same code, so the
        // comparison in selection is a plain equality test. `metadata` follows
        // symlinks, which is right: lsof identifies the file a name resolves
        // to, and that is what a process holding it will report.
        let md = std::fs::metadata(path).ok()?;
        // DEVICE means st_rdev for a device node and st_dev for everything
        // else, and a row is built the same way — so `lsof /dev/null` must
        // compare 1,3 against 1,3, not against the devtmpfs it lives on.
        Some((files::dev_cell(&md), md.ino().to_string()))
    }

    fn mounts(&self) -> Vec<lsof_core::MountEntry> {
        mounts::load()
    }

    fn identifies_paths(&self) -> bool {
        true
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

        // /proc/net is system-wide, so it is read once for the whole gather
        // rather than per process. `-T q` is the only reason to pay for queue
        // depths; see SocketTable::load.
        let socks = SocketTable::load(sel.tcp_info().queue);
        // /proc/locks is one table for the whole system, with a pid column, so
        // it is read once here rather than per process.
        let locks = crate::locks::load();
        // Built empty and filled only if a socket turns up that this
        // namespace's tables cannot explain — nothing is read on a host with
        // one network namespace.
        let nstab = crate::net::NetnsTables::new();

        for p in procs.iter_mut() {
            if restrict.as_ref().is_some_and(|s| !s.contains(&p.pid)) {
                continue;
            }
            // `None` here is a process we cannot read: it exited during the
            // scan, or it belongs to another user and we are not root. Both are
            // ordinary; the process still appears, just without its files.
            if let Some(files) = files::for_pid(p.pid, &socks, &locks, &nstab) {
                p.files = files;
            }
        }

        // `-K`: every other thread becomes its own entry, repeating the whole
        // file set from its own `/proc/<pid>/task/<tid>` — which is what makes
        // `lsof -K` on a 3-thread process print three times the rows, mapped
        // files included. The main thread is not among them: it IS the process,
        // and shows blank TID/TASKCMD cells.
        if sel.lists_tasks() {
            let mut tasks = Vec::new();
            // An explicit `-K` makes tasks a selector of their own, so EVERY
            // process's tasks are candidates — `lsof -K -p N` lists N's rows
            // and every other process's task rows, because the two selectors
            // are ORed. Without `-K` the listing is the unselected default,
            // where `restrict` is `None` anyway, so this costs nothing extra.
            let task_scope = match sel.tasks {
                lsof_core::TaskMode::Always => None,
                _ => restrict.as_ref(),
            };
            for p in procs.iter() {
                if task_scope.is_some_and(|s| !s.contains(&p.pid)) {
                    continue;
                }
                for mut t in process::tasks_of(p) {
                    let base = format!("/proc/{}/task/{}", p.pid, t.tid.unwrap_or(p.pid));
                    if let Some(files) = files::for_proc_dir(&base, p.pid, &socks, &locks, &nstab) {
                        t.files = files;
                    }
                    tasks.push(t);
                }
            }
            procs.extend(tasks);
            // The C emits each process followed by its tasks in tid order; a
            // stable sort on (pid, tid) reproduces that, with `None` — the
            // process itself — sorting first.
            procs.sort_by_key(|p| (p.pid, p.tid));
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
