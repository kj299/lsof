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

    fn path_fs_device(&self, path: &str) -> Option<u64> {
        // lstat, not stat: `arg.c` tests the entry's OWN st_dev before it
        // decides whether to resolve a symlink, so a link pointing at another
        // file system is judged by where the link is, not where it goes.
        std::fs::symlink_metadata(path).ok().map(|m| m.dev())
    }

    fn mounts(&self) -> Vec<lsof_core::MountEntry> {
        mounts::load()
    }

    fn identifies_paths(&self) -> bool {
        true
    }

    fn lookup_user(&self, value: &str) -> lsof_core::UserLookup {
        crate::users::lookup(value)
    }

    fn gather(&self, sel: &Selection) -> Result<Vec<Process>, BackendError> {
        let process::Enumerated { mut procs, zombies } = process::enumerate(sel.numeric_ids);

        // `-t` prints PIDs only, and the renderer emits a process's PID whether
        // or not it has files. When no file-level filter needs per-file data,
        // skip the entire fd walk — identical output, none of the work. Mirrors
        // the Windows backend's terse fast-path. Not under `-s`: a state it
        // names is a search item, located only by reading the sockets.
        if sel.terse
            && !sel.inet.enabled
            && sel.fd_filter.is_none()
            && !sel.has_path_filter()
            && sel.state_filter.is_none()
        {
            // A zombie is never listed (DIVERGENCES 31) — except through a
            // task that outlived its main thread, when tasks are listed at
            // all. Its entry stands in for that task here: the pid is the same
            // and `-t` prints nothing else.
            procs.retain(|p| {
                !zombies.contains(&p.pid) || (sel.lists_tasks() && !process::tasks_of(p).is_empty())
            });
            // `-t` sets `-w`, under which a file that cannot be read has no
            // row, and a process with no row is not printed — so the fast path
            // still has to know whether there is anything to read. Asked of
            // the processes that can be printed at all, and answered on the
            // first `readlink` for any process that can be read.
            if sel.omit_unreadable {
                for p in procs.iter_mut().filter(|p| sel.selects_process(p)) {
                    let readable = if zombies.contains(&p.pid) {
                        process::tasks_of(p).iter().any(|t| {
                            let tid = t.tid.unwrap_or(p.pid);
                            files::has_readable_file(&format!("/proc/{}/task/{tid}", p.pid))
                        })
                    } else {
                        files::has_readable_file(&format!("/proc/{}", p.pid))
                    };
                    p.unlisted = !readable;
                }
            }
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
        let socks = SocketTable::load(sel.tcp_info().queue, sel.skip_inet_tables);
        // /proc/locks is one table for the whole system, with a pid column, so
        // it is read once here rather than per process.
        let locks = crate::locks::load();
        // Built empty and filled only if a socket turns up that this
        // namespace's tables cannot explain — nothing is read on a host with
        // one network namespace.
        let nstab = crate::net::NetnsTables::new(sel.skip_inet_tables);
        // When nothing but a socket can reach the output, collect nothing but
        // sockets. The big one is the mapped-file walk: under `-i` the C opens
        // no `/proc/<pid>/maps` at all, and this port was opening one per
        // process and parsing every mapping, to drop the rows at selection.
        let ctx = files::GatherCtx {
            socks: &socks,
            locks: &locks,
            ns: &nstab,
            exempt: &sel.exempt_fs,
            sockets_only: sel.socket_rows_only(),
            omit_unreadable: sel.omit_unreadable,
        };

        for p in procs.iter_mut() {
            if restrict.as_ref().is_some_and(|s| !s.contains(&p.pid)) {
                continue;
            }
            // A zombie holds nothing — its fd table and `mm` are gone — and it
            // is dropped below; reading its empty directories would be waste.
            if zombies.contains(&p.pid) {
                continue;
            }
            // A process we cannot read — another user's, when we are not root
            // — comes back with the rows that say what could not be read, as
            // the C's do; under `-w` or `-t`, with none, and then it has no
            // line at all (it is still found: `-p` naming it is located).
            p.files = files::for_pid(p.pid, p.uid, &ctx);
            p.unlisted = p.files.is_empty();
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
                    t.files = files::for_proc_dir(&base, p.pid, t.uid, &ctx);
                    t.unlisted = t.files.is_empty();
                    tasks.push(t);
                }
            }
            procs.extend(tasks);
            // The C emits each process followed by its tasks in tid order; a
            // stable sort on (pid, tid) reproduces that, with `None` — the
            // process itself — sorting first.
            procs.sort_by_key(|p| (p.pid, p.tid));
        }

        // The C never lists a zombie: `read_id_stat()` says `Z` and the
        // process entry is skipped (`dproc.c`, `prv != 1`). Its live tasks,
        // gathered above, stay — that is how a process whose main thread has
        // exited is still listed, and only when tasks are. Everything else
        // about the zombie is gone: `lsof -p <zombie>` prints nothing and
        // exits 1 because the pid is no longer located, rather than printing
        // the bare `unk unknown` row the renderer draws for a fileless entry.
        if !zombies.is_empty() {
            procs.retain(|p| p.tid.is_some() || !zombies.contains(&p.pid));
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
    fn socket_only_selection_collects_only_sockets() {
        use lsof_core::model::FdType;
        // `-i` can print nothing but sockets, so the backend must not build
        // the rows that would only be dropped: the cwd/rtd/txt specials and,
        // the expensive one, every mapped file from /proc/<pid>/maps. Measured
        // at 577 processes: this port opened 578 maps files for `lsof -i`
        // where the C opened none.
        let sel = Selection {
            inet: lsof_core::selection::InetFilter {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(
            sel.socket_rows_only(),
            "the fixture must engage the fast path"
        );
        let procs = LinuxBackend::new().gather(&sel).unwrap();
        // A socket fd whose protocol nothing could identify still yields a
        // row -- `socket` is None and the NAME stays the kernel's
        // `socket:[<inode>]` (DIVERGENCES item 22: netlink, AF_VSOCK). It IS a
        // socket, so the test asks what the fast path actually promises: the
        // link was `socket:[...]`, not that the row resolved.
        let non_socket: Vec<String> = procs
            .iter()
            .flat_map(|p| p.files.iter())
            .filter(|f| f.socket.is_none() && !f.name.starts_with("socket:["))
            .map(|f| format!("{:?} {}", f.fd, f.name))
            .collect();
        assert!(
            non_socket.is_empty(),
            "socket-only gather produced non-socket rows: {non_socket:?}"
        );
        let specials: Vec<String> = procs
            .iter()
            .flat_map(|p| p.files.iter())
            .filter(|f| !matches!(f.fd, FdType::Handle(_)))
            .map(|f| format!("{:?}", f.fd))
            .collect();
        assert!(
            specials.is_empty(),
            "socket-only gather kept specials/mapped rows: {specials:?}"
        );
    }

    /// The control for `socket_only_selection_collects_only_sockets`, and the
    /// reason that test cannot pass vacuously: the same backend, with the fast
    /// path OFF, must still produce exactly the kinds it skips. Delete this and
    /// that one would hold on a host where there was nothing to collect.
    ///
    /// Scoped to this process, not the host. It proves the same thing — `-p`
    /// switches the socket-only path off, so the walk that runs is the full one
    /// — and a whole-host control is the most expensive thing this backend can
    /// do: under miri it measured **227 s on its own**, and it is where the
    /// 60-minute budget of the observe-first miri job went the first time this
    /// was written. `process_selector_scopes_the_fd_walk` pins that only the
    /// named pid pays for an fd walk, so one process is all this needs.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "miri's stat shim reports st_dev as 0, so maps::rows_for drops                   every live mapping on the device check: measured on the same                   process, 12132 bytes of /proc/<pid>/maps read and 30 mappings                   parsed, 0 mem rows built (natively: 4 parsed, 4 rows). Same                   shim as device_nodes_report_their_own_number_not_the_filesystem"
    )]
    fn default_selection_still_collects_specials_and_mapped_rows() {
        use lsof_core::model::FdType;
        let me: u32 = std::fs::read_to_string("/proc/self/stat")
            .unwrap()
            .split(' ')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let control = Selection {
            pids: vec![me],
            ..Default::default()
        };
        assert!(
            !control.socket_rows_only(),
            "a -p selection must NOT take the socket-only path"
        );
        let all = LinuxBackend::new().gather(&control).unwrap();
        let kinds: Vec<&FdType> = all
            .iter()
            .flat_map(|p| p.files.iter())
            .map(|f| &f.fd)
            .collect();
        for want in [FdType::Cwd, FdType::Txt, FdType::Mem] {
            assert!(
                kinds.contains(&&want),
                "control gather should still produce {want:?} rows"
            );
        }
    }

    /// A child that has exited and not been waited for: a zombie, until the
    /// returned [`std::process::Child`] is waited on.
    // Leaving a child unwaited is what this helper is FOR; every caller reaps
    // the one it returns, which is more than the lint can follow.
    #[expect(
        clippy::zombie_processes,
        reason = "the helper exists to make a zombie; its caller waits on the child"
    )]
    fn zombie() -> std::process::Child {
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn true");
        let pid = child.id();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            // `stat`'s state is the first field after the LAST `)`.
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
            if stat
                .rsplit(')')
                .next()
                .is_some_and(|rest| rest.trim_start().starts_with('Z'))
            {
                return child;
            }
            if std::time::Instant::now() >= deadline {
                // Reap it rather than leave the zombie this was waiting for.
                let _ = child.wait();
                panic!("pid {pid} never became a zombie");
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    /// DIVERGENCES 31: the C never lists a zombie, even one `-p` names —
    /// `lsof -p <zombie>` prints nothing and exits 1. lsof-rs gathered it,
    /// fileless, and the renderer drew its bare `unk unknown` row.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test needs a real zombie"
    )]
    fn a_zombie_is_not_gathered_even_when_named() {
        let mut child = zombie();
        let pid = child.id();
        let named = Selection {
            pids: vec![pid],
            ..Default::default()
        };
        let gathered = LinuxBackend::new().gather(&named).unwrap();
        let terse = LinuxBackend::new()
            .gather(&Selection {
                terse: true,
                ..named.clone()
            })
            .unwrap();
        // The control: the process is there to be found, and known for what it is.
        let seen = process::enumerate(false);
        child.wait().expect("reap the zombie");
        assert!(
            seen.procs.iter().any(|p| p.pid == pid) && seen.zombies.contains(&pid),
            "control: enumerate must find pid {pid} and know it is a zombie"
        );
        assert!(
            !gathered.iter().any(|p| p.pid == pid),
            "a zombie must not be gathered"
        );
        assert!(
            !terse.iter().any(|p| p.pid == pid),
            "nor through -t's fast path, which never walks files"
        );
    }

    /// A process could hide from lsof-rs by naming itself with a byte that is
    /// not UTF-8: `/proc/<pid>/status` then failed `read_to_string` and the
    /// process was skipped outright — `lsof -p` said it did not exist. And a
    /// mapped file with such a name emptied its process's `mem` rows the same
    /// way. The kernel takes `comm` from the exec'd file's name, so exec'ing a
    /// copy of `sleep` named `sl\xffeep` does both at once, with no `prctl`
    /// (the differential's fixtures C and D use the same trick).
    #[test]
    #[cfg_attr(
        miri,
        ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test needs a process named with a non-UTF-8 byte"
    )]
    fn a_process_named_with_a_non_utf8_byte_is_still_gathered() {
        use lsof_core::model::FdType;
        use std::os::unix::ffi::OsStrExt;
        let dir = std::env::temp_dir().join(format!("lsof-rs-comm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join(std::ffi::OsStr::from_bytes(b"sl\xffeep"));
        std::fs::copy("/bin/sleep", &exe).expect("copy /bin/sleep");
        // `ETXTBSY` is a race, not a failure: a test on another thread that
        // forks while the copy is still open for writing hands its child a
        // duplicate of that fd until the child execs, and exec'ing a file
        // someone holds open for writing is refused. It clears on its own.
        let mut tries = 0;
        let mut child = loop {
            match std::process::Command::new(&exe).arg("30").spawn() {
                Ok(child) => break child,
                Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy && tries < 100 => {
                    tries += 1;
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => panic!("spawn the renamed sleep: {e}"),
            }
        };
        let pid = child.id();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::fs::read(format!("/proc/{pid}/comm")).ok().as_deref() != Some(b"sl\xffeep\n") {
            assert!(
                std::time::Instant::now() < deadline,
                "the child never exec'd"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let strict = std::fs::read_to_string(format!("/proc/{pid}/status"));
        let procs = LinuxBackend::new()
            .gather(&Selection {
                pids: vec![pid],
                ..Default::default()
            })
            .unwrap();
        child.kill().ok();
        child.wait().ok();
        std::fs::remove_dir_all(&dir).ok();
        assert!(
            strict.is_err(),
            "control: the strict read must fail on this name"
        );
        let p = procs
            .iter()
            .find(|p| p.pid == pid)
            .expect("a non-UTF-8 name must not hide the process");
        assert_eq!(p.command, "sl\u{FFFD}eep");
        // /bin/sleep is dynamically linked, so libc is mapped: `mem` rows exist
        // only if `maps` survived the executable's own undecodable path.
        assert!(
            p.files.iter().any(|f| f.fd == FdType::Mem),
            "the mem rows must survive a mapping whose path is not UTF-8"
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
