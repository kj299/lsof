//! The Windows [`Backend`] implementation: enumerate processes, then attach the
//! sockets (and, in Phase 3, the file handles) they own.

use std::collections::{HashMap, HashSet};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use lsof_core::backend::{Backend, BackendError};
use lsof_core::model::{FileType, OpenFile, Process};
use lsof_core::selection::{EndpointMode, Selection};

use crate::util::trace;
use crate::{
    etw, handles, mapped, modules, peb, privilege, process, restart, sockets, tcpinfo, threads,
};

/// Gather a process's `cwd` + loaded modules (`txt`/`mem`) + mapped data files on
/// a worker thread, bounded by `timeout`. These run against a *foreign* process
/// (`CreateToolhelp32Snapshot` for modules, PEB / address-space reads for the
/// rest) and can occasionally block; doing them off the main thread means one
/// slow process can't freeze the whole run. On timeout the worker is abandoned
/// (its extras skipped) and reaped when the process exits.
fn per_process_extras(
    pid: u32,
    dos_map: Arc<Vec<(String, String)>>,
    timeout: Duration,
) -> Vec<OpenFile> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut files = Vec::new();
        trace(&format!("  cwd pid={pid}"));
        if let Some(cwd) = peb::cwd(pid) {
            files.push(cwd);
        }
        trace(&format!("  modules pid={pid}"));
        files.extend(modules::enumerate(pid));
        trace(&format!("  mapped pid={pid}"));
        files.extend(mapped::enumerate(pid, &dos_map));
        let _ = tx.send(files);
    });
    rx.recv_timeout(timeout).unwrap_or_default()
}

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
            endpoint_peer: false,
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
        let mut procs = process::enumerate(sel.numeric_ids);
        trace(&format!(
            "gather: process::enumerate done ({} procs)",
            procs.len()
        ));

        // Terse output (`-t`) is just the PID list, and the renderer prints a
        // process's PID regardless of its files. So when no file-level filter
        // needs per-file data, skip *all* handle/socket/module enumeration — it
        // would be gathered only to be discarded. Pure optimization (identical
        // output) that keeps `lsof -t` from doing system-wide work it never uses.
        if sel.terse && !sel.inet.enabled && sel.fd_filter.is_none() && !sel.has_path_filter() {
            trace("gather: terse fast-path (PIDs only)");
            return Ok(procs);
        }

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

        // `-i` and `-U` are network-only queries: gather only sockets and skip
        // the handle/per-process enumeration (which is where elevation matters),
        // preserving the least-privilege guarantee. (`-U`'s data itself comes
        // from ETW, which does need admin — handled in that block.)
        let socket_only = sel.inet.enabled || sel.unix_only;

        if !socket_only {
            // cwd + txt/mem (modules) + mapped data files, for each in-scope process.
            trace("gather: build_dos_map start");
            let dos_map = Arc::new(handles::build_dos_map());
            trace(&format!(
                "gather: build_dos_map done ({} volumes)",
                dos_map.len()
            ));
            trace("gather: per-process (cwd/modules/mapped) start");
            for p in procs.iter_mut() {
                if !wanted(p.pid) {
                    continue;
                }
                p.files.extend(per_process_extras(
                    p.pid,
                    Arc::clone(&dos_map),
                    Duration::from_secs(2),
                ));
            }
            trace("gather: per-process done");
        }

        // IP Helper covers TCP/UDP. Show those unless this is a `-U`-only
        // (UNIX-domain) query, which wants just the ETW-sourced AF_UNIX rows.
        let show_inet_sockets = sel.inet.enabled || !sel.unix_only;
        if show_inet_sockets {
            trace("gather: sockets::collect start");
            let socks = sockets::collect();
            trace(&format!(
                "gather: sockets::collect done ({} endpoints)",
                socks.len()
            ));
            // Resolve names (reverse DNS / service lookup) only for the sockets
            // we keep, and only when they can actually be displayed. A path/dir
            // filter (`+D`/`+d`/bare path) never matches a socket (no filesystem
            // path), so resolving them would be pure waste — and it's the slow,
            // reverse-DNS path. So skip resolution for those queries.
            let resolve_sockets = !sel.has_path_filter();
            for (pid, mut file) in socks {
                if wanted(pid) {
                    if resolve_sockets {
                        sockets::resolve_name(&mut file, sel.no_host_resolve, sel.no_port_resolve);
                    }
                    // `-T q/w`: append extended TCP stats (window / queue) to the
                    // socket NAME via per-connection EStats. Needs elevation.
                    if let Some(t) = &sel.tcp_info {
                        tcpinfo::annotate(&mut file, t, self.elevated);
                    }
                    attach(&mut procs, &mut idx, pid, file);
                }
            }
        }

        // AFD sockets IP Helper can't enumerate come from a short ETW capture.
        // `--etw` surfaces all of them (raw / ICMP / AF_UNIX); `-U` narrows to
        // AF_UNIX. Either implies the (Administrator-only) capture. Histogram +
        // per-event schemas still surface on stderr for diagnosability (§5).
        if sel.use_etw || sel.unix_only {
            trace("gather: etw::capture start");
            if let Some(summary) = etw::capture(Duration::from_secs(2)) {
                trace(&format!(
                    "gather: etw::capture done ({} events, {} sockets)",
                    summary.total,
                    summary.sockets.len()
                ));
                for s in &summary.sockets {
                    if !wanted(s.pid) {
                        continue;
                    }
                    // `-U`: keep only AF_UNIX; otherwise keep everything IP
                    // Helper didn't already cover.
                    let keep = if sel.unix_only {
                        s.is_unix()
                    } else {
                        !s.is_covered_by_ip_helper()
                    };
                    if keep {
                        attach(&mut procs, &mut idx, s.pid, etw::to_open_file(s));
                    }
                }
                eprintln!("{}", summary.render(10));
            } else {
                trace("gather: etw::capture returned None (setup failed)");
            }
        }

        if !socket_only {
            trace("gather: handles::enumerate start");
            // `-E`/`+E`: hand enumeration a pid → command map so pipe rows can
            // name their peer endpoints; its presence turns the queries on.
            let endpoint_cmds: Option<HashMap<u32, String>> = sel
                .endpoints
                .map(|_| procs.iter().map(|p| (p.pid, p.command.clone())).collect());
            let (hs, peers) = handles::enumerate(
                self.elevated,
                restrict.as_ref(),
                sel.verbose,
                endpoint_cmds.as_ref(),
            );
            trace(&format!(
                "gather: handles::enumerate done ({} handles)",
                hs.len()
            ));
            for (pid, file) in hs {
                attach(&mut procs, &mut idx, pid, file);
            }

            // `+E`: also display the endpoint processes' own pipe rows. Peers
            // inside the selected set are fully shown already; enumerate the
            // rest, keep just their pipe rows, and mark each process so the
            // selection engine retains it despite matching no selector.
            if sel.endpoints == Some(EndpointMode::Files) {
                if let Some(r) = &restrict {
                    let missing: HashSet<u32> = peers.difference(r).copied().collect();
                    if !missing.is_empty() {
                        trace(&format!("gather: +E peer pass ({} pids)", missing.len()));
                        let (extra, _) = handles::enumerate(
                            self.elevated,
                            Some(&missing),
                            false,
                            endpoint_cmds.as_ref(),
                        );
                        for (pid, file) in extra {
                            if file.file_type == FileType::Pipe {
                                attach(&mut procs, &mut idx, pid, file);
                                if let Some(&i) = idx.get(&pid) {
                                    procs[i].endpoint_peer = true;
                                }
                            }
                        }
                    }
                }
            }
        }

        // `-K`: list each in-scope process's threads as `task` rows. Toolhelp's
        // thread snapshot needs no elevation, so this works regardless of the
        // `-i`/path scoping above.
        if sel.list_tasks {
            trace("gather: threads::enumerate start");
            let ts = threads::enumerate(restrict.as_ref());
            trace(&format!(
                "gather: threads::enumerate done ({} threads)",
                ts.len()
            ));
            for (pid, file) in ts {
                if wanted(pid) {
                    attach(&mut procs, &mut idx, pid, file);
                }
            }
        }

        trace("gather: done");
        Ok(procs)
    }
}
