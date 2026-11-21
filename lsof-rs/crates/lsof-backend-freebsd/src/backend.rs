//! The FreeBSD [`Backend`]: the process table from `kern.proc.proc`, each
//! process's descriptors from `kern.proc.filedesc`, and what a row needs
//! beyond its record read once per gather, the first time a row asks.

use std::cell::{OnceCell, RefCell};
use std::collections::{HashMap, HashSet};
use std::path::Path;

use lsof_core::backend::{Backend, BackendError};
use lsof_core::model::{FdType, LockKind, Process};
use lsof_core::selection::{Selection, TaskMode};

use crate::kinfo::{self, KFile, Pcb, XFile};
use crate::layout::{self, kf, sock};
use crate::rows::{self, Env, Opts, Vfs};
use crate::{devnames, mounts, sys, users};

/// lsof-rs's native FreeBSD data source.
pub struct FreeBsdBackend {
    root: bool,
    /// The run's device table (`devnames::DevCache`): made as the first
    /// gather starts, as the C makes it as it starts, and kept for the run.
    devs: OnceCell<devnames::DevCache>,
    /// The file systems found so far (`readvfs()`'s `Lvfs`), kept for the
    /// run as the C keeps its list: a `-r` cycle finds what the last found.
    vfs: rows::VfsList,
    /// The devices of the rows the last gather typed NFS files, where `-N`
    /// asked ([`Backend::take_nfs_devices`]).
    nfs: RefCell<HashSet<u64>>,
}

impl FreeBsdBackend {
    pub fn new() -> Self {
        Self {
            root: sys::euid() == 0,
            devs: OnceCell::new(),
            vfs: rows::VfsList::default(),
            nfs: RefCell::default(),
        }
    }

    /// `readdev(ctx, 0)` at `main.c:1303-1304`: the table of `/dev`, made
    /// once, with its warnings (`WARNDEVACCESS`, unless `-w`); with no
    /// character device in it the C says so and ends the run
    /// (`lib/rdev.c:380-382`), and so does this, whenever it is read.
    fn devs(&self, sel: &Selection) -> &devnames::DevCache {
        let quiet = sel.suppress_warnings;
        let cache = self.devs.get_or_init(|| {
            devnames::DevCache::new(
                Box::new(move || {
                    let t = devnames::scan(Path::new("/dev"));
                    if !quiet {
                        for w in &t.warnings {
                            lsof_core::safefs::to_stderr(w);
                        }
                    }
                    if t.is_empty() {
                        lsof_core::safefs::to_stderr("lsof: no character devices found");
                        lsof_core::safefs::exit(1);
                    }
                    t
                }),
                Box::new(devnames::check),
            )
        });
        cache.load();
        cache
    }

    /// Whether this process runs as root, which is what lets it read every
    /// process's descriptors: `kern.proc.filedesc` of a process it cannot
    /// debug is `EPERM`.
    pub fn is_root(&self) -> bool {
        self.root
    }
}

impl Default for FreeBsdBackend {
    fn default() -> Self {
        Self::new()
    }
}

fn warn(sel: &Selection, line: &str) {
    if !sel.suppress_warnings {
        lsof_core::safefs::to_stderr(line);
    }
}

fn errno(e: &std::io::Error) -> String {
    lsof_core::backend::errno_text(e)
}

/// One process's descriptor records, or why there are none.
fn filedesc(pid: i32) -> std::io::Result<Vec<KFile>> {
    sys::sysctl_mib(&[
        layout::CTL_KERN,
        layout::KERN_PROC,
        layout::KERN_PROC_FILEDESC,
        pid,
    ])
    .map(|b| kinfo::files(&b))
}

#[derive(Default)]
struct Pcbs {
    tcp: HashMap<u64, Pcb>,
    udp: HashMap<u64, Pcb>,
    stream: HashMap<u64, Pcb>,
    dgram: HashMap<u64, Pcb>,
    seqpacket: HashMap<u64, Pcb>,
}

/// The [`Env`] of a live gather: each table read on first use.
struct Live<'a> {
    sel: &'a Selection,
    vfs: &'a rows::VfsList,
    nfs: &'a RefCell<HashSet<u64>>,
    locks: OnceCell<HashMap<(i32, u64, u64), LockKind>>,
    pcbs: OnceCell<Pcbs>,
    devs: &'a devnames::DevCache,
    dev_dev: OnceCell<Option<u64>>,
    xfiles: OnceCell<HashMap<(i32, i32), XFile>>,
}

impl<'a> Live<'a> {
    fn new(sel: &'a Selection, backend: &'a FreeBsdBackend, devs: &'a devnames::DevCache) -> Self {
        Live {
            sel,
            vfs: &backend.vfs,
            nfs: &backend.nfs,
            locks: OnceCell::new(),
            pcbs: OnceCell::new(),
            devs,
            dev_dev: OnceCell::new(),
            xfiles: OnceCell::new(),
        }
    }

    fn pcbs(&self) -> &Pcbs {
        self.pcbs.get_or_init(|| {
            let mut failed = None;
            let mut read = |name: &str, l: &layout::PcbLayout| match sys::sysctl_name(name) {
                Ok(b) => kinfo::pcblist(&b, l),
                Err(e) => {
                    failed.get_or_insert(e);
                    HashMap::new()
                }
            };
            let p = Pcbs {
                stream: read("net.local.stream.pcblist", &layout::XUNPCB),
                dgram: read("net.local.dgram.pcblist", &layout::XUNPCB),
                seqpacket: read("net.local.seqpacket.pcblist", &layout::XUNPCB),
                tcp: read("net.inet.tcp.pcblist", &layout::XTCPCB),
                udp: read("net.inet.udp.pcblist", &layout::XINPCB),
            };
            if let Some(e) = failed {
                warn(
                    self.sel,
                    &format!("lsof: WARNING -- reading PCBs failed: {}", errno(&e)),
                );
            }
            p
        })
    }
}

impl Env for Live<'_> {
    fn vfs(&self, fsid: u64, path: &[u8]) -> Option<Vfs> {
        use std::os::unix::ffi::OsStrExt;
        // `statfs(2)` in lsof itself, as the C's (DIVERGENCES 143).
        self.vfs.find(fsid, path, &|path| {
            sys::statfs_path(Path::new(std::ffi::OsStr::from_bytes(path)))
                .ok()
                .and_then(|b| kinfo::statfs(&b))
        })
    }

    fn nfs_file(&self, dev: u64) {
        if self.sel.nfs_only {
            self.nfs.borrow_mut().insert(dev);
        }
    }

    fn lock(&self, pid: i32, fsid: u64, fileid: u64) -> Option<LockKind> {
        self.locks
            .get_or_init(|| {
                let buf = sys::sysctl_mib(&[layout::CTL_KERN, layout::KERN_LOCKF]);
                let buf = match buf {
                    Ok(b) => b,
                    Err(e) => {
                        warn(
                            self.sel,
                            &format!("lsof: WARNING -- reading lockf list failed: {}", errno(&e)),
                        );
                        Vec::new()
                    }
                };
                let mut m = HashMap::new();
                for l in kinfo::locks(&buf).into_iter().filter(|l| l.sysid == 0) {
                    let whole = l.start == 0 && l.len == 0;
                    m.entry((l.pid, l.fsid, l.fileid))
                        .or_insert(LockKind::new(l.write, whole));
                }
                m
            })
            .get(&(pid, fsid, fileid))
            .copied()
    }

    fn pcb(&self, domain: i32, ty: i32, pcb: u64) -> Option<Pcb> {
        let p = self.pcbs();
        let table = match (domain, ty) {
            (sock::AF_INET | sock::AF_INET6, sock::SOCK_STREAM) => &p.tcp,
            (sock::AF_INET | sock::AF_INET6, sock::SOCK_DGRAM) => &p.udp,
            (sock::AF_UNIX, sock::SOCK_STREAM) => &p.stream,
            (sock::AF_UNIX, sock::SOCK_DGRAM) => &p.dgram,
            (sock::AF_UNIX, sock::SOCK_SEQPACKET) => &p.seqpacket,
            _ => return None,
        };
        table.get(&pcb).copied()
    }

    fn dev_name(&self, rdev: u64, inode: Option<u64>) -> Option<String> {
        self.devs.name(rdev, inode)
    }

    fn dev_inode(&self, rdev: u64) -> Option<u64> {
        self.devs.inode(rdev)
    }

    fn pts_seen(&self) {
        self.devs.mark_unsafe();
    }

    fn dev_dev(&self) -> Option<u64> {
        use std::os::unix::fs::MetadataExt;
        *self
            .dev_dev
            .get_or_init(|| std::fs::metadata("/dev").ok().map(|m| m.dev()))
    }

    fn xfile(&self, pid: i32, fd: i32) -> Option<XFile> {
        self.xfiles
            .get_or_init(|| {
                sys::sysctl_mib(&[layout::CTL_KERN, layout::KERN_FILE])
                    .map(|b| kinfo::xfiles(&b))
                    .unwrap_or_else(|e| {
                        warn(
                            self.sel,
                            &format!("lsof: WARNING -- reading xfile list failed: {}", errno(&e)),
                        );
                        HashMap::new()
                    })
            })
            .get(&(pid, fd))
            .copied()
    }
}

/// A process's [`lsof_core::Process::file_structs`].
type FileStructs = Option<Box<[(u64, lsof_core::FileStruct)]>>;

/// The rows of one process, in the kernel's order (`process_file_descriptors()`),
/// and, where `+f` asks for it, each numbered row's file structure, by
/// descriptor number.
///
/// `sockets_only` is the C's `ckscko`, which in this dialect skips no
/// record (`dproc.c:255-286`): it only keeps a special from being read as
/// one, and silences the warning for a kind it does not know. Every record
/// is still made a row and linked where its process was selected, a row
/// that no listing of sockets alone can print; but one that is there
/// locates `-K` and `-N`. Measured on FreeBSD 14.5: `lsof -V -K -a -p P
/// -U`, P holding no socket, prints nothing and exits 0, where Linux's C
/// says `no tasks located` and exits 1.
fn rows_of(
    pid: i32,
    files: &[KFile],
    env: &Live<'_>,
    sockets_only: bool,
    opts: Opts,
) -> (Vec<lsof_core::model::OpenFile>, FileStructs) {
    let mut out = Vec::with_capacity(files.len());
    let mut structs = Vec::new();
    rows::precache_vfs(files, env);
    for k in files {
        let special = match k.fd() {
            kf::FD_CWD => Some(FdType::Cwd),
            kf::FD_ROOT => Some(FdType::Root),
            kf::FD_JAIL => Some(FdType::Jail),
            kf::FD_TEXT => Some(FdType::Txt),
            kf::FD_CTTY => Some(FdType::Ctty),
            _ => None,
        };
        match (special, k.fd()) {
            // Under `ckscko` the C reads a special as a numbered descriptor
            // whose number is negative (the final `else`), a row it never
            // prints: here it is the special it is, never printed either.
            (Some(fd), _) => out.push(rows::special(k, fd, pid, env)),
            (None, n) if n < 0 => {
                if !sockets_only {
                    warn(
                        env.sel,
                        &format!("lsof: WARNING -- unsupported fd type {n}"),
                    );
                }
            }
            (None, _) => {
                let row = rows::numbered(k, pid, env, opts);
                if opts.file_struct {
                    if let lsof_core::model::FdType::Handle(n) = row.fd {
                        structs.push((n, rows::file_struct(k, env.xfile(pid, k.fd()))));
                    }
                }
                out.push(row);
            }
        }
    }
    out.shrink_to_fit();
    // Sorted and one per descriptor, for `Process::file_struct`'s search.
    structs.sort_by_key(|(n, _)| *n);
    structs.dedup_by_key(|(n, _)| *n);
    let structs = opts.file_struct.then(|| structs.into_boxed_slice());
    (out, structs)
}

impl Backend for FreeBsdBackend {
    fn name(&self) -> &str {
        "freebsd"
    }

    fn identify_stat(&self, st: &lsof_core::FileStat) -> Option<lsof_core::FileId> {
        // `st_dev` and `st_ino`: the C compares them with a row's
        // `kf_file_fsid` and `kf_file_fileid`, which the kernel fills from
        // the same `vattr` a `stat(2)` reports (`vn_stat()`).
        Some(lsof_core::FileId {
            dev: st.dev,
            ino: st.ino,
        })
    }

    fn identifies_paths(&self) -> bool {
        true
    }

    fn mount_table(
        &self,
        req: &lsof_core::MountRequest,
        fs: &lsof_core::SafeFs,
    ) -> lsof_core::MountTable {
        match sys::getfsstat_all() {
            Ok(b) => mounts::resolve(&kinfo::statfs_list(&b), req, fs),
            Err(_) => {
                fs.tell("lsof: no mount information");
                lsof_core::MountTable::default()
            }
        }
    }

    fn has_mount_type(&self, fstype: &str) -> bool {
        sys::getfsstat_all()
            .map(|b| mounts::has_type(&kinfo::statfs_list(&b), fstype))
            .unwrap_or(false)
    }

    fn lookup_user(&self, value: &str) -> lsof_core::UserLookup {
        users::lookup(value.as_bytes())
    }

    fn lookup_user_bytes(&self, value: &[u8]) -> lsof_core::UserLookup {
        users::lookup(value)
    }

    fn login_name(&self, uid: u32) -> Option<Box<[u8]>> {
        users::name_for(uid, false)
    }

    /// `-i @name`: the system's resolver, through `std` (`getaddrinfo(3)`),
    /// which reads `/etc/hosts` and DNS as `/etc/nsswitch.conf` orders them.
    /// Not measured against the C on FreeBSD (DIVERGENCES 38).
    fn lookup_host(&self, name: &[u8], v6: bool) -> Vec<std::net::IpAddr> {
        lsof_core::netnames::system_host(name, v6)
    }

    /// `-i :name`: `/etc/services`, whose lines FreeBSD writes as glibc's
    /// `files` service reads them.
    fn lookup_service(&self, name: &[u8], protocol: &str) -> Option<u16> {
        lsof_core::netnames::service_in_file(
            std::path::Path::new("/etc/services"),
            name,
            protocol.as_bytes(),
        )
        .found()
    }

    fn take_nfs_devices(&self) -> Option<HashSet<u64>> {
        Some(std::mem::take(&mut *self.nfs.borrow_mut()))
    }

    fn gather(&self, sel: &Selection) -> Result<Vec<Process>, BackendError> {
        // The C reads `/dev` before anything else it lists (`main.c:1304`).
        let devs = self.devs(sel);
        self.nfs.borrow_mut().clear();
        // `-K`, and not `-K i`: `Ftask`, under which the C reads every
        // thread's record and makes each a task (`dproc.c:390`, `:443`). A
        // run with no selection at all lists none, unlike Linux's: the
        // dialect asks `Ftask`, never `Selflags`.
        let tasks = sel.tasks == TaskMode::Always;
        let which = if tasks {
            layout::KERN_PROC_ALL
        } else {
            layout::KERN_PROC_PROC
        };
        let buf = sys::sysctl_mib(&[layout::CTL_KERN, layout::KERN_PROC, which])
            .map_err(|e| BackendError::Os(format!("can't read process table: {}", errno(&e))))?;
        let kprocs = kinfo::procs(&buf, layout::PROC_HOST.as_ref())
            .map_err(|e| BackendError::Os(format!("can't read process table: {}", e.0)))?;
        let mut procs = rows::entries(kprocs, tasks);

        // `-t` alone: no rows are printed, but a process is listed only
        // through its rows, and one whose descriptors cannot be read has
        // none. Reading the table is the only way to know; its rows are
        // not built.
        if sel.terse_skips_files() {
            for p in procs.iter_mut().filter(|p| sel.selects_process(p)) {
                let Ok(pid) = i32::try_from(p.pid) else {
                    continue;
                };
                p.unlisted = filedesc(pid).map_or(true, |f| f.is_empty());
            }
            return Ok(procs);
        }

        let restrict: Option<HashSet<(u32, Option<u32>)>> = sel.has_process_selector().then(|| {
            procs
                .iter()
                .filter(|p| sel.selects_process(p))
                .map(|p| (p.pid, p.tid))
                .collect()
        });
        let env = Live::new(sel, self, devs);
        let opts = Opts::of(sel);
        // The rows of the process whose task was read last: every thread of
        // a process is given the same files (the C reads them again for
        // each, `process_file_descriptors()` of the same PID).
        let mut last: Option<(u32, bool, Vec<lsof_core::model::OpenFile>, FileStructs)> = None;
        for p in procs.iter_mut() {
            if restrict
                .as_ref()
                .is_some_and(|s| !s.contains(&(p.pid, p.tid)))
            {
                continue;
            }
            let Ok(pid) = i32::try_from(p.pid) else {
                continue;
            };
            // The C's `ckscko`, a process at a time (`dproc.c:455-463`).
            let sockets_only = sel.sockets_only_for(p);
            match &last {
                Some((of, only, files, structs)) if *of == p.pid && *only == sockets_only => {
                    (p.files, p.file_structs) = (files.clone(), structs.clone());
                }
                _ => {
                    // A process whose descriptors cannot be read has no rows,
                    // and so no line, as in the C (`kinfo_getfile()` returns
                    // NULL, and nothing is linked): there is no `NOFD` row on
                    // FreeBSD.
                    (p.files, p.file_structs) = match filedesc(pid) {
                        Ok(files) => rows_of(pid, &files, &env, sockets_only, opts),
                        Err(_) => (Vec::new(), None),
                    };
                    if tasks {
                        last = Some((p.pid, sockets_only, p.files.clone(), p.file_structs.clone()));
                    }
                }
            }
            p.unlisted = p.files.is_empty();
        }
        Ok(procs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_process_is_gathered_with_its_cwd_and_an_open_file() {
        let f = std::fs::File::open("/etc/passwd").expect("open /etc/passwd");
        let me = std::process::id();
        let sel = Selection {
            pids: vec![me],
            ..Default::default()
        };
        let procs = FreeBsdBackend::new().gather(&sel).expect("gather");
        let p = procs.iter().find(|p| p.pid == me).expect("this process");
        assert!(p.files.iter().any(|f| f.fd == FdType::Cwd), "{:?}", p.files);
        assert!(p.files.iter().any(|f| f.fd == FdType::Txt));
        let row = p
            .files
            .iter()
            .find(|f| f.name.starts_with("/etc/passwd"))
            .expect("the open file is a row");
        // The identity a path argument finds it by is the one stat gives.
        use std::os::unix::fs::MetadataExt;
        let md = f.metadata().unwrap();
        assert_eq!(
            row.file_id(),
            Some(lsof_core::FileId {
                dev: md.dev(),
                ino: md.ino()
            }),
            "kf_file_fsid/fileid must be what std's stat reports"
        );
        assert_eq!(row.file_type.code(), "VREG");
    }

    #[test]
    fn a_listening_socket_is_found_with_its_state() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let me = std::process::id();
        let sel = Selection {
            pids: vec![me],
            ..Default::default()
        };
        let procs = FreeBsdBackend::new().gather(&sel).unwrap();
        let p = procs.iter().find(|p| p.pid == me).unwrap();
        let row = p
            .files
            .iter()
            .find(|f| f.name == format!("127.0.0.1:{port}->*:*"))
            .unwrap_or_else(|| panic!("no row for the listener: {:?}", p.files));
        assert_eq!(row.node.as_deref(), Some("TCP"));
        let st = row.socket.as_deref().and_then(|s| s.state);
        assert_eq!(st.map(lsof_core::model::SockState::as_str), Some("LISTEN"));
    }
    /// An unconnected IPv4 UDP socket has its foreign end, `*:*`; an IPv6
    /// one has none (DIVERGENCES 180).
    #[test]
    fn a_udp_socket_shows_its_far_end_as_the_c_does() {
        let v4 = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = v4.local_addr().unwrap().port();
        let v6 = std::net::UdpSocket::bind("[::1]:0").ok();
        let me = std::process::id();
        let sel = Selection {
            pids: vec![me],
            ..Default::default()
        };
        let procs = FreeBsdBackend::new().gather(&sel).unwrap();
        let p = procs.iter().find(|p| p.pid == me).unwrap();
        let named = |name: String| p.files.iter().any(|f| f.name == name);
        assert!(
            named(format!("127.0.0.1:{port}->*:*")),
            "no row for the IPv4 socket: {:?}",
            p.files
        );
        if let Some(port6) = v6
            .as_ref()
            .and_then(|s| s.local_addr().ok())
            .map(|a| a.port())
        {
            assert!(
                named(format!("[::1]:{port6}")),
                "no row for the IPv6 socket: {:?}",
                p.files
            );
        }
    }

    /// Under `-K` each thread of this process is an entry with its TID, a
    /// number FreeBSD starts at 100000 (so `ki_tid` is read where it is),
    /// each with the process's files; without `-K` the process is one entry
    /// and has none.
    #[test]
    fn under_dash_k_this_processs_threads_are_its_entries() {
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let rx = std::sync::Arc::new(std::sync::Mutex::new(rx));
        let workers: Vec<_> = (0..2)
            .map(|_| {
                let rx = std::sync::Arc::clone(&rx);
                std::thread::spawn(move || {
                    let _ = rx.lock().map(|r| r.recv());
                })
            })
            .collect();
        let me = std::process::id();
        let tasks = Selection {
            pids: vec![me],
            and_mode: true,
            tasks: TaskMode::Always,
            ..Default::default()
        };
        let backend = FreeBsdBackend::new();
        let procs = backend.gather(&tasks).expect("gather");
        let mine: Vec<&Process> = procs.iter().filter(|p| p.pid == me).collect();
        drop(tx);
        for w in workers {
            let _ = w.join();
        }
        assert!(mine.len() >= 3, "this thread and two more: {}", mine.len());
        let mut tids: Vec<u32> = mine.iter().filter_map(|p| p.tid).collect();
        assert_eq!(tids.len(), mine.len(), "every entry is a task");
        assert!(tids.iter().all(|&t| t >= 100_000), "{tids:?}");
        assert!(
            tids.windows(2).all(|w| w[0] < w[1]),
            "in TID order: {tids:?}"
        );
        tids.dedup();
        assert_eq!(tids.len(), mine.len(), "each thread once");
        for p in &mine {
            assert!(p.task_command.is_none());
            assert!(p.files.iter().any(|f| f.fd == FdType::Cwd), "{:?}", p.files);
            assert_eq!(p.files.len(), mine[0].files.len());
        }
        let plain = Selection {
            pids: vec![me],
            ..Default::default()
        };
        let procs = backend.gather(&plain).expect("gather");
        let mine: Vec<&Process> = procs.iter().filter(|p| p.pid == me).collect();
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0].tid, None);
    }
}
