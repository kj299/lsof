//! The FreeBSD [`Backend`]: the process table from `kern.proc.proc`, each
//! process's descriptors from `kern.proc.filedesc`, and what a row needs
//! beyond its record read once per gather, the first time a row asks.

use std::cell::{OnceCell, RefCell};
use std::collections::{HashMap, HashSet};
use std::path::Path;

use lsof_core::backend::{Backend, BackendError};
use lsof_core::model::{FdType, LockKind, Process};
use lsof_core::selection::Selection;

use crate::kinfo::{self, KFile, Pcb};
use crate::layout::{self, kf, sock};
use crate::rows::{self, Env, Opts, Vfs};
use crate::{devnames, mounts, sys, users};

/// lsof-rs's native FreeBSD data source.
pub struct FreeBsdBackend {
    root: bool,
}

impl FreeBsdBackend {
    pub fn new() -> Self {
        Self {
            root: sys::euid() == 0,
        }
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
    vfs: RefCell<Vec<Vfs>>,
    locks: OnceCell<HashMap<(i32, u64, u64), LockKind>>,
    pcbs: OnceCell<Pcbs>,
    devs: OnceCell<HashMap<u64, String>>,
    dev_dev: OnceCell<Option<u64>>,
    xfiles: OnceCell<HashMap<(i32, i32), u64>>,
}

impl<'a> Live<'a> {
    fn new(sel: &'a Selection) -> Self {
        Live {
            sel,
            vfs: RefCell::default(),
            locks: OnceCell::new(),
            pcbs: OnceCell::new(),
            devs: OnceCell::new(),
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
        if fsid != layout::VNOVAL {
            if let Some(v) = self.vfs.borrow().iter().find(|v| v.fsid == fsid) {
                return Some(v.clone());
            }
        }
        if path.is_empty() {
            return None;
        }
        let m = sys::statfs_path(Path::new(std::ffi::OsStr::from_bytes(path)))
            .ok()
            .and_then(|b| kinfo::statfs(&b))?;
        let mut cache = self.vfs.borrow_mut();
        if let Some(v) = cache
            .iter()
            .find(|v| v.fsname == m.mntfrom && v.dir == m.mnton)
        {
            return Some(v.clone());
        }
        let v = Vfs {
            dir: m.mnton,
            fsname: m.mntfrom,
            typnm: m.fstypename,
            fsid,
        };
        cache.push(v.clone());
        Some(v)
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

    fn dev_name(&self, rdev: u64) -> Option<String> {
        self.devs
            .get_or_init(|| devnames::scan(Path::new("/dev")))
            .get(&rdev)
            .cloned()
    }

    fn dev_dev(&self) -> Option<u64> {
        use std::os::unix::fs::MetadataExt;
        *self
            .dev_dev
            .get_or_init(|| std::fs::metadata("/dev").ok().map(|m| m.dev()))
    }

    fn file_addr(&self, pid: i32, fd: i32) -> Option<u64> {
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

/// The rows of one process, in the kernel's order (`process_file_descriptors()`).
fn rows_of(
    pid: i32,
    files: &[KFile],
    env: &Live<'_>,
    sockets_only: bool,
    opts: Opts,
) -> Vec<lsof_core::model::OpenFile> {
    let mut out = Vec::with_capacity(files.len());
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
            (Some(fd), _) => {
                if !sockets_only {
                    out.push(rows::special(k, fd, pid, env));
                }
            }
            (None, n) if n < 0 => {
                if !sockets_only {
                    warn(
                        env.sel,
                        &format!("lsof: WARNING -- unsupported fd type {n}"),
                    );
                }
            }
            (None, _) => {
                if sockets_only && k.kind() != kf::TYPE_SOCKET {
                    continue;
                }
                out.push(rows::numbered(k, pid, env, opts));
            }
        }
    }
    out.shrink_to_fit();
    out
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
        users::lookup(value)
    }

    fn gather(&self, sel: &Selection) -> Result<Vec<Process>, BackendError> {
        let buf = sys::sysctl_mib(&[layout::CTL_KERN, layout::KERN_PROC, layout::KERN_PROC_PROC])
            .map_err(|e| {
            BackendError::Os(format!("can't read process table: {}", errno(&e)))
        })?;
        let kprocs = kinfo::procs(&buf, layout::PROC_HOST.as_ref())
            .map_err(|e| BackendError::Os(format!("can't read process table: {}", e.0)))?;
        let mut procs: Vec<Process> = kprocs
            .into_iter()
            // The C passes by a process with no state and a zombie.
            .filter(|k| k.stat != 0 && k.stat != layout::SZOMB)
            .filter_map(|k| {
                Some(Process {
                    pid: u32::try_from(k.pid).ok()?,
                    ppid: u32::try_from(k.ppid).ok(),
                    command: String::from_utf8_lossy(&k.comm).into_owned(),
                    user: users::name_for(k.uid, sel.numeric_ids),
                    tid: None,
                    task_command: None,
                    uid: Some(k.uid),
                    pgid: u32::try_from(k.pgid).ok(),
                    files: Vec::new(),
                    endpoint_peer: false,
                    unlisted: false,
                })
            })
            .collect();
        procs.sort_by_key(|p| p.pid);
        procs.dedup_by_key(|p| p.pid);

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

        let restrict: Option<HashSet<u32>> = sel.has_process_selector().then(|| {
            procs
                .iter()
                .filter(|p| sel.selects_process(p))
                .map(|p| p.pid)
                .collect()
        });
        let env = Live::new(sel);
        let opts = Opts {
            inet: sel.inet.enabled,
            queues: sel.tcp_info().queue,
        };
        let sockets_only = sel.socket_rows_only();
        for p in procs.iter_mut() {
            if restrict.as_ref().is_some_and(|s| !s.contains(&p.pid)) {
                continue;
            }
            let Ok(pid) = i32::try_from(p.pid) else {
                continue;
            };
            // A process whose descriptors cannot be read has no rows, and so
            // no line, as in the C (`kinfo_getfile()` returns NULL, and
            // nothing is linked): there is no `NOFD` row on FreeBSD.
            p.files = match filedesc(pid) {
                Ok(files) => rows_of(pid, &files, &env, sockets_only, opts),
                Err(_) => Vec::new(),
            };
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
            .find(|f| f.name == format!("127.0.0.1:{port}"))
            .unwrap_or_else(|| panic!("no row for the listener: {:?}", p.files));
        assert_eq!(row.node.as_deref(), Some("TCP"));
        let st = row.socket.as_deref().and_then(|s| s.state);
        assert_eq!(st.map(lsof_core::model::SockState::as_str), Some("LISTEN"));
    }
}
