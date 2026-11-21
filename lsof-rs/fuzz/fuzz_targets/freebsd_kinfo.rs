#![no_main]

// Fuzz the FreeBSD backend's record parsers (lsof-backend-freebsd, `kinfo`)
// and the row rules that run on what they return (`rows`).
//
// Every byte here is what a sysctl handed back: `kern.proc.filedesc`'s packed
// `kinfo_file`s, whose lengths the parser must not trust, `kern.proc.proc`,
// `kern.lockf`, the pcblists, `getfsstat(2)`. A process names its files and
// binds its sockets, so a path is attacker-chosen text, and a record length
// is only as good as the kernel that wrote it. The contract is the kit's: no
// panic, and no record invented from bytes that were not there.

use libfuzzer_sys::fuzz_target;
use lsof_backend_freebsd::fuzz_api as f;
use f::Env as _;
use lsof_core::model::{FdType, LockKind};

/// An environment that knows everything a row can ask, so every branch that
/// depends on an answer is reached, alternating with one that knows nothing.
struct Knows(bool);

impl f::Env for Knows {
    fn vfs(&self, fsid: u64, path: &[u8]) -> Option<f::Vfs> {
        (self.0 && !path.is_empty()).then(|| f::Vfs {
            dir: path.get(..path.len() / 2).unwrap_or_default().to_vec(),
            fsname: path.to_vec(),
            typnm: match path.len() % 3 {
                0 => b"nullfs".to_vec(),
                1 => b"procfs".to_vec(),
                _ => b"nfs".to_vec(),
            },
            fsid,
        })
    }
    fn lock(&self, _: i32, _: u64, _: u64) -> Option<LockKind> {
        self.0.then_some(LockKind::ReadPartial)
    }
    fn pcb(&self, _: i32, _: i32, pcb: u64) -> Option<f::Pcb> {
        self.0.then_some(f::Pcb { so: pcb, t_state: Some((pcb % 16) as i32), ..f::Pcb::default() })
    }
    fn dev_name(&self, rdev: u64, _inode: Option<u64>) -> Option<String> {
        self.0.then(|| format!("/dev/{rdev}"))
    }
    fn dev_inode(&self, rdev: u64) -> Option<u64> {
        self.0.then_some(rdev)
    }
    fn dev_dev(&self) -> Option<u64> {
        self.0.then_some(0x5a)
    }
    fn pts_seen(&self) {}
    fn xfile(&self, _: i32, _: i32) -> Option<f::XFile> {
        self.0.then_some(f::XFile { file: u64::MAX, data: 1, vnode: 2, flag: u32::MAX })
    }
    fn nfs_file(&self, _: u64) {}
}

fuzz_target!(|data: &[u8]| {
    let files = f::files(data);
    // The first pass over a process's records, and the list it fills: every
    // path is `statfs`ed by a function that answers from the path's bytes.
    f::precache_vfs(&files, &Knows(true));
    let list = f::VfsList::default();
    for k in &files {
        let _ = list.find(k.file_fsid(), k.path(), &|path| {
            f::statfs_list(path).into_iter().next()
        });
    }
    let mut seen = 0usize;
    for (i, k) in files.iter().enumerate() {
        let env = Knows(i % 2 == 0);
        let opts = f::Opts { inet: i % 3 == 0, file_struct: i % 5 == 0 };
        let row = f::numbered(k, 1, &env, opts);
        let _ = f::file_struct(k, env.xfile(1, k.fd()));
        let _ = row.base_name();
        let _ = f::special(k, FdType::Cwd, 1, &env);
        seen += 1;
    }
    // Each record is at least the fixed part, so there are never more of
    // them than the bytes could hold.
    assert!(seen <= data.len() / 368, "invented records: {seen} from {} bytes", data.len());

    for l in [f::PROC_AMD64, f::PROC_I386] {
        if let Ok(p) = f::procs(data, Some(&l)) {
            assert!(p.len() <= data.len() / l.size);
            // The listing's entries, processes and then (`-K`) threads: never
            // more than the records, and in PID then TID order.
            let records = p.len();
            for tasks in [false, true] {
                let e = f::entries(p.clone(), tasks);
                assert!(e.len() <= records);
                assert!(e.windows(2).all(|w| (w[0].pid, w[0].tid) < (w[1].pid, w[1].tid)));
                assert!(tasks || e.iter().all(|p| p.tid.is_none()));
            }
        }
    }
    assert!(f::locks(data).len() <= data.len() / 1088);
    for l in [f::XTCPCB, f::XINPCB, f::XUNPCB] {
        let _ = f::pcblist(data, &l);
    }
    let _ = f::statfs_list(data);
    let _ = f::xfiles(data);
    let _ = f::unix_path(data);
    let _ = f::inet_addr(data, 2);
    let _ = f::inet_addr(data, 28);
});
