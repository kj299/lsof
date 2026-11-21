//! One `kinfo_file` record into one lsof row, as the C's FreeBSD dialect
//! builds it: `process_kinfo_file()` (`dproc.c`), `process_vnode()`,
//! `process_pipe()`, `process_pts()` and the rest of `dnode.c`, and
//! `process_socket()` (`dsock.c`). The `file:line`-free references below are
//! to those functions; each branch says what of the C it is.
//!
//! Pure: everything outside the record that a row needs — a file system's
//! names, a lock, a pcblist entry, a device's name in `/dev` — is asked of an
//! [`Env`], so the rules can be tested on any host with a fake one.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU32;

use lsof_core::model::{
    AccessMode, BsdSocket, FdType, FileStruct, FileType, LockKind, OpenFile, Process, Protocol,
    SockState, SocketInfo, TcpExtInfo,
};

use crate::kinfo::{inet_addr, unix_path, KFile, KProc, Pcb, XFile};
use crate::layout::{kf, sock, KF_TO_FFLAGS, SZOMB, VNOVAL};
use crate::names::{alt_hex, dev_string, iproto, kptr, ptr, tcp_state, unknown_family};

/// A mounted file system as `readvfs()` records it: `struct l_vfs`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vfs {
    /// `f_mntonname`.
    pub dir: Vec<u8>,
    /// `f_mntfromname`.
    pub fsname: Vec<u8>,
    /// `f_fstypename`.
    pub typnm: Vec<u8>,
    /// The `kf_file_fsid` it was first found by, or [`VNOVAL`] when it was
    /// found by path alone (a nullfs mount's lower layer).
    pub fsid: u64,
}

/// `readvfs()`'s list of the file systems found so far (`Lvfs`,
/// `dmnt.c:195-260`), kept for the run.
#[derive(Debug, Default)]
pub struct VfsList(std::cell::RefCell<Vec<Vfs>>);

impl VfsList {
    /// `readvfs(fsid, path)`: the entry first found by `fsid`, if there is
    /// an `fsid` to find one by; else, where there is a path, the file
    /// system `statfs` says it is on, which is the entry already listed
    /// under the same two names (and then that entry's `fsid` is the row's,
    /// [`VNOVAL`] included), or a new one, recorded under `fsid`. A path
    /// that cannot be `statfs`ed is on none, and is asked again next time.
    pub fn find(
        &self,
        fsid: u64,
        path: &[u8],
        statfs: &dyn Fn(&[u8]) -> Option<crate::kinfo::StatFs>,
    ) -> Option<Vfs> {
        if fsid != VNOVAL {
            if let Some(v) = self.0.borrow().iter().find(|v| v.fsid == fsid) {
                return Some(v.clone());
            }
        }
        if path.is_empty() {
            return None;
        }
        let m = statfs(path)?;
        let mut list = self.0.borrow_mut();
        if let Some(v) = list
            .iter()
            .find(|v| v.fsname == m.mntfrom && v.dir == m.mnton)
        {
            return Some(v.clone());
        }
        // `MFSNAMELEN - 1` bytes of the type's name, at most (`:243-246`).
        let mut typnm = m.fstypename;
        typnm.truncate(15);
        let v = Vfs {
            dir: m.mnton,
            fsname: m.mntfrom,
            typnm,
            fsid,
        };
        list.push(v.clone());
        Some(v)
    }
}

/// What a row needs from outside its record.
pub trait Env {
    /// `readvfs(fsid, path)`: the file system `path` is on, found first by
    /// `fsid` among those already found, then by `statfs(path)`.
    fn vfs(&self, fsid: u64, path: &[u8]) -> Option<Vfs>;
    /// The lock `pid` holds on the file (`get_lock_state_sysctl()`).
    fn lock(&self, pid: i32, fsid: u64, fileid: u64) -> Option<LockKind>;
    /// The pcblist entry for a socket of this domain and type whose
    /// `so_pcb` is `pcb` (`find_pcb_and_xsocket()`).
    fn pcb(&self, domain: i32, ty: i32, pcb: u64) -> Option<Pcb>;
    /// The name in `/dev` of the character device `rdev`: with `inode`, the
    /// entry with that inode too (`lkupdev(…, 1, …)`), without it the first
    /// the C's search meets (`lkupdev(…, 0, …)`); `devnames`.
    fn dev_name(&self, rdev: u64, inode: Option<u64>) -> Option<String>;
    /// `find_ch_ino()`: the inode `/dev` gives the character device `rdev`.
    fn dev_inode(&self, rdev: u64) -> Option<u64>;
    /// `DevDev`: the device `/dev` is on.
    fn dev_dev(&self) -> Option<u64>;
    /// A terminal row was made: `process_pts()`'s `DCunsafe = 1`
    /// (`dnode.c:750`), after which a lookup that misses reads `/dev` again
    /// ([`crate::devnames::DevCache`]).
    fn pts_seen(&self);
    /// `kern.file`'s record of `pid`'s `fd` (the C's `bsearch()` of its
    /// `xfile` list, `dproc.c:248-253`).
    fn xfile(&self, pid: i32, fd: i32) -> Option<XFile>;
    /// A row on device `dev` was typed an NFS file (`Ntype = N_NFS`,
    /// `dnode.c:364`): what `-N` selects (`:524`), by the file system each
    /// vnode is on and no mount table (DIVERGENCES 182).
    fn nfs_file(&self, dev: u64);
}

/// What of the run's options a row is built under.
#[derive(Clone, Copy, Debug, Default)]
pub struct Opts {
    /// The run asks about Internet files alone (the C's `Selinet`,
    /// `main.c:1236-1240`): a pipe is then not processed (`dproc.c:202`).
    pub inet: bool,
    /// `+f` (or `-F`, or JSON) asks for the file structure: FILE-FLAG's
    /// flags on each numbered row, and [`file_struct`] (DIVERGENCES 142).
    pub file_struct: bool,
}

impl Opts {
    /// The options a run's rows are built under. `inet` is `Selinet`, not
    /// `-i` given: with another selector beside it (`-u tester -i TCP:1`)
    /// the C processes a pipe as ever, and a process the other selector
    /// lists shows its pipes (measured on FreeBSD 14.5; lsof-rs had left
    /// them blank rows, typed `0000`).
    pub fn of(sel: &lsof_core::selection::Selection) -> Opts {
        Opts {
            inet: sel.inet_only(),
            file_struct: sel.file_struct,
        }
    }
}

/// A kernel address as wide as the C's `KA_T`, a `u_long` (`dlsof.h`): on
/// i386 the 64-bit `kvaddr_t` is cut to its low half, as the C's cast cuts
/// it.
fn ka(addr: u64) -> u64 {
    if cfg!(target_pointer_width = "32") {
        addr & 0xffff_ffff
    } else {
        addr
    }
}

/// `kf_flags_to_fflags()` (`dproc.c:137-158`): a `kinfo_file`'s flags as the
/// `struct file` flags they stand for.
pub fn kf_flags_to_fflags(kf_flags: i32) -> u32 {
    KF_TO_FFLAGS
        .iter()
        .filter(|(kf, _)| kf_flags & kf != 0)
        .fold(0, |f, (_, ff)| f | ff)
}

/// A numbered descriptor's file structure, as `process_kinfo_file()` sets
/// it (`dproc.c:177-189`) and `process_vnode()` amends it (`dnode.c:338-343`):
/// the count from the record, always; the address and node from `kern.file`,
/// where it lists the descriptor, the node a vnode's for a vnode or a FIFO.
pub fn file_struct(k: &KFile, xfile: Option<XFile>) -> FileStruct {
    let vnode = matches!(k.kind(), kf::TYPE_VNODE | kf::TYPE_FIFO);
    FileStruct {
        count: Some(i64::from(k.ref_count())),
        addr: xfile.map(|x| ka(x.file)),
        node: xfile.map(|x| ka(if vnode { x.vnode } else { x.data })),
    }
}

/// The listing's entries from the process table's records, as
/// `gather_proc_info()` makes them (`dproc.c:432-477`) and `main()` orders
/// them (`comppid()`): a record with no state, or a zombie's, is passed by;
/// each of the rest is an entry, a process from `kern.proc.proc`, or under
/// `-K` (`tasks`) one thread from `kern.proc.all`, its TID the record's
/// `ki_tid` (`tid = Ftask ? (int)p->ki_tid : 0`, `:443`), so that every
/// thread of every process is a task, a single-threaded process's one
/// thread included. The dialect never sets a task's own command
/// (`Lp->tcmd`): there is no TASKCMD. In PID order, a process's threads in
/// TID order; a second record of one entry is not kept.
pub fn entries(kprocs: Vec<KProc>, tasks: bool) -> Vec<Process> {
    let mut procs: Vec<Process> = kprocs
        .into_iter()
        .filter(|k| k.stat != 0 && k.stat != SZOMB)
        .filter_map(|k| {
            Some(Process {
                pid: u32::try_from(k.pid).ok()?,
                ppid: u32::try_from(k.ppid).ok(),
                command: String::from_utf8_lossy(&k.comm).into_owned(),
                // Asked as it is printed (`Backend::login_name`).
                user: None,
                // `if (Lp->tid)`: a TID of 0 is no task's.
                tid: u32::try_from(k.tid).ok().filter(|&t| tasks && t != 0),
                task_command: None,
                uid: Some(k.uid),
                pgid: u32::try_from(k.pgid).ok(),
                files: Vec::new().into(),
                endpoint_peer: false,
                unlisted: false,
                raw_names: None,
                file_structs: None,
            })
        })
        .collect();
    procs.sort_by_key(|p| (p.pid, p.tid));
    procs.dedup_by_key(|p| (p.pid, p.tid));
    procs
}

/// `process_file_descriptors()`'s first pass (`dproc.c:238-244`): before any
/// row of a process is made, the file system of each of its vnodes is looked
/// up, a special's whatever its kind, "as files w/o paths may need it from
/// other files with paths on the same fs". So a file with no path is named
/// by its file system when a later record of the same process has a path on
/// it, where the rows alone, made in order, would not have found it yet.
pub fn precache_vfs(files: &[KFile], env: &dyn Env) {
    for k in files {
        if k.fd() < 0 || matches!(k.kind(), kf::TYPE_FIFO | kf::TYPE_VNODE) {
            let _ = env.vfs(k.file_fsid(), k.path());
        }
    }
}

fn blank(fd: FdType) -> OpenFile {
    OpenFile {
        fd,
        access: AccessMode::Unknown,
        file_type: FileType::NoType,
        name: String::new(),
        device: None,
        size: None,
        offset: None,
        node: None,
        links: None,
        lock: None,
        fs_device: None,
        rdev: None,
        file_flags: None,
        socket: None,
        name_addition: None,
    }
}

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// The row of a special: `cwd`, `rtd`, `jld`, `txt` or `ctty`. The C hands
/// each to `process_vnode()` alone: no access letter, no offset.
pub fn special(k: &KFile, fd: FdType, pid: i32, env: &dyn Env) -> OpenFile {
    let mut f = blank(fd);
    vnode(&mut f, k, pid, env);
    f
}

/// The row of a numbered descriptor (`process_kinfo_file()`).
pub fn numbered(k: &KFile, pid: i32, env: &dyn Env, opts: Opts) -> OpenFile {
    let fd = u64::try_from(k.fd()).unwrap_or(0);
    let mut f = blank(FdType::Handle(fd));
    // Read once, where a row needs it: the C reads the whole list up front.
    let xfile = std::cell::OnceCell::new();
    let xfile = || *xfile.get_or_init(|| env.xfile(pid, k.fd()));
    // `Lf->ffg`, set for every numbered descriptor: `xf_flag`, or the
    // record's flags in their place.
    if opts.file_struct {
        f.file_flags = Some(xfile().map_or_else(|| kf_flags_to_fflags(k.flags()), |x| x.flag));
    }
    // `Lf->off = kf->kf_offset; Lf->off_def = 1`, for every descriptor; a
    // row that has a size shows that instead (the renderer's rule).
    f.offset = Some(k.offset() as u64);
    if k.ref_count() != 0 {
        f.access = match k.flags() & (kf::FLAG_READ | kf::FLAG_WRITE) {
            kf::FLAG_READ => AccessMode::Read,
            kf::FLAG_WRITE => AccessMode::Write,
            x if x == kf::FLAG_READ | kf::FLAG_WRITE => AccessMode::ReadWrite,
            _ => AccessMode::Unknown,
        };
    }
    match k.kind() {
        kf::TYPE_FIFO | kf::TYPE_VNODE => vnode(&mut f, k, pid, env),
        kf::TYPE_SOCKET => socket(&mut f, k, env),
        kf::TYPE_KQUEUE => {
            // `process_kf_kqueue()`, the 14.0 form: the count and state are
            // in the record. Its DEVICE is `xf_data` from `kern.file`, and
            // `0x00000000` where that lists no such descriptor
            // (`dproc.c:200`, DIVERGENCES 145).
            f.file_type = FileType::Other("KQUEUE".into());
            f.device = Some(kptr(xfile().map_or(0, |x| x.data)));
            f.name = format!(
                "count={}, state={}",
                k.kq_count(),
                alt_hex(k.kq_state() as u32)
            );
        }
        kf::TYPE_PIPE => {
            if !opts.inet {
                pipe(&mut f, k);
            }
        }
        kf::TYPE_PTS => pts(&mut f, k, env),
        kf::TYPE_EVENTFD => {
            f.file_type = FileType::Other("EVENTFD".into());
            f.device = Some(kptr(k.efd_addr()));
            // `"value=%ju, flags=0x%x"`: a literal `0x`, so zero is `0x0`.
            f.name = format!("value={}, flags=0x{:x}", k.efd_value(), k.efd_flags());
        }
        kf::TYPE_SHM => {
            // `process_shm()`: a size, and no offset.
            f.file_type = FileType::Other("SHM".into());
            f.size = Some(k.file_size());
            f.offset = None;
            if k.file_fileid() != VNOVAL {
                f.node = Some(k.file_fileid().to_string());
            }
            f.name = lossy(k.path());
        }
        kf::TYPE_PROCDESC => {
            f.file_type = FileType::Other("PROCDSC".into());
            f.name = lossy(k.path());
            f.add_name_addition(&format!("pid={}", k.proc_pid()));
        }
        other => {
            // No type the dialect decodes: the C names the `struct file`.
            let addr = xfile().map_or(0, |x| x.file);
            f.name = format!("{} file struct, ty={other}", ptr(addr));
        }
    }
    f
}

/// What `process_vnode()` makes of the file system a vnode is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ntype {
    Reglr,
    Nfs,
    Proc,
    Pseu,
    Tmp,
    Fifo,
}

fn vnode(f: &mut OpenFile, k: &KFile, pid: i32, env: &dyn Env) {
    let vtype = k.vnode_type();
    let mut fsid = k.file_fsid();
    let mut path = k.path().to_vec();
    let mut overlaid = 0u32;
    let (vfs, ntype) = loop {
        // `process_overlaid_node:`, at most 1024 times.
        overlaid += 1;
        if overlaid > 1024 {
            f.name = "too many overlaid nodes".into();
            return;
        }
        let vfs = env.vfs(fsid, &path);
        let mut ntype = Ntype::Reglr;
        if let Some(v) = &vfs {
            fsid = v.fsid;
            let t = &v.typnm[..];
            ntype = if t.eq_ignore_ascii_case(b"nfs") {
                Ntype::Nfs
            } else if t.eq_ignore_ascii_case(b"procfs") {
                Ntype::Proc
            } else if t.eq_ignore_ascii_case(b"pseudofs") {
                Ntype::Pseu
            } else if t.eq_ignore_ascii_case(b"tmpfs") {
                Ntype::Tmp
            } else {
                Ntype::Reglr
            };
        }
        if ntype == Ntype::Reglr && vtype == kf::VTYPE_VFIFO {
            ntype = Ntype::Fifo;
        }
        f.lock = env.lock(pid, k.file_fsid(), k.file_fileid());
        match &vfs {
            Some(v) if v.typnm == b"null" || v.typnm == b"nullfs" => {
                // A nullfs node: name the mount once, in an addition, then
                // look again at the same path on the layer beneath.
                if overlaid == 1 {
                    let dp = (v.fsid != VNOVAL).then(|| dev_string(v.fsid));
                    let mut t = String::from("(nullfs ");
                    t.push_str(&lossy(&v.fsname));
                    t.push_str(" on ");
                    t.push_str(&lossy(&v.dir));
                    if let Some(dp) = dp {
                        t.push_str(&format!(" ({dp})"));
                    }
                    t.push(')');
                    f.add_name_addition(&t);
                }
                fsid = VNOVAL;
                if path.len() >= v.dir.len() {
                    let mut lower = v.fsname.clone();
                    lower.extend_from_slice(&path[v.dir.len()..]);
                    path = lower;
                }
            }
            _ => break (vfs, ntype),
        }
    };
    let dev = (fsid != VNOVAL).then_some(fsid);
    if let (Ntype::Nfs, Some(dev)) = (ntype, dev) {
        env.nfs_file(dev);
    }
    let rdev = matches!(vtype, kf::VTYPE_VCHR | kf::VTYPE_VBLK).then(|| k.file_rdev());
    let mut inode = (k.file_fileid() != VNOVAL).then(|| k.file_fileid());
    // `find_ch_ino()` (`dnode.c:580`, `lib/fino.c:97`): a character device
    // on `/dev`'s file system with no inode takes the one `/dev` gives it.
    if inode.is_none() && vtype == kf::VTYPE_VCHR && dev.is_some() && dev == env.dev_dev() {
        inode = rdev.and_then(|r| env.dev_inode(r));
    }
    f.node = inode.map(|i| i.to_string());
    let size = k.file_size();
    f.size = match ntype {
        Ntype::Fifo => None,
        Ntype::Proc | Ntype::Nfs => Some(size),
        Ntype::Pseu => Some(0),
        Ntype::Reglr | Ntype::Tmp => {
            matches!(vtype, kf::VTYPE_VREG | kf::VTYPE_VDIR).then_some(size)
        }
    };
    f.links = u32::try_from(k.file_nlink()).ok();
    f.fs_device = dev;
    f.rdev = rdev
        .and_then(|r| u32::try_from(r).ok())
        .and_then(NonZeroU32::new);
    f.device = rdev.or(dev).map(dev_string);
    let mut device_node = false;
    f.file_type = match vtype {
        kf::VTYPE_VNON => FileType::Other("VNON".into()),
        kf::VTYPE_VREG => FileType::Other("VREG".into()),
        kf::VTYPE_VDIR => FileType::Other("VDIR".into()),
        kf::VTYPE_VBLK => {
            device_node = true;
            FileType::Other("VBLK".into())
        }
        kf::VTYPE_VCHR => {
            device_node = true;
            FileType::Other("VCHR".into())
        }
        kf::VTYPE_VLNK => FileType::Other("VLNK".into()),
        kf::VTYPE_VSOCK => FileType::Other("SOCK".into()),
        kf::VTYPE_VBAD => FileType::Other("VBAD".into()),
        kf::VTYPE_VFIFO => FileType::Other("FIFO".into()),
        n => FileType::Other(format!("{:04o}", (n as u32) & 0xfff)),
    };
    let mut name = None;
    if vtype == kf::VTYPE_VBAD {
        name = Some("(revoked)".to_string());
    } else if ntype == Ntype::Proc {
        f.file_type = proc_type(&path);
    }
    // NAME is the path and its file system's name (`dnode.c:638-646`), the
    // C's `Lf->nm`. A row with no path has none, and is named as
    // `printname()` names it (`print.c:1448-1592`): a device by its name in
    // `/dev`, then the file system's directory and name. That text is only
    // printed — JSON's `name`, `Lf->nm`, has none (`print.c:1990`).
    let mut like = None;
    match name {
        Some(n) => f.set_base_name(&n),
        None if !k.path().is_empty() => {
            let mut n = lossy(k.path());
            if let Some(v) = &vfs {
                n.push_str(" (");
                n.push_str(&lossy(&v.fsname));
                n.push(')');
            }
            f.set_base_name(&n);
        }
        None => {
            let named = match rdev.filter(|_| device_node && dev.is_some()) {
                Some(r) => device_name(r, dev, inode, vtype == kf::VTYPE_VBLK, env, &mut like),
                None => None,
            };
            let shown = named.unwrap_or_else(|| match &vfs {
                Some(v) => format!("{} ({})", lossy(&v.dir), lossy(&v.fsname)),
                None => String::new(),
            });
            f.set_shown_name(&shown);
        }
    }
    if let Some(like) = like {
        f.add_name_addition(&like);
    }
}

/// `printdevname()` (`lib/pdvn.c:64-166`) of a row whose file system is `dev`
/// and whose device is `rdev`: the name `/dev` gives the device, where the
/// row is on `/dev`'s file system and the entry has the row's inode; else,
/// where `/dev` names the device at all, `(like character special NAME)` in
/// `like` (block for a block special), and no name. The C's FreeBSD table
/// holds character devices alone (no `HASBLKDEV`), and both lookups are in
/// it.
fn device_name(
    rdev: u64,
    dev: Option<u64>,
    inode: Option<u64>,
    block: bool,
    env: &dyn Env,
    like: &mut Option<String>,
) -> Option<String> {
    if dev.is_some() && dev == env.dev_dev() {
        if let Some(n) = env.dev_name(rdev, inode) {
            return Some(n);
        }
    }
    if let Some(n) = env.dev_name(rdev, None) {
        let what = if block { "block" } else { "character" };
        *like = Some(format!("(like {what} special {n})"));
    }
    None
}

/// `parse_proc_path()`: what a file in procfs is, by its last component.
fn proc_type(path: &[u8]) -> FileType {
    let Some(slash) = path.iter().rposition(|&b| b == b'/') else {
        return FileType::NoType;
    };
    let code = match &path[slash + 1..] {
        b"cmdline" | b"dbregs" | b"osrel" | b"rlimit" => return FileType::NoType,
        b"etype" => "PETY",
        b"file" => "PFIL",
        b"fpregs" => "PFPR",
        b"map" => "PMAP",
        b"mem" => "PMEM",
        b"note" => "PNTF",
        b"notepg" => "PGID",
        b"regs" => "PREG",
        b"status" => "PSTA",
        _ => "PDIR",
    };
    FileType::Other(code.into())
}

/// `process_pipe()`, the 14.0 form.
fn pipe(f: &mut OpenFile, k: &KFile) {
    f.file_type = FileType::Pipe;
    f.device = Some(kptr(k.pipe_addr()));
    f.size = Some(u64::from(k.pipe_size()));
    let mut n = String::new();
    if k.pipe_peer() != 0 {
        n.push_str("->");
        n.push_str(&kptr(k.pipe_peer()));
    }
    for (what, v) in [
        ("cnt", k.pipe_cnt()),
        ("in", k.pipe_in()),
        ("out", k.pipe_out()),
    ] {
        if v != 0 {
            n.push_str(&format!(", {what}={}", v as i32));
        }
    }
    f.name = n;
}

/// `process_pts()`: a character device on `/dev`'s file system whose inode
/// and device are both the terminal's number; named from `/dev`.
fn pts(f: &mut OpenFile, k: &KFile, env: &dyn Env) {
    let d = k.pts_dev();
    f.file_type = FileType::Other("PTS".into());
    f.fs_device = env.dev_dev();
    f.node = Some(d.to_string());
    f.rdev = u32::try_from(d).ok().and_then(NonZeroU32::new);
    f.device = Some(dev_string(d));
    env.pts_seen();
    // `printdevname()` of a row the dialect names nothing (`print.c:1448`):
    // the inode it has is the terminal's number.
    // That name is only printed: the C's `Lf->nm` stays empty
    // (`dnode.c:747-750`), so JSON's `name` has none.
    if f.fs_device.is_some() {
        let mut like = None;
        if let Some(n) = device_name(d, f.fs_device, Some(d), false, env, &mut like) {
            f.set_shown_name(&n);
        } else if let Some(like) = like {
            f.add_name_addition(&like);
        }
    }
}

/// The ends `process_socket()` enters for an Internet socket it found a PCB
/// for (`dsock.c:452-557`), local and foreign, as the C built by the
/// system's compiler runs (measured on FreeBSD 14.5, clang 21.1.8 `-O2`;
/// DIVERGENCES 180):
///
/// * the local end, always: `la` is the record's address, whatever it holds;
/// * an IPv4 socket's foreign end, always too. The source tests it
///   (`:532-536`: not `INADDR_ANY`, or a port), but the branch not taken
///   leaves `fp` uninitialised where `ent_inaddr()` is then handed it, and
///   the compiler keeps the taken branch alone: the binary has no test;
/// * an IPv6 socket's foreign end unless its address is `::` and its port 0
///   (`:486-490`, which the binary does test);
/// * and where an IPv6 socket's local end, or its foreign one if entered, is
///   an IPv4 address mapped in IPv6, each end entered is read as IPv4, its
///   last four bytes whatever the rest (`IPv6_2_IPv4()`, `:539-551`).
///
/// A sockaddr the record is too short to hold reads as zeros, as every field
/// past a record's end does.
fn entered_ends(sa_local: &[u8], sa_peer: &[u8], domain: i32) -> [Option<SocketAddr>; 2] {
    let zero = || {
        let ip = if domain == sock::AF_INET {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        };
        SocketAddr::new(ip, 0)
    };
    let local = inet_addr(sa_local, domain).unwrap_or_else(zero);
    let peer = inet_addr(sa_peer, domain).unwrap_or_else(zero);
    let entered = domain == sock::AF_INET || !peer.ip().is_unspecified() || peer.port() != 0;
    let remote = entered.then_some(peer);
    let mapped = |a: &SocketAddr| matches!(a.ip(), IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some());
    if !(mapped(&local) || remote.as_ref().is_some_and(mapped)) {
        return [Some(local), remote];
    }
    let v4 = |a: SocketAddr| match a.ip() {
        IpAddr::V6(v6) => {
            let o = v6.octets();
            SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(o[12], o[13], o[14], o[15])),
                a.port(),
            )
        }
        IpAddr::V4(_) => a,
    };
    [Some(v4(local)), remote.map(v4)]
}

/// `IPPROTO_TCP`.
const IPPROTO_TCP: i32 = 6;

/// `process_socket()`.
fn socket(f: &mut OpenFile, k: &KFile, env: &dyn Env) {
    f.file_type = FileType::Socket("sock");
    let domain = k.sock_domain();
    let pcb = env.pcb(domain, k.sock_type(), k.sock_pcb());
    // The size is the queue the access reads from, or both.
    let (rq, sq) = (u64::from(k.sock_recvq()), u64::from(k.sock_sendq()));
    f.size = Some(match f.access {
        AccessMode::Read => rq,
        AccessMode::Write => sq,
        _ => rq + sq,
    });
    // `Lf->lts`: the queues, which every socket has (`HAS_KF_SOCK_SENDQ`),
    // the `xsocket`'s fields where the pcblists hold the socket, and the
    // buffer states from the record (`dsock.c:404-430`). A TCP socket whose
    // `xtcpcb` was found adds its flags and maximum segment and is the C's
    // TCP/TPI record (`lts.type = 0`, `:558-572`).
    let tcp_found = matches!(domain, sock::AF_INET | sock::AF_INET6)
        && k.sock_protocol() == IPPROTO_TCP
        && pcb.is_some();
    let tcp = Some(TcpExtInfo {
        recv_window: None,
        recv_queue: Some(rq),
        send_queue: Some(sq),
        bsd: Some(BsdSocket {
            record: tcp_found,
            xsocket: pcb.map(|p| p.xsocket),
            sbs_rcv: k.sock_rcv_sb_state(),
            sbs_snd: k.sock_snd_sb_state(),
            tcp: pcb.and_then(|p| p.tcp).filter(|_| tcp_found),
        }),
    });
    match domain {
        sock::AF_INET | sock::AF_INET6 => {
            let protocol = iproto(k.sock_protocol());
            f.file_type = if domain == sock::AF_INET {
                FileType::Ipv4
            } else {
                FileType::Ipv6
            };
            f.node = Some(protocol.as_str().to_string());
            let mut info = SocketInfo {
                protocol,
                local: None,
                remote: None,
                state: None,
                tcp,
                bound: None,
            };
            let Some(pcb) = pcb else {
                f.name = if domain == sock::AF_INET6 {
                    format!("can't read in6pcb at {}", kptr(k.sock_pcb()))
                } else {
                    let mut n = String::from("no PCB");
                    if k.sock_snd_sb_state() & sock::SBS_CANTSENDMORE != 0 {
                        n.push_str(", CANTSENDMORE");
                    }
                    if k.sock_rcv_sb_state() & sock::SBS_CANTRCVMORE != 0 {
                        n.push_str(", CANTRCVMORE");
                    }
                    n
                };
                f.socket = Some(Box::new(info));
                return;
            };
            f.device = Some(kptr(k.sock_pcb()));
            [info.local, info.remote] = entered_ends(k.sa_local(), k.sa_peer(), domain);
            if protocol == Protocol::Tcp {
                info.state = pcb.t_state.and_then(tcp_state).map(SockState::Tcp);
            }
            // `printinaddr()`'s text of the ends entered (`print.c`), with
            // no name looked up: `*` for an unspecified host and for port 0.
            f.name = lsof_core::sockname::SocketNames::numeric(&info);
            f.socket = Some(Box::new(info));
        }
        sock::AF_ROUTE => {
            // The pcblists hold no routing socket, so the C never has the
            // `xsocket` this branch asks for. Its queues it has, as every
            // socket's are set before the family is looked at
            // (`dsock.c:404-407`): `-T q` shows them (DIVERGENCES 147).
            f.file_type = FileType::Socket("rte");
            f.name = "no protocol control block".into();
            f.socket = Some(Box::new(queues_only(Protocol::Other("rte"), tcp)));
        }
        sock::AF_UNIX => {
            f.file_type = FileType::Unix;
            f.socket = Some(Box::new(SocketInfo {
                protocol: Protocol::Other("unix"),
                local: None,
                remote: None,
                state: None,
                tcp,
                bound: None,
            }));
            let Some(pcb) = pcb else {
                f.name = format!("can't read unpcb at {}", kptr(k.sock_pcb()));
                return;
            };
            f.device = Some(kptr(pcb.so));
            let path = unix_path(k.sa_local());
            f.name = if !path.is_empty() {
                let p = lossy(path);
                if let Some(s) = f.socket.as_deref_mut() {
                    s.bound = Some(Box::new(lsof_core::BoundPath {
                        path: std::str::from_utf8(path).ok().map(str::to_string),
                        id: None,
                    }));
                }
                p
            } else if k.sock_unpconn() != 0 {
                match env.pcb(domain, k.sock_type(), k.sock_unpconn()) {
                    Some(peer) => format!("->{}", kptr(peer.so)),
                    None => format!("can't read unp_conn at {}", kptr(k.sock_unpconn())),
                }
            } else {
                "->(none)".into()
            };
        }
        fam => {
            f.name = unknown_family(fam);
            f.socket = Some(Box::new(queues_only(Protocol::Other("sock"), tcp)));
        }
    }
}

/// A socket the C knows nothing of but its record's: no address or state,
/// only `Lf->lts`'s queues and buffer states, which it sets for every socket.
fn queues_only(protocol: Protocol, tcp: Option<TcpExtInfo>) -> SocketInfo {
    SocketInfo {
        protocol,
        local: None,
        remote: None,
        state: None,
        tcp,
        bound: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kinfo::tests::{kf_rec, put};
    use std::collections::HashMap;

    #[derive(Default)]
    struct Fake {
        vfs: Vec<(Vec<u8>, Vfs)>,
        locks: HashMap<(i32, u64, u64), LockKind>,
        pcbs: HashMap<u64, Pcb>,
        devs: HashMap<u64, String>,
        xfiles: HashMap<(i32, i32), XFile>,
        pts_seen: std::cell::Cell<bool>,
        nfs: std::cell::RefCell<Vec<u64>>,
    }

    impl Env for Fake {
        fn vfs(&self, fsid: u64, path: &[u8]) -> Option<Vfs> {
            if fsid != VNOVAL {
                if let Some((_, v)) = self.vfs.iter().find(|(_, v)| v.fsid == fsid) {
                    return Some(v.clone());
                }
            }
            self.vfs
                .iter()
                .filter(|(dir, _)| path.starts_with(dir))
                .max_by_key(|(dir, _)| dir.len())
                .map(|(_, v)| Vfs { fsid, ..v.clone() })
        }
        fn lock(&self, pid: i32, fsid: u64, fileid: u64) -> Option<LockKind> {
            self.locks.get(&(pid, fsid, fileid)).copied()
        }
        fn pcb(&self, _d: i32, _t: i32, pcb: u64) -> Option<Pcb> {
            self.pcbs.get(&pcb).copied()
        }
        fn dev_name(&self, rdev: u64, _inode: Option<u64>) -> Option<String> {
            self.devs.get(&rdev).cloned()
        }
        fn dev_inode(&self, rdev: u64) -> Option<u64> {
            self.devs.contains_key(&rdev).then_some(rdev)
        }
        fn dev_dev(&self) -> Option<u64> {
            Some(0x5a)
        }
        fn pts_seen(&self) {
            self.pts_seen.set(true);
        }
        fn xfile(&self, pid: i32, fd: i32) -> Option<XFile> {
            self.xfiles.get(&(pid, fd)).copied()
        }
        fn nfs_file(&self, dev: u64) {
            self.nfs.borrow_mut().push(dev);
        }
    }

    fn root_fs() -> Fake {
        Fake {
            vfs: vec![(
                b"/".to_vec(),
                Vfs {
                    dir: b"/".to_vec(),
                    fsname: b"zroot/ROOT/default".to_vec(),
                    typnm: b"zfs".to_vec(),
                    fsid: 0x5a00_ff01,
                },
            )],
            ..Fake::default()
        }
    }

    fn vnode_rec(fd: i32, vtype: i32, path: &[u8]) -> Vec<u8> {
        let mut r = kf_rec(kf::TYPE_VNODE, fd, path);
        put(&mut r, kf::VNODE_TYPE, &vtype.to_ne_bytes());
        put(&mut r, kf::FILE_FSID, &0x5a00_ff01u64.to_ne_bytes());
        put(&mut r, kf::FILE_FILEID, &1234u64.to_ne_bytes());
        put(&mut r, kf::FILE_SIZE, &4096u64.to_ne_bytes());
        put(&mut r, kf::FILE_NLINK, &2u64.to_ne_bytes());
        r
    }

    #[test]
    fn a_regular_file_is_vreg_named_with_its_file_system() {
        let env = root_fs();
        let mut r = vnode_rec(3, kf::VTYPE_VREG, b"/etc/motd");
        put(&mut r, kf::REF_COUNT, &1i32.to_ne_bytes());
        put(&mut r, kf::FLAGS, &kf::FLAG_READ.to_ne_bytes());
        let f = numbered(&KFile::from_bytes(&r), 7, &env, Opts::default());
        assert_eq!(f.file_type.code(), "VREG");
        assert_eq!(f.access, AccessMode::Read);
        assert_eq!(f.name, "/etc/motd (zroot/ROOT/default)");
        assert_eq!(f.device.as_deref(), Some("255,1509949441"));
        assert_eq!(
            (f.size, f.node.as_deref(), f.links, f.fs_device),
            (Some(4096), Some("1234"), Some(2), Some(0x5a00_ff01))
        );
        assert_eq!(f.offset, Some(0));
    }

    #[test]
    fn a_special_has_no_access_and_no_offset() {
        let env = root_fs();
        let r = vnode_rec(kf::FD_CWD, kf::VTYPE_VDIR, b"/home/u");
        let f = special(&KFile::from_bytes(&r), FdType::Cwd, 7, &env);
        assert_eq!(f.file_type.code(), "VDIR");
        assert_eq!((f.access, f.offset), (AccessMode::Unknown, None));
        assert_eq!(f.size, Some(4096));
    }

    #[test]
    fn a_device_node_is_named_from_dev_and_shows_the_device_it_names() {
        let mut env = root_fs();
        env.devs.insert(0x1f, "/dev/null".into());
        let mut r = vnode_rec(0, kf::VTYPE_VCHR, b"/dev/null");
        put(&mut r, kf::FILE_RDEV, &0x1fu64.to_ne_bytes());
        let f = numbered(&KFile::from_bytes(&r), 7, &env, Opts::default());
        assert_eq!(f.file_type.code(), "VCHR");
        // A path is the NAME, as for any vnode (`dnode.c:638`): `/dev` names
        // only a device whose row has none (DIVERGENCES 146).
        assert_eq!(f.name, "/dev/null (zroot/ROOT/default)");
        assert_eq!(f.device.as_deref(), Some("0,31"));
        assert_eq!(f.size, None, "a device has no size, so the offset shows");
        assert_eq!(f.rdev.map(NonZeroU32::get), Some(0x1f));
        // No path, on `/dev`'s file system: the name `/dev` gives it.
        let mut env = root_fs();
        env.devs.insert(0x1f, "/dev/null".into());
        env.vfs[0].1.fsid = 0x5a;
        let mut r = vnode_rec(0, kf::VTYPE_VCHR, b"");
        put(&mut r, kf::FILE_FSID, &0x5au64.to_ne_bytes());
        put(&mut r, kf::FILE_RDEV, &0x1fu64.to_ne_bytes());
        let f = numbered(&KFile::from_bytes(&r), 7, &env, Opts::default());
        assert_eq!(f.name, "/dev/null");
        assert_eq!(f.base_name(), None, "printed, not Lf->nm");
        assert!(
            !env.pts_seen.get(),
            "only a terminal makes the table unsafe"
        );
        // On another file system: the file system, and what `/dev` calls
        // the device in an addition.
        let mut other = r.clone();
        put(&mut other, kf::FILE_FSID, &0x5a00_ff01u64.to_ne_bytes());
        let mut env = root_fs();
        env.devs.insert(0x1f, "/dev/null".into());
        let f = numbered(&KFile::from_bytes(&other), 7, &env, Opts::default());
        assert_eq!(
            f.name,
            "/ (zroot/ROOT/default) (like character special /dev/null)"
        );
        // Printed, not the C's `Lf->nm`: JSON's `name` has none
        // (`print.c:1990`), and a path argument's name replaces the text,
        // keeping the addition, as the C prints `Lf->nm` and its `nma`.
        assert_eq!(f.base_name(), None);
        let mut renamed = f.clone();
        renamed.set_base_name("/arg");
        assert_eq!(renamed.name, "/arg (like character special /dev/null)");
        assert_eq!(renamed.base_name(), Some("/arg"));
        // A device `/dev` does not name, and a file with no path: the file
        // system alone.
        env.devs.clear();
        let f = numbered(&KFile::from_bytes(&other), 7, &env, Opts::default());
        assert_eq!(f.name, "/ (zroot/ROOT/default)");
        assert_eq!(f.base_name(), None);
        let plain = vnode_rec(0, kf::VTYPE_VREG, b"");
        let f = numbered(&KFile::from_bytes(&plain), 7, &env, Opts::default());
        assert_eq!(f.name, "/ (zroot/ROOT/default)");
    }

    /// `find_ch_ino()`: a character device on `/dev`'s file system with no
    /// inode of its own takes the one `/dev` gives it; elsewhere none.
    #[test]
    fn a_character_device_with_no_inode_takes_devs() {
        let mut env = root_fs();
        env.devs.insert(0x1f, "/dev/null".into());
        let mut r = vnode_rec(0, kf::VTYPE_VCHR, b"/dev/null");
        put(&mut r, kf::FILE_FILEID, &VNOVAL.to_ne_bytes());
        put(&mut r, kf::FILE_RDEV, &0x1fu64.to_ne_bytes());
        put(&mut r, kf::FILE_FSID, &0x5au64.to_ne_bytes());
        let f = numbered(&KFile::from_bytes(&r), 7, &env, Opts::default());
        assert_eq!(f.node.as_deref(), Some("31"));
        put(&mut r, kf::FILE_FSID, &0x77u64.to_ne_bytes());
        let f = numbered(&KFile::from_bytes(&r), 7, &env, Opts::default());
        assert_eq!(f.node, None);
    }

    #[test]
    fn a_lock_is_found_by_pid_fsid_and_fileid() {
        let mut env = root_fs();
        env.locks
            .insert((7, 0x5a00_ff01, 1234), LockKind::WriteFull);
        let r = vnode_rec(4, kf::VTYPE_VREG, b"/var/db/x");
        let f = numbered(&KFile::from_bytes(&r), 7, &env, Opts::default());
        assert_eq!(f.lock, Some(LockKind::WriteFull));
        let g = numbered(&KFile::from_bytes(&r), 8, &env, Opts::default());
        assert_eq!(g.lock, None);
    }

    #[test]
    fn a_nullfs_file_is_named_through_the_lower_layer() {
        let mut env = root_fs();
        env.vfs.push((
            b"/jail/usr".to_vec(),
            Vfs {
                dir: b"/jail/usr".to_vec(),
                fsname: b"/usr".to_vec(),
                typnm: b"nullfs".to_vec(),
                fsid: 0x77,
            },
        ));
        let mut r = vnode_rec(5, kf::VTYPE_VREG, b"/jail/usr/bin/sh");
        put(&mut r, kf::FILE_FSID, &0x77u64.to_ne_bytes());
        let f = numbered(&KFile::from_bytes(&r), 7, &env, Opts::default());
        // The lower layer is found by path, with no fsid: no DEVICE.
        assert_eq!(f.device, None);
        assert_eq!(
            f.name,
            "/jail/usr/bin/sh (zroot/ROOT/default) (nullfs /usr on /jail/usr (0,119))"
        );
        assert_eq!(f.base_name(), Some("/jail/usr/bin/sh (zroot/ROOT/default)"));
    }

    #[test]
    fn a_revoked_vnode_and_a_procfs_file_are_named_as_the_c_names_them() {
        let env = root_fs();
        let r = vnode_rec(6, kf::VTYPE_VBAD, b"/dev/ttyv0");
        assert_eq!(
            numbered(&KFile::from_bytes(&r), 1, &env, Opts::default()).name,
            "(revoked)"
        );
        let mut env = root_fs();
        env.vfs.push((
            b"/proc".to_vec(),
            Vfs {
                dir: b"/proc".to_vec(),
                fsname: b"procfs".to_vec(),
                typnm: b"procfs".to_vec(),
                fsid: 0x99,
            },
        ));
        for (p, code) in [
            (&b"/proc/1/status"[..], "PSTA"),
            (b"/proc/1", "PDIR"),
            (b"/proc/1/cmdline", "0000"),
        ] {
            let mut r = vnode_rec(6, kf::VTYPE_VREG, p);
            put(&mut r, kf::FILE_FSID, &0x99u64.to_ne_bytes());
            let f = numbered(&KFile::from_bytes(&r), 1, &env, Opts::default());
            assert_eq!(f.file_type.code(), code, "{p:?}");
        }
    }

    fn kproc(pid: i32, tid: i32, stat: u8, comm: &str) -> KProc {
        KProc {
            pid,
            ppid: 1,
            pgid: pid,
            uid: 1001,
            stat,
            comm: comm.as_bytes().to_vec(),
            tid,
        }
    }

    /// Measured on FreeBSD 14.5 with a four-thread process: `-K` lists each
    /// thread as an entry with its TID (`threads 1647 100152 …`, `… 102740
    /// …`), in PID then TID order, a single-threaded process's one thread
    /// too (`sleep 6883 100101`), and no entry has a task command. Without
    /// `-K` a process is one entry and has no TID, whatever `ki_tid` holds.
    #[test]
    fn under_dash_k_every_thread_is_an_entry_in_pid_and_tid_order() {
        let table = || {
            vec![
                kproc(1647, 102_741, 2, "threads"),
                kproc(1647, 100_152, 2, "threads"),
                kproc(6883, 100_101, 2, "sleep"),
                kproc(1647, 102_740, 2, "threads"),
                // A zombie, a record with no state, a PID that is none.
                kproc(50, 100_050, SZOMB, "gone"),
                kproc(51, 100_051, 0, "new"),
                kproc(-1, 100_052, 2, "bad"),
                // The kernel's process, and a second record of one thread.
                kproc(0, 100_000, 2, "kernel"),
                kproc(1647, 102_740, 2, "threads"),
                // A thread ID of 0 is no task's (`if (Lp->tid)`).
                kproc(77, 0, 2, "odd"),
            ]
        };
        let ids = |p: &[Process]| -> Vec<(u32, Option<u32>)> {
            p.iter().map(|p| (p.pid, p.tid)).collect()
        };
        let tasks = entries(table(), true);
        assert_eq!(
            ids(&tasks),
            [
                (0, Some(100_000)),
                (77, None),
                (1647, Some(100_152)),
                (1647, Some(102_740)),
                (1647, Some(102_741)),
                (6883, Some(100_101)),
            ]
        );
        assert!(tasks.iter().all(|p| p.task_command.is_none()));
        assert_eq!(tasks[2].command, "threads");
        assert_eq!(
            (tasks[2].ppid, tasks[2].pgid, tasks[2].uid),
            (Some(1), Some(1647), Some(1001))
        );
        // No `-K`: a process each, in PID order, and no TID.
        let procs = entries(table(), false);
        assert_eq!(
            ids(&procs),
            [(0, None), (77, None), (1647, None), (6883, None)]
        );
    }

    fn statfs_of(ty: &str, from: &str, on: &str) -> crate::kinfo::StatFs {
        crate::kinfo::StatFs {
            ftype: 1,
            fsid0: 0,
            fstypename: ty.into(),
            mntfrom: from.into(),
            mnton: on.into(),
        }
    }

    /// `readvfs()`: by `fsid` among those found, else by `statfs(path)`, an
    /// entry already listed under the same names being that entry, its
    /// `fsid` with it.
    #[test]
    fn a_file_system_is_found_by_fsid_then_by_path() {
        let calls = std::cell::RefCell::new(Vec::<Vec<u8>>::new());
        let statfs = |path: &[u8]| {
            calls.borrow_mut().push(path.to_vec());
            if path.starts_with(b"/gone") {
                None
            } else if path.starts_with(b"/mnt") {
                Some(statfs_of("a-type-name-of-16", "srv:/x", "/mnt"))
            } else {
                Some(statfs_of("ufs", "/dev/gpt/rootfs", "/"))
            }
        };
        let list = VfsList::default();
        // No path and nothing found yet: none, and nothing asked.
        assert_eq!(list.find(0x3d, b"", &statfs), None);
        assert!(calls.borrow().is_empty());
        // By path: recorded under the `fsid` asked with.
        let root = list.find(0x3d, b"/etc/passwd", &statfs).unwrap();
        assert_eq!(
            (&root.dir[..], &root.fsname[..], &root.typnm[..], root.fsid),
            (&b"/"[..], &b"/dev/gpt/rootfs"[..], &b"ufs"[..], 0x3d)
        );
        assert_eq!(calls.borrow().len(), 1);
        // By `fsid` now, path or none, and no `statfs`.
        assert_eq!(list.find(0x3d, b"", &statfs), Some(root.clone()));
        assert_eq!(list.find(0x3d, b"/bin/sh", &statfs), Some(root.clone()));
        assert_eq!(calls.borrow().len(), 1);
        // With no `fsid` (a nullfs mount's lower layer): by path, and the
        // entry listed under the same names, with the `fsid` it has.
        assert_eq!(list.find(VNOVAL, b"/usr/bin", &statfs), Some(root.clone()));
        assert_eq!(list.find(VNOVAL, b"", &statfs), None);
        // Another `fsid` whose path is on the same file system: that entry
        // too, and its `fsid` is the row's from then on.
        assert_eq!(
            list.find(0x99, b"/var", &statfs).map(|v| v.fsid),
            Some(0x3d)
        );
        // Found first with no `fsid`: listed with none, which a row found by
        // the same names then takes.
        let nfs = list.find(VNOVAL, b"/mnt/f", &statfs).unwrap();
        assert_eq!(nfs.fsid, VNOVAL);
        assert_eq!(nfs.typnm, b"a-type-name-of-", "MFSNAMELEN - 1 bytes");
        assert_eq!(
            list.find(0x77, b"/mnt/g", &statfs).map(|v| v.fsid),
            Some(VNOVAL)
        );
        // A path that cannot be `statfs`ed is on none, and is asked again.
        let before = calls.borrow().len();
        assert_eq!(list.find(0x55, b"/gone/x", &statfs), None);
        assert_eq!(list.find(0x55, b"/gone/x", &statfs), None);
        assert_eq!(calls.borrow().len(), before + 2);
        // No `fsid` and no path finds nothing, though an entry has none.
        assert_eq!(list.find(VNOVAL, b"", &statfs), None);
        // An entry is the one of both names: the same source mounted on
        // another directory, and another source on the same directory, are
        // each their own.
        let mounts = |path: &[u8]| {
            Some(match path {
                b"/a/x" => statfs_of("tmpfs", "tmpfs", "/a"),
                b"/b/x" => statfs_of("tmpfs", "tmpfs", "/b"),
                _ => statfs_of("ufs", "/dev/other", "/a"),
            })
        };
        let list = VfsList::default();
        let fsids = [
            list.find(1, b"/a/x", &mounts).map(|v| v.fsid),
            list.find(2, b"/b/x", &mounts).map(|v| v.fsid),
            list.find(3, b"/a/y", &mounts).map(|v| v.fsid),
        ];
        assert_eq!(fsids, [Some(1), Some(2), Some(3)]);
    }

    /// An [`Env`] over a [`VfsList`] and a table of mounts: what the live
    /// one is, with no system call.
    #[derive(Default)]
    struct Listed {
        list: VfsList,
        nfs: std::cell::RefCell<Vec<u64>>,
    }

    impl Env for Listed {
        fn vfs(&self, fsid: u64, path: &[u8]) -> Option<Vfs> {
            self.list.find(fsid, path, &|path| {
                if path.starts_with(b"/net") {
                    Some(statfs_of("nfs", "srv:/export", "/net"))
                } else {
                    Some(statfs_of("ufs", "/dev/gpt/rootfs", "/"))
                }
            })
        }
        fn lock(&self, _: i32, _: u64, _: u64) -> Option<LockKind> {
            None
        }
        fn pcb(&self, _: i32, _: i32, _: u64) -> Option<Pcb> {
            None
        }
        fn dev_name(&self, _: u64, _: Option<u64>) -> Option<String> {
            None
        }
        fn dev_inode(&self, _: u64) -> Option<u64> {
            None
        }
        fn dev_dev(&self) -> Option<u64> {
            Some(0x5a)
        }
        fn pts_seen(&self) {}
        fn xfile(&self, _: i32, _: i32) -> Option<XFile> {
            None
        }
        fn nfs_file(&self, dev: u64) {
            self.nfs.borrow_mut().push(dev);
        }
    }

    /// `process_file_descriptors()` looks up every vnode's file system
    /// before it makes a row, so a file with no path is named by its file
    /// system when a later record of the process has a path on it. Measured
    /// on FreeBSD 14.5: `sh … 1w VREG 0,61 13877 2249471 / (/dev/gpt/rootfs)`,
    /// a descriptor with no path.
    #[test]
    fn a_file_with_no_path_is_named_by_a_later_files_file_system() {
        let mut nameless = vnode_rec(1, kf::VTYPE_VREG, b"");
        put(&mut nameless, kf::FILE_FSID, &0x3du64.to_ne_bytes());
        let mut named = vnode_rec(3, kf::VTYPE_VREG, b"/etc/passwd");
        put(&mut named, kf::FILE_FSID, &0x3du64.to_ne_bytes());
        let files = [KFile::from_bytes(&nameless), KFile::from_bytes(&named)];
        // The rows alone, in order: the first finds no file system.
        let env = Listed::default();
        let f = numbered(&files[0], 7, &env, Opts::default());
        assert_eq!((f.name.as_str(), f.device.as_deref()), ("", Some("0,61")));
        // After the first pass it is found by its `fsid`.
        let env = Listed::default();
        precache_vfs(&files, &env);
        let f = numbered(&files[0], 7, &env, Opts::default());
        assert_eq!(f.name, "/ (/dev/gpt/rootfs)");
        assert_eq!(f.base_name(), None, "printed, not Lf->nm");
        // The pass is of vnodes, FIFOs and every special; a socket's or a
        // pipe's record has no file system to look up.
        let env = Listed::default();
        let mut sock = sock_rec(sock::AF_INET, sock::SOCK_STREAM, 6, 1);
        put(&mut sock, kf::PATH, b"/x");
        precache_vfs(&[KFile::from_bytes(&sock)], &env);
        assert_eq!(env.list.find(0, b"", &|_| None), None, "nothing was listed");
        let fifo = kf_rec(kf::TYPE_FIFO, 5, b"/tmp/f");
        let vnode = kf_rec(kf::TYPE_VNODE, 6, b"/tmp/v");
        // A special is looked up for its negative number, whatever its kind.
        let cwd = kf_rec(0, kf::FD_CWD, b"/home");
        for rec in [fifo, vnode, cwd] {
            let env = Listed::default();
            precache_vfs(&[KFile::from_bytes(&rec)], &env);
            assert!(env.list.find(0, b"", &|_| None).is_some());
        }
    }

    /// `-N` goes by the file system each vnode is on (`Ntype = N_NFS`): a
    /// row typed so tells its device, and no other row does.
    #[test]
    fn an_nfs_file_tells_its_device() {
        let env = Listed::default();
        let mut on_nfs = vnode_rec(3, kf::VTYPE_VREG, b"/net/f");
        put(
            &mut on_nfs,
            kf::FILE_FSID,
            &0x1234_5678_9abcu64.to_ne_bytes(),
        );
        let f = numbered(&KFile::from_bytes(&on_nfs), 7, &env, Opts::default());
        assert_eq!(f.name, "/net/f (srv:/export)");
        assert_eq!(f.size, Some(4096), "an NFS file's size, whatever its type");
        assert_eq!(*env.nfs.borrow(), [0x1234_5678_9abc]);
        let local = vnode_rec(4, kf::VTYPE_VREG, b"/etc/motd");
        let _ = numbered(&KFile::from_bytes(&local), 7, &env, Opts::default());
        assert_eq!(env.nfs.borrow().len(), 1, "a ufs file is no NFS file");
        // An NFS file with no device (found by path alone) tells none.
        let env = Listed::default();
        let mut nodev = vnode_rec(5, kf::VTYPE_VREG, b"/net/g");
        put(&mut nodev, kf::FILE_FSID, &VNOVAL.to_ne_bytes());
        let f = numbered(&KFile::from_bytes(&nodev), 7, &env, Opts::default());
        assert_eq!((f.device, f.name.as_str()), (None, "/net/g (srv:/export)"));
        assert!(env.nfs.borrow().is_empty());
    }

    fn sock_rec(domain: i32, ty: i32, proto: i32, pcb: u64) -> Vec<u8> {
        let mut r = kf_rec(kf::TYPE_SOCKET, 5, b"");
        put(&mut r, kf::REF_COUNT, &1i32.to_ne_bytes());
        put(
            &mut r,
            kf::FLAGS,
            &(kf::FLAG_READ | kf::FLAG_WRITE).to_ne_bytes(),
        );
        put(&mut r, kf::SOCK_DOMAIN, &domain.to_ne_bytes());
        put(&mut r, kf::SOCK_TYPE, &ty.to_ne_bytes());
        put(&mut r, kf::SOCK_PROTOCOL, &proto.to_ne_bytes());
        put(&mut r, kf::SOCK_PCB, &pcb.to_ne_bytes());
        r
    }

    #[test]
    fn a_listening_tcp_socket_shows_its_pcb_protocol_and_state() {
        let mut env = Fake::default();
        env.pcbs.insert(
            0xffff_f800_aaaa_0000,
            Pcb {
                so: 1,
                t_state: Some(1),
                ..Pcb::default()
            },
        );
        let mut r = sock_rec(sock::AF_INET, sock::SOCK_STREAM, 6, 0xffff_f800_aaaa_0000);
        let mut sa = [0u8; 16];
        sa[0] = 16;
        sa[1] = 2;
        put(&mut sa, 2, &22u16.to_be_bytes());
        put(&mut r, kf::SA_LOCAL, &sa);
        put(&mut r, kf::SOCK_SENDQ, &3u32.to_ne_bytes());
        put(&mut r, kf::SOCK_RECVQ, &4u32.to_ne_bytes());
        let f = numbered(&KFile::from_bytes(&r), 1, &env, Opts::default());
        assert_eq!(f.file_type, FileType::Ipv4);
        assert_eq!(f.node.as_deref(), Some("TCP"));
        // An IPv4 socket's foreign end is entered whatever it holds.
        assert_eq!(f.name, "*:22->*:*");
        assert_eq!(f.size, Some(7), "read and write: both queues");
        let s = f.socket.as_deref().unwrap();
        assert_eq!(s.state.map(SockState::as_str), Some("LISTEN"));
        #[cfg(target_pointer_width = "64")]
        assert_eq!(f.device.as_deref(), Some("0xfffff800aaaa0000"));
        assert!(f.is_internet());
    }

    #[test]
    fn an_inet_socket_without_a_pcb_says_so() {
        let env = Fake::default();
        let mut r = sock_rec(sock::AF_INET, 3, 1, 0x10);
        put(
            &mut r,
            kf::SOCK_SND_SB_STATE,
            &sock::SBS_CANTSENDMORE.to_ne_bytes(),
        );
        let f = numbered(&KFile::from_bytes(&r), 1, &env, Opts::default());
        assert_eq!(f.name, "no PCB, CANTSENDMORE");
        assert_eq!(f.node.as_deref(), Some("ICMP"));
        assert!(f.is_internet(), "still an Internet socket to -i");
        let r6 = sock_rec(sock::AF_INET6, sock::SOCK_DGRAM, 17, 0x10);
        assert_eq!(
            numbered(&KFile::from_bytes(&r6), 1, &env, Opts::default()).name,
            "can't read in6pcb at 0x00000010"
        );
    }

    #[test]
    fn a_v4_mapped_peer_is_printed_as_ipv4() {
        let mut env = Fake::default();
        env.pcbs.insert(
            0x20,
            Pcb {
                so: 2,
                t_state: Some(4),
                ..Pcb::default()
            },
        );
        let mut r = sock_rec(sock::AF_INET6, sock::SOCK_STREAM, 6, 0x20);
        let sa6 = |ip: [u8; 16], port: u16| {
            let mut sa = [0u8; 28];
            sa[0] = 28;
            sa[1] = 28;
            put(&mut sa, 2, &port.to_be_bytes());
            put(&mut sa, 8, &ip);
            sa
        };
        let mut l = [0u8; 16];
        l[10] = 0xff;
        l[11] = 0xff;
        l[12..].copy_from_slice(&[10, 0, 0, 1]);
        let mut p = l;
        p[15] = 2;
        put(&mut r, kf::SA_LOCAL, &sa6(l, 22));
        put(&mut r, kf::SA_PEER, &sa6(p, 50000));
        let f = numbered(&KFile::from_bytes(&r), 1, &env, Opts::default());
        assert_eq!(f.file_type, FileType::Ipv6);
        assert_eq!(f.name, "10.0.0.1:22->10.0.0.2:50000");
    }

    /// A `sockaddr_in` and a `sockaddr_in6` as the kernel fills them.
    fn sa4(ip: [u8; 4], port: u16) -> [u8; 16] {
        let mut sa = [0u8; 16];
        sa[0] = 16;
        sa[1] = 2;
        put(&mut sa, 2, &port.to_be_bytes());
        put(&mut sa, 4, &ip);
        sa
    }

    fn sa6(ip: &str, port: u16) -> [u8; 28] {
        let ip: Ipv6Addr = ip.parse().unwrap();
        let mut sa = [0u8; 28];
        sa[0] = 28;
        sa[1] = 28;
        put(&mut sa, 2, &port.to_be_bytes());
        put(&mut sa, 8, &ip.octets());
        sa
    }

    /// The row of a socket of `domain` and `proto` whose PCB the lists hold,
    /// with these sockaddrs in its record.
    fn inet_row(domain: i32, proto: i32, local: &[u8], peer: &[u8]) -> OpenFile {
        let mut env = Fake::default();
        env.pcbs.insert(
            0x50,
            Pcb {
                so: 5,
                t_state: Some(0),
                ..Pcb::default()
            },
        );
        let ty = if proto == 6 {
            sock::SOCK_STREAM
        } else {
            sock::SOCK_DGRAM
        };
        let mut r = sock_rec(domain, ty, proto, 0x50);
        put(&mut r, kf::SA_LOCAL, local);
        put(&mut r, kf::SA_PEER, peer);
        numbered(&KFile::from_bytes(&r), 1, &env, Opts::default())
    }

    fn ends(f: &OpenFile) -> [Option<String>; 2] {
        let s = f.socket.as_deref().expect("a socket row");
        [s.local, s.remote].map(|a| a.map(|a| a.to_string()))
    }

    /// Measured against the C on FreeBSD 14.5 (clang 21.1.8), a fixture
    /// holding each socket: an IPv4 socket's NAME always has its foreign
    /// end, `*:*` where there is none (a listener, an unbound socket, an
    /// unconnected UDP socket), and port 0 is `*` (DIVERGENCES 180).
    #[test]
    fn an_ipv4_socket_always_shows_its_foreign_end() {
        let zero = sa4([0; 4], 0);
        for (proto, local, peer, name) in [
            (6, zero, zero, "*:*->*:*"),
            (6, sa4([127, 0, 0, 1], 41000), zero, "127.0.0.1:41000->*:*"),
            (6, sa4([0; 4], 41008), zero, "*:41008->*:*"),
            (
                6,
                sa4([127, 0, 0, 1], 51893),
                sa4([127, 0, 0, 1], 41000),
                "127.0.0.1:51893->127.0.0.1:41000",
            ),
            (17, zero, zero, "*:*->*:*"),
            (17, sa4([127, 0, 0, 1], 41001), zero, "127.0.0.1:41001->*:*"),
            (17, sa4([0; 4], 514), zero, "*:514->*:*"),
            (
                17,
                sa4([127, 0, 0, 1], 42115),
                sa4([127, 0, 0, 1], 41001),
                "127.0.0.1:42115->127.0.0.1:41001",
            ),
        ] {
            let f = inet_row(sock::AF_INET, proto, &local, &peer);
            assert_eq!(f.name, name);
            assert_eq!(f.file_type, FileType::Ipv4);
            assert!(ends(&f)[1].is_some(), "{name}: the foreign end is entered");
        }
        // The far end of a listener is an end: 0.0.0.0, port 0.
        let f = inet_row(sock::AF_INET, 6, &sa4([127, 0, 0, 1], 41000), &zero);
        assert_eq!(
            ends(&f),
            [Some("127.0.0.1:41000".into()), Some("0.0.0.0:0".into())]
        );
        // A record with no sockaddr at all reads as zeros.
        let f = inet_row(sock::AF_INET, 6, &[], &[]);
        assert_eq!(f.name, "*:*->*:*");
    }

    /// An IPv6 socket's foreign end is entered unless it is `::` port 0
    /// (measured: `TCP [::1]:41002 (LISTEN)`, `UDP *:*`, `UDP *:41007`).
    #[test]
    fn an_ipv6_socket_shows_a_foreign_end_that_is_one() {
        let zero = sa6("::", 0);
        for (proto, local, peer, name, far) in [
            (6, zero, zero, "*:*", false),
            (6, sa6("::1", 41002), zero, "[::1]:41002", false),
            (6, sa6("::", 41009), zero, "*:41009", false),
            (
                6,
                sa6("::1", 40324),
                sa6("::1", 41002),
                "[::1]:40324->[::1]:41002",
                true,
            ),
            (17, zero, zero, "*:*", false),
            (17, sa6("::1", 41003), zero, "[::1]:41003", false),
            (
                17,
                sa6("::1", 45806),
                sa6("::1", 41003),
                "[::1]:45806->[::1]:41003",
                true,
            ),
            // An address with no port, and a port with no address: each an
            // end (`!IN6_IS_ADDR_UNSPECIFIED(…) || sin6_port`).
            (
                17,
                sa6("::1", 1),
                sa6("fe80::1", 0),
                "[::1]:1->[fe80::1]:*",
                true,
            ),
            (17, sa6("::1", 1), sa6("::", 9), "[::1]:1->*:9", true),
        ] {
            let f = inet_row(sock::AF_INET6, proto, &local, &peer);
            assert_eq!(f.name, name);
            assert_eq!(f.file_type, FileType::Ipv6);
            assert_eq!(ends(&f)[1].is_some(), far, "{name}");
        }
        // A record with no sockaddr reads as zeros of the socket's family.
        let f = inet_row(sock::AF_INET6, 17, &[], &[]);
        assert_eq!(f.name, "*:*");
        assert_eq!(ends(&f), [Some("[::]:0".into()), None]);
    }

    /// Where an IPv6 socket's end is an IPv4 address mapped in IPv6, each
    /// end entered is read as IPv4, and the row stays IPv6. The kernel gives
    /// an unconnected dual-stack socket bound to a mapped address the peer
    /// `::ffff:0.0.0.0`, which is not `::`, so its foreign end is entered:
    /// measured, `IPv6 … UDP 127.0.0.1:41005->*:*`.
    #[test]
    fn a_mapped_end_makes_both_ends_ipv4() {
        let f = inet_row(
            sock::AF_INET6,
            17,
            &sa6("::ffff:127.0.0.1", 41005),
            &sa6("::ffff:0.0.0.0", 0),
        );
        assert_eq!(f.name, "127.0.0.1:41005->*:*");
        assert_eq!(f.file_type, FileType::Ipv6);
        assert_eq!(
            ends(&f),
            [Some("127.0.0.1:41005".into()), Some("0.0.0.0:0".into())]
        );
        let f = inet_row(
            sock::AF_INET6,
            6,
            &sa6("::ffff:127.0.0.1", 41004),
            &sa6("::ffff:127.0.0.1", 57490),
        );
        assert_eq!(f.name, "127.0.0.1:41004->127.0.0.1:57490");
        // The local end mapped and no foreign end: IPv4, and no arrow.
        let f = inet_row(
            sock::AF_INET6,
            17,
            &sa6("::ffff:10.0.0.1", 53),
            &sa6("::", 0),
        );
        assert_eq!(f.name, "10.0.0.1:53");
        assert_eq!(ends(&f), [Some("10.0.0.1:53".into()), None]);
        // `IPv6_2_IPv4()` takes an end's last four bytes whatever the rest:
        // an end that is not mapped beside one that is.
        let f = inet_row(
            sock::AF_INET6,
            17,
            &sa6("::ffff:10.0.0.1", 53),
            &sa6("::1", 9),
        );
        assert_eq!(f.name, "10.0.0.1:53->0.0.0.1:9");
        let f = inet_row(
            sock::AF_INET6,
            17,
            &sa6("2001:db8::102:304", 53),
            &sa6("::ffff:10.0.0.2", 9),
        );
        assert_eq!(f.name, "1.2.3.4:53->10.0.0.2:9");
        // The ends themselves are IPv4 then, not only their text: `-i`
        // asks a specification's family of them.
        assert_eq!(
            ends(&f),
            [Some("1.2.3.4:53".into()), Some("10.0.0.2:9".into())]
        );
        // No end mapped: IPv6 as it is.
        let f = inet_row(sock::AF_INET6, 6, &sa6("::", 41004), &sa6("::", 0));
        assert_eq!(f.name, "*:41004");
        assert_eq!(ends(&f), [Some("[::]:41004".into()), None]);
    }

    /// A sockaddr the record is too short to hold reads as zeros of the
    /// socket's family, as every field past a record's end does: an IPv4
    /// socket then has both its ends, an IPv6 one its local end alone.
    #[test]
    fn a_sockaddr_the_record_cannot_hold_is_zeros_of_the_family() {
        let text = |e: [Option<SocketAddr>; 2]| e.map(|a| a.map(|a| a.to_string()));
        assert_eq!(
            text(entered_ends(&[], &[], sock::AF_INET)),
            [Some("0.0.0.0:0".into()), Some("0.0.0.0:0".into())]
        );
        assert_eq!(
            text(entered_ends(&[], &[], sock::AF_INET6)),
            [Some("[::]:0".into()), None]
        );
        // One the record holds beside one it cuts short.
        assert_eq!(
            text(entered_ends(
                &sa6("::1", 7),
                &sa6("::1", 9)[..20],
                sock::AF_INET6
            )),
            [Some("[::1]:7".into()), None]
        );
        assert_eq!(
            text(entered_ends(
                &sa4([10, 0, 0, 1], 7)[..3],
                &sa4([10, 0, 0, 2], 9),
                sock::AF_INET
            )),
            [Some("0.0.0.0:0".into()), Some("10.0.0.2:9".into())]
        );
    }

    /// An IPv6 address is written as FreeBSD's `inet_ntop()` writes it, in
    /// brackets (`gethostnm()`): each measured on 14.5.
    #[test]
    fn an_ipv6_address_is_written_as_inet_ntop_writes_it() {
        for (addr, text) in [
            ("::1", "[::1]"),
            ("::2", "[::2]"),
            ("::ffff", "[::ffff]"),
            ("::1:2", "[::0.1.0.2]"),
            ("::1.2.3.4", "[::1.2.3.4]"),
            ("::ffff:0:1.2.3.4", "[::ffff:0:102:304]"),
            ("1:0:0:2:0:0:0:3", "[1:0:0:2::3]"),
            ("1:0:0:2:0:0:3:4", "[1::2:0:0:3:4]"),
            ("2001:db8::", "[2001:db8::]"),
            ("2001:db8:0:1:1:1:1:1", "[2001:db8:0:1:1:1:1:1]"),
            ("fe80::1", "[fe80::1]"),
            ("::1:0:0:0", "[::1:0:0:0]"),
            ("0:0:0:0:0:0:1:0", "[::0.1.0.0]"),
            ("::fffe:1.2.3.4", "[::fffe:102:304]"),
            ("a::", "[a::]"),
            ("0:0:1::", "[0:0:1::]"),
        ] {
            let f = inet_row(sock::AF_INET6, 17, &sa6(addr, 7), &sa6("::", 0));
            assert_eq!(f.name, format!("{text}:7"), "{addr}");
        }
    }

    #[test]
    fn unix_sockets_are_named_by_path_or_peer() {
        let mut env = Fake::default();
        env.pcbs.insert(
            0x30,
            Pcb {
                so: 0xabc,
                t_state: None,
                ..Pcb::default()
            },
        );
        env.pcbs.insert(
            0x40,
            Pcb {
                so: 0xdef,
                t_state: None,
                ..Pcb::default()
            },
        );
        let mut r = sock_rec(sock::AF_UNIX, sock::SOCK_STREAM, 0, 0x30);
        let mut sa = [0u8; 106];
        sa[0] = 2 + 8;
        sa[1] = 1;
        put(&mut sa, 2, b"/var/run/log");
        put(&mut r, kf::SA_LOCAL, &sa);
        let f = numbered(&KFile::from_bytes(&r), 1, &env, Opts::default());
        assert_eq!(f.file_type, FileType::Unix);
        assert_eq!(f.name, "/var/run");
        assert_eq!(f.device.as_deref(), Some("0x00000abc"));
        assert_eq!(f.node, None);
        let mut c = sock_rec(sock::AF_UNIX, sock::SOCK_STREAM, 0, 0x30);
        put(&mut c, kf::SOCK_UNPCONN, &0x40u64.to_ne_bytes());
        assert_eq!(
            numbered(&KFile::from_bytes(&c), 1, &env, Opts::default()).name,
            "->0x00000def"
        );
        let n = sock_rec(sock::AF_UNIX, sock::SOCK_DGRAM, 0, 0x30);
        assert_eq!(
            numbered(&KFile::from_bytes(&n), 1, &env, Opts::default()).name,
            "->(none)"
        );
        let gone = sock_rec(sock::AF_UNIX, sock::SOCK_DGRAM, 0, 0x99);
        assert_eq!(
            numbered(&KFile::from_bytes(&gone), 1, &env, Opts::default()).name,
            "can't read unpcb at 0x00000099"
        );
    }

    #[test]
    fn pipes_kqueues_and_unknown_kinds() {
        let mut env = Fake::default();
        env.xfiles.insert(
            (1, 5),
            XFile {
                file: 0xffff_f800_0011_2233,
                ..XFile::default()
            },
        );
        let mut p = kf_rec(kf::TYPE_PIPE, 3, b"");
        put(&mut p, kf::PIPE_ADDR, &0x100u64.to_ne_bytes());
        put(&mut p, kf::PIPE_PEER, &0x200u64.to_ne_bytes());
        put(&mut p, kf::PIPE_CNT, &5u32.to_ne_bytes());
        put(&mut p, kf::PIPE_SIZE, &16384u32.to_ne_bytes());
        let f = numbered(&KFile::from_bytes(&p), 1, &env, Opts::default());
        assert_eq!(f.file_type, FileType::Pipe);
        assert_eq!(f.name, "->0x00000200, cnt=5");
        assert_eq!(
            (f.size, f.device.as_deref()),
            (Some(16384), Some("0x00000100"))
        );
        let under_i = numbered(
            &KFile::from_bytes(&p),
            1,
            &env,
            Opts {
                inet: true,
                ..Opts::default()
            },
        );
        assert_eq!(
            (under_i.file_type, under_i.name.as_str()),
            (FileType::NoType, "")
        );
        let mut q = kf_rec(kf::TYPE_KQUEUE, 4, b"");
        put(&mut q, kf::KQ_COUNT, &2i32.to_ne_bytes());
        put(&mut q, kf::KQ_STATE, &0x40i32.to_ne_bytes());
        put(&mut q, kf::KQ_ADDR, &0x77u64.to_ne_bytes());
        let f = numbered(&KFile::from_bytes(&q), 1, &env, Opts::default());
        assert_eq!(
            (f.file_type.code(), f.name.as_str()),
            ("KQUEUE".into(), "count=2, state=0x40")
        );
        // DEVICE is `xf_data`, not the record's own `kf_kqueue_addr`, and
        // 0 where `kern.file` lists no such descriptor (DIVERGENCES 145).
        assert_eq!(f.device.as_deref(), Some("0x00000000"));
        env.xfiles.insert(
            (1, 4),
            XFile {
                data: 0x1234_5678,
                ..XFile::default()
            },
        );
        let f = numbered(&KFile::from_bytes(&q), 1, &env, Opts::default());
        assert_eq!(f.device.as_deref(), Some("0x12345678"));
        let u = kf_rec(14, 5, b"");
        let f = numbered(&KFile::from_bytes(&u), 1, &env, Opts::default());
        assert_eq!(f.file_type, FileType::NoType);
        #[cfg(target_pointer_width = "64")]
        assert_eq!(f.name, "0xfffff80000112233 file struct, ty=14");
    }

    /// A pipe is left unprocessed under `Selinet`, a run that asks about
    /// Internet files and nothing else; `-i` beside another selector is not
    /// one. Measured on FreeBSD 14.5: `lsof -u tester -i TCP:1` lists the
    /// user's pipes as `PIPE` rows.
    #[test]
    fn a_runs_options_are_selinet_and_the_file_structure() {
        use lsof_core::selection::Selection;
        let mut inet = Selection::default();
        inet.inet.add_all(None);
        assert!(Opts::of(&inet).inet, "-i alone");
        let mut with_user = Selection {
            uids: vec![lsof_core::UidSel {
                uid: 1001,
                login: None,
            }],
            ..Default::default()
        };
        with_user.inet.add_all(None);
        assert!(!Opts::of(&with_user).inet, "-u U -i");
        assert!(!Opts::of(&Selection::default()).inet);
        assert!(!Opts::of(&inet).file_struct);
        let asked = Selection {
            file_struct: true,
            ..Default::default()
        };
        assert!(Opts::of(&asked).file_struct && !Opts::of(&asked).inet);
    }

    #[test]
    fn a_procdesc_names_its_pid_in_an_addition() {
        let env = Fake::default();
        let mut r = kf_rec(kf::TYPE_PROCDESC, 3, b"");
        put(&mut r, kf::PROC_PID, &4242i32.to_ne_bytes());
        let f = numbered(&KFile::from_bytes(&r), 1, &env, Opts::default());
        assert_eq!(
            (f.file_type.code(), f.name.as_str()),
            ("PROCDSC".into(), "pid=4242")
        );
        assert_eq!(f.base_name(), None);
    }

    #[test]
    fn a_pts_is_named_from_dev() {
        let mut env = Fake::default();
        env.devs.insert(0x6e, "/dev/pts/0".into());
        let mut r = kf_rec(kf::TYPE_PTS, 0, b"");
        put(&mut r, kf::PTS_DEV, &0x6eu64.to_ne_bytes());
        let f = numbered(&KFile::from_bytes(&r), 1, &env, Opts::default());
        assert_eq!(f.file_type.code(), "PTS");
        assert_eq!(f.name, "/dev/pts/0");
        assert_eq!(f.base_name(), None, "printed: process_pts() sets no Lf->nm");
        assert!(env.pts_seen.get(), "DCunsafe = 1");
        assert_eq!(f.device.as_deref(), Some("0,110"));
        assert_eq!((f.node.as_deref(), f.fs_device), (Some("110"), Some(0x5a)));
    }

    #[test]
    fn kf_flags_become_the_struct_file_flags_they_stand_for() {
        assert_eq!(kf_flags_to_fflags(0), 0);
        assert_eq!(kf_flags_to_fflags(0x1 | 0x2), 0x3);
        assert_eq!(
            kf_flags_to_fflags(0x4 | 0x20),
            0x8 | 0x4,
            "APPEND, NONBLOCK"
        );
        assert_eq!(
            kf_flags_to_fflags(0x8 | 0x10 | 0x80 | 0x800 | 0x40),
            0x40 | 0x80 | 0x4000 | 0x200 | 0x10000
        );
        assert_eq!(
            kf_flags_to_fflags(0x2000 | 0x4000 | 0x200 | 0x400 | 0x100 | 0x1000),
            0x800 | 0x40000 | 0x20 | 0x100 | 0x10 | 0x400
        );
        // A bit no entry has is dropped, as the C's loop drops it.
        assert_eq!(kf_flags_to_fflags(0x1_0000), 0);
    }

    #[test]
    fn the_file_structure_is_the_records_count_and_kern_files_addresses() {
        let x = XFile {
            file: 0xffff_f800_0000_0010,
            data: 0xffff_f800_0000_0020,
            vnode: 0xffff_f800_0000_0030,
            flag: 0x8003,
        };
        let mut v = vnode_rec(3, kf::VTYPE_VREG, b"/a");
        put(&mut v, kf::REF_COUNT, &2i32.to_ne_bytes());
        let fs = file_struct(&KFile::from_bytes(&v), Some(x));
        assert_eq!(fs.count, Some(2));
        #[cfg(target_pointer_width = "64")]
        assert_eq!(
            (fs.addr, fs.node),
            (Some(0xffff_f800_0000_0010), Some(0xffff_f800_0000_0030)),
            "a vnode's node is xf_vnode"
        );
        #[cfg(target_pointer_width = "32")]
        assert_eq!(
            (fs.addr, fs.node),
            (Some(0x10), Some(0x30)),
            "KA_T is 32 bits"
        );
        let fifo = kf_rec(kf::TYPE_FIFO, 4, b"/f");
        assert_eq!(
            file_struct(&KFile::from_bytes(&fifo), Some(x)).node,
            Some(ka(x.vnode))
        );
        let sock = sock_rec(sock::AF_INET, sock::SOCK_STREAM, 6, 1);
        let s = file_struct(&KFile::from_bytes(&sock), Some(x));
        assert_eq!((s.count, s.node), (Some(1), Some(ka(x.data))), "xf_data");
        // Not in `kern.file`: the count alone.
        let none = file_struct(&KFile::from_bytes(&sock), None);
        assert_eq!((none.count, none.addr, none.node), (Some(1), None, None));
    }

    #[test]
    fn the_flags_are_kern_files_or_the_records_and_only_when_asked() {
        let mut env = root_fs();
        let mut r = vnode_rec(3, kf::VTYPE_VREG, b"/etc/motd");
        put(&mut r, kf::FLAGS, &(0x1i32 | 0x4).to_ne_bytes());
        let k = KFile::from_bytes(&r);
        let asked = Opts {
            file_struct: true,
            ..Opts::default()
        };
        assert_eq!(numbered(&k, 7, &env, Opts::default()).file_flags, None);
        assert_eq!(numbered(&k, 7, &env, asked).file_flags, Some(0x1 | 0x8));
        env.xfiles.insert(
            (7, 3),
            XFile {
                flag: 0x4003,
                ..XFile::default()
            },
        );
        assert_eq!(numbered(&k, 7, &env, asked).file_flags, Some(0x4003));
        // A special has none.
        let c = vnode_rec(kf::FD_CWD, kf::VTYPE_VDIR, b"/");
        assert_eq!(
            special(&KFile::from_bytes(&c), FdType::Cwd, 7, &env).file_flags,
            None
        );
    }

    fn bsd(f: &OpenFile) -> BsdSocket {
        f.socket
            .as_deref()
            .and_then(|s| s.tcp)
            .and_then(|t| t.bsd)
            .expect("a FreeBSD socket row has its record")
    }

    #[test]
    fn a_sockets_tcp_tpi_record_is_the_cs() {
        let xso = lsof_core::model::BsdXSocket {
            options: 0x2,
            qlimit: 5,
            ..Default::default()
        };
        let mut env = Fake::default();
        env.pcbs.insert(
            0x10,
            Pcb {
                so: 0x11,
                t_state: Some(1),
                xsocket: xso,
                tcp: Some((0x4, 1460)),
            },
        );
        let mut r = sock_rec(sock::AF_INET, sock::SOCK_STREAM, 6, 0x10);
        put(&mut r, kf::SOCK_RCV_SB_STATE, &0x20u16.to_ne_bytes());
        put(&mut r, kf::SOCK_SND_SB_STATE, &0x10u16.to_ne_bytes());
        put(&mut r, kf::SOCK_RECVQ, &9u32.to_ne_bytes());
        let f = numbered(&KFile::from_bytes(&r), 1, &env, Opts::default());
        let t = f.socket.as_deref().and_then(|s| s.tcp).unwrap();
        assert_eq!((t.recv_queue, t.send_queue), (Some(9), Some(0)));
        assert_eq!(
            bsd(&f),
            BsdSocket {
                record: true,
                xsocket: Some(xso),
                sbs_rcv: 0x20,
                sbs_snd: 0x10,
                tcp: Some((0x4, 1460)),
            }
        );
        // UDP over the same pcb: its xsocket, no record, no TCP flags.
        let u = sock_rec(sock::AF_INET, sock::SOCK_DGRAM, 17, 0x10);
        let b = bsd(&numbered(&KFile::from_bytes(&u), 1, &env, Opts::default()));
        assert_eq!((b.record, b.xsocket, b.tcp), (false, Some(xso), None));
        // No pcb: nothing from the lists, and no record.
        let n = sock_rec(sock::AF_INET, sock::SOCK_STREAM, 6, 0x99);
        let b = bsd(&numbered(&KFile::from_bytes(&n), 1, &env, Opts::default()));
        assert_eq!((b.record, b.xsocket, b.tcp), (false, None, None));
        // A unix socket keeps its xsocket too.
        let x = sock_rec(sock::AF_UNIX, sock::SOCK_STREAM, 0, 0x10);
        let b = bsd(&numbered(&KFile::from_bytes(&x), 1, &env, Opts::default()));
        assert_eq!((b.record, b.xsocket), (false, Some(xso)));
        // A routing socket, and one of a family the C does not know: their
        // queues and buffer states, for `-T q` (`dsock.c:404-407`), and no
        // record; NAME as before.
        for (domain, name) in [(sock::AF_ROUTE, "no protocol control block"), (99, "")] {
            let mut r = sock_rec(domain, sock::SOCK_STREAM, 0, 0x99);
            put(&mut r, kf::SOCK_RECVQ, &3u32.to_ne_bytes());
            put(&mut r, kf::SOCK_SENDQ, &4u32.to_ne_bytes());
            put(&mut r, kf::SOCK_RCV_SB_STATE, &0x20u16.to_ne_bytes());
            let f = numbered(&KFile::from_bytes(&r), 1, &env, Opts::default());
            let t = f.socket.as_deref().and_then(|s| s.tcp).unwrap();
            assert_eq!((t.recv_queue, t.send_queue), (Some(3), Some(4)), "{domain}");
            let b = bsd(&f);
            assert_eq!((b.record, b.xsocket, b.sbs_rcv), (false, None, 0x20));
            if !name.is_empty() {
                assert_eq!(f.name, name);
            }
            assert_eq!(f.size, Some(7));
        }
    }
}
