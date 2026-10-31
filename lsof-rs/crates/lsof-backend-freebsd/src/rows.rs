//! One `kinfo_file` record into one lsof row, as the C's FreeBSD dialect
//! builds it: `process_kinfo_file()` (`dproc.c`), `process_vnode()`,
//! `process_pipe()`, `process_pts()` and the rest of `dnode.c`, and
//! `process_socket()` (`dsock.c`). The `file:line`-free references below are
//! to those functions; each branch says what of the C it is.
//!
//! Pure: everything outside the record that a row needs — a file system's
//! names, a lock, a pcblist entry, a device's name in `/dev` — is asked of an
//! [`Env`], so the rules can be tested on any host with a fake one.

use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;

use lsof_core::model::{
    AccessMode, FdType, FileType, LockKind, OpenFile, Protocol, SockState, SocketInfo, TcpExtInfo,
};

use crate::kinfo::{inet_addr, unix_path, KFile, Pcb};
use crate::layout::{kf, sock, VNOVAL};
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
    /// The name in `/dev` of the device `rdev` (`printdevname()`).
    fn dev_name(&self, rdev: u64) -> Option<String>;
    /// `DevDev`: the device `/dev` is on.
    fn dev_dev(&self) -> Option<u64>;
    /// The kernel address of the `struct file` behind `pid`'s `fd`, from
    /// `kern.file` (`xfile->xf_file`).
    fn file_addr(&self, pid: i32, fd: i32) -> Option<u64>;
}

/// What of the run's options a row is built under.
#[derive(Clone, Copy, Debug, Default)]
pub struct Opts {
    /// `-i` was given (the C's `Selinet`): a pipe is then not processed.
    pub inet: bool,
    /// `-T q`: socket queue lengths are wanted in the row's TCP info.
    pub queues: bool,
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
        kf::TYPE_SOCKET => socket(&mut f, k, env, opts),
        kf::TYPE_KQUEUE => {
            // `process_kf_kqueue()`, the 14.0 form: the count and state are
            // in the record. Its DEVICE is the kqueue's address, which the C
            // takes from `kern.file` and the record also holds.
            f.file_type = FileType::Other("KQUEUE".into());
            f.device = Some(kptr(k.kq_addr()));
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
            let addr = env.file_addr(pid, k.fd()).unwrap_or(0);
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
    let rdev = matches!(vtype, kf::VTYPE_VCHR | kf::VTYPE_VBLK).then(|| k.file_rdev());
    if k.file_fileid() != VNOVAL {
        f.node = Some(k.file_fileid().to_string());
    }
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
    // A device node that `/dev` names is printed by that name, in place of
    // the path (`print.c`, `printdevname()`); its addition stays.
    if device_node && dev.is_some() {
        if let Some(n) = rdev.and_then(|r| env.dev_name(r)) {
            name = Some(n);
        }
    }
    let base = match name {
        Some(n) => n,
        None if k.path().is_empty() => String::new(),
        None => {
            let mut n = lossy(k.path());
            if let Some(v) = &vfs {
                n.push_str(" (");
                n.push_str(&lossy(&v.fsname));
                n.push(')');
            }
            n
        }
    };
    f.set_base_name(&base);
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
    if f.fs_device.is_some() {
        if let Some(n) = env.dev_name(d) {
            f.name = n;
        }
    }
}

fn is_v4_mapped(ip: &IpAddr) -> Option<IpAddr> {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4),
        IpAddr::V4(_) => None,
    }
}

/// `process_socket()`.
fn socket(f: &mut OpenFile, k: &KFile, env: &dyn Env, opts: Opts) {
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
    let tcp = opts.queues.then_some(TcpExtInfo {
        recv_window: None,
        recv_queue: Some(rq),
        send_queue: Some(sq),
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
            let local = inet_addr(k.sa_local(), domain);
            let remote = inet_addr(k.sa_peer(), domain)
                .filter(|a| !a.ip().is_unspecified() || a.port() != 0);
            // An IPv4 address mapped in IPv6 is printed as IPv4.
            let map = |a: SocketAddr| match is_v4_mapped(&a.ip()) {
                Some(v4) => SocketAddr::new(v4, a.port()),
                None => a,
            };
            let mapped = local.is_some_and(|a| is_v4_mapped(&a.ip()).is_some())
                || remote.is_some_and(|a| is_v4_mapped(&a.ip()).is_some());
            info.local = if mapped { local.map(map) } else { local };
            info.remote = if mapped { remote.map(map) } else { remote };
            if protocol == Protocol::Tcp {
                info.state = pcb.t_state.and_then(tcp_state).map(SockState::Tcp);
            }
            f.name = info.display_name(false, false);
            f.socket = Some(Box::new(info));
        }
        sock::AF_ROUTE => {
            // The pcblists hold no routing socket, so the C never has the
            // `xsocket` this branch asks for.
            f.file_type = FileType::Socket("rte");
            f.name = "no protocol control block".into();
        }
        sock::AF_UNIX => {
            f.file_type = FileType::Unix;
            f.socket = Some(Box::new(SocketInfo {
                protocol: Protocol::Other("unix"),
                local: None,
                remote: None,
                state: None,
                tcp: None,
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
        }
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
        fn dev_name(&self, rdev: u64) -> Option<String> {
            self.devs.get(&rdev).cloned()
        }
        fn dev_dev(&self) -> Option<u64> {
            Some(0x5a)
        }
        fn file_addr(&self, _pid: i32, _fd: i32) -> Option<u64> {
            Some(0xffff_f800_0011_2233)
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
        assert_eq!(f.name, "/dev/null");
        assert_eq!(f.device.as_deref(), Some("0,31"));
        assert_eq!(f.size, None, "a device has no size, so the offset shows");
        assert_eq!(f.rdev.map(NonZeroU32::get), Some(0x1f));
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
        assert_eq!(f.name, "*:22");
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

    #[test]
    fn unix_sockets_are_named_by_path_or_peer() {
        let mut env = Fake::default();
        env.pcbs.insert(
            0x30,
            Pcb {
                so: 0xabc,
                t_state: None,
            },
        );
        env.pcbs.insert(
            0x40,
            Pcb {
                so: 0xdef,
                t_state: None,
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
        let env = Fake::default();
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
        let f = numbered(&KFile::from_bytes(&q), 1, &env, Opts::default());
        assert_eq!(
            (f.file_type.code(), f.name.as_str()),
            ("KQUEUE".into(), "count=2, state=0x40")
        );
        let u = kf_rec(14, 5, b"");
        let f = numbered(&KFile::from_bytes(&u), 1, &env, Opts::default());
        assert_eq!(f.file_type, FileType::NoType);
        #[cfg(target_pointer_width = "64")]
        assert_eq!(f.name, "0xfffff80000112233 file struct, ty=14");
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
        assert_eq!(f.device.as_deref(), Some("0,110"));
        assert_eq!((f.node.as_deref(), f.fs_device), (Some("110"), Some(0x5a)));
    }
}
