//! The parsing half of every sysctl this backend makes: bytes in, records
//! out, no system call.
//!
//! Each function takes the buffer the kernel filled and touches nothing else,
//! so the exact code the backend runs on kernel-supplied bytes is the code the
//! fuzz target drives with arbitrary ones, and the code the unit tests drive on
//! any host. The contract is the kit's: **no panic on any input**. Every read
//! is bounds-checked ([`u32_at`] and friends answer `None` past the end), every
//! length the kernel states is checked against what is there before it is
//! trusted, and a record that does not fit is the end of the list, not a read
//! past it.
//!
//! Integers are read in the host's byte order: the kernel wrote them in its
//! own, which is this process's.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::layout::{self, kf, kl, sf, sock, xf, PcbLayout, ProcLayout};

fn bytes_at<const N: usize>(b: &[u8], off: usize) -> Option<[u8; N]> {
    b.get(off..off.checked_add(N)?)?.try_into().ok()
}

pub(crate) fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    bytes_at(b, off).map(u16::from_ne_bytes)
}

pub(crate) fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    bytes_at(b, off).map(u32::from_ne_bytes)
}

pub(crate) fn i32_at(b: &[u8], off: usize) -> Option<i32> {
    bytes_at(b, off).map(i32::from_ne_bytes)
}

pub(crate) fn u64_at(b: &[u8], off: usize) -> Option<u64> {
    bytes_at(b, off).map(u64::from_ne_bytes)
}

pub(crate) fn i64_at(b: &[u8], off: usize) -> Option<i64> {
    bytes_at(b, off).map(i64::from_ne_bytes)
}

/// A C string in a fixed field: the bytes from `off` up to the first NUL,
/// or to the end of the field, or of the buffer, whichever comes first.
pub(crate) fn cstr_at(b: &[u8], off: usize, len: usize) -> &[u8] {
    let end = off.saturating_add(len).min(b.len());
    let field = b.get(off..end).unwrap_or_default();
    match field.iter().position(|&c| c == 0) {
        Some(n) => &field[..n],
        None => field,
    }
}

/// One process, as `kern.proc.proc` describes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KProc {
    pub pid: i32,
    pub ppid: i32,
    pub pgid: i32,
    pub uid: u32,
    pub stat: u8,
    /// `ki_comm`, as bytes: a process names itself, and need not in UTF-8.
    pub comm: Vec<u8>,
}

/// Why a buffer could not be read as the records it should hold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LayoutError(pub String);

/// `kern.proc.proc`'s buffer: `struct kinfo_proc`s back to back.
///
/// Every record's `ki_structsize` must be the layout's size: a kernel whose
/// `kinfo_proc` is another size wrote another layout, and reading it with
/// this one would put the wrong bytes in every field. That is refused, whole,
/// with the two sizes; a trailing piece too short to be a record is ignored.
pub fn procs(buf: &[u8], layout: Option<&ProcLayout>) -> Result<Vec<KProc>, LayoutError> {
    let Some(l) = layout else {
        return Err(LayoutError(
            "no kinfo_proc layout is known for this architecture".into(),
        ));
    };
    let mut out = Vec::with_capacity(buf.len() / l.size);
    for rec in buf.chunks_exact(l.size) {
        let size = i32_at(rec, 0).unwrap_or(0);
        if usize::try_from(size).ok() != Some(l.size) {
            return Err(LayoutError(format!(
                "kinfo_proc is {size} bytes here; this lsof reads {}",
                l.size
            )));
        }
        out.push(KProc {
            pid: i32_at(rec, l.pid).unwrap_or(0),
            ppid: i32_at(rec, l.ppid).unwrap_or(0),
            pgid: i32_at(rec, l.pgid).unwrap_or(0),
            uid: u32_at(rec, l.uid).unwrap_or(0),
            stat: rec.get(l.stat).copied().unwrap_or(0),
            comm: cstr_at(rec, l.comm, layout::COMMLEN + 1).to_vec(),
        });
    }
    Ok(out)
}

/// One open file, as `kern.proc.filedesc` describes it: the record's own
/// bytes, read by the accessors below. A field the record is too short to
/// hold reads as 0, the kernel's own fill for a field it did not set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KFile {
    rec: Box<[u8]>,
}

impl KFile {
    /// A record from its bytes, as [`files`] cut it from the buffer. Public
    /// so a test can build one.
    pub fn from_bytes(rec: &[u8]) -> Self {
        KFile { rec: rec.into() }
    }
    fn i32(&self, off: usize) -> i32 {
        i32_at(&self.rec, off).unwrap_or(0)
    }
    fn u32(&self, off: usize) -> u32 {
        u32_at(&self.rec, off).unwrap_or(0)
    }
    fn u64(&self, off: usize) -> u64 {
        u64_at(&self.rec, off).unwrap_or(0)
    }
    fn u16(&self, off: usize) -> u16 {
        u16_at(&self.rec, off).unwrap_or(0)
    }
    pub fn kind(&self) -> i32 {
        self.i32(kf::TYPE)
    }
    pub fn fd(&self) -> i32 {
        self.i32(kf::FD)
    }
    pub fn ref_count(&self) -> i32 {
        self.i32(kf::REF_COUNT)
    }
    pub fn flags(&self) -> i32 {
        self.i32(kf::FLAGS)
    }
    pub fn offset(&self) -> i64 {
        i64_at(&self.rec, kf::OFFSET).unwrap_or(0)
    }
    pub fn vnode_type(&self) -> i32 {
        self.i32(kf::VNODE_TYPE)
    }
    pub fn sock_domain(&self) -> i32 {
        self.i32(kf::SOCK_DOMAIN)
    }
    pub fn sock_type(&self) -> i32 {
        self.i32(kf::SOCK_TYPE)
    }
    pub fn sock_protocol(&self) -> i32 {
        self.i32(kf::SOCK_PROTOCOL)
    }
    /// `kf_sa_local`, as far as the record holds it.
    pub fn sa_local(&self) -> &[u8] {
        field(&self.rec, kf::SA_LOCAL, kf::SA_LEN)
    }
    pub fn sa_peer(&self) -> &[u8] {
        field(&self.rec, kf::SA_PEER, kf::SA_LEN)
    }
    pub fn sock_sendq(&self) -> u32 {
        self.u32(kf::SOCK_SENDQ)
    }
    pub fn sock_recvq(&self) -> u32 {
        self.u32(kf::SOCK_RECVQ)
    }
    pub fn sock_pcb(&self) -> u64 {
        self.u64(kf::SOCK_PCB)
    }
    pub fn sock_unpconn(&self) -> u64 {
        self.u64(kf::SOCK_UNPCONN)
    }
    pub fn sock_snd_sb_state(&self) -> u16 {
        self.u16(kf::SOCK_SND_SB_STATE)
    }
    pub fn sock_rcv_sb_state(&self) -> u16 {
        self.u16(kf::SOCK_RCV_SB_STATE)
    }
    pub fn file_nlink(&self) -> u64 {
        self.u64(kf::FILE_NLINK)
    }
    pub fn file_fsid(&self) -> u64 {
        self.u64(kf::FILE_FSID)
    }
    pub fn file_rdev(&self) -> u64 {
        self.u64(kf::FILE_RDEV)
    }
    pub fn file_fileid(&self) -> u64 {
        self.u64(kf::FILE_FILEID)
    }
    pub fn file_size(&self) -> u64 {
        self.u64(kf::FILE_SIZE)
    }
    pub fn pipe_addr(&self) -> u64 {
        self.u64(kf::PIPE_ADDR)
    }
    pub fn pipe_peer(&self) -> u64 {
        self.u64(kf::PIPE_PEER)
    }
    pub fn pipe_cnt(&self) -> u32 {
        self.u32(kf::PIPE_CNT)
    }
    pub fn pipe_in(&self) -> u32 {
        self.u32(kf::PIPE_IN)
    }
    pub fn pipe_out(&self) -> u32 {
        self.u32(kf::PIPE_OUT)
    }
    pub fn pipe_size(&self) -> u32 {
        self.u32(kf::PIPE_SIZE)
    }
    pub fn pts_dev(&self) -> u64 {
        self.u64(kf::PTS_DEV)
    }
    pub fn proc_pid(&self) -> i32 {
        self.i32(kf::PROC_PID)
    }
    pub fn kq_addr(&self) -> u64 {
        self.u64(kf::KQ_ADDR)
    }
    pub fn kq_count(&self) -> i32 {
        self.i32(kf::KQ_COUNT)
    }
    pub fn kq_state(&self) -> i32 {
        self.i32(kf::KQ_STATE)
    }
    pub fn efd_value(&self) -> u64 {
        self.u64(kf::EFD_VALUE)
    }
    pub fn efd_flags(&self) -> u32 {
        self.u32(kf::EFD_FLAGS)
    }
    pub fn efd_addr(&self) -> u64 {
        self.u64(kf::EFD_ADDR)
    }
    /// `kf_path`, without its NUL: empty where the kernel has no name.
    pub fn path(&self) -> &[u8] {
        cstr_at(&self.rec, kf::PATH, kf::PATH_LEN)
    }
}

fn field(b: &[u8], off: usize, len: usize) -> &[u8] {
    let end = off.saturating_add(len).min(b.len());
    b.get(off..end).unwrap_or_default()
}

/// `kern.proc.filedesc.<pid>`'s buffer: packed `struct kinfo_file`s, each
/// `kf_structsize` bytes. What `kinfo_getfile(3)` unpacks for the C.
///
/// A record whose size is 0, shorter than the fixed part before `kf_path`,
/// longer than a whole `kinfo_file`, or longer than what is left of the
/// buffer, ends the list: there is no next record to find after a length that
/// cannot be trusted. What came before it is returned.
pub fn files(buf: &[u8]) -> Vec<KFile> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < buf.len() {
        let Some(size) = i32_at(buf, off + kf::STRUCTSIZE).and_then(|s| usize::try_from(s).ok())
        else {
            break;
        };
        if !(kf::PATH..=kf::MAX_SIZE).contains(&size) {
            break;
        }
        let Some(rec) = off.checked_add(size).and_then(|end| buf.get(off..end)) else {
            break;
        };
        out.push(KFile::from_bytes(rec));
        off += size;
    }
    out
}

/// One advisory lock, from `kern.lockf`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KLock {
    pub write: bool,
    pub pid: i32,
    pub sysid: i32,
    pub fsid: u64,
    pub fileid: u64,
    pub start: i64,
    pub len: i64,
}

/// `kern.lockf`'s buffer: `struct kinfo_lockf`s, `kl_structsize` bytes
/// each. A lock that is neither read nor write (`kl_rw`) is no lock lsof
/// shows; a record whose size is not the one measured ends the list.
pub fn locks(buf: &[u8]) -> Vec<KLock> {
    let mut out = Vec::new();
    for rec in buf.chunks_exact(kl::SIZE) {
        if i32_at(rec, kl::STRUCTSIZE).and_then(|s| usize::try_from(s).ok()) != Some(kl::SIZE) {
            break;
        }
        let write = match i32_at(rec, kl::RW) {
            Some(kl::RW_READ) => false,
            Some(kl::RW_WRITE) => true,
            _ => continue,
        };
        out.push(KLock {
            write,
            pid: i32_at(rec, kl::PID).unwrap_or(0),
            sysid: i32_at(rec, kl::SYSID).unwrap_or(0),
            fsid: u64_at(rec, kl::FILE_FSID).unwrap_or(0),
            fileid: u64_at(rec, kl::FILE_FILEID).unwrap_or(0),
            start: i64_at(rec, kl::START).unwrap_or(0),
            len: i64_at(rec, kl::LEN).unwrap_or(0),
        });
    }
    out
}

/// What a pcblist says of one socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pcb {
    /// The socket's own address, `xso_so`.
    pub so: u64,
    /// TCP's `t_state`; `None` for every other list.
    pub t_state: Option<i32>,
}

/// A `*.pcblist` buffer, as the C walks it (`dsock.c`, `get_tcp_pcbs()`):
/// one `xinpgen` (or `xunpgen`) whose first field is its own length, then
/// records for as long as the length each begins with is the record's, then
/// the closing generation record. Keyed by `so_pcb`, which is what a
/// `kinfo_file`'s `kf_sock_pcb` (and an AF_UNIX one's `kf_sock_unpconn`)
/// holds.
pub fn pcblist(buf: &[u8], l: &PcbLayout) -> HashMap<u64, Pcb> {
    let mut out = HashMap::new();
    let Some(head) = u64_at(buf, 0).and_then(|n| usize::try_from(n).ok()) else {
        return out;
    };
    let Ok(rec_len) = usize::try_from(l.len) else {
        return out;
    };
    let mut off = head;
    while u64_at(buf, off) == Some(l.len) {
        let Some(rec) = off.checked_add(rec_len).and_then(|end| buf.get(off..end)) else {
            break;
        };
        let pcb = Pcb {
            so: u64_at(rec, l.xso_so).unwrap_or(0),
            t_state: l.t_state.and_then(|o| i32_at(rec, o)),
        };
        if let Some(key) = u64_at(rec, l.so_pcb) {
            out.entry(key).or_insert(pcb);
        }
        off += rec_len;
    }
    out
}

/// One `struct xfile` from `kern.file`, as far as lsof reads it: whose
/// descriptor it is, and the kernel address of its `struct file`.
pub fn xfiles(buf: &[u8]) -> HashMap<(i32, i32), u64> {
    let mut out = HashMap::new();
    for rec in buf.chunks_exact(xf::SIZE) {
        if u64_at(rec, 0) != Some(xf::SIZE as u64) {
            break;
        }
        if let (Some(pid), Some(fd), Some(file)) = (
            i32_at(rec, xf::PID),
            i32_at(rec, xf::FD),
            u64_at(rec, xf::FILE),
        ) {
            out.entry((pid, fd)).or_insert(file);
        }
    }
    out
}

/// A mounted file system, from `getfsstat(2)` or `statfs(2)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatFs {
    /// `f_type`: 0 is no file system the C records.
    pub ftype: u32,
    /// `f_fsid.val[0]`, which the C assumes for a mount it cannot `stat`.
    pub fsid0: u32,
    pub fstypename: Vec<u8>,
    pub mntfrom: Vec<u8>,
    pub mnton: Vec<u8>,
}

/// One `struct statfs`.
pub fn statfs(rec: &[u8]) -> Option<StatFs> {
    if rec.len() < sf::SIZE {
        return None;
    }
    Some(StatFs {
        ftype: u32_at(rec, sf::TYPE)?,
        fsid0: u32_at(rec, sf::FSID)?,
        fstypename: cstr_at(rec, sf::FSTYPENAME, sf::FSTYPENAME_LEN).to_vec(),
        mntfrom: cstr_at(rec, sf::MNTFROMNAME, sf::MNAMELEN).to_vec(),
        mnton: cstr_at(rec, sf::MNTONNAME, sf::MNAMELEN).to_vec(),
    })
}

/// `getfsstat(2)`'s buffer: `struct statfs`es back to back.
pub fn statfs_list(buf: &[u8]) -> Vec<StatFs> {
    buf.chunks_exact(sf::SIZE).filter_map(statfs).collect()
}

/// An Internet address and port from a `sockaddr_in` or `sockaddr_in6`
/// held in a `sockaddr_storage`, by the family the socket has rather than the
/// one the bytes claim (the C casts by `kf_sock_domain`). The port is in
/// network order.
pub fn inet_addr(sa: &[u8], family: i32) -> Option<SocketAddr> {
    let port = u16::from_be_bytes(bytes_at(sa, 2)?);
    let ip = match family {
        sock::AF_INET => IpAddr::V4(Ipv4Addr::from(bytes_at::<4>(sa, 4)?)),
        sock::AF_INET6 => IpAddr::V6(Ipv6Addr::from(bytes_at::<16>(sa, 8)?)),
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// An AF_UNIX socket's bound path, from its `sockaddr_un`, as the C cuts it
/// (`dsock.c`): `sun_len` less the two bytes before `sun_path`, the whole of
/// `sun_path` less one when that is out of range, then to the first NUL.
pub fn unix_path(sa: &[u8]) -> &[u8] {
    let sun_len = sa.first().copied().map_or(0, usize::from);
    let len = match sun_len.checked_sub(sock::SUN_PATH) {
        Some(n) if n < sock::SUN_PATH_LEN => n,
        _ => sock::SUN_PATH_LEN - 1,
    };
    cstr_at(sa, sock::SUN_PATH, len)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::layout::{PROC_AMD64, PROC_I386, XTCPCB, XUNPCB};

    pub fn put(b: &mut [u8], off: usize, v: &[u8]) {
        b[off..off + v.len()].copy_from_slice(v);
    }

    fn proc_rec(l: &ProcLayout, pid: i32, comm: &[u8]) -> Vec<u8> {
        let mut r = vec![0u8; l.size];
        put(&mut r, 0, &(l.size as i32).to_ne_bytes());
        put(&mut r, l.pid, &pid.to_ne_bytes());
        put(&mut r, l.ppid, &1i32.to_ne_bytes());
        put(&mut r, l.pgid, &pid.to_ne_bytes());
        put(&mut r, l.uid, &1001u32.to_ne_bytes());
        r[l.stat] = 3;
        put(&mut r, l.comm, comm);
        r
    }

    #[test]
    fn processes_read_on_both_layouts() {
        for l in [PROC_AMD64, PROC_I386] {
            let mut buf = proc_rec(&l, 42, b"sh");
            buf.extend(proc_rec(&l, 43, &[b'x'; 25]));
            buf.extend([1, 2, 3]); // a tail too short to be a record
            let p = procs(&buf, Some(&l)).unwrap();
            assert_eq!(p.len(), 2);
            assert_eq!(
                (p[0].pid, p[0].ppid, p[0].pgid, p[0].uid, p[0].stat),
                (42, 1, 42, 1001, 3)
            );
            assert_eq!(p[0].comm, b"sh");
            // No NUL in the field: the field's 20 bytes, and no more.
            assert_eq!(p[1].comm.len(), layout::COMMLEN + 1);
        }
    }

    #[test]
    fn a_kinfo_proc_of_another_size_is_refused_not_misread() {
        let buf = proc_rec(&PROC_I386, 42, b"sh");
        let err = procs(&buf, Some(&PROC_AMD64)).map(|_| ());
        assert!(
            err.is_ok(),
            "768 bytes is no whole 1088-byte record: nothing to read"
        );
        let mut two = proc_rec(&PROC_AMD64, 1, b"a");
        put(&mut two, 0, &768i32.to_ne_bytes());
        assert_eq!(
            procs(&two, Some(&PROC_AMD64)).unwrap_err().0,
            "kinfo_proc is 768 bytes here; this lsof reads 1088"
        );
        assert!(procs(&two, None).is_err());
    }

    pub fn kf_rec(kind: i32, fd: i32, path: &[u8]) -> Vec<u8> {
        let size = (kf::PATH + path.len() + 1).div_ceil(8) * 8;
        let mut r = vec![0u8; size];
        put(&mut r, kf::STRUCTSIZE, &(size as i32).to_ne_bytes());
        put(&mut r, kf::TYPE, &kind.to_ne_bytes());
        put(&mut r, kf::FD, &fd.to_ne_bytes());
        put(&mut r, kf::PATH, path);
        r
    }

    #[test]
    fn packed_file_records_are_cut_by_their_own_size() {
        let mut buf = kf_rec(kf::TYPE_VNODE, -1, b"/home/u");
        buf.extend(kf_rec(kf::TYPE_SOCKET, 3, b""));
        let f = files(&buf);
        assert_eq!(f.len(), 2);
        assert_eq!(
            (f[0].kind(), f[0].fd(), f[0].path()),
            (1, -1, &b"/home/u"[..])
        );
        assert_eq!((f[1].kind(), f[1].fd(), f[1].path()), (2, 3, &b""[..]));
        // A field past the record's end reads as 0, not as the next record.
        assert_eq!(f[1].pipe_size(), 0);
    }

    #[test]
    fn a_record_size_that_cannot_be_trusted_ends_the_list() {
        let good = kf_rec(kf::TYPE_VNODE, 0, b"/a");
        for bad in [0i32, -8, 8, (kf::MAX_SIZE + 8) as i32, i32::MAX] {
            let mut buf = good.clone();
            let mut next = kf_rec(kf::TYPE_VNODE, 1, b"/b");
            put(&mut next, 0, &bad.to_ne_bytes());
            buf.extend(next);
            assert_eq!(files(&buf).len(), 1, "size {bad}");
        }
        // A size longer than what is left.
        let mut cut = good.clone();
        cut.extend(&kf_rec(kf::TYPE_VNODE, 1, b"/b")[..200]);
        assert_eq!(files(&cut).len(), 1);
        assert!(files(&[]).is_empty());
        assert!(files(&[1, 2, 3]).is_empty());
    }

    #[test]
    fn a_path_with_no_nul_stops_at_the_record() {
        let mut r = kf_rec(kf::TYPE_VNODE, 0, b"/abc");
        let n = r.len();
        for b in &mut r[kf::PATH..n] {
            *b = b'z';
        }
        let f = files(&r);
        assert_eq!(f[0].path().len(), n - kf::PATH);
    }

    fn pcb_buf(l: &PcbLayout, head: usize, recs: &[(u64, u64, i32)], tail: usize) -> Vec<u8> {
        let mut b = vec![0u8; head];
        put(&mut b, 0, &(head as u64).to_ne_bytes());
        for &(pcb, so, st) in recs {
            let mut r = vec![0u8; l.len as usize];
            put(&mut r, 0, &l.len.to_ne_bytes());
            put(&mut r, l.so_pcb, &pcb.to_ne_bytes());
            put(&mut r, l.xso_so, &so.to_ne_bytes());
            if let Some(o) = l.t_state {
                put(&mut r, o, &st.to_ne_bytes());
            }
            b.extend(r);
        }
        if tail > 0 {
            let mut t = vec![0u8; tail];
            put(&mut t, 0, &(tail as u64).to_ne_bytes());
            b.extend(t);
        }
        b
    }

    #[test]
    fn a_pcblist_is_read_between_its_generation_records() {
        let b = pcb_buf(&XTCPCB, 64, &[(0x10, 0x11, 1), (0x20, 0x21, 4)], 64);
        let m = pcblist(&b, &XTCPCB);
        assert_eq!(m.len(), 2);
        assert_eq!(
            m[&0x20],
            Pcb {
                so: 0x21,
                t_state: Some(4)
            }
        );
        let u = pcb_buf(&XUNPCB, 32, &[(0x30, 0x31, 0)], 32);
        assert_eq!(
            pcblist(&u, &XUNPCB)[&0x30],
            Pcb {
                so: 0x31,
                t_state: None
            }
        );
        // A record cut short, a head that points past the end, nothing.
        let mut cut = pcb_buf(&XTCPCB, 64, &[(0x10, 0x11, 1)], 0);
        cut.truncate(64 + 100);
        assert!(pcblist(&cut, &XTCPCB).is_empty());
        let mut far = b.clone();
        put(&mut far, 0, &u64::MAX.to_ne_bytes());
        assert!(pcblist(&far, &XTCPCB).is_empty());
        assert!(pcblist(&[], &XTCPCB).is_empty());
    }

    #[test]
    fn locks_are_read_and_a_lock_with_no_mode_is_none() {
        let rec = |rw: i32, pid: i32| {
            let mut r = vec![0u8; kl::SIZE];
            put(&mut r, 0, &(kl::SIZE as i32).to_ne_bytes());
            put(&mut r, kl::RW, &rw.to_ne_bytes());
            put(&mut r, kl::PID, &pid.to_ne_bytes());
            put(&mut r, kl::FILE_FSID, &7u64.to_ne_bytes());
            put(&mut r, kl::FILE_FILEID, &9u64.to_ne_bytes());
            r
        };
        let mut b = rec(kl::RW_WRITE, 5);
        b.extend(rec(0, 6));
        b.extend(rec(kl::RW_READ, 7));
        let l = locks(&b);
        assert_eq!(l.len(), 2);
        assert!(l[0].write && l[0].pid == 5 && l[0].fsid == 7 && l[0].fileid == 9);
        assert!(!l[1].write && l[1].pid == 7);
    }

    #[test]
    fn socket_addresses_are_read_by_the_sockets_family() {
        let mut v4 = [0u8; 128];
        v4[0] = 16;
        v4[1] = 2;
        put(&mut v4, 2, &443u16.to_be_bytes());
        put(&mut v4, 4, &[127, 0, 0, 1]);
        assert_eq!(
            inet_addr(&v4, sock::AF_INET),
            Some("127.0.0.1:443".parse().unwrap())
        );
        let mut v6 = [0u8; 128];
        put(&mut v6, 2, &22u16.to_be_bytes());
        v6[23] = 1;
        assert_eq!(
            inet_addr(&v6, sock::AF_INET6),
            Some("[::1]:22".parse().unwrap())
        );
        assert_eq!(inet_addr(&v6[..10], sock::AF_INET6), None);
        assert_eq!(inet_addr(&v6, sock::AF_UNIX), None);
    }

    #[test]
    fn a_unix_path_is_cut_as_the_c_cuts_it() {
        let mut sa = [0u8; 128];
        put(&mut sa, 2, b"/tmp/s.sock");
        sa[0] = 2 + 11 + 1;
        assert_eq!(unix_path(&sa), b"/tmp/s.sock");
        // sun_len shorter than the name: the name is cut there.
        sa[0] = 2 + 4;
        assert_eq!(unix_path(&sa), b"/tmp");
        // Out of range: the whole field less one, to the NUL.
        sa[0] = 255;
        assert_eq!(unix_path(&sa), b"/tmp/s.sock");
        sa[0] = 0;
        assert_eq!(unix_path(&sa), b"/tmp/s.sock");
        assert_eq!(unix_path(&[]), b"");
    }

    #[test]
    fn statfs_records_are_read_whole_or_not_at_all() {
        let mut r = vec![0u8; sf::SIZE];
        put(&mut r, sf::TYPE, &0x35u32.to_ne_bytes());
        put(&mut r, sf::FSID, &0x5a00ff01u32.to_ne_bytes());
        put(&mut r, sf::FSTYPENAME, b"zfs");
        put(&mut r, sf::MNTFROMNAME, b"zroot/ROOT/default");
        put(&mut r, sf::MNTONNAME, b"/");
        let s = statfs(&r).unwrap();
        assert_eq!(
            (
                s.ftype,
                s.fsid0,
                &s.fstypename[..],
                &s.mntfrom[..],
                &s.mnton[..]
            ),
            (
                0x35,
                0x5a00ff01,
                &b"zfs"[..],
                &b"zroot/ROOT/default"[..],
                &b"/"[..]
            )
        );
        assert_eq!(statfs(&r[..100]), None);
        let mut two = r.clone();
        two.extend(&r);
        two.extend([0; 10]);
        assert_eq!(statfs_list(&two).len(), 2);
    }

    #[test]
    fn xfiles_are_keyed_by_pid_and_fd() {
        let mut r = vec![0u8; xf::SIZE];
        put(&mut r, 0, &(xf::SIZE as u64).to_ne_bytes());
        put(&mut r, xf::PID, &9i32.to_ne_bytes());
        put(&mut r, xf::FD, &4i32.to_ne_bytes());
        put(&mut r, xf::FILE, &0xffff_f800_0000_1000u64.to_ne_bytes());
        assert_eq!(xfiles(&r)[&(9, 4)], 0xffff_f800_0000_1000);
        assert!(xfiles(&r[..64]).is_empty());
    }
}
