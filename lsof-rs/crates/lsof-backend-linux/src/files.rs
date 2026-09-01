//! A process's open files, from `/proc/<pid>/{fd,cwd,root,exe}`.

use std::os::unix::fs::MetadataExt;
use std::path::Path;

use lsof_core::model::{AccessMode, FdType, FileType, OpenFile};

use crate::net::{self, SocketTable};

/// `st_mode` file-type mask and its values (POSIX `S_IFMT` and friends). Spelled
/// out rather than pulled from `libc` — they are fixed by the ABI.
const S_IFMT: u32 = 0o170000;
const S_IFSOCK: u32 = 0o140000;
const S_IFLNK: u32 = 0o120000;
const S_IFREG: u32 = 0o100000;
const S_IFBLK: u32 = 0o060000;
const S_IFDIR: u32 = 0o040000;
const S_IFCHR: u32 = 0o020000;
const S_IFIFO: u32 = 0o010000;

/// Decode Linux's packed `dev_t` into lsof's `major,minor` DEVICE column.
/// The layout is glibc's: 12 low + 20 high bits of major, 8 low + 12 high of
/// minor, interleaved.
fn dev_string(dev: u64) -> String {
    let major = ((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfffu64);
    let minor = (dev & 0xff) | ((dev >> 12) & !0xffu64);
    format!("{major},{minor}")
}

fn type_from_mode(mode: u32) -> FileType {
    match mode & S_IFMT {
        S_IFREG => FileType::Regular,
        S_IFDIR => FileType::Dir,
        S_IFCHR => FileType::Chr,
        S_IFBLK => FileType::Block,
        // A pipe and a FIFO are the same object to the kernel; lsof prints FIFO.
        S_IFIFO => FileType::Fifo,
        S_IFLNK => FileType::Other("LINK".into()),
        // Reached only when the /proc/net join missed — a socket in another
        // network namespace, or a family not read (netlink, packet). The row is
        // still real, and its `socket:[inode]` name is the key that would
        // resolve it, so it is reported unresolved rather than guessed at.
        S_IFSOCK => FileType::Other("SOCK".into()),
        _ => FileType::Unknown,
    }
}

/// Access mode for one fd, from `/proc/<pid>/fdinfo/<fd>`'s `flags:` line.
///
/// The flags are octal and their low two bits are `O_ACCMODE`. Absent or
/// unreadable fdinfo yields `Unknown`, which renders as lsof's `-`.
fn access_for(pid: u32, fd: &str) -> AccessMode {
    let Ok(info) = std::fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd}")) else {
        return AccessMode::Unknown;
    };
    let Some(flags) = info.lines().find_map(|l| l.strip_prefix("flags:")) else {
        return AccessMode::Unknown;
    };
    let Ok(flags) = u32::from_str_radix(flags.trim(), 8) else {
        return AccessMode::Unknown;
    };
    match flags & 0o3 {
        0 => AccessMode::Read,
        1 => AccessMode::Write,
        2 => AccessMode::ReadWrite,
        _ => AccessMode::Unknown,
    }
}

/// Build one row from a path under `/proc` that is a magic symlink (an fd, or
/// `cwd`/`root`/`exe`).
///
/// Both halves are best-effort and independently fallible:
/// * `read_link` gives the NAME — a real path for files, or a synthetic target
///   like `socket:[12345]`, `pipe:[12345]`, `anon_inode:[eventfd]`.
/// * `metadata` *follows* the magic link, so the kernel reports the underlying
///   file object's stat even for sockets and pipes that have no path.
///
/// A row is emitted if either succeeds; an fd we can see but cannot stat is
/// still worth showing.
fn row(link: &Path, fd: FdType, access: AccessMode, socks: &SocketTable) -> Option<OpenFile> {
    let target = std::fs::read_link(link).ok();
    let meta = std::fs::metadata(link).ok();
    if target.is_none() && meta.is_none() {
        return None;
    }

    let name = target
        .map(|t| t.to_string_lossy().into_owned())
        .unwrap_or_default();

    // A socket fd's link target carries only `socket:[inode]`; the inode is the
    // join key into /proc/net. A hit replaces the L0 row wholesale — real TYPE
    // (IPv4/IPv6/unix), protocol, addresses and state. A miss keeps the L0 row
    // exactly as it was, which is the honest result for a socket in another
    // network namespace.
    if let Some(inode) = net::socket_inode(&name) {
        if let Some(e) = socks.get(inode) {
            // NAME for AF_UNIX is the bound path plus lsof's `type=` tail; an
            // anonymous socket has no path and shows the tail alone.
            let name = match &e.unix_suffix {
                Some(suffix) => match &e.path {
                    Some(p) => format!("{p} {suffix}"),
                    None => suffix.clone(),
                },
                None => e.info.display_name(false, false),
            };
            return Some(OpenFile {
                fd,
                access,
                file_type: e.file_type.clone(),
                name,
                device: Some(e.device.clone()),
                size: None,
                // lsof prints `0t0` in SIZE/OFF for every socket row — a socket
                // has no size, and its offset is meaningless but always shown.
                offset: Some(0),
                node: Some(e.node.clone()),
                links: None,
                socket: Some(e.info.clone()),
            });
        }
    }

    let (file_type, device, size, node, links) = match &meta {
        Some(m) => {
            let ty = type_from_mode(m.mode());
            // DEVICE means two different things depending on the row, and lsof
            // follows the distinction: for a device node it is that device's
            // own number (`st_rdev` — /dev/null is `1,3`), for everything else
            // it is the filesystem the file lives on (`st_dev`).
            let dev = match ty {
                FileType::Chr | FileType::Block => m.rdev(),
                _ => m.dev(),
            };
            (
                ty,
                Some(dev_string(dev)),
                Some(m.size()),
                Some(m.ino().to_string()),
                u32::try_from(m.nlink()).ok(),
            )
        }
        None => (FileType::Unknown, None, None, None, None),
    };

    Some(OpenFile {
        fd,
        access,
        file_type,
        name,
        device,
        size,
        offset: None,
        node,
        links,
        socket: None,
    })
}

/// Every open file of one process: the `cwd`/`rtd`/`txt` specials plus each
/// numbered fd.
///
/// Returns `None` when `/proc/<pid>/fd` cannot be opened at all — the process
/// exited, or it belongs to another user and we are not root. The caller
/// distinguishes those (a vanished pid vs. a permission wall) only in aggregate,
/// which is enough for the `-V` inaccessible count.
pub fn for_pid(pid: u32, socks: &SocketTable) -> Option<Vec<OpenFile>> {
    let mut out = Vec::new();

    // The specials. Unlike fds these have no access mode of their own.
    for (name, fd) in [
        ("cwd", FdType::Cwd),
        ("root", FdType::Root),
        ("exe", FdType::Txt),
    ] {
        let p = format!("/proc/{pid}/{name}");
        if let Some(f) = row(Path::new(&p), fd, AccessMode::Unknown, socks) {
            out.push(f);
        }
    }

    let dir = std::fs::read_dir(format!("/proc/{pid}/fd")).ok()?;
    let mut fds: Vec<(u64, String)> = dir
        .flatten()
        .filter_map(|e| {
            let n = e.file_name().to_str()?.to_string();
            Some((n.parse::<u64>().ok()?, n))
        })
        .collect();
    fds.sort_unstable_by_key(|(n, _)| *n);

    for (num, name) in fds {
        let p = format!("/proc/{pid}/fd/{name}");
        let access = access_for(pid, &name);
        if let Some(f) = row(Path::new(&p), FdType::Handle(num), access, socks) {
            out.push(f);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_maps_to_lsof_type_codes() {
        // The bit patterns are ABI, so pin them against the rendered TYPE code.
        assert_eq!(type_from_mode(S_IFREG | 0o644).code(), "REG");
        assert_eq!(type_from_mode(S_IFDIR | 0o755).code(), "DIR");
        assert_eq!(type_from_mode(S_IFCHR | 0o666).code(), "CHR");
        assert_eq!(type_from_mode(S_IFBLK | 0o660).code(), "BLK");
        assert_eq!(type_from_mode(S_IFIFO | 0o600).code(), "FIFO");
        assert_eq!(type_from_mode(S_IFSOCK | 0o777).code(), "SOCK");
        assert_eq!(type_from_mode(S_IFLNK | 0o777).code(), "LINK");
        assert_eq!(type_from_mode(0).code(), "unknown");
    }

    #[test]
    fn dev_t_decodes_to_major_minor() {
        // Mirrors glibc's gnu_dev_major/minor. The low 16 bits hold the classic
        // 8-bit major / 8-bit minor pair: /dev/sda1 is 8,1 and /dev/null is 1,3.
        assert_eq!(dev_string(0x0801), "8,1");
        assert_eq!(dev_string(0x0103), "1,3");
        // 0,6 — devtmpfs, the st_dev those device nodes live on.
        assert_eq!(dev_string(0x0006), "0,6");
        // A minor above 255 comes from bits 20.., not by overflowing into
        // major: bit 20 set with major 8 must read 8,256 — the case a naive
        // 8-bit-each decode gets wrong.
        assert_eq!(dev_string(0x0010_0800), "8,256");
    }

    #[test]
    fn device_nodes_report_their_own_number_not_the_filesystem() {
        // The DEVICE column means st_rdev for a device node and st_dev for
        // everything else; /dev/null is the canonical check (1,3 not 0,6).
        let f = row(
            Path::new("/dev/null"),
            FdType::Handle(0),
            AccessMode::Read,
            &SocketTable::default(),
        )
        .expect("/dev/null is stat-able");
        assert_eq!(f.file_type, FileType::Chr);
        assert_eq!(f.device.as_deref(), Some("1,3"));
    }

    #[test]
    fn reads_this_process_and_finds_its_own_fds() {
        // The one thing every Linux host can assert without fixtures: a process
        // can always read its own /proc entry, and always has fd 0/1/2.
        let pid: u32 = std::fs::read_to_string("/proc/self/stat")
            .expect("/proc/self/stat readable")
            .split(' ')
            .next()
            .and_then(|s| s.parse().ok())
            .expect("pid parses");
        let files =
            for_pid(pid, &SocketTable::load(false)).expect("own /proc/<pid>/fd is readable");

        assert!(
            files.iter().any(|f| f.fd == FdType::Cwd),
            "expected a cwd row"
        );
        assert!(
            files.iter().any(|f| f.fd == FdType::Txt),
            "expected a txt (exe) row"
        );
        assert!(
            files
                .iter()
                .filter(|f| matches!(f.fd, FdType::Handle(_)))
                .count()
                >= 3,
            "expected at least stdin/stdout/stderr"
        );
        // Every numbered fd should have been stat'd into a concrete type.
        assert!(files
            .iter()
            .filter(|f| matches!(f.fd, FdType::Handle(_)))
            .all(|f| f.file_type != FileType::Unknown));
    }
}
