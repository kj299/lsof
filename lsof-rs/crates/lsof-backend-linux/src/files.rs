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
pub(crate) fn dev_string(dev: u64) -> String {
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

/// Access mode and file position for one fd, from `/proc/<pid>/fdinfo/<fd>`.
///
/// Two lines matter: `flags:` (octal; the low two bits are `O_ACCMODE`) and
/// `pos:` (decimal; the kernel's current file offset). Absent or unreadable
/// fdinfo yields `Unknown` and no offset, which render as lsof's `-` and an
/// empty cell. The position is what lsof shows as `0t<n>` in SIZE/OFF for any
/// file without a meaningful size — a device node, a FIFO — and what `-o`
/// asks for on every file; it was the first fidelity gap the C-vs-Rust
/// differential found, on its first fixture.
fn fdinfo_for(pid: u32, fd: &str) -> FdInfo {
    match std::fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd}")) {
        Ok(info) => parse_fdinfo(&info),
        Err(_) => FdInfo::default(),
    }
}

/// The C caps the fds it lists for an eventpoll at 32 and writes `...]` when
/// there were more (`EPOLL_MAX_TFDS`, `lib/dialects/linux/dproc.c:95`).
const EPOLL_MAX_TFDS: usize = 32;

/// What `/proc/<pid>/fdinfo/<fd>` tells us about one fd.
///
/// Beyond the access mode and offset every fd has, three anon-inode kinds
/// carry an identity here that lsof puts in NAME: an eventfd's id, a pidfd's
/// target pid, and the set of fds an eventpoll is watching.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FdInfo {
    pub access: Option<AccessMode>,
    pub pos: Option<u64>,
    /// `eventfd-id:` — *not* the counter value (`eventfd-count:`) and not the
    /// fd number; the C prints this one.
    pub eventfd_id: Option<i64>,
    /// `Pid:` on a pidfd — the process it refers to.
    pub pidfd_pid: Option<i64>,
    /// `tfd:` lines — the fds an eventpoll watches, ascending, capped.
    pub tfds: Vec<i64>,
    /// There were more than [`EPOLL_MAX_TFDS`] of them, so the list is cut.
    pub tfds_truncated: bool,
}

impl FdInfo {
    /// The access mode, defaulting to unknown when `flags:` was absent.
    pub fn access(&self) -> AccessMode {
        self.access.unwrap_or(AccessMode::Unknown)
    }
}

/// The parsing half of [`fdinfo_for`], over the file's text. Pure, so the fuzz
/// target can drive it with arbitrary bytes; must never panic.
pub fn parse_fdinfo(info: &str) -> FdInfo {
    let mut out = FdInfo::default();
    for line in info.lines() {
        if let Some(v) = line.strip_prefix("flags:") {
            if let Ok(flags) = u32::from_str_radix(v.trim(), 8) {
                out.access = Some(match flags & 0o3 {
                    0 => AccessMode::Read,
                    1 => AccessMode::Write,
                    2 => AccessMode::ReadWrite,
                    _ => AccessMode::Unknown,
                });
            }
        } else if let Some(v) = line.strip_prefix("pos:") {
            out.pos = v.trim().parse::<u64>().ok();
        } else if let Some(v) = line.strip_prefix("eventfd-id:") {
            out.eventfd_id = v.trim().parse::<i64>().ok();
        } else if let Some(v) = line.strip_prefix("Pid:") {
            out.pidfd_pid = v.trim().parse::<i64>().ok();
        } else if let Some(v) = line.strip_prefix("tfd:") {
            // `tfd:  6 events: 1f data: ... pos:0 ino:28d1 sdev:9`
            if let Some(Ok(fd)) = v.split_whitespace().next().map(str::parse::<i64>) {
                if out.tfds.len() < EPOLL_MAX_TFDS {
                    out.tfds.push(fd);
                } else {
                    out.tfds_truncated = true;
                }
            }
        }
    }
    // The C sorts before printing; fdinfo lists them most-recent first.
    out.tfds.sort_unstable();
    out
}

/// The NAME cell for a magic-link target. Real paths pass through. A pipe's
/// target is `pipe:[inode]`, and lsof prints just `pipe` — the inode is
/// already the NODE cell, so repeating it in NAME is noise the C does not
/// emit. Sockets are resolved elsewhere (`net`), and any other synthetic
/// target (`anon_inode:[eventfd]`) is kept verbatim until L2 names those.
pub fn name_for_target(target: &str, info: &FdInfo) -> String {
    if target.starts_with("pipe:[") && target.ends_with(']') {
        return "pipe".to_string();
    }
    // An anonymous inode: the kernel writes `anon_inode:<kind>`, and lsof drops
    // the prefix and prints the kind. Three kinds carry an identity in fdinfo
    // that the C substitutes in (`lib/dialects/linux/dproc.c:1283-1301`);
    // every other kind — `inotify`, `[timerfd]`, `[signalfd]`, `[io_uring]` —
    // prints its bare kind.
    if let Some(kind) = target.strip_prefix("anon_inode:") {
        return match kind {
            "[eventfd]" => match info.eventfd_id {
                Some(id) => format!("[eventfd:{id}]"),
                None => kind.to_string(),
            },
            "[pidfd]" => match info.pidfd_pid {
                Some(pid) => format!("[pidfd:{pid}]"),
                None => kind.to_string(),
            },
            "[eventpoll]" if !info.tfds.is_empty() => {
                let fds: Vec<String> = info.tfds.iter().map(i64::to_string).collect();
                let more = if info.tfds_truncated { "..." } else { "" };
                format!("[eventpoll:{}{more}]", fds.join(","))
            }
            _ => kind.to_string(),
        };
    }
    target.to_string()
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
///
/// `offset` is the fd's file position from fdinfo (`None` for the `cwd`/
/// `rtd`/`txt` specials, which have none).
fn row(link: &Path, fd: FdType, info: &FdInfo, socks: &SocketTable) -> Option<OpenFile> {
    let access = info.access();
    let offset = info.pos;
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
                lock: None,
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
            // An anonymous inode stats as a regular file, but lsof types it
            // `a_inode` — the kernel object has no filesystem identity, and
            // saying REG would invite `-d` and size comparisons that mean
            // nothing. The link target is the only thing that reveals it.
            let ty = if name.starts_with("anon_inode:") {
                FileType::Other("a_inode".into())
            } else {
                type_from_mode(m.mode())
            };
            // DEVICE means two different things depending on the row, and lsof
            // follows the distinction: for a device node it is that device's
            // own number (`st_rdev` — /dev/null is `1,3`), for everything else
            // it is the filesystem the file lives on (`st_dev`).
            let dev = match ty {
                FileType::Chr | FileType::Block => m.rdev(),
                _ => m.dev(),
            };
            // SIZE/OFF: lsof shows a size only where one means something. A
            // device node or a FIFO has an st_size of 0 that describes nothing,
            // so the C prints the offset (`0t0`) there and the size for regular
            // files and directories. Withholding the size for those types lets
            // the shared renderer fall through to the offset, matching the C
            // without a platform branch in `lsof-core`.
            let size = match ty {
                FileType::Chr | FileType::Block | FileType::Fifo => None,
                _ => Some(m.size()),
            };
            (
                ty,
                Some(dev_string(dev)),
                size,
                Some(m.ino().to_string()),
                u32::try_from(m.nlink()).ok(),
            )
        }
        None => (FileType::Unknown, None, None, None, None),
    };

    Some(OpenFile {
        lock: None,
        fd,
        access,
        file_type,
        name: name_for_target(&name, info),
        device,
        size,
        offset,
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
pub fn for_pid(
    pid: u32,
    socks: &SocketTable,
    locks: &crate::locks::LockTable,
) -> Option<Vec<OpenFile>> {
    let mut out = Vec::new();

    // The specials. Unlike fds these have no access mode of their own.
    for (name, fd) in [
        ("cwd", FdType::Cwd),
        ("root", FdType::Root),
        ("exe", FdType::Txt),
    ] {
        let p = format!("/proc/{pid}/{name}");
        if let Some(f) = row(Path::new(&p), fd, &FdInfo::default(), socks) {
            out.push(f);
        }
    }

    // Mapped files, after the specials and before the numbered fds — the
    // order the C emits them in. The txt row, if there is one, identifies the
    // executable's own mapping so it is not listed a second time as `mem`.
    let exe = out
        .iter()
        .find(|f| f.fd == FdType::Txt)
        .and_then(|f| Some((f.device.as_deref()?, f.node.as_deref()?)));
    out.extend(crate::maps::rows_for(pid, exe));

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
        let info = fdinfo_for(pid, &name);
        if let Some(mut f) = row(Path::new(&p), FdType::Handle(num), &info, socks) {
            // The lock character lsof appends to the FD cell (`8uW`). Only a
            // numbered fd can hold one: the specials and the mapped-file rows
            // are not open file descriptions.
            if let (Some(dev), Some(node)) = (f.device.as_deref(), f.node.as_deref()) {
                f.lock = locks
                    .get(&(pid, dev.to_string(), node.to_string()))
                    .copied();
            }
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
            &FdInfo {
                access: Some(AccessMode::Read),
                ..FdInfo::default()
            },
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
        let files = for_pid(pid, &SocketTable::load(false), &crate::locks::load())
            .expect("own /proc/<pid>/fd is readable");

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

    fn self_pid() -> u32 {
        std::fs::read_to_string("/proc/self/stat")
            .expect("/proc/self/stat readable")
            .split(' ')
            .next()
            .and_then(|s| s.parse().ok())
            .expect("pid parses")
    }

    #[test]
    fn pipe_target_is_named_pipe_everything_else_passes_through() {
        // The C prints `pipe` for a pipe fd; the inode is already NODE. Found by
        // the first C-vs-Rust differential fixture, which showed `pipe:[12047]`.
        let none = FdInfo::default();
        assert_eq!(name_for_target("pipe:[12047]", &none), "pipe");
        assert_eq!(name_for_target("/etc/passwd", &none), "/etc/passwd");
        assert_eq!(name_for_target("socket:[99]", &none), "socket:[99]");
        // Not a pipe target, merely a path that starts like one.
        assert_eq!(
            name_for_target("pipe:[unterminated", &none),
            "pipe:[unterminated"
        );
    }

    #[test]
    fn anon_inode_kinds_are_named_the_way_the_c_names_them() {
        // The kernel writes `anon_inode:<kind>`; lsof drops the prefix and
        // prints the kind, substituting an identity from fdinfo for the three
        // kinds that have one. Every string here was read off the real C.
        let none = FdInfo::default();
        assert_eq!(name_for_target("anon_inode:inotify", &none), "inotify");
        assert_eq!(name_for_target("anon_inode:[timerfd]", &none), "[timerfd]");
        // eventfd: the *id*, not the counter and not the fd number.
        let ev = parse_fdinfo("pos:\t0\neventfd-count:\t7\neventfd-id: 6\n");
        assert_eq!(name_for_target("anon_inode:[eventfd]", &ev), "[eventfd:6]");
        // pidfd: the process it refers to.
        let pf = parse_fdinfo("pos:\t0\nPid:\t4242\nNSpid:\t4242\n");
        assert_eq!(name_for_target("anon_inode:[pidfd]", &pf), "[pidfd:4242]");
        // eventpoll: the watched fds, ascending, however fdinfo ordered them.
        let ep = parse_fdinfo(
            "pos:\t0\ntfd:        6 events: 1f data: 0 pos:0 ino:1 sdev:9\n\
             tfd:        4 events: 1f data: 0 pos:0 ino:2 sdev:9\n",
        );
        assert_eq!(
            name_for_target("anon_inode:[eventpoll]", &ep),
            "[eventpoll:4,6]"
        );
        // An eventpoll watching nothing keeps the bare kind, as the C does
        // (it substitutes only when tfd_count > 0).
        assert_eq!(
            name_for_target("anon_inode:[eventpoll]", &none),
            "[eventpoll]"
        );
        // More than the C's 32-fd cap: the list is cut and marked.
        let many: String = (1..=40)
            .map(|n| format!("tfd:  {n} events: 1f data: 0\n"))
            .collect();
        let big = parse_fdinfo(&many);
        let name = name_for_target("anon_inode:[eventpoll]", &big);
        assert!(name.ends_with("...]"), "cap must be visible: {name}");
        assert_eq!(name.matches(',').count(), 31, "32 fds listed: {name}");
    }

    #[test]
    fn fdinfo_reports_access_and_the_kernel_file_position() {
        use std::io::Write;
        use std::os::unix::io::AsRawFd;
        // Write five bytes: the kernel's `pos:` for this fd must read 5, and the
        // flags must decode to write-only. Real fdinfo on a real fd — no fixture
        // text — so a format change in the kernel would fail here, not in CI's
        // differential.
        let dir = std::env::temp_dir().join(format!("lsof_rs_fdinfo_{}", self_pid()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut f = std::fs::File::create(dir.join("five")).unwrap();
        f.write_all(b"12345").unwrap();
        let info = fdinfo_for(self_pid(), &f.as_raw_fd().to_string());
        assert_eq!(info.access(), AccessMode::Write);
        assert_eq!(info.pos, Some(5), "pos: must track the write position");
        drop(f);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pipe_fd_is_a_fifo_named_pipe_with_offset_not_size() {
        use std::os::unix::io::AsRawFd;
        // An anonymous pipe is the exact shape the C showed: FIFO, NAME `pipe`,
        // SIZE/OFF as offset (`0t0`) because a pipe's st_size means nothing.
        let (reader, _writer) = std::io::pipe().expect("pipe(2)");
        let raw = reader.as_raw_fd();
        let link = format!("/proc/self/fd/{raw}");
        let info = fdinfo_for(self_pid(), &raw.to_string());
        let f = row(
            Path::new(&link),
            FdType::Handle(raw as u64),
            &info,
            &SocketTable::default(),
        )
        .expect("pipe fd is stat-able");
        assert_eq!(f.file_type, FileType::Fifo);
        assert_eq!(f.name, "pipe");
        assert_eq!(f.size, None, "a FIFO has no meaningful size");
        assert_eq!(f.offset, Some(0), "offset is shown instead, as the C does");
        assert_eq!(f.access, AccessMode::Read);
    }

    #[test]
    fn fdinfo_text_is_parsed_defensively() {
        // The pure half of fdinfo_for, over text rather than a live fd.
        let ap = |s: &str| {
            let i = parse_fdinfo(s);
            (i.access(), i.pos)
        };
        assert_eq!(
            ap("pos:\t5\nflags:\t0100001\n"),
            (AccessMode::Write, Some(5))
        );
        assert_eq!(ap("flags:\t02\n"), (AccessMode::ReadWrite, None));
        assert_eq!(ap("pos:\t12\n"), (AccessMode::Unknown, Some(12)));
        // Non-octal flags, a negative or absurd pos, junk lines, no newline at
        // all: each degrades to Unknown/None, none may panic.
        assert_eq!(ap("flags:\t9z\n"), (AccessMode::Unknown, None));
        assert_eq!(ap("pos:\t-1\n"), (AccessMode::Unknown, None));
        assert_eq!(ap("pos:\t99999999999999999999999\n").1, None);
        assert_eq!(ap(""), (AccessMode::Unknown, None));
        assert_eq!(ap("flags:pos:flags:\u{FFFD}"), (AccessMode::Unknown, None));
        // A repeated line: the last one wins, which is what a real kernel could
        // never produce and a fuzzer always will.
        assert_eq!(ap("pos:\t1\npos:\t2\n").1, Some(2));
        // The anon-inode identities degrade the same way.
        assert_eq!(parse_fdinfo("eventfd-id: nope\n").eventfd_id, None);
        assert_eq!(
            parse_fdinfo("tfd: nope events: 1\n").tfds,
            Vec::<i64>::new()
        );
    }
}
