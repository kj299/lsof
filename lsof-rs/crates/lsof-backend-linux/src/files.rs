//! A process's open files, from `/proc/<pid>/{fd,cwd,root,exe}`.

use std::num::NonZeroU32;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use lsof_core::errno_text;
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
/// The DEVICE cell for a stat result: `st_rdev` for a device node (a
/// character or block special names *its own* device), `st_dev` for everything
/// else (the filesystem the file lives on). Shared with `identify_path` so a
/// path argument and the row it should match are rendered by one rule.
pub(crate) fn dev_cell(md: &std::fs::Metadata) -> String {
    match type_from_mode(md.mode()) {
        FileType::Chr | FileType::Block => dev_string(md.rdev()),
        _ => dev_string(md.dev()),
    }
}

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
fn fdinfo_for(base: &str, fd: &str) -> FdInfo {
    match crate::text::read_lossy(format!("{base}/fdinfo/{fd}")) {
        Some(info) => parse_fdinfo(&info),
        None => FdInfo::default(),
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
    /// The raw `flags:` value, octal in the file. lsof's `-F G` prints it in
    /// hex; the access mode above is its low two bits.
    pub flags: Option<u32>,
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
                out.flags = Some(flags);
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

/// The exempted mount point a path falls under, if any (`-e`).
///
/// Prefix matching, not `stat`: `/` covers everything, and `/dev/shm` covers
/// `/dev/shm/x` but not `/dev/shmx`. A trailing slash on the argument is
/// tolerated, as the C tolerates `-e /dev/shm/`.
fn exempt_match<'a>(path: &str, exempt: &'a [String]) -> Option<&'a str> {
    exempt.iter().find_map(|e| {
        let trimmed = e.trim_end_matches('/');
        let mp = if trimmed.is_empty() { "/" } else { trimmed };
        // An fd whose link target is not an absolute path -- `socket:[14197]`,
        // `pipe:[…]`, `anon_inode:…` -- lives on no file system and is exempt
        // from nothing. Measured: under `-e /` the C still resolves sockets to
        // their `IPv4 … TCP` rows. Testing `mp == "/"` alone swallowed them.
        if !path.starts_with('/') {
            return None;
        }
        let hit = mp == "/"
            || path == mp
            || (path.len() > mp.len() && path.starts_with(mp) && path.as_bytes()[mp.len()] == b'/');
        hit.then_some(e.as_str())
    })
}

/// The C's `UNKN*` TYPE code for an fd kind — `UNKNfd`, `UNKNcwd`, `UNKNrtd`,
/// `UNKNtxt`, `UNKNmem`, `UNKNdel`. Measured: an exempted numeric fd is
/// `UNKNfd`, the cwd is `UNKNcwd`, the executable is `UNKNtxt`.
fn unkn_suffix(fd: &FdType) -> &'static str {
    match fd {
        FdType::Cwd => "cwd",
        FdType::Root => "rtd",
        FdType::Txt => "txt",
        FdType::Mem => "mem",
        FdType::Deleted => "del",
        _ => "fd",
    }
}

/// Everything a row needs that is the same for every row in one gather: the
/// system-wide tables read once, the `-e` exemptions, and whether this run can
/// print anything but sockets. Threading these as separate parameters put
/// `row` at eight arguments; they travel together because they are one thing —
/// the context the walk was started with.
pub struct GatherCtx<'a> {
    pub socks: &'a SocketTable,
    pub locks: &'a crate::locks::LockTable,
    pub ns: &'a net::NetnsTables,
    pub exempt: &'a [String],
    /// `Selection::socket_rows_only`: nothing but a socket can reach the
    /// output, so nothing but a socket is collected.
    pub sockets_only: bool,
    /// `Selection::omit_unreadable` — `-w`, or `-t`: make no row for a file
    /// that cannot be read, rather than one saying why.
    pub omit_unreadable: bool,
}

/// The kernel's name for a socket fd: `socket:[<inode>]`, for every family.
fn is_socket_link(target: &Path) -> bool {
    target
        .to_str()
        .is_some_and(|s| s.starts_with("socket:[") && s.ends_with(']'))
}

/// One row from a path under `/proc` that is a magic symlink (an fd, or
/// `cwd`/`root`/`exe`), whose target has been read: `target` is what
/// `read_link` returned for `link`, and gives the NAME — a real path, or a
/// synthetic target like `socket:[12345]`, `pipe:[12345]`,
/// `anon_inode:[eventfd]`. `metadata` then *follows* the magic link, so the
/// kernel reports the underlying object's stat even for a socket or pipe with
/// no path; when that fails the row stays, saying why (see below). A link
/// that could not be read is [`unreadable`]'s, never this function's — the C
/// does not `stat` a file it could not name. `info.pos` is the fd's position
/// (`None` for the specials, which have none).
fn row(
    link: &Path,
    target: std::path::PathBuf,
    fd: FdType,
    info: &FdInfo,
    pid: u32,
    ctx: &GatherCtx<'_>,
) -> Option<OpenFile> {
    let (socks, ns, exempt, sockets_only) = (ctx.socks, ctx.ns, ctx.exempt, ctx.sockets_only);
    let access = info.access();
    let offset = info.pos;
    let target = Some(target);
    // `sockets_only`: this run can print nothing but sockets
    // (`Selection::socket_rows_only`), so a row that is not one is built only
    // to be dropped. The kernel names every socket fd `socket:[<inode>]` —
    // AF_INET and AF_UNIX alike, which is why one test covers `-i` and `-U` —
    // so the link text decides it, before the `stat` that is the expensive
    // half. The `-e` exemption below cannot resurrect such a row: it matches
    // an absolute path prefix and `socket:[…]` is not a path.
    if sockets_only && !target.as_deref().is_some_and(is_socket_link) {
        return None;
    }
    // `-e <fs>`: never `stat(2)` a file on an exempted file system — that is
    // the whole option, whose reason is a hung NFS server. Membership is a
    // PATH PREFIX test on the link target, which costs a readlink and no stat.
    //
    // Measured against the C, field by field through `-F`: the row keeps what
    // the link and fdinfo give (name, flags, offset) and loses everything
    // `stat` would have supplied — the access letter goes blank, TYPE becomes
    // `UNKN<fd kind>`, DEVICE the literal `UNKNOWN`, and size, inode and link
    // count are absent. NAME gains ` (-e <fs>)`.
    if let Some(t) = target.as_ref() {
        let shown = t.to_string_lossy();
        if let Some(fs) = exempt_match(&shown, exempt) {
            let kind = unkn_suffix(&fd);
            return Some(OpenFile {
                rdev: None,
                fs_device: None,
                file_flags: info.flags,
                lock: None,
                fd,
                access: AccessMode::Unknown,
                file_type: FileType::Other(format!("UNKN{kind}")),
                name: format!("{shown} (-e {fs})"),
                device: Some("UNKNOWN".to_string()),
                size: None,
                // Pass the fdinfo position through rather than defaulting it:
                // a numeric fd has one (`o0t0`), and cwd/rtd/txt have none, so
                // the C leaves their SIZE/OFF cell empty. `unwrap_or(0)` here
                // printed `0t0` on all three.
                offset,
                node: None,
                links: None,
                socket: None,
            });
        }
    }
    let meta = std::fs::metadata(link);
    // What `stat` could not say is said in NAME, as the C says it: the link
    // is named but the file behind it cannot be examined — a dead FUSE mount
    // (`Transport endpoint is not connected`), a file gone between the two
    // calls. The C `lstat`s an fd's link as well and can add `(lstat: …)`;
    // that call fails only in the same race, and costs a syscall per fd on
    // every run, so lsof-rs makes the one call.
    let stat_failure = match &meta {
        Err(e) if !ctx.omit_unreadable => Some(format!(" (stat: {})", errno_text(e))),
        _ => None,
    };
    let meta = meta.ok();

    let name = target
        .map(|t| t.to_string_lossy().into_owned())
        .unwrap_or_default();

    // A socket fd's link target carries only `socket:[inode]`; the inode is the
    // join key into /proc/net. A hit replaces the L0 row wholesale — real TYPE
    // (IPv4/IPv6/unix), protocol, addresses and state. A miss keeps the L0 row
    // exactly as it was, which is the honest result for a socket in another
    // network namespace.
    if let Some(inode) = net::socket_inode(&name) {
        if socks.get(inode).is_none() {
            // Not in this namespace's tables. Before falling back to the bare
            // `socket:[inode]` row, ask for the name the C would print here —
            // the protocol from the owning process's OWN namespace
            // (`sock … protocol: TCP`), or, under `-X`, the fixed string that
            // replaces the lookup entirely.
            if let Some(name) = ns.unresolved_name(pid, inode) {
                return Some(OpenFile {
                    rdev: None,
                    fs_device: None,
                    file_flags: info.flags,
                    lock: None,
                    fd,
                    access,
                    // Lowercase `sock`, the C's LSOF_FILE_SOCKET, and the
                    // OFFSET rather than a size: an unidentified socket has no
                    // size worth printing and the C shows `0t0`.
                    file_type: FileType::Other("sock".into()),
                    name,
                    device: meta.as_ref().map(dev_cell),
                    size: None,
                    offset: Some(offset.unwrap_or(0)),
                    node: Some(inode.to_string()),
                    links: None,
                    socket: None,
                });
            }
        }
        if let Some(e) = socks.get(inode) {
            // NAME for AF_UNIX is the bound path plus lsof's `type=` tail; an
            // anonymous socket — and every AF_PACKET socket, which never has a
            // path — shows the tail alone.
            let name = match &e.type_suffix {
                Some(suffix) => match &e.path {
                    Some(p) => format!("{p} {suffix}"),
                    None => suffix.clone(),
                },
                None => e.info.display_name(false, false),
            };
            return Some(OpenFile {
                rdev: None,
                // A socket has no filesystem device, so `-F D` has nothing to
                // print; its open-file flags are real and come from fdinfo just
                // like any other fd's.
                fs_device: None,
                file_flags: info.flags,
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
                socket: Some(Box::new(e.info.clone())),
            });
        }
    }

    let fs_device = meta.as_ref().map(|m| m.dev());
    let (file_type, device, size, node, links, rdev) = match &meta {
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
            // ...and `-F r` prints that raw number, on a device node and
            // nowhere else (`dnode.c` records `rdev` for N_CHR and N_BLK):
            // `r0x103` for /dev/null (DIVERGENCES 47).
            let rdev = match ty {
                FileType::Chr | FileType::Block => {
                    u32::try_from(m.rdev()).ok().and_then(NonZeroU32::new)
                }
                _ => None,
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
            // No link count for a socket: the C hands a socket inode to
            // `process_proc_sock()` before `process_proc_node()` records one,
            // so `+L` never selects it and NLINK stays blank (DIVERGENCES 42).
            // This is the socket no table named; the rows the tables do name
            // carry none either.
            let links = if m.mode() & S_IFMT == S_IFSOCK {
                None
            } else {
                u32::try_from(m.nlink()).ok()
            };
            (
                ty,
                Some(dev_string(dev)),
                size,
                Some(m.ino().to_string()),
                links,
                rdev,
            )
        }
        None => (FileType::Unknown, None, None, None, None, None),
    };

    let mut name = name_for_target(&name, info);
    if let Some(why) = stat_failure {
        name.push_str(&why);
    }
    Some(OpenFile {
        rdev,
        fs_device,
        file_flags: info.flags,
        lock: None,
        fd,
        access,
        file_type,
        name,
        device,
        size,
        offset,
        node,
        links,
        socket: None,
    })
}

/// The row for a file that is there but could not be read: TYPE `unknown`,
/// every cell a `stat` would fill left blank, and NAME saying what was tried
/// and why it failed — `/proc/1/cwd (readlink: Permission denied)`.
///
/// This is what the C prints for another user's process when it is not root
/// (`dproc.c`, `process_id()`): lsof-rs printed one bare `unk unknown` line
/// instead, so a process nothing could read looked like a process with
/// nothing open. `info` is what fdinfo gave for a numbered fd — nothing, in
/// every case but a race, since the same permission guards both.
fn unreadable(name: String, fd: FdType, info: &FdInfo) -> OpenFile {
    OpenFile {
        rdev: None,
        fs_device: None,
        file_flags: info.flags,
        lock: None,
        fd,
        access: info.access(),
        file_type: FileType::Unknown,
        name,
        device: None,
        size: None,
        offset: info.pos,
        node: None,
        links: None,
        socket: None,
    }
}

/// NAME for a link that could not be read: the path, then the call and the C
/// library's reason for it (see [`lsof_core::errno_text`]).
///
/// One exception, the C's (`(errno != ENOENT) || uid`): the executable link
/// of a process owned by root that is simply not there is shown as the path
/// alone. That is a kernel thread, which has no executable — `kthreadd 2 root
/// txt unknown /proc/2/exe` — and saying `No such file or directory` on
/// every one of them would be noise.
fn unreadable_name(link: &str, fd: &FdType, err: &std::io::Error, root_owned: bool) -> String {
    if *fd == FdType::Txt && err.kind() == std::io::ErrorKind::NotFound && root_owned {
        link.to_string()
    } else {
        format!("{link} (readlink: {})", errno_text(err))
    }
}

/// Every open file of one process: the `cwd`/`rtd`/`txt` specials plus each
/// numbered fd — and, for any of them that could not be read, the row that
/// says so (see [`unreadable`]), unless `-w`/`-t` asked for none. `uid` is the
/// process's owner, which decides one of those rows' wording.
pub fn for_pid(pid: u32, uid: Option<u32>, ctx: &GatherCtx<'_>) -> Vec<OpenFile> {
    for_proc_dir(&format!("/proc/{pid}"), pid, uid, ctx)
}

/// The rows under one `/proc` directory — either a process's own
/// (`/proc/<pid>`) or a task's (`/proc/<pid>/task/<tid>`).
///
/// `-K` lists each task as its own entry repeating the whole file set, and the
/// C reads that set from the task's directory rather than copying the
/// process's: `CLONE_FS` and `CLONE_FILES` are optional, so a thread can hold
/// its own cwd, root and fds — and its mapped files come from its own `maps`
/// too (see [`crate::maps::rows_for`]). `pid` stays the process's, because
/// `/proc/locks` is keyed by process. The paths an unreadable row names are
/// this directory's, as the C's are: `/proc/85/task/86/cwd (readlink: …)`.
pub fn for_proc_dir(base: &str, pid: u32, uid: Option<u32>, ctx: &GatherCtx<'_>) -> Vec<OpenFile> {
    let sockets_only = ctx.sockets_only;
    // A row for what could not be read is never a socket row, so a run that
    // can print only sockets makes none — the C makes them and drops them.
    let report_unreadable = !ctx.omit_unreadable && !sockets_only;
    let mut out = Vec::new();

    // The specials. Unlike fds these have no access mode of their own.
    // None of the three can be a socket, so a socket-only run skips them —
    // and with them the mapped-file walk below, which is the one that costs:
    // `/proc/<pid>/maps` is a read per process and a parse per mapping, and
    // under `-i` the C opens it zero times. Measured at 577 processes:
    // lsof-rs opened 578 maps files for `lsof -i`, the C none.
    for (name, fd) in if sockets_only {
        [].as_slice()
    } else {
        [
            ("cwd", FdType::Cwd),
            ("root", FdType::Root),
            ("exe", FdType::Txt),
        ]
        .as_slice()
    } {
        let p = format!("{base}/{name}");
        match std::fs::read_link(&p) {
            Ok(target) => {
                if let Some(f) = row(
                    Path::new(&p),
                    target,
                    fd.clone(),
                    &FdInfo::default(),
                    pid,
                    ctx,
                ) {
                    out.push(f);
                }
            }
            Err(e) if report_unreadable => {
                let name = unreadable_name(&p, fd, &e, uid == Some(0));
                out.push(unreadable(name, fd.clone(), &FdInfo::default()));
            }
            Err(_) => {}
        }
    }

    // Mapped files, after the specials and before the numbered fds — the
    // order the C emits them in. The txt row, if there is one, identifies the
    // executable's own mapping so it is not listed a second time as `mem`.
    // A `maps` that cannot be read adds nothing, and says nothing: the C
    // returns from `process_proc_map()` without a row.
    if !sockets_only {
        let exe = out
            .iter()
            .find(|f| f.fd == FdType::Txt)
            .and_then(|f| Some((f.device.as_deref()?, f.node.as_deref()?)));
        out.extend(crate::maps::rows_for(base, exe));
    }

    let dir = match std::fs::read_dir(format!("{base}/fd")) {
        Ok(dir) => dir,
        Err(e) => {
            // `NOFD`: the fd table could not be listed at all. One row says
            // so, and the walk ends — the C `return`s after it.
            if report_unreadable {
                out.push(OpenFile {
                    fd: FdType::NoFd,
                    file_type: FileType::NoType,
                    ..unreadable(
                        format!("{base}/fd (opendir: {})", errno_text(&e)),
                        FdType::NoFd,
                        &FdInfo::default(),
                    )
                });
            }
            out.shrink_to_fit();
            return out;
        }
    };
    let mut fds: Vec<(u64, String)> = dir
        .flatten()
        .filter_map(|e| {
            let n = e.file_name().to_str()?.to_string();
            Some((n.parse::<u64>().ok()?, n))
        })
        .collect();
    fds.sort_unstable_by_key(|(n, _)| *n);

    for (num, name) in fds {
        let p = format!("{base}/fd/{name}");
        let info = fdinfo_for(base, &name);
        let target = match std::fs::read_link(&p) {
            Ok(target) => target,
            Err(e) => {
                if report_unreadable {
                    let fd = FdType::Handle(num);
                    let name = unreadable_name(&p, &fd, &e, uid == Some(0));
                    out.push(unreadable(name, fd, &info));
                }
                continue;
            }
        };
        if let Some(mut f) = row(Path::new(&p), target, FdType::Handle(num), &info, pid, ctx) {
            // The lock character lsof appends to the FD cell (`8uW`). Only a
            // numbered fd can hold one: the specials and the mapped-file rows
            // are not open file descriptions.
            if let (Some(dev), Some(node)) = (f.device.as_deref(), f.node.as_deref()) {
                f.lock = ctx
                    .locks
                    .get(&(pid, dev.to_string(), node.to_string()))
                    .copied();
            }
            out.push(f);
        }
    }
    // Every process's rows are held until the whole host has been walked and
    // sorted — the C does the same (`gather_proc_info()` fills `Lproc[]`,
    // `main.c` qsorts it, then prints) — so the growth slack a `Vec` keeps
    // for pushes that will never come is paid once per process for the whole
    // run. Measured at 1079 processes it was the largest single cost: 13.8 MB
    // of `Vec<OpenFile>` capacity holding 5.9 MB of rows (DIVERGENCES 30).
    out.shrink_to_fit();
    out
}

/// Whether the walk of `base` would find anything to show when unreadable
/// files make no rows: a link that reads, or a mapped file.
///
/// `-t`'s fast path asks this instead of walking. The C lists a process only
/// through its files, and `-t` sets `-w`, under which it makes no row for a
/// file it cannot read — so `lsof -t -p 1`, run by a user who cannot read
/// pid 1, prints nothing (DIVERGENCES 37). A process that can be read at all
/// answers on its first `readlink`; one that cannot costs three failed
/// `readlink`s and a failed `opendir`, and never reaches `maps`, which the
/// same permission guards.
pub fn has_readable_file(base: &str) -> bool {
    ["cwd", "root", "exe"]
        .iter()
        .any(|n| std::fs::read_link(format!("{base}/{n}")).is_ok())
        || std::fs::read_dir(format!("{base}/fd")).is_ok_and(|dir| {
            dir.flatten().any(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.parse::<u64>().is_ok())
                    && std::fs::read_link(e.path()).is_ok()
            })
        })
        || !crate::maps::rows_for(base, None).is_empty()
}

#[cfg(test)]
mod tests {
    /// `row` with the socket-only fast path off — what every case below wants,
    /// and what the parameter meant before it existed.
    fn row_all(
        link: &Path,
        fd: FdType,
        info: &FdInfo,
        pid: u32,
        socks: &SocketTable,
        ns: &net::NetnsTables,
        exempt: &[String],
    ) -> Option<OpenFile> {
        let locks = crate::locks::LockTable::default();
        // A path that is not a link (`/dev/null` itself) names its own target.
        let target = std::fs::read_link(link).unwrap_or_else(|_| link.to_path_buf());
        super::row(
            link,
            target,
            fd,
            info,
            pid,
            &GatherCtx {
                socks,
                locks: &locks,
                ns,
                exempt,
                sockets_only: false,
                omit_unreadable: false,
            },
        )
    }

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

    // Excluded from the miri job, not from `cargo test`. Measured under
    // nightly-2026-08-31 (the pinned toolchain the job uses): miri's `stat`
    // shim leaves `st_rdev` zero, so this reads DEVICE `0,0` where the host
    // says `/dev/null` is `rdev=259` -> `1,3`. The code is right and the
    // interpreter is the odd one out; a native run asserts the real number.
    #[test]
    #[cfg_attr(miri, ignore = "miri's stat shim reports st_rdev as 0")]
    fn device_nodes_report_their_own_number_not_the_filesystem() {
        // The DEVICE column means st_rdev for a device node and st_dev for
        // everything else; /dev/null is the canonical check (1,3 not 0,6).
        let f = row_all(
            Path::new("/dev/null"),
            FdType::Handle(0),
            &FdInfo {
                access: Some(AccessMode::Read),
                ..FdInfo::default()
            },
            0,
            &SocketTable::default(),
            &net::NetnsTables::default(),
            &[],
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
        let files = for_pid(
            pid,
            None,
            &GatherCtx {
                socks: &SocketTable::load(false, false),
                locks: &crate::locks::load(),
                ns: &net::NetnsTables::new(false),
                exempt: &[],
                sockets_only: false,
                omit_unreadable: false,
            },
        );
        assert!(
            files.iter().all(|f| f.fd != FdType::NoFd),
            "own /proc/<pid>/fd is readable: {files:?}"
        );

        // The rows are held for the rest of the run, so growth slack is paid
        // for the rest of the run too: 13.8 MB of capacity held 5.9 MB of rows
        // at 1079 processes before this was trimmed (DIVERGENCES 30). Too
        // small an effect on its own for the resource gate to separate on a
        // shared runner, so the capacity itself is the control.
        assert_eq!(
            files.capacity(),
            files.len(),
            "a process's rows keep no spare capacity"
        );

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
        // Our OWN stdio always stats, so those rows must be typed. This is the
        // part of "the backend really types fds" that is actually guaranteed.
        for n in [0u64, 1, 2] {
            let row = files
                .iter()
                .find(|f| f.fd == FdType::Handle(n))
                .unwrap_or_else(|| panic!("no row for fd {n}"));
            assert_ne!(row.file_type, FileType::Unknown, "fd {n}: {row:?}");
        }
        // `Unknown` is reachable and legitimate: it is the row for an fd whose
        // target cannot be read or cannot be `stat`ed, which says why in NAME
        // as the C does (DIVERGENCES, "Fixed by reporting what could not be
        // read"). So the invariant is not "no row is Unknown" — that is
        // stronger than true, and a GitHub runner disproved it after this
        // container and earlier runners had all agreed — but that an Unknown
        // row is *only ever* one that failed to stat, carrying none of the
        // cells a stat would have filled. A typing gap that produced Unknown
        // alongside a device and node would be a real bug, and this catches it.
        for f in files.iter().filter(|f| f.file_type == FileType::Unknown) {
            assert!(
                f.device.is_none() && f.node.is_none() && f.links.is_none(),
                "Unknown must mean the stat failed, not a typing gap: {f:?}"
            );
        }
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
        // Exactly one prefix is dropped: the kind is everything after the
        // FIRST colon, as it is in the C. Found by the proc_fdinfo fuzz target
        // on CI, whose assertion had been the stronger "never starts with
        // anon_inode:" — wrong, not the parser.
        assert_eq!(
            name_for_target("anon_inode:anon_inode:3", &none),
            "anon_inode:3"
        );
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

    // Excluded from the miri job, not from `cargo test`. This test correlates
    // an in-process fd with the kernel's view of it through
    // `/proc/<self>/fdinfo/<fd>`, and miri emulates its own fd table: the
    // number `as_raw_fd()` returns does not name the same file in the host's
    // /proc, so the read describes something else entirely. Same class as
    // miri's `strerror` shim, which forced `errno_text`'s test to be rewritten.
    #[test]
    #[cfg_attr(miri, ignore = "miri's emulated fds do not appear in the host's /proc")]
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
        let info = fdinfo_for(&format!("/proc/{}", self_pid()), &f.as_raw_fd().to_string());
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
        let info = fdinfo_for(&format!("/proc/{}", self_pid()), &raw.to_string());
        let f = row_all(
            Path::new(&link),
            FdType::Handle(raw as u64),
            &info,
            self_pid(),
            &SocketTable::default(),
            &net::NetnsTables::default(),
            &[],
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
    #[test]
    fn an_exempt_match_is_a_path_prefix_and_never_a_socket() {
        let root = vec!["/".to_string()];
        let shm = vec!["/dev/shm".to_string()];
        let shm_slash = vec!["/dev/shm/".to_string()];

        assert_eq!(exempt_match("/usr/bin/python3", &root), Some("/"));
        assert_eq!(exempt_match("/", &root), Some("/"));
        assert_eq!(exempt_match("/dev/shm/x", &shm), Some("/dev/shm"));
        assert_eq!(exempt_match("/dev/shm", &shm), Some("/dev/shm"));
        // A trailing slash on the argument is tolerated, as the C tolerates it.
        assert_eq!(exempt_match("/dev/shm/x", &shm_slash), Some("/dev/shm/"));
        // Prefix, not substring: /dev/shmx is a different directory.
        assert_eq!(exempt_match("/dev/shmx", &shm), None);
        assert_eq!(exempt_match("/usr/bin/python3", &shm), None);

        // The bug the oracle caught: an fd whose target is not a path lives on
        // no file system, and `-e /` must not swallow it. Under `-e /` the C
        // still resolves sockets to their `IPv4 … TCP` rows.
        for target in ["socket:[14197]", "pipe:[99]", "anon_inode:[eventfd]"] {
            assert_eq!(exempt_match(target, &root), None, "{target} is not a path");
        }
    }

    #[test]
    fn the_unkn_type_code_names_the_fd_kind() {
        // Measured: an exempted numeric fd is UNKNfd, the cwd UNKNcwd, the
        // executable UNKNtxt.
        assert_eq!(unkn_suffix(&FdType::Handle(3)), "fd");
        assert_eq!(unkn_suffix(&FdType::Cwd), "cwd");
        assert_eq!(unkn_suffix(&FdType::Root), "rtd");
        assert_eq!(unkn_suffix(&FdType::Txt), "txt");
        assert_eq!(unkn_suffix(&FdType::Mem), "mem");
        assert_eq!(unkn_suffix(&FdType::Deleted), "del");
    }
    /// A `/proc/<pid>`-shaped directory built from ordinary files, so the
    /// rows for what cannot be read are pinned without needing a process that
    /// cannot be read: `readlink` on a regular file fails (`EINVAL`), on a
    /// missing entry fails (`ENOENT`), and a link to nowhere reads but will
    /// not `stat`. The differential covers the real thing — a process made
    /// unreadable with `PR_SET_DUMPABLE` — on the paths a host can reach.
    fn fake_proc(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("lsof_rs_unreadable_{tag}_{}", self_pid()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn walk(
        base: &Path,
        uid: Option<u32>,
        omit_unreadable: bool,
        sockets_only: bool,
    ) -> Vec<OpenFile> {
        let locks = crate::locks::LockTable::default();
        for_proc_dir(
            base.to_str().unwrap(),
            0,
            uid,
            &GatherCtx {
                socks: &SocketTable::default(),
                locks: &locks,
                ns: &net::NetnsTables::default(),
                exempt: &[],
                sockets_only,
                omit_unreadable,
            },
        )
    }

    fn why(errno: i32) -> String {
        // The C library's text, computed the way the rows compute it, so the
        // expectation holds under miri's strerror too.
        errno_text(&std::io::Error::from_raw_os_error(errno))
    }

    const ENOENT: i32 = 2;
    const EINVAL: i32 = 22;

    #[test]
    fn a_file_that_cannot_be_read_is_a_row_that_says_why() {
        // Measured, run as a user who cannot read the process:
        //   python3 478 root  cwd  unknown   /proc/478/cwd (readlink: Permission denied)
        //   python3 478 root NOFD     0000   /proc/478/fd (opendir: Permission denied)
        // lsof-rs printed one bare `unk unknown` line for such a process.
        let dir = fake_proc("rows");
        std::fs::write(dir.join("cwd"), b"not a link").unwrap(); // EINVAL
        std::os::unix::fs::symlink("/", dir.join("root")).unwrap(); // readable
        let base = dir.to_str().unwrap();
        let rows = walk(&dir, Some(1000), false, false);
        let cells: Vec<(String, String, String)> = rows
            .iter()
            .map(|f| (f.fd.code(), f.file_type.code(), f.name.clone()))
            .collect();
        assert_eq!(
            cells,
            [
                (
                    "cwd".into(),
                    "unknown".into(),
                    format!("{base}/cwd (readlink: {})", why(EINVAL))
                ),
                ("rtd".into(), "DIR".into(), "/".into()),
                (
                    "txt".into(),
                    "unknown".into(),
                    format!("{base}/exe (readlink: {})", why(ENOENT))
                ),
                (
                    "NOFD".into(),
                    "0000".into(),
                    format!("{base}/fd (opendir: {})", why(ENOENT))
                ),
            ]
        );
        for f in rows.iter().filter(|f| f.file_type != FileType::Dir) {
            assert!(
                f.device.is_none() && f.size.is_none() && f.node.is_none() && f.offset.is_none(),
                "nothing was examined, so nothing is shown: {f:?}"
            );
            assert_eq!(f.access, AccessMode::Unknown);
        }
        // `-F` writes no `t` for the NOFD row, and a `t` for the others.
        assert!(!rows[3].file_type.has_code() && rows[0].file_type.has_code());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_root_process_missing_its_executable_is_named_without_a_reason() {
        // The C's `(errno != ENOENT) || uid`: a kernel thread has no
        // executable, and `kthreadd 2 root txt unknown /proc/2/exe` says so
        // without a reason. Any other failure, or any other owner, gets one.
        let dir = fake_proc("kthread");
        std::os::unix::fs::symlink("/", dir.join("cwd")).unwrap();
        std::os::unix::fs::symlink("/", dir.join("root")).unwrap();
        std::fs::create_dir(dir.join("fd")).unwrap();
        let base = dir.to_str().unwrap();
        let txt = |uid| {
            walk(&dir, uid, false, false)
                .into_iter()
                .find(|f| f.fd == FdType::Txt)
                .expect("a txt row")
                .name
        };
        assert_eq!(txt(Some(0)), format!("{base}/exe"));
        assert_eq!(
            txt(Some(1000)),
            format!("{base}/exe (readlink: {})", why(ENOENT))
        );
        assert_eq!(txt(None), format!("{base}/exe (readlink: {})", why(ENOENT)));
        // Not ENOENT: a root process still gets the reason.
        std::fs::write(dir.join("exe"), b"x").unwrap();
        assert_eq!(
            txt(Some(0)),
            format!("{base}/exe (readlink: {})", why(EINVAL))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_fd_that_cannot_be_read_is_a_row_under_its_number() {
        // What root sees of a process in another user namespace here: the fd
        // directory lists, every link refuses. `3 unknown /proc/1/fd/3
        // (readlink: Permission denied)`.
        let dir = fake_proc("fds");
        std::fs::create_dir(dir.join("fd")).unwrap();
        std::fs::write(dir.join("fd").join("3"), b"x").unwrap();
        std::fs::write(dir.join("fd").join("junk"), b"x").unwrap();
        let base = dir.to_str().unwrap();
        let rows = walk(&dir, Some(1000), false, false);
        let fd3 = rows
            .iter()
            .find(|f| f.fd == FdType::Handle(3))
            .expect("fd 3");
        assert_eq!(fd3.name, format!("{base}/fd/3 (readlink: {})", why(EINVAL)));
        assert_eq!(fd3.file_type, FileType::Unknown);
        assert!(
            rows.iter().all(|f| f.fd != FdType::NoFd),
            "the directory opened"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_link_that_reads_but_will_not_stat_says_so_in_name() {
        // A dead FUSE mount is the real case: the link names the file, `stat`
        // fails. The C appends `(stat: <reason>)`; lsof-rs had shown the
        // name alone, as though nothing had gone wrong.
        let dir = fake_proc("stat");
        std::os::unix::fs::symlink("/nonexistent/lsof-rs", dir.join("cwd")).unwrap();
        let cwd = walk(&dir, Some(1000), false, false)
            .into_iter()
            .find(|f| f.fd == FdType::Cwd)
            .expect("a cwd row");
        assert_eq!(
            cwd.name,
            format!("/nonexistent/lsof-rs (stat: {})", why(ENOENT))
        );
        assert_eq!(cwd.file_type, FileType::Unknown);
        // Under -w the row stays, without the reason — the C's `!Fwarn`.
        let quiet = walk(&dir, Some(1000), true, false)
            .into_iter()
            .find(|f| f.fd == FdType::Cwd)
            .expect("still a row");
        assert_eq!(quiet.name, "/nonexistent/lsof-rs");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_socket_no_table_names_has_no_link_count() {
        // The C hands every socket inode to `process_proc_sock()`, which
        // records no link count, so `+L` never selects one and NLINK is blank
        // (DIVERGENCES 42). lsof-rs's fallback row for a socket the tables do
        // not name (on the test host, an AF_VSOCK one) kept the `stat` count,
        // 1. A bound AF_UNIX socket's path stats as a socket too, which
        // reaches the same row without a namespace or a vsock module.
        let dir = fake_proc("sock");
        let sock = dir.join("bound.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let file = dir.join("plain");
        std::fs::write(&file, b"x").unwrap();
        std::fs::create_dir(dir.join("fd")).unwrap();
        std::os::unix::fs::symlink(&sock, dir.join("fd").join("3")).unwrap();
        std::os::unix::fs::symlink(&file, dir.join("cwd")).unwrap();
        let rows = walk(&dir, Some(1000), false, false);
        let s = rows
            .iter()
            .find(|f| f.fd == FdType::Handle(3))
            .expect("a row for fd 3");
        assert_eq!(s.file_type, FileType::Other("SOCK".into()), "{s:?}");
        assert_eq!(s.links, None, "a socket has no link count: {s:?}");
        let cwd = rows
            .iter()
            .find(|f| f.fd == FdType::Cwd)
            .expect("a cwd row");
        assert_eq!(cwd.links, Some(1), "anything else keeps its count: {cwd:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_device_node_carries_the_raw_number_it_names() {
        // `-F r` prints `st_rdev` for a character or block special and for
        // nothing else (DIVERGENCES 47): `/dev/null` is 1,3, which the kernel
        // encodes as 0x103.
        let dir = fake_proc("rdev");
        let file = dir.join("plain");
        std::fs::write(&file, b"x").unwrap();
        std::fs::create_dir(dir.join("fd")).unwrap();
        std::os::unix::fs::symlink("/dev/null", dir.join("fd").join("0")).unwrap();
        std::os::unix::fs::symlink(&file, dir.join("fd").join("3")).unwrap();
        let rows = walk(&dir, Some(1000), false, false);
        let at = |n: u64| {
            rows.iter()
                .find(|f| f.fd == FdType::Handle(n))
                .expect("a row")
        };
        assert_eq!(at(0).file_type, FileType::Chr);
        assert_eq!(at(0).rdev.map(|r| r.get()), Some(0x103));
        assert_eq!(at(3).rdev, None, "a regular file names no device");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn under_dash_w_or_for_sockets_only_nothing_unreadable_is_a_row() {
        // `-w` and `-t`: the C makes no row for what it cannot read, so a
        // process with nothing else has none (DIVERGENCES 37). A socket-only
        // run (`-i`, `-U`) makes none either: they could never be printed.
        let dir = fake_proc("quiet");
        std::fs::write(dir.join("cwd"), b"x").unwrap();
        assert!(walk(&dir, Some(1000), true, false).is_empty());
        assert!(walk(&dir, Some(1000), false, true).is_empty());
        assert!(!walk(&dir, Some(1000), false, false).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_terse_probe_finds_any_readable_file_and_nothing_else() {
        // `-t`'s fast path asks this instead of walking: `lsof -t -p 1`
        // prints nothing for a process nothing of which can be read.
        let dir = fake_proc("probe");
        let base = dir.to_str().unwrap().to_string();
        assert!(!has_readable_file(&base), "an empty directory");
        std::fs::write(dir.join("cwd"), b"x").unwrap();
        std::fs::create_dir(dir.join("fd")).unwrap();
        std::fs::write(dir.join("fd").join("0"), b"x").unwrap();
        assert!(!has_readable_file(&base), "links that will not read");
        std::os::unix::fs::symlink("/dev/null", dir.join("fd").join("1")).unwrap();
        assert!(has_readable_file(&base), "one fd that reads is enough");
        let _ = std::fs::remove_dir_all(&dir);
        // And a live process that can be read, itself.
        assert!(has_readable_file(&format!("/proc/{}", self_pid())));
    }
}
