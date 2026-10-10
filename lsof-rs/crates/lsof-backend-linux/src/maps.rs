//! `mem` rows from `/proc/<pid>/maps` — the mapped files a process holds open
//! without an fd.
//!
//! lsof lists every distinct file a process has mapped, because a mapping keeps
//! the file open just as an fd does: a deleted-but-mapped library still occupies
//! its inode, and `lsof | grep DEL` after a package upgrade is the canonical way
//! to find processes still running against the old shared objects. The C reads
//! the same file (`lib/dialects/linux/dproc.c:process_proc_map`).
//!
//! What the C does, measured against it row by row:
//!
//! * A mapping counts when it has a path and its device or inode is not 0.
//!   That is every mapped file, and also what the kernel names without a
//!   path: an io_uring ring (`anon_inode:[io_uring]`), a packet socket's ring
//!   (`socket:[N]`). `[heap]`, `[stack]`, `[vdso]` and anonymous mappings are
//!   device 0, inode 0, and produce nothing.
//! * A file mapped several times (a shared object is normally mapped four or
//!   five times, one segment per protection) produces **one** row. The identity
//!   is the `(device, inode)` pair from the maps line, not the path.
//! * The mapping of the executable itself is already the `txt` row, so it is
//!   not repeated as `mem`.
//! * Every other mapping is a row, whatever a `stat` of it says. A file the
//!   `stat` describes is typed from it (`CHR` for a mapped `/dev/zero`, with
//!   the device it names); one it cannot, or that names another file, keeps
//!   what the maps line says and the reason in NAME (see [`rows_for`]).
//! * A mapping whose file has been **deleted** becomes a `DEL` row rather than
//!   `mem` — unless the `stat` describes it after all, as it does through
//!   `map_files` in another mount namespace (see [`rows_for`]).
//!
//! Order matters: the differential compares stdout byte for byte, and the C
//! emits these in maps order (ascending address), so the dedup below preserves
//! first-seen order rather than sorting.

use std::ffi::OsStr;
use std::num::NonZeroU32;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};

use lsof_core::errno_text;
use lsof_core::model::{AccessMode, FdType, FileType, OpenFile};

use crate::files::{self, GatherCtx};

/// One distinct mapping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mapping {
    /// Device, as the `maj:min` hex pair the maps line carries, rendered the
    /// way lsof prints DEVICE (`254,0`).
    pub device: String,
    /// The same device as a `dev_t`, packed as `makedev()` packs it — what
    /// `-F D` prints, and what a `stat` of the file would say.
    pub dev: u64,
    pub inode: u64,
    /// The mapped path, with any ` (deleted)` marker removed — decoded for
    /// display, with U+FFFD for any byte sequence that is not UTF-8.
    pub path: String,
    /// The kernel appended ` (deleted)`: the file is unlinked but still mapped.
    pub deleted: bool,
    /// The path's bytes, kept only when [`Mapping::path`] could not hold them
    /// exactly — the name that has to be `stat`ed, because the decoded one
    /// names no file.
    pub raw_path: Option<Vec<u8>>,
    /// The first segment's addresses, which name the mapping under
    /// `/proc/<pid>/map_files/`. `None` if they did not parse.
    pub range: Option<(u64, u64)>,
}

/// The distinct file-backed mappings in `text`, in first-seen (address) order.
/// See [`parse_maps_bytes`], which this is over UTF-8 input — the shape the
/// unit tests and the fuzz target's cross-check are written in.
#[cfg(any(test, feature = "fuzzing"))]
pub fn parse_maps(text: &str) -> Vec<Mapping> {
    parse_maps_bytes(text.as_bytes())
}

/// The next blank- or tab-separated field of a maps line, as the C's
/// `get_fields()` cuts the first six.
fn next_field<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
    let start = rest.iter().position(|&b| b != b' ' && b != b'\t')?;
    let tail = &rest[start..];
    let end = tail
        .iter()
        .position(|&b| b == b' ' || b == b'\t')
        .unwrap_or(tail.len());
    let (field, after) = tail.split_at(end);
    *rest = after;
    Some(field)
}

/// The distinct mappings in a `/proc/<pid>/maps` file, in first-seen
/// (address) order.
///
/// Pure, so the fuzz target can drive it with arbitrary bytes; it must never
/// panic. A maps line is `address perms offset dev inode path`, and the path
/// is the only field that may contain spaces — so it is the rest of the line
/// after the blanks that pad it, as the C's `get_fields()` takes it. Trailing
/// blanks and a CR are part of a name (a file can be called `x `), so nothing
/// is trimmed: trimming them stat'ed `x`, another file. A TAB is part of it
/// too, where `get_fields()` ends the field: the C reads `libssl.so<TAB>x` as
/// `libssl.so`, the name of another file, which a name its owner chose then
/// passes for. lsof-rs keeps the whole name, as it keeps a socket's path that
/// the C cuts the same way (DIVERGENCES 103, 66). It is read as BYTES: a path may
/// hold any byte but `/` and NUL, and one that is not UTF-8 is still a file
/// the process has mapped — decoding the file as text first and stat'ing the
/// decoded name found nothing and dropped the row, so a library with such a
/// name was missing from `mem` where the C lists it.
pub fn parse_maps_bytes(data: &[u8]) -> Vec<Mapping> {
    let mut out: Vec<Mapping> = Vec::new();
    let mut seen: Vec<(u64, u64)> = Vec::new();
    for line in data.split(|&b| b == b'\n') {
        let mut rest = line;
        let (Some(addr), Some(_perms), Some(_off), Some(dev), Some(inode)) = (
            next_field(&mut rest),
            next_field(&mut rest),
            next_field(&mut rest),
            next_field(&mut rest),
            next_field(&mut rest),
        ) else {
            continue;
        };
        let path = match rest.iter().position(|&b| b != b' ' && b != b'\t') {
            Some(start) => &rest[start..],
            None => continue, // no path field at all: an anonymous mapping
        };
        let Some((maj, min)) = std::str::from_utf8(dev).ok().and_then(parse_dev) else {
            continue;
        };
        let Some(inode) = std::str::from_utf8(inode)
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
        else {
            continue;
        };
        let dev = files::makedev(maj, min);
        // `[heap]`, `[stack]`, `[vdso]`, `[anon:...]`: no device, no inode.
        if dev == 0 && inode == 0 {
            continue;
        }
        // Exactly one marker, and only after a name: the C strips it when
        // the path is longer than the marker itself.
        let (path, deleted) = match path.strip_suffix(b" (deleted)") {
            Some(p) if !p.is_empty() => (p, true),
            _ => (path, false),
        };
        // One row per file, however many segments it is mapped in.
        if seen.contains(&(dev, inode)) {
            continue;
        }
        seen.push((dev, inode));
        let (path, raw_path) = match std::str::from_utf8(path) {
            Ok(p) => (p.to_string(), None),
            Err(_) => (
                String::from_utf8_lossy(path).into_owned(),
                Some(path.to_vec()),
            ),
        };
        out.push(Mapping {
            device: format!("{maj},{min}"),
            dev,
            inode,
            path,
            deleted,
            raw_path,
            range: parse_range(addr),
        });
    }
    out
}

/// `7f1c4a000000-7f1c4a028000` → the two addresses.
fn parse_range(addr: &[u8]) -> Option<(u64, u64)> {
    let addr = std::str::from_utf8(addr).ok()?;
    let (start, end) = addr.split_once('-')?;
    Some((
        u64::from_str_radix(start, 16).ok()?,
        u64::from_str_radix(end, 16).ok()?,
    ))
}

/// `fe:00` → `(254, 0)`. The maps file writes the device as hex
/// `major:minor`; lsof prints it as decimal `major,minor`.
fn parse_dev(s: &str) -> Option<(u32, u32)> {
    let (maj, min) = s.split_once(':')?;
    Some((
        u32::from_str_radix(maj, 16).ok()?,
        u32::from_str_radix(min, 16).ok()?,
    ))
}

/// Whether `base`'s maps file names a mapping. Each one is a row, readable
/// or not (see [`rows_for`]), so this is what `-t`'s fast path asks — and
/// it costs a read and a parse, with no `stat` of any mapping.
pub fn has_mapping(base: &str) -> bool {
    std::fs::read(format!("{base}/maps")).is_ok_and(|b| !parse_maps_bytes(&b).is_empty())
}

/// Whether process `pid` lives in another mount namespace than this one,
/// whose namespace's inode is `ours` — the C's `compare_mntns()`, and like it
/// "no" when either inode cannot be had.
fn in_other_mount_ns(pid: u32, ours: Option<u64>) -> bool {
    ours.is_some_and(|ours| {
        std::fs::metadata(format!("/proc/{pid}/ns/mnt")).is_ok_and(|md| md.ino() != ours)
    })
}

/// The `mem` and `DEL` rows under one `/proc` directory — a process's
/// (`/proc/<pid>`) or a task's (`/proc/<pid>/task/<tid>`).
///
/// A task's are read from **its own** `maps`, as the C reads them. They are
/// the process's mappings — threads share an `mm` — right up until the main
/// thread exits while another runs on: then `/proc/<pid>/maps` is empty (the
/// leader's `mm` is gone) and only the task's own file still lists them.
/// Reading the process's for every task dropped the live task's `mem` rows
/// in exactly that case, the zombie leader of DIVERGENCES 31.
///
/// `exe` is the `(st_dev, st_ino)` of the `txt` row when it is known, so the
/// executable's own mapping is not listed twice. Each other mapping is a row,
/// built as [`mapping_row`] says.
pub fn rows_for(
    base: &str,
    pid: u32,
    exe: Option<(u64, u64)>,
    ctx: &GatherCtx<'_>,
) -> Vec<OpenFile> {
    // Bytes, not text: a mapped file's path holds any byte but `/` and NUL,
    // and one that is not UTF-8 made the strict read fail — taking every
    // `mem` row of the process with it (see `crate::text`) — and then, read
    // lossily, named no file that could be stat'ed.
    let Ok(bytes) = std::fs::read(format!("{base}/maps")) else {
        return Vec::new();
    };
    let maps = parse_maps_bytes(&bytes);
    if maps.is_empty() {
        return Vec::new();
    }
    // Asked once, of the process: a task lives where its process does.
    let foreign = in_other_mount_ns(pid, ctx.mnt_ns);
    maps.into_iter()
        .filter(|m| exe != Some((m.dev, m.inode)))
        .map(|m| mapping_row(m, pid, foreign, ctx))
        .collect()
}

/// One mapping's row, as `process_proc_map()` builds it.
///
/// * Under `-e`, a mapping on an exempted file system is not `stat`ed: TYPE
///   `UNKNmem` (`UNKNdel` for a deleted one), DEVICE and NODE from the maps
///   line, NAME `… (-e FS)`, and no lock — the C never takes it to
///   `process_proc_node()` (DIVERGENCES 40).
/// * Otherwise it is `stat`ed ([`stat_mapping`]): through
///   `/proc/<pid>/map_files/<range>` when the process lives in another mount
///   namespace — the path is the process's, and here it names another file
///   or none — and by its path otherwise.
/// * A `stat` that fails, or (in this namespace) names another file than
///   the maps line's device and inode, leaves the row to the maps line: TYPE
///   `REG`, no size or link count, and for a live mapping the reason in NAME
///   — `(stat: No such file or directory)`, `(path dev=0,42, inode=2)`,
///   `(path inode=N)` — unless `-w` (or `-t`) asked for no warnings.
///   Measured: as an unprivileged user, every mapping of a process in another
///   mount namespace is `(stat: Operation not permitted)`, since following a
///   `map_files` link takes `CAP_SYS_ADMIN`. lsof-rs had dropped all of these
///   rows (DIVERGENCES 95).
/// * A `stat` that describes the file types the row from it, as an fd's is
///   typed: a mapped device is `CHR` or `BLK` with the device it names and no
///   size (DIVERGENCES 48), and a mapped socket the socket's own row. It is
///   `mem` even when the maps line said deleted: in another mount namespace
///   `map_files` reaches the unlinked file, and here the path can name the
///   same inode again (relinked).
fn mapping_row(m: Mapping, pid: u32, foreign: bool, ctx: &GatherCtx<'_>) -> OpenFile {
    let bytes = m.raw_path.as_deref().unwrap_or(m.path.as_bytes());
    let gone = if m.deleted {
        FdType::Deleted
    } else {
        FdType::Mem
    };
    if let Some(fs) = files::exempt_match(bytes, ctx.exempt) {
        return OpenFile {
            rdev: None,
            fs_device: Some(m.dev),
            file_flags: None,
            lock: None,
            file_type: FileType::Exempt(files::unkn_suffix(&gone)),
            fd: gone,
            access: AccessMode::Unknown,
            name: format!("{} (-e {fs})", m.path),
            device: Some(m.device),
            size: None,
            offset: None,
            node: Some(m.inode.to_string()),
            links: None,
            socket: None,
        };
    }
    let stat = stat_mapping(bytes, m.range, pid, foreign);
    // What the maps line alone says, with the reason the `stat` could not
    // say more — none for a deleted mapping, whose path is expected to fail.
    let from_maps = |m: Mapping, why: Option<String>| {
        let why = why.filter(|_| !m.deleted && !ctx.omit_unreadable);
        OpenFile {
            rdev: None,
            fs_device: Some(m.dev),
            file_flags: None,
            lock: ctx.locks.get(&(pid, m.dev, m.inode)).copied(),
            fd: gone.clone(),
            access: AccessMode::Unknown,
            file_type: FileType::Regular,
            name: match why {
                Some(why) => format!("{} {why}", m.path),
                None => m.path,
            },
            device: Some(m.device),
            size: None,
            offset: None,
            node: Some(m.inode.to_string()),
            links: None,
            socket: None,
        }
    };
    match stat {
        Err(e) => from_maps(m, Some(format!("(stat: {})", errno_text(&e)))),
        Ok(md) => match path_note(&md, &m) {
            Some(note) if !foreign => from_maps(m, Some(note)),
            _ => from_stat(m.path, &md, pid, ctx),
        },
    }
}

/// `ENOENT`, fixed by the ABI, as `S_IFMT` and its fellows are in `files`.
const ENOENT: i32 = 2;

/// The `stat` that describes a mapping: of `/proc/<pid>/map_files/<range>`
/// for a process in another mount namespace, and of its path otherwise —
/// but never of a name that is no path. The kernel names some mappings with
/// no path at all (`anon_inode:[io_uring]`, `socket:[N]`), and the C `stat`s
/// that name relative to its own working directory: a file planted there
/// under it is described in the mapping's place (`(path dev=254,0,
/// inode=…)`, measured), and a link there into a hung file system stops the
/// run. The directory lsof runs in is often everyone's (`/tmp`). lsof-rs
/// does not look, and says what the C says when nothing is there: `No such
/// file or directory` (DIVERGENCES 102).
fn stat_mapping(
    bytes: &[u8],
    range: Option<(u64, u64)>,
    pid: u32,
    foreign: bool,
) -> std::io::Result<std::fs::Metadata> {
    match (foreign, range) {
        (true, Some((start, end))) => {
            std::fs::metadata(format!("/proc/{pid}/map_files/{start:x}-{end:x}"))
        }
        _ if !bytes.starts_with(b"/") => Err(std::io::Error::from_raw_os_error(ENOENT)),
        _ => std::fs::metadata(OsStr::from_bytes(bytes)),
    }
}

/// `(path dev=0,42, inode=2)`, `(path dev=0,42)` or `(path inode=2)`: the
/// file the path leads to now, where the maps line names another — the C's
/// two `add_nma()`s, joined by its space. `None` when it is the same file.
fn path_note(md: &std::fs::Metadata, m: &Mapping) -> Option<String> {
    let dev = (md.dev() != m.dev).then(|| files::dev_string(md.dev()));
    let ino = (md.ino() != m.inode).then(|| md.ino());
    Some(match (dev, ino) {
        (Some(dev), Some(ino)) => format!("(path dev={dev}, inode={ino})"),
        (Some(dev), None) => format!("(path dev={dev})"),
        (None, Some(ino)) => format!("(path inode={ino})"),
        (None, None) => return None,
    })
}

/// The row a `stat` of the mapped file describes, typed as an fd's is: a
/// device node shows the device it names, in DEVICE and `-F r`, and no size
/// (the C's `process_proc_node()` keeps one for neither a device nor a FIFO,
/// and a mapping has no offset to show instead), and a socket is the socket's
/// row. Always `mem`.
fn from_stat(name: String, md: &std::fs::Metadata, pid: u32, ctx: &GatherCtx<'_>) -> OpenFile {
    if md.file_type().is_socket() {
        return socket_mapping(md, pid, ctx);
    }
    let ty = files::type_from_mode(md.mode());
    let (device, rdev, size) = match ty {
        FileType::Chr | FileType::Block => (
            files::dev_string(md.rdev()),
            u32::try_from(md.rdev()).ok().and_then(NonZeroU32::new),
            None,
        ),
        FileType::Fifo => (files::dev_string(md.dev()), None, None),
        _ => (files::dev_string(md.dev()), None, Some(md.size())),
    };
    OpenFile {
        rdev,
        fs_device: Some(md.dev()),
        file_flags: None,
        lock: ctx.locks.get(&(pid, md.dev(), md.ino())).copied(),
        fd: FdType::Mem,
        access: AccessMode::Unknown,
        file_type: ty,
        name,
        device: Some(device),
        size,
        offset: None,
        node: Some(md.ino().to_string()),
        links: u32::try_from(md.nlink()).ok(),
        socket: None,
    }
}

/// A mapped socket's row (a packet ring, reached through `map_files`), as
/// the C's `process_proc_sock()` makes it with the mapping's name for a path.
/// A socket this namespace's tables know is that socket's row, with SIZE/OFF
/// blank where an fd's is `0t0` (measured: `mem pack 11337 <blank>`). One
/// they do not know the C names from `getxattr()` of that name, which is no
/// path, so it never can: `can't identify protocol`, `sock`, its file
/// system's device, no lock and no link count (measured, a packet ring in
/// another network namespace). An fd's link is a path, so the same socket's
/// fd row does get its protocol (`protocol: PACKET`).
fn socket_mapping(md: &std::fs::Metadata, pid: u32, ctx: &GatherCtx<'_>) -> OpenFile {
    if ctx.socks.get(md.ino()).is_some() {
        let info = files::FdInfo::default();
        if let Some(mut f) = files::socket_row(md.ino(), &FdType::Mem, &info, Some(md), pid, ctx) {
            f.offset = None;
            return f;
        }
    }
    OpenFile {
        rdev: None,
        fs_device: Some(md.dev()),
        file_flags: None,
        lock: None,
        fd: FdType::Mem,
        access: AccessMode::Unknown,
        file_type: FileType::Socket("sock"),
        name: ctx.ns.unidentified().to_string(),
        device: Some(files::dev_string(md.dev())),
        size: None,
        offset: None,
        node: Some(md.ino().to_string()),
        links: None,
        socket: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real excerpt: a shared object mapped five times, the heap, an
    // anonymous mapping, a vdso, and a deleted library with a space in its
    // name. Tab-free and byte-exact from a live /proc/<pid>/maps.
    const SAMPLE: &str = "\
55a4a2e00000-55a4a2e02000 r--p 00000000 fe:00 151615 /usr/bin/sleep
55a4a2e02000-55a4a2e06000 r-xp 00002000 fe:00 151615 /usr/bin/sleep
55a4a2e06000-55a4a2e08000 r--p 00006000 fe:00 151615 /usr/bin/sleep
55a4a3b0d000-55a4a3b2e000 rw-p 00000000 00:00 0 [heap]
7f1c4a000000-7f1c4a028000 r--p 00000000 fe:00 152035 /usr/lib/x86_64-linux-gnu/libc.so.6
7f1c4a028000-7f1c4a1b0000 r-xp 00028000 fe:00 152035 /usr/lib/x86_64-linux-gnu/libc.so.6
7f1c4a1b0000-7f1c4a200000 rw-p 00000000 00:00 0
7f1c4a300000-7f1c4a328000 r--p 00000000 fe:00 1892421 /tmp/dir/my lib.so (deleted)
7ffd0b3fe000-7ffd0b400000 r-xp 00000000 00:00 0 [vdso]
";

    #[test]
    fn one_row_per_file_in_address_order() {
        let m = parse_maps(SAMPLE);
        let names: Vec<&str> = m.iter().map(|m| m.path.as_str()).collect();
        assert_eq!(
            names,
            [
                "/usr/bin/sleep",
                "/usr/lib/x86_64-linux-gnu/libc.so.6",
                "/tmp/dir/my lib.so",
            ],
            "five segments of sleep and two of libc collapse to one row each; \
             [heap], [vdso] and the anonymous mapping produce none"
        );
    }

    #[test]
    fn device_is_decimal_and_deleted_is_flagged() {
        let m = parse_maps(SAMPLE);
        assert_eq!(m[0].device, "254,0", "fe:00 is hex; lsof prints decimal");
        assert_eq!(m[0].inode, 151615);
        assert!(!m[0].deleted);
        // A path may contain spaces, so it is the rest of the line — and the
        // kernel's " (deleted)" marker is not part of the name.
        assert_eq!(m[2].path, "/tmp/dir/my lib.so");
        assert!(m[2].deleted);
    }

    #[test]
    fn identity_is_device_plus_inode_not_the_path() {
        // The same inode under two paths (a bind mount) is one file; the same
        // inode on two devices is two.
        let m =
            parse_maps("0-1 r--p 0 fe:00 42 /a\n1-2 r--p 0 fe:00 42 /b\n2-3 r--p 0 fe:01 42 /c\n");
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].path, "/a");
        assert_eq!(m[1].device, "254,1");
    }

    #[test]
    fn exactly_one_deleted_marker_is_stripped() {
        // A file whose real name ends in " (deleted)" is not a hypothetical.
        // Created as `lib (deleted)`, mapped, then unlinked, the kernel reports
        //
        //     7f78...000 r--s 00000000 fe:00 1892464   /tmp/d/lib (deleted) (deleted)
        //
        // — its own marker appended to a name that already ended in one. The C
        // strips ONE (`dproc.c`: a single NUL store at `len - 10`, not a loop),
        // so the DEL row reads `/tmp/d/lib (deleted)`, and both binaries print
        // exactly that. Stripping greedily would rename the user's file; not
        // stripping at all would leak kernel metadata into it.
        let m = parse_maps("0-1 r--s 0 fe:00 42 /tmp/d/lib (deleted) (deleted)\n");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].path, "/tmp/d/lib (deleted)");
        assert!(m[0].deleted);

        // The ordinary case: one marker, nothing left behind.
        let m = parse_maps("0-1 r--s 0 fe:00 43 /tmp/d/lib.so (deleted)\n");
        assert_eq!(m[0].path, "/tmp/d/lib.so");
        assert!(m[0].deleted);

        // A live file that merely ends that way keeps its whole name, and is
        // not reported as deleted.
        let m = parse_maps("0-1 r--s 0 fe:00 44 /tmp/d/lib (deleted)x\n");
        assert_eq!(m[0].path, "/tmp/d/lib (deleted)x");
        assert!(!m[0].deleted);
    }

    #[test]
    fn arbitrary_text_never_panics_and_invents_nothing() {
        for s in [
            "",
            "\n\n",
            "garbage",
            "0-1 r--p 0 fe:00 42",                      // no path field
            "0-1 r--p 0 fe:00 notanumber /x",           // unparseable inode
            "0-1 r--p 0 nocolon 42 /x",                 // unparseable device
            "0-1 r--p 0 zz:zz 42 /x",                   // non-hex device
            "0-1 r--p 0 fe:00 42 relative/path",        // relative: kept
            "0-1 r--p 0 fe:00 99999999999999999999 /x", // inode overflows u64
            "0-1 r--p 0 fe:00 42 / (deleted)",
            "\u{FFFD} \u{FFFD} \u{FFFD} \u{FFFD} \u{FFFD} /\u{FFFD}",
        ] {
            let _ = parse_maps(s);
        }
        assert!(parse_maps("0-1 r--p 0 fe:00 42").is_empty());
        assert!(
            parse_maps("0-1 r--p 0 fe:00 42    ").is_empty(),
            "blanks are no path"
        );
        // A bare "/" is a legal absolute path and is kept.
        assert_eq!(parse_maps("0-1 r--p 0 fe:00 42 / (deleted)")[0].path, "/");
    }

    #[test]
    fn a_mapping_counts_by_device_and_inode_not_by_a_leading_slash() {
        // The C keeps any path whose device or inode is not 0: what the
        // kernel names without a path is a mapping too. Measured: an io_uring
        // ring is `mem REG 0,16 7103 anon_inode:[io_uring] (stat: No such
        // file or directory)`, and a packet ring `socket:[8925]` likewise.
        let m = parse_maps(
            "7fb5-7fb6 rw-s 00000000 00:10 7103 anon_inode:[io_uring]\n\
             7f1a-7f1b rw-s 00000000 00:09 10552 socket:[10552]\n\
             55a4-55a5 rw-p 00000000 00:00 0 [heap]\n\
             7ffd-7ffe r-xp 00000000 00:00 0 [vdso]\n",
        );
        let names: Vec<&str> = m.iter().map(|m| m.path.as_str()).collect();
        assert_eq!(names, ["anon_inode:[io_uring]", "socket:[10552]"]);
        assert_eq!(m[0].dev, 0x10, "00:10, packed");
    }

    #[test]
    fn the_path_is_the_rest_of_the_line() {
        // As the C's `get_fields()` takes it: the padding before it goes,
        // and nothing after — a file can be called `x ` or end in a CR, and
        // trimming named another file.
        let m = parse_maps("0-1 r--p 0 fe:00 1                    /tmp/x \n");
        assert_eq!(m[0].path, "/tmp/x ");
        let m = parse_maps("0-1 r--p 0 fe:00 2 /tmp/y\r\n");
        assert_eq!(m[0].path, "/tmp/y\r");
        // A TAB too, where the C ends the field: `/tmp/a` would be another
        // file's name (DIVERGENCES 103).
        let m = parse_maps("0-1 r--p 0 fe:00 3 /tmp/a\tb\n");
        assert_eq!(m[0].path, "/tmp/a\tb");
        // Tabs separate the leading fields too.
        let m = parse_maps("0-1\tr--p\t0\tfe:00\t4\t/tmp/z\n");
        assert_eq!((m[0].inode, m[0].path.as_str()), (4, "/tmp/z"));
    }

    #[test]
    fn the_first_segment_names_the_mapping_under_map_files() {
        // `/proc/<pid>/map_files/` names a mapping by its addresses without
        // leading zeros (the C prints them back with `PRIx64`), and the C
        // stats the file's first segment.
        let m = parse_maps(
            "00400000-00452000 r--p 0 fe:00 9 /bin/x\n\
             00452000-00460000 r-xp 52000 fe:00 9 /bin/x\n",
        );
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].range, Some((0x40_0000, 0x45_2000)));
        assert_eq!(
            format!("{:x}-{:x}", m[0].range.unwrap().0, m[0].range.unwrap().1),
            "400000-452000"
        );
        assert_eq!(parse_maps("zz-1 r--p 0 fe:00 9 /bin/x\n")[0].range, None);
    }

    #[test]
    #[cfg_attr(miri, ignore = "miri cannot create a socket")]
    fn a_mapped_socket_no_table_knows_cannot_be_named() {
        use std::os::fd::AsRawFd;
        // A socket's own `stat`, through its fd's link: what `map_files`
        // gives for a mapped packet ring in another network namespace. No
        // table here knows this one.
        let s = std::os::unix::net::UnixDatagram::unbound().unwrap();
        let md = std::fs::metadata(format!("/proc/self/fd/{}", s.as_raw_fd())).unwrap();
        let socks = crate::net::SocketTable::default();
        let locks = crate::locks::LockTable::default();
        let ns = crate::net::NetnsTables::new(false);
        let ctx = GatherCtx {
            socks: &socks,
            locks: &locks,
            ns: &ns,
            exempt: &[],
            sockets_only: false,
            omit_unreadable: false,
            bound_paths: false,
            mnt_ns: None,
            helpers: &crate::safefs::HelperFds::default(),
        };
        let f = socket_mapping(&md, std::process::id(), &ctx);
        assert_eq!(f.fd, FdType::Mem);
        assert_eq!(f.file_type.code(), "sock");
        assert_eq!(
            f.name, "can't identify protocol",
            "getxattr() of `socket:[N]` fails"
        );
        assert_eq!(f.fs_device, Some(md.dev()), "`-F` gives its device as `D`");
        // But no path finds it by that device and its inode, nor by its file
        // system: the C hands a socket to `process_proc_sock()`, which never
        // compares them (DIVERGENCES 101).
        assert_eq!((f.file_id(), f.searched_fs_device()), (None, None));
        assert_eq!(
            (f.size, f.offset, f.links, f.lock),
            (None, None, None, None)
        );
        // Under `-X` the C does not look, and says so.
        let ns = crate::net::NetnsTables::new(true);
        let ctx = GatherCtx { ns: &ns, ..ctx };
        assert_eq!(
            socket_mapping(&md, std::process::id(), &ctx).name,
            "can't identify protocol (-X specified)"
        );
    }

    #[test]
    fn a_mapping_the_c_could_not_stat_is_found_by_its_maps_line() {
        // DIVERGENCES 101: a mapping whose `stat` fails (as non-root, every
        // mapping of a process in another mount namespace; here, a path that
        // is no longer there) is `REG` with the maps line's device and inode,
        // and a path argument finds it by them: `lsof /dev/zero` lists the
        // `REG 0,6 4` row of a container's `/dev/zero` mapping, in the C and
        // now in lsof-rs, whose DEVICE cell (`0,6`) is not the `1,5` the
        // node names. A deleted one keeps them too.
        let socks = crate::net::SocketTable::default();
        let locks = crate::locks::LockTable::default();
        let ns = crate::net::NetnsTables::new(false);
        let ctx = GatherCtx {
            socks: &socks,
            locks: &locks,
            ns: &ns,
            exempt: &[],
            sockets_only: false,
            omit_unreadable: false,
            bound_paths: false,
            mnt_ns: None,
            helpers: &crate::safefs::HelperFds::default(),
        };
        let maps = parse_maps(
            "0-1 r--p 0 00:06 4 /nonexistent-lsof-rs/zero\n\
             1-2 r--p 0 01:2c 9 /nonexistent-lsof-rs/gone (deleted)\n",
        );
        let want = [
            (files::makedev(0, 6), 4, FdType::Mem),
            (files::makedev(1, 44), 9, FdType::Deleted),
        ];
        assert_eq!(maps.len(), want.len());
        for (m, (dev, ino, fd)) in maps.into_iter().zip(want) {
            let row = mapping_row(m, std::process::id(), false, &ctx);
            assert_eq!(row.fd, fd);
            assert_eq!(row.file_type, FileType::Regular);
            assert_eq!(row.file_id(), Some(lsof_core::FileId { dev, ino }));
        }
    }

    #[test]
    fn a_name_that_is_no_path_is_never_stated() {
        // Tests run in the package's directory, where `Cargo.toml` is a
        // file: the C would describe it, in place of whatever the kernel
        // named so. lsof-rs does not look (DIVERGENCES 102).
        assert!(std::path::Path::new("Cargo.toml").is_file());
        let e = stat_mapping(b"Cargo.toml", None, 0, false).unwrap_err();
        // `ENOENT`, which NAME gives as `No such file or directory`, the C's
        // words where nothing is planted (the differential compares them;
        // under miri the host's message already carries `(os error 2)`).
        assert_eq!(e.raw_os_error(), Some(ENOENT));
        assert!(
            stat_mapping(b"/", None, 0, false).is_ok(),
            "a path is stat'ed"
        );
    }

    #[test]
    fn a_path_that_names_another_file_says_which() {
        // The C's two `add_nma()`s, joined by its space: measured as
        // `(path inode=1900956)` for a bind mount over the path and
        // `(path dev=0,42, inode=2)` for a tmpfs over its directory.
        let md = std::fs::metadata("/").unwrap();
        let mapping = |dev: u64, inode: u64| Mapping {
            device: files::dev_string(dev),
            dev,
            inode,
            path: "/".into(),
            deleted: false,
            raw_path: None,
            range: None,
        };
        assert_eq!(path_note(&md, &mapping(md.dev(), md.ino())), None);
        assert_eq!(
            path_note(&md, &mapping(md.dev(), md.ino() + 1)),
            Some(format!("(path inode={})", md.ino()))
        );
        let other = md.dev() ^ 1;
        assert_eq!(
            path_note(&md, &mapping(other, md.ino())),
            Some(format!("(path dev={})", files::dev_string(md.dev())))
        );
        assert_eq!(
            path_note(&md, &mapping(other, md.ino() + 1)),
            Some(format!(
                "(path dev={}, inode={})",
                files::dev_string(md.dev()),
                md.ino()
            ))
        );
    }
}
