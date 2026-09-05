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
//! * Only file-backed mappings count. `[heap]`, `[stack]`, `[vdso]`, `[vvar]`
//!   and anonymous mappings have no file and produce nothing.
//! * A file mapped several times (a shared object is normally mapped four or
//!   five times, one segment per protection) produces **one** row. The identity
//!   is the `(device, inode)` pair from the maps line, not the path.
//! * The mapping of the executable itself is already the `txt` row, so it is
//!   not repeated as `mem`.
//! * A mapping whose file has been **deleted** becomes an `FdType::Deleted`
//!   row (`DEL`) rather than `mem`, carrying the device and inode from the maps
//!   line and no size — there is nothing left to stat.
//!
//! Order matters: the differential compares stdout byte for byte, and the C
//! emits these in maps order (ascending address), so the dedup below preserves
//! first-seen order rather than sorting.

use std::os::unix::fs::MetadataExt;

use lsof_core::model::{AccessMode, FdType, FileType, OpenFile};

/// One distinct file-backed mapping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mapping {
    /// Device, as the `maj:min` hex pair the maps line carries, rendered the
    /// way lsof prints DEVICE (`254,0`).
    pub device: String,
    pub inode: u64,
    /// The mapped path, with any ` (deleted)` marker removed.
    pub path: String,
    /// The kernel appended ` (deleted)`: the file is unlinked but still mapped.
    pub deleted: bool,
}

/// The distinct file-backed mappings in `text`, in first-seen (address) order.
///
/// Pure, so the fuzz target can drive it with arbitrary bytes; it must never
/// panic. A maps line is
/// `address perms offset dev inode path`, and the path is the only field that
/// may contain spaces — so it is taken as "the rest of the line", never split.
pub fn parse_maps(text: &str) -> Vec<Mapping> {
    let mut out: Vec<Mapping> = Vec::new();
    let mut seen: Vec<(String, u64)> = Vec::new();
    for line in text.lines() {
        // splitn(6) leaves the path whole: `/usr/lib/my lib.so` is one field.
        let mut f = line.splitn(6, ' ').filter(|s| !s.is_empty());
        let (Some(_addr), Some(_perms), Some(_off), Some(dev), Some(inode)) =
            (f.next(), f.next(), f.next(), f.next(), f.next())
        else {
            continue;
        };
        let Some(path) = f.next().map(str::trim) else {
            continue; // anonymous mapping: no path field at all
        };
        // `[heap]`, `[stack]`, `[vdso]`, `[vvar]`, `[anon:...]` — not files.
        if !path.starts_with('/') {
            continue;
        }
        let Some(device) = parse_dev(dev) else {
            continue;
        };
        let Ok(inode) = inode.parse::<u64>() else {
            continue;
        };
        let (path, deleted) = match path.strip_suffix(" (deleted)") {
            Some(p) => (p, true),
            None => (path, false),
        };
        // One row per file, however many segments it is mapped in.
        if seen.iter().any(|(d, i)| d == &device && *i == inode) {
            continue;
        }
        seen.push((device.clone(), inode));
        out.push(Mapping {
            device,
            inode,
            path: path.to_string(),
            deleted,
        });
    }
    out
}

/// `fe:00` → `254,0`. The maps file writes the device as hex `major:minor`;
/// lsof prints it as decimal `major,minor`.
fn parse_dev(s: &str) -> Option<String> {
    let (maj, min) = s.split_once(':')?;
    let maj = u32::from_str_radix(maj, 16).ok()?;
    let min = u32::from_str_radix(min, 16).ok()?;
    Some(format!("{maj},{min}"))
}

/// The `mem` and `DEL` rows for one process.
///
/// `exe` is the `(device, inode)` of the `txt` row when it is known, so the
/// executable's own mapping is not listed twice.
pub fn rows_for(pid: u32, exe: Option<(&str, &str)>) -> Vec<OpenFile> {
    let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for m in parse_maps(&text) {
        let node = m.inode.to_string();
        if exe == Some((m.device.as_str(), node.as_str())) {
            continue; // already the txt row
        }
        if m.deleted {
            // Unlinked but still mapped. Nothing to stat, so the device and
            // inode come from the maps line and SIZE stays blank, exactly as
            // the C prints it.
            out.push(OpenFile {
                lock: None,
                fd: FdType::Deleted,
                access: AccessMode::Unknown,
                file_type: FileType::Regular,
                name: m.path,
                device: Some(m.device),
                size: None,
                offset: None,
                node: Some(node),
                links: None,
                socket: None,
            });
            continue;
        }
        // A live mapping is stat'd for its size and link count. If the stat
        // fails, or names a different file than the mapping did, the C prints
        // the row with a `(stat: ...)` or `(path inode=...)` name addition;
        // lsof-rs omits rows it cannot describe, the same deliberate choice it
        // makes for an unreadable /proc link (DIVERGENCES.md, "Deliberate").
        let Ok(md) = std::fs::metadata(&m.path) else {
            continue;
        };
        if super::files::dev_string(md.dev()) != m.device || md.ino() != m.inode {
            continue;
        }
        out.push(OpenFile {
            lock: None,
            fd: FdType::Mem,
            access: AccessMode::Unknown,
            file_type: FileType::Regular,
            name: m.path,
            device: Some(m.device),
            size: Some(md.size()),
            offset: None,
            node: Some(node),
            links: u32::try_from(md.nlink()).ok(),
            socket: None,
        });
    }
    out
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
    fn arbitrary_text_never_panics_and_invents_nothing() {
        for s in [
            "",
            "\n\n",
            "garbage",
            "0-1 r--p 0 fe:00 42",                      // no path field
            "0-1 r--p 0 fe:00 notanumber /x",           // unparseable inode
            "0-1 r--p 0 nocolon 42 /x",                 // unparseable device
            "0-1 r--p 0 zz:zz 42 /x",                   // non-hex device
            "0-1 r--p 0 fe:00 42 relative/path",        // not absolute
            "0-1 r--p 0 fe:00 99999999999999999999 /x", // inode overflows u64
            "0-1 r--p 0 fe:00 42 / (deleted)",
            "\u{FFFD} \u{FFFD} \u{FFFD} \u{FFFD} \u{FFFD} /\u{FFFD}",
        ] {
            let _ = parse_maps(s);
        }
        assert!(parse_maps("0-1 r--p 0 fe:00 42").is_empty());
        assert!(parse_maps("0-1 r--p 0 fe:00 42 relative/path").is_empty());
        // A bare "/" is a legal absolute path and is kept.
        assert_eq!(parse_maps("0-1 r--p 0 fe:00 42 / (deleted)")[0].path, "/");
    }
}
