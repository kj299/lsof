//! The mount table, from `/proc/self/mounts`.
//!
//! lsof reads a path argument as a **file system name** when it matches a
//! mounted-on directory, and then selects every open file on that filesystem
//! (Lsof.8; `arg.c`'s `ck_file_arg`). This supplies the table that rule needs:
//! the mounted-on directory, the mount source, and the device every file on the
//! filesystem carries.
//!
//! Read and kept as bytes: the kernel escapes only space, tab, newline and
//! backslash, so any other byte of a mount point's name comes through raw, and
//! the argument is compared with it byte for byte.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileTypeExt, MetadataExt};

use lsof_core::MountEntry;

/// Read and stat the host's mount table. Unreadable or unstattable rows are
/// dropped rather than guessed at: a mount we cannot measure cannot be matched.
/// With `sources`, each mount's source is spelt as well; see
/// [`lsof_core::Backend::mounts`].
pub fn load(sources: bool) -> Vec<MountEntry> {
    let Ok(text) = std::fs::read("/proc/self/mounts") else {
        return Vec::new();
    };
    parse_mounts(&text)
        .into_iter()
        .filter_map(|row| {
            // The device comes from the mounted-on DIRECTORY, not from the
            // source: it is what every file on the filesystem reports as
            // `st_dev`, and for a bind mount or a pseudo-filesystem there is no
            // device file to ask. A directory we cannot stat (a mount we lack
            // permission to traverse) is dropped.
            let device = std::fs::metadata(&row.dir).ok()?.dev();
            let (source, source_is_block) = if sources {
                source(row.source)
            } else {
                (None, false)
            };
            Some(MountEntry {
                dir: row.dir,
                source,
                source_is_block,
                device,
                fstype: row.fstype,
            })
        })
        .collect()
}

/// A mount's source as the C's `readmnt()` keeps it (`dmnt.c`): a path —
/// one that starts with `/` — spelt by `Readlink()`, and a block device if
/// what that names is one; a name like `tmpfs` or `proc` as it stands, and
/// never a block device. A path `Readlink()` gives up on matches nothing.
///
/// `canonicalize()` had resolved both, so a relative link — `/dev/mapper/x`
/// -> `../dm-0` — became `/dev/dm-0`, where the C keeps
/// `/dev/mapper/../dm-0`, the spelling the same link gives an argument; and a
/// file in the working directory named like a source turned the name into a
/// path.
fn source(raw: OsString) -> (Option<OsString>, bool) {
    if raw.as_bytes().first() != Some(&b'/') {
        return (Some(raw), false);
    }
    match lsof_core::readlink::resolve(&raw) {
        Ok(path) => {
            let is_block = std::fs::metadata(&path)
                .map(|m| m.file_type().is_block_device())
                .unwrap_or(false);
            (Some(path), is_block)
        }
        Err(_) => (None, false),
    }
}

/// One raw `/proc/self/mounts` line: what is mounted, and where.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountLine {
    pub source: OsString,
    pub dir: OsString,
    /// Field 3 — the file-system type (`ext4`, `nfs4`, `tmpfs`). `-N` selects
    /// on it, and nothing else here did, so it used to be discarded.
    pub fstype: String,
}

/// The parsing half of [`load`]. Pure, so the fuzz target can drive it with
/// arbitrary bytes, and it must never panic.
///
/// The kernel writes five space-separated fields and escapes space, tab,
/// newline and backslash in the first two as `\040`, `\011`, `\012` and `\134`
/// (`fs/proc_namespace.c` via `seq_path_root`). A mount point with a space in
/// its name is therefore ordinary, not exotic — and splitting on whitespace
/// without decoding those escapes would silently mis-key it.
pub fn parse_mounts(text: &[u8]) -> Vec<MountLine> {
    let mut out = Vec::new();
    for line in text.split(|&b| b == b'\n') {
        let mut f = line.split(|&b| b == b' ');
        let (Some(source), Some(dir)) = (f.next(), f.next()) else {
            continue;
        };
        if dir.is_empty() {
            continue;
        }
        // The type is field 3 and is NOT octal-escaped — the kernel writes it
        // from the file system's own name, which cannot contain a space. A
        // line truncated before it yields an empty type rather than dropping
        // the mount, because the first two fields are still usable.
        let fstype = String::from_utf8_lossy(f.next().unwrap_or_default()).into_owned();
        out.push(MountLine {
            source: unescape_octal(source),
            dir: unescape_octal(dir),
            fstype,
        });
    }
    out
}

/// Undo the kernel's `\OOO` octal escaping of a mounts-file field.
///
/// Only a backslash followed by exactly three octal digits is an escape; the
/// kernel emits nothing else, and anything else is kept literally rather than
/// guessed at (a mount source is attacker-influenced on a host where users can
/// mount).
fn unescape_octal(b: &[u8]) -> OsString {
    if !b.contains(&b'\\') {
        return OsStr::from_bytes(b).to_os_string();
    }
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() {
            let d = &b[i + 1..i + 4];
            if d.iter().all(|c| (b'0'..=b'7').contains(c)) {
                // Widened, then masked to a byte exactly as the C does
                // (`cur_ch = temp_ch & 0xff`, dmnt.c): three octal digits reach
                // 511, so `\777` is a value no byte can hold. Computing this in
                // a `u8` overflowed and panicked — found by the fuzz target in
                // seconds, on a field a local user can influence by mounting.
                let v = (d[0] - b'0') as u32 * 64 + (d[1] - b'0') as u32 * 8 + (d[2] - b'0') as u32;
                out.push((v & 0xff) as u8);
                i += 4;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    OsString::from_vec(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_formed_lines_yield_source_and_dir() {
        let t = "/dev/vda / ext4 rw,relatime 0 0\ntmpfs /dev/shm tmpfs rw 0 0\n";
        assert_eq!(
            parse_mounts(t.as_bytes()),
            vec![
                MountLine {
                    source: "/dev/vda".into(),
                    dir: "/".into(),
                    fstype: "ext4".into()
                },
                MountLine {
                    source: "tmpfs".into(),
                    dir: "/dev/shm".into(),
                    fstype: "tmpfs".into()
                },
            ]
        );
    }

    #[test]
    fn the_kernels_octal_escaping_is_undone() {
        // A mount point with a space is ordinary; the kernel writes `\040`.
        // Splitting on whitespace without decoding would key it as `/mnt/my`.
        let t = "/dev/sdb /mnt/my\\040disk ext4 rw 0 0\n";
        assert_eq!(parse_mounts(t.as_bytes())[0].dir, "/mnt/my disk");
        // Tab, newline and backslash are the other three the kernel escapes.
        assert_eq!(unescape_octal(b"a\\011b"), "a\tb");
        assert_eq!(unescape_octal(b"a\\012b"), "a\nb");
        assert_eq!(unescape_octal(b"a\\134b"), "a\\b");
        // Shapes the kernel never writes are kept literally, not guessed at.
        assert_eq!(unescape_octal(b"a\\b"), "a\\b");
        assert_eq!(unescape_octal(b"a\\09"), "a\\09");
        assert_eq!(unescape_octal(b"a\\999"), "a\\999");
        // Three octal digits reach 511; the C masks to a byte and so does this,
        // rather than overflowing. `\777` is 0o777 & 0xff = 0xff, kept as the
        // byte it is.
        assert_eq!(unescape_octal(b"\\101"), "A");
        assert_eq!(unescape_octal(b"\\400"), "\u{0}");
        assert_eq!(unescape_octal(b"\\777"), OsStr::from_bytes(b"\xff"));
        assert_eq!(unescape_octal(b"trailing\\"), "trailing\\");
        assert_eq!(unescape_octal(b""), "");
    }

    #[test]
    fn a_byte_that_is_not_utf8_is_kept() {
        // The kernel writes it raw; a lossy read made it U+FFFD, which no
        // argument that names the mount point can equal, and one spelt with a
        // U+FFFD could.
        let m = parse_mounts(b"/dev/sdb1 /media/\xe9t\xe9 vfat rw 0 0\n");
        assert_eq!(m[0].dir, OsStr::from_bytes(b"/media/\xe9t\xe9"));
        assert_eq!(m[0].source, "/dev/sdb1");
    }

    #[test]
    fn a_source_that_is_a_name_is_kept_as_it_stands() {
        // `tmpfs`, `proc`: no Readlink(), and never a block device.
        assert_eq!(source("tmpfs".into()), (Some("tmpfs".into()), false));
        // A path is Readlink()'s spelling: here it holds no link.
        assert_eq!(
            source("/dev/null".into()),
            (Some("/dev/null".into()), false)
        );
        // One Readlink() gives up on matches nothing.
        // The canonical temp directory: a symlinked TMPDIR would be replaced
        // by `Readlink()`, and this compares spellings.
        let tmp = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let dir = tmp.join(format!("lsof-rs-mnt-src-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::os::unix::fs::symlink("l2", dir.join("l1")).unwrap();
        std::os::unix::fs::symlink("l1", dir.join("l2")).unwrap();
        assert_eq!(source(dir.join("l1").into_os_string()), (None, false));
        // A relative link is replaced where it stands, `..` and all.
        std::os::unix::fs::symlink("../null", dir.join("rel")).unwrap();
        let mut want = dir.clone().into_os_string();
        want.push("/../null");
        assert_eq!(
            source(dir.join("rel").into_os_string()),
            (Some(want), false)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn malformed_lines_are_skipped_not_guessed() {
        assert_eq!(parse_mounts(b""), vec![]);
        assert_eq!(parse_mounts(b"onlyonefield\n"), vec![]);
        assert_eq!(parse_mounts(b"src \n"), vec![]);
        // A line with more fields than expected still yields the first two.
        assert_eq!(parse_mounts(b"a b c d e f g\n")[0].dir, "b");
    }

    #[test]
    fn the_live_table_is_readable_and_holds_the_root() {
        // A Linux host always has `/` mounted; an empty table would mean the
        // read or the parse silently dropped everything.
        let m = load(true);
        assert!(!m.is_empty(), "expected a non-empty mount table");
        // A source is spelt when asked for, and not otherwise: `/proc` and the
        // root file system each have one.
        assert!(m.iter().any(|e| e.source.is_some()), "{m:?}");
        assert!(load(false)
            .iter()
            .all(|e| e.source.is_none() && !e.source_is_block));
        assert!(m.iter().any(|e| e.dir == "/"), "no root mount: {m:?}");
        // Every entry's device must match what stat says about its directory.
        for e in &m {
            if let Ok(md) = std::fs::metadata(&e.dir) {
                assert_eq!(md.dev(), e.device, "device mismatch for {:?}", e.dir);
            }
        }
    }
    #[test]
    fn the_file_system_type_is_field_three() {
        // `-N` selects on it, and nothing else here did, so it was discarded.
        // The type is NOT octal-escaped: the kernel writes the file system's
        // own name, which cannot contain a space.
        let t = "/dev/sda1 / ext4 rw,relatime 0 0\n\
                 server:/export /mnt/nfs nfs4 rw 0 0\n\
                 tmpfs /dev/shm tmpfs rw 0 0\n";
        let m = parse_mounts(t.as_bytes());
        assert_eq!(m.len(), 3);
        assert_eq!(m[0].fstype, "ext4");
        assert_eq!(m[1].fstype, "nfs4");
        assert_eq!(m[1].dir, "/mnt/nfs");
        assert_eq!(m[2].fstype, "tmpfs");
        // A line cut short before field 3 still yields a usable mount — the
        // first two fields are what every other caller needs.
        let short = parse_mounts(b"/dev/sda1 /\n");
        assert_eq!(short.len(), 1);
        assert_eq!(short[0].dir, "/");
        assert_eq!(short[0].fstype, "");
        // An escaped mount point keeps working alongside the new field.
        let esc = parse_mounts(b"none /mnt/a\\040b nfs rw 0 0\n");
        assert_eq!(esc[0].dir, "/mnt/a b");
        assert_eq!(esc[0].fstype, "nfs");
    }
}
