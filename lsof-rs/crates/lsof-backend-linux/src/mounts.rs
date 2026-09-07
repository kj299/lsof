//! The mount table, from `/proc/self/mounts`.
//!
//! lsof reads a path argument as a **file system name** when it matches a
//! mounted-on directory, and then selects every open file on that filesystem
//! (Lsof.8; `arg.c`'s `ck_file_arg`). This supplies the table that rule needs:
//! the mounted-on directory, the mount source, and the device every file on the
//! filesystem carries.

use std::os::unix::fs::{FileTypeExt, MetadataExt};

use lsof_core::MountEntry;

/// Read and stat the host's mount table. Unreadable or unstattable rows are
/// dropped rather than guessed at: a mount we cannot measure cannot be matched.
pub fn load() -> Vec<MountEntry> {
    let Ok(text) = std::fs::read_to_string("/proc/self/mounts") else {
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
            // The source is resolved and typed only when it exists: `tmpfs`,
            // `proc` and `cgroup` are names, not paths.
            let (source, source_is_block) = match std::fs::canonicalize(&row.source) {
                Ok(p) => {
                    let is_block = std::fs::metadata(&p)
                        .map(|m| m.file_type().is_block_device())
                        .unwrap_or(false);
                    (Some(p.to_string_lossy().into_owned()), is_block)
                }
                Err(_) => (Some(row.source.clone()), false),
            };
            Some(MountEntry {
                dir: row.dir,
                source,
                source_is_block,
                device,
            })
        })
        .collect()
}

/// One raw `/proc/self/mounts` line: what is mounted, and where.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountLine {
    pub source: String,
    pub dir: String,
}

/// The parsing half of [`load`]. Pure, so the fuzz target can drive it with
/// arbitrary bytes, and it must never panic.
///
/// The kernel writes five space-separated fields and escapes space, tab,
/// newline and backslash in the first two as `\040`, `\011`, `\012` and `\134`
/// (`fs/proc_namespace.c` via `seq_path_root`). A mount point with a space in
/// its name is therefore ordinary, not exotic — and splitting on whitespace
/// without decoding those escapes would silently mis-key it.
pub fn parse_mounts(text: &str) -> Vec<MountLine> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut f = line.split(' ');
        let (Some(source), Some(dir)) = (f.next(), f.next()) else {
            continue;
        };
        if dir.is_empty() {
            continue;
        }
        out.push(MountLine {
            source: unescape_octal(source),
            dir: unescape_octal(dir),
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
fn unescape_octal(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    let b = s.as_bytes();
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
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_formed_lines_yield_source_and_dir() {
        let t = "/dev/vda / ext4 rw,relatime 0 0\ntmpfs /dev/shm tmpfs rw 0 0\n";
        assert_eq!(
            parse_mounts(t),
            vec![
                MountLine {
                    source: "/dev/vda".into(),
                    dir: "/".into()
                },
                MountLine {
                    source: "tmpfs".into(),
                    dir: "/dev/shm".into()
                },
            ]
        );
    }

    #[test]
    fn the_kernels_octal_escaping_is_undone() {
        // A mount point with a space is ordinary; the kernel writes `\040`.
        // Splitting on whitespace without decoding would key it as `/mnt/my`.
        let t = "/dev/sdb /mnt/my\\040disk ext4 rw 0 0\n";
        assert_eq!(parse_mounts(t)[0].dir, "/mnt/my disk");
        // Tab, newline and backslash are the other three the kernel escapes.
        assert_eq!(unescape_octal("a\\011b"), "a\tb");
        assert_eq!(unescape_octal("a\\012b"), "a\nb");
        assert_eq!(unescape_octal("a\\134b"), "a\\b");
        // Shapes the kernel never writes are kept literally, not guessed at.
        assert_eq!(unescape_octal("a\\b"), "a\\b");
        assert_eq!(unescape_octal("a\\09"), "a\\09");
        assert_eq!(unescape_octal("a\\999"), "a\\999");
        // Three octal digits reach 511; the C masks to a byte and so does this,
        // rather than overflowing. `\777` is 0o777 & 0xff = 0xff, which is not
        // valid UTF-8 on its own and comes back as the replacement character.
        assert_eq!(unescape_octal("\\101"), "A");
        assert_eq!(unescape_octal("\\400"), "\u{0}");
        assert_eq!(unescape_octal("\\777"), "\u{fffd}");
        assert_eq!(unescape_octal("trailing\\"), "trailing\\");
        assert_eq!(unescape_octal(""), "");
    }

    #[test]
    fn malformed_lines_are_skipped_not_guessed() {
        assert_eq!(parse_mounts(""), vec![]);
        assert_eq!(parse_mounts("onlyonefield\n"), vec![]);
        assert_eq!(parse_mounts("src \n"), vec![]);
        // A line with more fields than expected still yields the first two.
        assert_eq!(parse_mounts("a b c d e f g\n")[0].dir, "b");
    }

    #[test]
    fn the_live_table_is_readable_and_holds_the_root() {
        // A Linux host always has `/` mounted; an empty table would mean the
        // read or the parse silently dropped everything.
        let m = load();
        assert!(!m.is_empty(), "expected a non-empty mount table");
        assert!(m.iter().any(|e| e.dir == "/"), "no root mount: {m:?}");
        // Every entry's device must match what stat says about its directory.
        for e in &m {
            if let Ok(md) = std::fs::metadata(&e.dir) {
                assert_eq!(md.dev(), e.device, "device mismatch for {}", e.dir);
            }
        }
    }
}
