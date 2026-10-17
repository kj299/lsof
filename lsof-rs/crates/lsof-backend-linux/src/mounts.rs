//! The mount table, from `/proc/self/mounts`, read as the C's `readmnt()`
//! reads it (`lib/dialects/linux/dmnt.c`).
//!
//! lsof reads a path argument as a **file system name** when it matches a
//! mounted-on directory, and then selects every open file on that filesystem
//! (Lsof.8; `arg.c`'s `ck_file_arg`); `-e` names one, and `-N` selects the
//! files on NFS. This supplies the table those rules need: the mounted-on
//! directory, the mount source, and the device every file on the filesystem
//! carries.
//!
//! Read and kept as bytes: the kernel escapes only space, tab, newline and
//! backslash, so any other byte of a mount point's name comes through raw, and
//! the argument is compared with it byte for byte.

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::Path;

use lsof_core::render::Escaper;
use lsof_core::{MountEntry, MountKind, MountRequest, MountTable, SafeFs};

/// At most this many bytes of `/proc/self/mounts` are read. The table is the
/// kernel's, but a local user who may mount (a FUSE file system through
/// `fusermount`) chooses its paths, each up to 4,095 bytes and four times
/// that escaped, and `fs.mount-max` allows 100,000 mounts. 64 MiB is two
/// hundred times this host's table (about 2.5 KiB for 26 mounts), and a
/// table of 100,000 mounts of 600 bytes each; what lies past it is not read,
/// and those mounts are not in the table (DIVERGENCES 129). The C reads it
/// all, into a `malloc` per mount.
pub const MOUNTS_MAX_BYTES: u64 = 64 << 20;

/// `      Output information may be incomplete.`: the line the C prints after
/// a warning that the listing may lack something.
const INCOMPLETE: &str = "      Output information may be incomplete.";

/// `/proc/self/mounts`, at most `cap` bytes of it: a table longer than that
/// is cut after the last whole line within it, so no mount is read in part.
/// Empty when it cannot be read.
fn read_capped(path: &Path, cap: u64) -> Vec<u8> {
    let mut text = Vec::new();
    let Ok(file) = std::fs::File::open(path) else {
        return text;
    };
    // One byte past the cap tells a table that ends there from a longer one.
    if file
        .take(cap.saturating_add(1))
        .read_to_end(&mut text)
        .is_err()
    {
        return Vec::new();
    }
    if text.len() as u64 > cap {
        let within = &text[..text.len() - 1];
        let keep = within
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(0, |nl| nl + 1);
        text.truncate(keep);
    }
    text
}

/// Where the kernel lists this process's mounts.
const PROC_MOUNTS: &str = "/proc/self/mounts";

/// Read the host's mount table and examine it as the C does
/// ([`resolve_table`]), through `fs`, the bounded layer, under the options in
/// force where the C reads it.
pub fn load(req: &MountRequest, fs: &SafeFs) -> MountTable {
    load_from(Path::new(PROC_MOUNTS), MOUNTS_MAX_BYTES, req, fs)
}

/// [`load`] of the table at `path`, at most `cap` bytes of it: the one place
/// the table is read for its mounts, so a test reads it under a cap it can
/// pass (DIVERGENCES 129).
fn load_from(path: &Path, cap: u64, req: &MountRequest, fs: &SafeFs) -> MountTable {
    resolve_table(&parse_mounts(&read_capped(path, cap)), req, fs)
}

/// Whether a mount of type `fstype` is listed, its third field compared
/// exactly as the kernel wrote it, and nothing else: what `-Z` asks of the
/// table. No `stat`, no `readlink`, and no line decoded.
pub fn has_type(fstype: &str) -> bool {
    has_type_in(Path::new(PROC_MOUNTS), MOUNTS_MAX_BYTES, fstype)
}

/// [`has_type`] of the table at `path`, at most `cap` bytes of it, as
/// [`load_from`] reads it.
fn has_type_in(path: &Path, cap: u64, fstype: &str) -> bool {
    read_capped(path, cap)
        .split(|&b| b == b'\n')
        .any(|line| line.split(|&b| b == b' ').nth(2) == Some(fstype.as_bytes()))
}

/// Whether the C skips a mount before it looks at it at all (`dmnt.c:420-434`):
/// an automounter's (a source whose FIRST `:` is followed by `(pid`, in any
/// case: `server:(pid1234)`, the BSD `amd` spelling), and a mount of type
/// `autofs`, `pipefs` or `sockfs`, in any case. Nothing of it is read, `stat`ed
/// or recorded: a path argument naming its directory is a plain file, `+f` of
/// its source is `not a file system`, and `-e` of it is refused (measured).
/// So an autofs mount point is never `stat`ed, and never mounted by lsof.
fn skipped(line: &MountLine) -> bool {
    let src = line.source.as_bytes();
    let automounter = src.iter().position(|&b| b == b':').is_some_and(|colon| {
        src[colon + 1..]
            .get(..4)
            .is_some_and(|w| w.eq_ignore_ascii_case(b"(pid"))
    });
    let ty = line.fstype.as_bytes();
    automounter
        || [&b"autofs"[..], b"pipefs", b"sockfs"]
            .iter()
            .any(|t| ty.eq_ignore_ascii_case(t))
}

/// `nfs`, `nfs3` or `nfs4`, in any case (`dmnt.c:497-499`, `strcasecmp`).
fn is_nfs(fstype: &OsStr) -> bool {
    let ty = fstype.as_bytes();
    [&b"nfs"[..], b"nfs3", b"nfs4"]
        .iter()
        .any(|t| ty.eq_ignore_ascii_case(t))
}

/// The table as the C's `readmnt()` makes it of the kernel's lines
/// (`dmnt.c:400-660`), mount by mount in the kernel's order:
///
/// 1. A mount it skips ([`skipped`]) is left out before anything is asked.
/// 2. An `-e`/`+e` mount is one whose directory, as the kernel spells it, is
///    exactly an exempt path. It is never `stat`ed, nor its source; `+e`'s
///    directory and source are not `Readlink()`ed either.
/// 3. The directory is spelt by `Readlink()`. One it gives up on is dropped,
///    with its message and the `Output information` line, unless `-w`; one
///    whose spelling does not start with `/` is dropped in silence.
/// 4. A directory already recorded is a duplicate: the first row stays, with
///    its source and type, and the later one is neither `stat`ed nor read.
///    For `/` alone an NFS row replaces a row that is not NFS.
/// 5. The directory is `stat`ed, once. One that cannot be (any error, a
///    timeout and `-b` included) is dropped, with `lsof: WARNING: can't
///    stat() TYPE file system DIR` and the `Output information` line unless
///    `-w`, and was never recorded: a later row of the same directory is
///    tried again (measured: as `nobody`, and under `-b`, each of a host's
///    two `/dev/shm` rows is warned of).
/// 6. The source is spelt by `Readlink()` when it is a path (one it gives up
///    on says so, with no second line, and the mount is kept), and then
///    `stat`ed for whether it is a block device: not for an `-e`/`+e`
///    mount, and in silence.
///
/// Every call goes through `fs`, whose `-b` says `avoiding readlink(DIR)` and
/// `avoiding stat(DIR)` before the warning, so under `-b` each mount prints
/// the C's four lines, a duplicate its own again. The warnings go to `fs`'s
/// sink as they are found, escaped as `safestrprt()` escapes them (`^[`,
/// `\n`), and `-w` (and `-t`) mute them: `fs.warns()`. Measured against the C
/// in a private mount namespace holding each such mount (DIVERGENCES 87, 110).
pub fn resolve_table(lines: &[MountLine], req: &MountRequest, fs: &SafeFs) -> MountTable {
    let esc = Escaper::UNIX;
    let mut table = MountTable::default();
    // Where each directory recorded is in `table.entries`: the duplicate
    // test asks it of every row, and a table may hold as many rows as the
    // cap lets in (100,000 mounts or more), so a scan of the entries for
    // each would cost the square of that.
    let mut recorded: HashMap<OsString, usize> = HashMap::new();
    for line in lines {
        if skipped(line) {
            continue;
        }
        // The C keeps its list newest first and takes the first match; a
        // path is entered once, so at most one matches.
        let exempt = req.exempt.iter().find(|e| e.path == line.dir);
        let (no_readlink, no_stat) = exempt.map_or((false, false), |e| (e.plus, true));
        let dir = if no_readlink {
            line.dir.clone()
        } else {
            match lsof_core::readlink::resolve(&line.dir, fs) {
                Ok(dir) => dir,
                Err(e) => {
                    if fs.warns() {
                        fs.tell(&format!(
                            "lsof: {}",
                            e.message(&esc.bytes(line.dir.as_bytes()))
                        ));
                        fs.tell(INCOMPLETE);
                    }
                    continue;
                }
            }
        };
        if dir.as_bytes().first() != Some(&b'/') {
            continue;
        }
        let nfs = is_nfs(&line.fstype);
        // Before the duplicate test: an NFS row dropped as one still counts.
        if nfs && table.has_nfs == 0 {
            table.has_nfs = 1;
        }
        let duplicate = recorded.get(&dir).copied();
        if let Some(i) = duplicate {
            let replaces = dir.as_bytes() == b"/" && table.entries[i].kind != MountKind::Nfs && nfs;
            if !replaces {
                continue;
            }
        }
        let device = if no_stat {
            None
        } else {
            match fs.stat(Path::new(&dir)) {
                Ok(st) => Some(st.dev),
                Err(_) => {
                    if fs.warns() {
                        fs.tell(&format!(
                            "lsof: WARNING: can't stat() {} file system {}",
                            esc.bytes(line.fstype.as_bytes()),
                            esc.bytes(dir.as_bytes())
                        ));
                        fs.tell(INCOMPLETE);
                    }
                    continue;
                }
            }
        };
        let kind = if nfs {
            table.has_nfs = 2;
            MountKind::Nfs
        } else if line.fstype.as_bytes() == b"mqueue" {
            // The last one recorded wins, an `-e` one's too, which has none.
            table.mqueue_device = device;
            MountKind::Mqueue
        } else {
            MountKind::Regular
        };
        let (source_resolved, source_is_block) = source(&line.source, exempt, fs, esc);
        let entry = MountEntry {
            dir,
            device,
            source_resolved,
            source_is_block,
            kind,
        };
        match duplicate {
            Some(i) => table.entries[i] = entry,
            None => {
                recorded.insert(entry.dir.clone(), table.entries.len());
                table.entries.push(entry);
            }
        }
    }
    table
}

/// A mount's source as the C's `readmnt()` keeps it to compare with a path
/// argument (`dmnt.c:624-656`, `fsnmres` and `fs_mode`): a path — one that
/// starts with `/` — spelt by `Readlink()`, and a block device if what that
/// names is one; a name like `tmpfs` or `proc` as it stands, and never a
/// block device. A path `Readlink()` gives up on matches nothing, and says
/// so, with no `Output information` line, unless `-w`. An `-e` mount's
/// source is read but not `stat`ed, a `+e` mount's neither (`ignrdl`,
/// `ignstat`): measured, `-e` of a mount whose source is a link loop prints
/// the loop's message, `+e` of it nothing.
///
/// `canonicalize()` had resolved both, so a relative link — `/dev/mapper/x`
/// -> `../dm-0` — became `/dev/dm-0`, where the C keeps
/// `/dev/mapper/../dm-0`, the spelling the same link gives an argument; and a
/// file in the working directory named like a source turned the name into a
/// path.
fn source(
    raw: &OsStr,
    exempt: Option<&lsof_core::ExemptFs>,
    fs: &SafeFs,
    esc: Escaper,
) -> (Option<OsString>, bool) {
    if exempt.is_some_and(|e| e.plus) || raw.as_bytes().first() != Some(&b'/') {
        return (Some(raw.to_os_string()), false);
    }
    match lsof_core::readlink::resolve(raw, fs) {
        Ok(path) => {
            let is_block = exempt.is_none()
                && fs
                    .stat(Path::new(&path))
                    .is_ok_and(|st| st.is_block_device());
            (Some(path), is_block)
        }
        Err(e) => {
            if fs.warns() {
                fs.tell(&format!("lsof: {}", e.message(&esc.bytes(raw.as_bytes()))));
            }
            (None, false)
        }
    }
}

/// One raw `/proc/self/mounts` line: what is mounted, and where.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountLine {
    pub source: OsString,
    pub dir: OsString,
    /// Field 3 — the file-system type (`ext4`, `nfs4`, `tmpfs`), as the
    /// kernel wrote it: the C compares and prints its `fp[2]` without
    /// undoing the escapes, which a FUSE subtype may hold. Bytes, as a
    /// subtype need not be UTF-8.
    pub fstype: OsString,
}

/// The parsing half of [`load`]. Pure, so the fuzz target can drive it with
/// arbitrary bytes, and it must never panic.
///
/// The kernel writes six space-separated fields and escapes space, tab,
/// newline and backslash in the first two as `\040`, `\011`, `\012` and `\134`
/// (`fs/proc_namespace.c` via `seq_path_root`). A mount point with a space in
/// its name is therefore ordinary, not exotic — and splitting on whitespace
/// without decoding those escapes would silently mis-key it. A line with
/// fewer than three fields is no mount, as it is none to the C's `readmnt()`
/// (`get_fields(…) < 3`): it had been kept with an empty type.
pub fn parse_mounts(text: &[u8]) -> Vec<MountLine> {
    let mut out = Vec::new();
    for line in text.split(|&b| b == b'\n') {
        let mut f = line.split(|&b| b == b' ');
        let (Some(source), Some(dir), Some(fstype)) = (f.next(), f.next(), f.next()) else {
            continue;
        };
        if source.is_empty() || dir.is_empty() || fstype.is_empty() {
            continue;
        }
        out.push(MountLine {
            source: unescape_octal(source),
            dir: unescape_octal(dir),
            fstype: OsStr::from_bytes(fstype).to_os_string(),
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
    use lsof_core::safefs::{Blocking, FileStat, FsCalls};
    use lsof_core::ExemptFs;
    use std::cell::RefCell;
    use std::collections::HashMap;

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
    fn malformed_lines_are_skipped_not_guessed() {
        assert_eq!(parse_mounts(b""), vec![]);
        assert_eq!(parse_mounts(b"onlyonefield\n"), vec![]);
        assert_eq!(parse_mounts(b"src \n"), vec![]);
        // (l) Two fields are no mount to the C (`get_fields(…) < 3`); it had
        // been kept with an empty type.
        assert_eq!(parse_mounts(b"/dev/sda1 /\n"), vec![]);
        assert_eq!(parse_mounts(b"/dev/sda1 / \n"), vec![]);
        // A line with more fields than expected still yields the first three.
        assert_eq!(parse_mounts(b"a b c d e f g\n")[0].dir, "b");
    }

    #[test]
    fn the_file_system_type_is_field_three_as_written() {
        // `-N` selects on it. The C compares and prints field 3 as the kernel
        // wrote it, escapes and all.
        let t = "/dev/sda1 / ext4 rw,relatime 0 0\n\
                 server:/export /mnt/nfs nfs4 rw 0 0\n\
                 tmpfs /dev/shm tmpfs rw 0 0\n\
                 s /f fuse.a\\040b rw 0 0\n";
        let m = parse_mounts(t.as_bytes());
        assert_eq!(m.len(), 4);
        assert_eq!(m[0].fstype, "ext4");
        assert_eq!(m[1].fstype, "nfs4");
        assert_eq!(m[1].dir, "/mnt/nfs");
        assert_eq!(m[2].fstype, "tmpfs");
        assert_eq!(m[3].fstype, "fuse.a\\040b");
    }

    /// A past-the-cap table is cut at a line, and a short one is whole.
    #[test]
    fn a_table_past_the_cap_is_cut_after_a_whole_line() {
        let tmp = std::env::temp_dir().join(format!("lsof-rs-mounts-cap-{}", std::process::id()));
        std::fs::write(&tmp, b"a /a t 0 0\nb /b t 0 0\nc /c t 0 0\n").unwrap();
        assert_eq!(read_capped(&tmp, 1 << 20).len(), 33);
        assert_eq!(read_capped(&tmp, 33).len(), 33, "exactly the cap is whole");
        assert_eq!(read_capped(&tmp, 32), b"a /a t 0 0\nb /b t 0 0\n");
        assert_eq!(read_capped(&tmp, 22), b"a /a t 0 0\nb /b t 0 0\n");
        assert_eq!(read_capped(&tmp, 21), b"a /a t 0 0\n");
        assert_eq!(read_capped(&tmp, 5), b"");
        std::fs::remove_file(&tmp).ok();
        assert!(read_capped(Path::new("/nonexistent/mounts"), 10).is_empty());
    }

    /// Both reads of the table, the mounts and `-Z`'s types, stop at the
    /// cap: what lies past it is neither in the table nor asked about. A
    /// read that skipped the cap had passed the test above, which reads the
    /// file itself (DIVERGENCES 129).
    #[test]
    fn the_table_and_its_types_are_read_up_to_the_cap() {
        let tmp =
            std::env::temp_dir().join(format!("lsof-rs-mounts-cap-at-{}", std::process::id()));
        std::fs::write(&tmp, b"a /a t 0 0\nb /b t 0 0\nc /c u 0 0\n").unwrap();
        let host = Host::default();
        let quiet = |_: &str| {};
        let fs = SafeFs::new(&host, &quiet);
        let t = load_from(&tmp, 22, &MountRequest::default(), &fs);
        assert_eq!(dirs(&t), ["/a", "/b"]);
        assert!(host.calls_of("/c").is_empty(), "past the cap, asked");
        assert!(has_type_in(&tmp, 22, "t"));
        assert!(!has_type_in(&tmp, 22, "u"), "past the cap, read");
        assert!(has_type_in(&tmp, 1 << 20, "u"));
        assert!(!has_type_in(&tmp, 1 << 20, "/c"), "the third field alone");
        assert!(!has_type_in(&tmp, 1 << 20, "U"), "as written, exactly");
        std::fs::remove_file(&tmp).ok();
    }

    /// A table as long as the cap may let in is read in time linear in its
    /// rows: 50,000 mounts, every one listed twice, the first row of each
    /// kept, each directory `stat`ed once. A scan of the entries per row
    /// (the duplicate test as it was) made this 2.5e9 comparisons of paths.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "100,000 rows under the interpreter outlast CI's miri job; a timing test means nothing there"
    )]
    fn a_long_table_keeps_each_first_row_in_linear_time() {
        let n = 50_000;
        let mut text = String::new();
        for pass in ["a", "b"] {
            for i in 0..n {
                text.push_str(&format!("{pass}{i} /m/{i} tmpfs rw 0 0\n"));
            }
        }
        let quiet = |_: &str| {};
        let host = Host::default();
        let fs = SafeFs::new(&host, &quiet);
        let start = std::time::Instant::now();
        let t = resolve_table(&table(&text), &MountRequest::default(), &fs);
        let took = start.elapsed();
        assert_eq!(t.entries.len(), n);
        assert!(t
            .entries
            .iter()
            .all(|m| m.source_resolved.as_ref().unwrap().as_bytes()[0] == b'a'));
        assert_eq!(host.calls_of("/m/7"), ["readlink", "stat", "readlink"]);
        assert!(took < std::time::Duration::from_secs(5), "took {took:?}");
    }

    /// The host's file system as a table of answers: what each path `stat`s
    /// to (by default a directory on device 1), which paths are links, and
    /// every call asked, with its limit.
    #[derive(Default)]
    struct Host {
        stats: HashMap<&'static str, std::io::Result<FileStat>>,
        links: HashMap<&'static str, &'static str>,
        asked: RefCell<Vec<(&'static str, String, u32)>>,
    }

    impl Host {
        fn note(&self, call: &'static str, p: &Path, limit: u32) {
            self.asked
                .borrow_mut()
                .push((call, p.to_string_lossy().into_owned(), limit));
        }
        /// Every call made of `path`, by name.
        fn calls_of(&self, path: &str) -> Vec<&'static str> {
            self.asked
                .borrow()
                .iter()
                .filter(|(_, p, _)| p == path)
                .map(|(c, _, _)| *c)
                .collect()
        }
    }

    fn dir_on(dev: u64) -> std::io::Result<FileStat> {
        Ok(FileStat {
            dev,
            mode: 0o040_755,
            ..FileStat::default()
        })
    }

    fn errno(n: i32) -> std::io::Result<FileStat> {
        Err(std::io::Error::from_raw_os_error(n))
    }

    impl FsCalls for Host {
        fn stat(&self, p: &Path, limit: u32) -> std::io::Result<FileStat> {
            self.note("stat", p, limit);
            match self.stats.get(p.to_str().unwrap()) {
                Some(Ok(st)) => Ok(*st),
                Some(Err(e)) => Err(std::io::Error::from(e.kind())),
                None => dir_on(1),
            }
        }
        fn lstat(&self, _: &Path, _: u32) -> std::io::Result<FileStat> {
            unreachable!("the mount table is stat()ed, never lstat()ed")
        }
        fn readlink(&self, p: &Path, limit: u32) -> std::io::Result<OsString> {
            self.note("readlink", p, limit);
            match self.links.get(p.to_str().unwrap()) {
                Some(t) => Ok((*t).into()),
                None => Err(std::io::Error::from_raw_os_error(22)),
            }
        }
        fn read_dir(&self, _: &Path, _: u32) -> std::io::Result<Vec<OsString>> {
            unreachable!("the mount table lists no directory")
        }
    }

    fn table(text: &str) -> Vec<MountLine> {
        parse_mounts(text.as_bytes())
    }

    fn e(path: &str, plus: bool) -> ExemptFs {
        ExemptFs {
            path: path.into(),
            plus,
        }
    }

    /// `resolve_table` over `host`, with `exempt` and the options `blocking`
    /// and `warn`: the table, and every line it said.
    fn resolve_with(
        host: &Host,
        text: &str,
        exempt: Vec<ExemptFs>,
        blocking: Blocking,
        warn: bool,
    ) -> (MountTable, Vec<String>) {
        let said = RefCell::new(Vec::new());
        let say = |l: &str| said.borrow_mut().push(l.to_string());
        let fs = SafeFs::new(host, &say).with(blocking, warn);
        let t = resolve_table(&table(text), &MountRequest { exempt }, &fs);
        (t, said.into_inner())
    }

    fn resolve(host: &Host, text: &str, exempt: Vec<ExemptFs>) -> (MountTable, Vec<String>) {
        resolve_with(host, text, exempt, Blocking::default(), true)
    }

    fn dirs(t: &MountTable) -> Vec<&str> {
        t.entries.iter().map(|m| m.dir.to_str().unwrap()).collect()
    }

    /// (a), (b): what the C skips is never asked about, and not recorded.
    #[test]
    fn resolve_table_skips_automounters_and_three_types_before_asking() {
        let host = Host::default();
        let (t, said) = resolve(
            &host,
            "a /a autofs rw 0 0\n\
             b /b AutoFS rw 0 0\n\
             c /c pipefs rw 0 0\n\
             d /d SOCKFS rw 0 0\n\
             srv:(PID12) /e nfs rw 0 0\n\
             srv:(pid1) /f tmpfs rw 0 0\n\
             a:b:(pid1) /g tmpfs rw 0 0\n\
             x:(pi /h tmpfs rw 0 0\n\
             autofsx /i autofsx rw 0 0\n",
            vec![],
        );
        // Only the first `:` counts, and `(pi` is not `(pid`.
        assert_eq!(dirs(&t), ["/g", "/h", "/i"]);
        for skipped in ["/a", "/b", "/c", "/d", "/e", "/f"] {
            assert!(
                host.calls_of(skipped).is_empty(),
                "{skipped} was asked about"
            );
        }
        assert_eq!(t.has_nfs, 0, "a skipped NFS row is no NFS");
        assert!(said.is_empty(), "{said:?}");
    }

    /// (c): an `-e` mount's directory and source are read, never `stat`ed; a
    /// `+e` mount's are not even read. Both are recorded with no device.
    #[test]
    fn resolve_table_never_stats_an_exempt_mount() {
        let host = Host::default();
        let text = "/dev/x /m tmpfs rw 0 0\n/dev/y /p tmpfs rw 0 0\n/dev/z /q tmpfs rw 0 0\n";
        let (t, said) = resolve(&host, text, vec![e("/m", false), e("/p", true)]);
        assert_eq!(dirs(&t), ["/m", "/p", "/q"]);
        assert_eq!(t.entries[0].device, None);
        assert_eq!(t.entries[1].device, None);
        assert_eq!(t.entries[2].device, Some(1));
        assert!(!t.entries[0].source_is_block && !t.entries[1].source_is_block);
        // `-e`: the directory's and the source's components, Readlink()ed.
        assert_eq!(host.calls_of("/m"), ["readlink"]);
        assert_eq!(host.calls_of("/dev/x"), ["readlink"]);
        assert_eq!(
            t.entries[0].source_resolved.as_deref(),
            Some(OsStr::new("/dev/x"))
        );
        // `+e`: nothing at all, and the source kept as it stands.
        assert!(host.calls_of("/p").is_empty());
        assert!(host.calls_of("/dev/y").is_empty());
        assert_eq!(
            t.entries[1].source_resolved.as_deref(),
            Some(OsStr::new("/dev/y"))
        );
        // The rest as ever: read, then stat()ed, source too.
        assert_eq!(host.calls_of("/q"), ["readlink", "stat"]);
        assert_eq!(host.calls_of("/dev/z"), ["readlink", "stat"]);
        // An exempt path is the directory as the kernel spells it, exactly.
        let (t, _) = resolve(&host, text, vec![e("/m/", false)]);
        assert_eq!(t.entries[0].device, Some(1));
        assert!(said.is_empty(), "{said:?}");
    }

    /// (d), (e): a directory listed twice is the first row's, with the top
    /// mount's device, `stat`ed once; one whose `stat` failed was not
    /// recorded, so its next row is tried again.
    #[test]
    fn resolve_table_keeps_the_first_row_of_a_directory_with_its_one_stat() {
        let mut host = Host::default();
        host.stats.insert("/dup", dir_on(0x2f));
        let (t, said) = resolve(
            &host,
            "src_dup_bottom /dup tmpfs rw 0 0\nsrc_dup_top /dup ramfs rw 0 0\n",
            vec![],
        );
        assert_eq!(t.entries.len(), 1);
        assert_eq!(
            t.entries[0].source_resolved.as_deref(),
            Some(OsStr::new("src_dup_bottom"))
        );
        assert_eq!(t.entries[0].device, Some(0x2f));
        // The second row's directory is read, for the duplicate test is on
        // its spelling, and then nothing more.
        assert_eq!(host.calls_of("/dup"), ["readlink", "stat", "readlink"]);
        // So `+f -- src_dup_top` names no file system, and the bottom does.
        use lsof_core::selection::filesystems_named;
        use lsof_core::FilesystemArgs::AlwaysFilesystem;
        let named = |p: &str| filesystems_named(&t.entries, OsStr::new(p), AlwaysFilesystem);
        assert!(named("src_dup_top").is_empty());
        assert_eq!(named("src_dup_bottom"), [0x2f]);
        assert!(said.is_empty());

        let mut host = Host::default();
        host.stats.insert("/a", errno(2));
        let (t, said) = resolve(&host, "s1 /a tmpfs rw 0 0\ns2 /a tmpfs rw 0 0\n", vec![]);
        assert!(t.entries.is_empty());
        assert_eq!(
            host.calls_of("/a"),
            ["readlink", "stat", "readlink", "stat"]
        );
        let pair = [
            "lsof: WARNING: can't stat() tmpfs file system /a",
            "      Output information may be incomplete.",
        ];
        assert_eq!(said, [pair, pair].concat());
        // A later row that can be stat()ed is recorded.
        let mut host = Host::default();
        host.stats.insert("/a", errno(2));
        let calls = RefCell::new(0);
        struct Second<'a>(&'a Host, &'a RefCell<u32>);
        impl FsCalls for Second<'_> {
            fn stat(&self, p: &Path, l: u32) -> std::io::Result<FileStat> {
                *self.1.borrow_mut() += 1;
                if *self.1.borrow() == 1 {
                    self.0.stat(p, l)
                } else {
                    dir_on(9)
                }
            }
            fn lstat(&self, p: &Path, l: u32) -> std::io::Result<FileStat> {
                self.0.lstat(p, l)
            }
            fn readlink(&self, p: &Path, l: u32) -> std::io::Result<OsString> {
                self.0.readlink(p, l)
            }
            fn read_dir(&self, p: &Path, l: u32) -> std::io::Result<Vec<OsString>> {
                self.0.read_dir(p, l)
            }
        }
        let second = Second(&host, &calls);
        let fs = SafeFs::new(&second, &|_: &str| {});
        let t = resolve_table(
            &table("s1 /a tmpfs rw 0 0\ns2 /a xfs rw 0 0\n"),
            &MountRequest::default(),
            &fs,
        );
        assert_eq!(dirs(&t), ["/a"]);
        assert_eq!(
            (t.entries[0].source_resolved.as_deref(), t.entries[0].device),
            (Some(OsStr::new("s2")), Some(9))
        );
    }

    /// (f): `/` listed twice keeps the first row unless an NFS row follows
    /// one that is not NFS, which replaces it, and is `stat`ed.
    #[test]
    fn resolve_table_lets_nfs_alone_replace_the_root() {
        let mut host = Host::default();
        host.stats.insert("/", dir_on(0xfe00));
        let (t, _) = resolve(
            &host,
            "/dev/vda / ext4 rw 0 0\nnone / tmpfs rw 0 0\nsrv:/x / nfs rw 0 0\nnone / ext4 rw 0 0\n",
            vec![],
        );
        assert_eq!(t.entries.len(), 1);
        assert_eq!(
            (t.entries[0].source_resolved.as_deref(), t.entries[0].kind),
            (Some(OsStr::new("srv:/x")), MountKind::Nfs)
        );
        assert_eq!(
            host.calls_of("/").iter().filter(|c| **c == "stat").count(),
            2
        );
        assert_eq!(t.has_nfs, 2);
        // An NFS row first is kept against another NFS row too.
        let (t, _) = resolve(&host, "a:/ / nfs4 rw 0 0\nb:/ / NFS rw 0 0\n", vec![]);
        assert_eq!(
            t.entries[0].source_resolved.as_deref(),
            Some(OsStr::new("a:/"))
        );
        // A directory but `/` is never replaced, NFS or not.
        let (t, _) = resolve(&host, "x /m ext4 rw 0 0\ns:/ /m nfs rw 0 0\n", vec![]);
        assert_eq!((t.entries[0].kind, t.has_nfs), (MountKind::Regular, 1));
    }

    /// (g), (h), and a directory `Readlink()` spells as another one.
    #[test]
    fn resolve_table_spells_a_directory_and_a_source_by_readlink() {
        let mut host = Host::default();
        host.links.insert("/x/m", "m2");
        host.links.insert("/x/m2", "m");
        host.links.insert("/l1", "l2");
        host.links.insert("/l2", "l1");
        host.links.insert("/hp/m", "/plain");
        host.links.insert("/dev/disk", "/dev/real");
        let text = "src_plain /plain tmpfs rw 0 0\n\
                    src_hidden /hp/m tmpfs rw 0 0\n\
                    src_xm /x/m tmpfs rw 0 0\n\
                    /l1 /loopsrc tmpfs rw 0 0\n\
                    /dev/disk/a /d ext4 rw 0 0\n";
        let (t, said) = resolve(&host, text, vec![]);
        // `/hp/m` spells `/plain`: a duplicate, gone; `/x/m` loops: dropped.
        assert_eq!(dirs(&t), ["/plain", "/loopsrc", "/d"]);
        assert_eq!(
            t.entries[0].source_resolved.as_deref(),
            Some(OsStr::new("src_plain"))
        );
        assert!(!host.calls_of("/plain").is_empty());
        assert_eq!(
            said,
            [
                "lsof: too many (> 20) symbolic links in readlink() path: /x/m",
                "      Output information may be incomplete.",
                "lsof: too many (> 20) symbolic links in readlink() path: /l1",
            ]
        );
        // A source that loops is kept, matching nothing, and never stat()ed.
        assert_eq!(t.entries[1].source_resolved, None);
        assert!(!host.calls_of("/l1").contains(&"stat"));
        assert_eq!(
            t.entries[2].source_resolved.as_deref(),
            Some(OsStr::new("/dev/real/a"))
        );
        // `-w` mutes both.
        let (_, said) = resolve_with(&host, text, vec![], Blocking::default(), false);
        assert!(said.is_empty(), "{said:?}");
        // A directory `Readlink()` does not spell from the root is dropped,
        // in silence, before it is `stat`ed (`if (*dn != '/') continue`).
        let (t, said) = resolve(&host, "s rel tmpfs rw 0 0\n", vec![]);
        assert!(t.entries.is_empty() && said.is_empty(), "{t:?} {said:?}");
        assert_eq!(host.calls_of("rel"), ["readlink"]);
    }

    /// (i), (j), (k): a name for a source is kept as it stands and never
    /// asked about; the types the C names; and `HasNFS`.
    #[test]
    fn resolve_table_types_mounts_as_the_c_does() {
        let mut host = Host::default();
        host.stats.insert("/q1", dir_on(0x14));
        host.stats.insert("/q2", dir_on(0x15));
        let (t, _) = resolve(
            &host,
            "tmpfs /t tmpfs rw 0 0\n\
             s:/ /n1 nfs rw 0 0\n\
             s:/ /n2 NFS3 rw 0 0\n\
             s:/ /n3 nfs4 rw 0 0\n\
             s:/ /n4 nfsd rw 0 0\n\
             mq /q1 mqueue rw 0 0\n\
             mq /q2 MQUEUE rw 0 0\n",
            vec![],
        );
        assert!(host.calls_of("tmpfs").is_empty());
        assert_eq!(
            t.entries[0].source_resolved.as_deref(),
            Some(OsStr::new("tmpfs"))
        );
        let kinds: Vec<MountKind> = t.entries.iter().map(|m| m.kind).collect();
        use MountKind::*;
        assert_eq!(kinds, [Regular, Nfs, Nfs, Nfs, Regular, Mqueue, Regular]);
        assert_eq!(t.mqueue_device, Some(0x14), "`MQUEUE` is no mqueue");
        assert_eq!(t.has_nfs, 2);
        // The last mqueue recorded is the one, an -e one's no device too.
        let (t, _) = resolve(
            &host,
            "mq /q2 mqueue rw 0 0\nmq /q1 mqueue rw 0 0\n",
            vec![],
        );
        assert_eq!(t.mqueue_device, Some(0x14));
        let (t, _) = resolve(
            &host,
            "mq /q1 mqueue rw 0 0\nmq /q2 mqueue rw 0 0\n",
            vec![e("/q2", false)],
        );
        assert_eq!(t.mqueue_device, None);
        // An NFS row seen but not recorded is 1: its stat failed.
        host.stats.insert("/n", errno(13));
        let (t, _) = resolve(&host, "s:/ /n nfs rw 0 0\n", vec![]);
        assert_eq!((t.has_nfs, t.entries.len()), (1, 0));
    }

    /// (m): the warning escapes what it quotes, as `safestrprt()` does.
    #[test]
    fn resolve_table_escapes_what_a_warning_quotes() {
        let mut host = Host::default();
        host.stats.insert("/g/\x1b[2J x\ny", errno(2));
        let (_, said) = resolve(
            &host,
            "src\\033 /g/\x1b[2J\\040x\\012y fuse.a\x1b rw 0 0\n",
            vec![],
        );
        assert_eq!(
            said,
            [
                "lsof: WARNING: can't stat() fuse.a^[ file system /g/^[[2J x\\ny",
                "      Output information may be incomplete.",
            ]
        );
    }

    /// Under `-b` every mount but an exempt one says the C's four lines, in
    /// its order, a duplicate again, and nothing is asked of anyone; `-w`
    /// mutes them all.
    #[test]
    fn resolve_table_under_b_says_four_lines_a_mount() {
        let host = Host::default();
        let b = Blocking {
            avoid: true,
            ..Blocking::default()
        };
        let text = "tmpfs /a tmpfs rw 0 0\ntmpfs /a tmpfs rw 0 0\n/dev/y /e tmpfs rw 0 0\n";
        let (t, said) = resolve_with(&host, text, vec![e("/e", false)], b, true);
        assert!(host.asked.borrow().is_empty(), "-b made a call");
        let four = [
            "lsof: avoiding readlink(/a): -b was specified.",
            "lsof: avoiding stat(/a): -b was specified.",
            "lsof: WARNING: can't stat() tmpfs file system /a",
            "      Output information may be incomplete.",
        ];
        let exempt = [
            "lsof: avoiding readlink(/e): -b was specified.",
            "lsof: avoiding readlink(/dev/y): -b was specified.",
        ];
        assert_eq!(said, [&four[..], &four[..], &exempt[..]].concat());
        assert_eq!(dirs(&t), ["/e"]);
        let (t, said) = resolve_with(&host, text, vec![e("/e", false)], b, false);
        assert!(said.is_empty(), "{said:?}");
        assert_eq!(dirs(&t), ["/e"]);
    }

    /// Every call goes through the bounded layer with the limit `-S` gave,
    /// and a mount that times out is dropped with the C's warning.
    #[test]
    fn every_mount_point_is_stated_through_the_bounded_layer() {
        let mut host = Host::default();
        host.stats
            .insert("/hung", Err(lsof_core::safefs::timed_out()));
        let four = Blocking {
            limit: 4,
            ..Blocking::default()
        };
        let (t, said) = resolve_with(
            &host,
            "/dev/vda / ext4 rw 0 0\nfuse /hung fuse.hang rw 0 0\n",
            vec![],
            four,
            true,
        );
        assert_eq!(dirs(&t), ["/"]);
        let asked = host.asked.borrow();
        assert!(
            !asked.is_empty() && asked.iter().all(|(_, _, l)| *l == 4),
            "{asked:?}"
        );
        assert_eq!(
            said,
            [
                "lsof: WARNING: can't stat() fuse.hang file system /hung",
                "      Output information may be incomplete.",
            ]
        );
    }

    /// A source that is a path is read as `Readlink()` reads it, and then
    /// `stat`ed for whether it is a block device, every call through the
    /// bounded layer with the limit `-S` gave: a source on a file system that
    /// does not answer costs the limit, not the run.
    #[test]
    fn a_source_is_read_and_stated_through_the_bounded_layer() {
        let mut host = Host::default();
        host.links.insert("/dev/disk/x", "../../vda");
        host.stats.insert(
            "/dev/disk/../../vda",
            Ok(FileStat {
                mode: 0o060_660,
                ..FileStat::default()
            }),
        );
        let four = Blocking {
            limit: 4,
            ..Blocking::default()
        };
        let said = RefCell::new(Vec::<String>::new());
        let say = |l: &str| said.borrow_mut().push(l.to_string());
        let fs = SafeFs::new(&host, &say).with(four, true);
        assert_eq!(
            source(OsStr::new("/dev/disk/x"), None, &fs, Escaper::UNIX),
            (Some("/dev/disk/../../vda".into()), true)
        );
        let made = host.asked.take();
        assert!(made.iter().all(|(_, _, limit)| *limit == 4), "{made:?}");
        let made: Vec<(&str, &str)> = made.iter().map(|(c, p, _)| (*c, p.as_str())).collect();
        assert_eq!(
            made,
            [
                ("readlink", "/dev"),
                ("readlink", "/dev/disk"),
                ("readlink", "/dev/disk/x"),
                // Reread past what held no link (`readlink::resolve_with`).
                ("readlink", "/dev/disk/.."),
                ("readlink", "/dev/disk/../.."),
                ("readlink", "/dev/disk/../../vda"),
                ("stat", "/dev/disk/../../vda"),
            ]
        );
        // A name is kept as it stands; an `-e` mount's path source is read
        // and not stat()ed, a `+e` one's neither.
        assert_eq!(
            source(OsStr::new("tmpfs"), None, &fs, Escaper::UNIX),
            (Some("tmpfs".into()), false)
        );
        let minus = e("/m", false);
        assert_eq!(
            source(OsStr::new("/dev/disk/x"), Some(&minus), &fs, Escaper::UNIX),
            (Some("/dev/disk/../../vda".into()), false)
        );
        assert!(!host.asked.take().iter().any(|(c, _, _)| *c == "stat"));
        let plus = e("/m", true);
        assert_eq!(
            source(OsStr::new("/dev/disk/x"), Some(&plus), &fs, Escaper::UNIX),
            (Some("/dev/disk/x".into()), false)
        );
        assert!(host.asked.take().is_empty());
        assert!(said.borrow().is_empty());
    }

    #[test]
    fn a_source_that_is_a_name_is_kept_and_a_real_one_is_read() {
        // `tmpfs`, `proc`: no Readlink(), and never a block device.
        let fs = SafeFs::in_process();
        assert_eq!(
            source(OsStr::new("tmpfs"), None, &fs, Escaper::UNIX),
            (Some("tmpfs".into()), false)
        );
        // A path is Readlink()'s spelling: here it holds no link.
        assert_eq!(
            source(OsStr::new("/dev/null"), None, &fs, Escaper::UNIX),
            (Some("/dev/null".into()), false)
        );
        // The canonical temp directory: a symlinked TMPDIR would be replaced
        // by `Readlink()`, and this compares spellings.
        let tmp = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let dir = tmp.join(format!("lsof-rs-mnt-src-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::os::unix::fs::symlink("../null", dir.join("rel")).unwrap();
        // A relative link is replaced where it stands, `..` and all.
        let mut want = dir.clone().into_os_string();
        want.push("/../null");
        assert_eq!(
            source(dir.join("rel").as_os_str(), None, &fs, Escaper::UNIX),
            (Some(want), false)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_live_table_is_readable_and_holds_the_root() {
        // A Linux host always has `/` mounted; an empty table would mean the
        // read or the parse silently dropped everything.
        use std::os::unix::fs::MetadataExt;
        let quiet = |_: &str| {};
        let fs = SafeFs::new(&lsof_core::InProcess, &quiet);
        let m = load(&MountRequest::default(), &fs);
        assert!(!m.entries.is_empty(), "expected a non-empty mount table");
        assert!(
            m.entries.iter().any(|e| e.dir == "/"),
            "no root mount: {m:?}"
        );
        let listed = std::fs::read_to_string("/proc/self/mounts").unwrap();
        let root_type = listed
            .lines()
            .find(|l| l.split(' ').nth(1) == Some("/"))
            .and_then(|l| l.split(' ').nth(2))
            .unwrap();
        assert!(has_type(root_type));
        assert!(!has_type("no-such-type"));
        // Every entry's device must match what stat says about its directory.
        for e in &m.entries {
            if let Ok(md) = std::fs::metadata(&e.dir) {
                assert_eq!(Some(md.dev()), e.device, "device mismatch for {:?}", e.dir);
            }
        }
        // One entry a directory.
        let mut seen = std::collections::HashSet::new();
        assert!(m.entries.iter().all(|e| seen.insert(e.dir.clone())));
    }
}
