//! Device names, as the C's `readdev()` collects them (`lib/rdev.c`) and
//! `lkupdev()` and `find_ch_ino()` look them up (`lib/lkud.c`, `lib/fino.c`):
//! what `printdevname()` (`lib/pdvn.c`) prints for a character device whose
//! row has no NAME, `/dev/pts/0` for a terminal (DIVERGENCES 146).
//!
//! The table is `readdev()`'s: a walk of `/dev`, every directory of it, each
//! entry `lstat`ed (a symbolic link is neither followed nor named), an entry
//! whose inode is 0 or whose name starts with `.` passed by, and every
//! **character** special kept (FreeBSD's dialect has no `HASBLKDEV`, so a
//! block special is not), with its device, inode and path. The table is then
//! sorted by device, inode and name (`compdev()`, `lib/misc.c:197`) and of
//! entries with the same device and inode only the first kept (`rmdupdev()`):
//! a device two such paths name gets the one that sorts first by `strcmp()`.
//! Lookups are the C's binary searches, so which entry a lookup by device
//! alone meets, of several with that device, is the one the C meets.
//!
//! Read as the C reads it ([`DevCache`]): once, as the run starts
//! (`main.c:1303-1304`, `readdev(ctx, 0)` under `HASDCACHE`, which FreeBSD's
//! `machine.h:139` defines), with its warnings and its `no character devices
//! found`, every run that lists; kept for the run, `-r`'s cycles included;
//! and read again, once, where a lookup misses, or a name it found no
//! longer `lstat`s as the device, after a terminal row has made the table
//! "unsafe" (`DCunsafe`, `dnode.c:750`; `rereaddev()`, `vfy_dev()`,
//! `lib/rdev.c:399-487`). `/dev` is devfs, which answers from memory, so the
//! walk is made in-process, as the C makes it. The device cache file the C
//! can keep (`-D`) is neither read nor written.
//!
//! Bounded where the C is not: at most [`MAX_DIRS`] directories are read and
//! [`MAX_DEVS`] character devices kept, in the walk's order (the last
//! directory found read first, as the C's `Dstk`), and past either the rest
//! are not, with a warning (unless `-w`) that the C, which has no such
//! bound, never gives. A directory whose read fails part way is read no
//! further, as the C's `readdir()` loop ends at its first `NULL`.

use std::cell::{Cell, RefCell};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{DirEntryExt, FileTypeExt, MetadataExt};
use std::path::Path;

/// At most this many directories are read: devfs is small, and a mount over
/// `/dev` (a nullfs of `/dev` inside it) cannot make the walk endless.
pub const MAX_DIRS: usize = 4096;

/// At most this many character devices are kept: a bound on what a file
/// system mounted under `/dev` can make lsof hold (a devfs has hundreds).
pub const MAX_DEVS: usize = 1 << 16;

/// One character special: `struct l_dev`, with its `v`, whether it has been
/// checked against `/dev` since the table became unsafe (`vfy_dev()`).
#[derive(Clone, Debug, PartialEq, Eq)]
struct Dev {
    rdev: u64,
    inode: u64,
    name: Vec<u8>,
    verified: Cell<bool>,
}

/// `Sdev[]`: the sorted, de-duplicated character devices.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DevTable {
    devs: Vec<Dev>,
    /// What the walk had to say (`WARNDEVACCESS`, `machine.h:591`): each
    /// directory it could not open and each entry it could not `lstat` for
    /// another reason than that it is gone.
    pub warnings: Vec<String>,
}

impl DevTable {
    /// The table of `entries` (device, inode, path), as `readdev()` sorts
    /// and de-duplicates them.
    fn from_entries(mut devs: Vec<Dev>, warnings: Vec<String>) -> Self {
        devs.sort_by(|a, b| (a.rdev, a.inode, &a.name[..]).cmp(&(b.rdev, b.inode, &b.name[..])));
        devs.dedup_by(|b, a| a.rdev == b.rdev && a.inode == b.inode);
        devs.shrink_to_fit();
        DevTable { devs, warnings }
    }

    /// Whether no character device was found: the C then says `no
    /// character devices found` and ends the run.
    pub fn is_empty(&self) -> bool {
        self.devs.is_empty()
    }

    /// `lkupdev()`'s binary search for `rdev`: with `inode`, the entry with
    /// that inode too (the C's `i` set and `inp_ty == 1`), without it the
    /// first entry with that device the search meets.
    fn find(&self, rdev: u64, inode: Option<u64>) -> Option<&Dev> {
        let (mut low, mut hi) = (0usize, self.devs.len());
        // `[low, hi)`: the C's `low <= hi` over `[low, hi - 1]`.
        while low < hi {
            let mid = low + (hi - 1 - low) / 2;
            let d = self.devs.get(mid)?;
            if rdev < d.rdev {
                hi = mid;
            } else if rdev > d.rdev {
                low = mid + 1;
            } else {
                match inode {
                    None => return Some(d),
                    Some(i) if i == d.inode => return Some(d),
                    Some(i) if i < d.inode => hi = mid,
                    Some(_) => low = mid + 1,
                }
            }
        }
        None
    }

    /// The name of the device `rdev`, as [`DevTable::find`] finds it.
    #[cfg(test)]
    pub fn name(&self, rdev: u64, inode: Option<u64>) -> Option<String> {
        self.find(rdev, inode)
            .map(|d| String::from_utf8_lossy(&d.name).into_owned())
    }

    /// `find_ch_ino()`: the inode of the first entry with device `rdev` the
    /// search meets, for a character device whose record has none.
    #[cfg(test)]
    pub fn inode(&self, rdev: u64) -> Option<u64> {
        self.find(rdev, None).map(|d| d.inode)
    }
}

/// `readdev()` of `root`, within [`MAX_DIRS`] and [`MAX_DEVS`].
pub fn scan(root: &Path) -> DevTable {
    scan_within(root, MAX_DIRS, MAX_DEVS)
}

/// [`scan`] with its two bounds given: what the tests reach them with.
fn scan_within(root: &Path, max_dirs: usize, max_devs: usize) -> DevTable {
    let esc = lsof_core::Escaper::UNIX;
    let mut devs = Vec::new();
    let mut warnings = Vec::new();
    // `Dstk`: directories still to read, the last pushed read first. Every
    // path in it is one no other has been: an entry is `lstat`ed, so a link
    // is never followed, and each name is its parent's plus a component.
    let mut stack = vec![root.to_path_buf()];
    let mut dirs = 0usize;
    let mut cut_devs = false;
    while let Some(dir) = stack.pop() {
        if dirs == max_dirs {
            warnings.push(format!(
                "lsof: WARNING: more than {max_dirs} directories in {}; the rest are not read",
                esc.bytes(root.as_os_str().as_bytes())
            ));
            break;
        }
        dirs += 1;
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(_) => {
                warnings.push(format!(
                    "lsof: WARNING: can't open: {}",
                    esc.bytes(dir.as_os_str().as_bytes())
                ));
                continue;
            }
        };
        // The C's `readdir()` loop ends at its first `NULL`, an error too.
        for e in rd.map_while(Result::ok) {
            if e.ino() == 0 || e.file_name().as_bytes().first() == Some(&b'.') {
                continue;
            }
            let path = e.path();
            let md = match path.symlink_metadata() {
                Ok(md) => md,
                // A link to nowhere, or an entry gone since the listing.
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(err) => {
                    warnings.push(format!(
                        "lsof: can't stat {}: {}",
                        esc.bytes(path.as_os_str().as_bytes()),
                        lsof_core::backend::errno_text(&err)
                    ));
                    continue;
                }
            };
            let ft = md.file_type();
            if ft.is_dir() {
                stack.push(path);
            } else if ft.is_char_device() {
                if devs.len() == max_devs {
                    cut_devs = true;
                    continue;
                }
                devs.push(Dev {
                    rdev: md.rdev(),
                    inode: md.ino(),
                    name: path.into_os_string().into_vec(),
                    verified: Cell::new(false),
                });
            }
        }
    }
    if cut_devs {
        warnings.push(format!(
            "lsof: WARNING: more than {max_devs} character devices in {}; the rest are not kept",
            esc.bytes(root.as_os_str().as_bytes())
        ));
    }
    DevTable::from_entries(devs, warnings)
}

/// What a lookup comes to: its answer, or a reading of `/dev` again first.
enum Step<T> {
    Done(Option<T>),
    Reread,
}

/// The run's device table as the C keeps it (`Sdev`, `DCunsafe`): made by
/// `scan` the first time it is asked for ([`DevCache::load`], which a run
/// does as it starts), and made again by `scan` where a lookup misses, or a
/// name found no longer `lstat`s (`check`) as the device and inode it was
/// found with, while the table is unsafe — once a terminal row has been
/// made ([`DevCache::mark_unsafe`]) and until the table is read again.
/// `scan` is where the walk's warnings are said, and where a table with no
/// character device ends the run.
pub struct DevCache {
    scan: Scan,
    check: Check,
    table: RefCell<Option<DevTable>>,
    unsafe_: Cell<bool>,
}

/// How [`DevCache`] reads `/dev`.
pub type Scan = Box<dyn Fn() -> DevTable>;

/// How [`DevCache`] asks what a name is now: its `(st_rdev, st_ino)`.
pub type Check = Box<dyn Fn(&[u8]) -> Option<(u64, u64)>>;

impl DevCache {
    pub fn new(scan: Scan, check: Check) -> Self {
        DevCache {
            scan,
            check,
            table: RefCell::new(None),
            unsafe_: Cell::new(false),
        }
    }

    /// `readdev(ctx, 0)`: the table, made now if it has not been.
    pub fn load(&self) {
        if self.table.borrow().is_none() {
            let t = (self.scan)();
            *self.table.borrow_mut() = Some(t);
        }
    }

    /// `rereaddev()`: the table made again, and safe.
    fn reread(&self) {
        let t = (self.scan)();
        *self.table.borrow_mut() = Some(t);
        self.unsafe_.set(false);
    }

    /// `DCunsafe = 1`, as `process_pts()` sets it (`dnode.c:750`).
    pub fn mark_unsafe(&self) {
        self.unsafe_.set(true);
    }

    /// The C's search, its `vfy_dev()` of what it finds, and, with
    /// `reread_on_miss` (`lkupdev()`'s `r`), its `rereaddev()` on a miss,
    /// both while the table is unsafe. Each reading makes the table safe, so
    /// a lookup reads `/dev` at most once more, as the C's does; that is
    /// also a bound here, whatever the table says.
    fn lookup<T>(
        &self,
        rdev: u64,
        inode: Option<u64>,
        reread_on_miss: bool,
        take: impl Fn(&Dev) -> T,
    ) -> Option<T> {
        self.load();
        let mut reread = false;
        loop {
            let step = {
                let table = self.table.borrow();
                match table.as_ref().and_then(|t| t.find(rdev, inode)) {
                    Some(d) if !self.unsafe_.get() || d.verified.get() => Step::Done(Some(take(d))),
                    Some(d) if (self.check)(&d.name) == Some((d.rdev, d.inode)) => {
                        d.verified.set(true);
                        Step::Done(Some(take(d)))
                    }
                    Some(_) => Step::Reread,
                    None if self.unsafe_.get() && reread_on_miss => Step::Reread,
                    None => Step::Done(None),
                }
            };
            match step {
                Step::Done(found) => return found,
                Step::Reread if !reread => {
                    reread = true;
                    self.reread();
                }
                Step::Reread => return None,
            }
        }
    }

    /// `lkupdev(…, r = 1)`'s name of the device `rdev`: with `inode`, the
    /// entry with that inode too, without it the first the search meets.
    pub fn name(&self, rdev: u64, inode: Option<u64>) -> Option<String> {
        self.lookup(rdev, inode, true, |d| {
            String::from_utf8_lossy(&d.name).into_owned()
        })
    }

    /// `find_ch_ino()`: the inode of the first entry with device `rdev` the
    /// search meets; checked as found, and no reading again for a miss.
    pub fn inode(&self, rdev: u64) -> Option<u64> {
        self.lookup(rdev, None, false, |d| d.inode)
    }
}

/// What `/dev` says of `name` now: its `(st_rdev, st_ino)`, by `lstat`, as
/// `vfy_dev()` asks (`RDEV_STATFN`, `lstat` on FreeBSD).
pub fn check(name: &[u8]) -> Option<(u64, u64)> {
    std::fs::symlink_metadata(std::ffi::OsStr::from_bytes(name))
        .ok()
        .map(|m| (m.rdev(), m.ino()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(rdev: u64, inode: u64, name: &str) -> Dev {
        Dev {
            rdev,
            inode,
            name: name.into(),
            verified: Cell::new(false),
        }
    }

    #[test]
    fn two_names_of_one_device_and_inode_keep_the_first_by_strcmp() {
        let t = DevTable::from_entries(
            vec![
                dev(7, 70, "/dev/zz"),
                dev(5, 50, "/dev/null"),
                dev(7, 70, "/dev/aa"),
                dev(7, 71, "/dev/other"),
                dev(6, 60, "/dev/zero"),
            ],
            Vec::new(),
        );
        assert_eq!(t.devs.len(), 4);
        assert_eq!(t.name(7, Some(70)).as_deref(), Some("/dev/aa"));
        assert_eq!(t.name(7, Some(71)).as_deref(), Some("/dev/other"));
        assert_eq!(t.name(7, Some(72)), None, "no such inode");
        assert_eq!(t.name(5, Some(50)).as_deref(), Some("/dev/null"));
        assert_eq!(t.name(4, None), None);
        assert_eq!(t.name(8, None), None);
        assert_eq!(t.inode(6), Some(60));
        assert!(!t.is_empty() && DevTable::default().is_empty());
    }

    /// Without an inode the search takes the first entry of the device it
    /// meets, which is the C's midpoint: of `[a, b, c]` all device 9, `b`.
    #[test]
    fn a_lookup_by_device_alone_meets_what_the_cs_search_meets() {
        let t = DevTable::from_entries(
            vec![
                dev(9, 1, "/dev/a"),
                dev(9, 2, "/dev/b"),
                dev(9, 3, "/dev/c"),
            ],
            Vec::new(),
        );
        assert_eq!(t.name(9, None).as_deref(), Some("/dev/b"));
        assert_eq!(t.inode(9), Some(2));
        // Five entries, the device in the first two: mid 2 is above it, then
        // mid 0 of [0, 1] finds it.
        let t = DevTable::from_entries(
            vec![
                dev(1, 1, "/dev/x"),
                dev(1, 2, "/dev/y"),
                dev(3, 3, "/dev/p"),
                dev(4, 4, "/dev/q"),
                dev(5, 5, "/dev/r"),
            ],
            Vec::new(),
        );
        assert_eq!(t.name(1, None).as_deref(), Some("/dev/x"));
        assert_eq!(t.name(1, Some(2)).as_deref(), Some("/dev/y"));
        assert_eq!(t.name(5, None).as_deref(), Some("/dev/r"));
    }

    #[test]
    #[cfg_attr(miri, ignore = "walks the real /dev")]
    fn the_walk_keeps_character_devices_and_passes_dot_names_and_links() {
        let Ok(md) = std::fs::metadata("/dev/null") else {
            return;
        };
        let names = scan(Path::new("/dev"));
        assert_eq!(
            names.name(md.rdev(), Some(md.ino())).as_deref(),
            Some("/dev/null")
        );
        // No block special is kept (no `HASBLKDEV` on FreeBSD).
        for e in std::fs::read_dir("/dev").into_iter().flatten().flatten() {
            let Ok(md) = e.path().symlink_metadata() else {
                continue;
            };
            if md.file_type().is_block_device() {
                assert_eq!(names.name(md.rdev(), Some(md.ino())), None, "{e:?}");
            }
        }
        // A tree of no devices: nothing, and a directory that cannot be
        // opened is said.
        let dir = std::env::temp_dir().join(format!("lsof-rs-devnames-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".hidden")).unwrap();
        std::os::unix::fs::symlink("/dev/null", dir.join("link")).unwrap();
        std::fs::write(dir.join("plain"), b"").unwrap();
        let t = scan(&dir);
        assert!(t.is_empty() && t.warnings.is_empty(), "{t:?}");
        let gone = scan(&dir.join("missing"));
        assert_eq!(gone.warnings.len(), 1);
        assert!(gone.warnings[0].starts_with("lsof: WARNING: can't open: /"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A `DevCache` over scripted scans: each scan gives the next table of
    /// `tables` (the last again once they run out) and is counted, and
    /// `check` answers from `now`.
    type Now = std::rc::Rc<RefCell<Vec<(Vec<u8>, (u64, u64))>>>;

    fn cache(tables: Vec<Vec<Dev>>, now: Now) -> (DevCache, std::rc::Rc<Cell<usize>>) {
        let scans = std::rc::Rc::new(Cell::new(0usize));
        let counted = std::rc::Rc::clone(&scans);
        let c = DevCache::new(
            Box::new(move || {
                let i = counted.get();
                counted.set(i + 1);
                let t = tables.get(i).or(tables.last()).cloned().unwrap_or_default();
                DevTable::from_entries(t, Vec::new())
            }),
            Box::new(move |name| {
                now.borrow()
                    .iter()
                    .find(|(n, _)| n == name)
                    .map(|(_, id)| *id)
            }),
        );
        (c, scans)
    }

    /// Read once as the run starts and kept; safe, a miss is a miss.
    /// Unsafe (a terminal row was made), a miss of a name reads `/dev`
    /// again, once, and the table is safe again; `find_ch_ino()`'s miss does
    /// not read it (`lib/fino.c`). A name found while unsafe is `lstat`ed:
    /// as found, it is kept and not asked again; changed, `/dev` is read
    /// again and the lookup made in the new table.
    #[test]
    fn the_table_is_read_once_and_again_only_where_the_c_reads_it() {
        let now = std::rc::Rc::new(RefCell::new(vec![(b"/dev/a".to_vec(), (1, 10))]));
        let first = vec![dev(1, 10, "/dev/a")];
        let second = vec![dev(1, 10, "/dev/a"), dev(2, 20, "/dev/pts/9")];
        let (c, scans) = cache(vec![first, second.clone()], std::rc::Rc::clone(&now));
        assert_eq!(scans.get(), 0, "nothing until asked");
        c.load();
        c.load();
        assert_eq!(scans.get(), 1, "read once");
        assert_eq!(c.name(2, None), None, "safe: a miss");
        assert_eq!(c.inode(2), None);
        assert_eq!(scans.get(), 1);
        c.mark_unsafe();
        assert_eq!(c.inode(2), None, "find_ch_ino() reads no table for a miss");
        assert_eq!(scans.get(), 1);
        assert_eq!(c.name(2, Some(20)).as_deref(), Some("/dev/pts/9"));
        assert_eq!(scans.get(), 2, "read again once");
        assert_eq!(c.name(3, None), None);
        assert_eq!(scans.get(), 2, "safe again");
        // Unsafe and found: lstat'ed, as found, so kept; asked once.
        c.mark_unsafe();
        assert_eq!(c.name(1, Some(10)).as_deref(), Some("/dev/a"));
        now.borrow_mut().clear();
        assert_eq!(c.name(1, Some(10)).as_deref(), Some("/dev/a"), "verified");
        assert_eq!(c.inode(1), Some(10));
        assert_eq!(scans.get(), 2);
        // Found but gone from /dev: read again, and looked up there.
        let (c, scans) = cache(
            vec![vec![dev(1, 10, "/dev/old")], vec![dev(1, 11, "/dev/new")]],
            std::rc::Rc::new(RefCell::new(vec![(b"/dev/new".to_vec(), (1, 11))])),
        );
        c.mark_unsafe();
        assert_eq!(c.inode(1), Some(11), "vfy_dev() failed: rereaddev()");
        assert_eq!(scans.get(), 2);
        // A name found with another device or inode now is no match either.
        let (c, scans) = cache(
            vec![vec![dev(1, 10, "/dev/x")]],
            std::rc::Rc::new(RefCell::new(vec![(b"/dev/x".to_vec(), (1, 12))])),
        );
        c.mark_unsafe();
        assert_eq!(c.name(1, None).as_deref(), Some("/dev/x"));
        assert_eq!(scans.get(), 2, "read again, then safe: taken as found");
    }

    /// Past either bound the walk stops and says so; within them it is
    /// whole. A directory is read once.
    #[test]
    #[cfg_attr(miri, ignore = "walks real directories")]
    fn the_walk_stops_at_its_bounds_and_says_so() {
        assert_eq!((MAX_DIRS, MAX_DEVS), (4096, 65536));
        let dir = std::env::temp_dir().join(format!("lsof-rs-devwalk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for d in ["a/x", "b", "c"] {
            std::fs::create_dir_all(dir.join(d)).unwrap();
        }
        // Five directories: the root, a, a/x, b, c.
        let whole = scan_within(&dir, 5, MAX_DEVS);
        assert!(whole.warnings.is_empty(), "{:?}", whole.warnings);
        let cut = scan_within(&dir, 4, MAX_DEVS);
        assert_eq!(cut.warnings.len(), 1, "{:?}", cut.warnings);
        assert!(cut.warnings[0].starts_with("lsof: WARNING: more than 4 directories in /"));
        assert!(cut.warnings[0].ends_with("; the rest are not read"));
        std::fs::remove_dir_all(&dir).unwrap();
        // Character devices: /dev has more than one here.
        let all = scan(Path::new("/dev"));
        if all.devs.len() > 1 {
            let one = scan_within(Path::new("/dev"), MAX_DIRS, 1);
            assert_eq!(one.devs.len(), 1);
            assert!(
                one.warnings.iter().any(|w| {
                    w
                    == "lsof: WARNING: more than 1 character devices in /dev; the rest are not kept"
                }),
                "{:?}",
                one.warnings
            );
            assert!(!all.warnings.iter().any(|w| w.contains("character devices")));
        }
    }
}
