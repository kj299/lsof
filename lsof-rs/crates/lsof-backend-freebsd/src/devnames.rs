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
//! Read once, the first time a row asks, and only then: a run that meets no
//! device row and no terminal walks nothing. `/dev` is devfs, which answers
//! from memory, so the walk is made in-process, as the C makes it. The
//! device cache the C can keep (`-D`) is not kept.

use std::collections::HashSet;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{DirEntryExt, FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

/// At most this many directories are read: devfs is small, and a loop
/// through a mount over `/dev` cannot make the walk endless.
pub const MAX_DIRS: usize = 4096;

/// At most this many character devices are kept: a bound on what a file
/// system mounted under `/dev` can make lsof hold (a devfs has hundreds).
pub const MAX_DEVS: usize = 1 << 16;

/// One character special: `struct l_dev`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Dev {
    rdev: u64,
    inode: u64,
    name: Vec<u8>,
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
    pub fn name(&self, rdev: u64, inode: Option<u64>) -> Option<String> {
        self.find(rdev, inode)
            .map(|d| String::from_utf8_lossy(&d.name).into_owned())
    }

    /// `find_ch_ino()`: the inode of the first entry with device `rdev` the
    /// search meets, for a character device whose record has none.
    pub fn inode(&self, rdev: u64) -> Option<u64> {
        self.find(rdev, None).map(|d| d.inode)
    }
}

/// `readdev()` of `root`.
pub fn scan(root: &Path) -> DevTable {
    let esc = lsof_core::Escaper::UNIX;
    let mut devs = Vec::new();
    let mut warnings = Vec::new();
    // `Dstk`: directories still to read, the last pushed read first.
    let mut stack = vec![root.to_path_buf()];
    let mut seen: HashSet<PathBuf> = HashSet::new();
    let mut budget = MAX_DIRS;
    while let Some(dir) = stack.pop() {
        if budget == 0 {
            break;
        }
        budget -= 1;
        if !seen.insert(dir.clone()) {
            continue;
        }
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
        for e in rd.flatten() {
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
            } else if ft.is_char_device() && devs.len() < MAX_DEVS {
                devs.push(Dev {
                    rdev: md.rdev(),
                    inode: md.ino(),
                    name: path.into_os_string().into_vec(),
                });
            }
        }
    }
    DevTable::from_entries(devs, warnings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(rdev: u64, inode: u64, name: &str) -> Dev {
        Dev {
            rdev,
            inode,
            name: name.into(),
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
}
