//! Device names, as the C's `readdev()` collects them (`lib/rdev.c`): a walk
//! of `/dev` for every character and block special, so `printdevname()` can
//! print `/dev/pts/0` for a terminal no path names.
//!
//! Read once, the first time a row asks, and only then: a run that meets no
//! device node and no terminal walks nothing. Symbolic links are not
//! followed, as `readdev()` `lstat`s; the first name found for a device wins.
//! `/dev` is devfs, which answers from memory, so the walk is made
//! in-process (the device cache the C can keep, `-D`, is not kept).

use std::collections::HashMap;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;

/// `rdev` → its first name under `root`.
pub fn scan(root: &Path) -> HashMap<u64, String> {
    let mut out = HashMap::new();
    let mut dirs = vec![root.to_path_buf()];
    // A cap on directories, not names: devfs is small, and a loop through a
    // mount over /dev cannot make the walk endless.
    let mut budget = 4096usize;
    while let Some(dir) = dirs.pop() {
        if budget == 0 {
            break;
        }
        budget -= 1;
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut entries: Vec<_> = rd.flatten().collect();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for e in entries {
            let Ok(md) = e.path().symlink_metadata() else {
                continue;
            };
            let ft = md.file_type();
            if ft.is_dir() {
                dirs.push(e.path());
            } else if ft.is_char_device() || ft.is_block_device() {
                out.entry(md.rdev())
                    .or_insert_with(|| e.path().to_string_lossy().into_owned());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn dev_null_is_found_by_its_number() {
        use std::os::unix::fs::MetadataExt;
        let Ok(md) = std::fs::metadata("/dev/null") else {
            return;
        };
        let names = super::scan(std::path::Path::new("/dev"));
        assert!(
            names.contains_key(&md.rdev()),
            "/dev/null's device is named"
        );
    }
}
