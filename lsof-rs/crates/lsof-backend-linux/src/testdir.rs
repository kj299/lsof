//! A private directory for a unit test's own files, in the system's shared
//! temp directory.
//!
//! A name there that a test can predict, another local user can predict too:
//! one who makes it first (a directory `create_dir_all` accepts, or a symlink
//! `std::fs::write` follows) gets the test's files written where they chose,
//! or theirs read as the test's. So the directory is made by `mkdir(2)` with
//! mode 0700, which fails on anything already there, under a name not tried
//! before in this process, and then checked to be a directory, not a link,
//! owned by the test's own effective uid. Nothing in it was put there by
//! anyone else, and no one else can put anything there. It is removed when
//! dropped, a failing test's too.

use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

/// The directory; removed, with what it holds, on drop.
#[derive(Debug)]
pub struct TestDir(PathBuf);

impl TestDir {
    /// A new directory `lsof-rs-<tag>-<pid>-<n>` under the canonical temp
    /// directory (a symlinked `TMPDIR` would make a path through it differ
    /// from the kernel's spelling of it, which the `-e` tests compare).
    pub fn new(tag: &str) -> TestDir {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let tmp = std::fs::canonicalize(std::env::temp_dir()).expect("the temp directory");
        let pid = std::process::id();
        let names = std::iter::repeat_with(|| NEXT.fetch_add(1, Ordering::Relaxed))
            .take(64)
            .map(|n| tmp.join(format!("lsof-rs-{tag}-{pid}-{n}")));
        TestDir::first_fresh(names).unwrap_or_else(|| panic!("no fresh directory for {tag}"))
    }

    /// The first of `names` that `mkdir` makes; a name already taken
    /// (someone's, or a killed run's) is passed over, never used or removed.
    fn first_fresh(names: impl Iterator<Item = PathBuf>) -> Option<TestDir> {
        let euid = effective_uid();
        for dir in names {
            match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => {
                    let md = std::fs::symlink_metadata(&dir).expect("the directory just made");
                    assert!(md.is_dir(), "{} is not a directory", dir.display());
                    assert_eq!(md.uid(), euid, "{} is not ours", dir.display());
                    assert_eq!(md.mode() & 0o077, 0, "{} is open to others", dir.display());
                    return Some(TestDir(dir));
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => panic!("mkdir {}: {e}", dir.display()),
            }
        }
        None
    }
}

impl std::ops::Deref for TestDir {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for TestDir {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// This process's effective uid, from `/proc/self/status` (the crate has no
/// `geteuid()` binding; `process::is_root` reads it the same way).
fn effective_uid() -> u32 {
    let status = std::fs::read_to_string("/proc/self/status").expect("/proc/self/status");
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|v| v.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .expect("an effective uid")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_test_directory_is_fresh_private_and_gone_when_dropped() {
        let a = TestDir::new("testdir");
        let b = TestDir::new("testdir");
        assert_ne!(*a, *b, "each is new");
        let md = std::fs::symlink_metadata(&*a).unwrap();
        assert!(md.is_dir());
        assert_eq!(md.mode() & 0o777, 0o700);
        let kept = a.to_path_buf();
        std::fs::write(a.join("f"), b"x").unwrap();
        drop(a);
        assert!(std::fs::symlink_metadata(&kept).is_err(), "removed");
        // A name already taken, by a link to a directory elsewhere, is passed
        // over, not followed; the next is made.
        let target = b.join("elsewhere");
        std::fs::create_dir(&target).unwrap();
        let planted = b.join("planted");
        std::os::unix::fs::symlink(&target, &planted).unwrap();
        let fresh = b.join("fresh");
        let c = TestDir::first_fresh([planted.clone(), fresh.clone()].into_iter()).unwrap();
        assert_eq!(*c, fresh);
        assert!(std::fs::symlink_metadata(&*c).unwrap().is_dir());
        assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0);
        assert!(TestDir::first_fresh([planted, fresh].into_iter()).is_none());
    }
}
