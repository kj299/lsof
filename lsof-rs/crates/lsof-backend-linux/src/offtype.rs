//! Whether a file's offset can be told: the C's probe (`initialize()`,
//! `lib/dialects/linux/dproc.c:630-656`), which sets its `OffType`.
//!
//! Before it reads the mount table or lists anything, the C opens `/`,
//! seeks the descriptor to byte 1, and asks its own `fdinfo` for the
//! position. Where that does not say 1 it cannot report offsets, nor the
//! file flags it reads from the same file: it says so where `-o` or `+f`
//! asked for them, and lists sizes (`dproc.c:657-664`, `main.c:1279-1286`;
//! DIVERGENCES 177). lsof-rs makes the same probe at the same point
//! ([`known`], asked by the CLI through
//! [`lsof_core::Backend::reports_offsets`]).
//!
//! Two things are not the C's:
//!
//! * The file asked is `/proc/self/fdinfo/N`, where the C asks
//!   `/proc/<getpid()>/fdinfo/N`. In a pid namespace whose `/proc` is an
//!   outer one, the C's own pid names another process there, or none: its
//!   probe fails, it reads no `fdinfo` at all from then on, and it crashes
//!   on the first eventpoll (a C defect, recorded with the Linux audit's
//!   rows). `/proc/self` is this process whatever it is numbered, so the
//!   probe succeeds there and lsof-rs goes on reading `fdinfo`.
//! * The C first `lstat`s `/proc/PID/fd/N` and takes the offset from the
//!   link's size where that is 1 (`OFFSET_LSTAT`). No kernel since 2.6.22
//!   reports a position there (the size is 64), so that branch is never
//!   taken on a kernel Rust runs on, and is not made.
//!
//! The read cannot wait: [`crate::text::open_unwaiting`], and at most
//! [`FDINFO_MAX_BYTES`] of it.

use std::io::{Read, Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::path::Path;

/// The C's `LSTAT_TEST_FILE` and `LSTAT_TEST_SEEK` (`dproc.c:67-68`).
const TEST_FILE: &str = "/";
const TEST_SEEK: u64 = 1;

/// Where a process's own `fdinfo` files are.
const OWN_FDINFO: &str = "/proc/self/fdinfo";

/// At most this much of the probe's `fdinfo` file is read: procfs writes
/// some sixty bytes for a directory.
const FDINFO_MAX_BYTES: u64 = 4096;

/// Whether this process can read a file's offset from `fdinfo`: the C's
/// `OffType == OFFSET_FDINFO` once `initialize()` has run.
pub fn known() -> bool {
    probe(Path::new(TEST_FILE), Path::new(OWN_FDINFO))
}

/// The probe, of `file` and the `fdinfo` directory it is to be found in:
/// `file` opened for reading, sought to [`TEST_SEEK`], and the position
/// `fdinfo` gives for the descriptor compared with it. `false` wherever a
/// step fails, as the C's `OffType` stays `OFFSET_UNKNOWN`.
fn probe(file: &Path, fdinfo: &Path) -> bool {
    let Ok(mut held) = std::fs::File::open(file) else {
        return false;
    };
    if held.seek(SeekFrom::Start(TEST_SEEK)).ok() != Some(TEST_SEEK) {
        return false;
    }
    let own = fdinfo.join(held.as_raw_fd().to_string());
    read_fdinfo(&own).is_some_and(|text| says_the_position(&text))
}

/// The text of the `fdinfo` file at `path`, opened without waiting and read
/// to [`FDINFO_MAX_BYTES`]; `None` where it cannot be opened or read.
fn read_fdinfo(path: &Path) -> Option<String> {
    let file = crate::text::open_unwaiting(path).ok()?;
    let mut text = Vec::new();
    file.take(FDINFO_MAX_BYTES).read_to_end(&mut text).ok()?;
    Some(crate::text::lossy(text))
}

/// Whether an `fdinfo` text gives the position the probe sought to: its
/// `pos:` line, read as every descriptor's is ([`crate::files::parse_fdinfo`]).
fn says_the_position(text: &str) -> bool {
    crate::files::parse_fdinfo(text).pos == Some(TEST_SEEK)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The probe's answer is the `pos:` line of its own `fdinfo`, and 1.
    #[test]
    fn the_position_is_the_one_sought_to() {
        assert!(says_the_position("pos:\t1\nflags:\t0100000\nmnt_id:\t26\n"));
        assert!(says_the_position("flags:\t0100000\npos:\t1\n"));
        for no in [
            "pos:\t0\nflags:\t0100000\n",
            "pos:\t2\n",
            "pos:\t11\n",
            "flags:\t0100000\nmnt_id:\t26\n",
            "pos:\n",
            "pos:\tx\n",
            "",
        ] {
            assert!(!says_the_position(no), "{no:?}");
        }
    }

    /// On a host with procfs the probe succeeds, as the C's does (measured:
    /// neither says a word under `-o` or `+f g`).
    #[test]
    #[cfg_attr(miri, ignore = "miri cannot read /proc links")]
    fn the_probe_succeeds_where_proc_is_procfs() {
        assert!(known());
    }

    /// Each step that fails leaves the offset unknown: a file that cannot
    /// be opened, an `fdinfo` that is not there, one that says another
    /// position, and one that is a FIFO, which is refused and not waited on.
    #[test]
    #[cfg_attr(miri, ignore = "it makes files and reads /proc")]
    fn the_probe_fails_where_a_step_does() {
        use std::os::unix::ffi::OsStrExt;
        let own = Path::new(OWN_FDINFO);
        assert!(probe(Path::new("/"), own));
        assert!(probe(Path::new("/proc"), own), "any directory will do");
        assert!(!probe(Path::new("/nonexistent/lsof-rs"), own));
        assert!(!probe(Path::new("/"), Path::new("/nonexistent/lsof-rs")));
        // An `fdinfo` of the test's own making, for whatever number the
        // probe's descriptor gets: every number that is free now.
        let dir = std::env::temp_dir().join(format!("lsof-rs-offtype-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let all = |text: &str| {
            for fd in 0..64 {
                std::fs::write(dir.join(fd.to_string()), text).unwrap();
            }
        };
        all("pos:\t1\nflags:\t0100000\n");
        assert!(probe(Path::new("/"), &dir));
        all("pos:\t0\nflags:\t0100000\n");
        assert!(!probe(Path::new("/"), &dir));
        all("flags:\t0100000\n");
        assert!(!probe(Path::new("/"), &dir));
        for fd in 0..64 {
            let path = dir.join(fd.to_string());
            std::fs::remove_file(&path).unwrap();
            rustix::fs::mknodat(
                rustix::fs::CWD,
                std::ffi::CString::new(path.as_os_str().as_bytes())
                    .unwrap()
                    .as_c_str(),
                rustix::fs::FileType::Fifo,
                rustix::fs::Mode::from_raw_mode(0o600),
                0,
            )
            .unwrap();
        }
        // No writer ever opens them: a probe that waited would never
        // return, so it is made on a thread of its own and given ten seconds.
        let (tx, rx) = std::sync::mpsc::channel();
        let fdinfo = dir.clone();
        std::thread::spawn(move || {
            let _ = tx.send(probe(Path::new("/"), &fdinfo));
        });
        let told = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the probe waited on a FIFO");
        assert!(!told);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
