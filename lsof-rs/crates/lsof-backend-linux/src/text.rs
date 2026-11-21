//! Reading the kernel's text tables, which are not always text.
//!
//! Every table this backend reads — `/proc/<pid>/status`, `maps`, `fdinfo`,
//! `/proc/net/*`, `/proc/locks`, the mount table, `/etc/passwd` — is mostly
//! ASCII and **partly whatever someone put there**: a process names itself
//! with `prctl(PR_SET_NAME)`, anyone can bind a unix socket or map a file whose
//! path holds any byte but `/` and NUL. None of that has to be UTF-8.
//!
//! The backend read all of them with `read_to_string`, which fails on the
//! first byte that is not, and it treated the failure the way it treats a
//! vanished file: the whole table became empty. So one byte blinded lsof-rs
//! to the whole of it, and the byte was an unprivileged user's to write:
//!
//! * a process that named itself `\xff` was **missing from every listing** —
//!   `lsof -p` said it did not exist, and the C listed it as `\xff\xfe`;
//! * one unix socket bound to a path holding `\xff`, anywhere on the host,
//!   made `lsof -U` print **nothing** for every process, where the C listed
//!   all of them and that one as `…/sock\xff`;
//! * one mapped file with such a name took every `mem` row of its process
//!   with it.
//!
//! A forensic tool that anyone can hide from is worse than a slow one
//! (porting-kit LESSONS #067). So the
//! read goes through [`read_lossy`], which decodes what is not UTF-8 as U+FFFD
//! and keeps everything else. Only the undecodable bytes are lost, and only
//! their display: the C prints each as `\xNN`, lsof-rs as `�`, which is the
//! price of a `String` model — recorded in DIVERGENCES.

use std::path::Path;

/// `ENXIO`, `No such device or address` (6 in `errno-base.h` on every Linux
/// architecture): what the kernel answers an `open()` of a socket file, and
/// what [`open_unwaiting`] answers for a FIFO.
pub const ENXIO: i32 = 6;

/// The file at `path`, opened for reading in a way that cannot wait, for a
/// table lsof-rs reads in its own process.
///
/// A plain `open()` of a FIFO waits until a writer opens it, for ever where
/// none does; the C's `fopen()` does (measured: a `/proc` that is a tmpfs
/// with `mkfifo /proc/mounts` holds the C at `readmnt()`). Here the open is
/// `O_NONBLOCK`, which returns at once on a FIFO and on a device, and a
/// FIFO is then refused with [`ENXIO`], the error the kernel itself gives a
/// socket there, so that a table that is no file to read is said one way.
///
/// Anything else is given back: a regular file (procfs's own are), a
/// directory (whose read fails at once: the C's empty table), and a
/// device, the descriptor still `O_NONBLOCK`, so that a read of it does not
/// wait either as far as its driver honours the flag. What a device may
/// give is for the caller to bound: a table's reader takes none of it
/// (`mounts::open_table`), and the offset probe at most a page. On procfs
/// the flag changes nothing.
pub fn open_unwaiting(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
    // Not under miri, whose `open` refuses the flag.
    let nonblocking = if cfg!(miri) {
        0
    } else {
        i32::try_from(rustix::fs::OFlags::NONBLOCK.bits()).unwrap_or(0)
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nonblocking)
        .open(path)?;
    if file.metadata()?.file_type().is_fifo() {
        return Err(std::io::Error::from_raw_os_error(ENXIO));
    }
    Ok(file)
}

/// The file at `path` as text, with any byte sequence that is not UTF-8
/// replaced by U+FFFD. `None` only when the file cannot be read at all — the
/// same meaning `read_to_string(..).ok()` had, minus the one it should never
/// have had.
pub fn read_lossy(path: impl AsRef<Path>) -> Option<String> {
    std::fs::read(path).ok().map(lossy)
}

/// `bytes` as text, as [`read_lossy`] decodes a file.
pub fn lossy(bytes: Vec<u8>) -> String {
    match String::from_utf8(bytes) {
        Ok(s) => s,
        // The common case costs nothing extra: only a table that really holds
        // a stray byte is copied.
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file holding `bytes`, named for the test so parallel tests never
    /// share one. Removed by the caller.
    fn temp_with(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("lsof-rs-text-{}-{name}", std::process::id()));
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn a_stray_byte_costs_that_byte_not_the_table() {
        // Two lines; the first holds a byte that is not UTF-8. The control is
        // `read_to_string`, which fails outright on it — and the caller
        // dropped BOTH lines, which is the bug this module exists to end.
        let path = temp_with("stray", b"sock\xff\nother\n");
        let strict = std::fs::read_to_string(&path);
        let text = read_lossy(&path);
        std::fs::remove_file(&path).ok();
        assert!(
            strict.is_err(),
            "the control must fail, or this proves nothing"
        );
        assert_eq!(text.as_deref(), Some("sock\u{FFFD}\nother\n"));
    }

    #[test]
    fn valid_text_is_returned_as_is() {
        let path = temp_with("valid", "é ok\n".as_bytes());
        let text = read_lossy(&path);
        std::fs::remove_file(&path).ok();
        assert_eq!(text.as_deref(), Some("é ok\n"));
    }

    #[test]
    fn a_missing_file_is_none() {
        assert_eq!(read_lossy("/nonexistent/lsof-rs/text"), None);
    }
}
