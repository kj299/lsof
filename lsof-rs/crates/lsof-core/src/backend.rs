//! The platform "dialect" boundary.
//!
//! A [`Backend`] is the Rust analog of an lsof dialect's `gather_proc_info()`
//! hook: it knows how to enumerate the system's processes and their open files
//! on one platform. The portable code in this crate drives a `&dyn Backend`,
//! so the Windows implementation (and any future Linux one) is fully decoupled
//! from selection and rendering.

use std::ffi::OsString;

use crate::model::Process;
use crate::selection::Selection;

/// `strerror(errno)` as the C prints it, from a Rust `io::Error`.
///
/// `Display` for an OS error is the C library's own message — std asks libc's
/// `strerror_r`, the library the C's `strerror` reads — followed by
/// ` (os error N)`, which the C never prints. Trimming that one suffix gives
/// the C's words byte for byte: `lsof: status error on /nope: No such file or
/// directory`, and the `(readlink: Permission denied)` a backend writes into
/// NAME for a file it could not read. An error that is not an OS error has no
/// suffix and is kept whole.
///
/// It lives here, beside the seam, because both sides need it: the CLI for
/// its argument errors and a backend for the files it cannot examine.
pub fn errno_text(e: &std::io::Error) -> String {
    let s = e.to_string();
    match s.rfind(" (os error ") {
        Some(i) if s.ends_with(')') => s[..i].to_string(),
        _ => s,
    }
}

/// An OS privilege that a particular query may require. Used to implement the
/// least-privilege model: the CLI/back end only ever requests a privilege when
/// the switches in use actually need it, and never holds it longer than the
/// single call that needs it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Privilege {
    /// No elevation required — visible in the plain user context.
    None,
    /// Requires `SeDebugPrivilege` (Administrator) to reach data owned by other
    /// users' / protected processes (e.g. duplicating their handles).
    SeDebug,
}

/// One row of the host's mount table.
///
/// Only what the file-system-argument rule needs: which directory the mount is
/// on, what it was mounted from, and the device number every file on it
/// carries in [`OpenFile::fs_device`](crate::model::OpenFile::fs_device).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountEntry {
    /// The mounted-on directory, e.g. `/` or `/boot`, byte for byte: a path
    /// argument names the file system only when it is spelt the same.
    pub dir: OsString,
    /// What was mounted, as the C's `Readlink()` spells it when it is a path
    /// — `/dev/vda`, or `/dev/mapper/../dm-0` for a link that is relative —
    /// or the name itself when it is none, like `tmpfs` or `proc`. `None`
    /// when the table was read without sources ([`Backend::mounts`]), or a
    /// path could not be read.
    pub source: Option<OsString>,
    /// Whether [`Self::source`] names a block device. lsof accepts a mount's
    /// *source* as a file-system argument only when it is one — `lsof /dev/vda`
    /// means the root filesystem, while `lsof tmpfs` means nothing — unless
    /// `+f` widens it to any source.
    pub source_is_block: bool,
    /// The device of the mounted filesystem: the `st_dev` every file on it has.
    pub device: u64,
    /// The file-system type as the host names it (`ext4`, `nfs4`, `tmpfs`).
    /// Empty where the platform does not report one. `-N` selects on it.
    pub fstype: String,
}

/// Errors a backend can report. Selection that simply yields no rows is *not*
/// an error — it returns an empty `Vec`.
#[derive(Debug)]
pub enum BackendError {
    /// The backend isn't available on this build/platform.
    Unsupported(String),
    /// An underlying OS call failed.
    Os(String),
}

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendError::Unsupported(m) => write!(f, "unsupported: {m}"),
            BackendError::Os(m) => write!(f, "OS error: {m}"),
        }
    }
}

impl std::error::Error for BackendError {}

/// What a platform makes of one `-u` value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserLookup {
    /// A numeric user ID: the value was one, or it named an account.
    Uid(u32),
    /// The value names no account this platform knows. The C treats that as
    /// an option error while it parses — `lsof: can't get UID for nosuchuser`,
    /// then the usage message, exit 1 — so nothing is listed.
    Unknown,
    /// This platform selects users by name, and has no ID to resolve to.
    ByName,
}

/// A platform data source for lsof-rs.
pub trait Backend {
    /// A short human-readable name (e.g. `"windows"`, `"mock"`).
    fn name(&self) -> &str;

    /// The `(DEVICE, NODE)` identity of the file a `stat` described, rendered
    /// exactly as this backend renders those cells on a row — so the
    /// comparison in [`Selection::path_matches`](crate::selection::Selection)
    /// is a plain equality test and the formatting lives with the code that
    /// produces it.
    ///
    /// This is what makes a path argument mean what lsof means by it: `lsof
    /// /a/hardlink` finds the file even though it was opened under its other
    /// name, and `lsof /some/dir` matches that directory and *not* the files
    /// beneath it. A backend that cannot identify files returns `None`, and
    /// selection falls back to comparing names.
    ///
    /// The `stat` itself is the caller's, made through the bounded layer
    /// ([`crate::safefs::SafeFs`]) under the `-b`/`-O`/`-S` in force where the
    /// path was named, so a path on a file system that does not answer costs
    /// a timeout and not the run, and a failed `stat` is reported with that
    /// call's own error. Until 2026-10-09 this took a path and `stat`ed it
    /// here, in-process and unbounded, and a `+d`/`+D` walk asked for an
    /// entry's file system through a second method, `path_fs_device`, which
    /// is now the caller's `lstat`.
    fn identify_stat(&self, _st: &crate::safefs::FileStat) -> Option<(String, String)> {
        None
    }

    /// The host's mount table, as `mount(8)` reports it.
    ///
    /// lsof reads a path argument as a **file system name** when it matches a
    /// mounted-on directory, and then selects every open file on that
    /// filesystem rather than the directory alone (Lsof.8; `arg.c`'s
    /// `ck_file_arg`). The rule itself is portable and lives in the CLI —
    /// what a backend supplies is the table. A platform with no such table
    /// returns an empty one, and every path argument is then a plain file.
    ///
    /// Each mount's [`MountEntry::source`] is filled in only with `sources`:
    /// only a path argument is compared with one, and spelling a source can
    /// cost what a user who chose it wants it to cost (the C's `Readlink()`
    /// re-reads a long chain of links up to 21 times), so a run that names
    /// no path pays nothing for it.
    ///
    /// Every `stat` and `readlink` of a mount point or a source goes through
    /// `fs`, the bounded layer under the options the C reads its table with:
    /// a mount whose file system does not answer is dropped after the `-S`
    /// limit, where it had stopped the run, and under `-b` none is examined
    /// (DIVERGENCES 94, 110).
    fn mounts(&self, _sources: bool, _fs: &crate::safefs::SafeFs) -> Vec<MountEntry> {
        Vec::new()
    }

    /// Whether [`Backend::identify_stat`] works on this platform.
    ///
    /// Selection needs this stated rather than inferred. "Did any path resolve
    /// to an identity?" looks like the same question and is not: a run whose
    /// only path argument names a *file system* resolves no identities at all,
    /// and inferring from that put path matching back on the name-prefix
    /// fallback, where `/` is a prefix of every absolute path and `lsof /`
    /// listed files on every filesystem.
    fn identifies_paths(&self) -> bool {
        false
    }

    /// Resolve a `-u` value the way the platform names users.
    ///
    /// The C does it with `getpwnam(3)` while it parses its options: a number
    /// is a UID as it stands, a name is looked up, and a name that resolves to
    /// nothing is fatal. A backend without numeric user IDs keeps matching by
    /// name, which is the default here.
    fn lookup_user(&self, _value: &str) -> UserLookup {
        UserLookup::ByName
    }

    /// Gather processes and their open files, already narrowed by `sel` where
    /// the backend can do so cheaply. The portable [`selection`](crate::selection)
    /// engine applies the authoritative filtering afterwards, so a backend may
    /// also return a superset.
    fn gather(&self, sel: &Selection) -> Result<Vec<Process>, BackendError>;
}

#[cfg(test)]
mod tests {
    use super::errno_text;

    /// `errno_text` strips the ` (os error N)` that Rust appends and the C
    /// never prints, so `lsof: status error on /nope: No such file or
    /// directory` is byte-identical to the oracle's line.
    ///
    /// The rule is **strip exactly one, never greedily** — the same shape as
    /// the `/proc/maps` ` (deleted)` marker. The first version of this test
    /// asserted the result never *contains* `os error`, which is over-strong,
    /// and miri said so: its `strerror` shim already ends the message with
    /// `(os error 2)`, `Display` appends a second, and a correct single strip
    /// leaves one behind. Constructed strings pin the rule portably; the live
    /// error then only has to show that the suffix `Display` added is gone.
    #[test]
    fn errno_text_drops_one_rust_suffix() {
        use std::io::Error;

        // `Error::other` Displays as the message alone, so these pin the
        // transformation itself on every platform and under miri.
        assert_eq!(
            errno_text(&Error::other("No such file or directory (os error 2)")),
            "No such file or directory"
        );
        // Nothing to strip: survives whole.
        assert_eq!(errno_text(&Error::other("handmade")), "handmade");
        // The suffix counts only at the very end, in parentheses.
        assert_eq!(
            errno_text(&Error::other("no (os error 2) here")),
            "no (os error 2) here"
        );
        // Exactly one. Greedy stripping would rename an errno message that
        // legitimately ends that way — and it is the shape miri produces.
        assert_eq!(
            errno_text(&Error::other("x (os error 2) (os error 2)")),
            "x (os error 2)"
        );

        // On a live OS error, whatever the platform's message is, the suffix
        // `Display` appended is gone and something is left.
        let e = Error::from_raw_os_error(2);
        let raw = e.to_string();
        let t = errno_text(&e);
        assert_eq!(t, raw.strip_suffix(" (os error 2)").unwrap_or(&raw));
        assert!(!t.is_empty());
    }
}
