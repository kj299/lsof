//! The platform "dialect" boundary.
//!
//! A [`Backend`] is the Rust analog of an lsof dialect's `gather_proc_info()`
//! hook: it knows how to enumerate the system's processes and their open files
//! on one platform. The portable code in this crate drives a `&dyn Backend`,
//! so the Windows implementation (and any future Linux one) is fully decoupled
//! from selection and rendering.

use crate::model::Process;
use crate::selection::Selection;

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
    /// The mounted-on directory, e.g. `/` or `/boot`.
    pub dir: String,
    /// What was mounted, symlink-resolved — a device path like `/dev/vda`, or
    /// a name with no file behind it like `tmpfs` or `proc`. `None` when the
    /// source could not be resolved.
    pub source: Option<String>,
    /// Whether [`Self::source`] names a block device. lsof accepts a mount's
    /// *source* as a file-system argument only when it is one — `lsof /dev/vda`
    /// means the root filesystem, while `lsof tmpfs` means nothing — unless
    /// `+f` widens it to any source.
    pub source_is_block: bool,
    /// The device of the mounted filesystem: the `st_dev` every file on it has.
    pub device: u64,
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

/// A platform data source for lsof-rs.
pub trait Backend {
    /// A short human-readable name (e.g. `"windows"`, `"mock"`).
    fn name(&self) -> &str;

    /// The `(DEVICE, NODE)` identity of the file at `path`, rendered exactly as
    /// this backend renders those cells on a row — so the comparison in
    /// [`Selection::path_matches`](crate::selection::Selection) is a plain
    /// equality test and the formatting lives with the code that produces it.
    ///
    /// This is what makes a path argument mean what lsof means by it: `lsof
    /// /a/hardlink` finds the file even though it was opened under its other
    /// name, and `lsof /some/dir` matches that directory and *not* the files
    /// beneath it. A backend that cannot cheaply identify a path returns
    /// `None`, and selection falls back to comparing names.
    fn identify_path(&self, _path: &str) -> Option<(String, String)> {
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
    fn mounts(&self) -> Vec<MountEntry> {
        Vec::new()
    }

    /// Whether [`Backend::identify_path`] works on this platform.
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

    /// Gather processes and their open files, already narrowed by `sel` where
    /// the backend can do so cheaply. The portable [`selection`](crate::selection)
    /// engine applies the authoritative filtering afterwards, so a backend may
    /// also return a superset.
    fn gather(&self, sel: &Selection) -> Result<Vec<Process>, BackendError>;
}
