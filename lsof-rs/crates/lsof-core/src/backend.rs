//! The platform "dialect" boundary.
//!
//! A [`Backend`] is the Rust analog of an lsof dialect's `gather_proc_info()`
//! hook: it knows how to enumerate the system's processes and their open files
//! on one platform. The portable code in this crate drives a `&dyn Backend`,
//! so the Windows and Linux implementations are fully decoupled from
//! selection and rendering.

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

/// How the C's `readmnt()` types a mount it records (`dmnt.c`, `mp->ty`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MountKind {
    /// `nfs`, `nfs3` or `nfs4`, in any case (`strcasecmp`): `N_NFS`, what
    /// `-N` selects files on.
    Nfs,
    /// Exactly `mqueue` (`strcmp`): `N_MQUEUE`. Its device is
    /// [`MountTable::mqueue_device`].
    Mqueue,
    /// Anything else: `N_REGLR`.
    #[default]
    Regular,
}

/// One mount the host's table records, as the C's `readmnt()` records it
/// (`dmnt.c`): which directory the mount is on, what it was mounted from, and
/// the device number every file on it carries in
/// [`OpenFile::fs_device`](crate::model::OpenFile::fs_device).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountEntry {
    /// The mounted-on directory as `Readlink()` spells it (as the kernel
    /// does for a `+e` mount), byte for byte: a path argument names the file
    /// system only when it is spelt the same, and an `-e`/`+e` path only when
    /// it is this.
    pub dir: OsString,
    /// The `st_dev` of [`Self::dir`]'s one `stat`: what every file on the
    /// file system reports, and of a directory mounted over twice, the top
    /// mount's. `None` for an `-e`/`+e` mount, which is never `stat`ed (the
    /// C records it with no device, `ds = 0`), so a file-system argument
    /// naming it finds nothing.
    pub device: Option<u64>,
    /// The source as the C compares it with a path argument (`fsnmres`):
    /// spelt by `Readlink()` when it is a path, `/dev/vda` or
    /// `/dev/mapper/../dm-0` for a link that is relative; as it stands when
    /// it is a name like `tmpfs`, or the mount is `+e`'s. `None` where
    /// `Readlink()` gave up on it.
    pub source_resolved: Option<OsString>,
    /// Whether [`Self::source_resolved`] names a block device. lsof accepts
    /// a mount's *source* as a file-system argument only when it is one —
    /// `lsof /dev/vda` means the root filesystem, while `lsof tmpfs` means
    /// nothing — unless `+f` widens it to any source. Never for an
    /// `-e`/`+e` mount, whose source is not `stat`ed.
    pub source_is_block: bool,
    /// The C's type for it: what `-N` selects on. The type's name itself is
    /// read by nothing: `-Z` asks the host's table for one by name
    /// ([`Backend::has_mount_type`]), and a warning names the row's own.
    pub kind: MountKind,
}

/// The host's mount table as the C's `readmnt()` leaves it: the mounts it
/// recorded, in the order the kernel lists them, and what it noted on the
/// way.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MountTable {
    /// Every mount recorded: one per directory, `/proc/self/mounts` order.
    pub entries: Vec<MountEntry>,
    /// The C's `HasNFS`: 0, none; 1, an NFS mount was listed (one dropped
    /// as a duplicate counts); 2, one was recorded. Recorded as the C
    /// records it, and read by nothing yet: the C makes every per-file
    /// `stat` through its child once it is not 0, and lsof-rs does not
    /// (DIVERGENCES 124, OPEN), whose step this is kept for.
    pub has_nfs: u8,
    /// The device of the last `mqueue` mount recorded (the C's
    /// `MqueueDev`), what a POSIX message queue's descriptor is on. `None`
    /// when there is none, or it was `-e`/`+e`'s and so never `stat`ed.
    /// Read by nothing yet: the C types a regular file there `PSXMQ`, and
    /// lsof-rs does not (DIVERGENCES 128, OPEN), whose step this is kept for.
    pub mqueue_device: Option<u64>,
}

/// What a read of the mount table needs to know of the options: the
/// `-e`/`+e` file systems entered so far, which it neither `stat`s nor,
/// for `+e`, reads the links of. The C reads its table once, where it first
/// needs it, under the options in force there (`-b`, `-O`, `-S` and `-w`
/// travel in the [`SafeFs`](crate::safefs::SafeFs) view the read is made
/// through).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MountRequest {
    /// The C's `Efsysl` as it stood.
    pub exempt: Vec<crate::selection::ExemptFs>,
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

    /// The identity of the file a `stat` described: its `st_dev` and
    /// `st_ino`, as the C keeps them for a path argument (`arg.c`,
    /// `ck_file_arg()`: `sfp->dev = sb.st_dev`, `sfp->i = sb.st_ino`), and
    /// never the DEVICE cell. A device node is the file that holds it, not
    /// the device it names: `lsof /dev/zero` finds a row whose
    /// [`OpenFile::file_id`](crate::model::OpenFile::file_id) is devtmpfs's
    /// `0,6` and inode 4, the fd's `CHR 1,5` and a mapping's `REG 0,6` alike,
    /// and not a node with that device and inode on another file system
    /// (DIVERGENCES 101). The number is the same kind as a row's
    /// [`OpenFile::fs_device`](crate::model::OpenFile::fs_device) and a
    /// mount's [`MountEntry::device`], so selection compares numbers.
    ///
    /// This is what makes a path argument mean what lsof means by it: `lsof
    /// /a/hardlink` finds the file even though it was opened under its other
    /// name, and `lsof /some/dir` matches that directory and *not* the files
    /// beneath it. A backend that cannot identify files says so through
    /// [`Backend::identifies_paths`], and selection then compares names; a
    /// `None` from one that can is matched by nothing.
    ///
    /// The `stat` itself is the caller's, made through the bounded layer
    /// ([`crate::safefs::SafeFs`]) under the `-b`/`-O`/`-S` in force where the
    /// path was named, so a path on a file system that does not answer costs
    /// a timeout and not the run, and a failed `stat` is reported with that
    /// call's own error. Until 2026-10-09 this took a path and `stat`ed it
    /// here, in-process and unbounded, and a `+d`/`+D` walk asked for an
    /// entry's file system through a second method, `path_fs_device`, which
    /// is now the caller's `lstat`. Until then too it returned the DEVICE and
    /// NODE cells as text, `st_rdev` for a device node.
    fn identify_stat(&self, _st: &crate::safefs::FileStat) -> Option<crate::model::FileId> {
        None
    }

    /// The host's mount table, read and examined as the C's `readmnt()` does
    /// it (`dmnt.c`), once per run and only on a run that needs it
    /// ([`Selection::needs_mount_table`]).
    ///
    /// lsof reads a path argument as a **file system name** when it matches a
    /// mounted-on directory, and then selects every open file on that
    /// filesystem rather than the directory alone (Lsof.8; `arg.c`'s
    /// `ck_file_arg`); `-e` names one, and `-N` selects the files on NFS. The
    /// rules themselves are portable and live in the CLI — what a backend
    /// supplies is the table. A platform with no such table returns an empty
    /// one, and every path argument is then a plain file.
    ///
    /// Every `stat` and `readlink` of a mount point or a source goes through
    /// `fs`, the bounded layer under the options in force where the C reads
    /// its table: a mount whose file system does not answer is dropped after
    /// the `-S` limit, with the C's warning unless `-w`, where it had stopped
    /// the run, and under `-b` none is examined (DIVERGENCES 87, 94, 110).
    /// What the C says while it reads (that warning, a `Readlink()` that gave
    /// up) goes to `fs`'s sink as it is found, so it comes in order with the
    /// rest of what the run says.
    fn mount_table(&self, _req: &MountRequest, _fs: &crate::safefs::SafeFs) -> MountTable {
        MountTable::default()
    }

    /// Whether the host lists a mount of type `fstype`, read from its
    /// table's text and nothing else: no `stat` and no `readlink`. What `-Z`
    /// asks of the table (whether a `selinuxfs` is mounted, the C's
    /// `is_selinux_enabled()`), so that `-i -Z`, which reads no table in the
    /// C, examines no mount here either.
    fn has_mount_type(&self, _fstype: &str) -> bool {
        false
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
