//! The bounded file-system layer: the C's `statsafely()`, `lstatsafely()`,
//! `Readlink()` and the `doinchild()` they share (`lib/misc.c`), and its
//! options `-b`, `-O` and `-S [t]` (Lsof.8, "BLOCKS AND TIMEOUTS").
//!
//! A path a user names (an argument, a `+d`/`+D` directory and what is in it,
//! a mount point the mount table lists) may live on a file system that never
//! answers: a hard NFS mount whose server is gone, a FUSE daemon that is
//! stuck. A `stat` of it then sleeps in the kernel for as long as that lasts,
//! and so does lsof. The C makes those calls in a child process under an
//! `alarm(TmLimit)`; this module is where lsof-rs makes them, in one of three
//! ways the options choose ([`Blocking`]):
//!
//! * **bounded** (the default): through an [`FsCalls`] implementation that
//!   gives each call `-S` seconds (15, at least 2) and gives up with
//!   `ETIMEDOUT` after that. On Linux that is a helper process
//!   (`lsof-backend-linux`'s `safefs`); a thread blocked on such a file
//!   system cannot be abandoned there (measured: the process is not reaped
//!   while it waits, and its stdout never reaches EOF).
//! * **in-process** (`-O`): the call is made here, with no time limit. The C
//!   arms `alarm()` around it, which cannot end a FUSE or NFS wait either, so
//!   the documented risk is the C's too.
//! * **avoided** (`-b`): no call at all. The C says so, `lsof: avoiding
//!   stat(P): -b was specified.`, unless `-w`, and fails with `EWOULDBLOCK`.
//!
//! The C's own timeout works only the first time it fires in a run
//! (DIVERGENCES 118), its `-O` crashes when a timed-out call returns (119),
//! and a timed-out `readlink` is read as a one-byte link (120). None of that
//! is reproduced: here every call is bounded, each on its own.
//!
//! What is portable lives here: the options, the stat record, the
//! in-process calls, and the dispatch. The helper that bounds a call is a
//! platform's; Windows and every unit test use [`InProcess`].

use std::ffi::OsString;
use std::io;
use std::path::Path;

use crate::render::Escaper;

/// `-S`'s default, the C's `TMLIMIT` (`lib/common.h`).
pub const TMLIMIT: u32 = 15;

/// The smallest `-S` the C accepts, `TMLIMMIN`: a smaller one is raised to it
/// with a warning.
pub const TMLIMMIN: u32 = 2;

/// At most this many names come back from one [`SafeFs::read_dir`]: more than
/// a `+D` walk takes in all (its budget is 200,000 entries), so a listing it
/// walks is never cut. It bounds what a directory, or a helper, can make lsof
/// hold.
pub const READ_DIR_MAX_NAMES: usize = 1 << 20;

/// At most this many bytes of names come back from one [`SafeFs::read_dir`],
/// for the same reason: a walk stops after 16 MiB of the longer paths.
pub const READ_DIR_MAX_BYTES: usize = 64 << 20;

/// The longest name or link target a call returns, `MAXPATHLEN`: the C reads
/// a link into a buffer that size, and Linux keeps both below it.
pub const MAX_NAME: usize = crate::readlink::MAXPATHLEN;

/// What `-b`, `-O` and `-S` say, as they stood at one point of the command
/// line. The C reads its options in order and acts on a `+d`/`+D` where it
/// stands, so a `+d`'s directory is examined under the options given before
/// it (`-b +d D` fails, `+d D -b` does not); a [`crate::DirArg`] keeps its
/// own copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Blocking {
    /// `-b`/`+b`: make none of these calls. It beats `-O`.
    pub avoid: bool,
    /// `-O`: make them in-process, with no time limit; `+O` undoes it.
    pub in_process: bool,
    /// `-S [t]`: the seconds each may take. Never below [`TMLIMMIN`] once
    /// the parser has it.
    pub limit: u32,
}

impl Default for Blocking {
    fn default() -> Self {
        Blocking {
            avoid: false,
            in_process: false,
            limit: TMLIMIT,
        }
    }
}

/// How a call is made, as [`Blocking`] decides it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Avoid,
    InProcess,
    Bounded(u32),
}

impl Blocking {
    fn mode(&self) -> Mode {
        if self.avoid {
            Mode::Avoid
        } else if self.in_process {
            Mode::InProcess
        } else {
            Mode::Bounded(self.limit)
        }
    }
}

const S_IFMT: u32 = 0o170_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFLNK: u32 = 0o120_000;
const S_IFBLK: u32 = 0o060_000;
#[cfg(not(unix))]
const S_IFREG: u32 = 0o100_000;

/// What a `stat` says about a file, as plain numbers: what crosses from a
/// helper process, and all any caller reads. Copy, so a result can be kept.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileStat {
    /// `st_dev`: the file system the file is on.
    pub dev: u64,
    /// `st_ino`.
    pub ino: u64,
    /// `st_rdev`: the device a device node names.
    pub rdev: u64,
    /// `st_mode`, type bits and permissions.
    pub mode: u32,
    /// `st_nlink`.
    pub nlink: u64,
    /// `st_size`.
    pub size: u64,
    /// `st_uid`.
    pub uid: u32,
    /// `st_gid`.
    pub gid: u32,
}

impl FileStat {
    pub fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }

    pub fn is_symlink(&self) -> bool {
        self.mode & S_IFMT == S_IFLNK
    }

    pub fn is_block_device(&self) -> bool {
        self.mode & S_IFMT == S_IFBLK
    }
}

impl From<&std::fs::Metadata> for FileStat {
    #[cfg(unix)]
    fn from(md: &std::fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        FileStat {
            dev: md.dev(),
            ino: md.ino(),
            rdev: md.rdev(),
            mode: md.mode(),
            nlink: md.nlink(),
            size: md.size(),
            uid: md.uid(),
            gid: md.gid(),
        }
    }

    /// Where there is no `st_mode` (Windows), the type bits a caller asks
    /// about, and the size. Names are matched there, not identities, so
    /// nothing reads the rest.
    #[cfg(not(unix))]
    fn from(md: &std::fs::Metadata) -> Self {
        let kind = md.file_type();
        let mode = if kind.is_symlink() {
            S_IFLNK
        } else if kind.is_dir() {
            S_IFDIR
        } else {
            S_IFREG
        };
        FileStat {
            mode,
            size: md.len(),
            ..FileStat::default()
        }
    }
}

// The numbers this module needs from <errno.h> and <fcntl.h>, written out
// because `std` exports none of them and this crate takes no dependency.
// Only for the architectures whose values were checked: against this host's
// headers (x86_64: `bits/fcntl-linux.h`, `asm-generic/errno-base.h`,
// `asm-generic/errno.h`) and the `libc` crate's per-architecture tables
// (0.2.189). Anywhere else ([`sys::KNOWN`] false) an error is built from its
// text and a `stat` is std's.
#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "riscv64",
        target_arch = "powerpc64",
        target_arch = "powerpc",
        target_arch = "s390x",
        target_arch = "loongarch64",
    )
))]
mod sys {
    pub const KNOWN: bool = true;
    pub const ECHILD: i32 = 10;
    pub const EAGAIN: i32 = 11;
    pub const EINVAL: i32 = 22;
    pub const ENAMETOOLONG: i32 = 36;
    pub const ETIMEDOUT: i32 = 110;
    pub const O_PATH: i32 = 0o10_000_000;
    #[cfg(any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "powerpc64",
        target_arch = "powerpc"
    ))]
    pub const O_NOFOLLOW: i32 = 0o100_000;
    #[cfg(not(any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "powerpc64",
        target_arch = "powerpc"
    )))]
    pub const O_NOFOLLOW: i32 = 0o400_000;
}

#[cfg(not(all(
    target_os = "linux",
    any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "riscv64",
        target_arch = "powerpc64",
        target_arch = "powerpc",
        target_arch = "s390x",
        target_arch = "loongarch64",
    )
)))]
mod sys {
    pub const KNOWN: bool = false;
    pub const ECHILD: i32 = 0;
    pub const EAGAIN: i32 = 0;
    pub const EINVAL: i32 = 0;
    pub const ENAMETOOLONG: i32 = 0;
    pub const ETIMEDOUT: i32 = 0;
    #[cfg(unix)]
    pub const O_PATH: i32 = 0;
    #[cfg(unix)]
    pub const O_NOFOLLOW: i32 = 0;
}

/// `errno` as an error, so that `strerror()`'s words are the C library's,
/// byte for byte the C's; where the number was not checked, those words.
fn os_error(errno: i32, kind: io::ErrorKind, text: &'static str) -> io::Error {
    if sys::KNOWN {
        io::Error::from_raw_os_error(errno)
    } else {
        io::Error::new(kind, text)
    }
}

/// `ETIMEDOUT`, `Connection timed out`: a bounded call ran out of time, as
/// the C's `doinchild()` says it (`errno = ETIMEDOUT`).
pub fn timed_out() -> io::Error {
    os_error(
        sys::ETIMEDOUT,
        io::ErrorKind::TimedOut,
        "Connection timed out",
    )
}

/// Whether `e` is a bounded call running out of time ([`timed_out`]).
pub fn is_timed_out(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::TimedOut
}

/// `EWOULDBLOCK` (Linux's `EAGAIN`), `Resource temporarily unavailable`: a
/// call `-b` avoided.
pub fn would_block() -> io::Error {
    os_error(
        sys::EAGAIN,
        io::ErrorKind::WouldBlock,
        "Resource temporarily unavailable",
    )
}

/// `ECHILD`, `No child processes`: the process making a call went away or
/// answered nonsense, as the C's `doinchild()` says when its pipes fail.
pub fn lost_child() -> io::Error {
    os_error(sys::ECHILD, io::ErrorKind::Other, "No child processes")
}

/// `EINVAL`, `Invalid argument`: a path no call can take, one holding a NUL.
/// Only a mount point can (`\000` in the mount table), and the C would have
/// cut it there; this refuses it, whichever way the call is made.
pub fn invalid_path() -> io::Error {
    os_error(sys::EINVAL, io::ErrorKind::InvalidInput, "Invalid argument")
}

/// `ENAMETOOLONG`, `File name too long`: a path longer than a helper takes,
/// and longer than any the kernel would.
pub fn name_too_long() -> io::Error {
    os_error(
        sys::ENAMETOOLONG,
        io::ErrorKind::InvalidInput,
        "File name too long",
    )
}

/// `stat(2)` of `path`, or with `follow` false `lstat(2)`, made here and now:
/// the one way lsof-rs looks at a path it was given, wherever the call runs.
///
/// Where the flags are known (see `sys`), it opens the path `O_PATH` (and
/// `O_NOFOLLOW` for `lstat`) and asks the descriptor, which is what `stat(2)`
/// does and std's `metadata()` does not: std's `statx` lacks
/// `AT_NO_AUTOMOUNT`, so `std::fs::metadata` of an autofs mount point mounts
/// it (measured: `metadata`, `symlink_metadata` and `DirEntry::metadata`
/// each triggered an automount; `O_PATH` + `File::metadata` did not, nor did
/// `stat(2)`). `O_PATH` opens no file: a FIFO or a device is not opened, and
/// its permissions are not checked beyond search. Elsewhere, and under miri,
/// which has no `O_PATH`, std's calls.
pub fn stat_now(path: &Path, follow: bool) -> io::Result<FileStat> {
    #[cfg(unix)]
    if sys::KNOWN && !cfg!(miri) {
        use std::os::unix::fs::OpenOptionsExt;
        let flags = if follow {
            sys::O_PATH
        } else {
            sys::O_PATH | sys::O_NOFOLLOW
        };
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(flags)
            .open(path)?;
        return file.metadata().map(|md| FileStat::from(&md));
    }
    let md = if follow {
        std::fs::metadata(path)?
    } else {
        std::fs::symlink_metadata(path)?
    };
    Ok(FileStat::from(&md))
}

/// `readlink(2)` of `path`, here and now: the target of the link that is its
/// last component.
pub fn readlink_now(path: &Path) -> io::Result<OsString> {
    std::fs::read_link(path).map(|p| p.into_os_string())
}

/// The names in a directory, here and now, in the order the system gives
/// them: names only. The type a walk acts on is its own `lstat`'s, never the
/// directory entry's `d_type` (which a file system may leave unknown, and
/// which a rename can make wrong). A name longer than [`MAX_NAME`] cannot be
/// looked up and is left out; past [`READ_DIR_MAX_NAMES`] names or
/// [`READ_DIR_MAX_BYTES`] bytes of them the rest are too. An entry the system
/// fails to read ends the listing, as `readdir()` returning NULL ends the C's.
pub fn read_dir_now(path: &Path) -> io::Result<Vec<OsString>> {
    let mut names = Vec::new();
    let mut bytes = 0usize;
    for entry in std::fs::read_dir(path)?.map_while(Result::ok) {
        let name = entry.file_name();
        let len = name.len();
        if len > MAX_NAME {
            continue;
        }
        if names.len() == READ_DIR_MAX_NAMES || bytes + len > READ_DIR_MAX_BYTES {
            break;
        }
        bytes += len;
        names.push(name);
    }
    Ok(names)
}

/// Where the four calls are made, given `limit` seconds each: a platform's
/// helper process, or [`InProcess`]. A call that runs out of time fails with
/// [`timed_out`]; one whose helper fails, with [`lost_child`]. A caller goes
/// through [`SafeFs`], which applies `-b` and `-O` first.
pub trait FsCalls {
    /// `stat(2)`: follows a final symbolic link.
    fn stat(&self, path: &Path, limit: u32) -> io::Result<FileStat>;
    /// `lstat(2)`: describes a final symbolic link itself.
    fn lstat(&self, path: &Path, limit: u32) -> io::Result<FileStat>;
    /// `readlink(2)`: the target of the link `path` names.
    fn readlink(&self, path: &Path, limit: u32) -> io::Result<OsString>;
    /// The names in a directory ([`read_dir_now`]).
    fn read_dir(&self, path: &Path, limit: u32) -> io::Result<Vec<OsString>>;

    /// The processes these calls run in that are still there: a helper that
    /// is waiting for its next call, and one killed while a call outlived its
    /// limit and still waiting on that file system. Such a process holds
    /// what it opened for the call, and a scan must not `stat` that
    /// (`Selection::helpers`). None for calls made in this process.
    fn helper_pids(&self) -> Vec<u32> {
        Vec::new()
    }
}

/// The calls made in this process, with no time limit: `-O`, and the whole
/// layer where there is no helper (Windows, and every unit test, since under
/// `cargo test` the running binary is the test harness and no lsof to start).
#[derive(Clone, Copy, Debug, Default)]
pub struct InProcess;

impl FsCalls for InProcess {
    fn stat(&self, path: &Path, _limit: u32) -> io::Result<FileStat> {
        stat_now(path, true)
    }

    fn lstat(&self, path: &Path, _limit: u32) -> io::Result<FileStat> {
        stat_now(path, false)
    }

    fn readlink(&self, path: &Path, _limit: u32) -> io::Result<OsString> {
        readlink_now(path)
    }

    fn read_dir(&self, path: &Path, _limit: u32) -> io::Result<Vec<OsString>> {
        read_dir_now(path)
    }
}

/// Where a warning goes: stderr, as the C prints them, where it stands.
pub fn to_stderr(line: &str) {
    eprintln!("{line}");
}

/// The calls lsof-rs makes on a path it was given, under the `-b`, `-O` and
/// `-S` in force where the path was given, and the `-w` too: a `-b` message
/// is a warning. Copy: [`SafeFs::with`] makes the view a `+d`'s snapshot
/// asks for from the run's one.
#[derive(Clone, Copy)]
pub struct SafeFs<'a> {
    calls: &'a dyn FsCalls,
    say: &'a dyn Fn(&str),
    blocking: Blocking,
    warn: bool,
}

impl std::fmt::Debug for SafeFs<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SafeFs")
            .field("blocking", &self.blocking)
            .field("warn", &self.warn)
            .finish_non_exhaustive()
    }
}

static IN_PROCESS: InProcess = InProcess;

impl<'a> SafeFs<'a> {
    /// The layer over `calls`, warning through `say`, with the defaults: no
    /// `-b`, no `-O`, 15 seconds, warnings on.
    pub fn new(calls: &'a dyn FsCalls, say: &'a dyn Fn(&str)) -> Self {
        SafeFs {
            calls,
            say,
            blocking: Blocking::default(),
            warn: true,
        }
    }

    /// The same layer under other options: `-b`/`-O`/`-S` as `blocking`
    /// says, warnings as `warn` says (the C's `!Fwarn`).
    pub fn with(self, blocking: Blocking, warn: bool) -> Self {
        SafeFs {
            blocking,
            warn,
            ..self
        }
    }

    /// The options this view applies.
    pub fn blocking(&self) -> Blocking {
        self.blocking
    }

    /// Whether this view's warnings print.
    pub fn warns(&self) -> bool {
        self.warn
    }

    /// Print `line` where this layer's warnings go, whatever `-w` says: for
    /// what the C prints unconditionally while it parses (`-S time (N)
    /// changed to 2`), so that it comes in order with what this layer says.
    pub fn tell(&self, line: &str) {
        (self.say)(line);
    }

    /// `lsof: avoiding CALL(P): -b was specified.`, unless warnings are off.
    /// `P` is escaped, though the C prints `stat`'s raw (DIVERGENCES 122): a
    /// path is a name anyone may choose, and it goes to a terminal.
    pub fn avoiding(&self, call: &str, path: &[u8]) {
        if self.warn {
            (self.say)(&format!(
                "lsof: avoiding {call}({}): -b was specified.",
                Escaper::for_host().bytes(path)
            ));
        }
    }

    fn shown(path: &Path) -> &[u8] {
        path.as_os_str().as_encoded_bytes()
    }

    /// `statsafely()`: `stat(2)`, bounded.
    pub fn stat(&self, path: &Path) -> io::Result<FileStat> {
        match self.blocking.mode() {
            Mode::Avoid => {
                self.avoiding("stat", Self::shown(path));
                Err(would_block())
            }
            _ if Self::shown(path).contains(&0) => Err(invalid_path()),
            Mode::InProcess => IN_PROCESS.stat(path, 0),
            Mode::Bounded(limit) => self.calls.stat(path, limit),
        }
    }

    /// `lstatsafely()`: `lstat(2)`, bounded. Under `-b` the C's message
    /// says `stat` here too (`lib/misc.c`).
    pub fn lstat(&self, path: &Path) -> io::Result<FileStat> {
        match self.blocking.mode() {
            Mode::Avoid => {
                self.avoiding("stat", Self::shown(path));
                Err(would_block())
            }
            _ if Self::shown(path).contains(&0) => Err(invalid_path()),
            Mode::InProcess => IN_PROCESS.lstat(path, 0),
            Mode::Bounded(limit) => self.calls.lstat(path, limit),
        }
    }

    /// One `readlink(2)`, bounded: the step the C's `Readlink()` makes per
    /// path component (`doinchild(doreadlink)`). Under `-b`,
    /// `readlink::resolve` (Unix) makes none and says so once; a lone call
    /// says so for its path.
    pub fn readlink(&self, path: &Path) -> io::Result<OsString> {
        match self.blocking.mode() {
            Mode::Avoid => {
                self.avoiding("readlink", Self::shown(path));
                Err(would_block())
            }
            _ if Self::shown(path).contains(&0) => Err(invalid_path()),
            Mode::InProcess => IN_PROCESS.readlink(path, 0),
            Mode::Bounded(limit) => self.calls.readlink(path, limit),
        }
    }

    /// A directory's names ([`read_dir_now`]), bounded: each batch the
    /// system returns must come within the limit. The C reads directories in
    /// lsof itself, with no limit; a `+D` into a file system whose `stat`
    /// answers and whose `readdir` does not would hang it there. Under `-b`
    /// it is avoided in silence: the C has no such message, and a `+d`/`+D`
    /// under `-b` has already failed on its directory's `stat`.
    pub fn read_dir(&self, path: &Path) -> io::Result<Vec<OsString>> {
        match self.blocking.mode() {
            Mode::Avoid => Err(would_block()),
            _ if Self::shown(path).contains(&0) => Err(invalid_path()),
            Mode::InProcess => IN_PROCESS.read_dir(path, 0),
            Mode::Bounded(limit) => self.calls.read_dir(path, limit),
        }
    }
}

impl SafeFs<'static> {
    /// The layer with no helper: every call in-process, warnings to stderr.
    /// What the option parser's tests, the fuzz targets and Windows use.
    pub fn in_process() -> Self {
        SafeFs::new(&IN_PROCESS, &to_stderr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// A record of what was asked of a fake `FsCalls`, and with what limit.
    #[derive(Default)]
    struct Recorder(RefCell<Vec<(&'static str, Vec<u8>, u32)>>);

    impl Recorder {
        fn note(&self, call: &'static str, path: &Path, limit: u32) {
            self.0
                .borrow_mut()
                .push((call, path.as_os_str().as_encoded_bytes().to_vec(), limit));
        }
    }

    impl FsCalls for Recorder {
        fn stat(&self, path: &Path, limit: u32) -> io::Result<FileStat> {
            self.note("stat", path, limit);
            Ok(FileStat::default())
        }
        fn lstat(&self, path: &Path, limit: u32) -> io::Result<FileStat> {
            self.note("lstat", path, limit);
            Ok(FileStat::default())
        }
        fn readlink(&self, path: &Path, limit: u32) -> io::Result<OsString> {
            self.note("readlink", path, limit);
            Err(io::Error::from(io::ErrorKind::InvalidInput))
        }
        fn read_dir(&self, path: &Path, limit: u32) -> io::Result<Vec<OsString>> {
            self.note("read_dir", path, limit);
            Ok(Vec::new())
        }
    }

    /// The default is bounded, with the limit `-S` gave; `-O` makes the call
    /// here and asks nothing of the helper; `-b` asks nothing of anyone and
    /// beats `-O`.
    #[test]
    fn the_options_choose_where_a_call_is_made() {
        let rec = Recorder::default();
        let said = RefCell::new(Vec::<String>::new());
        let say = |l: &str| said.borrow_mut().push(l.to_string());
        let fs = SafeFs::new(&rec, &say);
        let p = Path::new("/");
        fs.stat(p).unwrap();
        let seven = fs.with(
            Blocking {
                limit: 7,
                ..Blocking::default()
            },
            true,
        );
        seven.lstat(p).unwrap();
        seven.read_dir(p).unwrap();
        seven.readlink(p).unwrap_err();
        assert_eq!(
            *rec.0.borrow(),
            [
                ("stat", b"/".to_vec(), TMLIMIT),
                ("lstat", b"/".to_vec(), 7),
                ("read_dir", b"/".to_vec(), 7),
                ("readlink", b"/".to_vec(), 7),
            ]
        );
        let o = Blocking {
            in_process: true,
            ..Blocking::default()
        };
        assert!(
            fs.with(o, true).stat(p).unwrap().is_dir(),
            "a real stat of /"
        );
        let b = Blocking {
            avoid: true,
            in_process: true,
            ..Blocking::default()
        };
        assert!(fs.with(b, true).stat(p).is_err());
        assert!(fs.with(b, true).read_dir(p).is_err());
        assert_eq!(
            rec.0.borrow().len(),
            4,
            "-O and -b asked nothing of the helper"
        );
        assert!(said.borrow().iter().all(|l| l.contains("avoiding")));
    }

    /// `-b`: no call, `EWOULDBLOCK`, and the C's words for stat and lstat
    /// alike, with the path escaped; nothing said once warnings are off.
    #[test]
    fn avoided_calls_say_so_escaped_unless_warnings_are_off() {
        let rec = Recorder::default();
        let said = RefCell::new(Vec::<String>::new());
        let say = |l: &str| said.borrow_mut().push(l.to_string());
        let b = Blocking {
            avoid: true,
            ..Blocking::default()
        };
        let fs = SafeFs::new(&rec, &say).with(b, true);
        let hostile = Path::new("/tmp/e\x1b[2Jx");
        let e = fs.stat(hostile).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::WouldBlock);
        if sys::KNOWN {
            assert_eq!(e.raw_os_error(), Some(11));
        }
        #[cfg(not(miri))]
        assert_eq!(crate::errno_text(&e), "Resource temporarily unavailable");
        fs.lstat(Path::new("/l")).unwrap_err();
        fs.readlink(Path::new("/r")).unwrap_err();
        assert_eq!(
            *said.borrow(),
            [
                "lsof: avoiding stat(/tmp/e^[[2Jx): -b was specified.",
                "lsof: avoiding stat(/l): -b was specified.",
                "lsof: avoiding readlink(/r): -b was specified.",
            ]
        );
        assert!(rec.0.borrow().is_empty(), "-b made a call");
        said.borrow_mut().clear();
        let quiet = fs.with(b, false);
        quiet.stat(hostile).unwrap_err();
        quiet.readlink(hostile).unwrap_err();
        assert!(said.borrow().is_empty(), "{:?}", said.borrow());
    }

    /// The errors carry the C library's words, which is what the C prints.
    #[cfg(not(miri))]
    #[test]
    fn the_errors_read_as_the_c_prints_them() {
        assert_eq!(crate::errno_text(&timed_out()), "Connection timed out");
        assert_eq!(crate::errno_text(&lost_child()), "No child processes");
        assert_eq!(crate::errno_text(&invalid_path()), "Invalid argument");
        assert_eq!(crate::errno_text(&name_too_long()), "File name too long");
        if sys::KNOWN {
            assert_eq!(timed_out().raw_os_error(), Some(110));
            assert_eq!(lost_child().raw_os_error(), Some(10));
        }
    }

    /// A path holding a NUL is refused in every mode that makes a call, the
    /// same way, and reaches no one.
    #[test]
    fn a_path_with_a_nul_reaches_no_call() {
        let rec = Recorder::default();
        let fs = SafeFs::new(&rec, &to_stderr);
        let p = Path::new("/a\0b");
        assert_eq!(fs.stat(p).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        let o = Blocking {
            in_process: true,
            ..Blocking::default()
        };
        assert_eq!(
            fs.with(o, true).lstat(p).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(rec.0.borrow().is_empty());
    }

    /// `stat` follows a final link and `lstat` does not; a FIFO with no
    /// writer is described, not opened (an `O_RDONLY` open would block).
    #[cfg(unix)]
    #[test]
    #[cfg_attr(miri, ignore = "miri cannot make a FIFO (mkfifo is not shimmed)")]
    fn stat_now_follows_lstat_does_not_and_neither_opens() {
        let dir = std::env::temp_dir().join(format!("lsof-rs-safefs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::os::unix::fs::symlink(".", dir.join("dot")).unwrap();
        let link = stat_now(&dir.join("dot"), false).unwrap();
        assert!(link.is_symlink());
        let target = stat_now(&dir.join("dot"), true).unwrap();
        assert!(target.is_dir());
        let fifo = dir.join("fifo");
        let made = std::process::Command::new("mkfifo").arg(&fifo).status();
        if made.is_ok_and(|s| s.success()) {
            let st = stat_now(&fifo, true).unwrap();
            assert_eq!(st.mode & S_IFMT, 0o010_000, "a FIFO");
        }
        assert_eq!(
            stat_now(&dir.join("nope"), true).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Names only, and every one of them.
    #[test]
    #[cfg_attr(miri, ignore = "miri's readdir shim is slow and this asks the host")]
    fn read_dir_now_gives_the_names() {
        let dir = std::env::temp_dir().join(format!("lsof-rs-safefs-rd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("f"), b"x").unwrap();
        let mut names = read_dir_now(&dir).unwrap();
        names.sort();
        assert_eq!(names, ["f", "sub"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_type_bits_are_read_from_the_mode() {
        let st = |mode| FileStat {
            mode,
            ..FileStat::default()
        };
        assert!(st(0o040_755).is_dir() && !st(0o040_755).is_symlink());
        assert!(st(0o120_777).is_symlink() && !st(0o120_777).is_dir());
        assert!(st(0o060_660).is_block_device());
        assert!(!st(0o020_666).is_block_device(), "a character device");
    }

    /// The limits a walk relies on: a listing is cut only past what a walk
    /// takes (`main.rs`: 200,000 entries, 16 MiB of paths).
    #[test]
    fn a_listing_holds_more_than_a_walk_takes() {
        const _: () = assert!(READ_DIR_MAX_NAMES > 200_000);
        const _: () = assert!(READ_DIR_MAX_BYTES > 16 << 20);
    }
}
