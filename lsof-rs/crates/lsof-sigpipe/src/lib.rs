//! What must happen before the Rust runtime starts: the `SIGPIPE`
//! disposition lsof-rs inherited is read (and can be put back), and the C
//! lsof's first two steps are taken, on the descriptors it inherited.
//!
//! # `SIGPIPE`
//!
//! The C lsof never touches `SIGPIPE`: a closed pipe kills it at the
//! `write(2)` that meets it where the signal was left at its default, and
//! where its parent ignored or blocked it the write fails and the C, whose
//! stdio errors go unchecked, writes on and exits with its usual status
//! (measured: `lsof | head -1` is killed by the signal, `trap '' PIPE` and a
//! blocked signal exit 0). The Rust runtime sets `SIGPIPE` to `SIG_IGN`
//! before `main` and keeps nothing of what it replaced, and no stable
//! interface leaves it alone (`-Zon-broken-pipe=inherit` is nightly-only and
//! to be removed, rust-lang/rust#97889). So this crate reads it first, from
//! a constructor glibc runs from `.init_array` before the runtime's own
//! initialisation, as std itself reads `argv` and as uutils reads this same
//! disposition (`uucore::signals`), and gives the binary
//! [`restore_default`] to put the default back.
//!
//! # The descriptors lsof starts with
//!
//! The C's `main()` begins (`src/main.c:173-183`):
//!
//! ```c
//! closefrom_shim(ctx, 3);
//! while (((i = open("/dev/null", O_RDWR, 0)) >= 0) && (i < 2))
//!     ;
//! if (i < 0)
//!     Error(ctx);
//! if (i > 2)
//!     (void)close(i);
//! ```
//!
//! Every descriptor from 3 up that it was given is closed, each of 0, 1 and
//! 2 that was closed is `/dev/null`, read and write, and a run that cannot
//! open `/dev/null` ends there, exit 1, with nothing said, before an option
//! is read (`Error()`, `lib/misc.c:778`). So a file only lsof itself was
//! handed is not in its listing (`lsof FILE 9<FILE` lists nothing and exits
//! 1, measured), no reader of an inherited pipe waits on lsof or on its
//! helper, and `lsof -v` with no usable `/dev/null` prints nothing.
//!
//! The same constructor does both (`startup::start_up`), because it is the
//! one point where closing a descriptor this program does not own is sound:
//! see `startup::Kernel::at_start`. Rust's own start-up, which comes after, puts
//! `/dev/null` on a closed 0, 1 or 2 itself and **aborts** where it cannot
//! (measured, exit 134: a `/dev` with no `null`, `lsof -v <&-`); it now
//! finds all three open.
//!
//! `closefrom_shim()` (`lib/misc.c:215-250`) is `closefrom(3)` where the C
//! library has it (`HAS_CLOSEFROM`: FreeBSD, and glibc since 2.34, whose
//! `closefrom()` is `close_range(low, ~0U, 0)`, measured with `strace`), and
//! else `close_range(2)`, then a walk of `/proc/self/fd`, then every number
//! below the descriptor limit one by one. Here (`startup::close_from`): on
//! FreeBSD `closefrom(3)`; on Linux the raw `close_range(3, ~0U, 0)` (no
//! glibc version is needed for it), where that fails (a kernel before 5.9,
//! a seccomp filter that refuses it) the walk of `/proc/self/fd`, read with
//! `getdents64(2)` into a buffer on the stack, and where there is no
//! `/proc` either the numbers below the limit, at most 1,048,576 of them
//! (`startup::SWEEP_MAX`). glibc's `closefrom()` aborts in that last case,
//! and the shim's loop runs to the limit whatever it is (a limit of 2^30 is
//! a thousand million `close()` calls): the bound is lsof-rs's own.
//!
//! This runs in every process of the binary: lsof, and the helper its
//! bounded calls run in, which is lsof re-executed. The helper is given two
//! pipes and `/dev/null` on 0 to 2 and nothing above on purpose, so there
//! the close finds nothing and the loop opens and closes one descriptor. It
//! also runs in the two test binaries whose link takes this crate's object
//! in (measured with `strace`): the unit tests of the binary's own source,
//! `lsof-cli/src/main.rs`, which calls [`inherited_ignored`], and this
//! crate's. cargo hands a test binary 0 to 2 alone (measured), so nothing is
//! closed there; one whose `/dev/null` cannot be opened ends with status 1
//! and no message, as lsof does. No other test binary, and no fuzz target,
//! refers to this crate, and none runs the constructor.
//!
//! # Safety
//!
//! Each `unsafe` site carries a `SAFETY` comment: the constructor's
//! `link_section` static (an attribute `#![forbid(unsafe_code)]` refuses,
//! which is why this is a crate of its own: lsof-core, lsof-cli and
//! lsof-backend-linux keep it), its query-only `sigaction()`,
//! `restore_default`'s `signal()`, the one place a `startup::Kernel` is made,
//! and the system calls behind it, one a block: `close_range` (or FreeBSD's
//! `closefrom`), `open`, `getdents64`, `getdtablesize`, `close`, `_exit`.
//! None writes memory but a local of its own. The constructor allocates
//! nothing, cannot panic (no index, no arithmetic that can overflow, no
//! formatting) and uses nothing of std but an atomic. Off Linux and FreeBSD
//! there is no constructor, nothing is known, and nothing is changed; under
//! miri, which runs constructors and has none of these calls, it does
//! nothing.
#![deny(unsafe_op_in_unsafe_fn)]

use std::sync::atomic::{AtomicU8, Ordering};

/// What the constructor saw: 0 nothing (it did not run), 1 the default or a
/// handler, 2 ignored.
static INHERITED: AtomicU8 = AtomicU8::new(0);

/// Whether `SIGPIPE` was ignored when the process started: `Some(true)`
/// where its parent left it `SIG_IGN` (`trap '' PIPE`, `nohup`, a Python
/// child with `restore_signals=False`), `Some(false)` where it was the
/// default, `None` where it could not be read (no constructor on this
/// platform, or `sigaction()` failed).
pub fn inherited_ignored() -> Option<bool> {
    match INHERITED.load(Ordering::Relaxed) {
        1 => Some(false),
        2 => Some(true),
        _ => None,
    }
}

/// Whether `SIGPIPE` is in this thread's blocked mask, which the Rust
/// runtime keeps as it was inherited: read, safely, from the `SigBlk` line
/// of `/proc/self/status` (bit 12, signal 13). `false` where that cannot
/// be read, and off Linux.
pub fn blocked() -> bool {
    #[cfg(target_os = "linux")]
    {
        let Ok(status) = std::fs::read_to_string("/proc/thread-self/status")
            .or_else(|_| std::fs::read_to_string("/proc/self/status"))
        else {
            return false;
        };
        sigpipe_in_mask(&status)
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Bit 12 of `SigBlk:`'s hexadecimal mask in a `/proc/<pid>/status` text.
pub fn sigpipe_in_mask(status: &str) -> bool {
    status
        .lines()
        .find_map(|l| l.strip_prefix("SigBlk:"))
        .and_then(|mask| u64::from_str_radix(mask.trim(), 16).ok())
        .is_some_and(|mask| mask & (1 << 12) != 0)
}

/// Put `SIGPIPE` back to `SIG_DFL`, so that a write to a pipe with no
/// reader ends the process with the signal, at that write, as it ends the
/// C. The caller does this only where the disposition was inherited as the
/// default and the signal is not blocked ([`inherited_ignored`],
/// [`blocked`]). Nothing off Linux and FreeBSD.
pub fn restore_default() {
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    // SAFETY: `signal()` with `SIG_DFL` installs no handler: no code of ours
    // runs on the signal, so nothing it could touch needs to be
    // async-signal-safe, and the call reads and writes only the kernel's
    // disposition table. `SIGPIPE` is a valid signal number on both
    // platforms, so it cannot fail (`SIG_ERR` would leave the disposition as
    // it was, which is harmless here).
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

/// The descriptors lsof starts with: the C's first two steps, as safe code
/// over the system calls they make ([`startup::Fds`]), and those calls. On
/// Linux and FreeBSD, where the constructor runs them; and in the tests.
#[cfg(any(target_os = "linux", target_os = "freebsd", test))]
mod startup {
    use std::ffi::c_int;

    /// The first descriptor the C closes as it starts: `closefrom_shim(ctx, 3)`.
    pub(crate) const FIRST_CLOSED: c_int = 3;

    /// The C's `MaxFd` is never below this (`main.c:173-174`): where every
    /// number is closed one by one, at least these are.
    pub(crate) const SWEEP_MIN: c_int = 53;

    /// At most this many numbers are closed one by one where neither
    /// `close_range(2)` nor `/proc/self/fd` is there: the kernel's default
    /// `fs.nr_open`, past which no descriptor is numbered unless root raised
    /// it. The C's loop runs to the soft limit whatever it is.
    pub(crate) const SWEEP_MAX: c_int = 1 << 20;

    /// The exit status of a run that cannot open `/dev/null`: the C's
    /// `LSOF_EXIT_ERROR`.
    pub(crate) const NO_DEV_NULL: c_int = 1;

    /// The system calls the start-up steps make, so that the steps themselves
    /// ([`start_up`]) are safe code a test runs over a table of its own.
    pub(crate) trait Fds {
        /// Close every descriptor from `low` up in one call; `false` where the
        /// system has no such call, and nothing was closed.
        fn close_from(&mut self, low: c_int) -> bool;
        /// Open the directory that lists this process's descriptors.
        fn open_fd_dir(&mut self) -> Option<c_int>;
        /// The next entries of that directory, as `getdents64(2)` writes them:
        /// how many bytes of `buf` were filled, 0 at its end or on an error.
        fn read_fd_dir(&mut self, dir: c_int, buf: &mut [u8]) -> usize;
        /// `getdtablesize()`: the descriptor limit.
        fn table_size(&mut self) -> c_int;
        /// `close(fd)`, its result unread, as the C leaves it.
        fn close(&mut self, fd: c_int);
        /// `open("/dev/null", O_RDWR)`: the descriptor, or a negative number.
        fn open_null(&mut self) -> c_int;
        /// End the process with `status`, at once. The kernel's does not
        /// return; a test's records the status and does.
        fn exit(&mut self, status: c_int);
    }

    /// The C's first two steps (`main.c:176-183`), in its order: every
    /// descriptor from 3 up closed ([`close_from`]), and then `/dev/null` on
    /// each of 0, 1 and 2 that was closed ([`open_standard`]). The close
    /// comes first, so that a table that was handed down full is no failure
    /// to open `/dev/null`.
    pub(crate) fn start_up(sys: &mut impl Fds) {
        close_from(sys, FIRST_CLOSED);
        open_standard(sys);
    }

    /// The C's loop (`main.c:178-183`): `/dev/null` opened until the
    /// descriptor it gets is at least 2, which leaves it on each of 0, 1 and
    /// 2 that was closed; a third one, past 2, is closed again, and where
    /// `/dev/null` cannot be opened the run ends, exit 1, with nothing said.
    pub(crate) fn open_standard(sys: &mut impl Fds) {
        loop {
            let fd = sys.open_null();
            if fd < 0 {
                sys.exit(NO_DEV_NULL);
                return;
            }
            if fd < 2 {
                continue;
            }
            if fd > 2 {
                sys.close(fd);
            }
            return;
        }
    }

    /// `closefrom_shim(ctx, low)` (`lib/misc.c:215-250`): the one call where
    /// the system has it; else each descriptor `/proc/self/fd` lists, but the
    /// listing's own; else every number from `low` to the descriptor limit
    /// ([`sweep_end`]).
    pub(crate) fn close_from(sys: &mut impl Fds, low: c_int) {
        if sys.close_from(low) || close_listed(sys, low) {
            return;
        }
        for fd in low..sweep_end(sys.table_size()) {
            sys.close(fd);
        }
    }

    /// Where the one-by-one close ends: the C's `MaxFd`, the descriptor limit
    /// and at least [`SWEEP_MIN`], and here at most [`SWEEP_MAX`].
    pub(crate) fn sweep_end(table_size: c_int) -> c_int {
        table_size.clamp(SWEEP_MIN, SWEEP_MAX)
    }

    /// The C's walk of `/proc/self/fd` (`lib/misc.c:230-243`): every entry
    /// whose name is a number from `low` up is closed, but the descriptor the
    /// directory itself is read through, which is closed last. `false` where
    /// the directory cannot be opened, and nothing was closed. Closing while
    /// listing skips nothing: procfs lists by descriptor number, from the last
    /// one it gave.
    pub(crate) fn close_listed(sys: &mut impl Fds, low: c_int) -> bool {
        let Some(dir) = sys.open_fd_dir() else {
            return false;
        };
        // Room for a hundred entries a call; one entry is at most 280 bytes.
        let mut buf = [0u8; 4096];
        loop {
            let filled = sys.read_fd_dir(dir, &mut buf);
            let Some(records) = buf.get(..filled).filter(|r| !r.is_empty()) else {
                break;
            };
            listed(records, &mut |fd| {
                if fd >= low && fd != dir {
                    sys.close(fd);
                }
            });
        }
        sys.close(dir);
        true
    }

    /// Where a `linux_dirent64`'s length is, its two bytes in the machine's
    /// order, and where its name begins: after `d_ino` and `d_off`, eight bytes
    /// each, the length and one byte of type (`getdents64(2)`).
    pub(crate) const DIRENT_RECLEN: std::ops::Range<usize> = 16..18;
    pub(crate) const DIRENT_NAME: usize = 19;

    /// Each descriptor number among the entries `getdents64(2)` wrote into
    /// `records`, in order. An entry whose name is no number (`.`, `..`) is
    /// passed by; one that says it is shorter than its own head, or longer than
    /// what is left, which the kernel never writes, ends the reading. Nothing
    /// is read outside `records`, and the reading ends whatever they hold:
    /// there are no more entries than bytes.
    pub(crate) fn listed(mut records: &[u8], each: &mut dyn FnMut(c_int)) {
        for _ in 0..records.len() {
            let Some(&[lo, hi]) = records.get(DIRENT_RECLEN) else {
                return;
            };
            let len = usize::from(u16::from_ne_bytes([lo, hi]));
            let Some(record) = records.get(..len).filter(|r| r.len() > DIRENT_NAME) else {
                return;
            };
            let name = record.get(DIRENT_NAME..).unwrap_or_default();
            let name = name.split(|&b| b == 0).next().unwrap_or_default();
            if let Some(fd) = fd_named(name) {
                each(fd);
            }
            records = records.get(len..).unwrap_or_default();
        }
    }

    /// The descriptor a `/proc/self/fd` entry names: decimal digits and nothing
    /// else, below `INT_MAX` (the C's `strtol()` and its `fd < INT_MAX`).
    pub(crate) fn fd_named(name: &[u8]) -> Option<c_int> {
        if name.is_empty() {
            return None;
        }
        let mut fd: c_int = 0;
        for &b in name {
            if !b.is_ascii_digit() {
                return None;
            }
            fd = fd
                .checked_mul(10)?
                .checked_add(c_int::from(b.wrapping_sub(b'0')))?;
        }
        (fd < c_int::MAX).then_some(fd)
    }

    /// The system itself ([`Fds`]). [`Kernel::at_start`] is the one way to
    /// make it, and the constructor the one place lsof-rs does.
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    pub(crate) struct Kernel(());

    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    impl Kernel {
        /// The system's descriptor table, to be closed and reopened as
        /// [`start_up`] does.
        ///
        /// # Safety
        ///
        /// No descriptor that is closed through the value may be owned by
        /// an object of this program: its methods close descriptors by
        /// number, whoever opened them, and a `File`, a socket or an
        /// `OwnedFd` whose descriptor was closed under it would next close,
        /// or read, whatever was opened at that number since. [`start_up`]
        /// closes every descriptor from 3 up, so for it no object may own
        /// one at all, which holds at one point alone: in a `.init_array`
        /// constructor, before `main` and before the Rust runtime's own
        /// initialisation, when nothing of this program has run yet and
        /// the process holds only what it was started with.
        pub(crate) unsafe fn at_start() -> Self {
            Kernel(())
        }
    }

    #[cfg(target_os = "linux")]
    impl Fds for Kernel {
        fn close_from(&mut self, low: c_int) -> bool {
            let Ok(first) = libc::c_uint::try_from(low) else {
                return false;
            };
            let (last, flags): (libc::c_uint, libc::c_uint) = (libc::c_uint::MAX, 0);
            // The raw call, as the C's shim makes it, so that no glibc version
            // is needed for it. A kernel without the call answers `ENOSYS`, a
            // filter that refuses it its own error, and nothing is closed.
            //
            // SAFETY: `close_range(first, last, flags)` takes three unsigned
            // integers and no pointer, and touches no memory of this process:
            // it closes the descriptors numbered `first` to `last`, none of
            // which an object of this program owns (`Kernel::at_start`'s
            // contract, taken on by whoever made this value).
            let rc = unsafe { libc::syscall(libc::SYS_close_range, first, last, flags) };
            rc == 0
        }

        fn open_fd_dir(&mut self) -> Option<c_int> {
            // SAFETY: the path is a NUL-terminated literal that `open()` only
            // reads; the flags are plain integers; the result is a new
            // descriptor of this function's caller, or -1.
            let dir = unsafe {
                libc::open(
                    c"/proc/self/fd".as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            };
            (dir >= 0).then_some(dir)
        }

        fn read_fd_dir(&mut self, dir: c_int, buf: &mut [u8]) -> usize {
            let (at, room) = (buf.as_mut_ptr(), buf.len());
            // SAFETY: `getdents64(fd, buf, count)` writes at most `count` bytes
            // at `buf`: `at` and `room` are the start and the length of a live,
            // writable slice that this call borrows exclusively until it
            // returns. `dir` is a number the kernel alone reads. What was
            // written is read afterwards as bytes, by safe code (`listed`).
            let filled = unsafe { libc::syscall(libc::SYS_getdents64, dir, at, room) };
            // An error (-1) is the listing's end, as the C's `readdir()` NULL.
            usize::try_from(filled).unwrap_or(0)
        }

        fn table_size(&mut self) -> c_int {
            // SAFETY: `getdtablesize()` takes nothing and returns an integer.
            unsafe { libc::getdtablesize() }
        }

        fn close(&mut self, fd: c_int) {
            // SAFETY: `close()` takes a descriptor number and touches no memory
            // of this process. Closing one is unsound only where an object
            // owns it, and `Kernel::at_start`'s contract, taken on by whoever
            // made this value, says none owns one closed here: `fd` is one
            // the process was started with, or one opened through this value
            // and held in no object.
            unsafe {
                libc::close(fd);
            }
        }

        fn open_null(&mut self) -> c_int {
            // SAFETY: the path is a NUL-terminated literal that `open()` only
            // reads; the flags are plain integers (no `O_CREAT`, so no mode is
            // read); the result is a new descriptor, in no object, or -1.
            // `O_LARGEFILE` is what the C's `open()` adds where it is not
            // implied (`-D_FILE_OFFSET_BITS=64`).
            unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_LARGEFILE) }
        }

        fn exit(&mut self, status: c_int) {
            // SAFETY: `_exit()` takes an integer and does not return. It runs
            // no `atexit` handler and flushes no stream, and at this point
            // there is none of this program's to run or flush: nothing of it
            // has run yet.
            unsafe { libc::_exit(status) }
        }
    }

    #[cfg(target_os = "freebsd")]
    impl Fds for Kernel {
        fn close_from(&mut self, low: c_int) -> bool {
            // SAFETY: `closefrom(lowfd)` takes an integer and touches no memory
            // of this process: it closes every descriptor from `lowfd` up,
            // none of which an object of this program owns (`Kernel::at_start`'s
            // contract, taken on by whoever made this value). It cannot fail.
            // The C's own call (`HAS_CLOSEFROM`).
            unsafe { libc::closefrom(low) };
            true
        }

        // `closefrom()` is always there: nothing is ever listed or swept.
        fn open_fd_dir(&mut self) -> Option<c_int> {
            None
        }

        fn read_fd_dir(&mut self, _dir: c_int, _buf: &mut [u8]) -> usize {
            0
        }

        fn table_size(&mut self) -> c_int {
            0
        }

        fn close(&mut self, fd: c_int) {
            // SAFETY: `close()` takes a descriptor number and touches no memory
            // of this process. Closing one is unsound only where an object
            // owns it, and `Kernel::at_start`'s contract, taken on by whoever
            // made this value, says none owns one closed here: `fd` is one
            // opened through this value and held in no object.
            unsafe {
                libc::close(fd);
            }
        }

        fn open_null(&mut self) -> c_int {
            // SAFETY: the path is a NUL-terminated literal that `open()` only
            // reads; the flags are plain integers (no `O_CREAT`, so no mode is
            // read); the result is a new descriptor, in no object, or -1.
            unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR) }
        }

        fn exit(&mut self, status: c_int) {
            // SAFETY: `_exit()` takes an integer and does not return. It runs
            // no `atexit` handler and flushes no stream, and at this point
            // there is none of this program's to run or flush: nothing of it
            // has run yet.
            unsafe { libc::_exit(status) }
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
extern "C" fn capture() {
    // miri runs constructors and has neither `sigaction()` nor the calls
    // the descriptors need: nothing is known, and nothing is closed.
    if cfg!(miri) {
        return;
    }
    // SAFETY: `libc::sigaction` is a plain C struct of integers, pointers
    // and a signal set, for which all-zero bytes are a valid value; it is
    // only an out-parameter here.
    let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: a query only: the new action is NULL, so nothing is changed,
    // and `old` is a valid, writable `sigaction` that outlives the call.
    // This runs from `.init_array`, before `main` and before the Rust
    // runtime's initialisation, on the one thread there is; it uses no part
    // of std that needs that initialisation (an atomic store alone).
    let rc = unsafe { libc::sigaction(libc::SIGPIPE, std::ptr::null(), &mut old) };
    if rc == 0 {
        let ignored = old.sa_sigaction == libc::SIG_IGN;
        INHERITED.store(if ignored { 2 } else { 1 }, Ordering::Relaxed);
    }
    // The C's first two steps, on the descriptors this process was started
    // with (`startup`). This is a `.init_array` constructor: the C runtime
    // calls it before `main`, so before the Rust runtime's initialisation
    // and before any code of lsof-rs or of a crate it links, on the one
    // thread there is. The only other constructor in the program is std's,
    // which stores `argc`, `argv` and `envp` and opens nothing (measured:
    // the binary's `.init_array` holds three entries, the C start-up files'
    // `frame_dummy`, std's and this one; lsof-cli's `tests/startup.rs`
    // fails on a fourth). So the process holds exactly what it was started
    // with. What a shared object loaded before the program opened in a
    // constructor of its own (a preloaded library) is closed too, as the C,
    // whose `closefrom()` comes after every constructor, closes it.
    //
    // SAFETY: `Kernel::at_start` asks that no object of this program own a
    // descriptor closed through it, and `start_up` closes every one from 3
    // up. None can: nothing of the program has run yet (above), so no
    // `File`, socket, `OwnedFd` or buffered stream exists to be left holding
    // a closed number. The value is dropped before this function returns.
    let mut kernel = unsafe { startup::Kernel::at_start() };
    startup::start_up(&mut kernel);
}

/// The constructor: glibc (and FreeBSD's rtld) call each function in
/// `.init_array` before `main`, and before the Rust runtime's own
/// initialisation, which sets `SIGPIPE` to `SIG_IGN` and would own the
/// descriptors it opens. glibc passes `argc`, `argv` and `envp`, which a
/// function of no parameters ignores under the C calling convention (the
/// arguments are in registers the callee need not read; uutils' constructor
/// is the same `extern "C" fn()`), and which the ELF ABI calls with none.
/// `#[used]` keeps the static; the binary calls [`inherited_ignored`], in
/// this same object, so the linker takes it in.
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
#[used]
// SAFETY: the section holds pointers to functions the C runtime calls
// before `main`: `capture` is an `extern "C" fn()`, the type the ELF ABI
// gives `.init_array` entries (glibc's extra arguments go unread), touches
// no Rust runtime state but an atomic, and cannot unwind (it calls nothing
// that panics, allocates nothing, and formats nothing). The static is one
// pointer, aligned as the section's entries are.
#[unsafe(link_section = ".init_array")]
static CAPTURE: extern "C" fn() = capture;

#[cfg(test)]
mod tests {
    use super::startup::*;
    use super::*;
    use std::collections::BTreeSet;
    use std::ffi::c_int;

    #[test]
    fn the_mask_line_is_read_for_bit_12() {
        assert!(sigpipe_in_mask("Name:\tx\nSigBlk:\t0000000000001000\n"));
        assert!(sigpipe_in_mask("SigBlk:\tffffffffffffffff\n"));
        assert!(!sigpipe_in_mask("SigBlk:\t0000000000000800\n"));
        assert!(!sigpipe_in_mask("SigBlk:\tzz\n"));
        assert!(!sigpipe_in_mask("SigIgn:\t0000000000001000\n"));
    }

    /// The constructor ran in this test binary before its `main`: the test
    /// harness, started by cargo, which leaves `SIGPIPE` as it was given.
    #[test]
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    #[cfg_attr(
        miri,
        ignore = "under miri the constructor reads nothing (miri has no sigaction)"
    )]
    fn the_constructor_ran() {
        assert!(inherited_ignored().is_some());
    }

    /// A process's descriptor table, as the kernel keeps one: the lowest
    /// free number is the next one opened, none at or past the limit.
    #[derive(Debug, Default)]
    struct Table {
        open: BTreeSet<c_int>,
        /// `RLIMIT_NOFILE`: no descriptor is opened at or past it.
        limit: c_int,
        /// What `getdtablesize()` answers, where that is not the limit.
        table_size: Option<c_int>,
        /// Whether `close_range(2)` is there, `/proc/self/fd`, `/dev/null`.
        has_close_range: bool,
        has_proc: bool,
        has_null: bool,
        /// The descriptors `/dev/null` was opened on and still is.
        null: BTreeSet<c_int>,
        /// The status the run ended with, and what was called after it.
        exited: Option<c_int>,
        after_exit: usize,
        /// Every `close()` made one by one, in order.
        closed: Vec<c_int>,
        /// How many `getdents64()` calls were made.
        reads: usize,
        /// Where the listing stands: the next number it gives.
        at: c_int,
    }

    impl Table {
        fn holding(open: &[c_int]) -> Self {
            Table {
                open: open.iter().copied().collect(),
                limit: 1024,
                has_close_range: true,
                has_proc: true,
                has_null: true,
                ..Table::default()
            }
        }

        fn lowest_free(&self) -> Option<c_int> {
            (0..self.limit).find(|fd| !self.open.contains(fd))
        }

        fn fds(&self) -> Vec<c_int> {
            self.open.iter().copied().collect()
        }

        fn called(&mut self) {
            if self.exited.is_some() {
                self.after_exit += 1;
            }
        }
    }

    /// One `linux_dirent64` for `name`, as the kernel lays it out: padded
    /// with NULs to a multiple of eight bytes.
    fn dirent(name: &[u8]) -> Vec<u8> {
        let len = (DIRENT_NAME + name.len() + 1).next_multiple_of(8);
        let mut out = vec![0u8; len];
        out[DIRENT_RECLEN].copy_from_slice(&(len as u16).to_ne_bytes());
        out[DIRENT_NAME..DIRENT_NAME + name.len()].copy_from_slice(name);
        out
    }

    impl Fds for Table {
        fn close_from(&mut self, low: c_int) -> bool {
            self.called();
            if self.has_close_range {
                self.open.retain(|&fd| fd < low);
                self.null.retain(|&fd| fd < low);
            }
            self.has_close_range
        }

        fn open_fd_dir(&mut self) -> Option<c_int> {
            self.called();
            let fd = self.lowest_free().filter(|_| self.has_proc)?;
            self.open.insert(fd);
            self.at = -2;
            Some(fd)
        }

        fn read_fd_dir(&mut self, dir: c_int, buf: &mut [u8]) -> usize {
            self.called();
            assert!(self.open.contains(&dir), "a listing through a closed fd");
            self.reads += 1;
            let mut filled = 0;
            loop {
                // `.` and `..` first, then each open number from where the
                // last call stopped, as procfs lists them.
                let (name, next) = match self.at {
                    -2 => (b".".to_vec(), -1),
                    -1 => (b"..".to_vec(), 0),
                    at => match self.open.range(at..).next() {
                        Some(&fd) => (fd.to_string().into_bytes(), fd + 1),
                        None => break,
                    },
                };
                let entry = dirent(&name);
                let Some(room) = buf.get_mut(filled..filled + entry.len()) else {
                    break;
                };
                room.copy_from_slice(&entry);
                filled += entry.len();
                self.at = next;
            }
            filled
        }

        fn table_size(&mut self) -> c_int {
            self.called();
            self.table_size.unwrap_or(self.limit)
        }

        fn close(&mut self, fd: c_int) {
            self.called();
            self.closed.push(fd);
            self.open.remove(&fd);
            self.null.remove(&fd);
        }

        fn open_null(&mut self) -> c_int {
            self.called();
            match self.lowest_free().filter(|_| self.has_null) {
                Some(fd) => {
                    self.open.insert(fd);
                    self.null.insert(fd);
                    fd
                }
                None => -1,
            }
        }

        fn exit(&mut self, status: c_int) {
            self.called();
            self.exited.get_or_insert(status);
        }
    }

    /// `closefrom_shim(ctx, 3)`, then the `/dev/null` loop: what was open
    /// from 3 up is closed, 0 to 2 are left as they were, and the one
    /// `/dev/null` the loop opened past 2 is closed again.
    #[test]
    fn every_descriptor_from_three_up_is_closed() {
        let mut t = Table::holding(&[0, 1, 2, 3, 4, 9, 255, 1000]);
        start_up(&mut t);
        assert_eq!(t.fds(), [0, 1, 2]);
        assert!(t.null.is_empty(), "no standard descriptor was replaced");
        assert_eq!(t.closed, [3], "the loop's own descriptor, and no other");
        assert_eq!(t.exited, None);
        // Nothing above 2 to begin with: the same end.
        let mut t = Table::holding(&[0, 1, 2]);
        start_up(&mut t);
        assert_eq!(
            (t.fds(), t.closed, t.exited),
            (vec![0, 1, 2], vec![3], None)
        );
    }

    /// The C's loop, case by case: each of 0, 1 and 2 that was closed is
    /// `/dev/null` afterwards and stays open, and nothing else is.
    #[test]
    fn a_closed_standard_descriptor_is_dev_null() {
        let cases: &[(&[c_int], &[c_int], &[c_int])] = &[
            // open before; `/dev/null` after; closed one by one.
            (&[1, 2], &[0], &[3]),
            (&[0, 2], &[1], &[3]),
            // 2 is the loop's end: it is kept, and nothing is closed.
            (&[0, 1], &[2], &[]),
            (&[2], &[0, 1], &[3]),
            (&[1], &[0, 2], &[]),
            (&[0], &[1, 2], &[]),
            (&[], &[0, 1, 2], &[]),
            // With an inherited descriptor in the way, closed first.
            (&[1, 2, 3, 7], &[0], &[3]),
            (&[3, 4, 5], &[0, 1, 2], &[]),
        ];
        for (before, null, closed) in cases {
            let mut t = Table::holding(before);
            start_up(&mut t);
            assert_eq!(t.fds(), [0, 1, 2], "{before:?}");
            assert_eq!(
                t.null.iter().copied().collect::<Vec<_>>(),
                *null,
                "{before:?}"
            );
            assert_eq!(t.closed, *closed, "{before:?}");
            assert_eq!(t.exited, None, "{before:?}");
        }
    }

    /// No `/dev/null`, or no descriptor left for it: the run ends there,
    /// status 1, and nothing more is done.
    #[test]
    fn no_dev_null_ends_the_run_with_status_one() {
        let mut t = Table::holding(&[0, 1, 2, 5]);
        t.has_null = false;
        start_up(&mut t);
        assert_eq!(t.exited, Some(1));
        assert_eq!(t.after_exit, 0, "nothing is called after the exit");
        assert_eq!(t.fds(), [0, 1, 2], "the close came first, as in the C");
        // A descriptor limit of three with all three open (`ulimit -n 3`).
        let mut t = Table::holding(&[0, 1, 2]);
        t.limit = 3;
        start_up(&mut t);
        assert_eq!((t.exited, t.after_exit), (Some(1), 0));
        // The same with stdin closed: 0 is opened, the next open fails.
        let mut t = Table::holding(&[1, 2]);
        t.limit = 3;
        start_up(&mut t);
        assert_eq!((t.exited, t.after_exit), (Some(1), 0));
        assert_eq!(t.fds(), [0, 1, 2]);
        // And a limit of four leaves room for the loop's own descriptor.
        let mut t = Table::holding(&[0, 1, 2]);
        t.limit = 4;
        start_up(&mut t);
        assert_eq!((t.exited, t.fds()), (None, vec![0, 1, 2]));
        // A table handed down full is no failure: the close comes first, as
        // in the C, and makes the room `/dev/null` needs.
        let mut t = Table::holding(&[0, 1, 2, 3]);
        t.limit = 4;
        start_up(&mut t);
        assert_eq!((t.exited, t.fds()), (None, vec![0, 1, 2]));
        let mut t = Table::holding(&[1, 2, 3, 4, 5]);
        t.limit = 6;
        start_up(&mut t);
        assert_eq!((t.exited, t.fds()), (None, vec![0, 1, 2]));
        assert_eq!(t.null.iter().copied().collect::<Vec<_>>(), [0]);
    }

    /// Without `close_range(2)` the descriptors `/proc/self/fd` lists are
    /// closed one by one, the listing's own last, and no number is swept.
    #[test]
    fn without_close_range_the_listed_descriptors_are_closed() {
        let mut t = Table::holding(&[0, 1, 2, 4, 9, 700]);
        t.has_close_range = false;
        start_up(&mut t);
        assert_eq!(t.fds(), [0, 1, 2]);
        // The listing was read through 3, the lowest free number; then the
        // `/dev/null` loop's descriptor, 3 again.
        assert_eq!(t.closed, [4, 9, 700, 3, 3]);
        assert_eq!(t.exited, None);
        // More descriptors than one `getdents64()` call gives: every one is
        // still closed, over several calls.
        let many: Vec<c_int> = (0..900).collect();
        let mut t = Table::holding(&many);
        t.has_close_range = false;
        close_from(&mut t, FIRST_CLOSED);
        assert_eq!(t.fds(), [0, 1, 2]);
        assert!(t.reads > 2, "{} reads", t.reads);
        // From another number: what is below it stays.
        let mut t = Table::holding(&[0, 1, 2, 3, 4, 5, 6]);
        t.has_close_range = false;
        close_from(&mut t, 5);
        assert_eq!(t.fds(), [0, 1, 2, 3, 4]);
    }

    /// With neither, every number below the descriptor limit is closed, at
    /// least to 53 and at most [`SWEEP_MAX`] of them.
    #[test]
    fn without_proc_every_number_below_the_limit_is_closed() {
        let mut t = Table::holding(&[0, 1, 2, 4, 9, 63]);
        t.has_close_range = false;
        t.has_proc = false;
        t.limit = 64;
        close_from(&mut t, FIRST_CLOSED);
        assert_eq!(t.fds(), [0, 1, 2]);
        assert_eq!(t.closed, (3..64).collect::<Vec<_>>());
        // A limit below 53: the C's `MaxFd` is 53 all the same.
        let mut t = Table::holding(&[0, 1, 2, 52, 53]);
        t.has_close_range = false;
        t.has_proc = false;
        t.table_size = Some(20);
        close_from(&mut t, FIRST_CLOSED);
        assert_eq!(t.fds(), [0, 1, 2, 53]);
        assert_eq!(t.closed.len(), 50);
        assert_eq!(sweep_end(20), 53);
        assert_eq!(sweep_end(-1), 53, "an unlimited table is -1 to the C");
        assert_eq!(sweep_end(54), 54);
        assert_eq!(sweep_end(1024), 1024);
        assert_eq!(sweep_end(SWEEP_MAX), SWEEP_MAX);
        assert_eq!(sweep_end(c_int::MAX), SWEEP_MAX);
        assert_eq!(sweep_end(1 << 30), 1 << 20);
        // The one call, where it is there, is all that is made.
        let mut t = Table::holding(&[0, 1, 2, 4]);
        close_from(&mut t, FIRST_CLOSED);
        assert_eq!((t.fds(), t.closed.len(), t.reads), (vec![0, 1, 2], 0, 0));
    }

    /// A listing's entries are read as the kernel lays them out, and
    /// nothing outside the bytes it wrote.
    #[test]
    fn a_listing_is_read_entry_by_entry() {
        let fds = |records: &[u8]| {
            let mut got = Vec::new();
            listed(records, &mut |fd| got.push(fd));
            got
        };
        let all = [
            dirent(b"."),
            dirent(b".."),
            dirent(b"0"),
            dirent(b"17"),
            dirent(b"2147483646"),
        ]
        .concat();
        assert_eq!(fds(&all), [0, 17, 2_147_483_646]);
        assert_eq!(fds(&[]), [] as [c_int; 0]);
        // Cut anywhere, it gives the whole entries before the cut and never
        // reads past it.
        for cut in 0..all.len() {
            let got = fds(&all[..cut]);
            assert!(
                [0, 17, 2_147_483_646].starts_with(&got),
                "cut at {cut}: {got:?}"
            );
        }
        // An entry that says it has no room for a name, or none at all,
        // ends the reading: no loop over a length of zero.
        let mut zero = dirent(b"5");
        zero[DIRENT_RECLEN].copy_from_slice(&0u16.to_ne_bytes());
        assert_eq!(fds(&[zero, dirent(b"6")].concat()), [] as [c_int; 0]);
        let mut short = dirent(b"5");
        short[DIRENT_RECLEN].copy_from_slice(&(DIRENT_NAME as u16).to_ne_bytes());
        assert_eq!(fds(&[short, dirent(b"6")].concat()), [] as [c_int; 0]);
        // One that says it is longer than what is left, too.
        let mut long = dirent(b"5");
        long[DIRENT_RECLEN].copy_from_slice(&u16::MAX.to_ne_bytes());
        assert_eq!(fds(&long), [] as [c_int; 0]);
        // A name with no NUL after it is read to the entry's end.
        let mut unterminated = dirent(b"1234");
        unterminated.truncate(DIRENT_NAME + 4);
        unterminated[DIRENT_RECLEN].copy_from_slice(&((DIRENT_NAME + 4) as u16).to_ne_bytes());
        assert_eq!(fds(&[unterminated, dirent(b"7")].concat()), [1234, 7]);
    }

    /// A descriptor's name is digits alone, and below `INT_MAX`.
    #[test]
    fn a_descriptor_name_is_digits_below_int_max() {
        assert_eq!(fd_named(b"0"), Some(0));
        assert_eq!(fd_named(b"3"), Some(3));
        assert_eq!(fd_named(b"007"), Some(7));
        assert_eq!(fd_named(b"1048576"), Some(1 << 20));
        assert_eq!(fd_named(b"2147483646"), Some(c_int::MAX - 1));
        for no in [
            &b""[..],
            b".",
            b"..",
            b"-1",
            b"+1",
            b" 1",
            b"1 ",
            b"1a",
            b"0x1",
            b"2147483647",
            b"2147483648",
            b"99999999999999999999",
            b"\xff",
        ] {
            assert_eq!(fd_named(no), None, "{no:?}");
        }
    }

    /// The real calls, on this process's own table: `/proc/self/fd` lists
    /// the descriptors this test opens, through `getdents64(2)`.
    #[test]
    #[cfg(target_os = "linux")]
    #[cfg_attr(miri, ignore = "miri has no getdents64 through syscall()")]
    fn the_kernels_listing_names_this_process_descriptors() {
        use std::os::fd::AsRawFd;
        let held: Vec<std::fs::File> = (0..5)
            .map(|_| std::fs::File::open("/dev/null").expect("open /dev/null"))
            .collect();
        // SAFETY: the one descriptor closed through it is the listing's
        // own, which was opened through it and is held in no object; the
        // other methods called here close nothing.
        let mut kernel = unsafe { Kernel::at_start() };
        let dir = kernel.open_fd_dir().expect("/proc/self/fd");
        let mut seen = Vec::new();
        let mut buf = [0u8; 256];
        loop {
            let filled = kernel.read_fd_dir(dir, &mut buf);
            if filled == 0 {
                break;
            }
            listed(&buf[..filled], &mut |fd| seen.push(fd));
        }
        kernel.close(dir);
        for f in &held {
            assert!(seen.contains(&f.as_raw_fd()), "{seen:?}");
        }
        assert!(seen.contains(&dir), "the listing lists itself: {seen:?}");
        assert!(seen.contains(&0) && seen.contains(&2), "{seen:?}");
        assert!(kernel.table_size() >= 3);
    }
}
