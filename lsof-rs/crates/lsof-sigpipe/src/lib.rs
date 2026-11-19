//! What `SIGPIPE` was when lsof-rs started, and putting it back.
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
//! # Safety
//!
//! Three `unsafe` sites, each with a `SAFETY` comment: the constructor's
//! `link_section` static (an attribute `#![forbid(unsafe_code)]` refuses,
//! which is why this is a crate of its own: lsof-core, lsof-cli and
//! lsof-backend-linux keep it), its query-only `sigaction()`, and
//! `restore_default`'s `signal()`. None writes memory but a local of its
//! own. Off Linux and FreeBSD there is no constructor, nothing is known,
//! and nothing is changed.
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

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
extern "C" fn capture() {
    // miri runs constructors and has no `sigaction()`: nothing is known.
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
}

/// The constructor: glibc (and FreeBSD's rtld) call each function in
/// `.init_array` before `main`, and before the Rust runtime's own
/// initialisation, which sets `SIGPIPE` to `SIG_IGN`. glibc passes `argc`,
/// `argv` and `envp`, which a function of no parameters ignores under the C
/// calling convention (the arguments are in registers the callee need not
/// read; uutils' constructor is the same `extern "C" fn()`), and which the
/// ELF ABI calls with none. `#[used]` keeps the static; the binary calls
/// [`inherited_ignored`], in this same object, so the linker takes it in.
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
#[used]
// SAFETY: the section holds pointers to functions the C runtime calls
// before `main`: `capture` is an `extern "C" fn()`, the type the ELF ABI
// gives `.init_array` entries (glibc's extra arguments go unread), touches
// no Rust runtime state but an atomic, and cannot unwind (it calls nothing
// that panics). The static is one pointer, aligned as the section's entries
// are.
#[unsafe(link_section = ".init_array")]
static CAPTURE: extern "C" fn() = capture;

#[cfg(test)]
mod tests {
    use super::*;

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
}
