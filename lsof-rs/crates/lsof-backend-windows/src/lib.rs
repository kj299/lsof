//! `lsof-backend-windows` — the Windows "dialect" for lsof-rs.
//!
//! Implements [`lsof_core::Backend`] using native Win32/NT APIs (Toolhelp for
//! processes, IP Helper for sockets, and — in Phase 3 — the NT handle table for
//! open files), all behind a strict least-privilege model (see [`privilege`]).
//!
//! Everything here is gated on `#[cfg(windows)]`; on other hosts the crate
//! compiles to an empty shell so the workspace builds and `lsof-core` stays
//! testable. The CLI selects this backend only when built for Windows.

#![cfg_attr(not(windows), allow(unused))]

#[cfg(windows)]
mod backend;
#[cfg(windows)]
mod etw;
#[cfg(windows)]
mod handles;
// NOT `#[cfg(windows)]`: these are pure string transforms over text Windows
// hands us, and the fuzz job that must cover them runs on Linux.
#[cfg(windows)]
mod mapped;
#[cfg(windows)]
mod modules;
mod names;
#[cfg(windows)]
mod peb;
#[cfg(windows)]
mod privilege;
#[cfg(windows)]
mod process;
#[cfg(windows)]
mod resolve;
#[cfg(windows)]
mod restart;
#[cfg(windows)]
mod sockets;
#[cfg(windows)]
mod tcpinfo;
#[cfg(windows)]
mod threads;
#[cfg(windows)]
mod util;

#[cfg(windows)]
pub use backend::WindowsBackend;

/// Switch the console output code page to UTF-8 (65001), so non-ASCII glyphs
/// in our user-facing strings (em-dashes, arrows in socket NAMEs) render
/// correctly. PowerShell 5.1 and cmd.exe default to Windows-1252 / OEM CP,
/// which would otherwise mangle the bytes into Latin-1 garbage like `â€”`.
/// Idempotent; called once near main entry.
#[cfg(windows)]
pub fn enable_utf8_console() {
    // SAFETY: SetConsoleOutputCP takes one UINT, returns BOOL. Failure is
    // harmless (the worst case is the previous behavior).
    unsafe {
        windows_sys::Win32::System::Console::SetConsoleOutputCP(65001);
    }
}

/// Flush stdio and terminate the current process *now* with `code`.
///
/// lsof-rs's handle-name resolver abandons worker threads that block in an
/// uninterruptible kernel call (`NtQueryObject` on a synchronous pipe/device).
/// Such a thread can keep orderly teardown — the runtime's exit path and
/// `ExitProcess`'s DLL-detach — from ever completing, so once output is written
/// the CLI calls this to exit hard rather than wait on it. `TerminateProcess`
/// skips DLL detach and lets the kernel cancel the stuck I/O during process
/// rundown. Buffers are flushed first because a hard terminate won't.
#[cfg(windows)]
pub fn exit_now(code: u32) -> ! {
    use std::io::Write;
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    // SAFETY: `GetCurrentProcess` is a pseudo-handle to this process;
    // `TerminateProcess` on it terminates immediately and does not return.
    unsafe {
        windows_sys::Win32::System::Threading::TerminateProcess(
            windows_sys::Win32::System::Threading::GetCurrentProcess(),
            code,
        );
    }
    // Fallback if TerminateProcess somehow returned (it won't for self).
    std::process::exit(code as i32)
}

/// The crate's text parsers, exposed for `cargo-fuzz`.
///
/// Unlike the Linux backend's `fuzz_api` this is **not** `cfg(windows)`: the
/// fuzz job runs on Linux, and the point of [`crate::names`] is that these
/// functions need no Windows to run. Gated on the feature alone so an ordinary
/// build still exposes nothing.
///
/// A panic here is a denial of service against the tool that is supposed to be
/// diagnosing one (porting-kit LESSONS #021), and every input below is a
/// string the operating system chose, not the user.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzz_api {
    pub use crate::names::{
        device_to_dos, drive_of, normalize_final, pipe_display, short_type_code, wide_to_string,
        win_type_to_filetype,
    };
}
