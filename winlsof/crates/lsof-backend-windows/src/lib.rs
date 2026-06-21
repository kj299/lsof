//! `lsof-backend-windows` — the Windows "dialect" for winlsof.
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
mod handles;
#[cfg(windows)]
mod mapped;
#[cfg(windows)]
mod modules;
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
mod util;

#[cfg(windows)]
pub use backend::WindowsBackend;

/// Flush stdio and terminate the current process *now* with `code`.
///
/// winlsof's handle-name resolver abandons worker threads that block in an
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
