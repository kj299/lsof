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
mod modules;
#[cfg(windows)]
mod privilege;
#[cfg(windows)]
mod process;
#[cfg(windows)]
mod sockets;
#[cfg(windows)]
mod util;

#[cfg(windows)]
pub use backend::WindowsBackend;
