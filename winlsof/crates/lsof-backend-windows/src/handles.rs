//! Phase 3 — system-wide open *file handle* enumeration (the core lsof
//! behavior; the analog of reading `/proc/<pid>/fd`).
//!
//! The planned implementation uses
//! `NtQuerySystemInformation(SystemExtendedHandleInformation)` to list every
//! handle with its owning PID, then, for handles we need to name,
//! `DuplicateHandle`s them into this process and calls `NtQueryObject` for the
//! object type and path — with name resolution run on a worker thread under a
//! timeout to avoid the well-known hangs on synchronous pipe/device handles, and
//! NT device paths (`\Device\HarddiskVolumeN\...`) mapped to drive letters via
//! `QueryDosDeviceW`.
//!
//! Reaching *other* processes' handles needs elevation, so per the
//! least-privilege model the caller passes whether we hold an elevated token;
//! the real implementation will wrap only the `DuplicateHandle` calls that need
//! it in a [`crate::privilege::PrivilegeGuard`], enabling `SeDebugPrivilege`
//! for the smallest possible window. Until this phase lands, it returns nothing
//! so processes and sockets still list correctly.

use lsof_core::model::OpenFile;

/// Returns the open file handles as `(owning_pid, OpenFile)` pairs. Currently a
/// no-op placeholder (Phase 3).
pub fn enumerate(_elevated: bool) -> Vec<(u32, OpenFile)> {
    Vec::new()
}
