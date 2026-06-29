//! Per-process thread enumeration — the data behind `-K` (task listing).
//!
//! Lsof's `-K` flag adds one row per thread under each in-scope process. On
//! Linux this comes from `/proc/<pid>/task/<tid>`; on Windows we get the
//! global thread set in one shot via `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)`
//! and filter by owning PID. The snapshot is cheap (no per-thread handle work,
//! no `OpenThread` calls), and importantly needs no elevation: a normal user
//! can enumerate every thread's TID and owning PID, which is all `-K` needs.
//!
//! We emit one [`OpenFile`] per thread:
//! - `fd`   = [`FdType::Task`] (renders as `task`)
//! - `file_type` = [`FileType::Thread`] (renders as `THRD`)
//! - `node` = TID as a decimal string
//! - `name` = empty (a follow-up could populate with the start address via
//!   `NtQueryInformationThread(ThreadQuerySetWin32StartAddress)`, but that
//!   needs `THREAD_QUERY_LIMITED_INFORMATION` and adds an unbounded per-
//!   thread call we'd have to defend against — out of scope for the MVP).

use std::collections::HashSet;

use lsof_core::model::{AccessMode, FdType, FileType, OpenFile};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};

use crate::util::OwnedHandle;

/// Enumerate all live threads as `(owning_pid, OpenFile)` pairs. When
/// `wanted` is `Some`, only threads of those PIDs are emitted — mirroring
/// the scoping pattern used by `handles::enumerate` so a focused query
/// (`lsof -p N -K`) doesn't drag a system-wide thread list through the
/// renderer.
pub fn enumerate(wanted: Option<&HashSet<u32>>) -> Vec<(u32, OpenFile)> {
    let mut out = Vec::new();

    // SAFETY: TH32CS_SNAPTHREAD + pid=0 takes a system-wide thread snapshot;
    // INVALID_HANDLE_VALUE on failure (caught by OwnedHandle::new).
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    let Some(snap) = OwnedHandle::new(snap) else {
        return out;
    };

    let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

    // SAFETY: snap is valid; entry.dwSize is set per the API contract.
    if unsafe { Thread32First(snap.raw(), &mut entry) } == 0 {
        return out;
    }

    loop {
        let pid = entry.th32OwnerProcessID;
        let tid = entry.th32ThreadID;

        if wanted.as_ref().is_none_or(|w| w.contains(&pid)) {
            out.push((
                pid,
                OpenFile {
                    fd: FdType::Task,
                    access: AccessMode::Unknown,
                    file_type: FileType::Thread,
                    name: String::new(),
                    device: None,
                    size: None,
                    offset: None,
                    node: Some(tid.to_string()),
                    links: None,
                    socket: None,
                },
            ));
        }

        // SAFETY: same invariants as Thread32First.
        if unsafe { Thread32Next(snap.raw(), &mut entry) } == 0 {
            break;
        }
    }
    out
}
