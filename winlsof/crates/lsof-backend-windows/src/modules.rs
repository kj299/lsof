//! Loaded-module enumeration → lsof `txt` (program image) and `mem`
//! (memory-mapped library) entries. This is the Windows replacement for the
//! executable/library mappings lsof reads from `/proc/<pid>/maps`.
//!
//! A Toolhelp module snapshot lists the image and every loaded DLL for a
//! process. The first entry is the executable itself (shown as `txt`); the rest
//! are mapped libraries (shown as `mem`). Snapshotting another process's modules
//! needs access to it, so without elevation we see only our own — matching the
//! least-privilege model. Failures (e.g. a WOW64 mismatch) just yield no rows.

use lsof_core::model::{AccessMode, FdType, FileType, OpenFile};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};

use crate::util::{wide_to_string, OwnedHandle};

/// Return the `txt` (image) and `mem` (library) entries for `pid`.
pub fn enumerate(pid: u32) -> Vec<OpenFile> {
    let mut out = Vec::new();

    // SAFETY: returns a snapshot handle or INVALID_HANDLE_VALUE (rejected below).
    let snapshot =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) };
    let Some(snapshot) = OwnedHandle::new(snapshot) else {
        return out;
    };

    let mut entry: MODULEENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

    // SAFETY: snapshot is valid; `entry.dwSize` is set as the API requires.
    let mut more = unsafe { Module32FirstW(snapshot.raw(), &mut entry) };
    let mut is_image = true;
    while more != 0 {
        let path = wide_to_string(&entry.szExePath);
        let device = if path.len() >= 2 && path.as_bytes()[1] == b':' {
            Some(path[..2].to_string())
        } else {
            None
        };
        out.push(OpenFile {
            fd: if is_image { FdType::Txt } else { FdType::Mem },
            access: AccessMode::Read,
            file_type: FileType::Regular,
            name: path,
            device,
            size: Some(entry.modBaseSize as u64),
            offset: None,
            node: None,
            socket: None,
        });
        is_image = false;
        // SAFETY: same invariants as Module32FirstW.
        more = unsafe { Module32NextW(snapshot.raw(), &mut entry) };
    }
    out
}
