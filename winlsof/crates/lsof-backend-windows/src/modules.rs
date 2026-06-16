//! Loaded-module enumeration → lsof `txt` (program image) and `mem`
//! (memory-mapped library) entries — the Windows replacement for the
//! executable/library mappings lsof reads from `/proc/<pid>/maps`.
//!
//! A Toolhelp module snapshot lists the image and every loaded DLL for a
//! process; the first entry is the executable (`txt`), the rest are mapped
//! libraries (`mem`). Snapshotting another process needs access to it, so
//! without elevation we see only our own — matching the least-privilege model.
//!
//! Snapshot creation can transiently fail with `ERROR_BAD_LENGTH` (the module
//! list changed mid-snapshot) or `ERROR_PARTIAL_COPY` (a 32-bit target from a
//! 64-bit caller); per the documented guidance we retry a few times.

use lsof_core::model::{AccessMode, FdType, FileType, OpenFile};
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};

use crate::util::{wide_to_string, OwnedHandle};

const ERROR_BAD_LENGTH: u32 = 24;
const ERROR_PARTIAL_COPY: u32 = 299;

/// Return the `txt` (image) and `mem` (library) entries for `pid`, retrying the
/// snapshot a few times on the transient failures documented above.
pub fn enumerate(pid: u32) -> Vec<OpenFile> {
    for _ in 0..5 {
        match try_enumerate(pid) {
            Ok(out) => return out,
            Err(retry) if retry => continue,
            Err(_) => return Vec::new(),
        }
    }
    Vec::new()
}

/// One attempt. `Err(true)` means "transient — retry"; `Err(false)` means give up.
fn try_enumerate(pid: u32) -> Result<Vec<OpenFile>, bool> {
    // SAFETY: returns a snapshot handle or INVALID_HANDLE_VALUE.
    let snapshot =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) };
    let Some(snapshot) = OwnedHandle::new(snapshot) else {
        return Err(transient(unsafe { GetLastError() }));
    };

    let mut entry: MODULEENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

    // SAFETY: snapshot is valid; `entry.dwSize` is set as the API requires.
    if unsafe { Module32FirstW(snapshot.raw(), &mut entry) } == 0 {
        return Err(transient(unsafe { GetLastError() }));
    }

    let mut out = Vec::new();
    let mut is_image = true;
    loop {
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
        if unsafe { Module32NextW(snapshot.raw(), &mut entry) } == 0 {
            break;
        }
    }
    Ok(out)
}

fn transient(err: u32) -> bool {
    err == ERROR_BAD_LENGTH || err == ERROR_PARTIAL_COPY
}
