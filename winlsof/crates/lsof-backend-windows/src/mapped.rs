//! Memory-mapped *data* files → lsof `mem` entries, beyond the loaded modules
//! that `modules.rs` already covers.
//!
//! We walk the target's address space with `VirtualQueryEx`; for each committed
//! `MEM_MAPPED` region (`MEM_IMAGE` regions are loaded modules, already handled),
//! `GetMappedFileNameW` returns the backing file's NT device path, which we map
//! to a drive letter and de-duplicate (a file maps many pages). Needs
//! `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` — the same access as `cwd`.

use std::collections::HashSet;
use std::ffi::c_void;

use lsof_core::model::{AccessMode, FdType, FileType, OpenFile};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION};
use windows_sys::Win32::System::ProcessStatus::GetMappedFileNameW;
use windows_sys::Win32::System::Threading::OpenProcess;

use crate::handles::{device_to_dos, drive_of};
use crate::util::{wide_to_string, OwnedHandle};

const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
const PROCESS_VM_READ: u32 = 0x0010;
const MEM_COMMIT: u32 = 0x0000_1000;
const MEM_MAPPED: u32 = 0x0004_0000;
/// Safety bound on the region walk.
const MAX_REGIONS: usize = 200_000;

/// Return `mem` entries for the data files mapped into `pid`.
pub fn enumerate(pid: u32, dos_map: &[(String, String)]) -> Vec<OpenFile> {
    let mut out = Vec::new();
    // SAFETY: returns null on failure (rejected by OwnedHandle::new).
    let process = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) };
    let Some(process) = OwnedHandle::new(process) else {
        return out;
    };

    let mut seen: HashSet<String> = HashSet::new();
    let mut addr: usize = 0;
    for _ in 0..MAX_REGIONS {
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: mbi is correctly sized; VirtualQueryEx returns 0 past the end
        // of the address space.
        let n = unsafe {
            VirtualQueryEx(
                process.raw(),
                addr as *const c_void,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if n == 0 {
            break;
        }
        // `MEM_MAPPED` excludes `MEM_IMAGE` (modules) and `MEM_PRIVATE`.
        if mbi.State == MEM_COMMIT && mbi.Type == MEM_MAPPED {
            if let Some(nt) = mapped_name(process.raw(), mbi.BaseAddress) {
                let path = device_to_dos(&nt, dos_map);
                if seen.insert(path.clone()) {
                    out.push(OpenFile {
                        fd: FdType::Mem,
                        access: AccessMode::Read,
                        file_type: FileType::Regular,
                        device: drive_of(&path),
                        name: path,
                        size: None,
                        offset: None,
                        node: None,
                        socket: None,
                    });
                }
            }
        }
        // Advance to the next region; stop on overflow / non-progress.
        let region = mbi.RegionSize.max(1);
        match addr.checked_add(region) {
            Some(next) if next > addr => addr = next,
            _ => break,
        }
    }
    out
}

/// `GetMappedFileNameW` for the file backing a mapped region (NT device path).
fn mapped_name(process: HANDLE, base: *mut c_void) -> Option<String> {
    let mut buf = [0u16; 1024];
    // SAFETY: base is a region base address in `process`; buf/len are paired.
    let len = unsafe {
        GetMappedFileNameW(
            process,
            base as *const c_void,
            buf.as_mut_ptr(),
            buf.len() as u32,
        )
    };
    if len == 0 {
        return None;
    }
    let name = wide_to_string(&buf);
    (!name.is_empty()).then_some(name)
}
