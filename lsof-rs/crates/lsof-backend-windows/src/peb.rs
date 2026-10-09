//! Current-directory (`cwd`) resolution by reading another process's PEB.
//!
//! Windows has no `/proc/<pid>/cwd`; the working directory lives in the
//! process's PEB → `RTL_USER_PROCESS_PARAMETERS.CurrentDirectory`. We get the
//! PEB base via `NtQueryInformationProcess` and walk it with `ReadProcessMemory`
//! at the documented field offsets. Both 64-bit targets and 32-bit (WOW64)
//! targets are handled — for WOW64 we use `ProcessWow64Information` to find the
//! 32-bit PEB and read 32-bit pointers/offsets.
//!
//! Best-effort: needs `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` on the
//! target, and any failure simply yields no `cwd` row. (Windows has no
//! per-process root directory, so there is no `rtd` analog.)
//!
//! The walk itself, which follows pointers the target wrote into its own PEB,
//! is `crate::peb_walk`, portable so that it is unit-tested and fuzzed on
//! Linux; this module holds the Win32 calls that feed it.

// No unchecked arithmetic here either: the addresses this module handles come
// from the kernel and the target process (see `peb_walk`).
#![deny(clippy::arithmetic_side_effects)]

use std::ffi::c_void;
use std::mem::size_of;

use lsof_core::model::{AccessMode, FdType, FileType, OpenFile};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Threading::OpenProcess;

use crate::peb_walk;
use crate::util::OwnedHandle;

const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
const PROCESS_VM_READ: u32 = 0x0010;

const PROCESS_BASIC_INFORMATION_CLASS: i32 = 0;
const PROCESS_WOW64_INFORMATION_CLASS: i32 = 26;

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryInformationProcess(
        handle: HANDLE,
        class: i32,
        info: *mut c_void,
        len: u32,
        ret_len: *mut u32,
    ) -> i32;
}

#[repr(C)]
#[allow(dead_code)] // only peb_base_address is read; the rest documents the layout.
struct ProcessBasicInformation {
    exit_status: i32,
    peb_base_address: *mut c_void,
    affinity_mask: usize,
    base_priority: i32,
    unique_process_id: usize,
    inherited_from_unique_process_id: usize,
}

/// Return the process's working directory as a `cwd` [`OpenFile`], if readable.
pub fn cwd(pid: u32) -> Option<OpenFile> {
    // SAFETY: returns null on failure (rejected by OwnedHandle::new).
    let process = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) };
    let process = OwnedHandle::new(process)?;

    // A non-zero result means a 32-bit (WOW64) process, giving its PEB32 address.
    let mut wow64_peb: usize = 0;
    // SAFETY: writes one pointer-sized value into `wow64_peb`.
    unsafe {
        NtQueryInformationProcess(
            process.raw(),
            PROCESS_WOW64_INFORMATION_CLASS,
            &mut wow64_peb as *mut _ as *mut c_void,
            size_of::<usize>() as u32,
            std::ptr::null_mut(),
        );
    }

    let handle = process.raw();
    let mut read = |addr, len| read_bytes(handle, addr, len);
    let raw = if wow64_peb != 0 {
        peb_walk::cwd32(wow64_peb, &mut read)?
    } else {
        peb_walk::cwd64(peb_base(handle)?, &mut read)?
    };

    let mut path = raw;
    // The stored cwd usually ends with a separator; trim it (but keep `C:\`).
    while path.ends_with('\\') && path.len() > 3 {
        path.pop();
    }
    let device = if path.len() >= 2 && path.as_bytes()[1] == b':' {
        Some(path[..2].to_string())
    } else {
        None
    };

    Some(OpenFile {
        rdev: None,
        fs_device: None,
        file_flags: None,
        lock: None,
        fd: FdType::Cwd,
        access: AccessMode::Read,
        file_type: FileType::Dir,
        name: path,
        device,
        size: None,
        offset: None,
        node: None,
        links: None,
        socket: None,
    })
}

/// 64-bit target: the PEB's address, from `ProcessBasicInformation`.
fn peb_base(handle: HANDLE) -> Option<usize> {
    // SAFETY: all-zero is a valid ProcessBasicInformation.
    let mut pbi: ProcessBasicInformation = unsafe { std::mem::zeroed() };
    // SAFETY: class 0 (ProcessBasicInformation) fits the provided buffer.
    let status = unsafe {
        NtQueryInformationProcess(
            handle,
            PROCESS_BASIC_INFORMATION_CLASS,
            &mut pbi as *mut _ as *mut c_void,
            size_of::<ProcessBasicInformation>() as u32,
            std::ptr::null_mut(),
        )
    };
    if status != 0 || pbi.peb_base_address.is_null() {
        return None;
    }
    Some(pbi.peb_base_address as usize)
}

/// Read `len` bytes from the target's address space.
fn read_bytes(handle: HANDLE, addr: usize, len: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let mut read = 0usize;
    // SAFETY: `buf` has `len` bytes; the call writes at most that many.
    let ok = unsafe {
        ReadProcessMemory(
            handle,
            addr as *const c_void,
            buf.as_mut_ptr() as *mut c_void,
            len,
            &mut read,
        )
    };
    if ok == 0 || read != len {
        return None;
    }
    Some(buf)
}
