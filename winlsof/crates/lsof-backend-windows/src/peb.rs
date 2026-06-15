//! Current-directory (`cwd`) resolution by reading another process's PEB.
//!
//! Windows has no `/proc/<pid>/cwd`; the working directory lives in the
//! process's PEB → `RTL_USER_PROCESS_PARAMETERS.CurrentDirectory`. We obtain the
//! PEB base via `NtQueryInformationProcess(ProcessBasicInformation)` and walk it
//! with `ReadProcessMemory`, using the documented 64-bit field offsets.
//!
//! This is strictly best-effort: it needs `PROCESS_QUERY_INFORMATION |
//! PROCESS_VM_READ` on the target (so an unelevated run resolves its own
//! processes), the offsets are for 64-bit processes, and any failure simply
//! yields no `cwd` row. (Windows has no per-process root directory, so there is
//! no `rtd` analog.)

use std::ffi::c_void;
use std::mem::{size_of, MaybeUninit};

use lsof_core::model::{AccessMode, FdType, FileType, OpenFile};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Threading::OpenProcess;

use crate::util::OwnedHandle;

const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
const PROCESS_VM_READ: u32 = 0x0010;

// 64-bit field offsets.
const PEB_PROCESS_PARAMETERS: usize = 0x20;
const RTLUPP_CURDIR_DOSPATH: usize = 0x38; // UNICODE_STRING: Length@+0, Buffer@+8
const UNICODE_STRING_BUFFER: usize = 0x08;

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

    let mut pbi: ProcessBasicInformation = unsafe { std::mem::zeroed() };
    // SAFETY: class 0 (ProcessBasicInformation) fits the provided buffer.
    let status = unsafe {
        NtQueryInformationProcess(
            process.raw(),
            0,
            &mut pbi as *mut _ as *mut c_void,
            size_of::<ProcessBasicInformation>() as u32,
            std::ptr::null_mut(),
        )
    };
    if status != 0 || pbi.peb_base_address.is_null() {
        return None;
    }

    let peb = pbi.peb_base_address as usize;
    let params: *mut c_void = read_pod(process.raw(), peb + PEB_PROCESS_PARAMETERS)?;
    if params.is_null() {
        return None;
    }
    let params = params as usize;

    let length: u16 = read_pod(process.raw(), params + RTLUPP_CURDIR_DOSPATH)?;
    let buffer: *mut u16 = read_pod(
        process.raw(),
        params + RTLUPP_CURDIR_DOSPATH + UNICODE_STRING_BUFFER,
    )?;
    if length == 0 || buffer.is_null() {
        return None;
    }

    let bytes = read_bytes(process.raw(), buffer as usize, length as usize)?;
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let mut path = String::from_utf16_lossy(&units);
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
        fd: FdType::Cwd,
        access: AccessMode::Read,
        file_type: FileType::Dir,
        name: path,
        device,
        size: None,
        offset: None,
        node: None,
        socket: None,
    })
}

/// Read a `Copy` value of type `T` from the target's address space.
fn read_pod<T: Copy>(handle: HANDLE, addr: usize) -> Option<T> {
    let mut value = MaybeUninit::<T>::uninit();
    let mut read = 0usize;
    // SAFETY: `value` has room for size_of::<T> bytes; the call writes at most
    // that many and reports the count.
    let ok = unsafe {
        ReadProcessMemory(
            handle,
            addr as *const c_void,
            value.as_mut_ptr() as *mut c_void,
            size_of::<T>(),
            &mut read,
        )
    };
    if ok == 0 || read != size_of::<T>() {
        return None;
    }
    // SAFETY: the full T was read.
    Some(unsafe { value.assume_init() })
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
