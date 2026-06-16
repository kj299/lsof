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

use std::ffi::c_void;
use std::mem::{size_of, MaybeUninit};

use lsof_core::model::{AccessMode, FdType, FileType, OpenFile};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Threading::OpenProcess;

use crate::util::OwnedHandle;

const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
const PROCESS_VM_READ: u32 = 0x0010;

const PROCESS_BASIC_INFORMATION_CLASS: i32 = 0;
const PROCESS_WOW64_INFORMATION_CLASS: i32 = 26;

// 64-bit offsets: PEB.ProcessParameters, then CurrentDirectory.DosPath
// (UNICODE_STRING: Length @ +0, 8-byte Buffer pointer @ +8).
const PEB64_PARAMS: usize = 0x20;
const RTLUPP64_CURDIR: usize = 0x38;
const US64_BUFFER: usize = 0x08;

// 32-bit (WOW64) offsets: PEB32.ProcessParameters, then CurrentDirectory.DosPath
// (UNICODE_STRING32: Length @ +0, 4-byte Buffer pointer @ +4).
const PEB32_PARAMS: usize = 0x10;
const RTLUPP32_CURDIR: usize = 0x24;
const US32_BUFFER: usize = 0x04;

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

    let raw = if wow64_peb != 0 {
        read_cwd32(process.raw(), wow64_peb)?
    } else {
        read_cwd64(process.raw())?
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

/// 64-bit target: PEB → ProcessParameters → CurrentDirectory.DosPath.
fn read_cwd64(handle: HANDLE) -> Option<String> {
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
    let peb = pbi.peb_base_address as usize;
    let params: u64 = read_pod(handle, peb + PEB64_PARAMS)?;
    if params == 0 {
        return None;
    }
    let params = params as usize;
    let length: u16 = read_pod(handle, params + RTLUPP64_CURDIR)?;
    let buffer: u64 = read_pod(handle, params + RTLUPP64_CURDIR + US64_BUFFER)?;
    read_wide(handle, buffer as usize, length)
}

/// 32-bit (WOW64) target: PEB32 → ProcessParameters32 → CurrentDirectory.
fn read_cwd32(handle: HANDLE, peb32: usize) -> Option<String> {
    let params: u32 = read_pod(handle, peb32 + PEB32_PARAMS)?;
    if params == 0 {
        return None;
    }
    let params = params as usize;
    let length: u16 = read_pod(handle, params + RTLUPP32_CURDIR)?;
    let buffer: u32 = read_pod(handle, params + RTLUPP32_CURDIR + US32_BUFFER)?;
    read_wide(handle, buffer as usize, length)
}

/// Read `length` bytes of UTF-16 at `addr` and decode to a `String`.
fn read_wide(handle: HANDLE, addr: usize, length: u16) -> Option<String> {
    if length == 0 || addr == 0 {
        return None;
    }
    let bytes = read_bytes(handle, addr, length as usize)?;
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    Some(String::from_utf16_lossy(&units))
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
