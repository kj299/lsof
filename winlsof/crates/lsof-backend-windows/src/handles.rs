//! Phase 3 — system-wide open *file handle* enumeration (the core lsof
//! behavior; the analog of reading `/proc/<pid>/fd`).
//!
//! Strategy (the approach Sysinternals `handle.exe` uses):
//! 1. `NtQuerySystemInformation(SystemExtendedHandleInformation)` lists every
//!    handle in the system with its owning PID, value, granted access, and
//!    object-type index.
//! 2. For each handle we open the owner with `PROCESS_DUP_HANDLE` (cached per
//!    PID), `DuplicateHandle` it into this process, and `NtQueryObject` for the
//!    object type — keeping only `File` objects (regular files, directories,
//!    named pipes), which are the lsof-relevant ones.
//! 3. We resolve the NT name (`\Device\HarddiskVolumeN\...`) and map it to a
//!    drive letter via `QueryDosDeviceW`, and read size / file-index via
//!    `GetFileInformationByHandle`.
//!
//! Hang avoidance: `NtQueryObject(ObjectNameInformation)` can block forever on
//! certain synchronous handles (some pipes/devices). We apply the well-known
//! heuristic of skipping the *name* query for handles whose granted access is
//! the value used by those handles (`0x0012019F`); the type query is safe.
//!
//! Least privilege: reaching other users' / protected processes' handles needs
//! `SeDebugPrivilege`. We enable it via [`PrivilegeGuard`] only for the duration
//! of this function, and only when already elevated — never globally. Unelevated
//! runs simply see fewer processes (the owner `OpenProcess` calls fail), exactly
//! like lsof without root.

use std::collections::HashMap;
use std::ffi::c_void;

use lsof_core::model::{AccessMode, FdType, FileType, OpenFile};
use windows_sys::Win32::Foundation::{DuplicateHandle, HANDLE};
use windows_sys::Win32::Storage::FileSystem::{
    GetFileInformationByHandle, GetLogicalDrives, QueryDosDeviceW, BY_HANDLE_FILE_INFORMATION,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcess};

use crate::privilege::PrivilegeGuard;
use crate::util::{wide_to_string, OwnedHandle};

// --- NT functions (declared directly against ntdll to avoid binding churn) ---

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQuerySystemInformation(class: i32, info: *mut c_void, len: u32, ret_len: *mut u32) -> i32;
    fn NtQueryObject(
        handle: HANDLE,
        class: i32,
        info: *mut c_void,
        len: u32,
        ret_len: *mut u32,
    ) -> i32;
}

const SYSTEM_EXTENDED_HANDLE_INFORMATION: i32 = 64;
const OBJECT_NAME_INFORMATION: i32 = 1;
const OBJECT_TYPE_INFORMATION: i32 = 2;

const STATUS_INFO_LENGTH_MISMATCH: i32 = -1073741820i32; // 0xC0000004
const STATUS_BUFFER_OVERFLOW: i32 = -2147483643i32; // 0x80000005
const STATUS_BUFFER_TOO_SMALL: i32 = -1073741789i32; // 0xC0000023

// Win32 access / option constants (declared locally to keep the import surface
// minimal and obvious).
const PROCESS_DUP_HANDLE: u32 = 0x0040;
const DUPLICATE_SAME_ACCESS: u32 = 0x0000_0002;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_READ_DATA: u32 = 0x0001;
const FILE_WRITE_DATA: u32 = 0x0002;
const FILE_APPEND_DATA: u32 = 0x0004;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;

/// Granted-access mask used by synchronous handles on which
/// `NtQueryObject(name)` can hang; we skip the name query for these.
const HANG_PRONE_ACCESS: u32 = 0x0012_019F;

// --- NT structures (repr(C), matching the documented layouts) ---

#[repr(C)]
#[allow(dead_code)] // FFI layout: some fields are read only via pointer casts.
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
#[allow(dead_code)] // FFI layout: not every field is consumed.
struct SystemHandleTableEntryInfoEx {
    object: *mut c_void,
    unique_process_id: usize,
    handle_value: usize,
    granted_access: u32,
    creator_back_trace_index: u16,
    object_type_index: u16,
    handle_attributes: u32,
    reserved: u32,
}

#[repr(C)]
#[allow(dead_code)] // FFI layout: `reserved` is unused padding.
struct SystemHandleInformationEx {
    number_of_handles: usize,
    reserved: usize,
    handles: [SystemHandleTableEntryInfoEx; 1],
}

/// Enumerate open file handles as `(owning_pid, OpenFile)` pairs.
pub fn enumerate(elevated: bool) -> Vec<(u32, OpenFile)> {
    // Least privilege: only request SeDebugPrivilege when already elevated, and
    // only for this function (the guard drops it on return).
    let _guard = if elevated {
        PrivilegeGuard::enable("SeDebugPrivilege")
    } else {
        None
    };

    let Some(buf) = query_all_handles() else {
        return Vec::new();
    };

    // SAFETY: the buffer is 8-byte aligned (Vec<u64>) and was filled by the API
    // with a SystemHandleInformationEx header followed by `number_of_handles`
    // entries.
    let info = unsafe { &*(buf.as_ptr() as *const SystemHandleInformationEx) };
    let count = info.number_of_handles;
    let entries = unsafe {
        std::slice::from_raw_parts(
            std::ptr::addr_of!(info.handles) as *const SystemHandleTableEntryInfoEx,
            count,
        )
    };

    // SAFETY: a pseudo-handle to the current process; must not be closed.
    let me = unsafe { GetCurrentProcess() };
    let dos_map = build_dos_map();
    let mut proc_cache: HashMap<u32, Option<OwnedHandle>> = HashMap::new();
    let mut out = Vec::new();

    for e in entries {
        let pid = e.unique_process_id as u32;
        if pid == 0 {
            continue;
        }
        let source = proc_cache.entry(pid).or_insert_with(|| open_for_dup(pid));
        let Some(source) = source.as_ref() else {
            continue;
        };
        let Some(dup) = duplicate(source.raw(), e.handle_value as HANDLE, me) else {
            continue;
        };
        // Keep only File objects (files, dirs, named pipes); skip events, keys,
        // unnamed socket/AFD handles, etc.
        if query_object_string(dup.raw(), OBJECT_TYPE_INFORMATION).as_deref() != Some("File") {
            continue;
        }
        if e.granted_access == HANG_PRONE_ACCESS {
            continue; // would risk hanging on the name query
        }
        let Some(nt_name) = query_object_string(dup.raw(), OBJECT_NAME_INFORMATION) else {
            continue; // unnamed (e.g. a socket/AFD handle) — listed via IP Helper
        };
        if nt_name.is_empty() {
            continue;
        }

        let d = describe(dup.raw(), &nt_name, &dos_map);
        out.push((
            pid,
            OpenFile {
                fd: FdType::Handle(e.handle_value as u64),
                access: access_from_granted(e.granted_access),
                file_type: d.file_type,
                name: d.name,
                device: d.device,
                size: d.size,
                offset: None,
                node: d.node,
                socket: None,
            },
        ));
    }
    out
}

/// Call `NtQuerySystemInformation` with a growing, 8-byte-aligned buffer.
fn query_all_handles() -> Option<Vec<u64>> {
    let mut cap: usize = 1 << 20; // 1 MiB to start
    for _ in 0..8 {
        let mut buf = vec![0u64; cap / 8];
        let mut ret = 0u32;
        // SAFETY: buf is `cap` bytes; the class writes a SystemHandleInformationEx.
        let status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_EXTENDED_HANDLE_INFORMATION,
                buf.as_mut_ptr() as *mut c_void,
                cap as u32,
                &mut ret,
            )
        };
        if status == 0 {
            return Some(buf);
        }
        if status == STATUS_INFO_LENGTH_MISMATCH {
            cap = (cap * 2).max(ret as usize + 4096);
            continue;
        }
        return None;
    }
    None
}

/// `NtQueryObject` into a growing buffer, returning the inner `UNICODE_STRING`
/// for the name/type information classes.
fn query_object_string(handle: HANDLE, class: i32) -> Option<String> {
    let mut cap: usize = 0x1000;
    for _ in 0..6 {
        let mut buf = vec![0u64; cap / 8];
        let mut ret = 0u32;
        // SAFETY: handle is a live duplicated handle; buf is `cap` bytes.
        let status = unsafe {
            NtQueryObject(
                handle,
                class,
                buf.as_mut_ptr() as *mut c_void,
                cap as u32,
                &mut ret,
            )
        };
        if status == 0 {
            return parse_unicode_string(&buf);
        }
        if status == STATUS_INFO_LENGTH_MISMATCH
            || status == STATUS_BUFFER_OVERFLOW
            || status == STATUS_BUFFER_TOO_SMALL
        {
            cap = (cap * 2).max(ret as usize + 256);
            continue;
        }
        return None;
    }
    None
}

/// Read a leading `UNICODE_STRING` (the layout of both OBJECT_NAME_INFORMATION
/// and OBJECT_TYPE_INFORMATION) from a query buffer.
fn parse_unicode_string(buf: &[u64]) -> Option<String> {
    // SAFETY: buf begins with a UNICODE_STRING written by NtQueryObject; its
    // `buffer` points within `buf`, which outlives this read.
    let us = unsafe { &*(buf.as_ptr() as *const UnicodeString) };
    if us.buffer.is_null() || us.length == 0 {
        return None;
    }
    let n = (us.length as usize) / 2;
    let chars = unsafe { std::slice::from_raw_parts(us.buffer, n) };
    Some(String::from_utf16_lossy(chars))
}

/// Open a process for handle duplication with the minimum required right.
fn open_for_dup(pid: u32) -> Option<OwnedHandle> {
    // SAFETY: returns null on failure (rejected by OwnedHandle::new).
    let h = unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, pid) };
    OwnedHandle::new(h)
}

/// Duplicate a handle from `source` into our process.
fn duplicate(source: HANDLE, handle: HANDLE, me: HANDLE) -> Option<OwnedHandle> {
    let mut dup: HANDLE = std::ptr::null_mut();
    // SAFETY: source/me are valid process handles; `handle` is a value within
    // source; DUPLICATE_SAME_ACCESS ignores the desired-access argument.
    let ok = unsafe { DuplicateHandle(source, handle, me, &mut dup, 0, 0, DUPLICATE_SAME_ACCESS) };
    if ok == 0 {
        None
    } else {
        OwnedHandle::new(dup)
    }
}

struct Described {
    file_type: FileType,
    name: String,
    device: Option<String>,
    node: Option<String>,
    size: Option<u64>,
}

/// Classify a File handle and fill in name/device/size/node.
fn describe(handle: HANDLE, nt_name: &str, dos_map: &[(String, String)]) -> Described {
    let is_pipe = nt_name.starts_with("\\Device\\NamedPipe");
    let display = device_to_dos(nt_name, dos_map);
    let device = if display.len() >= 2 && display.as_bytes()[1] == b':' {
        Some(display[..2].to_string())
    } else {
        None
    };

    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: handle is a live File handle; info is sized correctly.
    let have = unsafe { GetFileInformationByHandle(handle, &mut info) } != 0;

    if have {
        let is_dir = info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        let size = ((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64;
        let node = ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64;
        Described {
            file_type: if is_dir {
                FileType::Dir
            } else {
                FileType::Regular
            },
            name: display,
            device,
            node: Some(node.to_string()),
            size: if is_dir { None } else { Some(size) },
        }
    } else if is_pipe {
        Described {
            file_type: FileType::Pipe,
            name: display,
            device: None,
            node: None,
            size: None,
        }
    } else {
        // A named device we couldn't stat (console, etc.) — treat as character.
        Described {
            file_type: FileType::Chr,
            name: display,
            device,
            node: None,
            size: None,
        }
    }
}

/// Build the `\Device\...` → drive-letter map from the live volume set.
fn build_dos_map() -> Vec<(String, String)> {
    let mut map = Vec::new();
    // SAFETY: no arguments; returns a bitmask of present drive letters.
    let drives = unsafe { GetLogicalDrives() };
    for i in 0..26u32 {
        if drives & (1 << i) == 0 {
            continue;
        }
        let letter = (b'A' + i as u8) as char;
        let dos = format!("{letter}:");
        let devname: Vec<u16> = format!("{dos}\0").encode_utf16().collect();
        let mut target = [0u16; 512];
        // SAFETY: devname is NUL-terminated; target/len are paired.
        let len =
            unsafe { QueryDosDeviceW(devname.as_ptr(), target.as_mut_ptr(), target.len() as u32) };
        if len == 0 {
            continue;
        }
        let t = wide_to_string(&target);
        if !t.is_empty() {
            map.push((dos, t));
        }
    }
    map
}

/// Replace a `\Device\HarddiskVolumeN` prefix with its drive letter, requiring
/// the match to fall on a path boundary. Returns the input unchanged if no
/// mapping applies.
fn device_to_dos(nt_name: &str, dos_map: &[(String, String)]) -> String {
    for (dos, dev) in dos_map {
        if let Some(rest) = nt_name.strip_prefix(dev.as_str()) {
            if rest.is_empty() || rest.starts_with('\\') {
                return format!("{dos}{rest}");
            }
        }
    }
    nt_name.to_string()
}

/// Derive the lsof access letter from a granted-access mask.
fn access_from_granted(granted: u32) -> AccessMode {
    let read = granted & (FILE_READ_DATA | GENERIC_READ) != 0;
    let write = granted & (FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE) != 0;
    match (read, write) {
        (true, true) => AccessMode::ReadWrite,
        (true, false) => AccessMode::Read,
        (false, true) => AccessMode::Write,
        (false, false) => AccessMode::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map() -> Vec<(String, String)> {
        vec![
            ("C:".to_string(), "\\Device\\HarddiskVolume3".to_string()),
            ("D:".to_string(), "\\Device\\HarddiskVolume33".to_string()),
        ]
    }

    #[test]
    fn maps_device_path_to_drive() {
        assert_eq!(
            device_to_dos("\\Device\\HarddiskVolume3\\Users\\me\\f.txt", &map()),
            "C:\\Users\\me\\f.txt"
        );
    }

    #[test]
    fn respects_path_boundary() {
        // Volume3 must not swallow the longer Volume33.
        assert_eq!(
            device_to_dos("\\Device\\HarddiskVolume33\\x", &map()),
            "D:\\x"
        );
    }

    #[test]
    fn unmapped_device_passes_through() {
        let s = "\\Device\\NamedPipe\\foo";
        assert_eq!(device_to_dos(s, &map()), s);
    }

    #[test]
    fn access_letters() {
        assert_eq!(access_from_granted(FILE_READ_DATA), AccessMode::Read);
        assert_eq!(access_from_granted(FILE_WRITE_DATA), AccessMode::Write);
        assert_eq!(
            access_from_granted(FILE_READ_DATA | FILE_WRITE_DATA),
            AccessMode::ReadWrite
        );
        assert_eq!(access_from_granted(0), AccessMode::Unknown);
    }
}
