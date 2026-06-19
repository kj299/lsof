//! Phase 3 — system-wide open *file handle* enumeration (the core lsof
//! behavior; the analog of reading `/proc/<pid>/fd`).
//!
//! Strategy (the approach Sysinternals `handle.exe` uses):
//! 1. `NtQuerySystemInformation(SystemExtendedHandleInformation)` lists every
//!    handle in the system with its owning PID, value, granted access, and
//!    object-type index.
//! 2. We keep only `File` objects (regular files, directories, named pipes,
//!    char devices, sockets) — the lsof-relevant ones — by matching the entry's
//!    object-type index against the index "File" uses this boot (learned once
//!    from a NUL-device probe). This deliberately avoids a per-handle
//!    `NtQueryObject(ObjectTypeInformation)`, which can block forever on
//!    synchronous handles (console/pipe/device) and would hang enumeration. For
//!    the survivors we open the owner with `PROCESS_DUP_HANDLE` (cached per PID)
//!    and `DuplicateHandle` the handle into this process.
//! 3. We resolve the NT name (`\Device\HarddiskVolumeN\...`) and map it to a
//!    drive letter via `QueryDosDeviceW`, and read size / file-index via
//!    `GetFileInformationByHandle`.
//!
//! Names: disk files use `GetFinalPathNameByHandleW` (robust and hang-free,
//! yielding a clean DOS path); char devices, named pipes, and the disk fallback
//! resolve via `NtQueryObject(ObjectNameInformation)`, which can block forever on
//! synchronous handles — so *every* name query runs on a worker thread under a
//! timeout (a hung query is abandoned, never allowed to freeze enumeration).
//! Only true socket/AFD handles are dropped (IP Helper lists those); every other
//! File handle is emitted, with a placeholder name if it can't be resolved.
//!
//! Least privilege: reaching other users' / protected processes' handles needs
//! `SeDebugPrivilege`. We enable it via [`PrivilegeGuard`] only for the duration
//! of this function, and only when already elevated — never globally. Unelevated
//! runs simply see fewer processes (the owner `OpenProcess` calls fail), exactly
//! like lsof without root.

use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::time::Duration;

use lsof_core::model::{AccessMode, FdType, FileType, OpenFile};
use windows_sys::Win32::Foundation::{CloseHandle, DuplicateHandle, HANDLE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetFileInformationByHandle, GetFileType, GetFinalPathNameByHandleW,
    GetLogicalDrives, QueryDosDeviceW, BY_HANDLE_FILE_INFORMATION,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetCurrentProcessId, OpenProcess};

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
    fn NtQueryInformationFile(
        handle: HANDLE,
        io_status: *mut IoStatusBlock,
        info: *mut c_void,
        len: u32,
        class: i32,
    ) -> i32;
}

const SYSTEM_EXTENDED_HANDLE_INFORMATION: i32 = 64;
const OBJECT_NAME_INFORMATION: i32 = 1;
const OBJECT_TYPE_INFORMATION: i32 = 2;
const FILE_POSITION_INFORMATION_CLASS: i32 = 14;

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

// CreateFileW arguments for the NUL-device type probe.
const OPEN_EXISTING: u32 = 3;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_SHARE_DELETE: u32 = 0x0000_0004;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;

// GetFileType return values.
const FILE_TYPE_DISK: u32 = 0x0001;
const FILE_TYPE_CHAR: u32 = 0x0002;
const FILE_TYPE_PIPE: u32 = 0x0003;

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

#[repr(C)]
#[allow(dead_code)] // FFI layout: only `Information` matters; the union is sized.
struct IoStatusBlock {
    status_or_pointer: usize,
    information: usize,
}

/// Enumerate open file handles as `(owning_pid, OpenFile)` pairs. When `wanted`
/// is `Some`, only handles owned by those PIDs are inspected — so the expensive
/// per-handle duplication is skipped for processes the user didn't ask about.
/// With `verbose`, the count of processes that couldn't be opened is reported.
pub fn enumerate(
    elevated: bool,
    wanted: Option<&HashSet<u32>>,
    verbose: bool,
) -> Vec<(u32, OpenFile)> {
    // Least privilege: only request SeDebugPrivilege when already elevated, and
    // only for this function (the guard drops it on return).
    let _guard = if elevated {
        PrivilegeGuard::enable("SeDebugPrivilege")
    } else {
        None
    };

    // Open a throwaway NUL handle *before* snapshotting so it appears in the
    // table; its type index tells us which index means "File", letting us
    // classify handles without a per-handle NtQueryObject(type) — that call can
    // block forever on synchronous handles (console/pipe/device), which is what
    // made `lsof -p`/`-t` hang.
    let probe = nul_probe();

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
    let file_index = probe
        .as_ref()
        .and_then(|p| file_type_index(entries, p.raw()));

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
        // Scope to the requested processes before the costly duplicate.
        if let Some(w) = wanted {
            if !w.contains(&pid) {
                continue;
            }
        }
        // Keep only File objects (disk files, dirs, named pipes, char devices,
        // and sockets); other object types (keys, events, …) aren't lsof-like.
        // The table's type index does this without a hang-prone type query.
        if let Some(fi) = file_index {
            if e.object_type_index != fi {
                continue;
            }
        }
        let source = proc_cache.entry(pid).or_insert_with(|| open_for_dup(pid));
        let Some(source) = source.as_ref() else {
            continue;
        };
        let Some(dup) = duplicate(source.raw(), e.handle_value as HANDLE, me) else {
            continue;
        };
        // Fallback only when the File index is unknown (the NUL probe failed):
        // confirm the type directly. This is the lone remaining main-thread type
        // query, and it's effectively unreachable in practice.
        if file_index.is_none()
            && query_object_string(dup.raw(), OBJECT_TYPE_INFORMATION).as_deref() != Some("File")
        {
            continue;
        }
        let Some(d) = describe(
            source.raw(),
            e.handle_value as HANDLE,
            me,
            dup.raw(),
            &dos_map,
        ) else {
            continue; // a socket/AFD handle — listed via IP Helper
        };
        out.push((
            pid,
            OpenFile {
                fd: FdType::Handle(e.handle_value as u64),
                access: access_from_granted(e.granted_access),
                file_type: d.file_type,
                name: d.name,
                device: d.device,
                size: d.size,
                offset: d.offset,
                node: d.node,
                socket: None,
            },
        ));
    }

    if verbose {
        let inaccessible = proc_cache.values().filter(|v| v.is_none()).count();
        if inaccessible > 0 {
            eprintln!(
                "lsof: {inaccessible} process(es) not accessible (try running as Administrator)"
            );
        }
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

/// Open a throwaway handle to the NUL device — a guaranteed File-type object
/// that never blocks — used only to learn the "File" object-type index.
fn nul_probe() -> Option<OwnedHandle> {
    let name: Vec<u16> = "NUL\0".encode_utf16().collect();
    // SAFETY: `name` is NUL-terminated; a plain read-only open of the NUL device.
    let h = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    OwnedHandle::new(h)
}

/// The `ObjectTypeIndex` that "File" objects use this boot session, read from the
/// NUL probe's entry in the handle snapshot. Every file-system object — disk
/// files, directories, named pipes, console/char devices, AFD sockets — shares
/// this one index, so it classifies handles without ever calling `NtQueryObject`.
fn file_type_index(entries: &[SystemHandleTableEntryInfoEx], probe: HANDLE) -> Option<u16> {
    // SAFETY: no arguments; returns this process's PID.
    let me_pid = unsafe { GetCurrentProcessId() };
    let probe_val = probe as usize;
    entries
        .iter()
        .find(|e| e.unique_process_id as u32 == me_pid && e.handle_value == probe_val)
        .map(|e| e.object_type_index)
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

/// Resolve a handle's object name on a worker thread, giving up after
/// `timeout`. Takes ownership of `handle`: the worker closes it, so on a hang
/// the handle (and thread) are abandoned rather than stalling enumeration.
fn name_with_timeout(handle: HANDLE, timeout: Duration) -> Option<String> {
    let handle_value = handle as usize;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let handle = handle_value as HANDLE;
        let name = query_object_string(handle, OBJECT_NAME_INFORMATION);
        // SAFETY: this thread is the sole owner of `handle`; close it once.
        unsafe { CloseHandle(handle) };
        let _ = tx.send(name);
    });
    rx.recv_timeout(timeout).unwrap_or(None)
}

/// Resolve a handle's object name on a worker thread with a timeout, because
/// `NtQueryObject(name)` can block forever on synchronous handles (pipes, some
/// devices). Duplicates a dedicated handle the worker owns and closes, so a hung
/// query is abandoned rather than freezing enumeration.
fn timed_object_name(source: HANDLE, handle_value: HANDLE, me: HANDLE) -> Option<String> {
    let worker = duplicate(source, handle_value, me)?;
    name_with_timeout(worker.into_raw(), Duration::from_millis(100))
}

struct Described {
    file_type: FileType,
    name: String,
    device: Option<String>,
    node: Option<String>,
    size: Option<u64>,
    offset: Option<u64>,
}

/// Classify a File-typed handle by its file type and fill in name/size/node.
/// Returns `None` only for socket/AFD handles (which IP Helper enumerates).
fn describe(
    source: HANDLE,
    handle_value: HANDLE,
    me: HANDLE,
    dup: HANDLE,
    dos_map: &[(String, String)],
) -> Option<Described> {
    // SAFETY: dup is a live File handle.
    match unsafe { GetFileType(dup) } {
        FILE_TYPE_DISK => {
            // Robust, hang-free path for disk files; fall back to the NT name.
            let name = final_path(dup)
                .or_else(|| {
                    timed_object_name(source, handle_value, me).map(|n| device_to_dos(&n, dos_map))
                })
                .unwrap_or_else(|| "(unnamed file)".to_string());
            let (file_type, node, size) = disk_details(dup);
            Some(Described {
                file_type,
                device: drive_of(&name),
                name,
                node,
                size,
                offset: file_offset(dup),
            })
        }
        FILE_TYPE_PIPE => {
            // A named pipe or a socket. The name query can hang on a synchronous
            // handle, so it always goes through the timeout-bounded worker.
            match timed_object_name(source, handle_value, me) {
                Some(n) if n.starts_with("\\Device\\NamedPipe") => Some(Described {
                    file_type: FileType::Pipe,
                    name: pipe_display(&n),
                    device: None,
                    node: None,
                    size: None,
                    offset: None,
                }),
                // Sockets (\Device\Afd) and unnamed pipes: IP Helper covers
                // sockets, so skip rather than emit a nameless row.
                _ => None,
            }
        }
        FILE_TYPE_CHAR => {
            let name = timed_object_name(source, handle_value, me)
                .map(|n| device_to_dos(&n, dos_map))
                .unwrap_or_else(|| "(character device)".to_string());
            Some(Described {
                file_type: FileType::Chr,
                name,
                device: None,
                node: None,
                size: None,
                offset: None,
            })
        }
        _ => {
            // Unknown file type: best-effort name, else drop.
            let name = device_to_dos(&timed_object_name(source, handle_value, me)?, dos_map);
            Some(Described {
                device: drive_of(&name),
                name,
                file_type: FileType::Unknown,
                node: None,
                size: None,
                offset: None,
            })
        }
    }
}

/// The current file offset of a disk handle, via `NtQueryInformationFile`.
/// The duplicate shares the owner's file object, so this is the live position.
fn file_offset(dup: HANDLE) -> Option<u64> {
    let mut iosb: IoStatusBlock = unsafe { std::mem::zeroed() };
    let mut pos: i64 = 0;
    // SAFETY: writes a FILE_POSITION_INFORMATION (a single i64) into `pos`.
    let status = unsafe {
        NtQueryInformationFile(
            dup,
            &mut iosb,
            &mut pos as *mut _ as *mut c_void,
            8,
            FILE_POSITION_INFORMATION_CLASS,
        )
    };
    if status != 0 || pos < 0 {
        None
    } else {
        Some(pos as u64)
    }
}

/// The drive-letter `DEVICE` prefix of a `X:\...` path, if present.
pub(crate) fn drive_of(path: &str) -> Option<String> {
    if path.len() >= 2 && path.as_bytes()[1] == b':' {
        Some(path[..2].to_string())
    } else {
        None
    }
}

/// `GetFinalPathNameByHandleW` → a clean DOS path (drops the `\\?\` prefix).
fn final_path(dup: HANDLE) -> Option<String> {
    let mut buf = vec![0u16; 1024];
    // SAFETY: buf/len are paired; returns the char count, the required length if
    // the buffer is too small, or 0 on failure.
    let mut len = unsafe { GetFinalPathNameByHandleW(dup, buf.as_mut_ptr(), buf.len() as u32, 0) };
    if len == 0 {
        return None;
    }
    if len as usize >= buf.len() {
        buf = vec![0u16; len as usize + 1];
        // SAFETY: as above, with a buffer grown to the reported size.
        len = unsafe { GetFinalPathNameByHandleW(dup, buf.as_mut_ptr(), buf.len() as u32, 0) };
        if len == 0 || len as usize >= buf.len() {
            return None;
        }
    }
    Some(normalize_final(&wide_to_string(&buf)))
}

/// Strip the `\\?\` / `\\?\UNC\` prefixes from a final-path string.
fn normalize_final(s: &str) -> String {
    if let Some(rest) = s.strip_prefix("\\\\?\\UNC\\") {
        format!("\\\\{rest}")
    } else if let Some(rest) = s.strip_prefix("\\\\?\\") {
        rest.to_string()
    } else {
        s.to_string()
    }
}

/// `\Device\NamedPipe\foo` → `\\.\pipe\foo`.
fn pipe_display(nt_name: &str) -> String {
    match nt_name.strip_prefix("\\Device\\NamedPipe") {
        Some(rest) => format!("\\\\.\\pipe{rest}"),
        None => nt_name.to_string(),
    }
}

/// Read dir/size/file-index for a disk file via `GetFileInformationByHandle`.
fn disk_details(dup: HANDLE) -> (FileType, Option<String>, Option<u64>) {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: dup is a live disk handle; info is sized correctly.
    if unsafe { GetFileInformationByHandle(dup, &mut info) } == 0 {
        return (FileType::Regular, None, None);
    }
    let is_dir = info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    let node = ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64;
    let size = ((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64;
    (
        if is_dir {
            FileType::Dir
        } else {
            FileType::Regular
        },
        Some(node.to_string()),
        if is_dir { None } else { Some(size) },
    )
}

/// Build the `\Device\...` → drive-letter map from the live volume set.
pub(crate) fn build_dos_map() -> Vec<(String, String)> {
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
pub(crate) fn device_to_dos(nt_name: &str, dos_map: &[(String, String)]) -> String {
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

    #[test]
    fn normalizes_final_paths() {
        assert_eq!(normalize_final("\\\\?\\C:\\a\\b.txt"), "C:\\a\\b.txt");
        assert_eq!(
            normalize_final("\\\\?\\UNC\\srv\\share\\f"),
            "\\\\srv\\share\\f"
        );
        assert_eq!(normalize_final("C:\\plain"), "C:\\plain");
    }

    #[test]
    fn pipe_display_names() {
        assert_eq!(pipe_display("\\Device\\NamedPipe\\foo"), "\\\\.\\pipe\\foo");
    }

    #[test]
    fn drive_prefix() {
        assert_eq!(drive_of("C:\\x"), Some("C:".to_string()));
        assert_eq!(drive_of("\\\\srv\\share"), None);
    }
}
