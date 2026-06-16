//! Process enumeration and owner (user) resolution.
//!
//! Replaces lsof's `/proc` PID scan with a Toolhelp snapshot, and the
//! `/proc/<pid>/status` uid lookup with the process token's user SID resolved
//! to an account name. Owner lookup uses the *minimum* access right
//! (`PROCESS_QUERY_LIMITED_INFORMATION`); when it's denied (another user's
//! process, no elevation) we simply leave USER blank rather than failing.

use std::ffi::c_void;

use lsof_core::model::Process;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Security::{
    GetTokenInformation, LookupAccountSidW, TokenUser, SID_NAME_USE, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::util::{wide_to_string, OwnedHandle};

/// Enumerate all processes visible to the caller, with PID, PPID, image name,
/// and (best-effort) owning user. Files are left empty; callers attach them.
pub fn enumerate() -> Vec<Process> {
    let mut out = Vec::new();

    // SAFETY: returns a snapshot handle or INVALID_HANDLE_VALUE (rejected below).
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    let Some(snapshot) = OwnedHandle::new(snapshot) else {
        return out;
    };

    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    // SAFETY: snapshot is valid; `entry.dwSize` is set as the API requires.
    let mut more = unsafe { Process32FirstW(snapshot.raw(), &mut entry) };
    while more != 0 {
        let pid = entry.th32ProcessID;
        out.push(Process {
            pid,
            ppid: Some(entry.th32ParentProcessID),
            command: wide_to_string(&entry.szExeFile),
            user: owner_user(pid),
            files: Vec::new(),
        });
        // SAFETY: same invariants as Process32FirstW.
        more = unsafe { Process32NextW(snapshot.raw(), &mut entry) };
    }
    out
}

/// Resolve a process's owning account as `DOMAIN\\user`, or `None` if it can't
/// be read with least-privilege access.
fn owner_user(pid: u32) -> Option<String> {
    // SAFETY: returns null on failure (rejected by OwnedHandle::new).
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    let process = OwnedHandle::new(process)?;

    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: process is valid; token adopted below.
    let ok = unsafe { OpenProcessToken(process.raw(), TOKEN_QUERY, &mut token) };
    if ok == 0 {
        return None;
    }
    let token = OwnedHandle::new(token)?;

    // First call sizes the TOKEN_USER buffer.
    let mut len = 0u32;
    // SAFETY: querying required length with a null buffer is the documented idiom.
    unsafe { GetTokenInformation(token.raw(), TokenUser, std::ptr::null_mut(), 0, &mut len) };
    if len == 0 {
        return None;
    }
    let mut buf = vec![0u8; len as usize];
    // SAFETY: buf is `len` bytes; receives a TOKEN_USER (with trailing SID).
    let ok = unsafe {
        GetTokenInformation(
            token.raw(),
            TokenUser,
            buf.as_mut_ptr() as *mut c_void,
            len,
            &mut len,
        )
    };
    if ok == 0 {
        return None;
    }
    // SAFETY: buf holds a valid TOKEN_USER written by the call above; the SID it
    // points into lives within `buf`, which outlives this borrow.
    let token_user = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    lookup_account(token_user.User.Sid)
}

/// Resolve a SID to `DOMAIN\\name` via `LookupAccountSidW`.
fn lookup_account(sid: *mut c_void) -> Option<String> {
    let mut name = [0u16; 256];
    let mut domain = [0u16; 256];
    let mut name_len = name.len() as u32;
    let mut domain_len = domain.len() as u32;
    let mut sid_use: SID_NAME_USE = 0;

    // SAFETY: sid points to a valid SID; buffers and their lengths are paired.
    let ok = unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            sid,
            name.as_mut_ptr(),
            &mut name_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut sid_use,
        )
    };
    if ok == 0 {
        return None;
    }
    let name = wide_to_string(&name);
    let domain = wide_to_string(&domain);
    if domain.is_empty() {
        Some(name)
    } else {
        Some(format!("{domain}\\{name}"))
    }
}
