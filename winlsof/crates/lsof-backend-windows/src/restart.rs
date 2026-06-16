//! Restart Manager named-file lookups: given a path, find the processes that
//! currently have it open. This is the supported, *unprivileged* way to answer
//! lsof's "who has this file open" query — a bare path argument or `+D`/`+d` —
//! complementing the handle table (which needs elevation for other users).

use std::collections::HashMap;

use lsof_core::model::{AccessMode, FdType, FileType, OpenFile, Process};
use windows_sys::Win32::System::RestartManager::{
    RmEndSession, RmGetList, RmRegisterResources, RmStartSession, CCH_RM_SESSION_KEY,
    RM_PROCESS_INFO,
};

/// Return the PIDs of processes holding `path` open (best-effort).
fn processes_using(path: &str) -> Vec<u32> {
    let mut session = 0u32;
    let mut key = vec![0u16; CCH_RM_SESSION_KEY as usize + 1];
    // SAFETY: `key` is a writable buffer of the documented size.
    if unsafe { RmStartSession(&mut session, 0, key.as_mut_ptr()) } != 0 {
        return Vec::new();
    }

    let wpath: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let files = [wpath.as_ptr()];
    // SAFETY: registering one file resource by NUL-terminated wide path.
    let reg = unsafe {
        RmRegisterResources(
            session,
            1,
            files.as_ptr(),
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
        )
    };
    let pids = if reg == 0 {
        get_list(session)
    } else {
        Vec::new()
    };
    // SAFETY: `session` was started successfully above.
    unsafe { RmEndSession(session) };
    pids
}

/// Two-call `RmGetList`: size the array, then fetch the affected processes.
fn get_list(session: u32) -> Vec<u32> {
    let mut needed = 0u32;
    let mut have = 0u32;
    let mut reasons = 0u32;
    // SAFETY: a null array with have=0 is the documented sizing call.
    unsafe {
        RmGetList(
            session,
            &mut needed,
            &mut have,
            std::ptr::null_mut(),
            &mut reasons,
        );
    }
    if needed == 0 {
        return Vec::new();
    }

    let mut infos: Vec<RM_PROCESS_INFO> = vec![unsafe { std::mem::zeroed() }; needed as usize];
    have = needed;
    // SAFETY: `infos` has `have` elements as the call requires.
    let res = unsafe {
        RmGetList(
            session,
            &mut needed,
            &mut have,
            infos.as_mut_ptr(),
            &mut reasons,
        )
    };
    if res != 0 {
        return Vec::new();
    }
    infos
        .iter()
        .take(have as usize)
        .map(|i| i.Process.dwProcessId)
        .collect()
}

/// Resolve all `paths` to the processes holding them, decorated with the
/// command/user from the process snapshot in `by_pid`.
pub fn lookup(paths: &[String], by_pid: &HashMap<u32, Process>) -> Vec<Process> {
    let mut out: HashMap<u32, Process> = HashMap::new();
    for path in paths {
        let device = if path.len() >= 2 && path.as_bytes()[1] == b':' {
            Some(path[..2].to_string())
        } else {
            None
        };
        for pid in processes_using(path) {
            let entry = out.entry(pid).or_insert_with(|| {
                let base = by_pid.get(&pid);
                Process {
                    pid,
                    ppid: base.and_then(|p| p.ppid),
                    command: base
                        .map(|p| p.command.clone())
                        .unwrap_or_else(|| "<unknown>".to_string()),
                    user: base.and_then(|p| p.user.clone()),
                    files: Vec::new(),
                }
            });
            entry.files.push(OpenFile {
                fd: FdType::Unknown,
                access: AccessMode::Unknown,
                file_type: FileType::Regular,
                name: path.clone(),
                device: device.clone(),
                size: None,
                offset: None,
                node: None,
                socket: None,
            });
        }
    }
    out.into_values().collect()
}
