//! Process enumeration from `/proc`.

use lsof_core::model::Process;

use crate::users;

/// Every process currently in `/proc`, with pid, ppid, command and owner.
///
/// A pid that vanishes mid-scan is skipped, not reported: `/proc` is a live
/// view, and a process exiting while we walk it is normal operation rather
/// than an error. Every read here is therefore best-effort.
pub fn enumerate(numeric_ids: bool) -> Vec<Process> {
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in dir.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        // /proc holds plenty of non-pid entries (self, net, meminfo, …).
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        if let Some(p) = read_one(pid, numeric_ids) {
            out.push(p);
        }
    }
    out.sort_by_key(|p| p.pid);
    out
}

fn read_one(pid: u32, numeric_ids: bool) -> Option<Process> {
    // `status` rather than `stat`: `stat`'s second field is the command in
    // parentheses, and a command containing ") " defeats naive splitting — a
    // real and exploitable parsing trap, since process names are attacker-
    // controlled. `status` is line-oriented and has no such ambiguity.
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;

    let mut command = String::new();
    let mut ppid = None;
    let mut uid = None;
    for line in status.lines() {
        if let Some(v) = line.strip_prefix("Name:") {
            command = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("PPid:") {
            ppid = v.trim().parse::<u32>().ok();
        } else if let Some(v) = line.strip_prefix("Uid:") {
            // real, effective, saved, fs — the real uid is the owner lsof shows.
            uid = v
                .split_whitespace()
                .next()
                .and_then(|s| s.parse::<u32>().ok());
        }
        if !command.is_empty() && ppid.is_some() && uid.is_some() {
            break;
        }
    }

    Some(Process {
        pid,
        ppid,
        command,
        user: uid.map(|u| users::name_for(u, numeric_ids)),
        files: Vec::new(),
        endpoint_peer: false,
    })
}

/// Whether this process is running as root, the Linux analog of the Windows
/// backend's elevation check. Read from `/proc/self/status` rather than
/// `geteuid()` to stay free of `libc`.
pub fn is_root() -> bool {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        // real, *effective*, saved, fs — effective is what governs access.
        .and_then(|v| v.split_whitespace().nth(1))
        .map(|euid| euid == "0")
        .unwrap_or(false)
}
