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
    let st = parse_status(&status);

    Some(Process {
        uid: st.uid,
        pgid: st.pgid,
        pid,
        ppid: st.ppid,
        command: st.command,
        user: st.uid.map(|u| users::name_for(u, numeric_ids)),
        files: Vec::new(),
        endpoint_peer: false,
    })
}

/// What one `/proc/<pid>/status` yields.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Status {
    pub command: String,
    pub ppid: Option<u32>,
    /// The **real** uid — the owner lsof shows, and its `-F u` value.
    pub uid: Option<u32>,
    /// From `NSpgid:`, for `-F g`.
    pub pgid: Option<u32>,
}

/// The parsing half of [`read_one`]: the fields of the text
/// of `/proc/<pid>/status`. Pure, so the fuzz target can drive it with arbitrary
/// bytes, and it must never panic — `Name:` is set by the process itself
/// (`prctl(PR_SET_NAME)`), which makes this the one parser in the backend whose
/// input an unprivileged local user controls outright. Missing or malformed
/// fields come back empty/`None`; nothing is guessed.
pub fn parse_status(status: &str) -> Status {
    let mut command = String::new();
    let mut ppid = None;
    let mut uid = None;
    let mut pgid = None;
    for line in status.lines() {
        if let Some(v) = line.strip_prefix("Name:") {
            // The kernel writes `Name:\t<comm>` — exactly one tab. The comm's
            // own whitespace (a trailing space is legal) is part of the name
            // and is kept; the renderer decides how to show it.
            command = unescape_comm(v.strip_prefix('\t').unwrap_or(v));
        } else if let Some(v) = line.strip_prefix("PPid:") {
            ppid = v.trim().parse::<u32>().ok();
        } else if let Some(v) = line.strip_prefix("Uid:") {
            // real, effective, saved, fs — the real uid is the owner lsof shows.
            uid = v
                .split_whitespace()
                .next()
                .and_then(|s| s.parse::<u32>().ok());
        }
        // `NSpgid` is the process group as seen in our own namespace, which
        // is the number lsof's `-F g` reports. There is no `Pgid:` line.
        else if let Some(v) = line.strip_prefix("NSpgid:") {
            pgid = v.trim().parse::<u32>().ok();
        }
        if !command.is_empty() && ppid.is_some() && uid.is_some() && pgid.is_some() {
            break;
        }
    }
    Status {
        command,
        ppid,
        uid,
        pgid,
    }
}

/// Undo the kernel's escaping of the command in `/proc/<pid>/status`.
///
/// `fs/proc/array.c` writes `Name:` through `seq_escape_str(…, ESCAPE_SPECIAL,
/// "\n\\")`, which turns a newline into the two characters `\n` and a backslash
/// into `\\`, and touches nothing else (a `\r` or an ESC comes through raw —
/// the `proc_status` fuzz target's finding). The C `lsof` reads the comm from
/// `stat`, where it is raw, so the model must hold the raw bytes for both
/// binaries to escape it the same way in the renderer; left encoded, one
/// backslash in a name would print as four. A `\` followed by anything else
/// cannot come from the kernel and is kept literally — this must be faithful
/// and must not panic, whatever a fuzzer feeds it.
pub fn unescape_comm(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.peek() {
                Some('n') => {
                    chars.next();
                    out.push('\n');
                    continue;
                }
                Some('\\') => {
                    chars.next();
                    out.push('\\');
                    continue;
                }
                _ => {}
            }
        }
        out.push(c);
    }
    out
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The three fields a caller most often wants, as a tuple, so the asserts
    /// below stay readable.
    fn triple(s: &str) -> (String, Option<u32>, Option<u32>) {
        let st = parse_status(s);
        (st.command, st.ppid, st.uid)
    }

    #[test]
    fn well_formed_status_yields_every_field() {
        let s = "Name:\tsleep\nUmask:\t0022\nState:\tS (sleeping)\nPid:\t42\nPPid:\t7\nNSpgid:\t41\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\n";
        assert_eq!(
            parse_status(s),
            Status {
                command: "sleep".to_string(),
                ppid: Some(7),
                uid: Some(1000),
                pgid: Some(41),
            }
        );
    }

    #[test]
    fn hostile_names_are_faithful_and_never_panic() {
        // The reason `status` was chosen over `stat`: a name containing ") " (or
        // anything else) is attacker-controlled via prctl(PR_SET_NAME). The
        // parser must return it verbatim and must not panic.
        let s = "Name:\t) ) :Uid: 0\nPPid:\t1\nUid:\t0\t0\t0\t0\n";
        assert_eq!(triple(s), (") ) :Uid: 0".to_string(), Some(1), Some(0)));
        // The proc_status fuzz target's first finding, verbatim: one line, no
        // newline, a bare '\r' mid-value. lines() yields it whole; trim() keeps
        // the interior '\r'. Faithful is correct here (DIVERGENCES.md #10 is
        // about the renderer, not this).
        let (cmd, ppid, uid) = triple("Name:PPid:\rd:Uid:");
        assert_eq!(cmd, "PPid:\rd:Uid:");
        assert_eq!((ppid, uid), (None, None));
    }

    #[test]
    fn the_kernels_status_escaping_is_undone_nothing_else_is_touched() {
        // What the kernel wrote for a comm of `a\b` (one backslash) and for one
        // holding a newline — observed on 6.x: `Name:\ta\\b`, `Name:\tx\ny`.
        assert_eq!(parse_status("Name:\ta\\\\b\n").command, "a\\b");
        assert_eq!(parse_status("Name:\tx\\ny\n").command, "x\ny");
        // Raw controls and non-ASCII are not the kernel's to escape and come
        // through untouched; so does the comm's own trailing whitespace.
        assert_eq!(
            parse_status("Name:\th\x1b[2J\r \x7f\t\u{e9}\u{9b}z\n").command,
            "h\x1b[2J\r \x7f\t\u{e9}\u{9b}z"
        );
        assert_eq!(parse_status("Name:\ttrailing \n").command, "trailing ");
        // Shapes the kernel never produces must be kept literally, not guessed.
        assert_eq!(unescape_comm("a\\tb"), "a\\tb");
        assert_eq!(unescape_comm("trailing\\"), "trailing\\");
        assert_eq!(unescape_comm("\\\\\\n"), "\\\n");
        assert_eq!(unescape_comm(""), "");
    }

    #[test]
    fn missing_or_malformed_fields_are_none_not_guesses() {
        assert_eq!(parse_status(""), Status::default());
        assert_eq!(parse_status("Name:\n"), Status::default());
        assert_eq!(
            triple("PPid:\tnotanumber\nUid:\t\n"),
            (String::new(), None, None)
        );
        // A uid line with only whitespace after the tag.
        assert_eq!(triple("Uid:   \n"), (String::new(), None, None));
        // Numbers that overflow u32 are malformed, not clamped.
        assert_eq!(parse_status("PPid:\t99999999999\n").ppid, None);
        // There is no `Pgid:` line in /proc — only `NSpgid:` — so a `Pgid:`
        // line must not be mistaken for one.
        assert_eq!(parse_status("Pgid:\t9\n").pgid, None);
        assert_eq!(parse_status("NSpgid:\t9\n").pgid, Some(9));
    }

    #[test]
    fn the_first_complete_set_wins_and_later_lines_are_ignored() {
        // Once every field is seen the loop stops — a second `Name:` further
        // down (impossible from the kernel, trivial from a fuzzer) is ignored.
        let s = "Name:\tfirst\nPPid:\t1\nNSpgid:\t1\nUid:\t2\t2\t2\t2\nName:\tsecond\n";
        assert_eq!(parse_status(s).command, "first");
    }
}
