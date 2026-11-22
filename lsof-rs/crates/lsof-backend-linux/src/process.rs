//! Process enumeration from `/proc`.

use std::collections::HashSet;

use lsof_core::model::Process;

/// Every process in `/proc`, and which of them are zombies.
pub struct Enumerated {
    /// Every process, zombies included, sorted by pid.
    pub procs: Vec<Process>,
    /// The pids whose `State:` is `Z`.
    ///
    /// The C never lists one: `read_id_stat()` returns 1 for state `Z` and
    /// `dproc.c` skips the process entry on that (`if ((prv >= 0) && (prv !=
    /// 1))`), so `lsof -p <zombie>` prints nothing, exits 1, and `-V` says
    /// `process ID not located`. lsof-rs printed a bare `unk unknown` row for
    /// it and exited 0 (DIVERGENCES 31). They are reported here rather than
    /// dropped because a zombie's **tasks** are still walked — `prv == 1` is
    /// not `< 0` — so a process whose main thread has exited while another
    /// thread runs on is listed through that live task, and only through it.
    pub zombies: HashSet<u32>,
    /// `/proc` itself, still open: the C opens it once (`opendir(PROCFS)`,
    /// `dproc.c:301`) and closes it only when every process has been read
    /// (`closedir(ps)`, `dproc.c:437-440`), so lsof's own listing has the
    /// row `Nr DIR … /proc`, and `lsof /proc`, which names the file system,
    /// finds a user of it and exits 0. Whoever holds this holds the
    /// descriptor; the gather keeps it until it has read its last file.
    /// `None` where `/proc` could not be opened.
    pub proc_dir: Option<std::fs::ReadDir>,
}

/// Every process currently in `/proc`, with pid, ppid, command and owner
/// (its uid: the login is asked later, for what is printed).
///
/// A pid that vanishes mid-scan is skipped, not reported: `/proc` is a live
/// view, and a process exiting while we walk it is normal operation rather
/// than an error. Every read here is therefore best-effort.
pub fn enumerate() -> Enumerated {
    let mut out = Enumerated {
        procs: Vec::new(),
        zombies: HashSet::new(),
        proc_dir: None,
    };
    let Ok(mut dir) = std::fs::read_dir("/proc") else {
        return out;
    };
    // `by_ref()`: the entries are read here, and the directory handed back
    // open ([`Enumerated::proc_dir`]).
    for entry in dir.by_ref().flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        // /proc holds plenty of non-pid entries (self, net, meminfo, …).
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        if let Some((p, zombie)) = read_one(pid) {
            if zombie {
                out.zombies.insert(pid);
            }
            out.procs.push(p);
        }
    }
    out.procs.sort_by_key(|p| p.pid);
    out.proc_dir = Some(dir);
    out
}

/// The comm in `status` bytes that are not UTF-8, as bytes: the `Name:`
/// line's value, unescaped as [`unescape_comm`] does and a newline made `?`,
/// so that `-c` compares, and COMMAND, `-F c` and `-E` print, the bytes the
/// C reads (DIVERGENCES 92). `None` when that line is text after all.
pub fn raw_comm(status: &[u8]) -> Option<Vec<u8>> {
    let line = status
        .split(|&b| b == b'\n')
        .find_map(|l| l.strip_prefix(b"Name:"))?;
    let v = line.strip_prefix(b"\t").unwrap_or(line);
    if std::str::from_utf8(v).is_ok() {
        return None;
    }
    let mut out = Vec::with_capacity(v.len());
    let mut i = 0;
    while let Some(&b) = v.get(i) {
        match (b, v.get(i + 1)) {
            (b'\\', Some(b'n')) => {
                out.push(b'?');
                i += 2;
            }
            (b'\\', Some(b'\\')) => {
                out.push(b'\\');
                i += 2;
            }
            (b'\n', _) => {
                out.push(b'?');
                i += 1;
            }
            _ => {
                out.push(b);
                i += 1;
            }
        }
    }
    Some(out)
}

/// The bytes of a command that is not UTF-8 ([`lsof_core::RawNames`]),
/// which COMMAND, `-F c` and `-c` use. The owner's login is not looked up
/// here: lsof asks for it only for a process it prints by name
/// ([`lsof_core::Backend::login_name`], DIVERGENCES 39).
fn raw_names(raw_command: Option<Vec<u8>>) -> Option<Box<lsof_core::RawNames>> {
    raw_command.map(|command| {
        Box::new(lsof_core::RawNames {
            command: Some(command.into_boxed_slice()),
            login: None,
            task_command: None,
        })
    })
}

/// One process, and whether it is a zombie.
fn read_one(pid: u32) -> Option<(Process, bool)> {
    // `status` rather than `stat`: `stat`'s second field is the command in
    // parentheses, and a command containing ") " defeats naive splitting — a
    // real and exploitable parsing trap, since process names are attacker-
    // controlled. `status` is line-oriented and has no such ambiguity.
    let bytes = std::fs::read(format!("/proc/{pid}/status")).ok()?;
    let raw_command = std::str::from_utf8(&bytes)
        .is_err()
        .then(|| raw_comm(&bytes))
        .flatten();
    let status = crate::text::lossy(bytes);
    let st = parse_status(&status);
    let zombie = st.state == Some('Z');
    let raw_names = raw_names(raw_command);

    let p = Process {
        tid: None,
        task_command: None,
        uid: st.uid,
        pgid: st.pgid,
        pid,
        ppid: st.ppid,
        command: st.command,
        user: None,
        files: Vec::new().into(),
        endpoint_peer: false,
        unlisted: false,
        raw_names,
        file_structs: None,
    };
    Some((p, zombie))
}

/// The other threads of `pid`, as lsof models them: each task is its **own**
/// process entry, repeating the whole file set.
///
/// That is not redundancy — a Linux thread may hold its own cwd, root and fd
/// table, since `CLONE_FS` and `CLONE_FILES` are separate flags — so the rows
/// are read from `/proc/<pid>/task/<tid>/` rather than copied from the process.
/// For the common case where the thread shares them, the answer comes out
/// identical, which is what makes `lsof -K` look repetitive on ordinary
/// programs.
///
/// The main thread (`tid == pid`) is **not** returned: it is the process, and
/// the C shows it with blank TID and TASKCMD cells.
///
/// Nor is a **zombie** task — the C reads each task's `stat` and skips one in
/// state `Z` (`dproc.c`, `if ((rv < 0) || (rv == 1)) continue`). The name
/// and the state come from the task's own `status` in one read, decoded the
/// same lossy way as the process's, so a thread cannot hide itself with a
/// non-UTF-8 name either (it had been skipped the same way, reading `comm`).
pub fn tasks_of(parent: &Process) -> Vec<Process> {
    let Ok(dir) = std::fs::read_dir(format!("/proc/{}/task", parent.pid)) else {
        return Vec::new();
    };
    let mut out: Vec<Process> = dir
        .flatten()
        .filter_map(|e| {
            let name = e.file_name();
            let tid: u32 = name.to_str()?.parse().ok()?;
            if tid == parent.pid {
                return None;
            }
            // A thread that exits mid-scan is ordinary, not an error: its
            // status is simply gone, and the task is skipped rather than
            // reported with a guessed name.
            // `status` is decoded **lossily** ([`crate::text::lossy`]): `Name:`
            // is whatever the thread set with `prctl(PR_SET_NAME)` and need not
            // be UTF-8; read strictly, the first byte that was not made the read
            // fail and the task vanish, so any thread could hide from lsof-rs by
            // naming itself `\xff`.
            let bytes = std::fs::read(format!("/proc/{}/task/{tid}/status", parent.pid)).ok()?;
            // The name's bytes where they are not UTF-8, as the process's
            // are kept ([`raw_comm`]): TASKCMD prints them as the C does,
            // `ab\xc3` and not the bytes of the U+FFFD they decode to.
            let raw_task = std::str::from_utf8(&bytes)
                .is_err()
                .then(|| raw_comm(&bytes))
                .flatten();
            let st = parse_status(&crate::text::lossy(bytes));
            if st.state == Some('Z') {
                return None;
            }
            let mut raw_names = parent.raw_names.clone();
            if let Some(name) = raw_task {
                raw_names.get_or_insert_with(Box::default).task_command =
                    Some(name.into_boxed_slice());
            }
            Some(Process {
                tid: Some(tid),
                task_command: Some(st.command),
                files: Vec::new().into(),
                raw_names,
                ..parent.clone()
            })
        })
        .collect();
    out.sort_by_key(|p| p.tid);
    out
}

/// What one `/proc/<pid>/status` yields.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Status {
    pub command: String,
    pub ppid: Option<u32>,
    /// The **effective** uid — the owner lsof shows, and its `-F u` value.
    pub uid: Option<u32>,
    /// From `NSpgid:`, for `-F g` and `-g`.
    pub pgid: Option<u32>,
    /// The one-letter scheduler state from `State:` (`R`, `S`, `Z`, …). A
    /// `Z` is a zombie, which the C never lists.
    pub state: Option<char>,
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
    let mut state = None;
    // '\n' only: `str::lines()` also drops a '\r' before it, and a comm may
    // end in one (`prctl(PR_SET_NAME, "tail\r")`), which the C keeps: it
    // prints `ctail\r` and `-c` matches it (measured). The kernel ends every
    // line with a bare '\n'.
    for line in status.split('\n') {
        if let Some(v) = line.strip_prefix("Name:") {
            // The kernel writes `Name:\t<comm>` — exactly one tab. The comm's
            // own whitespace (a trailing space is legal) is part of the name
            // and is kept; the renderer decides how to show it. A newline is
            // the exception: the C reads the comm from `stat` and replaces
            // each one with `?` before anything sees it (`read_id_stat()`),
            // so COMMAND, TASKCMD, `-F c`, `-F M`, JSON and `-c` all have
            // `?` there (DIVERGENCES 58, measured).
            command = unescape_comm(v.strip_prefix('\t').unwrap_or(v)).replace('\n', "?");
        } else if let Some(v) = line.strip_prefix("State:") {
            // `State:\tZ (zombie)` — the letter is all lsof reads.
            state = v.trim_start().chars().next();
        } else if let Some(v) = line.strip_prefix("PPid:") {
            ppid = v.trim().parse::<u32>().ok();
        } else if let Some(v) = line.strip_prefix("Uid:") {
            // real, effective, saved, fs. The owner lsof shows is the
            // EFFECTIVE one: the C takes `stat("/proc/<pid>/").st_uid`
            // (`dproc.c`), and the kernel gives that directory the task's
            // effective uid whatever its dumpable state (`task_dump_owner()`
            // exempts a world-readable directory from the root fallback).
            // Measured on a process with real uid 0 and effective 65534: the
            // C shows `nobody`, and `-u nobody` selects it. lsof-rs had read
            // the real uid and shown `root` (DIVERGENCES 55).
            uid = v
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse::<u32>().ok());
        }
        // `NSpgid` is the process group as seen in our own namespace, which
        // is the number lsof's `-F g` reports. There is no `Pgid:` line.
        //
        // It is a LIST — one pgid per nested pid namespace, outermost (ours)
        // first — so a process in a container reads `NSpgid:\t4242\t1`.
        // Parsing the whole value as one number made every such process's
        // pgid `None`, which `-g` would have been unable to select.
        else if let Some(v) = line.strip_prefix("NSpgid:") {
            pgid = v
                .split_whitespace()
                .next()
                .and_then(|s| s.parse::<u32>().ok());
        }
        if !command.is_empty()
            && state.is_some()
            && ppid.is_some()
            && uid.is_some()
            && pgid.is_some()
        {
            break;
        }
    }
    Status {
        command,
        ppid,
        uid,
        pgid,
        state,
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
    let Some(status) = crate::text::read_lossy("/proc/self/status") else {
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

    /// The C opens `/proc` once and keeps it open until it has read every
    /// process (`opendir(PROCFS)` … `closedir(ps)`, `dproc.c:301, 437-440`):
    /// the enumeration hands the open directory back, and while its caller
    /// holds it this process has a descriptor on `/proc`, the one lsof's
    /// own listing shows as `Nr DIR … /proc`. lsof-rs had closed it once
    /// the pids were read.
    #[test]
    #[cfg_attr(miri, ignore = "miri's emulated fds do not appear in the host's /proc")]
    fn enumeration_hands_back_proc_still_open() {
        let on_proc = || {
            std::fs::read_dir("/proc/self/fd")
                .expect("own fd directory")
                .flatten()
                .filter(|e| {
                    std::fs::read_link(e.path()).is_ok_and(|t| t == std::path::Path::new("/proc"))
                })
                .count()
        };
        let seen = enumerate();
        assert!(seen.proc_dir.is_some(), "the directory is handed back");
        assert!(!seen.procs.is_empty(), "and its entries were read");
        assert!(on_proc() >= 1, "a descriptor on /proc while it is held");
        let Enumerated { proc_dir, .. } = seen;
        // Held by whoever takes it, and gone with them: another test's own
        // enumeration may hold one of its own meanwhile, so the count can
        // only be compared, never pinned.
        let held = on_proc();
        drop(proc_dir);
        assert!(held >= 1 && on_proc() <= held);
    }

    /// A command that is not UTF-8 is kept as its bytes, and no login is
    /// named as the process is read.
    #[test]
    fn a_command_that_is_not_utf8_is_kept_as_bytes() {
        assert_eq!(raw_names(None), None);
        let raw = raw_names(Some(b"x\xff".to_vec())).expect("kept");
        assert_eq!(raw.command.as_deref(), Some(&b"x\xff"[..]));
        assert_eq!(raw.login, None);
    }

    /// A thread whose name is not UTF-8 is a task with that name's bytes,
    /// beside the text it decodes to, and its process's command kept: what
    /// TASKCMD prints (DIVERGENCES 93). Named here by writing its own
    /// `comm`, as `prctl(PR_SET_NAME)` names it.
    #[test]
    #[cfg_attr(miri, ignore = "it names a live thread through /proc")]
    fn a_thread_name_that_is_not_utf8_is_kept_as_bytes() {
        let (named_tx, named_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let worker = std::thread::spawn(move || {
            let me = std::fs::read_link("/proc/thread-self").unwrap();
            let tid: u32 = me.file_name().unwrap().to_str().unwrap().parse().unwrap();
            std::fs::write("/proc/thread-self/comm", b"ab\xc3").unwrap();
            named_tx.send(tid).unwrap();
            let _ = done_rx.recv();
        });
        let tid = named_rx.recv().unwrap();
        let (parent, _) = read_one(std::process::id()).expect("this process");
        let task = tasks_of(&parent)
            .into_iter()
            .find(|t| t.tid == Some(tid))
            .expect("the named thread");
        done_tx.send(()).unwrap();
        worker.join().unwrap();
        assert_eq!(task.task_command.as_deref(), Some("ab\u{fffd}"));
        assert_eq!(task.task_command_bytes(), Some(&b"ab\xc3"[..]));
        assert_eq!(task.command_bytes(), parent.command_bytes());
    }

    /// The comm of a `status` that is not UTF-8, as bytes: unescaped as
    /// the kernel escapes it (`\\` and `\n`), a newline made `?`; none
    /// where the comm is text, which [`parse_status`] reads.
    #[test]
    fn the_raw_comm_is_the_name_lines_bytes() {
        assert_eq!(
            raw_comm(b"Name:\tx\xff\\\\a\\nb\nState:\tS\n"),
            Some(b"x\xff\\a?b".to_vec())
        );
        assert_eq!(raw_comm(b"Name:\tok\nUid:\t\xff\n"), None);
        assert_eq!(raw_comm(b"State:\tS\n"), None);
        assert_eq!(raw_comm(b"Name:\xfe"), Some(b"\xfe".to_vec()));
    }

    /// The three fields a caller most often wants, as a tuple, so the asserts
    /// below stay readable.
    fn triple(s: &str) -> (String, Option<u32>, Option<u32>) {
        let st = parse_status(s);
        (st.command, st.ppid, st.uid)
    }

    #[test]
    fn the_owner_is_the_effective_uid() {
        // `Uid:` is real, effective, saved, fs. The C's owner is the owner of
        // `/proc/<pid>/`, which the kernel sets to the effective uid
        // (DIVERGENCES 55), so each of these reads the second field.
        let uid = |line: &str| parse_status(&format!("Name:\tx\n{line}\n")).uid;
        assert_eq!(uid("Uid:\t0\t65534\t0\t65534"), Some(65534));
        assert_eq!(uid("Uid:\t65534\t0\t0\t0"), Some(0));
        assert_eq!(uid("Uid:\t1000\t1000\t1000\t1000"), Some(1000));
        // A line with no effective field names no owner: not the real uid.
        assert_eq!(uid("Uid:\t1000"), None);
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
                state: Some('S'),
            }
        );
    }

    #[test]
    fn a_zombie_is_recognised_by_its_state_letter() {
        // What the kernel writes for a zombie, and for a stopped process —
        // lsof skips the first and lists the second.
        assert_eq!(
            parse_status("Name:\tz\nState:\tZ (zombie)\n").state,
            Some('Z')
        );
        assert_eq!(
            parse_status("Name:\tt\nState:\tT (stopped)\n").state,
            Some('T')
        );
        assert_eq!(parse_status("State:\n").state, None);
        assert_eq!(parse_status("").state, None);
    }

    #[test]
    fn nspgid_is_a_list_and_the_first_entry_is_ours() {
        // A process in a nested pid namespace — a container seen from the
        // host — has one pgid per level, outermost first. The first is the
        // one lsof reports (it is `stat`'s field 5 for the same reader).
        assert_eq!(parse_status("NSpgid:\t4242\t1\n").pgid, Some(4242));
        assert_eq!(parse_status("NSpgid:\t4242\n").pgid, Some(4242));
        assert_eq!(parse_status("NSpgid:\tx\t1\n").pgid, None);
        assert_eq!(parse_status("NSpgid:\n").pgid, None);
    }

    #[test]
    fn hostile_names_are_faithful_and_never_panic() {
        // The reason `status` was chosen over `stat`: a name containing ") " (or
        // anything else) is attacker-controlled via prctl(PR_SET_NAME). The
        // parser must return it verbatim and must not panic.
        let s = "Name:\t) ) :Uid: 0\nPPid:\t1\nUid:\t0\t0\t0\t0\n";
        assert_eq!(triple(s), (") ) :Uid: 0".to_string(), Some(1), Some(0)));
        // The proc_status fuzz target's first finding, verbatim: one line, no
        // newline, a bare '\r' mid-value. split('\n') yields it whole; trim() keeps
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
        // ...which the C's `read_id_stat()` then makes a `?` (DIVERGENCES 58).
        assert_eq!(parse_status("Name:\tx\\ny\n").command, "x?y");
        assert_eq!(parse_status("Name:\t\\n\\\\n\n").command, "?\\n");
        // Raw controls and non-ASCII are not the kernel's to escape and come
        // through untouched; so does the comm's own trailing whitespace.
        assert_eq!(
            parse_status("Name:\th\x1b[2J\r \x7f\t\u{e9}\u{9b}z\n").command,
            "h\x1b[2J\r \x7f\t\u{e9}\u{9b}z"
        );
        assert_eq!(parse_status("Name:\ttrailing \n").command, "trailing ");
        // A comm ending in '\r': the kernel writes `Name:\ttail\r\n`, and the
        // '\r' is the name's, as the C keeps it (`-F c` gives `ctail\r`).
        let st = parse_status("Name:\ttail\r\nState:\tS (sleeping)\r\nPPid:\t7\n");
        assert_eq!(st.command, "tail\r");
        assert_eq!(st.ppid, Some(7));
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
        let s = "Name:\tfirst\nState:\tS (sleeping)\nPPid:\t1\nNSpgid:\t1\nUid:\t2\t2\t2\t2\nName:\tsecond\n";
        assert_eq!(parse_status(s).command, "first");
    }
}
