//! End-to-end renderer checks over the deterministic mock data set.

use lsof_core::mock::sample_processes;
use lsof_core::render::{fields, json, table, FileFlags, JsonFormat, TableOpts};
use lsof_core::{Escaper, TcpInfoFlags};

#[test]
fn table_has_header_and_rows() {
    // A plain run: `TableOpts::new` is `lsof` with no options, which includes
    // the 9-character COMMAND cap. `explorer.exe` and `server.exe` are 12 and
    // 10 characters, so both are cut — that IS the default output.
    let out = table::render(&sample_processes(), TableOpts::new(Escaper::WINDOWS));
    let header = out.lines().next().unwrap();
    for col in ["COMMAND", "PID", "USER", "FD", "TYPE", "NODE", "NAME"] {
        assert!(header.contains(col), "header missing {col}: {header:?}");
    }
    assert!(out.contains("explorer."), "{out:?}");
    assert!(out.contains("server.ex"), "{out:?}");
    assert!(!out.contains("explorer.exe"), "default cap is 9: {out:?}");
    assert!(out.contains("1500"));
    assert!(out.contains("(LISTEN)"));
    // cwd row renders the special FD code, not a number.
    assert!(out.contains("cwd"));
    // The column is exactly the cap here, and the header floor does not widen
    // it: `COMMAND` is 7, the capped rows are 9.
    assert!(header.starts_with("COMMAND    PID"), "{header:?}");
}

#[test]
fn the_command_column_defaults_to_nine_characters() {
    // DIVERGENCES #3: lsof-rs printed the whole command where the C caps it at
    // CMDL (9). Measured against lsof 4.99.6 with a 15-character command:
    // the C prints `abcdefghi`, and `+c 0` is what asks for the full name.
    let p = named("abcdefghijklmno", "u", "f");
    let cell = |opts: TableOpts| -> String {
        table::render(std::slice::from_ref(&p), opts)
            .lines()
            .nth(1)
            .unwrap()
            .split(' ')
            .next()
            .unwrap()
            .to_string()
    };
    assert_eq!(cell(TableOpts::new(Escaper::UNIX)), "abcdefghi");
    assert_eq!(
        cell(TableOpts {
            command_width: None,
            ..TableOpts::new(Escaper::UNIX)
        }),
        "abcdefghijklmno"
    );
    // A command shorter than the cap is untouched, and the column then falls
    // back to the header width.
    let short = named("sh0rt", "u", "f");
    let out = table::render(std::slice::from_ref(&short), TableOpts::new(Escaper::UNIX));
    assert!(out.starts_with("COMMAND "), "{out:?}");
    assert!(
        out.lines().nth(1).unwrap().starts_with("sh0rt  "),
        "{out:?}"
    );
}

#[test]
fn table_empty_when_nothing_matches() {
    // No matching processes -> no output at all (not even a bare header),
    // matching lsof. Regression guard for `lsof -a -p <pid> -c <nomatch>`.
    assert_eq!(
        table::render(
            &[],
            TableOpts {
                command_width: None,
                ..TableOpts::new(Escaper::WINDOWS)
            }
        ),
        ""
    );
    assert_eq!(
        table::render(
            &[],
            TableOpts {
                show_ppid: true,
                command_width: None,
                ..TableOpts::new(Escaper::WINDOWS)
            }
        ),
        ""
    );
}

#[test]
fn a_process_with_no_files_still_gets_one_blank_row() {
    // The renderer's own contract, whichever selection path hands it such a
    // process: one row, FD `unk`, TYPE `unknown`, every file cell empty, the
    // row padded like any other. Pinned because the table renderer was
    // rewritten to stream (two passes over the rows, nothing retained), and
    // the blank row is the one row that is not in `p.files` — a rewrite that
    // iterates the files alone drops it silently, and nothing else covered it.
    let mut idle = sample_processes().remove(0);
    idle.files.clear();
    let out = table::render(std::slice::from_ref(&idle), TableOpts::new(Escaper::UNIX));
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 2, "a header and exactly one row: {out:?}");
    let cells: Vec<&str> = lines[1].split_whitespace().collect();
    assert_eq!(cells[1], idle.pid.to_string(), "{out:?}");
    assert!(
        cells.ends_with(&["unk", "unknown"]),
        "FD unk, TYPE unknown, nothing after: {out:?}"
    );
    // ...and it is sized like every other row: the header and the row are
    // the same width up to NAME, so the columns still line up.
    let name_at = lines[0].find("NAME").unwrap();
    assert_eq!(
        lines[1].len(),
        name_at,
        "row padded to the NAME column: {out:?}"
    );
}

#[test]
fn terse_lists_unique_pids() {
    let out = table::render(
        &sample_processes(),
        TableOpts {
            terse: true,
            command_width: None,
            ..TableOpts::new(Escaper::WINDOWS)
        },
    );
    assert_eq!(out, "1000\n1500\n");
}

#[test]
fn fields_tokens() {
    let out = fields::render(
        &sample_processes(),
        false,
        None,
        TcpInfoFlags::DEFAULT,
        Escaper::WINDOWS,
    );
    assert!(out.contains("p1000\n"));
    assert!(out.contains("p1500\n"));
    assert!(out.contains("cexplorer.exe\n"));
    assert!(out.contains("PTCP\n"));
    assert!(out.contains("TST=LISTEN\n"));
    // ppid is emitted.
    assert!(out.contains("R4\n"));
}

#[test]
fn fields_only_restricts_output() {
    // Request only the name field; structural p/f markers still appear.
    let out = fields::render(
        &sample_processes(),
        false,
        Some(&['n']),
        TcpInfoFlags::DEFAULT,
        Escaper::WINDOWS,
    );
    assert!(out.contains("p1000\n"));
    assert!(out.contains("f"));
    assert!(out.contains("nC:\\Users\\alice\n"));
    // Command/type fields suppressed.
    assert!(!out.contains("cexplorer.exe\n"));
    assert!(!out.contains("tDIR\n"));
}

#[test]
fn table_ppid_column() {
    let out = table::render(
        &sample_processes(),
        TableOpts {
            show_ppid: true,
            command_width: None,
            ..TableOpts::new(Escaper::WINDOWS)
        },
    );
    assert!(out.lines().next().unwrap().contains("PPID"));
    // explorer.exe's ppid (4) shows up.
    assert!(out.contains(" 4 ") || out.contains("   4 "));
}

#[test]
fn table_offset_with_dash_o() {
    use lsof_core::{AccessMode, FdType, FileType, OpenFile, Process};
    let p = Process {
        tid: None,
        task_command: None,
        uid: None,
        pgid: None,
        pid: 7,
        ppid: None,
        command: "x".into(),
        user: None,
        endpoint_peer: false,
        unlisted: false,
        files: vec![OpenFile {
            rdev: None,
            fs_device: None,
            file_flags: None,
            lock: None,
            fd: FdType::Handle(3),
            access: AccessMode::Read,
            file_type: FileType::Regular,
            name: "C:\\f".into(),
            device: Some("C:".into()),
            size: Some(100),
            offset: Some(42),
            node: None,
            links: None,
            socket: None,
            name_addition: None,
        }],
    };
    // Default prefers size; -o prefers the offset (0t<dec>).
    assert!(table::render(
        std::slice::from_ref(&p),
        TableOpts {
            command_width: None,
            ..TableOpts::new(Escaper::WINDOWS)
        }
    )
    .contains("100"));
    assert!(table::render(
        &[p],
        TableOpts {
            show_offset: true,
            command_width: None,
            ..TableOpts::new(Escaper::WINDOWS)
        }
    )
    .contains("0t42"));
}

/// The SIZE/OFF column's three modes, as `print.c` chooses them (DIVERGENCES
/// 6). The rows are the shapes that tell the modes apart: a regular file with
/// both a size and an offset, a `cwd` with a size and no offset (no fdinfo),
/// and a pipe with an offset and no size.
#[test]
fn the_size_off_column_has_three_modes() {
    use lsof_core::{AccessMode, FdType, FileType, OpenFile, Process};
    let file = |fd: FdType, ty: FileType, size: Option<u64>, offset: Option<u64>| OpenFile {
        rdev: None,
        fs_device: None,
        file_flags: None,
        lock: None,
        fd,
        access: AccessMode::Read,
        file_type: ty,
        name: "n".into(),
        device: Some("8,1".into()),
        size,
        offset,
        node: Some("1".into()),
        links: None,
        socket: None,
        name_addition: None,
    };
    let p = Process {
        tid: None,
        task_command: None,
        uid: None,
        pgid: Some(77),
        pid: 7,
        ppid: Some(1),
        command: "x".into(),
        user: None,
        endpoint_peer: false,
        unlisted: false,
        files: vec![
            file(FdType::Handle(3), FileType::Regular, Some(100), Some(42)),
            file(FdType::Cwd, FileType::Dir, Some(4096), None),
            file(FdType::Handle(4), FileType::Fifo, None, Some(9)),
        ],
    };
    let render = |opts: TableOpts| table::render(std::slice::from_ref(&p), opts);
    let cells = |out: &str| -> Vec<String> {
        // The SIZE/OFF cell is the sixth whitespace field of every row
        // (COMMAND PID USER FD TYPE DEVICE ...) — USER is blank here, so the
        // fifth. Blank cells collapse, so compare whole lines instead.
        out.lines()
            .skip(1)
            .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect()
    };
    let base = TableOpts {
        command_width: None,
        ..TableOpts::new(Escaper::UNIX)
    };

    // Default: prefer the size, fall back to the offset.
    let out = render(base);
    assert!(out.lines().next().unwrap().contains("SIZE/OFF"), "{out}");
    assert_eq!(
        cells(&out),
        [
            "x 7 3r REG 8,1 100 1 n",
            "x 7 cwd DIR 8,1 4096 1 n",
            "x 7 4r FIFO 8,1 0t9 1 n"
        ]
    );

    // -o: offsets ONLY. The cwd has no offset and stays blank — it does not
    // fall back to its size, which is what lsof-rs did under a SIZE/OFF header.
    let out = render(TableOpts {
        show_offset: true,
        ..base
    });
    let header = out.lines().next().unwrap();
    assert!(
        header.contains("OFFSET") && !header.contains("SIZE"),
        "{out}"
    );
    assert_eq!(
        cells(&out),
        [
            "x 7 3r REG 8,1 0t42 1 n",
            "x 7 cwd DIR 8,1 1 n",
            "x 7 4r FIFO 8,1 0t9 1 n"
        ]
    );

    // -s: sizes ONLY; the pipe's offset is not shown.
    let out = render(TableOpts {
        show_size: true,
        ..base
    });
    let header = out.lines().next().unwrap();
    assert!(
        header.contains(" SIZE ") && !header.contains("SIZE/OFF"),
        "{out}"
    );
    assert_eq!(
        cells(&out),
        [
            "x 7 3r REG 8,1 100 1 n",
            "x 7 cwd DIR 8,1 4096 1 n",
            "x 7 4r FIFO 8,1 1 n"
        ]
    );

    // -g: a PGID column, after PPID when -R is also given, as print.c orders them.
    let out = render(TableOpts {
        show_ppid: true,
        show_pgid: true,
        ..base
    });
    assert!(
        out.lines().next().unwrap().contains("PID PPID PGID USER"),
        "{out}"
    );
    assert!(
        out.lines().nth(1).unwrap().contains(" 7    1   77 "),
        "{out}"
    );
}

/// Past `-o`'s digit limit (8 by default) an offset prints in hex — in the
/// table and in `-F`'s `o` field alike. Measured on an fd seeked to 123456789:
/// the C prints `0x75bcd15`; `-o 9` or `-o 0` bring back `0t123456789`.
#[test]
fn a_long_offset_prints_in_hex_past_the_digit_limit() {
    use lsof_core::render::{offset_text, DEFAULT_OFFSET_DIGITS};
    assert_eq!(DEFAULT_OFFSET_DIGITS, 8);
    assert_eq!(offset_text(12_345_678, 8), "0t12345678");
    assert_eq!(offset_text(123_456_789, 8), "0x75bcd15");
    assert_eq!(offset_text(123_456_789, 9), "0t123456789");
    assert_eq!(offset_text(123_456_789, 0), "0t123456789", "0 is no limit");
    assert_eq!(offset_text(0, 1), "0t0");
    assert_eq!(offset_text(10, 1), "0xa");
    assert_eq!(
        offset_text(u64::MAX, usize::MAX),
        format!("0t{}", u64::MAX),
        "no overflow"
    );

    use lsof_core::{AccessMode, FdType, FileType, OpenFile, Process};
    let p = Process {
        tid: None,
        task_command: None,
        uid: None,
        pgid: None,
        pid: 7,
        ppid: None,
        command: "x".into(),
        user: None,
        endpoint_peer: false,
        unlisted: false,
        files: vec![OpenFile {
            rdev: None,
            fs_device: None,
            file_flags: None,
            lock: None,
            fd: FdType::Handle(3),
            access: AccessMode::Read,
            file_type: FileType::Regular,
            name: "n".into(),
            device: None,
            size: Some(1),
            offset: Some(123_456_789),
            node: None,
            links: None,
            socket: None,
            name_addition: None,
        }],
    };
    let f = fields::render(
        std::slice::from_ref(&p),
        false,
        Some(&['o']),
        TcpInfoFlags::DEFAULT,
        Escaper::UNIX,
    );
    assert!(f.contains("o0x75bcd15\n"), "{f:?}");
    let f = fields::render_with_offset_digits(
        std::slice::from_ref(&p),
        false,
        Some(&['o']),
        TcpInfoFlags::DEFAULT,
        Escaper::UNIX,
        0,
        lsof_core::render::FileFlags::Hex,
    );
    assert!(f.contains("o0t123456789\n"), "{f:?}");
    let t = table::render(
        &[p],
        TableOpts {
            show_offset: true,
            ..TableOpts::new(Escaper::UNIX)
        },
    );
    assert!(t.contains("0x75bcd15"), "{t}");
}

/// A task entry for the TASKCMD tests: one row, one file, its own `comm`.
#[cfg(test)]
fn task_entry(command: &str, task_command: &str) -> lsof_core::Process {
    use lsof_core::{AccessMode, FdType, FileType, OpenFile, Process};
    Process {
        tid: Some(4242),
        task_command: Some(task_command.into()),
        uid: None,
        pgid: None,
        pid: 7,
        ppid: None,
        command: command.into(),
        user: None,
        endpoint_peer: false,
        unlisted: false,
        files: vec![OpenFile {
            rdev: None,
            fs_device: None,
            file_flags: None,
            lock: None,
            fd: FdType::Cwd,
            access: AccessMode::Read,
            file_type: FileType::Dir,
            name: "/tmp".into(),
            device: None,
            size: None,
            offset: None,
            node: None,
            links: None,
            socket: None,
            name_addition: None,
        }],
    }
}

#[test]
fn taskcmd_is_sized_by_its_own_column_not_by_command() {
    // `print.c` keeps `TaskCmdColW` separate from `CmdColW`: it starts at
    // `strlen("TASKCMD")` and grows over the task names, each capped by `+c`
    // (`TaskCmdLim`). Reusing the COMMAND width cuts a long thread name against
    // a short command — `python3` with a 15-character thread name printed
    // seven characters of it, where the C prints all fifteen under `+c 0`.
    let p = task_entry("py", "taskname-long-1");

    // No cap: the whole name, even though COMMAND is two characters.
    let full = table::render(
        std::slice::from_ref(&p),
        TableOpts {
            command_width: None,
            ..TableOpts::new(Escaper::UNIX)
        },
    );
    assert!(full.contains("taskname-long-1"), "{full:?}");

    // `+c 12` caps the contribution, so twelve characters print.
    let capped = table::render(
        std::slice::from_ref(&p),
        TableOpts {
            command_width: Some(12),
            ..TableOpts::new(Escaper::UNIX)
        },
    );
    assert!(capped.contains("taskname-lon"), "{capped:?}");
    assert!(!capped.contains("taskname-long-1"), "{capped:?}");

    // BELOW the header: `+c` caps each name's contribution, but the column
    // still starts at `strlen("TASKCMD")`, so three characters of `+c` yield
    // seven of output — the one case that can see the seed.
    let narrow = table::render(
        std::slice::from_ref(&p),
        TableOpts {
            command_width: Some(3),
            ..TableOpts::new(Escaper::UNIX)
        },
    );
    assert!(narrow.contains("tasknam"), "{narrow:?}");
    assert!(!narrow.contains("taskname"), "{narrow:?}");
}

#[test]
fn a_hostile_thread_name_is_escaped_in_taskcmd() {
    // A thread names itself with `prctl(PR_SET_NAME)`, so TASKCMD is as
    // attacker-controlled as COMMAND — and it is a NEW cell, not covered by
    // the COMMAND escaping tests. `\x1b[2J` clears the terminal of whoever ran
    // lsof; it must reach the column as the six printable characters
    // `^[[2J` and never as the byte.
    let p = task_entry("py", "h\x1b[2J\r x\\\x7f\ty");
    let out = table::render(
        std::slice::from_ref(&p),
        TableOpts {
            command_width: None,
            ..TableOpts::new(Escaper::UNIX)
        },
    );
    assert!(!out.contains('\x1b'), "raw ESC reached TASKCMD: {out:?}");
    assert!(!out.contains('\r'), "raw CR reached TASKCMD: {out:?}");
    assert!(!out.contains('\x7f'), "raw DEL reached TASKCMD: {out:?}");
    // The space becomes `\x20` so the column still splits on whitespace, and
    // the row keeps the field count every other row has.
    assert!(out.contains(r"h^[[2J\r\x20x\\\x7f\ty"), "{out:?}");
}

#[test]
fn a_task_row_is_distinguishable_from_a_thread_handle() {
    // On Windows BOTH of these render TYPE `THRD`: `-K` emits a task row, and
    // the all-handle scan types a thread HANDLE the same way (`handles.rs`
    // maps the native "Thread" object type). So "the output contains THRD" is
    // not a test of `-K` — the smoke suite asserted exactly that, and the case
    // passed with the feature deleted while two suppression cases failed with
    // it working. What separates them is the FD cell: `task` for the task row,
    // a handle number for the handle.
    //
    // The smoke suite now keys on `task` followed by `THRD`, and this test is
    // what keeps that discriminator honest on every push, from a platform that
    // cannot run it.
    use lsof_core::{AccessMode, FdType, FileType, OpenFile, Process};
    let file = |fd: FdType| OpenFile {
        rdev: None,
        fs_device: None,
        file_flags: None,
        lock: None,
        fd,
        access: AccessMode::Unknown,
        file_type: FileType::Thread,
        name: String::new(),
        device: None,
        size: None,
        offset: None,
        node: Some("4242".into()),
        links: None,
        socket: None,
        name_addition: None,
    };
    let p = Process {
        tid: None,
        task_command: None,
        uid: None,
        pgid: None,
        pid: 1234,
        ppid: None,
        command: "pwsh.exe".into(),
        user: Some("runneradmin".into()),
        endpoint_peer: false,
        unlisted: false,
        files: vec![file(FdType::Task), file(FdType::Handle(180))],
    };
    let out = table::render(&[p], TableOpts::new(Escaper::WINDOWS));

    // Both rows are THRD, so the substring cannot tell them apart.
    assert_eq!(out.matches("THRD").count(), 2, "{out:?}");

    // The FD cell can. `task` and `THRD` land in adjacent columns, which is
    // what the smoke suite's `\btask\s+THRD\b` matches; the handle row puts a
    // number there instead.
    let rows: Vec<&str> = out.lines().skip(1).collect();
    assert_eq!(rows.len(), 2, "{out:?}");
    let cells = |r: &str| -> Vec<String> { r.split_whitespace().map(str::to_string).collect() };
    let task = cells(rows[0]);
    let handle = cells(rows[1]);
    let fd_at = task.iter().position(|c| c == "task").expect("a task cell");
    assert_eq!(task[fd_at + 1], "THRD", "{task:?}");
    assert_eq!(handle[fd_at], "180", "{handle:?}");
    assert_eq!(handle[fd_at + 1], "THRD", "{handle:?}");
}

#[test]
fn table_command_width_caps() {
    use lsof_core::{AccessMode, FdType, FileType, OpenFile, Process};
    let p = Process {
        tid: None,
        task_command: None,
        uid: None,
        pgid: None,
        pid: 7,
        ppid: None,
        command: "verylongcommandname.exe".into(),
        user: None,
        endpoint_peer: false,
        unlisted: false,
        files: vec![OpenFile {
            rdev: None,
            fs_device: None,
            file_flags: None,
            lock: None,
            fd: FdType::Handle(3),
            access: AccessMode::Read,
            file_type: FileType::Regular,
            name: "C:\\f".into(),
            device: None,
            size: None,
            offset: None,
            node: None,
            links: None,
            socket: None,
            name_addition: None,
        }],
    };
    // +c 4: the COMMAND cell is truncated to 4 chars; the full name is gone.
    let capped = table::render(
        std::slice::from_ref(&p),
        TableOpts {
            command_width: Some(4),
            ..TableOpts::new(Escaper::WINDOWS)
        },
    );
    assert!(
        capped.contains("very"),
        "expected truncated command: {capped:?}"
    );
    assert!(
        !capped.contains("verylongcommandname.exe"),
        "full command should be truncated: {capped:?}"
    );
    // Without the cap, the full name is present.
    let full = table::render(
        &[p],
        TableOpts {
            command_width: None,
            ..TableOpts::new(Escaper::WINDOWS)
        },
    );
    assert!(full.contains("verylongcommandname.exe"));
}

#[test]
fn fields_skips_empty_name() {
    // `-K` thread `task` rows have no name; the -F output must not emit a bare
    // `n` field code (regression guard for the lone-`n`-line bug).
    use lsof_core::{AccessMode, FdType, FileType, OpenFile, Process};
    let p = Process {
        tid: None,
        task_command: None,
        uid: None,
        pgid: None,
        pid: 7,
        ppid: None,
        command: "x".into(),
        user: None,
        endpoint_peer: false,
        unlisted: false,
        files: vec![OpenFile {
            rdev: None,
            fs_device: None,
            file_flags: None,
            lock: None,
            fd: FdType::Task,
            access: AccessMode::Unknown,
            file_type: FileType::Thread,
            name: String::new(),
            device: None,
            size: None,
            offset: None,
            node: Some("4242".into()),
            links: None,
            socket: None,
            name_addition: None,
        }],
    };
    let out = fields::render(&[p], false, None, TcpInfoFlags::DEFAULT, Escaper::WINDOWS);
    assert!(out.contains("ftask\n"), "task FD field expected: {out:?}");
    assert!(
        out.contains("i4242\n"),
        "TID in the i field expected: {out:?}"
    );
    // No bare `n` line.
    assert!(
        !out.lines().any(|l| l == "n"),
        "bare empty n field: {out:?}"
    );
}

#[test]
fn fields_nul_terminator() {
    // -F0: every field is NUL-terminated, and each process/file set gets a NL
    // *appended* after that NUL, so a set ends `…\0\n`. Measured against
    // lsof 4.99.6: `lsof -Fcn0 -p <pid>` returns
    // `p3792\0cpython3\0\nn/tmp/x\0\nn/\0\n`. Appending rather than replacing
    // is what makes `-F0` usable at all — a consumer splitting the stream on
    // NUL, which is the whole point of the flag, otherwise gets the last field
    // of one set glued to the first field of the next.
    let out = fields::render(
        &sample_processes(),
        true,
        None,
        TcpInfoFlags::DEFAULT,
        Escaper::WINDOWS,
    );
    assert!(
        out.contains("p1000\0"),
        "fields within a set are NUL-terminated: {out:?}"
    );
    assert!(
        out.contains("\0\n"),
        "a set ends with its field's NUL and then a NL: {out:?}"
    );
    // Every field is NUL-terminated: nothing sits between a NL and the next
    // field, so splitting on NUL never yields a value with a stray letter on it.
    for field in out.split('\0') {
        // The set-closing NL rides ahead of the next field, and the stream ends
        // with one; neither is a field.
        let Some(first) = field.trim_start_matches('\n').chars().next() else {
            continue;
        };
        assert!(
            first.is_ascii_alphabetic(),
            "a NUL-split field must start with its letter: {field:?}"
        );
    }
    // Every NL-delimited set begins with a `p` or `f` structural marker.
    for set in out.split('\n').filter(|s| !s.is_empty()) {
        let first = set.chars().next().unwrap();
        assert!(
            first == 'p' || first == 'f',
            "set must start with p/f: {set:?}"
        );
    }
}

#[test]
fn fields_no_inode_for_sockets() {
    // lsof leaves `-F i` empty for sockets — the protocol goes in `P`, not the
    // inode. (Regression guard: the socket `node` carries the protocol string
    // for the table's NODE column, which must not leak into `-F i`.)
    let out = fields::render(
        &sample_processes(),
        false,
        None,
        TcpInfoFlags::DEFAULT,
        Escaper::WINDOWS,
    );
    assert!(
        !out.contains("iTCP\n"),
        "socket protocol leaked into -Fi: {out:?}"
    );
    assert!(
        !out.contains("iUDP\n"),
        "socket protocol leaked into -Fi: {out:?}"
    );
    assert!(
        out.contains("PTCP\n"),
        "protocol still reported via -FP: {out:?}"
    );
}

#[test]
fn windows_object_types_render() {
    // The all-handle scan surfaces native kernel objects (registry keys, events,
    // semaphores, …). Named variants and `FileType::Other(code)` must both show
    // their TYPE code in the table and `-F t` and carry their object-path NAME.
    use lsof_core::{AccessMode, FdType, FileType, OpenFile, Process};
    let mk = |h: u64, ft: FileType, name: &str| OpenFile {
        rdev: None,
        fs_device: None,
        file_flags: None,
        lock: None,
        fd: FdType::Handle(h),
        access: AccessMode::ReadWrite,
        file_type: ft,
        name: name.into(),
        device: None,
        size: None,
        offset: None,
        node: None,
        links: None,
        socket: None,
        name_addition: None,
    };
    let p = Process {
        tid: None,
        task_command: None,
        uid: None,
        pgid: None,
        pid: 7,
        ppid: None,
        command: "svc".into(),
        user: None,
        endpoint_peer: false,
        unlisted: false,
        files: vec![
            mk(0x1a4, FileType::Key, "\\REGISTRY\\MACHINE\\SOFTWARE"),
            mk(
                0x1a8,
                FileType::Other("SEM".into()),
                "\\BaseNamedObjects\\Foo",
            ),
        ],
    };
    let table = table::render(
        std::slice::from_ref(&p),
        TableOpts {
            command_width: None,
            ..TableOpts::new(Escaper::WINDOWS)
        },
    );
    assert!(table.contains("KEY"), "registry-key TYPE code: {table:?}");
    assert!(table.contains("SEM"), "Other object TYPE code: {table:?}");
    assert!(
        table.contains("\\REGISTRY\\MACHINE\\SOFTWARE"),
        "key path in NAME"
    );
    let f = fields::render(&[p], false, None, TcpInfoFlags::DEFAULT, Escaper::WINDOWS);
    assert!(f.contains("tKEY\n"), "-Ft KEY: {f:?}");
    assert!(f.contains("tSEM\n"), "-Ft SEM: {f:?}");
}

#[test]
fn repeat_marker_is_format_aware() {
    // lsof's `-r` cycle separator differs by format (src/main.c): `=======` for
    // the table, the `m` marker field for `-F` (NUL- then NL-terminated under
    // `-F0`), and nothing for JSON (objects self-delimit).
    use lsof_core::render::Format;
    assert_eq!(Format::Table.repeat_marker(), "=======\n");
    assert_eq!(
        Format::Fields {
            nul: false,
            only: None
        }
        .repeat_marker(),
        "m\n"
    );
    assert_eq!(
        Format::Fields {
            nul: true,
            only: None
        }
        .repeat_marker(),
        "m\0\n"
    );
    // A `-J` document ends in its own newline; the C prints one more after
    // each `-j` cycle (measured: an empty `-j -r` cycle is `\n` alone).
    let jf = |lines| {
        Format::Json(JsonFormat {
            lines,
            only: None,
            file_flags: FileFlags::Names,
            tcp_show: TcpInfoFlags::DEFAULT,
        })
    };
    assert_eq!(jf(false).repeat_marker(), "");
    assert_eq!(jf(true).repeat_marker(), "\n");
}

/// What `-J`/`-j` print with no `-F` selection: the C's default set, flags
/// by name and every TCP/TPI member.
fn dj() -> json::JsonOpts<'static> {
    json::JsonOpts {
        only: None,
        tcp_show: TcpInfoFlags {
            state: true,
            queue: true,
            window: true,
            options: false,
        },
        file_flags: FileFlags::Names,
        numeric_ids: false,
        version: "9.9.9",
    }
}

#[test]
fn json_aggregated_shape() {
    let out = json::render_aggregated(&sample_processes(), &dj());
    assert!(out.starts_with("{\"lsof_version\":\"9.9.9\",\"processes\":[{\"pid\":1000,"));
    assert!(out.ends_with("]}]}\n"));
    assert_eq!(out.matches('\n').count(), 1);
    assert!(out.contains("\"pid\":1500"));
    assert!(out.contains("\"protocol\":\"TCP\""));
    assert!(out.contains("\"tcp_info\":{\"state\":\"LISTEN\"}"));
    assert!(out.contains("\"command\":\"explorer.exe\""));
}

#[test]
fn json_lines_one_per_file() {
    let procs = sample_processes();
    let total_files: usize = procs.iter().map(|p| p.files.len()).sum();
    let out = json::render_lines(&procs, &dj());
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), total_files);
    for l in lines {
        assert!(l.starts_with('{') && l.ends_with('}'));
    }
}

#[test]
fn json_escapes_backslashes() {
    // Windows paths and DOMAIN\user must be valid JSON.
    let out = json::render_aggregated(&sample_processes(), &dj());
    assert!(out.contains("EXAMPLE\\\\alice"));
    assert!(out.contains("C:\\\\Users\\\\alice"));
}

/// One process whose command, user and single file name are whatever the test
/// says — the shape of the hostile-name checks below.
fn named(command: &str, user: &str, name: &str) -> lsof_core::model::Process {
    use lsof_core::{AccessMode, FdType, FileType, OpenFile, Process};
    Process {
        tid: None,
        task_command: None,
        uid: None,
        pgid: None,
        pid: 7,
        ppid: None,
        command: command.into(),
        user: Some(user.into()),
        endpoint_peer: false,
        unlisted: false,
        files: vec![OpenFile {
            rdev: None,
            fs_device: None,
            file_flags: None,
            lock: None,
            fd: FdType::Handle(4),
            access: AccessMode::Read,
            file_type: FileType::Regular,
            name: name.into(),
            device: None,
            size: None,
            offset: None,
            node: None,
            links: None,
            socket: None,
            name_addition: None,
        }],
    }
}

#[test]
fn hostile_names_are_escaped_the_way_the_c_prints_them() {
    // DIVERGENCES.md #10, found by the proc_status fuzz target: a `\r` — or an
    // ANSI escape — in COMMAND or NAME reached the terminal raw, on both
    // platforms. COMMAND, USER and NAME now go through lsof's safestrprt()
    // rules. The comm and the file name are the Linux differential's hostile
    // fixtures, and the expected text is what the C (4.99.6, C.UTF-8) prints
    // for them: COMMAND whitespace-free and pure ASCII, NAME with the space
    // and the é kept and the 8-bit CSI (U+009B) hex-escaped.
    let comm = "h\x1b[2J\r \\\x7f\t\u{e9}\u{9b}z";
    let file = "/tmp/n\x1b[31m\r\t \\\x7f\u{e9}\u{9b}.txt";
    let p = named(comm, "us\x1ber", file);

    let table = table::render(
        std::slice::from_ref(&p),
        TableOpts {
            command_width: None,
            ..TableOpts::new(Escaper::UNIX)
        },
    );
    let row = table.lines().nth(1).expect("one data row");
    assert!(
        row.starts_with("h^[[2J\\r\\x20\\\\\\x7f\\t\\xc3\\xa9\\xc2\\x9bz "),
        "COMMAND cell: {row:?}"
    );
    assert!(
        row.ends_with(" /tmp/n^[[31m\\r\\t \\\\\\x7f\u{e9}\\xc2\\x9b.txt"),
        "NAME cell: {row:?}"
    );
    assert!(row.contains(" us^[er "), "USER cell: {row:?}");
    assert!(
        !table.chars().any(|c| c.is_control() && c != '\n'),
        "a control character reached the table: {table:?}"
    );

    // `-F`: the values are text-mode (space kept), and the terminators cannot
    // be forged — a newline in a name is `\n`, so it is still one `n` field.
    let f = fields::render(
        std::slice::from_ref(&p),
        false,
        None,
        TcpInfoFlags::DEFAULT,
        Escaper::UNIX,
    );
    assert!(
        f.contains("ch^[[2J\\r \\\\\\x7f\\t\u{e9}\\xc2\\x9bz\n"),
        "{f:?}"
    );
    assert!(f.contains("Lus^[er\n"), "{f:?}");
    assert!(
        f.contains("n/tmp/n^[[31m\\r\\t \\\\\\x7f\u{e9}\\xc2\\x9b.txt\n"),
        "{f:?}"
    );
    let split = named("x", "u", "two\nlines");
    let f0 = fields::render(&[split], true, None, TcpInfoFlags::DEFAULT, Escaper::UNIX);
    // Under `-F0` the name's own newline is escaped, so the only real NUL and
    // the only real NL are the ones the renderer wrote: the value cannot forge
    // either boundary.
    assert!(f0.contains("ntwo\\nlines\0\n"), "{f0:?}");
    assert_eq!(
        f0.matches('\n').count(),
        2,
        "one process set, one file set: {f0:?}"
    );

    // The fuzz target's exact finding, in COMMAND.
    let q = named("PPid:\rd:Uid:", "u", "f");
    let t = table::render(
        &[q],
        TableOpts {
            command_width: None,
            ..TableOpts::new(Escaper::UNIX)
        },
    );
    assert!(t.contains("PPid:\\rd:Uid:"), "{t:?}");
}

#[test]
fn backslash_is_text_on_windows_and_escaped_on_unix() {
    // Every Windows NAME is `C:\…` and every domain user is `DOMAIN\user`; the
    // C's `\\` rule would double each separator, so on Windows the backslash is
    // text. On Unix it is escaped so `\` `n` cannot pose as a newline.
    let win = table::render(
        &sample_processes(),
        TableOpts {
            command_width: None,
            ..TableOpts::new(Escaper::WINDOWS)
        },
    );
    assert!(win.contains("C:\\Windows\\System32\\config.dat"), "{win:?}");
    assert!(win.contains("EXAMPLE\\alice"), "{win:?}");
    let unix = table::render(
        &sample_processes(),
        TableOpts {
            command_width: None,
            ..TableOpts::new(Escaper::UNIX)
        },
    );
    assert!(
        unix.contains("C:\\\\Windows\\\\System32\\\\config.dat"),
        "{unix:?}"
    );
    assert!(unix.contains("EXAMPLE\\\\alice"), "{unix:?}");
    assert_eq!(
        Escaper::for_host(),
        if cfg!(windows) {
            Escaper::WINDOWS
        } else {
            Escaper::UNIX
        }
    );
}

#[test]
fn the_command_cut_is_the_column_width_not_the_plus_c_number() {
    // `+c` caps what each row CONTRIBUTES to the column width; the cut then
    // happens at the width, which is never narrower than the `COMMAND` header.
    // So a `+c` below 7 is effectively 7 — `print.c` starts `CmdColW` at
    // `strlen("COMMAND")` and truncates with `safestrprtn(cp, CmdColW, …)`.
    //
    // Measured against lsof 4.99.6 on a process whose comm prints as
    // `a^[bcdefgh` (10 columns from 9 bytes — the width is counted after
    // escaping, and an escape is emitted only if it fits whole):
    //
    //   +c 2 / 3 / 6 -> a^[bcde     (7, the header floor)
    //   +c 8         -> a^[bcdef
    //   default (9)  -> a^[bcdefg
    //   +c 0 / 10+   -> a^[bcdefgh
    let p = named("a\x1bbcdefgh", "u", "f");
    let cell = |w: Option<usize>| -> String {
        let out = table::render(
            std::slice::from_ref(&p),
            TableOpts {
                command_width: w,
                ..TableOpts::new(Escaper::UNIX)
            },
        );
        out.lines()
            .nth(1)
            .unwrap()
            .split(' ')
            .next()
            .unwrap()
            .to_string()
    };
    for narrow in [2, 3, 6] {
        assert_eq!(cell(Some(narrow)), "a^[bcde", "+c {narrow}");
    }
    assert_eq!(cell(Some(8)), "a^[bcdef");
    assert_eq!(cell(Some(9)), "a^[bcdefg");
    assert_eq!(cell(Some(10)), "a^[bcdefgh");
    assert_eq!(cell(None), "a^[bcdefgh");
    // The default is 9, so a plain run cuts here without being asked.
    let plain = table::render(std::slice::from_ref(&p), TableOpts::new(Escaper::UNIX));
    assert_eq!(
        plain.lines().nth(1).unwrap().split(' ').next().unwrap(),
        "a^[bcdefg"
    );
}

#[test]
fn json_escapes_every_control_and_the_line_separators() {
    // JSON needs only C0 escaped; DEL, the C1 block (U+009B is the 8-bit CSI)
    // and U+2028/U+2029 are escaped too, so `-j` stays one object per line and
    // a document read on a terminal cannot drive it. Decoders see the same
    // string either way.
    let p = named("a\u{9b}b\u{2028}c\u{2029}d\x7f\x1b", "u", "f");
    let out = json::render_lines(&[p], &dj());
    assert!(
        out.contains("\"command\":\"a\\u009bb\\u2028c\\u2029d\\u007f\\u001b\""),
        "{out:?}"
    );
    assert!(!out.chars().any(|c| c.is_control() && c != '\n'), "{out:?}");
    assert_eq!(out.matches('\n').count(), 1);
}

/// One established-TCP process with `-T q/w` extended info attached — what the
/// Windows backend produces under `-Tqw` (elevated). Built directly because
/// the mock's static sample deliberately has `tcp: None` (a plain run shows
/// nothing extra).
fn tcp_info_fixture() -> Vec<lsof_core::model::Process> {
    use lsof_core::model::{
        AccessMode, FdType, FileType, OpenFile, Process, Protocol, SocketInfo, TcpExtInfo, TcpState,
    };
    let sock = SocketInfo {
        bound: None,
        protocol: Protocol::Tcp,
        local: Some("127.0.0.1:5000".parse().unwrap()),
        remote: Some("127.0.0.1:51000".parse().unwrap()),
        state: Some(TcpState::Established.into()),
        tcp: Some(TcpExtInfo {
            recv_window: Some(262144),
            recv_queue: Some(0),
            send_queue: Some(12),
        }),
    };
    vec![Process {
        tid: None,
        task_command: None,
        uid: None,
        pgid: None,
        pid: 2000,
        ppid: None,
        command: "server.exe".to_string(),
        user: Some("EXAMPLE\\alice".to_string()),
        files: vec![OpenFile {
            rdev: None,
            fs_device: None,
            file_flags: None,
            lock: None,
            fd: FdType::Handle(77),
            access: AccessMode::ReadWrite,
            file_type: FileType::Ipv4,
            name: sock.display_name(false, false),
            device: None,
            size: None,
            offset: None,
            node: Some("TCP".to_string()),
            links: None,
            socket: Some(Box::new(sock)),
            name_addition: None,
        }],
        endpoint_peer: false,
        unlisted: false,
    }]
}

#[test]
fn tcp_info_table_suffix_is_one_group() {
    // ONE parenthesised group, space-separated, in `print_tcptpi()`'s fixed
    // order — not one group per fact. Measured against lsof 4.99.6:
    // `-T qs` gives `127.0.0.1:53431 (LISTEN QR=0 QS=0)`.
    let all = TcpInfoFlags {
        state: true,
        queue: true,
        window: true,
        options: false,
    };
    let out = table::render(
        &tcp_info_fixture(),
        TableOpts {
            command_width: None,
            tcp_show: all,
            ..TableOpts::new(Escaper::WINDOWS)
        },
    );
    assert!(
        out.contains("(ESTABLISHED Win=262144 QR=0 QS=12)"),
        "one space-separated group expected: {out:?}"
    );
}

#[test]
fn tcp_info_selects_rather_than_adds() {
    // `-T q` is the queues *instead of* the state: the C zeroes `Ftcptpi`
    // before ORing the letters in, so asking for one thing deselects the
    // others. Measured: `lsof -T q` gives `(QR=0 QS=0)`, no state.
    let cell = |show: TcpInfoFlags| -> String {
        table::render(
            &tcp_info_fixture(),
            TableOpts {
                command_width: None,
                tcp_show: show,
                ..TableOpts::new(Escaper::WINDOWS)
            },
        )
    };
    let queues = cell(TcpInfoFlags {
        queue: true,
        ..TcpInfoFlags::default()
    });
    assert!(queues.contains("(QR=0 QS=12)"), "{queues:?}");
    assert!(
        !queues.contains("ESTABLISHED"),
        "-T q must not keep the state: {queues:?}"
    );

    let state = cell(TcpInfoFlags::DEFAULT);
    assert!(state.contains("(ESTABLISHED)"), "{state:?}");
    assert!(!state.contains("QR="), "{state:?}");

    // A bare `-T` selects nothing, and then not even the separator is written.
    let none = cell(TcpInfoFlags::default());
    assert!(!none.contains("ESTABLISHED"), "{none:?}");
    assert!(!none.contains("QR="), "{none:?}");
    assert!(
        none.lines().nth(1).is_some_and(|l| !l.ends_with(' ')),
        "a bare -T leaves no separator: {none:?}"
    );
}

#[test]
fn a_selected_but_empty_tcp_group_still_writes_its_separator() {
    // The C writes the separator space before it knows whether
    // `print_tcptpi()` will print anything: `print.c` gates on `Ftcptpi` being
    // non-zero and the row being a resolved socket, so `lsof -T f` on Linux
    // leaves a trailing space on EVERY socket row. Reproduced deliberately —
    // the differential's normalizer strips trailing whitespace, so this test is
    // the only thing that holds it.
    let options_only = TcpInfoFlags {
        options: true,
        ..TcpInfoFlags::default()
    };
    let out = table::render(
        &tcp_info_fixture(),
        TableOpts {
            command_width: None,
            tcp_show: options_only,
            ..TableOpts::new(Escaper::WINDOWS)
        },
    );
    let row = out.lines().nth(1).expect("a socket row");
    assert!(
        row.ends_with(' '),
        "expected the dangling separator: {row:?}"
    );
    assert!(!row.contains('('), "nothing should have printed: {row:?}");
}

#[test]
fn tcp_info_fields_tokens() {
    // Structured `T` tokens with lsof's own prefixes (QR/QS/WR), after ST=;
    // the n (name) field stays clean of the table-only suffix. `-T` gates these
    // in `-F` exactly as it gates the table suffix — `print_tcptpi()` consults
    // `Ftcptpi` in both modes — so the flags have to ask for them.
    let all = TcpInfoFlags {
        state: true,
        queue: true,
        window: true,
        options: false,
    };
    let out = fields::render(&tcp_info_fixture(), false, None, all, Escaper::WINDOWS);
    assert!(
        out.contains("TST=ESTABLISHED\nTQR=0\nTQS=12\nTWR=262144\n"),
        "{out:?}"
    );
    assert!(
        !out.contains("(Win="),
        "-F must not leak the table suffix into the name field: {out:?}"
    );
    // And `-T q` drops ST= from `-F` too, not just from the table.
    let queues = fields::render(
        &tcp_info_fixture(),
        false,
        None,
        TcpInfoFlags {
            queue: true,
            ..TcpInfoFlags::default()
        },
        Escaper::WINDOWS,
    );
    assert!(queues.contains("TQR=0\n"), "{queues:?}");
    assert!(!queues.contains("TST="), "{queues:?}");
}

#[test]
fn tcp_info_json_keys() {
    // The C's members, in its order (`print.c:1996-2043`): read_window is
    // `-T w`'s, which the Windows backend fills; Linux has none.
    let out = json::render_aggregated(&tcp_info_fixture(), &dj());
    assert!(
        out.contains(
            "\"tcp_info\":{\"state\":\"ESTABLISHED\",\"recv_queue\":0,\"send_queue\":12,\"read_window\":262144}"
        ),
        "{out:?}"
    );
    assert!(!out.contains("(Win="), "JSON name must stay clean: {out:?}");
    assert!(!out.contains("write_window"), "{out:?}");
    // And absent info stays absent: the plain mock sample has no queues.
    assert!(!json::render_aggregated(&sample_processes(), &dj()).contains("_queue"));
}

#[test]
fn fields_follow_the_cs_order() {
    // `print.c` walks a fixed sequence and prints each selected field that has
    // a value. Order is not cosmetic: a `-F` consumer that treats the first `T`
    // after `n` as the end of a record mis-parses a differently ordered stream.
    // Measured against lsof 4.99.6 on a live fixture, one field per line:
    //   f a l t G d D s o i k P n  TST= TQR= TQS=
    let out = fields::render(
        &sample_processes(),
        false,
        None,
        TcpInfoFlags::DEFAULT,
        Escaper::WINDOWS,
    );
    let letters: Vec<char> = out.lines().filter_map(|l| l.chars().next()).collect();
    // The process set comes first and starts with `p`, the one field Lsof.8
    // calls "always selected".
    assert_eq!(letters[0], 'p', "{out:?}");
    // Within one file set, the letters appear in this relative order.
    const ORDER: &str = "faltGdDsoikPnT";
    let mut seen_file_set = false;
    let mut last = 0usize;
    for c in letters {
        if c == 'f' {
            seen_file_set = true;
            last = 0;
        }
        if !seen_file_set {
            continue;
        }
        let Some(pos) = ORDER.find(c) else { continue };
        assert!(
            pos >= last,
            "field {c:?} came after a later field in {out:?}"
        );
        last = pos;
    }
}

#[test]
fn fields_report_a_sockets_node_cell_as_p_never_as_i() {
    // `i` and `P` are one cell under two names, and the C picks between them
    // with one discriminant (`Lf->inp_ty`): an internet socket's NODE *is* its
    // protocol, so it comes out as `P` and never as `i`. (An AF_UNIX socket
    // takes the other branch — see the `sockets-unix-fields-F` differential
    // case, which has a real /proc to read.)
    let out = fields::render(
        &sample_processes(),
        false,
        None,
        TcpInfoFlags::DEFAULT,
        Escaper::WINDOWS,
    );
    assert!(out.contains("PTCP\n"), "{out:?}");
    assert!(out.contains("PUDP\n"), "{out:?}");
    assert!(!out.contains("iTCP"), "protocol leaked into i: {out:?}");
    // The mock's sockets carry no inode, so no socket row may emit `i` at all;
    // the only `i` in the output belongs to the regular file.
    assert_eq!(out.matches("\ni").count(), 1, "{out:?}");
}

#[test]
fn a_sockets_state_is_reported_once_and_in_its_own_field() {
    // Baking the state into NAME reported it twice — in the table's NAME cell
    // (once from the name, once from the suffix) and in both the `n` and `T`
    // fields of `-F`. It lives in `SocketInfo::state`, and each renderer places
    // it: a table suffix, a `TST=` token, a JSON key.
    let t = table::render(
        &sample_processes(),
        TableOpts {
            command_width: None,
            ..TableOpts::new(Escaper::WINDOWS)
        },
    );
    assert_eq!(t.matches("(LISTEN)").count(), 1, "{t:?}");
    assert_eq!(t.matches("(ESTABLISHED)").count(), 1, "{t:?}");

    let f = fields::render(
        &sample_processes(),
        false,
        None,
        TcpInfoFlags::DEFAULT,
        Escaper::WINDOWS,
    );
    assert!(f.contains("n*:445\n"), "state in the n field: {f:?}");
    assert!(f.contains("TST=LISTEN\n"), "{f:?}");
    assert_eq!(f.matches("LISTEN").count(), 1, "{f:?}");

    let j = json::render_aggregated(&sample_processes(), &dj());
    assert!(j.contains("\"tcp_info\":{\"state\":\"LISTEN\"}"), "{j:?}");
    assert_eq!(j.matches("LISTEN").count(), 1, "{j:?}");
    assert!(j.contains("\"name\":\"*:445\""), "{j:?}");
}

#[test]
fn the_f_marker_is_emitted_for_a_row_with_no_handle_value() {
    // A backend that cannot name a row's fd still gets an `f` marker under bare
    // `-F` — the value is the FD *code*, `unk`, not a number. The Windows
    // backend's socket rows are exactly this shape: `GetExtendedTcpTable` has
    // no handle value to give (`sockets.rs`), so every `-iTCP:… -F` row there
    // is `funk`. Guarding it here rather than only in the Windows smoke suite,
    // because "the fd field is numeric" is the kind of stronger-than-true
    // proxy that reads as obvious and holds on exactly one platform — it was
    // asserted in that suite and only a real Windows runner disproved it.
    use lsof_core::{AccessMode, FdType, FileType, OpenFile, Process, Protocol, SocketInfo};
    let p = Process {
        tid: None,
        task_command: None,
        uid: None,
        pgid: None,
        pid: 7,
        ppid: None,
        command: "server.exe".into(),
        user: None,
        endpoint_peer: false,
        unlisted: false,
        files: vec![OpenFile {
            rdev: None,
            fs_device: None,
            file_flags: None,
            lock: None,
            fd: FdType::Unknown,
            access: AccessMode::ReadWrite,
            file_type: FileType::Ipv4,
            name: "*:445".into(),
            device: None,
            size: None,
            offset: None,
            node: Some("TCP".into()),
            links: None,
            socket: Some(Box::new(SocketInfo {
                bound: None,
                protocol: Protocol::Tcp,
                local: None,
                remote: None,
                state: None,
                tcp: None,
            })),
            name_addition: None,
        }],
    };
    let out = fields::render(&[p], false, None, TcpInfoFlags::DEFAULT, Escaper::WINDOWS);
    assert!(out.contains("funk\n"), "{out:?}");
    // And a list that does not name `f` still has none, whatever the value.
    let only = fields::render(
        std::slice::from_ref(&sample_processes()[1]),
        false,
        Some(&['n']),
        TcpInfoFlags::DEFAULT,
        Escaper::WINDOWS,
    );
    assert!(!only.lines().any(|l| l.starts_with('f')), "{only:?}");
}

#[test]
fn a_restricted_field_list_emits_only_those_letters() {
    // `-Fcn`: `p` is always selected, `f` is not — the C emits the `f` marker
    // only when it is asked for, so a consumer keying on `f` to start a file
    // record must not see one here.
    let out = fields::render(
        &sample_processes(),
        false,
        Some(&['c', 'n']),
        TcpInfoFlags::DEFAULT,
        Escaper::WINDOWS,
    );
    for line in out.lines().filter(|l| !l.is_empty()) {
        let c = line.chars().next().unwrap();
        assert!(
            c == 'p' || c == 'c' || c == 'n',
            "unselected field {c:?} emitted: {out:?}"
        );
    }
    assert!(out.contains("cserver.exe\n"), "{out:?}");
    assert!(out.contains("n*:445\n"), "{out:?}");
}

/// `-F r` (DIVERGENCES 47): the device a character or block special names,
/// in hex, after `D`, measured against the C on `/dev/null` (`r0x103`) and a
/// pty slave (`r0x8800`). A bare `-F` leaves it out, "for compatibility", and
/// a row with no raw device prints no `r` at all.
#[test]
fn the_raw_device_field_is_only_asked_for_and_only_on_devices() {
    use lsof_core::{AccessMode, FdType, FileType};
    let mut null = row(
        FdType::Handle(0),
        AccessMode::Read,
        None,
        FileType::Chr,
        "1,3",
        None,
        Some(0),
        "3",
        "/dev/null",
    );
    null.fs_device = Some(0x6);
    null.rdev = std::num::NonZeroU32::new(0x103);
    let mut pts = null.clone();
    pts.fd = FdType::Handle(7);
    pts.rdev = std::num::NonZeroU32::new(0x8800);
    pts.name = "/dev/pts/0".into();
    let plain = row(
        FdType::Handle(3),
        AccessMode::Write,
        None,
        FileType::Regular,
        "254,0",
        Some(1),
        None,
        "12",
        "/tmp/f",
    );
    let p = python3(vec![null, pts, plain]);
    let render = |only: Option<&[char]>| {
        fields::render(
            std::slice::from_ref(&p),
            false,
            only,
            TcpInfoFlags::DEFAULT,
            Escaper::UNIX,
        )
    };
    assert_eq!(
        render(Some(&['f', 'D', 'r'])),
        "p496\nf0\nD0x6\nr0x103\nf7\nD0x6\nr0x8800\nf3\n",
    );
    let bare = render(None);
    assert!(!bare.lines().any(|l| l.starts_with('r')), "{bare:?}");
    assert!(
        bare.contains("\nD0x6\n"),
        "the rest of the default set: {bare:?}"
    );
}

/// `+f g`, `+f G` and `-F G` (DIVERGENCES 46), against the C's own bytes: four
/// fds of the flags fixture of 2026-09-28, printed by the C with
/// `lsof -n -P +fg -a -d 3,8,13,14 -p P` (paths shortened; NAME is the last
/// column and unpadded, so that changes nothing else). FILE-FLAG follows TYPE,
/// right-aligned and at least as wide as its title; the C's table order
/// decides which name a shared bit gets.
#[test]
fn the_file_flags_column_is_the_cs() {
    use lsof_core::render::FileFlags;
    use lsof_core::{AccessMode, FdType, FileType};
    let reg = |fd: u64, access, flags: u32, node: &str, name: &str| {
        let mut f = row(
            FdType::Handle(fd),
            access,
            None,
            FileType::Regular,
            "254,0",
            Some(0),
            None,
            node,
            name,
        );
        f.file_flags = Some(flags);
        f
    };
    let mut p = python3(vec![
        reg(3, AccessMode::Write, 0o2102001, "1917894", "/w/f"),
        reg(8, AccessMode::ReadWrite, 0o12000000, "1917894", "/w/f"),
        reg(13, AccessMode::ReadWrite, 0o2100003, "1917894", "/w/f"),
        reg(
            14,
            AccessMode::ReadWrite,
            0o22300002,
            "1917895",
            "/w/#1917895 (deleted)",
        ),
    ]);
    p.pid = 9850;
    let table_with = |file_flags| {
        table::render(
            std::slice::from_ref(&p),
            TableOpts {
                file_flags,
                ..TableOpts::new(Escaper::UNIX)
            },
        )
    };
    assert_eq!(
        table_with(FileFlags::Names),
        concat!(
            "COMMAND  PID USER FD   TYPE         FILE-FLAG DEVICE SIZE/OFF    NODE NAME\n",
            "python3 9850 root  3w   REG        W,AP,LG,CX  254,0        0 1917894 /w/f\n",
            "python3 9850 root  8u   REG           CX,PATH  254,0        0 1917894 /w/f\n",
            "python3 9850 root 13u   REG        W,RW,LG,CX  254,0        0 1917894 /w/f\n",
            "python3 9850 root 14u   REG RW,DTY,LG,CX,TMPF  254,0        0 1917895 /w/#1917895 (deleted)\n",
        )
    );
    assert_eq!(
        table_with(FileFlags::Hex),
        concat!(
            "COMMAND  PID USER FD   TYPE    FILE-FLAG DEVICE SIZE/OFF    NODE NAME\n",
            "python3 9850 root  3w   REG  0x88401;0x0  254,0        0 1917894 /w/f\n",
            "python3 9850 root  8u   REG 0x280000;0x0  254,0        0 1917894 /w/f\n",
            "python3 9850 root 13u   REG  0x88003;0x0  254,0        0 1917894 /w/f\n",
            "python3 9850 root 14u   REG 0x498002;0x0  254,0        0 1917895 /w/#1917895 (deleted)\n",
        )
    );
    assert!(
        !table_with(FileFlags::Off).contains("FILE-FLAG"),
        "no column unless asked for"
    );
    // `-F faG +fg`: the same names in the `G` field.
    let fields_with = |file_flags| {
        fields::render_with_offset_digits(
            std::slice::from_ref(&p),
            false,
            Some(&['f', 'a', 'G']),
            TcpInfoFlags::DEFAULT,
            Escaper::UNIX,
            lsof_core::render::DEFAULT_OFFSET_DIGITS,
            file_flags,
        )
    };
    assert_eq!(
        fields_with(FileFlags::Names),
        "p9850\nf3\naw\nGW,AP,LG,CX\nf8\nau\nGCX,PATH\nf13\nau\nGW,RW,LG,CX\nf14\nau\nGRW,DTY,LG,CX,TMPF\n"
    );
    assert!(
        !fields_with(FileFlags::Off).contains("\nG"),
        "`-F -fG`: no G field"
    );
}

/// One regular-file row carrying `size` and `offset`, for the `-H` cases.
fn sized(size: Option<u64>, offset: Option<u64>) -> lsof_core::model::Process {
    let mut p = named("app", "root", "/tmp/f");
    p.files[0].size = size;
    p.files[0].offset = offset;
    p
}

/// The SIZE/OFF cell of the first data row — under whichever of the column's
/// three headers the options chose (`SIZE/OFF`, `-o`'s `OFFSET`, `-s`'s `SIZE`).
fn size_cell(p: &lsof_core::model::Process, opts: TableOpts) -> String {
    let out = table::render(std::slice::from_ref(p), opts);
    let header = out.lines().next().unwrap();
    let (col, name) = ["SIZE/OFF", "OFFSET", "SIZE"]
        .iter()
        .find_map(|h| header.find(h).map(|c| (c, *h)))
        .expect("a size/offset header");
    let end = col + name.len();
    out.lines().nth(1).unwrap()[..end]
        .trim_end()
        .rsplit(' ')
        .next()
        .unwrap()
        .to_string()
}

#[test]
fn human_size_reproduces_the_cs_scale_exactly() {
    // DIVERGENCES: `-H` was waived as a "legacy headers toggle on certain
    // dialects". In lsof 4.99.6 it is human-readable sizes, and the C's
    // `human_readable_size()` (print.c) is idiosyncratic in three ways this
    // pins. Every pair below was READ OFF THE ORACLE on sparse files of that
    // exact length, not derived from the source.
    let h = |n: u64| {
        let mut o = TableOpts::new(Escaper::UNIX);
        o.human_size = true;
        size_cell(&sized(Some(n), None), o)
    };

    // 1. Under 1024 is a raw count with a `B`, not `0.5K`.
    for (n, want) in [(0u64, "0B"), (1, "1B"), (512, "512B"), (1023, "1023B")] {
        assert_eq!(h(n), want, "{n}");
    }

    // 2. The divide truncates before it scales: 2125328 / 1024 = 2075 (not
    //    2075.5), then / 1024.0 = 2.026 -> "2.0M".
    for (n, want) in [
        (1024u64, "1.0K"),
        (1025, "1.0K"),
        (1536, "1.5K"),
        (10240, "10.0K"),
        (27028, "26.4K"),
        (2125328, "2.0M"),
        (6639992, "6.3M"),
        (1572864, "1.5M"),
        // These three separate the C's order of operations from the obvious
        // `sz as f64 / unit as f64`, which agrees everywhere else. A mutation
        // to pure floating division survived this test until they were added:
        // it would print 24.7M / 154.1M / 396.1M. Oracle-checked on sparse
        // files of exactly these lengths.
        (25847420, "24.6M"),
        (161533414, "154.0M"),
        (415288979, "396.0M"),
    ] {
        assert_eq!(h(n), want, "{n}");
    }

    // 3. The suffix is chosen BEFORE rounding, so just under a boundary the C
    //    prints 1024.0 of the smaller unit rather than 1.0 of the larger. This
    //    is the rule most likely to be "fixed" by someone tidying up.
    for (n, want) in [
        (1048575u64, "1024.0K"),
        (1048576, "1.0M"),
        (1073741823, "1024.0M"),
        (1073741824, "1.0G"),
        (1099511627775, "1024.0G"),
        (1099511627776, "1.0T"),
    ] {
        assert_eq!(h(n), want, "{n}");
    }

    // Ties round half-to-even, as C's %.1lf does: 174336 is exactly 170.25 KiB.
    assert_eq!(h(174336), "170.2K");
    // The top of the range must not panic on the C's overflowing last step.
    assert_eq!(h(u64::MAX), "16.0E");
}

#[test]
fn human_size_scales_the_size_and_never_the_offset() {
    // print.c humanises inside the `sz_def` branch alone. A row with only an
    // offset falls back to `0t<dec>` under `-H` exactly as it does without it —
    // measured on a FIFO, which the C renders `0t0` with and without `-H`.
    let mut human = TableOpts::new(Escaper::UNIX);
    human.human_size = true;
    let mut plain = TableOpts::new(Escaper::UNIX);
    plain.human_size = false;

    let off_only = sized(None, Some(4096));
    assert_eq!(size_cell(&off_only, plain), "0t4096");
    assert_eq!(
        size_cell(&off_only, human),
        "0t4096",
        "-H must not touch an offset"
    );

    // And with `-o` the offset wins even though a size is present, so `-H` has
    // nothing to scale.
    let both = sized(Some(1048576), Some(4096));
    assert_eq!(size_cell(&both, human), "1.0M");
    let mut human_o = human;
    human_o.show_offset = true;
    assert_eq!(size_cell(&both, human_o), "0t4096");
}

#[test]
fn human_size_is_table_only() {
    // The C's `-F` and JSON writers never consult Fhuman: `lsof -H -Fs` and
    // `lsof -H -J` are byte-identical to the runs without `-H`. Nothing in this
    // port may quietly humanise a machine-readable format either.
    let p = sized(Some(1048576), None);
    let procs = std::slice::from_ref(&p);
    assert!(
        fields::render(procs, false, None, TcpInfoFlags::DEFAULT, Escaper::UNIX)
            .contains("s1048576"),
        "-F must stay in raw bytes"
    );
    assert!(
        json::render_aggregated(procs, &dj()).contains("\"size\":\"1048576\""),
        "JSON must stay in raw bytes"
    );
}

/// One AF_PACKET row exactly as the Linux backend builds it: the inode in
/// DEVICE, the ethernet protocol in NODE, `type=SOCK_RAW` as the whole NAME.
/// Measured against the C on a live fixture:
///
/// ```text
/// python3 835 root 3u pack 1399 0t0 ALL type=SOCK_RAW
/// ```
fn packet_row() -> Vec<lsof_core::model::Process> {
    use lsof_core::model::{Protocol, SocketInfo};
    use lsof_core::{AccessMode, FdType, FileType, OpenFile, Process};
    vec![Process {
        tid: None,
        task_command: None,
        uid: Some(0),
        pgid: None,
        pid: 835,
        ppid: None,
        command: "python3".into(),
        user: Some("root".into()),
        endpoint_peer: false,
        unlisted: false,
        files: vec![OpenFile {
            rdev: None,
            fs_device: None,
            file_flags: None,
            lock: None,
            fd: FdType::Handle(3),
            access: AccessMode::ReadWrite,
            file_type: FileType::Other("pack".into()),
            name: "type=SOCK_RAW".into(),
            device: Some("1399".into()),
            size: None,
            offset: Some(0),
            node: Some("ALL".into()),
            links: None,
            socket: Some(Box::new(SocketInfo {
                bound: None,
                protocol: Protocol::Other("packet"),
                local: None,
                remote: None,
                state: None,
                tcp: None,
            })),
            name_addition: None,
        }],
    }]
}

#[test]
fn a_packet_rows_node_reaches_dash_f_as_p_not_as_i() {
    // The C picks between `i` and `P` on one discriminant and fills the chosen
    // one from the NODE cell (`Lf->inp_ty`). For TCP that is indistinguishable
    // from reading `socket.protocol`, because the two strings are equal. For
    // AF_PACKET they are not: the protocol names the *family* and NODE names
    // the ethernet protocol, and `PALL` is what the oracle emits.
    let out = fields::render(
        &packet_row(),
        false,
        None,
        TcpInfoFlags::DEFAULT,
        Escaper::UNIX,
    );
    assert!(
        out.contains("PALL\n"),
        "-FP should be the NODE cell: {out:?}"
    );
    assert!(
        !out.contains("Ppacket\n"),
        "-FP must not be socket.protocol: {out:?}"
    );
    assert!(
        !out.contains("i1399\n") && !out.contains("iALL\n"),
        "a socket row has no -Fi: {out:?}"
    );
    assert!(out.contains("tpack\n"), "TYPE: {out:?}");
    assert!(out.contains("d1399\n"), "DEVICE is the inode: {out:?}");
    assert!(out.contains("o0t0\n"), "SIZE/OFF is the offset: {out:?}");
    assert!(out.contains("ntype=SOCK_RAW\n"), "NAME: {out:?}");
}

#[test]
fn a_packet_row_renders_in_the_table_and_in_json() {
    let t = table::render(&packet_row(), TableOpts::new(Escaper::UNIX));
    let row = t
        .lines()
        .find(|l| l.contains("pack"))
        .expect("a pack row in the table");
    // NODE is the ethernet protocol; DEVICE is the inode. Both appear, and the
    // inode must not also show up as NODE.
    let cells: Vec<&str> = row.split_whitespace().collect();
    assert_eq!(cells[4], "pack", "TYPE: {row:?}");
    assert_eq!(cells[5], "1399", "DEVICE: {row:?}");
    assert_eq!(cells[6], "0t0", "SIZE/OFF: {row:?}");
    assert_eq!(cells[7], "ALL", "NODE: {row:?}");
    assert_eq!(cells[8], "type=SOCK_RAW", "NAME: {row:?}");

    // The C's JSON: NODE is the protocol, as `-F P` prints it, and a packet
    // row has no TCP/TPI record (measured: `"protocol":"ALL"`, no tcp_info).
    let j = json::render_lines(&packet_row(), &dj());
    assert!(j.contains("\"type\":\"pack\""), "{j}");
    assert!(j.contains("\"protocol\":\"ALL\""), "{j}");
    assert!(!j.contains("\"inode\""), "{j}");
    assert!(!j.contains("tcp_info"), "{j}");
}

#[test]
fn an_af_unix_row_reports_its_inode_as_i_and_has_no_p() {
    // The other side of the `Lf->inp_ty` discriminant, and the one no fixture
    // covered: AF_UNIX is the single socket family whose NODE is an inode, so
    // it takes the `i` branch like a regular file. Measured against the C on a
    // live fixture — `i3939`, `ntype=STREAM`, `TST=CONNECTED`, and no `P` line
    // anywhere in the set.
    use lsof_core::model::{Protocol, SocketInfo, UnixState};
    use lsof_core::{AccessMode, FdType, FileType, OpenFile, Process};
    let procs = vec![Process {
        tid: None,
        task_command: None,
        uid: Some(0),
        pgid: None,
        pid: 992,
        ppid: None,
        command: "python3".into(),
        user: Some("root".into()),
        endpoint_peer: false,
        unlisted: false,
        files: vec![OpenFile {
            rdev: None,
            fs_device: None,
            file_flags: None,
            lock: None,
            fd: FdType::Handle(0),
            access: AccessMode::ReadWrite,
            file_type: FileType::Unix,
            name: "type=STREAM".into(),
            device: Some("0x0000000077f6ffc1".into()),
            size: None,
            offset: Some(0),
            node: Some("3939".into()),
            links: None,
            socket: Some(Box::new(SocketInfo {
                bound: None,
                protocol: Protocol::Other("unix"),
                local: None,
                remote: None,
                state: Some(UnixState::Connected.into()),
                tcp: None,
            })),
            name_addition: None,
        }],
    }];
    let out = fields::render(&procs, false, None, TcpInfoFlags::DEFAULT, Escaper::UNIX);
    assert!(out.contains("i3939\n"), "unix NODE is its inode: {out:?}");
    assert!(
        !out.lines().any(|l| l.starts_with('P')),
        "a unix row has no -FP field at all: {out:?}"
    );
    assert!(out.contains("tunix\n"), "{out:?}");
    assert!(
        out.contains("d0x0000000077f6ffc1\n"),
        "DEVICE is the pcb: {out:?}"
    );
}

/// One row, spelled out: every golden below is laid out from real `lsof`
/// output, so its cells are the ones the C printed.
#[allow(clippy::too_many_arguments)]
fn row(
    fd: lsof_core::FdType,
    access: lsof_core::AccessMode,
    lock: Option<lsof_core::model::LockKind>,
    ty: lsof_core::FileType,
    device: &str,
    size: Option<u64>,
    offset: Option<u64>,
    node: &str,
    name: &str,
) -> lsof_core::OpenFile {
    lsof_core::OpenFile {
        rdev: None,
        fs_device: None,
        file_flags: None,
        lock,
        fd,
        access,
        file_type: ty,
        name: name.into(),
        device: Some(device.into()),
        size,
        offset,
        node: Some(node.into()),
        links: None,
        socket: None,
        name_addition: None,
    }
}

fn python3(files: Vec<lsof_core::OpenFile>) -> lsof_core::Process {
    lsof_core::Process {
        tid: None,
        task_command: None,
        uid: Some(0),
        pgid: Some(496),
        pid: 496,
        ppid: Some(493),
        command: "python3".into(),
        user: Some("root".into()),
        files,
        endpoint_peer: false,
        unlisted: false,
    }
}

/// The table's layout is `print.c`'s, byte for byte (DIVERGENCES 35). These
/// four lines are the C's own output for the process they describe, copied
/// with `cat -A`: every column right-aligned but COMMAND; FD the descriptor
/// right-aligned, then an access character and a lock character that are
/// always there (a space when there is none); NAME after one space, unpadded.
/// lsof-rs had left-aligned USER, FD, TYPE, DEVICE and NODE — which the
/// differential could not see, because it collapsed whitespace until then.
#[test]
fn the_table_is_laid_out_the_way_print_c_lays_it_out() {
    use lsof_core::model::LockKind;
    use lsof_core::{AccessMode as A, FdType as Fd, FileType as T};
    let p = python3(vec![
        row(
            Fd::Cwd,
            A::Unknown,
            None,
            T::Dir,
            "254,0",
            Some(4096),
            None,
            "475157",
            "/home/user/lsof",
        ),
        row(
            Fd::Handle(0),
            A::ReadWrite,
            None,
            T::Unix,
            "0x00000000b83b321e",
            None,
            Some(0),
            "281",
            "type=STREAM (CONNECTED)",
        ),
        row(
            Fd::Handle(4),
            A::Write,
            Some(LockKind::WriteFull),
            T::Regular,
            "254,0",
            Some(0),
            Some(0),
            "1884552",
            "/tmp/locked",
        ),
        row(
            Fd::Handle(18),
            A::Read,
            None,
            T::Fifo,
            "0,15",
            None,
            Some(0),
            "3757",
            "pipe",
        ),
    ]);
    let out = table::render(std::slice::from_ref(&p), TableOpts::new(Escaper::UNIX));
    assert_eq!(
        out,
        "COMMAND PID USER  FD   TYPE             DEVICE SIZE/OFF    NODE NAME\n\
         python3 496 root cwd    DIR              254,0     4096  475157 /home/user/lsof\n\
         python3 496 root   0u  unix 0x00000000b83b321e      0t0     281 type=STREAM (CONNECTED)\n\
         python3 496 root   4wW  REG              254,0        0 1884552 /tmp/locked\n\
         python3 496 root  18r  FIFO               0,15      0t0    3757 pipe\n"
    );
}

/// Two details of the C's FD column, both reproduced.
///
/// * FD is sized by its descriptors and not its title: `FdColW` starts at
///   `strlen("FD")` and the descriptor is printed in `FdColW - 2`. When every
///   descriptor is one character, the `FD` title overruns its one-character
///   field and the rest of the HEADER sits one column right of the rows.
///   Measured, `lsof -d 0-9`.
/// * A lock with no access mode shows `-` in the access place. Read from
///   `print.c`, not measured: no host here holds a lock on an fd whose
///   access its fdinfo cannot report.
#[test]
fn a_one_character_fd_field_lets_the_title_overrun_it() {
    use lsof_core::model::LockKind;
    use lsof_core::{AccessMode as A, FdType as Fd, FileType as T};
    let p = python3(vec![
        row(
            Fd::Handle(1),
            A::Write,
            None,
            T::Regular,
            "254,0",
            Some(436),
            Some(0),
            "1884511",
            "/tmp/out",
        ),
        row(
            Fd::Handle(5),
            A::Unknown,
            Some(LockKind::ReadFull),
            T::Fifo,
            "0,15",
            None,
            Some(0),
            "3757",
            "pipe",
        ),
    ]);
    let out = table::render(std::slice::from_ref(&p), TableOpts::new(Escaper::UNIX));
    assert_eq!(
        out,
        "COMMAND PID USER FD   TYPE DEVICE SIZE/OFF    NODE NAME\n\
         python3 496 root 1w   REG  254,0      436 1884511 /tmp/out\n\
         python3 496 root 5-R FIFO   0,15      0t0    3757 pipe\n"
    );
}

/// USER when there is no name to show — `-l`, or a UID no account has. The
/// C prints the number with `printuid()`'s `"%*lu"`, eight wide, so the column
/// is never narrower than that; and `-F` writes no `L` field for it, where it
/// does for a name (DIVERGENCES 36). JSON keeps the number, as it always had.
#[test]
fn a_numeric_user_is_eight_wide_and_has_no_login_field() {
    use lsof_core::{AccessMode as A, FdType as Fd, FileType as T};
    let mut p = python3(vec![row(
        Fd::Cwd,
        A::Unknown,
        None,
        T::Dir,
        "254,0",
        Some(4096),
        None,
        "475157",
        "/home/user/lsof",
    )]);
    p.user = None;
    let out = table::render(std::slice::from_ref(&p), TableOpts::new(Escaper::UNIX));
    assert_eq!(
        out,
        "COMMAND PID     USER  FD   TYPE DEVICE SIZE/OFF   NODE NAME\n\
         python3 496        0 cwd    DIR  254,0     4096 475157 /home/user/lsof\n"
    );
    let only = ['p', 'L'];
    let f = fields::render(
        std::slice::from_ref(&p),
        false,
        Some(&only),
        TcpInfoFlags::DEFAULT,
        Escaper::UNIX,
    );
    assert_eq!(f, "p496\n", "no L field for a number");
    let j = json::render_lines(std::slice::from_ref(&p), &dj());
    assert!(j.contains("\"uid\":0,"), "{j}");
    assert!(!j.contains("\"login\""), "{j}");
    assert!(!j.contains("\"user\""), "{j}");
}

/// NLINK's cell is formatted `" %ld"` — with its leading space — before it is
/// measured, so a five-digit count makes the column six wide. Measured on a
/// directory holding 12343 subdirectories (12345 links).
#[test]
fn a_five_digit_link_count_widens_nlink_by_its_leading_space() {
    use lsof_core::{AccessMode as A, FdType as Fd, FileType as T};
    let mut cwd = row(
        Fd::Cwd,
        A::Unknown,
        None,
        T::Dir,
        "254,0",
        Some(245760),
        None,
        "1884285",
        "/d",
    );
    cwd.links = Some(12345);
    let mut txt = row(
        Fd::Txt,
        A::Unknown,
        None,
        T::Regular,
        "254,0",
        Some(35336),
        None,
        "151615",
        "/usr/bin/sleep",
    );
    txt.links = Some(1);
    let mut p = python3(vec![cwd, txt]);
    p.command = "sleep".into();
    p.pid = 7258;
    let out = table::render(
        std::slice::from_ref(&p),
        TableOpts {
            show_links: true,
            ..TableOpts::new(Escaper::UNIX)
        },
    );
    assert_eq!(
        out,
        "COMMAND  PID USER  FD   TYPE DEVICE SIZE/OFF  NLINK    NODE NAME\n\
         sleep   7258 root cwd    DIR  254,0   245760  12345 1884285 /d\n\
         sleep   7258 root txt    REG  254,0    35336      1  151615 /usr/bin/sleep\n"
    );
}

/// The `-T` separator goes on a row the C keeps a TCP/TPI record for — TCP,
/// UDP and AF_UNIX — even when there is nothing after it, and on no other.
/// A packet socket's NAME ended in a space the C does not print; comparing
/// whitespace found it.
#[test]
fn only_tcp_udp_and_unix_rows_carry_the_dash_t_separator() {
    use lsof_core::model::{SocketInfo, TcpState};
    use lsof_core::{AccessMode as A, FdType as Fd, FileType as T, Protocol};
    let sock = |fd: u64, ty: T, proto: Protocol, state: Option<TcpState>, name: &str| {
        let mut f = row(
            Fd::Handle(fd),
            A::ReadWrite,
            None,
            ty,
            "1",
            None,
            Some(0),
            "x",
            name,
        );
        f.socket = Some(Box::new(SocketInfo {
            bound: None,
            protocol: proto,
            local: None,
            remote: None,
            state: state.map(Into::into),
            tcp: None,
        }));
        f
    };
    let p = python3(vec![
        sock(
            3,
            T::Other("pack".into()),
            Protocol::Other("packet"),
            None,
            "type=SOCK_RAW",
        ),
        sock(
            4,
            T::Ipv4,
            Protocol::Udp,
            Some(TcpState::Close),
            "127.0.0.1:1",
        ),
    ]);
    let out = table::render(std::slice::from_ref(&p), TableOpts::new(Escaper::UNIX));
    let rows: Vec<&str> = out.lines().skip(1).collect();
    assert!(rows[0].ends_with("type=SOCK_RAW"), "{out:?}");
    assert!(rows[1].ends_with("127.0.0.1:1 "), "{out:?}");
}

// ---- The C's JSON schema (DIVERGENCES 91), each rule measured against it. ----

/// A row with nothing known but its fd, type and name, for the JSON tests.
fn jrow(fd: lsof_core::FdType, ty: lsof_core::FileType, name: &str) -> lsof_core::OpenFile {
    lsof_core::OpenFile {
        fd,
        access: lsof_core::AccessMode::Unknown,
        file_type: ty,
        name: name.into(),
        device: None,
        size: None,
        offset: None,
        node: None,
        links: None,
        lock: None,
        fs_device: None,
        rdev: None,
        file_flags: None,
        socket: None,
        name_addition: None,
    }
}

fn jproc(files: Vec<lsof_core::OpenFile>) -> lsof_core::Process {
    lsof_core::Process {
        tid: None,
        task_command: None,
        uid: Some(0),
        pgid: Some(21683),
        pid: 21683,
        ppid: Some(1),
        command: "python3".into(),
        user: Some("root".into()),
        endpoint_peer: false,
        unlisted: false,
        files,
    }
}

fn jsock(
    protocol: lsof_core::Protocol,
    state: Option<lsof_core::SockState>,
    queues: Option<(u64, u64)>,
) -> Option<Box<lsof_core::SocketInfo>> {
    Some(Box::new(lsof_core::SocketInfo {
        bound: None,
        protocol,
        local: Some("127.0.0.1:41095".parse().unwrap()),
        remote: None,
        state,
        tcp: queues.map(|(r, s)| lsof_core::model::TcpExtInfo {
            recv_window: None,
            recv_queue: Some(r),
            send_queue: Some(s),
        }),
    }))
}

/// The files of one `-j` line: what follows the process's keys.
fn jfile(f: lsof_core::OpenFile) -> String {
    let p = jproc(vec![f]);
    let line = json::render_lines(&[p], &dj());
    let head = "{\"pid\":21683,\"pgid\":21683,\"ppid\":1,\"command\":\"python3\",\"uid\":0,\"login\":\"root\",";
    line.strip_prefix(head)
        .and_then(|l| l.strip_suffix("}\n"))
        .unwrap_or_else(|| panic!("{line:?}"))
        .to_string()
}

/// Measured: `lsof -J -p 999999` prints the envelope and a newline, and
/// `-j` prints nothing at all.
#[test]
fn json_envelope_is_the_cs() {
    assert_eq!(
        json::render_aggregated(&[], &dj()),
        "{\"lsof_version\":\"9.9.9\",\"processes\":[]}\n"
    );
    assert_eq!(json::render_lines(&[], &dj()), "");
}

/// A process with no file left is no object, in either form (`print.c:2128`).
#[test]
fn json_skips_a_process_with_no_files() {
    let empty = jproc(vec![]);
    let one = jproc(vec![jrow(
        lsof_core::FdType::Cwd,
        lsof_core::FileType::Dir,
        "/",
    )]);
    let doc = json::render_aggregated(&[empty.clone(), one], &dj());
    assert_eq!(doc.matches("\"pid\"").count(), 1, "{doc}");
    assert_eq!(json::render_lines(&[empty], &dj()), "");
}

/// pid, tid, task_cmd, pgid, ppid, command, uid, login: the measured `-J -K`
/// object of a task, `{"pid":21683,"tid":21685,"task_cmd":"fxworker",...}`.
#[test]
fn json_process_keys_in_the_cs_order() {
    let mut p = jproc(vec![jrow(
        lsof_core::FdType::Cwd,
        lsof_core::FileType::Dir,
        "/x",
    )]);
    p.tid = Some(21685);
    p.task_command = Some("fxworker".into());
    let doc = json::render_aggregated(&[p.clone()], &dj());
    assert!(
        doc.starts_with(
            "{\"lsof_version\":\"9.9.9\",\"processes\":[{\"pid\":21683,\"tid\":21685,\"task_cmd\":\"fxworker\",\"pgid\":21683,\"ppid\":1,\"command\":\"python3\",\"uid\":0,\"login\":\"root\",\"files\":[{\"fd\":\"cwd\",\"type\":\"DIR\",\"name\":\"/x\"}]}]}\n"
        ),
        "{doc}"
    );
    // `-l`: no login key.
    let numeric = json::JsonOpts {
        numeric_ids: true,
        ..dj()
    };
    assert!(!json::render_lines(&[p], &numeric).contains("login"));
}

/// A uid of 2^31 or more is printed as the number it is, where the C casts
/// it to `int` and prints `-294967296` (DIVERGENCES 68, C-DEFECT).
#[test]
fn json_uid_is_unsigned() {
    let mut p = jproc(vec![jrow(
        lsof_core::FdType::Cwd,
        lsof_core::FileType::Dir,
        "/",
    )]);
    p.uid = Some(4_000_000_000);
    p.user = None;
    let line = json::render_lines(&[p], &dj());
    assert!(line.contains("\"uid\":4000000000,\"fd\""), "{line}");
}

/// The measured fd 53: every file key, in `json_print_file()`'s order, with
/// size and offset as decimal strings and nlink a number.
#[test]
fn json_file_keys_in_the_cs_order() {
    use lsof_core::model::LockKind;
    let mut f = jrow(
        lsof_core::FdType::Handle(53),
        lsof_core::FileType::Regular,
        "/fx/locked.txt",
    );
    f.access = lsof_core::AccessMode::ReadWrite;
    f.lock = Some(LockKind::WriteFull);
    f.fs_device = Some(0xfe00);
    f.device = Some("254,0".into());
    f.size = Some(4);
    f.offset = Some(0);
    f.node = Some("2834481".into());
    f.links = Some(1);
    f.file_flags = Some(0o2 | 0o100000 | 0o2000000);
    assert_eq!(
        jfile(f.clone()),
        "\"fd\":\"53\",\"access\":\"u\",\"lock\":\"W\",\"type\":\"REG\",\"device_number\":\"0xfe00\",\"size\":\"4\",\"offset\":\"0\",\"inode\":\"2834481\",\"nlink\":1,\"flags\":\"RW,LG,CX\",\"name\":\"/fx/locked.txt\""
    );
    // raw_device is `-F r`'s, outside the default set, after device_number.
    f.rdev = std::num::NonZeroU32::new(0x103);
    let only = ['r'];
    let r = json::render_lines(
        &[jproc(vec![f])],
        &json::JsonOpts {
            only: Some(&only),
            ..dj()
        },
    );
    assert_eq!(r, "{\"pid\":21683,\"raw_device\":\"0x103\"}\n");
}

/// `"offset":"123456789"` whatever `-o` says; `-F o` prints `0x75bcd15`.
#[test]
fn json_offset_is_decimal() {
    let mut f = jrow(
        lsof_core::FdType::Handle(3),
        lsof_core::FileType::Regular,
        "/a",
    );
    f.offset = Some(123_456_789);
    assert!(jfile(f).contains("\"offset\":\"123456789\""));
}

/// A `-F` selection prints exactly those keys, and pid: measured `-J -Fc`
/// gives `{"pid":P,"command":"python3","files":[{}]}`.
#[test]
fn json_field_selection() {
    let p = jproc(vec![jrow(
        lsof_core::FdType::Handle(33),
        lsof_core::FileType::Regular,
        "/r",
    )]);
    let only = ['c'];
    let o = json::JsonOpts {
        only: Some(&only),
        ..dj()
    };
    assert_eq!(
        json::render_aggregated(std::slice::from_ref(&p), &o),
        "{\"lsof_version\":\"9.9.9\",\"processes\":[{\"pid\":21683,\"command\":\"python3\",\"files\":[{}]}]}\n"
    );
    assert_eq!(
        json::render_lines(&[p], &o),
        "{\"pid\":21683,\"command\":\"python3\"}\n"
    );
}

/// The C's escapes: BS and FF by name, the other C0 controls as lowercase
/// `\u00xx`; DEL, C1 and U+2028/2029 escaped too (a ledgered C-DEFECT).
#[test]
fn json_escapes_like_the_c() {
    let f = jrow(
        lsof_core::FdType::Handle(52),
        lsof_core::FileType::Regular,
        "h\u{1b}[31m\u{1}\t\n\"\\\u{8}\u{c}\r\u{1f}\u{7f}\u{9b}\u{2028}\u{2029}\u{fffd}",
    );
    assert_eq!(
        jfile(f),
        "\"fd\":\"52\",\"type\":\"REG\",\"name\":\"h\\u001b[31m\\u0001\\t\\n\\\"\\\\\\b\\f\\r\\u001f\\u007f\\u009b\\u2028\\u2029\u{fffd}\""
    );
}

/// An AF_UNIX row: device the PCB address, its inode, and `"tcp_info":{}`,
/// never a state (the C's writer reads one the unix path never sets).
#[test]
fn json_unix_row_has_empty_tcp_info() {
    let mut f = jrow(
        lsof_core::FdType::Handle(37),
        lsof_core::FileType::Unix,
        "type=STREAM",
    );
    f.access = lsof_core::AccessMode::ReadWrite;
    f.device = Some("0x000000009408aa33".into());
    f.offset = Some(0);
    f.node = Some("115824".into());
    f.socket = jsock(
        lsof_core::Protocol::Other("unix"),
        Some(lsof_core::UnixState::Connected.into()),
        None,
    );
    assert_eq!(
        jfile(f),
        "\"fd\":\"37\",\"access\":\"u\",\"type\":\"unix\",\"device\":\"0x000000009408aa33\",\"offset\":\"0\",\"inode\":\"115824\",\"name\":\"type=STREAM\",\"tcp_info\":{}"
    );
}

/// TCP: protocol, not inode, and the state and queues; UDP's state only when
/// ESTABLISHED; UDP-Lite never one, its queues always (measured on all four).
#[test]
fn json_udp_state_only_when_established() {
    use lsof_core::{Protocol, TcpState};
    let inet = |proto: Protocol, st: Option<TcpState>| {
        let mut f = jrow(
            lsof_core::FdType::Handle(39),
            lsof_core::FileType::Ipv4,
            "127.0.0.1:41095",
        );
        f.device = Some("115826".into());
        f.node = Some(proto.as_str().into());
        f.socket = jsock(proto, st.map(Into::into), Some((7, 0)));
        jfile(f)
    };
    assert_eq!(
        inet(Protocol::Tcp, Some(TcpState::Listen)),
        "\"fd\":\"39\",\"type\":\"IPv4\",\"device\":\"115826\",\"protocol\":\"TCP\",\"name\":\"127.0.0.1:41095\",\"tcp_info\":{\"state\":\"LISTEN\",\"recv_queue\":7,\"send_queue\":0}"
    );
    assert!(inet(Protocol::Udp, Some(TcpState::Close))
        .ends_with("\"tcp_info\":{\"recv_queue\":7,\"send_queue\":0}"));
    assert!(inet(Protocol::Udp, Some(TcpState::Established))
        .ends_with("\"tcp_info\":{\"state\":\"ESTABLISHED\",\"recv_queue\":7,\"send_queue\":0}"));
    for st in [TcpState::Close, TcpState::Established] {
        let u = inet(Protocol::UdpLite, Some(st));
        assert!(u.contains("\"protocol\":\"UDPLITE\""), "{u}");
        assert!(
            u.ends_with("\"tcp_info\":{\"recv_queue\":7,\"send_queue\":0}"),
            "{u}"
        );
    }
}

/// A raw row (`FileType::Socket("raw")`, no SocketInfo) prints its inode,
/// as the C's `inp_ty` 1 row does, and no protocol or tcp_info; a netlink
/// `sock` row keeps its device number; a packet row has no tcp_info.
#[test]
fn json_raw_packet_netlink_have_no_tcp_info() {
    let mut raw = jrow(
        lsof_core::FdType::Handle(48),
        lsof_core::FileType::Socket("raw"),
        "00000000:0001->00000000:0000 st=07",
    );
    raw.access = lsof_core::AccessMode::ReadWrite;
    raw.offset = Some(0);
    raw.node = Some("115832".into());
    assert_eq!(
        jfile(raw),
        "\"fd\":\"48\",\"access\":\"u\",\"type\":\"raw\",\"offset\":\"0\",\"inode\":\"115832\",\"name\":\"00000000:0001->00000000:0000 st=07\""
    );
    // device_number from fs_device itself, where searched_fs_device() is None.
    let mut nl = jrow(
        lsof_core::FdType::Handle(49),
        lsof_core::FileType::Socket("sock"),
        "protocol: NETLINK",
    );
    nl.fs_device = Some(9);
    nl.device = Some("0,9".into());
    nl.node = Some("3660206".into());
    assert_eq!(
        jfile(nl),
        "\"fd\":\"49\",\"type\":\"sock\",\"device_number\":\"0x9\",\"inode\":\"3660206\",\"name\":\"protocol: NETLINK\""
    );
    assert!(!json::render_lines(&packet_row(), &dj()).contains("tcp_info"));
}

/// `name` is the C's `Lf->nm`: never an addition, and none at all for NOFD.
#[test]
fn json_name_is_the_base() {
    let mut cwd = jrow(
        lsof_core::FdType::Cwd,
        lsof_core::FileType::Unknown,
        "/proc/1/cwd",
    );
    cwd.add_name_addition("(readlink: Permission denied)");
    assert_eq!(
        jfile(cwd.clone()),
        "\"fd\":\"cwd\",\"type\":\"unknown\",\"name\":\"/proc/1/cwd\""
    );
    let mut nofd = jrow(lsof_core::FdType::NoFd, lsof_core::FileType::NoType, "");
    nofd.add_name_addition("/proc/1/fd (opendir: Permission denied)");
    assert_eq!(jfile(nofd.clone()), "\"fd\":\"NOFD\"");
    let mut del = jrow(
        lsof_core::FdType::Handle(44),
        lsof_core::FileType::Regular,
        "/fx/d (deleted)",
    );
    let mut ex = jrow(
        lsof_core::FdType::Handle(5),
        lsof_core::FileType::Exempt("fd"),
        "/m/f",
    );
    ex.add_name_addition("(-e /m)");
    let mut plus = ex.clone();
    plus.name = "/m/g".into();
    plus.name_addition = None;
    plus.add_name_addition("(+e /m)");
    let mut st = jrow(
        lsof_core::FdType::Mem,
        lsof_core::FileType::Regular,
        "/lib/x.so",
    );
    st.add_name_addition("(stat: No such file or directory)");
    let mut path = st.clone();
    path.name = "/lib/y.so".into();
    path.name_addition = None;
    path.add_name_addition("(path dev=0,42, inode=2)");
    del.add_name_addition("(stat: x)");
    let all = jproc(vec![cwd, nofd, del, ex, plus, st, path]);
    let doc = json::render_aggregated(std::slice::from_ref(&all), &dj());
    for bad in [
        " (readlink: ",
        " (stat: ",
        " (opendir: ",
        " (-e ",
        " (+e ",
        " (path ",
    ] {
        assert!(!doc.contains(bad), "{bad}: {doc}");
    }
    assert!(doc.contains("\"name\":\"/fx/d (deleted)\""), "{doc}");
    // The table and -F still print the whole.
    let f = fields::render(&[all], false, None, TcpInfoFlags::DEFAULT, Escaper::UNIX);
    assert!(
        f.contains("n/m/g (+e /m)\n") && f.contains("n/proc/1/cwd (readlink: Permission denied)\n"),
        "{f}"
    );
}

/// Whatever the rows, a JSON key is printed exactly when `-F` prints its
/// letter, with the same value source: the renderers share their row
/// predicates. The measured exceptions: a blank access or lock (`-F` prints
/// a space, JSON no key), name (JSON's is the base, and none for NOFD), and
/// tcp_info, which JSON prints, maybe empty, on every row with a TCP/TPI
/// record.
#[test]
fn json_keys_follow_the_dash_f_letters() {
    use lsof_core::{Protocol, TcpState};
    let mut rows = Vec::new();
    for p in sample_processes()
        .into_iter()
        .chain(packet_row())
        .chain(tcp_info_fixture())
    {
        rows.extend(p.files);
    }
    let mut tcp = jrow(
        lsof_core::FdType::Handle(39),
        lsof_core::FileType::Ipv4,
        "a:1",
    );
    tcp.node = Some("TCP".into());
    tcp.device = Some("1".into());
    tcp.socket = jsock(Protocol::Tcp, Some(TcpState::Listen.into()), Some((1, 2)));
    rows.push(tcp);
    let mut raw = jrow(
        lsof_core::FdType::Handle(48),
        lsof_core::FileType::Socket("raw"),
        "r",
    );
    raw.node = Some("9".into());
    raw.fs_device = Some(9);
    rows.push(raw);
    let mut unix = jrow(
        lsof_core::FdType::Handle(37),
        lsof_core::FileType::Unix,
        "u",
    );
    unix.node = Some("8".into());
    unix.device = Some("0x1".into());
    unix.socket = jsock(
        Protocol::Other("unix"),
        Some(lsof_core::UnixState::Listen.into()),
        None,
    );
    rows.push(unix);
    let mut dev = jrow(
        lsof_core::FdType::Handle(45),
        lsof_core::FileType::Chr,
        "/dev/null",
    );
    dev.fs_device = Some(5);
    dev.rdev = std::num::NonZeroU32::new(0x103);
    dev.links = Some(1);
    dev.file_flags = Some(1);
    dev.access = lsof_core::AccessMode::Write;
    rows.push(dev);
    let keys = [
        ('f', "fd"),
        ('a', "access"),
        ('l', "lock"),
        ('t', "type"),
        ('d', "device"),
        ('D', "device_number"),
        ('r', "raw_device"),
        ('s', "size"),
        ('o', "offset"),
        ('i', "inode"),
        ('k', "nlink"),
        ('P', "protocol"),
        ('G', "flags"),
    ];
    let every: Vec<char> = keys.iter().map(|k| k.0).chain(['T']).collect();
    let tcp_all = dj().tcp_show;
    for f in rows {
        let p = jproc(vec![f.clone()]);
        let ff = fields::render_with_offset_digits(
            std::slice::from_ref(&p),
            false,
            Some(&every),
            tcp_all,
            Escaper::UNIX,
            0,
            FileFlags::Names,
        );
        let j = json::render_lines(
            &[p],
            &json::JsonOpts {
                only: Some(&every),
                ..dj()
            },
        );
        for (letter, key) in keys {
            let field = ff.lines().find(|l| l.starts_with(letter));
            let shown = match field {
                Some(l) if matches!(letter, 'a' | 'l') => l != format!("{letter} "),
                Some(_) => true,
                None => false,
            };
            assert_eq!(
                shown,
                j.contains(&format!("\"{key}\":")),
                "{letter}/{key}: {ff:?} {j:?}"
            );
        }
        // Where -F prints any T token, JSON has a tcp_info object.
        if ff.lines().any(|l| l.starts_with('T')) {
            assert!(j.contains("\"tcp_info\":{"), "{ff:?} {j:?}");
        }
    }
}
