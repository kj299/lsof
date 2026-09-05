//! End-to-end renderer checks over the deterministic mock data set.

use lsof_core::mock::sample_processes;
use lsof_core::render::{fields, json, table};
use lsof_core::Escaper;

#[test]
fn table_has_header_and_rows() {
    let out = table::render(
        &sample_processes(),
        false,
        false,
        false,
        None,
        false,
        Escaper::WINDOWS,
    );
    let header = out.lines().next().unwrap();
    for col in ["COMMAND", "PID", "USER", "FD", "TYPE", "NODE", "NAME"] {
        assert!(header.contains(col), "header missing {col}: {header:?}");
    }
    assert!(out.contains("explorer.exe"));
    assert!(out.contains("server.exe"));
    assert!(out.contains("1500"));
    assert!(out.contains("(LISTEN)"));
    // cwd row renders the special FD code, not a number.
    assert!(out.contains("cwd"));
}

#[test]
fn table_empty_when_nothing_matches() {
    // No matching processes -> no output at all (not even a bare header),
    // matching lsof. Regression guard for `lsof -a -p <pid> -c <nomatch>`.
    assert_eq!(
        table::render(&[], false, false, false, None, false, Escaper::WINDOWS),
        ""
    );
    assert_eq!(
        table::render(&[], false, true, false, None, false, Escaper::WINDOWS),
        ""
    );
}

#[test]
fn terse_lists_unique_pids() {
    let out = table::render(
        &sample_processes(),
        true,
        false,
        false,
        None,
        false,
        Escaper::WINDOWS,
    );
    assert_eq!(out, "1000\n1500\n");
}

#[test]
fn fields_tokens() {
    let out = fields::render(&sample_processes(), false, None, Escaper::WINDOWS);
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
    let out = fields::render(&sample_processes(), false, Some(&['n']), Escaper::WINDOWS);
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
        false,
        true,
        false,
        None,
        false,
        Escaper::WINDOWS,
    );
    assert!(out.lines().next().unwrap().contains("PPID"));
    // explorer.exe's ppid (4) shows up.
    assert!(out.contains(" 4 ") || out.contains("   4 "));
}

#[test]
fn table_offset_with_dash_o() {
    use lsof_core::{AccessMode, FdType, FileType, OpenFile, Process};
    let p = Process {
        pid: 7,
        ppid: None,
        command: "x".into(),
        user: None,
        endpoint_peer: false,
        files: vec![OpenFile {
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
        }],
    };
    // Default prefers size; -o prefers the offset (0t<dec>).
    assert!(table::render(
        std::slice::from_ref(&p),
        false,
        false,
        false,
        None,
        false,
        Escaper::WINDOWS
    )
    .contains("100"));
    assert!(
        table::render(&[p], false, false, true, None, false, Escaper::WINDOWS).contains("0t42")
    );
}

#[test]
fn table_command_width_caps() {
    use lsof_core::{AccessMode, FdType, FileType, OpenFile, Process};
    let p = Process {
        pid: 7,
        ppid: None,
        command: "verylongcommandname.exe".into(),
        user: None,
        endpoint_peer: false,
        files: vec![OpenFile {
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
        }],
    };
    // +c 4: the COMMAND cell is truncated to 4 chars; the full name is gone.
    let capped = table::render(
        std::slice::from_ref(&p),
        false,
        false,
        false,
        Some(4),
        false,
        Escaper::WINDOWS,
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
    let full = table::render(&[p], false, false, false, None, false, Escaper::WINDOWS);
    assert!(full.contains("verylongcommandname.exe"));
}

#[test]
fn fields_skips_empty_name() {
    // `-K` thread `task` rows have no name; the -F output must not emit a bare
    // `n` field code (regression guard for the lone-`n`-line bug).
    use lsof_core::{AccessMode, FdType, FileType, OpenFile, Process};
    let p = Process {
        pid: 7,
        ppid: None,
        command: "x".into(),
        user: None,
        endpoint_peer: false,
        files: vec![OpenFile {
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
        }],
    };
    let out = fields::render(&[p], false, None, Escaper::WINDOWS);
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
    // -F0: fields within a set are NUL-separated, and each process/file set ends
    // with a NL so a consumer can split records on it (lsof's documented format).
    let out = fields::render(&sample_processes(), true, None, Escaper::WINDOWS);
    assert!(
        out.contains("p1000\0"),
        "fields within a set are NUL-separated: {out:?}"
    );
    assert!(
        out.contains('\n'),
        "sets must be NL-delimited so parsers can split them"
    );
    // The last field of a set is NL-terminated, NOT NUL — no `\0\n` sequence.
    assert!(
        !out.contains("\0\n"),
        "a set's last field should end with NL, not NUL+NL: {out:?}"
    );
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
    let out = fields::render(&sample_processes(), false, None, Escaper::WINDOWS);
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
    };
    let p = Process {
        pid: 7,
        ppid: None,
        command: "svc".into(),
        user: None,
        endpoint_peer: false,
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
        false,
        false,
        false,
        None,
        false,
        Escaper::WINDOWS,
    );
    assert!(table.contains("KEY"), "registry-key TYPE code: {table:?}");
    assert!(table.contains("SEM"), "Other object TYPE code: {table:?}");
    assert!(
        table.contains("\\REGISTRY\\MACHINE\\SOFTWARE"),
        "key path in NAME"
    );
    let f = fields::render(&[p], false, None, Escaper::WINDOWS);
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
    assert_eq!(Format::Json.repeat_marker(), "");
    assert_eq!(Format::JsonLines.repeat_marker(), "");
}

#[test]
fn json_aggregated_shape() {
    let out = json::render_aggregated(&sample_processes());
    assert!(out.starts_with("{\"processes\":["));
    assert!(out.ends_with("]}"));
    assert!(out.contains("\"pid\":1500"));
    assert!(out.contains("\"protocol\":\"TCP\""));
    assert!(out.contains("\"state\":\"LISTEN\""));
    assert!(out.contains("\"command\":\"explorer.exe\""));
}

#[test]
fn json_lines_one_per_file() {
    let procs = sample_processes();
    let total_files: usize = procs.iter().map(|p| p.files.len()).sum();
    let out = json::render_lines(&procs);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), total_files);
    for l in lines {
        assert!(l.starts_with('{') && l.ends_with('}'));
    }
}

#[test]
fn json_escapes_backslashes() {
    // Windows paths and DOMAIN\user must be valid JSON.
    let out = json::render_aggregated(&sample_processes());
    assert!(out.contains("EXAMPLE\\\\alice"));
    assert!(out.contains("C:\\\\Users\\\\alice"));
}

/// One process whose command, user and single file name are whatever the test
/// says — the shape of the hostile-name checks below.
fn named(command: &str, user: &str, name: &str) -> lsof_core::model::Process {
    use lsof_core::{AccessMode, FdType, FileType, OpenFile, Process};
    Process {
        pid: 7,
        ppid: None,
        command: command.into(),
        user: Some(user.into()),
        endpoint_peer: false,
        files: vec![OpenFile {
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
        false,
        false,
        false,
        None,
        false,
        Escaper::UNIX,
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
    let f = fields::render(std::slice::from_ref(&p), false, None, Escaper::UNIX);
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
    let f0 = fields::render(&[split], true, None, Escaper::UNIX);
    assert!(f0.contains("ntwo\\nlines\n"), "{f0:?}");
    assert_eq!(
        f0.matches('\n').count(),
        2,
        "one process set, one file set: {f0:?}"
    );

    // The fuzz target's exact finding, in COMMAND.
    let q = named("PPid:\rd:Uid:", "u", "f");
    let t = table::render(&[q], false, false, false, None, false, Escaper::UNIX);
    assert!(t.contains("PPid:\\rd:Uid:"), "{t:?}");
}

#[test]
fn backslash_is_text_on_windows_and_escaped_on_unix() {
    // Every Windows NAME is `C:\…` and every domain user is `DOMAIN\user`; the
    // C's `\\` rule would double each separator, so on Windows the backslash is
    // text. On Unix it is escaped so `\` `n` cannot pose as a newline.
    let win = table::render(
        &sample_processes(),
        false,
        false,
        false,
        None,
        false,
        Escaper::WINDOWS,
    );
    assert!(win.contains("C:\\Windows\\System32\\config.dat"), "{win:?}");
    assert!(win.contains("EXAMPLE\\alice"), "{win:?}");
    let unix = table::render(
        &sample_processes(),
        false,
        false,
        false,
        None,
        false,
        Escaper::UNIX,
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
fn command_width_is_counted_after_escaping() {
    // `+c 3` on a command that prints as `a^[bcd`: the C's safestrprtn() emits
    // an escape only if it fits whole, so 3 gives `a^[` and 2 gives `a`.
    let p = named("a\x1bbcd", "u", "f");
    let cell = |w: usize| -> String {
        let out = table::render(
            std::slice::from_ref(&p),
            false,
            false,
            false,
            Some(w),
            false,
            Escaper::UNIX,
        );
        out.lines()
            .nth(1)
            .unwrap()
            .split(' ')
            .next()
            .unwrap()
            .to_string()
    };
    assert_eq!(cell(6), "a^[bcd");
    assert_eq!(cell(3), "a^[");
    assert_eq!(cell(2), "a");
}

#[test]
fn json_escapes_every_control_and_the_line_separators() {
    // JSON needs only C0 escaped; DEL, the C1 block (U+009B is the 8-bit CSI)
    // and U+2028/U+2029 are escaped too, so `-j` stays one object per line and
    // a document read on a terminal cannot drive it. Decoders see the same
    // string either way.
    let p = named("a\u{9b}b\u{2028}c\x7f\x1b", "u", "f");
    let out = json::render_lines(&[p]);
    assert!(
        out.contains("\"command\":\"a\\u009bb\\u2028c\\u007f\\u001b\""),
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
        protocol: Protocol::Tcp,
        local: Some("127.0.0.1:5000".parse().unwrap()),
        remote: Some("127.0.0.1:51000".parse().unwrap()),
        state: Some(TcpState::Established),
        tcp: Some(TcpExtInfo {
            recv_window: Some(262144),
            recv_queue: Some(0),
            send_queue: Some(12),
        }),
    };
    vec![Process {
        pid: 2000,
        ppid: None,
        command: "server.exe".to_string(),
        user: Some("EXAMPLE\\alice".to_string()),
        files: vec![OpenFile {
            fd: FdType::Handle(77),
            access: AccessMode::ReadWrite,
            file_type: FileType::Ipv4,
            name: sock.display_name(false, false),
            device: None,
            size: None,
            offset: None,
            node: Some("TCP".to_string()),
            links: None,
            socket: Some(sock),
        }],
        endpoint_peer: false,
    }]
}

#[test]
fn tcp_info_table_suffix() {
    // The exact v0.2.0-validated shape the live smoke cases assert: the info
    // rides the NAME column, after the state.
    let out = table::render(
        &tcp_info_fixture(),
        false,
        false,
        false,
        None,
        false,
        Escaper::WINDOWS,
    );
    assert!(
        out.contains("(ESTABLISHED) (Win=262144) (QR=0) (QS=12)"),
        "table NAME must carry the (Win=)/(QR=)/(QS=) suffix: {out:?}"
    );
}

#[test]
fn tcp_info_fields_tokens() {
    // Structured `T` tokens with lsof's own prefixes (QR/QS/WR), after ST=;
    // the n (name) field stays clean of the table-only suffix.
    let out = fields::render(&tcp_info_fixture(), false, None, Escaper::WINDOWS);
    assert!(out.contains("TST=ESTABLISHED\nTQR=0\nTQS=12\nTWR=262144\n"));
    assert!(
        !out.contains("(Win="),
        "-F must not leak the table suffix into the name field: {out:?}"
    );
}

#[test]
fn tcp_info_json_keys() {
    let out = json::render_aggregated(&tcp_info_fixture());
    for key in [
        "\"tcp_window\":262144",
        "\"tcp_queue_recv\":0",
        "\"tcp_queue_send\":12",
    ] {
        assert!(out.contains(key), "JSON missing {key}: {out:?}");
    }
    assert!(!out.contains("(Win="), "JSON name must stay clean: {out:?}");
    // And absent info stays absent: the plain mock sample has no tcp_* keys.
    assert!(!json::render_aggregated(&sample_processes()).contains("tcp_window"));
}
