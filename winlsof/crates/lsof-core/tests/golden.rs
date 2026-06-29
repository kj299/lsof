//! End-to-end renderer checks over the deterministic mock data set.

use lsof_core::mock::sample_processes;
use lsof_core::render::{fields, json, table};

#[test]
fn table_has_header_and_rows() {
    let out = table::render(&sample_processes(), false, false, false, None, false);
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
    assert_eq!(table::render(&[], false, false, false, None, false), "");
    assert_eq!(table::render(&[], false, true, false, None, false), "");
}

#[test]
fn terse_lists_unique_pids() {
    let out = table::render(&sample_processes(), true, false, false, None, false);
    assert_eq!(out, "1000\n1500\n");
}

#[test]
fn fields_tokens() {
    let out = fields::render(&sample_processes(), false, None);
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
    let out = fields::render(&sample_processes(), false, Some(&['n']));
    assert!(out.contains("p1000\n"));
    assert!(out.contains("f"));
    assert!(out.contains("nC:\\Users\\alice\n"));
    // Command/type fields suppressed.
    assert!(!out.contains("cexplorer.exe\n"));
    assert!(!out.contains("tDIR\n"));
}

#[test]
fn table_ppid_column() {
    let out = table::render(&sample_processes(), false, true, false, None, false);
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
    assert!(
        table::render(std::slice::from_ref(&p), false, false, false, None, false).contains("100")
    );
    assert!(table::render(&[p], false, false, true, None, false).contains("0t42"));
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
    let out = fields::render(&[p], false, None);
    assert!(out.contains("ftask\n"), "task FD field expected: {out:?}");
    assert!(out.contains("i4242\n"), "TID in the i field expected: {out:?}");
    // No bare `n` line.
    assert!(!out.lines().any(|l| l == "n"), "bare empty n field: {out:?}");
}

#[test]
fn fields_nul_terminator() {
    let out = fields::render(&sample_processes(), true, None);
    assert!(out.contains("p1000\0"));
    assert!(!out.contains('\n'));
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
