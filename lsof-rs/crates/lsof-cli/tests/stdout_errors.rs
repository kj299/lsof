//! What lsof does when its standard output fails (LESSONS #063).
//!
//! The table used to go out in one `print!`, and `print!` panics on any write
//! error, so `lsof | head -1` ended with
//! `failed printing to stdout: Broken pipe (os error 32)` and exit 101 — where
//! the C dies of SIGPIPE, silently, and the shell reports 141. Now that the
//! table is written as it is formatted, a closed pipe is met mid-stream as
//! often as not, so the behaviour is pinned here rather than left to whichever
//! write happens to fail.
#![cfg(target_os = "linux")]

use std::fs::OpenOptions;
use std::process::{Command, Stdio};

fn self_pid() -> String {
    std::process::id().to_string()
}

#[test]
fn a_normal_run_writes_its_table_and_exits_0() {
    // The control for the two tests below, and not a formality: a mutation
    // that sent EVERY run down the write-error path — table printed, then
    // "lsof: write error", exit 1 — passed both of them, because each one only
    // ever looks at a failing write. Nothing else in `cargo test` runs this
    // binary on Linux.
    let out = Command::new(env!("CARGO_BIN_EXE_lsof"))
        .args(["-p", &self_pid()])
        .output()
        .expect("run lsof");
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.starts_with("COMMAND"), "{text}");
    assert!(
        text.lines().count() > 1,
        "a header and this process's rows: {text}"
    );
    assert!(
        out.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn a_closed_pipe_exits_141_and_says_nothing() {
    // The read end is dropped before lsof has written a byte — it spends
    // milliseconds reading /proc first — so the first write meets EPIPE.
    let mut child = Command::new(env!("CARGO_BIN_EXE_lsof"))
        .args(["-p", &self_pid()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn lsof");
    drop(child.stdout.take());
    let out = child.wait_with_output().expect("wait for lsof");
    assert_eq!(
        out.status.code(),
        Some(141),
        "the status the shell shows for the C's SIGPIPE; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.stderr.is_empty(),
        "a closed pipe is not an error to report: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn any_other_write_error_is_reported_not_panicked() {
    // /dev/full accepts the open and fails every write with ENOSPC — the
    // `lsof > file` on a full disk case. That IS an error, and it is one line
    // on stderr and exit 1, not a Rust panic message and exit 101.
    let full = OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .expect("open /dev/full");
    let out = Command::new(env!("CARGO_BIN_EXE_lsof"))
        .args(["-p", &self_pid()])
        .stdout(Stdio::from(full))
        .stderr(Stdio::piped())
        .output()
        .expect("run lsof");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "stderr: {err}");
    assert!(err.starts_with("lsof: write error: "), "stderr: {err}");
    assert!(!err.contains("panicked"), "stderr: {err}");
}
