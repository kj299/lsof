//! The binary's behaviour when its standard output fails (LESSONS #063).
//!
//! Every test that runs a CLI reads all of its output, so the one case no test
//! reaches by accident is the reader leaving early. These three pin it: the
//! control first, because tests that only look at failing writes pass on a
//! program that fails every write.
#![cfg(unix)]

use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn a_normal_run_prints_and_exits_0() {
    let out = Command::new(env!("CARGO_BIN_EXE_port"))
        .arg("--version")
        .output()
        .expect("run port");
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("port "));
    assert!(out.stderr.is_empty());
}

#[test]
fn a_closed_pipe_exits_141_and_says_nothing() {
    // The read end is gone before the first write, so that write meets EPIPE.
    let mut child = Command::new(env!("CARGO_BIN_EXE_port"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn port");
    drop(child.stdout.take());
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(b"a=1\nb=2\n");
    }
    let out = child.wait_with_output().expect("wait for port");
    assert_eq!(
        out.status.code(),
        Some(141),
        "the shell's status for the C's SIGPIPE; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn any_other_write_error_is_reported_not_panicked() {
    // /dev/full fails every write with ENOSPC: a real error, one line, exit 1.
    let full = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .expect("open /dev/full");
    let out = Command::new(env!("CARGO_BIN_EXE_port"))
        .arg("--version")
        .stdout(Stdio::from(full))
        .output()
        .expect("run port");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.starts_with("write error: "), "{err}");
    assert!(!err.contains("panicked"), "{err}");
}
