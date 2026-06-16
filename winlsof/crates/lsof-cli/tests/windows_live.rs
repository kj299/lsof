//! Live runtime integration tests — they execute the real `lsof.exe` on Windows
//! and assert it reports a known open file and a known listening socket. These
//! run on the `windows-latest` CI runner (the first time the native backend is
//! exercised at runtime, not just compiled).
//!
//! Queries are deliberately scoped — `-p <self>` limits handle enumeration to
//! this test process, and `-i :port` is a sockets-only path — so there is no
//! system-wide `NtQueryObject` work and thus no hang risk.
#![cfg(windows)]

use std::io::Write;
use std::net::TcpListener;
use std::process::Command;

/// Run the built `lsof` binary with `args` and return its stdout.
fn lsof(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_lsof"))
        .args(args)
        .output()
        .expect("failed to run lsof.exe");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn version_and_help() {
    assert!(lsof(&["-v"]).contains("winlsof"), "version banner missing");
    let help = lsof(&["-h"]);
    assert!(help.contains("USAGE"), "usage header missing:\n{help}");
    assert!(help.contains("-i"), "options missing from help:\n{help}");
}

#[test]
fn lists_its_own_open_file() {
    let pid = std::process::id();
    let mut path = std::env::temp_dir();
    path.push(format!("winlsof_live_{pid}.dat"));

    let mut file = std::fs::File::create(&path).expect("create temp file");
    file.write_all(b"winlsof live test").unwrap();
    file.flush().unwrap();

    // `file` stays open across the lsof run.
    let out = lsof(&["-p", &pid.to_string()]);

    drop(file);
    let _ = std::fs::remove_file(&path);

    let needle = format!("winlsof_live_{pid}");
    assert!(
        out.to_lowercase().contains(&needle.to_lowercase()),
        "expected our open file `{needle}` in `lsof -p {pid}` output:\n{out}"
    );
}

#[test]
fn shows_listening_socket() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().unwrap().port();
    let pid = std::process::id().to_string();

    let out = lsof(&["-nP", &format!("-iTCP:{port}")]);

    assert!(
        out.contains(&format!(":{port}")),
        "port {port} missing:\n{out}"
    );
    assert!(out.contains("LISTEN"), "LISTEN state missing:\n{out}");
    assert!(out.contains(&pid), "owning pid {pid} missing:\n{out}");

    drop(listener);
}

#[test]
fn json_output_is_shaped() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().unwrap().port();

    let out = lsof(&["-nP", &format!("-iTCP:{port}"), "-J"]);

    assert!(
        out.trim_start().starts_with("{\"processes\":["),
        "expected JSON object:\n{out}"
    );
    assert!(
        out.contains("\"protocol\":\"TCP\""),
        "TCP protocol missing:\n{out}"
    );
    assert!(
        out.contains(&format!("{port}")),
        "port {port} missing:\n{out}"
    );

    drop(listener);
}
