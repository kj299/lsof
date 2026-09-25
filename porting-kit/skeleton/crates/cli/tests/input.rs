//! What the binary does with input that is not all text (LESSONS #065).
//!
//! A C tool reads bytes; a Rust port that reads a `String` fails on the first
//! byte that is not UTF-8. This skeleton had thrown that error away, so one
//! bad byte turned the whole input into an empty one: nothing printed, exit 0.
#![cfg(unix)]

use std::io::Write;
use std::process::{Command, Stdio};

#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's output"
)]
fn a_byte_that_is_not_utf8_costs_that_byte_not_the_input() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_port"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn port");
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(b"a=1\n\xff=2\nb=3\n").expect("write input");
    }
    let out = child.wait_with_output().expect("wait for port");
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{text}");
    // The lines around the bad byte survive; the bad byte is shown, not lost.
    assert!(text.contains("a\t1") && text.contains("b\t3"), "{text:?}");
    assert!(text.contains("\u{FFFD}\t2"), "{text:?}");
}
