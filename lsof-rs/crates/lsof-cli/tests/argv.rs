//! What the binary does with an argument it cannot hold.
//!
//! `std::env::args()` panics on an argument that is not UTF-8, and a Linux
//! file name may contain any byte but `/` and NUL: `lsof /tmp/$'\xff'` exited
//! 101 with `called Result::unwrap() on an Err value`. The contract every
//! input path here keeps is *no panic on input*; this one is argv.
#![cfg(unix)]

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::process::Command;

#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's exit status"
)]
fn a_non_utf8_argument_is_refused_not_panicked_on() {
    // An ESC as well as the undecodable byte: the argument is quoted back in
    // the error, and it is attacker text, so it must come back escaped.
    let out = Command::new(env!("CARGO_BIN_EXE_lsof"))
        .arg(OsStr::from_bytes(b"/tmp/no\xff\x1b[2Jsuch"))
        .output()
        .expect("run lsof");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(!err.contains("panicked"), "{err}");
    assert!(err.contains("not valid UTF-8"), "{err}");
    assert!(
        !out.stderr.contains(&0x1b),
        "a raw ESC reached stderr: {err:?}"
    );
    assert!(err.contains("^[[2Jsuch"), "{err:?}");
}
