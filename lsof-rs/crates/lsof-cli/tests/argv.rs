//! What the binary does with an argument that is not UTF-8.
//!
//! `std::env::args()` panics on an argument that is not UTF-8, and a Linux
//! file name may contain any byte but `/` and NUL: `lsof /tmp/$'\xff'` exited
//! 101 with `called Result::unwrap() on an Err value`, and was then refused
//! in one line. A path is now read as the bytes it is, as the C reads it,
//! and an option that reads text refuses what is not (DIVERGENCES 92). The
//! contract every input path here keeps is *no panic on input*; this one is
//! argv.
#![cfg(unix)]

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::process::Command;

#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's exit status"
)]
fn a_path_that_is_not_utf8_is_looked_up_and_named_escaped() {
    // An ESC as well as the undecodable byte: the argument is quoted back in
    // the error, and it is attacker text, so it must come back escaped.
    let out = Command::new(env!("CARGO_BIN_EXE_lsof"))
        .arg(OsStr::from_bytes(b"/tmp/no\xff\x1b[2Jsuch"))
        .output()
        .expect("run lsof");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(!err.contains("panicked"), "{err}");
    assert!(!err.contains("UTF-8"), "{err}");
    assert!(
        !out.stderr.contains(&0x1b),
        "a raw ESC reached stderr: {err:?}"
    );
    assert!(
        err.contains("status error on /tmp/no\\xff^[[2Jsuch: No such file or directory"),
        "{err:?}"
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's exit status"
)]
fn an_option_that_reads_text_says_the_cs_words_about_what_is_not() {
    let out = Command::new(env!("CARGO_BIN_EXE_lsof"))
        .arg("-p")
        .arg(OsStr::from_bytes(b"x\xff\x1b[2J"))
        .output()
        .expect("run lsof");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(!out.stderr.contains(&0x1b), "{err:?}");
    // The C's `illegal process ID: x\xff^[[2J` (measured), escaped as the
    // C's `safestrprt()` escapes it, then the usage (DIVERGENCES 92).
    assert_eq!(
        err.lines().next(),
        Some("lsof: illegal process ID: x\\xff^[[2J")
    );
    // `-u` reads bytes, as the C's `getpwnam()`: a login no account has
    // is its error, the bytes escaped (DIVERGENCES 92).
    let out = Command::new(env!("CARGO_BIN_EXE_lsof"))
        .arg("-u")
        .arg(OsStr::from_bytes(b"x\xff\x1b[2J"))
        .output()
        .expect("run lsof");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(!out.stderr.contains(&0x1b), "{err:?}");
    assert!(
        err.starts_with("lsof: can't get UID for x\\xff^[[2J\n"),
        "{err:?}"
    );
}

#[cfg(target_os = "linux")]
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's exit status"
)]
fn a_file_named_by_bytes_is_listed() {
    let dir = std::env::temp_dir().join(format!("lsof-rs-argv-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(OsStr::from_bytes(b"bad\xffname"));
    let held = std::fs::File::create(&path).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_lsof"))
        .args(["-Fn", "-a", "-p", &std::process::id().to_string()])
        .arg(&path)
        .output()
        .expect("run lsof");
    drop(held);
    let _ = std::fs::remove_dir_all(&dir);
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{text} {:?}", out.stderr);
    // Listed; how a NAME that is not UTF-8 is shown is another matter (the
    // C `\xff`, lsof-rs U+FFFD where the name comes from the kernel).
    assert!(text.contains("\nn/"), "{text:?}");
    assert!(text.contains("name\n"), "{text:?}");
}
