//! What lsof says on stderr about a path argument it cannot use. The C prints
//! it with `safestrprt()` (`arg.c`): escaped, and for `+f` as typed. The
//! differential compares stdout and the exit status only, so these lines are
//! pinned here.
#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::Command;

/// A directory of the test's own, removed when it goes out of scope.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("lsof-rs-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("make a scratch directory");
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's stderr"
)]
fn plus_f_reports_a_plain_directory_as_typed_and_escaped() {
    // `./plain`, not the absolute path lsof-rs resolves it to, and the ESC of
    // a name the script running lsof may not have chosen comes back as `^[`.
    let dir = Scratch::new("plus-f");
    std::fs::create_dir(dir.0.join("plain")).expect("mkdir plain");
    std::fs::create_dir(dir.0.join("esc\x1b[2J")).expect("mkdir esc");
    let out = Command::new(env!("CARGO_BIN_EXE_lsof"))
        .current_dir(&dir.0)
        .args(["+f", "--", "./plain", "esc\x1b[2J"])
        .output()
        .expect("run lsof");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(
        err.contains("lsof: not a file system: ./plain\n"),
        "{err:?}"
    );
    assert!(
        err.contains("lsof: not a file system: esc^[[2J\n"),
        "{err:?}"
    );
    assert!(
        !out.stderr.contains(&0x1b),
        "a raw ESC reached stderr: {err:?}"
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's stderr"
)]
fn a_status_error_escapes_the_argument() {
    let dir = Scratch::new("status-error");
    let out = Command::new(env!("CARGO_BIN_EXE_lsof"))
        .current_dir(&dir.0)
        .arg("no\x1b[2Jsuch")
        .output()
        .expect("run lsof");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(
        err.contains("lsof: status error on no^[[2Jsuch: No such file or directory\n"),
        "{err:?}"
    );
    assert!(
        !out.stderr.contains(&0x1b),
        "a raw ESC reached stderr: {err:?}"
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's stderr"
)]
fn a_parse_error_escapes_the_argument_it_quotes() {
    let out = Command::new(env!("CARGO_BIN_EXE_lsof"))
        .args(["-p", "1\x1b[2J"])
        .output()
        .expect("run lsof");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(
        err.contains("lsof: illegal process ID: 1^[[2J\n"),
        "{err:?}"
    );
    assert!(
        !out.stderr.contains(&0x1b),
        "a raw ESC reached stderr: {err:?}"
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's stderr"
)]
fn a_refusal_the_c_makes_in_silence_under_dash_t_still_ends_the_run() {
    // A `-d` list of both kinds is refused. The C's `Fwarn`, which `-t` and
    // `-w` set, mutes the message, not the refusal: only the usage follows.
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_lsof"))
            .args(args)
            .output()
            .expect("run lsof")
    };
    let out = run(&["-t", "-d", "3,^4"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "Try 'lsof -h' for usage.\n"
    );
    let out = run(&["-d", "3,^4"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr)
        .starts_with("lsof: exclude in an include -d list: ^4\n"));
}
