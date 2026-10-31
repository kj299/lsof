//! What lsof does when its standard output fails (LESSONS #063), or its
//! standard error does.
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

/// What lsof said on stderr, less the mount table's warnings: where the user
/// running the tests cannot `stat` some mount, a run that reads the table
/// says so, as the C does (DIVERGENCES 87). Exactly that pair is tolerated.
fn stderr_of(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let mut kept = String::new();
    let mut lines = text.split_inclusive('\n').peekable();
    while let Some(line) = lines.next() {
        if line.starts_with("lsof: WARNING: can't stat() ")
            && line.contains(" file system ")
            && lines.peek() == Some(&"      Output information may be incomplete.\n")
        {
            lines.next();
            continue;
        }
        kept.push_str(line);
    }
    kept
}

#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's exit status"
)]
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
        stderr_of(&out.stderr).is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's exit status"
)]
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
        stderr_of(&out.stderr).is_empty(),
        "a closed pipe is not an error to report: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's exit status"
)]
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

/// A pipe whose reader is gone before lsof starts: the stdin of a `true`
/// that has already exited. Writing to it is EPIPE every time, where
/// dropping a reader after the spawn races lsof's first write.
fn a_closed_pipe() -> Stdio {
    let mut reader = Command::new("true")
        .stdin(Stdio::piped())
        .spawn()
        .expect("spawn true");
    let writer = reader.stdin.take().expect("its stdin");
    reader.wait().expect("wait for true");
    Stdio::from(writer)
}

fn dev_full() -> Stdio {
    Stdio::from(
        OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .expect("open /dev/full"),
    )
}

/// The help, written where the C's `usage()` writes it, to stderr: a failed
/// write is ignored as the C ignores its unchecked `fprintf(stderr)`'s, exit
/// 0, and a reader that has gone is the C's SIGPIPE, 141. `eprint!` had
/// panicked on both, exit 101.
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's exit status"
)]
fn the_help_on_a_failing_stderr() {
    for args in [&["-h"][..], &["-F", "?"]] {
        let out = Command::new(env!("CARGO_BIN_EXE_lsof"))
            .args(args)
            .stdout(Stdio::piped())
            .stderr(dev_full())
            .output()
            .expect("run lsof");
        assert_eq!(out.status.code(), Some(0), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
        let out = Command::new(env!("CARGO_BIN_EXE_lsof"))
            .args(args)
            .stdout(Stdio::piped())
            .stderr(a_closed_pipe())
            .output()
            .expect("run lsof");
        assert_eq!(out.status.code(), Some(141), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
    }
}

/// A process whose owner no password entry names, held while `f` runs: a
/// `sleep` under a UID this host's `/etc/passwd` does not list. `None` where
/// the tests are not run as root, which alone can start one.
fn with_a_nameless_owner(f: impl FnOnce(u32, u32)) -> Option<()> {
    use std::os::unix::process::CommandExt;
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let euid = status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|l| l.split_whitespace().nth(1));
    if euid != Some("0") {
        eprintln!("skipped: needs root to start a process under a UID with no name");
        return None;
    }
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    let uid = (3_999_000u32..3_999_100).find(|u| {
        !passwd
            .lines()
            .any(|l| l.split(':').nth(2) == Some(&u.to_string()))
    })?;
    let mut child = Command::new("sleep")
        .arg("60")
        .uid(uid)
        .gid(uid)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sleep");
    let pid = child.id();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(pid, uid)));
    let _ = child.kill();
    let _ = child.wait();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
    Some(())
}

/// DIVERGENCES 36 made `lsof: no pwd entry for UID N` the first thing a
/// listing writes on a host with a nameless owner, which containers often
/// have. With stderr on a full device the C lists everything and exits 0;
/// lsof-rs had panicked before its first row, exit 101. With stderr's
/// reader gone the C dies of SIGPIPE: 141.
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's exit status"
)]
fn a_listing_on_a_failing_stderr() {
    with_a_nameless_owner(|pid, uid| {
        let pid = pid.to_string();
        // The control: the warning is written, so the runs below meet a
        // failing write.
        let out = Command::new(env!("CARGO_BIN_EXE_lsof"))
            .args(["-p", &pid])
            .output()
            .expect("run lsof");
        assert_eq!(out.status.code(), Some(0));
        let listed = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(
            String::from_utf8_lossy(&out.stderr)
                .contains(&format!("lsof: no pwd entry for UID {uid}\n")),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(listed.lines().count() > 1, "{listed}");

        let out = Command::new(env!("CARGO_BIN_EXE_lsof"))
            .args(["-p", &pid])
            .stdout(Stdio::piped())
            .stderr(dev_full())
            .output()
            .expect("run lsof");
        assert_eq!(out.status.code(), Some(0));
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            listed,
            "the whole listing"
        );

        let out = Command::new(env!("CARGO_BIN_EXE_lsof"))
            .args(["-p", &pid])
            .stdout(Stdio::piped())
            .stderr(a_closed_pipe())
            .output()
            .expect("run lsof");
        assert_eq!(out.status.code(), Some(141));
    });
}
