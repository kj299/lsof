//! What lsof does when its standard output fails (LESSONS #063), or its
//! standard error does: what the C does (DIVERGENCES 36, measured against
//! it in every case here). The C never checks a write: with `SIGPIPE` at
//! its default a closed pipe kills it at the write that meets it, silently;
//! with `SIGPIPE` ignored (`trap '' PIPE`) or blocked the write fails and
//! the C goes on, as it does on a full disk (`/dev/full`), and exits with
//! its usual status, saying nothing.
//!
//! The table used to go out in one `print!`, and `print!` panics on any write
//! error, so `lsof | head -1` ended with
//! `failed printing to stdout: Broken pipe (os error 32)` and exit 101; then
//! with exit 141 where the C is killed, and with `lsof: write error`, exit 1,
//! on `/dev/full`, where the C exits 0.
#![cfg(target_os = "linux")]

use std::fs::OpenOptions;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};
use std::sync::{Mutex, MutexGuard};

/// One test of this file at a time. A child that another test thread forks
/// while a pipe's read end is still open in this process holds that end too,
/// until it execs, so a write that should meet EPIPE could succeed instead
/// (measured: about 1 run in 25 of this file, `-h` exiting 0, not 141).
/// Running the tests one after another removes that by construction.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

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
    let _serial = serial();
    // The control for the two tests below, and not a formality: a mutation
    // that sent EVERY run down the write-error path — table printed, then
    // "lsof: write error", exit 1 — passed both of them, because each one only
    // ever looks at a failing write. Nothing else in `cargo test` runs this
    // binary on Linux.
    let out = Command::new(env!("CARGO_BIN_EXE_lsof"))
        .env("RES_OPTIONS", "attempts:0")
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

/// `SIGPIPE`, which a `Command`'s child starts with at its default (std
/// puts the default back before `exec`), as a shell's child does.
const SIGPIPE: i32 = 13;

/// lsof run as a child of `sh -c "trap '' PIPE; exec …"`: `SIGPIPE` ignored,
/// as `trap '' PIPE`, `nohup` and a Python child with
/// `restore_signals=False` leave it.
fn lsof_with_sigpipe_ignored() -> Command {
    let mut c = Command::new("sh");
    c.args([
        "-c",
        "trap '' PIPE; exec \"$0\" \"$@\"",
        env!("CARGO_BIN_EXE_lsof"),
    ])
    .env("RES_OPTIONS", "attempts:0");
    c
}

#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's exit status"
)]
fn a_closed_pipe_kills_with_sigpipe_and_says_nothing() {
    let _serial = serial();
    let out = Command::new(env!("CARGO_BIN_EXE_lsof"))
        .env("RES_OPTIONS", "attempts:0")
        .args(["-p", &self_pid()])
        .stdout(a_closed_pipe())
        .stderr(Stdio::piped())
        .output()
        .expect("run lsof");
    assert_eq!(
        (out.status.code(), out.status.signal()),
        (None, Some(SIGPIPE)),
        "killed by the signal, as the C is (the shell's 141); stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stderr_of(&out.stderr).is_empty(),
        "a closed pipe is not an error to report: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// `SIGPIPE` ignored: the write fails, nothing is said, and lsof exits as
/// it would have, 0 (measured: the C under `trap '' PIPE`).
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's exit status"
)]
fn with_sigpipe_ignored_a_closed_pipe_is_no_error() {
    let _serial = serial();
    for args in [
        &["-p", &self_pid()][..],
        &["-F", "pcfn", "-p", &self_pid()],
        &["-J", "-p", &self_pid()],
    ] {
        let out = lsof_with_sigpipe_ignored()
            .args(args)
            .stdout(a_closed_pipe())
            .stderr(Stdio::piped())
            .output()
            .expect("run lsof");
        assert_eq!(out.status.code(), Some(0), "{args:?}");
        assert!(
            stderr_of(&out.stderr).is_empty(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// A repeating run into a closed pipe, `SIGPIPE` ignored, goes on to its
/// count, sleeping between cycles, as the C does (measured: `-r1c3mX`
/// takes three seconds, the C's and lsof-rs's), and exits as it would have.
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's exit status"
)]
fn with_sigpipe_ignored_a_repeating_run_goes_on() {
    let _serial = serial();
    let started = std::time::Instant::now();
    let out = lsof_with_sigpipe_ignored()
        .args(["-r", "1c2mX", "-p", &self_pid()])
        .stdout(a_closed_pipe())
        .stderr(Stdio::piped())
        .output()
        .expect("run lsof");
    assert_eq!(out.status.code(), Some(0));
    assert!(
        started.elapsed() >= std::time::Duration::from_secs(2),
        "two cycles, each followed by its sleep: {:?}",
        started.elapsed()
    );
    // At its default, the first write ends it.
    let started = std::time::Instant::now();
    let out = Command::new(env!("CARGO_BIN_EXE_lsof"))
        .env("RES_OPTIONS", "attempts:0")
        .args(["-r", "1c2mX", "-p", &self_pid()])
        .stdout(a_closed_pipe())
        .output()
        .expect("run lsof");
    assert_eq!(out.status.signal(), Some(SIGPIPE));
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
}

#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's exit status"
)]
fn a_full_disk_is_no_error() {
    let _serial = serial();
    // /dev/full accepts the open and fails every write with ENOSPC — the
    // `lsof > file` on a full disk case. The C says nothing and exits 0
    // (measured), its stdio errors unchecked; and 1 where the search
    // failed, its usual status.
    for (args, code) in [
        (vec!["-p".to_string(), self_pid()], 0),
        (vec!["-p".into(), "999999999".into()], 1),
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_lsof"))
            .env("RES_OPTIONS", "attempts:0")
            .args(&args)
            .stdout(dev_full())
            .stderr(Stdio::piped())
            .output()
            .expect("run lsof");
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(code), "{args:?} stderr: {err}");
        assert!(stderr_of(&out.stderr).is_empty(), "stderr: {err}");
    }
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
/// 0, and a reader that has gone kills it with `SIGPIPE`, as it kills the
/// C, or, the signal ignored, is ignored too, exit 0. `eprint!` had panicked
/// on both, exit 101.
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's exit status"
)]
fn the_help_on_a_failing_stderr() {
    let _serial = serial();
    for args in [&["-h"][..], &["-F", "?"]] {
        let out = Command::new(env!("CARGO_BIN_EXE_lsof"))
            .env("RES_OPTIONS", "attempts:0")
            .args(args)
            .stdout(Stdio::piped())
            .stderr(dev_full())
            .output()
            .expect("run lsof");
        assert_eq!(out.status.code(), Some(0), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
        let out = Command::new(env!("CARGO_BIN_EXE_lsof"))
            .env("RES_OPTIONS", "attempts:0")
            .args(args)
            .stdout(Stdio::piped())
            .stderr(a_closed_pipe())
            .output()
            .expect("run lsof");
        assert_eq!(out.status.signal(), Some(SIGPIPE), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
        let out = lsof_with_sigpipe_ignored()
            .args(args)
            .stdout(Stdio::piped())
            .stderr(a_closed_pipe())
            .output()
            .expect("run lsof");
        assert_eq!(out.status.code(), Some(0), "{args:?}");
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
/// reader gone the C is killed by `SIGPIPE`, and so is lsof-rs.
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's exit status"
)]
fn a_listing_on_a_failing_stderr() {
    let _serial = serial();
    with_a_nameless_owner(|pid, uid| {
        let pid = pid.to_string();
        // The control: the warning is written, so the runs below meet a
        // failing write.
        let out = Command::new(env!("CARGO_BIN_EXE_lsof"))
            .env("RES_OPTIONS", "attempts:0")
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
            .env("RES_OPTIONS", "attempts:0")
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
            .env("RES_OPTIONS", "attempts:0")
            .args(["-p", &pid])
            .stdout(Stdio::piped())
            .stderr(a_closed_pipe())
            .output()
            .expect("run lsof");
        assert_eq!(out.status.signal(), Some(SIGPIPE));
    });
}

/// `+m`'s print to a reader that has gone: the C is killed by `SIGPIPE` at
/// its write and says nothing (DIVERGENCES 153), and so is lsof-rs; with
/// the signal ignored both exit 0.
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's exit status"
)]
fn the_mount_print_into_a_closed_pipe_is_killed_by_sigpipe() {
    let _serial = serial();
    let out = Command::new(env!("CARGO_BIN_EXE_lsof"))
        .env("RES_OPTIONS", "attempts:0")
        .args(["+m"])
        .stdout(a_closed_pipe())
        .stderr(Stdio::piped())
        .output()
        .expect("run lsof");
    assert_eq!(
        out.status.signal(),
        Some(SIGPIPE),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stderr_of(&out.stderr).is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = lsof_with_sigpipe_ignored()
        .args(["+m"])
        .stdout(a_closed_pipe())
        .stderr(Stdio::piped())
        .output()
        .expect("run lsof");
    assert_eq!(out.status.code(), Some(0));
}

/// What is in stdout's buffer when a run ends without listing is written,
/// as the C's `exit()` writes it: `+m`'s lines, printed while `+d` reads
/// the mount table, before `-h` ends the run (measured: `lsof +m +d /tmp
/// -h 2>/dev/null | wc -c` is 551 bytes in the C on the review host;
/// lsof-rs had returned from `main` past its flush and printed none).
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's output"
)]
fn a_run_that_ends_at_its_help_writes_what_it_printed() {
    let _serial = serial();
    let dir = std::env::temp_dir();
    let out = Command::new(env!("CARGO_BIN_EXE_lsof"))
        .env("RES_OPTIONS", "attempts:0")
        .args(["-n", "-P", "+m", "+d"])
        .arg(&dir)
        .arg("-h")
        .stderr(Stdio::null())
        .output()
        .expect("run lsof");
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.lines()
            .any(|l| l.starts_with("/ 0x") || l.ends_with(" 0x0")),
        "{text:?}"
    );
}
