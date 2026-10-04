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
        // The canonical temp directory: under a symlinked TMPDIR (macOS) the
        // C's spelling of a path replaces the link, and these tests compare
        // spellings.
        let tmp = std::fs::canonicalize(std::env::temp_dir()).expect("a temp directory");
        let dir = tmp.join(format!("lsof-rs-{name}-{}", std::process::id()));
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

/// Run the binary in `dir` with `args`, which may hold any bytes.
fn lsof_in(dir: &std::path::Path, args: &[&std::ffi::OsStr]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_lsof"))
        .current_dir(dir)
        .args(args)
        .output()
        .expect("run lsof")
}

/// `&str`s as the `OsStr`s [`lsof_in`] takes.
fn os<'a>(args: &[&'a str]) -> Vec<&'a std::ffi::OsStr> {
    args.iter().map(|a| std::ffi::OsStr::new(*a)).collect()
}

#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's stderr"
)]
fn a_status_error_names_the_path_readlink_made() {
    // The C `stat`s the argument as `Readlink()` spelt it, and names that
    // (DIVERGENCES 62): a link to a missing file is reported by its target,
    // a target that is not UTF-8 escaped byte by byte.
    use std::os::unix::ffi::OsStrExt;
    let dir = Scratch::new("status-readlink");
    let gone = dir.0.join("nosuch").join("f");
    std::os::unix::fs::symlink(&gone, dir.0.join("dangle")).unwrap();
    std::os::unix::fs::symlink(
        std::ffi::OsStr::from_bytes(b"\xfd-missing"),
        dir.0.join("nudangle"),
    )
    .unwrap();
    let out = lsof_in(&dir.0, &os(&["dangle", "nudangle"]));
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(out.stdout.is_empty());
    assert_eq!(
        err,
        format!(
            "lsof: status error on {}: No such file or directory\n\
             lsof: status error on \\xfd-missing: No such file or directory\n",
            gone.display()
        )
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's stderr"
)]
fn readlink_gives_up_as_the_c_does_and_minus_w_mutes_it() {
    let dir = Scratch::new("readlink-gives-up");
    std::os::unix::fs::symlink("loop2", dir.0.join("loop1")).unwrap();
    std::os::unix::fs::symlink("loop1", dir.0.join("loop2")).unwrap();
    let long = "a/".repeat(2100) + "f";
    let said = format!(
        "lsof: too many (> 20) symbolic links in readlink() path: loop1\n\
         lsof: readlink() path too long: {long}\n"
    );
    let out = lsof_in(&dir.0, &os(&["loop1", &long]));
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(String::from_utf8_lossy(&out.stderr), said);
    // A warning: `-w` mutes it, and the arguments are still dropped.
    let out = lsof_in(&dir.0, &os(&["-w", "loop1", &long]));
    assert_eq!(out.status.code(), Some(1));
    assert!(
        out.stderr.is_empty(),
        "{:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    // `-Q` mutes the search failure, not the warning.
    let out = lsof_in(&dir.0, &os(&["-Q", "loop1", &long]));
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&out.stderr), said);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's stderr"
)]
fn a_plus_d_the_c_cannot_use_ends_the_run_as_it_parses() {
    // DIVERGENCES 74: before anything is listed, `-Q` or not, ahead of `-h`;
    // the message muted by a `-w` before it, not by one after it.
    let dir = Scratch::new("plus-d-refused");
    std::fs::write(dir.0.join("x"), "x").unwrap();
    let gone = dir.0.join("nosuch").join("f");
    std::os::unix::fs::symlink(&gone, dir.0.join("dangle")).unwrap();
    std::os::unix::fs::symlink("loop2", dir.0.join("loop1")).unwrap();
    std::os::unix::fs::symlink("loop1", dir.0.join("loop2")).unwrap();
    let usage = "Try 'lsof -h' for usage.\n";
    let refused = |args: &[&str], said: &str| {
        let out = lsof_in(&dir.0, &os(args));
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
        assert_eq!(
            String::from_utf8_lossy(&out.stderr),
            format!("{said}{usage}"),
            "{args:?}"
        );
    };
    let cannot_stat = format!(
        "lsof: WARNING: can't stat({}): No such file or directory\n",
        gone.display()
    );
    refused(&["+d", "dangle", "x"], &cannot_stat);
    refused(&["-Q", "+D", "dangle", "x"], &cannot_stat);
    refused(&["+d", "dangle", "-h"], &cannot_stat);
    refused(&["+d", "dangle", "-w"], &cannot_stat);
    refused(&["-w", "+d", "dangle"], "");
    refused(&["-t", "+d", "dangle"], "");
    refused(&["+d", "x"], "lsof: WARNING: not a directory: x\n");
    refused(
        &["+D", "loop1"],
        "lsof: too many (> 20) symbolic links in readlink() path: loop1\n",
    );
    for value in ["", "-x", "+c"] {
        refused(
            &["+D", value],
            "lsof: +d not followed by a directory path\n",
        );
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's stderr"
)]
fn plus_f_drops_what_is_no_file_system() {
    // DIVERGENCES 76: said and dropped, the run ending only when nothing is
    // left; under `-Q`, in silence and with exit 0.
    let dir = Scratch::new("plus-f-drops");
    std::fs::create_dir(dir.0.join("plain")).unwrap();
    let out = lsof_in(&dir.0, &os(&["+f", "--", "plain"]));
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "lsof: not a file system: plain\n"
    );
    let out = lsof_in(&dir.0, &os(&["-Q", "+f", "--", "plain"]));
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stderr.is_empty() && out.stdout.is_empty());
}

#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's stderr"
)]
fn the_walk_warns_of_a_link_it_cannot_follow() {
    // Under `-x l` the C `stat`s a link to follow it, and says so when it
    // cannot (its spelling, `symbolc`, kept); without `-x l` it skips the
    // link unread, and `-w` mutes the warning.
    let dir = Scratch::new("walk-warns");
    std::fs::create_dir(dir.0.join("d")).unwrap();
    std::os::unix::fs::symlink("self", dir.0.join("d").join("self")).unwrap();
    let out = lsof_in(&dir.0, &os(&["-x", "l", "+d", "d"]));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "lsof: WARNING: can't stat(d/self) symbolc link: Too many levels of symbolic links\n"
    );
    // A `-w` after the option does not reach the walk the option began.
    let out = lsof_in(&dir.0, &os(&["-x", "l", "+d", "d", "-w"]));
    assert!(String::from_utf8_lossy(&out.stderr).contains("symbolc link"));
    for args in [&["+d", "d"][..], &["-w", "-x", "l", "+d", "d"]] {
        let out = lsof_in(&dir.0, &os(args));
        assert!(
            out.stderr.is_empty(),
            "{args:?}: {:?}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's stderr"
)]
fn an_empty_path_argument_is_a_status_error() {
    // The C's `Readlink("")` reads a buffer it never wrote, and in practice
    // searches for the argument before it again (a C-DEFECT, DIVERGENCES 79).
    // lsof-rs `stat`s the empty path, as written.
    let dir = Scratch::new("empty-arg");
    let out = lsof_in(&dir.0, &os(&[""]));
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "lsof: status error on : No such file or directory\n"
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's stderr"
)]
fn a_walk_stops_at_its_budget_and_says_so() {
    // Two links to `.` under `-x l` make a tree the C never finishes; lsof-rs
    // stops at its budget of names, quickly, and says so (DIVERGENCES 81).
    // The names are long so the bytes, not the entries, run out first.
    let dir = Scratch::new("walk-budget");
    std::fs::create_dir(dir.0.join("d")).unwrap();
    for c in ["a", "b"] {
        std::os::unix::fs::symlink(".", dir.0.join("d").join(c.repeat(250))).unwrap();
    }
    let started = std::time::Instant::now();
    let out = lsof_in(&dir.0, &os(&["-a", "-p", "1", "-x", "l", "+D", "d"]));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.lines()
            .any(|l| l.starts_with("lsof: WARNING: stopped walking d after ")),
        "{err}"
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(60));
    let out = lsof_in(&dir.0, &os(&["-w", "-a", "-p", "1", "-x", "l", "+D", "d"]));
    assert!(out.stderr.is_empty(), "-w mutes it");
}
