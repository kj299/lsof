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
    let err = stderr_of(&out);
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
    let err = stderr_of(&out);
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
    let err = stderr_of(&out);
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

/// Run the binary with `args`, from nowhere in particular.
fn lsof(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_lsof"))
        .args(args)
        .output()
        .expect("run lsof")
}

/// `out` ended the parse with exactly `message` and the usage hint, nothing
/// listed, and no raw ESC on stderr.
fn refused_with(out: &std::process::Output, message: &str) {
    let err = stderr_of(out);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(out.stdout.is_empty(), "{err}");
    assert_eq!(err, format!("lsof: {message}\nTry 'lsof -h' for usage.\n"));
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
fn an_inet_error_escapes_the_argument_it_quotes() {
    // DIVERGENCES 112: the C's words, and its `safestrprt()` of the spec.
    // lsof-rs had said `unterminated [` and written the ESC raw.
    refused_with(
        &lsof(&["-i", "@[1::\x1b[2J"]),
        "unacceptable Internet address in: -i @[1::^[[2J",
    );
    refused_with(
        &lsof(&["-i", ":1\x1b[2J"]),
        "unacceptable port specification in: -i :1^[[2J",
    );
    refused_with(
        &lsof(&["-i", ""]),
        "incomplete Internet address specification: -i ",
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's stderr"
)]
fn an_inet_name_error_escapes_the_name_too() {
    // The C prints the protocol, host and service names raw before the
    // escaped spec (DIVERGENCES 122); lsof-rs escapes both.
    refused_with(
        &lsof(&["-i", "a\x1b[2J"]),
        "unknown protocol name (a^[[2J) in: -i a^[[2J",
    );
    refused_with(
        &lsof(&["-i", ":a\x1b[2J"]),
        "service names are not resolved: -i :a^[[2J (give the port number)",
    );
    refused_with(
        &lsof(&["-i", "@h\x1b[2J"]),
        "host names are not resolved: -i @h^[[2J (give the address)",
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's stderr"
)]
fn plus_c_quotes_nothing() {
    // lsof-rs had said `invalid +c width: ` and the value, raw.
    for args in [&["+c", "\x1b[2J"][..], &["+c"][..]] {
        refused_with(&lsof(args), "+c not followed by width number");
    }
    // An attached value is given back and read as letters, as the C reads
    // it (DIVERGENCES 83): `+cx` is `-x` as well (measured).
    refused_with(
        &lsof(&["+cx"]),
        "+c not followed by width number\nlsof: -x must accompany +d or +D",
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's stderr"
)]
fn the_c_length_message_escapes_the_name() {
    // `safestrprt(…, 2)`: a space is `\x20` too (measured).
    refused_with(
        &lsof(&["-c", "aaaaaaaaaaaaaa\x1b[2J"]),
        "\"-c aaaaaaaaaaaaaa^[[2J\" length (18) > what system provides (15)",
    );
    refused_with(
        &lsof(&["-c", "a ba ba ba ba ba b"]),
        "\"-c a\\x20ba\\x20ba\\x20ba\\x20ba\\x20ba\\x20b\" length (18) > what system provides (15)",
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
    assert_eq!(stderr_of(&out), "Try 'lsof -h' for usage.\n");
    let out = run(&["-d", "3,^4"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr_of(&out).starts_with("lsof: exclude in an include -d list: ^4\n"));
}

/// What lsof said on stderr, less the mount table's warnings: on a host
/// where the user running the tests cannot `stat` some mount, every run that
/// reads the table says, as the C does, `lsof: WARNING: can't stat() TYPE file
/// system DIR` and `      Output information may be incomplete.` of it
/// (DIVERGENCES 87). Exactly that pair is tolerated, nothing else.
fn stderr_of(out: &std::process::Output) -> String {
    let text = String::from_utf8_lossy(&out.stderr);
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
    let err = stderr_of(&out);
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
    assert_eq!(stderr_of(&out), said);
    // A warning: `-w` mutes it, and the arguments are still dropped.
    let out = lsof_in(&dir.0, &os(&["-w", "loop1", &long]));
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr_of(&out).is_empty(), "{:?}", stderr_of(&out));
    // `-Q` mutes the search failure, not the warning.
    let out = lsof_in(&dir.0, &os(&["-Q", "loop1", &long]));
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(stderr_of(&out), said);
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
        assert_eq!(stderr_of(&out), format!("{said}{usage}"), "{args:?}");
    };
    let cannot_stat = format!(
        "lsof: WARNING: can't stat({}): No such file or directory\n",
        gone.display()
    );
    refused(&["+d", "dangle", "x"], &cannot_stat);
    refused(&["-Q", "+D", "dangle", "x"], &cannot_stat);
    // The C reads on after the error, so a later `-h` is read too, and
    // its help printed after it, exit 1 (DIVERGENCES 83, measured).
    let out = lsof_in(&dir.0, &os(&["+d", "dangle", "-h"]));
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    let err = stderr_of(&out);
    assert!(err.starts_with(&cannot_stat), "{err}");
    assert!(err[cannot_stat.len()..].starts_with("lsof-rs "), "{err}");
    assert!(!err.contains(usage), "{err}");
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
    assert_eq!(stderr_of(&out), "lsof: not a file system: plain\n");
    let out = lsof_in(&dir.0, &os(&["-Q", "+f", "--", "plain"]));
    assert_eq!(out.status.code(), Some(0));
    assert!(stderr_of(&out).is_empty() && out.stdout.is_empty());
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
        stderr_of(&out),
        "lsof: WARNING: can't stat(d/self) symbolc link: Too many levels of symbolic links\n"
    );
    // A `-w` after the option does not reach the walk the option began.
    let out = lsof_in(&dir.0, &os(&["-x", "l", "+d", "d", "-w"]));
    assert!(stderr_of(&out).contains("symbolc link"));
    for args in [&["+d", "d"][..], &["-w", "-x", "l", "+d", "d"]] {
        let out = lsof_in(&dir.0, &os(args));
        assert!(
            stderr_of(&out).is_empty(),
            "{args:?}: {:?}",
            stderr_of(&out)
        );
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's stderr"
)]
fn the_walk_warns_before_a_bare_paths_status_error() {
    // The C expands `+d` as it parses its options, before it looks at a bare
    // path: the walk's warning comes first, and still comes when the status
    // error then drops the last bare path and ends the run (DIVERGENCES 52,
    // 82). Measured against the C, byte for byte.
    let dir = Scratch::new("walk-first");
    std::fs::create_dir(dir.0.join("d")).unwrap();
    std::os::unix::fs::symlink("self", dir.0.join("d").join("self")).unwrap();
    let out = lsof_in(&dir.0, &os(&["-x", "l", "+d", "d", "/nonexistent"]));
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert_eq!(
        stderr_of(&out),
        "lsof: WARNING: can't stat(d/self) symbolc link: Too many levels of symbolic links\n\
         lsof: status error on /nonexistent: No such file or directory\n"
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's output"
)]
fn minus_v_reports_under_minus_q_and_never_under_minus_r() {
    use std::io::BufRead;
    let dir = Scratch::new("verbose");
    for f in ["a", "b"] {
        std::fs::write(dir.0.join(f), "").unwrap();
    }
    // `-Q` changes the exit status alone, as the C's `FsearchErr` does
    // (DIVERGENCES 53), and the report runs last given first (52).
    let out = lsof_in(&dir.0, &os(&["-V", "-Q", "a", "b"]));
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "lsof: no file use located: b\nlsof: no file use located: a\n"
    );
    // Under `-r` the C reports only after its loop, and a plain `-r` loop
    // ends only on a signal, which kills it first: no report at all (54).
    // The first two lines are therefore two cycles' markers, where lsof-rs
    // had printed the report before each.
    let mut child = Command::new(env!("CARGO_BIN_EXE_lsof"))
        .current_dir(&dir.0)
        .args(["-V", "-r", "1", "a"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("run lsof");
    let stdout = child.stdout.take().expect("stdout");
    let first: Vec<String> = std::io::BufReader::new(stdout)
        .lines()
        .take(2)
        .map(|l| l.expect("a line"))
        .collect();
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(first, ["=======", "======="]);
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
        stderr_of(&out),
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
    let err = stderr_of(&out);
    assert!(
        err.lines()
            .any(|l| l.starts_with("lsof: WARNING: stopped walking d after ")),
        "{err}"
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(60));
    let out = lsof_in(&dir.0, &os(&["-w", "-a", "-p", "1", "-x", "l", "+D", "d"]));
    assert!(stderr_of(&out).is_empty(), "-w mutes it");
}

#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's stderr"
)]
fn a_walk_entry_past_path_max_is_file_name_too_long() {
    // An entry whose path is 4097 bytes or more: the C's child takes at most
    // `MAXPATHLEN + 1` bytes of argument (`lib/misc.c` `doinchild()`), exits
    // on a longer one, and the C reports its own lost child as the `lstat`'s
    // error, `No child processes`, which no `lstat` returned (`File name too
    // long` under `-O`, where it makes the call itself). lsof-rs reports the
    // kernel's answer, by default and under `-O` (a C-DEFECT, DIVERGENCES
    // 127). The tree is built by relative steps, as no absolute path to its
    // bottom fits in PATH_MAX.
    let dir = Scratch::new("walk-deep");
    let level = "d".repeat(250);
    // `d`, 16 levels of `/` and 250 bytes, `/` and 82: 4100 bytes.
    let leaf = "e".repeat(82);
    let script = format!(
        "set -e; mkdir d; cd d; for i in $(seq 16); do mkdir {level}; cd {level}; done; : > {leaf}"
    );
    let made = Command::new("sh")
        .current_dir(&dir.0)
        .args(["-c", &script])
        .status()
        .expect("run sh");
    assert!(made.success(), "build the tree");
    let entry = format!("d{}/{leaf}", format!("/{level}").repeat(16));
    assert_eq!(entry.len(), 4100);
    for extra in [&[][..], &["-O"]] {
        let mut args = vec!["-a", "-p", "1"];
        args.extend_from_slice(extra);
        args.extend_from_slice(&["+D", "d"]);
        let out = lsof_in(&dir.0, &os(&args));
        assert_eq!(
            stderr_of(&out),
            format!("lsof: WARNING: can't lstat({entry}): File name too long\n"),
            "{extra:?}"
        );
    }
    let out = lsof_in(&dir.0, &os(&["-w", "-a", "-p", "1", "+D", "d"]));
    assert!(stderr_of(&out).is_empty(), "-w mutes it");
}

/// `-b` (DIVERGENCES 94, 122): a path argument is neither read nor `stat`ed,
/// lsof says so, and the status error follows, every one of them escaped —
/// where the C prints `avoiding stat(P)` raw. Between the first two lines the
/// mount table is read, as the C reads it at the first argument `Readlink()`
/// spelt, under `-f` too (DIVERGENCES 110, 113): each mount says it avoided
/// its `readlink` and its `stat` and that it could not be `stat`ed, in four
/// lines, which depend on the host and are checked for their shape. `-w`
/// mutes all but the status error.
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's stderr"
)]
fn dash_b_avoids_a_path_argument_and_says_so_escaped() {
    let dir = Scratch::new("dash-b");
    std::fs::write(dir.0.join("e\x1b[2Jx"), b"").expect("make a file");
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_lsof"))
            .current_dir(&dir.0)
            .args(args)
            .output()
            .expect("run lsof")
    };
    let out = run(&["-b", "-f", "--", "e\x1b[2Jx"]);
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    let lines: Vec<&str> = err.lines().collect();
    assert!(lines.len() >= 3, "{err}");
    assert_eq!(
        lines[0],
        "lsof: avoiding readlink(e^[[2Jx): -b was specified."
    );
    assert_eq!(
        lines[lines.len() - 2..],
        [
            "lsof: avoiding stat(e^[[2Jx): -b was specified.",
            "lsof: status error on e^[[2Jx: Resource temporarily unavailable",
        ]
    );
    let table = &lines[1..lines.len() - 2];
    assert!(!table.is_empty() && table.len() % 4 == 0, "{err}");
    for mount in table.chunks(4) {
        let dir = mount[0]
            .strip_prefix("lsof: avoiding readlink(")
            .and_then(|l| l.strip_suffix("): -b was specified."))
            .unwrap_or_else(|| panic!("{mount:?}"));
        assert_eq!(
            mount[1],
            format!("lsof: avoiding stat({dir}): -b was specified.")
        );
        assert!(
            mount[2].starts_with("lsof: WARNING: can't stat() ")
                && mount[2].ends_with(&format!(" file system {dir}")),
            "{mount:?}"
        );
        assert_eq!(mount[3], "      Output information may be incomplete.");
    }
    let out = run(&["-b", "-w", "-f", "--", "e\x1b[2Jx"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "lsof: status error on e^[[2Jx: Resource temporarily unavailable\n"
    );
}

/// `-b` before `+d` ends the run where the option stands, in the C's words
/// and order: the two `avoiding` lines, the warning, then the usage; `-w`
/// before it leaves the usage alone. A `-S` below 2 warns before an error
/// the parse finds after it.
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's stderr"
)]
fn what_the_parse_says_comes_in_the_cs_order() {
    let dir = Scratch::new("dash-b-plus-d");
    std::fs::create_dir(dir.0.join("d")).expect("mkdir d");
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_lsof"))
            .current_dir(&dir.0)
            .args(args)
            .output()
            .expect("run lsof")
    };
    let out = run(&["-b", "+d", "d"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert_eq!(
        stderr_of(&out),
        "lsof: avoiding readlink(d): -b was specified.\n\
         lsof: avoiding stat(d): -b was specified.\n\
         lsof: WARNING: can't stat(d): Resource temporarily unavailable\n\
         Try 'lsof -h' for usage.\n"
    );
    let out = run(&["-w", "-b", "+d", "d"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(stderr_of(&out), "Try 'lsof -h' for usage.\n");
    let out = run(&["-S", "0x", "-p", "1"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        stderr_of(&out),
        "lsof: WARNING: -S time (0) changed to 2\n\
         lsof: -x must accompany +d or +D\n\
         Try 'lsof -h' for usage.\n"
    );
}

/// A helper that cannot be started ends the run, in the C's words for the
/// step that failed: under a descriptor limit its pipes cannot be made, and
/// the C says `can't open pipes: Too many open files` (measured with
/// `ulimit -n 5`), exit 1. The limit leaves exactly three descriptor numbers
/// free below it ([`limit_leaving_free`]): enough to load the binary, not for
/// the helper's pipes.
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's stderr"
)]
fn no_helper_no_run() {
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "ulimit -n {} && exec '{}' -a -d cwd -p 1 /",
            limit_leaving_free(3),
            env!("CARGO_BIN_EXE_lsof")
        ))
        .output()
        .expect("run lsof");
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    assert_eq!(
        stderr_of(&out),
        "lsof: can't open pipes: Too many open files\n"
    );
}

/// The `ulimit -n` under which a child of this process starts with exactly
/// `free` descriptor numbers to open: past its stdin, stdout and stderr, and
/// past every descriptor this process holds without close-on-exec, which the
/// child inherits (`flags:` in fdinfo, octal; `O_CLOEXEC` is `02000000` on
/// x86 and arm). Counted, not taken as the highest one plus `free`: a CI
/// runner passed one down at a high number, which left the gap below it
/// free, and the helper started.
fn limit_leaving_free(free: usize) -> usize {
    let mut held: std::collections::BTreeSet<usize> = [0, 1, 2].into();
    for entry in std::fs::read_dir("/proc/self/fd")
        .expect("/proc/self/fd")
        .flatten()
    {
        let Ok(fd) = entry.file_name().to_string_lossy().parse::<usize>() else {
            continue;
        };
        let flags = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}"))
            .ok()
            .and_then(|info| {
                let f = info.lines().find_map(|l| l.strip_prefix("flags:"))?;
                u32::from_str_radix(f.trim(), 8).ok()
            });
        if flags.is_some_and(|f| f & 0o2_000_000 == 0) {
            held.insert(fd);
        }
    }
    let last = (0..)
        .filter(|fd| !held.contains(fd))
        .nth(free - 1)
        .expect("a free descriptor number");
    last + 1
}

/// A process to list, killed and reaped when it goes out of scope.
struct Sleeper(std::process::Child);

impl Sleeper {
    /// `sleep` reading `/dev/null`, in `/`.
    fn on_dev_null() -> Self {
        Sleeper(
            Command::new("sleep")
                .arg("60")
                .current_dir("/")
                .stdin(std::fs::File::open("/dev/null").expect("open /dev/null"))
                .spawn()
                .expect("start a sleeper"),
        )
    }
}

impl Drop for Sleeper {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// `/proc/self` is lsof however a path spells its way there (DIVERGENCES 89):
/// the links are read by lsof's helper, whose own `/proc/self` is another
/// process, and every spelling — doubled slashes, `.`, `..`, a link to it,
/// and relative from `/proc`, `/` and `/dev` — must still reach lsof's fd 0,
/// which is `/dev/null` here, as the sleeper's is. Measured before the fix:
/// `/proc//self/fd/0` was `status error on /proc/HELPER/fd/pipe:[N]`.
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation)"
)]
fn a_path_through_proc_self_is_lsof_however_it_is_spelt() {
    let sleeper = Sleeper::on_dev_null();
    let pid = sleeper.0.id().to_string();
    let dev_fd =
        std::fs::read_link("/dev/fd").is_ok_and(|t| t == std::path::Path::new("/proc/self/fd"));
    let mut spellings = vec![
        ("/", "/proc/self/fd/0"),
        ("/", "/proc//self/fd/0"),
        ("/", "/proc/./self/fd/0"),
        ("/", "//proc/self/fd/0"),
        ("/", "/proc/self/../self/fd/0"),
        ("/", "/proc/thread-self/fd/0"),
        ("/proc", "self/fd/0"),
        ("/", "proc/self/fd/0"),
    ];
    if dev_fd {
        spellings.extend([("/", "/dev//fd/0"), ("/", "/dev/stdin"), ("/dev", "fd/0")]);
    }
    for (cwd, arg) in spellings {
        let out = Command::new(env!("CARGO_BIN_EXE_lsof"))
            .current_dir(cwd)
            .args(["-n", "-P", "-a", "-d", "0", "-p", &pid, arg])
            .stdin(std::fs::File::open("/dev/null").expect("open /dev/null"))
            .output()
            .expect("run lsof");
        let text = String::from_utf8_lossy(&out.stdout);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{arg} from {cwd}: {}",
            stderr_of(&out)
        );
        assert!(
            text.lines()
                .any(|l| l.starts_with("sleep") && l.ends_with("/dev/null")),
            "{arg} from {cwd}: {text}"
        );
    }
}

/// lsof run by naming the dynamic loader (`ld.so lsof ...`, as a binary on a
/// `noexec` mount is run): `/proc/self/exe` is then the loader, and the
/// helper must be started through it. Measured before the fix: every run
/// that read the mount table ended `lsof: can't fork: No child processes`.
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation)"
)]
fn run_through_the_loader_the_helper_is_too() {
    // The loader this test process was loaded by, which loads lsof too.
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap_or_default();
    let Some(loader) = maps.lines().find_map(|l| {
        let path = l.split_whitespace().nth(5)?;
        let name = path.rsplit('/').next()?;
        (name.starts_with("ld-") && name.contains(".so")).then(|| path.to_string())
    }) else {
        eprintln!("skipped: no dynamic loader mapped (a static build)");
        return;
    };
    let sleeper = Sleeper::on_dev_null();
    let out = Command::new(&loader)
        .arg(env!("CARGO_BIN_EXE_lsof"))
        .args(["-n", "-P", "-a", "-d", "0", "-p"])
        .arg(sleeper.0.id().to_string())
        .arg("/dev/null")
        .output()
        .expect("run lsof through the loader");
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{loader}: {}", stderr_of(&out));
    assert!(stderr_of(&out).is_empty(), "{}", stderr_of(&out));
    assert!(
        text.lines()
            .any(|l| l.starts_with("sleep") && l.ends_with("/dev/null")),
        "{text}"
    );
}

/// The helper as lsof lists it, measured on a live one (`-r` keeps it): its
/// command name is lsof's, though `/proc/self/exe` is what it execs, which
/// would make it `exe`; its working directory is lsof's, as a forked child's
/// is; and it holds its pipes and `/dev/null`, on fds 0, 1 and 2.
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation)"
)]
fn the_helper_is_named_and_placed_as_lsof_is() {
    let dir = Scratch::new("helper-seen");
    std::fs::write(dir.0.join("f"), b"").expect("make a file");
    // `-r` lists, sleeps, lists again: the helper the first listing started
    // waits for the next call meanwhile. `f`: a path argument, so a call.
    let mut lsof = Command::new(env!("CARGO_BIN_EXE_lsof"))
        .current_dir(&dir.0)
        .args(["-r", "30", "-n", "-P", "f"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("start lsof");
    let me = lsof.id().to_string();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let helper = loop {
        let found = std::fs::read_dir("/proc")
            .expect("read /proc")
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter(|p| p.bytes().all(|b| b.is_ascii_digit()))
            .find(|p| {
                let status =
                    std::fs::read_to_string(format!("/proc/{p}/status")).unwrap_or_default();
                let cmdline = std::fs::read(format!("/proc/{p}/cmdline")).unwrap_or_default();
                status
                    .lines()
                    .any(|l| l.strip_prefix("PPid:").map(str::trim) == Some(&me))
                    && cmdline
                        .split(|&b| b == 0)
                        .any(|a| a == b"--lsof-rs-bounded-fs-helper")
            });
        if let Some(p) = found {
            break p;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no helper under lsof {me}"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    // Found by its argument the moment it execs, it is still `exe` until
    // `serve()` takes lsof's name, a few milliseconds later and before it
    // greets (so lsof, which waits for the greeting, never lists it as
    // `exe`). Read once at once, this had failed now and then.
    let comm = loop {
        let comm = std::fs::read_to_string(format!("/proc/{helper}/comm"));
        if comm.as_deref().is_ok_and(|c| c == "lsof\n") || std::time::Instant::now() >= deadline {
            break comm;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    let cwd = std::fs::read_link(format!("/proc/{helper}/cwd"));
    let fds: Vec<String> = (0..3)
        .map(|fd| {
            std::fs::read_link(format!("/proc/{helper}/fd/{fd}"))
                .map(|t| t.to_string_lossy().into_owned())
                .unwrap_or_default()
        })
        .collect();
    let _ = lsof.kill();
    let _ = lsof.wait();
    assert_eq!(comm.expect("the helper's comm"), "lsof\n");
    assert_eq!(cwd.expect("the helper's cwd"), dir.0);
    assert!(
        fds[0].starts_with("pipe:[") && fds[1].starts_with("pipe:["),
        "{fds:?}"
    );
    assert_eq!(fds[2], "/dev/null");
}

/// A `stat` is the path opened `O_PATH` and the descriptor asked, never
/// `statx` of the path, which std's `metadata()` makes without
/// `AT_NO_AUTOMOUNT` and which so mounts an automount point (DIVERGENCES
/// 110): pinned with `strace`, in the helper and under `-O` in lsof itself.
/// Skipped where there is no `strace` that can trace.
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation)"
)]
fn a_stat_opens_the_path_o_path_and_never_statx_it() {
    let dir = Scratch::new("o-path");
    let file = dir.0.join("f");
    std::fs::write(&file, b"").expect("make a file");
    let shown = file.to_str().expect("a UTF-8 scratch path");
    for extra in [&[][..], &["-O"][..]] {
        let trace = dir.0.join("trace");
        let out = Command::new("strace")
            .args([
                "-f",
                "-qq",
                "-e",
                "trace=openat,statx,newfstatat,stat,lstat",
                "-o",
            ])
            .arg(&trace)
            .arg(env!("CARGO_BIN_EXE_lsof"))
            .args(extra)
            .args(["-n", "-P", shown])
            .output();
        let Ok(out) = out else {
            eprintln!("skipped: no strace");
            return;
        };
        let Ok(text) = std::fs::read_to_string(&trace) else {
            eprintln!("skipped: strace could not trace: {}", stderr_of(&out));
            return;
        };
        let quoted = format!("\"{shown}\"");
        let on_it: Vec<&str> = text.lines().filter(|l| l.contains(&quoted)).collect();
        assert!(
            on_it
                .iter()
                .any(|l| l.contains("openat(") && l.contains("O_PATH")),
            "{extra:?}: no O_PATH open of the path: {on_it:#?}"
        );
        assert!(
            !on_it.iter().any(|l| l.contains("statx(")
                || l.contains("newfstatat(")
                || l.contains(" stat(")
                || l.contains("lstat(")),
            "{extra:?}: a stat of the path itself: {on_it:#?}"
        );
    }
}

/// Each `lstat` (`L`) and `stat` (`F`) a traced lsof made of a path, in
/// order, read from an `strace -f` log of `openat`, `statx`, `newfstatat`,
/// `fstat`, `stat` and `lstat`. lsof-rs makes one as `stat_now` does: the
/// path opened `O_PATH`, with `O_NOFOLLOW` for an `lstat`, and then, in the
/// same process, the descriptor asked (`statx(fd, "", AT_EMPTY_PATH)`, or
/// `fstat`). A `stat` of the path by name, which lsof-rs never makes, is a
/// `B`. A call cut in two by another process's (`<unfinished ...>`, `<...
/// resumed>`) is joined first.
fn stat_profile(log: &str) -> std::collections::HashMap<String, String> {
    use std::collections::HashMap;
    let mut profile: HashMap<String, String> = HashMap::new();
    // (pid, fd) -> the path an `O_PATH` open gave it, and its letter.
    let mut open: HashMap<(String, String), (String, char)> = HashMap::new();
    let mut cut: HashMap<String, String> = HashMap::new();
    let quoted = |s: &str| -> Option<String> {
        let start = s.find('"')? + 1;
        let len = s[start..].find('"')?;
        Some(s[start..start + len].to_string())
    };
    for line in log.lines() {
        let Some((pid, call)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        let mut call = call.trim_start().to_string();
        if let Some(head) = call.strip_suffix(" <unfinished ...>") {
            cut.insert(pid.to_string(), head.to_string());
            continue;
        }
        if call.starts_with("<... ") {
            let Some((_, rest)) = call.split_once("resumed>") else {
                continue;
            };
            call = cut.remove(pid).unwrap_or_default() + rest;
        }
        let Some((_, ret)) = call.rsplit_once(" = ") else {
            continue;
        };
        let ok = !ret.starts_with('-');
        let (name, args) = call.split_once('(').unwrap_or_default();
        let first = args.split(',').next().unwrap_or_default();
        match name {
            "openat" => {
                let fd = ret.split_whitespace().next().unwrap_or_default();
                let key = (pid.to_string(), fd.to_string());
                // Any open that gives the descriptor ends what it was.
                open.remove(&key);
                if let (true, true, Some(path)) = (ok, args.contains("O_PATH"), quoted(args)) {
                    let letter = if args.contains("O_NOFOLLOW") {
                        'L'
                    } else {
                        'F'
                    };
                    open.insert(key, (path, letter));
                }
            }
            "statx" | "newfstatat" | "stat" | "lstat" if args.contains('"') => {
                if args.contains("\"\"") && args.contains("AT_EMPTY_PATH") {
                    if let Some((path, letter)) = open.get(&(pid.to_string(), first.to_string())) {
                        profile.entry(path.clone()).or_default().push(*letter);
                    }
                } else if let Some(path) = quoted(args) {
                    profile.entry(path).or_default().push('B');
                }
            }
            "fstat" => {
                if let Some((path, letter)) = open.get(&(pid.to_string(), first.to_string())) {
                    profile.entry(path.clone()).or_default().push(*letter);
                }
            }
            _ => {}
        }
    }
    profile
}

/// A `+d`/`+D` entry is described by its one `lstat`, and a link `-x l`
/// follows by one `stat` more; the directory itself is the option's one
/// `stat`, and the walk asks it nothing but its listing (DIVERGENCES 111).
/// That is the C's profile, measured (`arg.c:876,1014,1047`): `L` an
/// entry, `LF` a followed link, `F` the directory, where lsof-rs had made
/// `LF`, `LFF` and `FFL`. Pinned with `strace -f`, so in the helper that
/// makes the calls and, under `-O`, in lsof itself; and with no `stat` of
/// any of them by name. The tree has no socket (a socket's bound path is
/// `stat`ed for its row), and `-a -p` keeps the scan to this test. Skipped
/// where there is no `strace` that can trace.
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation)"
)]
fn a_walk_entry_is_stated_once() {
    let scratch = Scratch::new("walk-once");
    let d = scratch.0.join("d");
    std::fs::create_dir_all(d.join("sub")).expect("mkdir d/sub");
    std::fs::write(d.join("reg"), b"").expect("make d/reg");
    std::fs::write(d.join("sub/in"), b"").expect("make d/sub/in");
    std::os::unix::fs::symlink("reg", d.join("lnk")).expect("make d/lnk");
    let top = d.to_str().expect("a UTF-8 scratch path").to_string();
    let me = std::process::id().to_string();
    for in_process in [false, true] {
        for follow in [false, true] {
            let trace = scratch.0.join("trace");
            let _ = std::fs::remove_file(&trace);
            let mut args = vec!["-n", "-P", "-a", "-p", &me];
            if in_process {
                args.push("-O");
            }
            if follow {
                args.extend(["-x", "l"]);
            }
            args.extend(["+D", &top]);
            let out = Command::new("strace")
                .args(["-f", "-qq", "-e"])
                .arg("trace=execve,openat,statx,newfstatat,fstat,stat,lstat")
                .arg("-o")
                .arg(&trace)
                .arg(env!("CARGO_BIN_EXE_lsof"))
                .args(&args)
                .output();
            let Ok(out) = out else {
                eprintln!("skipped: no strace");
                return;
            };
            let log = std::fs::read_to_string(&trace).unwrap_or_default();
            if !log.contains("execve(") {
                eprintln!("skipped: strace could not trace: {}", stderr_of(&out));
                return;
            }
            let how = format!("{args:?}");
            // Nothing here is open in this test, so nothing is located.
            assert_eq!(out.status.code(), Some(1), "{how}: {out:?}");
            let profile = stat_profile(&log);
            let of = |rel: &str| {
                let path = if rel.is_empty() {
                    top.clone()
                } else {
                    format!("{top}/{rel}")
                };
                profile.get(&path).cloned().unwrap_or_default()
            };
            let link = if follow { "LF" } else { "L" };
            assert_eq!(
                [of(""), of("reg"), of("sub"), of("sub/in"), of("lnk")],
                ["F", "L", "L", "L", link],
                "{how}: the directory, reg, sub, sub/in, lnk"
            );
        }
    }
}

/// In a pid namespace that shares the host's `/proc`, lsof's `getpid()` is
/// not the pid procfs gives it, and `/proc/self` must still be lsof
/// (DIVERGENCES 89): the helper takes both pids from `/proc`. Here lsof's
/// stdin is a file only a sleeper outside holds as well, so `/proc/self/fd/0`
/// finds the sleeper only if it is read as lsof's. Root only (`unshare -p`),
/// skipped, saying why, otherwise.
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation)"
)]
fn proc_self_is_lsof_in_a_pid_namespace_too() {
    let works = Command::new("unshare")
        .args(["-p", "-f", "true"])
        .output()
        .is_ok_and(|o| o.status.success());
    if !works {
        eprintln!("skipped: no `unshare -p` here (root only)");
        return;
    }
    let dir = Scratch::new("pid-namespace");
    let file = dir.0.join("held");
    std::fs::write(&file, b"x").expect("make a file");
    let held = || std::fs::File::open(&file).expect("open the file");
    let sleeper = Sleeper(
        Command::new("sleep")
            .arg("60")
            .current_dir("/")
            .stdin(held())
            .spawn()
            .expect("start a sleeper"),
    );
    let out = Command::new("unshare")
        .args([
            "-p",
            "-f",
            env!("CARGO_BIN_EXE_lsof"),
            "-n",
            "-P",
            "-a",
            "-d",
            "0",
            "-p",
        ])
        .arg(sleeper.0.id().to_string())
        .arg("/proc/self/fd/0")
        .stdin(held())
        .output()
        .expect("run lsof in a pid namespace");
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    assert!(
        text.lines()
            .any(|l| l.starts_with("sleep") && l.ends_with(file.to_str().unwrap())),
        "{text}"
    );
}

/// What the C prints as it reads its mount table, in its order, where the
/// differential can only compare stdout and the status: a run that ends in
/// the usage (DIVERGENCES 83, 87, 110, 114, 115). In a mount namespace of the
/// test's own, a tmpfs mounted over the one at `gone/m`, which no one can
/// `stat` then; nothing is held on either. Root only (`unshare -m`), skipped,
/// saying why, otherwise.
///
/// * `+d D -e GONE`: the table is read at the `+d`, before the `-e`, so GONE
///   is `stat`ed and warned of, and then the `-e` is refused; `-e GONE +d D`
///   neither warns nor refuses (critic gap 0).
/// * every unmounted `-e` is refused, the last given first, after the
///   table's lines (critic gap 1, m1);
/// * an error found once every option is read, before the `-e` check, comes
///   before the table's lines, which that check reads (m9).
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation)"
)]
fn a_mount_table_of_its_own_says_what_the_c_says() {
    let works = Command::new("unshare")
        .args(["-m", "--propagation", "private", "true"])
        .output()
        .is_ok_and(|o| o.status.success());
    if !works {
        eprintln!("skipped: no `unshare -m` here (root only)");
        return;
    }
    let dir = Scratch::new("own-table");
    let base = dir.0.join("t");
    std::fs::create_dir(&base).expect("make the base");
    let script = format!(
        r#"set -u
B='{base}'; LSOF='{lsof}'
cd /
mount -t tmpfs lsof-rs-own-table "$B" || {{ echo "nomount"; exit 0; }}
mkdir -p "$B/gone/m" "$B/d"
mount -t tmpfs src_gone "$B/gone/m"
mount -t tmpfs src_gone_top "$B/gone"
run() {{
    "$LSOF" "$@" -a -p 1 -d cwd >/dev/null 2>"$B.err"
    echo "rc=$?"
    tr '\n' '|' < "$B.err"; echo
}}
run +d "$B/d" -e "$B/gone/m"
run -e "$B/gone/m" +d "$B/d"
run -e /nosuch1 -e /nosuch2
run -e /nosuch -x f
umount -l "$B"
"#,
        base = base.display(),
        lsof = env!("CARGO_BIN_EXE_lsof"),
    );
    let out = Command::new("timeout")
        .args([
            "60",
            "unshare",
            "-m",
            "--propagation",
            "private",
            "sh",
            "-c",
        ])
        .arg(&script)
        .output()
        .expect("run the namespace");
    let text = String::from_utf8_lossy(&out.stdout);
    if text.starts_with("nomount") {
        eprintln!("skipped: tmpfs could not be mounted here");
        return;
    }
    let gone = base.join("gone/m");
    let warned = format!(
        "lsof: WARNING: can't stat() tmpfs file system {}|      Output information may be incomplete.|",
        gone.display()
    );
    let refused = |p: &str| format!("lsof: \"-e {p}\" is not a mounted file system.|");
    let usage = "Try 'lsof -h' for usage.|";
    let want = [
        "rc=1".to_string(),
        format!("{warned}{}{usage}", refused(&gone.display().to_string())),
        // `d` holds nothing: the search fails, and nothing is said.
        "rc=1".to_string(),
        String::new(),
        "rc=1".to_string(),
        format!(
            "{warned}{}{}{usage}",
            refused("/nosuch2"),
            refused("/nosuch1")
        ),
        "rc=1".to_string(),
        format!(
            "lsof: -x must accompany +d or +D|{warned}{}{usage}",
            refused("/nosuch")
        ),
    ];
    let got: Vec<&str> = text.lines().collect();
    assert_eq!(got, want, "{text}");
    // Nothing of the namespace outlives it.
    let mounts = std::fs::read_to_string("/proc/self/mounts").unwrap_or_default();
    assert!(!mounts.contains(&base.display().to_string()), "{mounts}");
}

/// `-f` only stops a path argument from naming a file system: the table is
/// read for `-e` under it too, and a mounted `-e` is accepted. lsof-rs had
/// read no table under `-f` and refused it, exit 1 (DIVERGENCES 113).
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation)"
)]
fn dash_f_dash_e_of_a_mount_is_accepted() {
    let mounts = std::fs::read_to_string("/proc/self/mounts").unwrap_or_default();
    if !mounts
        .lines()
        .any(|l| l.split(' ').nth(1) == Some("/dev/shm"))
    {
        eprintln!("skipped: /dev/shm is not a mount point here");
        return;
    }
    let me = std::process::id().to_string();
    let out = Command::new(env!("CARGO_BIN_EXE_lsof"))
        .args(["-w", "-f", "-e", "/dev/shm", "-a", "-d", "cwd", "-p", &me])
        .output()
        .expect("run lsof");
    assert_eq!(out.status.code(), Some(0), "{}", stderr_of(&out));
    assert!(stderr_of(&out).is_empty(), "{}", stderr_of(&out));
    let out = Command::new(env!("CARGO_BIN_EXE_lsof"))
        .args([
            "-w",
            "-f",
            "-e",
            "/nonexistent-mount",
            "-a",
            "-d",
            "cwd",
            "-p",
            &me,
        ])
        .output()
        .expect("run lsof");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        stderr_of(&out),
        "lsof: \"-e /nonexistent-mount\" is not a mounted file system.\nTry 'lsof -h' for usage.\n"
    );
}

/// `-h` and `-?` write the help to stderr and exit 0, as the C's `usage()`
/// does (DIVERGENCES 114): a script reading `lsof -h 2>/dev/null` gets nothing
/// from either. With another option the help still wins, and an error the C
/// finds once every option is read still beats it (item 115): the error, then
/// the help, exit 1, as the C's `usage()` prints them (DIVERGENCES 150).
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's streams"
)]
fn the_help_goes_to_stderr() {
    for args in [&["-h"][..], &["-?"], &["-h", "-p", "1"], &["-p", "1", "-h"]] {
        let out = lsof(args);
        assert_eq!(out.status.code(), Some(0), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}: help on stdout");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("USAGE:"), "{args:?}: {err}");
    }
    // `-hx` is `-x`'s error, then the help in place of the usage hint.
    let out = lsof(&["-hx"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.starts_with("lsof: -x must accompany +d or +D\nlsof-rs "),
        "{err}"
    );
    assert!(
        err.contains("USAGE:") && !err.contains("Try 'lsof -h'"),
        "{err}"
    );
}

/// `-v` writes lsof-rs's version line to stderr and exits 0, as the C's
/// `usage()` writes its version report (DIVERGENCES 150): stdout is empty.
/// With `-h` or `-F ?` it comes after them, whatever the order given; with an
/// error alone it is not printed; with an error and `-h` or `-F ?` it is,
/// last, and the run exits 1 (all measured on the C).
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's streams"
)]
fn the_version_goes_to_stderr() {
    let version = format!("lsof-rs {} (memory-safe lsof)\n", env!("CARGO_PKG_VERSION"));
    for args in [
        &["-v"][..],
        &["-v", "-p", "1"],
        &["-p", "1", "-v"],
        &["+v"],
        &["-v", "-v"],
    ] {
        let out = lsof(args);
        assert_eq!(out.status.code(), Some(0), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}: version on stdout");
        assert_eq!(String::from_utf8_lossy(&out.stderr), version, "{args:?}");
    }
    // The help, the field letters, the version: in that order, exit 0.
    for args in [&["-v", "-h"][..], &["-h", "-v"], &["-vh"]] {
        let out = lsof(args);
        assert_eq!(out.status.code(), Some(0), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.starts_with("lsof-rs ") && err.contains("USAGE:"),
            "{args:?}"
        );
        assert!(err.ends_with(&version), "{args:?}: {err}");
    }
    for args in [&["-v", "-F", "?"][..], &["-F", "?", "-v"]] {
        let out = lsof(args);
        assert_eq!(out.status.code(), Some(0), "{args:?}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.starts_with("lsof:\tID    field description\n"),
            "{args:?}"
        );
        assert!(err.ends_with(&version), "{args:?}: {err}");
    }
    let out = lsof(&["-h", "-v", "-F", "?"]);
    let err = String::from_utf8_lossy(&out.stderr);
    let (help, field, ver) = (
        err.find("USAGE:").unwrap(),
        err.find("ID    field description").unwrap(),
        err.find(&version).unwrap(),
    );
    assert!(help < field && field < ver, "{err}");
    // An error with `-h` and `-F ?`: the error, the help, the letters, and
    // no usage hint, which the help stands in for (measured: the C prints
    // its usage line once, then the help).
    for args in [&["-W", "-h", "-F", "?"][..], &["-F", "?", "-h", "-x"]] {
        let out = lsof(args);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.starts_with("lsof: ") && err.contains("\nlsof-rs "),
            "{args:?}: {err}"
        );
        assert!(!err.contains("Try 'lsof -h'"), "{args:?}: {err}");
        assert!(err.contains("ID    field description"), "{args:?}: {err}");
    }
    let out = lsof(&["-W", "-h", "-F", "?"]);
    assert!(String::from_utf8_lossy(&out.stderr)
        .starts_with("lsof: illegal option character: W\nlsof-rs "));
    // An error and `-v`: the error and the hint, no version.
    let out = lsof(&["-v", "-x"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "lsof: -x must accompany +d or +D\nTry 'lsof -h' for usage.\n"
    );
    // An error, `-F ?` and `-v`: the error, the hint, the letters, the
    // version, exit 1.
    let out = lsof(&["-W", "-F", "?", "-v"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.starts_with(
            "lsof: illegal option character: W\nTry 'lsof -h' for usage.\nlsof:\tID    field description\n"
        ),
        "{err}"
    );
    assert!(err.ends_with(&version), "{err}");
    // An error, `-h` and `-v`: the error, the help, the version.
    let out = lsof(&["-W", "-h", "-v"]);
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.starts_with("lsof: illegal option character: W\nlsof-rs "),
        "{err}"
    );
    assert!(err.contains("USAGE:") && err.ends_with(&version), "{err}");
}

/// A letter that is no option is the C's `illegal option character: X`, and
/// the parse reads on, through the rest of the word and the words after:
/// every error it then finds is printed, and the run exits 1 (DIVERGENCES
/// 149, measured on the C).
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's streams"
)]
fn an_illegal_option_character_reads_on() {
    let hint = "Try 'lsof -h' for usage.";
    let cases: &[(&[&str], &[&str])] = &[
        (&["-W"], &["lsof: illegal option character: W"]),
        (&["+W"], &["lsof: illegal option character: W"]),
        (
            &["-Wz"],
            &[
                "lsof: illegal option character: W",
                "lsof: illegal option character: z",
            ],
        ),
        (
            &["-W", "-Y"],
            &[
                "lsof: illegal option character: W",
                "lsof: illegal option character: Y",
            ],
        ),
        (
            &["-o", "-s", "-W"],
            &[
                "lsof: illegal option character: W",
                "lsof: -o and -s are mutually exclusive",
            ],
        ),
        (
            &["-u", "lsofrs-no-such-login", "-W"],
            &[
                "lsof: can't get UID for lsofrs-no-such-login",
                "lsof: illegal option character: W",
            ],
        ),
        (&["-W", "-X", "-i"], &["lsof: illegal option character: W"]),
        (&["-W", "-a"], &["lsof: illegal option character: W"]),
        (
            &["-W", "/nonexistent"],
            &["lsof: illegal option character: W"],
        ),
        (&["-:"], &["lsof: colon is an illegal option character."]),
        (
            &["-W:"],
            &[
                "lsof: illegal option character: W",
                "lsof: colon is an illegal option character.",
            ],
        ),
        (&["-+"], &["lsof: illegal option character: +"]),
        (&["-\u{1b}"], &["lsof: illegal option character: ^["]),
        (
            &["-D", "-W", "-Y"],
            &[
                "lsof: unsupported option: -D",
                "lsof: illegal option character: Y",
            ],
        ),
        (
            &["-Dfoo", "-W"],
            &[
                "lsof: unsupported option: -D",
                "lsof: illegal option character: W",
            ],
        ),
    ];
    for (args, want) in cases {
        let out = lsof(args);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}");
        let mut lines: Vec<&str> = want.to_vec();
        lines.push(hint);
        assert_eq!(stderr_of(&out), lines.join("\n") + "\n", "{args:?}");
    }
}

/// `-m` is the C's `-m not supported` on Linux, which reads no kernel memory
/// file, and takes its value word as the C's `GetOpt` does (measured).
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation); this test is about the spawned binary's streams"
)]
fn dash_m_is_not_supported_in_the_cs_words() {
    for (args, want) in [
        (&["-m"][..], &["lsof: -m not supported"][..]),
        (
            &["-m", "-W", "-Y"],
            &[
                "lsof: -m not supported",
                "lsof: illegal option character: Y",
            ],
        ),
        (
            &["-mfoo", "-W"],
            &[
                "lsof: -m not supported",
                "lsof: illegal option character: W",
            ],
        ),
    ] {
        let out = lsof(args);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        let mut lines = want.to_vec();
        lines.push("Try 'lsof -h' for usage.");
        assert_eq!(stderr_of(&out), lines.join("\n") + "\n", "{args:?}");
    }
}
