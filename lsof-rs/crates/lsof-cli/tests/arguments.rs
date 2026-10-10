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
        String::from_utf8_lossy(&out.stderr),
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

/// `-b` (DIVERGENCES 94, 122): a path argument is neither read nor `stat`ed,
/// lsof says so, and the status error follows, every one of them escaped —
/// where the C prints `avoiding stat(P)` raw. `-f` because lsof-rs then reads
/// no mount table, so the three lines stand alone (the C still names every
/// mount it avoids). `-w` mutes the first two, never the status error.
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
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "lsof: avoiding readlink(e^[[2Jx): -b was specified.\n\
         lsof: avoiding stat(e^[[2Jx): -b was specified.\n\
         lsof: status error on e^[[2Jx: Resource temporarily unavailable\n"
    );
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
        String::from_utf8_lossy(&out.stderr),
        "lsof: avoiding readlink(d): -b was specified.\n\
         lsof: avoiding stat(d): -b was specified.\n\
         lsof: WARNING: can't stat(d): Resource temporarily unavailable\n\
         Try 'lsof -h' for usage.\n"
    );
    let out = run(&["-w", "-b", "+d", "d"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "Try 'lsof -h' for usage.\n"
    );
    let out = run(&["-S", "0x", "-p", "1"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
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
        String::from_utf8_lossy(&out.stderr),
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
            String::from_utf8_lossy(&out.stderr)
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
    assert_eq!(
        out.status.code(),
        Some(0),
        "{loader}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
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
            eprintln!(
                "skipped: strace could not trace: {}",
                String::from_utf8_lossy(&out.stderr)
            );
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
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        text.lines()
            .any(|l| l.starts_with("sleep") && l.ends_with(file.to_str().unwrap())),
        "{text}"
    );
}
