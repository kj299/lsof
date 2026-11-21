//! How lsof starts, as the C starts (`src/main.c:173-183`), and what follows
//! from it: the real binary, run with descriptors it was handed, with
//! descriptors closed, with no `/dev/null` and with no `/proc`.
//!
//! The C closes every descriptor from 3 up (`closefrom_shim(ctx, 3)`), opens
//! `/dev/null` until the descriptor it gets is at least 2, and ends, exit 1
//! with nothing said, where it cannot open it, all before it reads an
//! option. lsof-rs does the same in a constructor that runs before the Rust
//! runtime (`lsof-sigpipe`; DIVERGENCES 170, 171). Every expectation here
//! was measured on the C lsof 4.99.6 with the same command.
//!
//! The cases that need a mount namespace (a `/dev` with no `null`, a
//! `/dev/null` that cannot be written, no `/proc`) run as root, or where an
//! unprivileged user may make a user namespace, and are skipped, saying
//! why, elsewhere; the differential runs the same ones against the C. The
//! rest need nothing.
#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::{Command, Output};

const LSOF: &str = env!("CARGO_BIN_EXE_lsof");

/// A directory of the test's own, removed when it goes out of scope.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let tmp = std::fs::canonicalize(std::env::temp_dir()).expect("a temp directory");
        let dir = tmp.join(format!("lsof-rs-startup-{name}-{}", std::process::id()));
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

/// `sh -c SCRIPT sh LSOF ARGS...`: the script names the binary `"$1"` and
/// `exec`s it, so that `$$` is lsof's own pid and the descriptors the script
/// set up are the ones lsof starts with. No name is looked up: every listing
/// here is `-n -P`, and the resolver is told to ask no one.
fn sh(script: &str, args: &[&str]) -> Output {
    Command::new("sh")
        .arg("-c")
        .arg(script)
        .arg("sh")
        .arg(LSOF)
        .args(args)
        .env("RES_OPTIONS", "attempts:0")
        .current_dir("/")
        .output()
        .expect("run sh")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// `out` ended with status 1 and wrote nothing at all: the C's `Error()`.
fn ended_in_silence(out: &Output, what: &str) {
    assert_eq!(out.status.code(), Some(1), "{what}: {}", text(&out.stderr));
    assert!(out.stdout.is_empty(), "{what}: {}", text(&out.stdout));
    assert!(out.stderr.is_empty(), "{what}: {}", text(&out.stderr));
}

/// What a run said on stderr, but for what it says of the host's mounts:
/// a user who is not root cannot `stat` every mount point (tracefs, another
/// user's FUSE mount), and both lsofs warn of each, with a second line.
fn said(out: &Output) -> Vec<String> {
    text(&out.stderr)
        .lines()
        .filter(|l| {
            !l.starts_with("lsof: WARNING: can't stat() ")
                && *l != "      Output information may be incomplete."
        })
        .map(str::to_string)
        .collect()
}

/// `out` listed nothing, said nothing of its own, and ended with status 1:
/// a search that found nothing.
fn found_nothing(out: &Output, what: &str) {
    assert_eq!(out.status.code(), Some(1), "{what}: {}", text(&out.stderr));
    assert!(out.stdout.is_empty(), "{what}: {}", text(&out.stdout));
    assert_eq!(said(out), [] as [String; 0], "{what}");
}

/// A file only lsof itself was handed is no open file to it: the C closes
/// the descriptor before it looks at anything, lists nothing, and exits 1
/// for the file it did not find (measured: `lsof FILE 9<FILE`). lsof-rs had
/// kept it, listed itself and its helper, and exited 0.
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation)"
)]
fn a_file_only_lsof_was_handed_is_not_found() {
    let dir = Scratch::new("handed");
    let file = dir.0.join("probe");
    std::fs::write(&file, "").expect("write the probe");
    let file = file.to_str().expect("a UTF-8 temp directory");
    for script in [
        "exec \"$1\" -n -P -- \"$2\" 9<\"$2\"",
        "exec \"$1\" -n -P -- \"$2\" 3<\"$2\"",
        "exec \"$1\" -n -P -- \"$2\" 3<\"$2\" 4<\"$2\" 5<\"$2\" 6<\"$2\" 7<\"$2\" 8<\"$2\" 9<\"$2\"",
    ] {
        let out = sh(script, &[file]);
        found_nothing(&out, script);
    }
    // No pid for it, lsof's or its helper's (lsof-rs had printed both).
    let out = sh("exec \"$1\" -n -P -t -- \"$2\" 9<\"$2\"", &[file]);
    found_nothing(&out, "-t");
    // `-V` says what was not found, on stdout, as the C does.
    let out = sh("exec \"$1\" -n -P -V -- \"$2\" 9<\"$2\"", &[file]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        text(&out.stdout),
        format!("lsof: no file use located: {file}\n")
    );
    // Its name through the descriptor is no file either: the C's status
    // error, of lsof's own `/proc/PID/fd/9`. (`/dev/fd` is asked where it
    // is the usual link to `/proc/self/fd`.)
    let dev_fd =
        std::fs::read_link("/dev/fd").is_ok_and(|t| t == std::path::Path::new("/proc/self/fd"));
    let names: &[&str] = if dev_fd {
        &["/proc/self/fd/9", "/dev/fd/9"]
    } else {
        &["/proc/self/fd/9"]
    };
    for name in names {
        let out = sh("exec \"$1\" -n -P -- \"$3\" 9<\"$2\"", &[file, name]);
        assert_eq!(out.status.code(), Some(1), "{name}");
        assert!(out.stdout.is_empty(), "{name}: {}", text(&out.stdout));
        let err = said(&out);
        assert!(
            err.len() == 1
                && err[0].starts_with("lsof: status error on /proc/")
                && err[0].ends_with("/fd/9: No such file or directory"),
            "{name}: {err:?}"
        );
    }
}

/// lsof's own rows hold no descriptor it was handed: the C has closed them
/// all (measured: `lsof -a -p $$ -d 9 9<FILE` lists nothing and exits 0,
/// the process being there), and no row names the file. (The shell hands
/// down single digits alone; 9 is past what lsof holds of its own while it
/// lists: 3 to 6 in the C and 3 to 5 here, measured.)
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation)"
)]
fn lsof_lists_no_descriptor_it_was_handed() {
    let dir = Scratch::new("own-rows");
    let file = dir.0.join("probe");
    std::fs::write(&file, "").expect("write the probe");
    let file = file.to_str().expect("a UTF-8 temp directory");
    let out = sh("exec \"$1\" -n -P -a -p $$ -d 9 9<\"$2\"", &[file]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(out.stdout.is_empty(), "{}", text(&out.stdout));
    // Whatever lsof holds of its own while it lists, the file is not among
    // them, at any of the numbers it was handed.
    let out = sh(
        "exec \"$1\" -n -P -a -p $$ -d 0-255 -F fn \
         3<\"$2\" 4<\"$2\" 5<\"$2\" 6<\"$2\" 7<\"$2\" 8<\"$2\" 9<\"$2\"",
        &[file],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let listed = text(&out.stdout);
    assert!(listed.starts_with('p'), "{listed}");
    assert!(!listed.lines().any(|l| l == format!("n{file}")), "{listed}");
    assert!(!listed.lines().any(|l| l == "f9"), "{listed}");
}

/// The descriptors lsof was handed do not count against its descriptor
/// limit, as they do not count against the C's: with 3 and 4 handed down
/// and a limit of 8, the C has five numbers free once it has closed them,
/// starts its child and lists (measured); lsof-rs, which kept them, had
/// three, and ended `can't open pipes: Too many open files`.
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation)"
)]
fn handed_descriptors_do_not_count_against_the_limit() {
    // 5 to 7 are closed by the shell, so that exactly 3 and 4 are taken
    // below the limit whatever this test binary was started with.
    let out = sh(
        "exec 3</dev/null 4</dev/null 5>&- 6>&- 7>&-; ulimit -n 8 && \
         exec \"$1\" -n -P -a -d cwd -p $$ -F n",
        &[],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(said(&out), [] as [String; 0]);
    let listed = text(&out.stdout);
    let mut lines = listed.lines();
    assert!(lines.next().is_some_and(|p| p.starts_with('p')), "{listed}");
    assert_eq!(lines.next(), Some("n/"), "{listed}");
    assert_eq!(lines.next(), None, "{listed}");
}

/// Each of 0, 1 and 2 that is closed when lsof starts is `/dev/null`, read
/// and write, in lsof's own rows, as the C's loop leaves it (measured:
/// `lsof -a -p $$ -d 0,2 <&- 2>&-` lists `0u` and `2u`, `CHR`, `/dev/null`;
/// under `+f g` the flags are `RW,LG`), and one that is open is what it
/// was.
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation)"
)]
fn a_closed_standard_descriptor_is_dev_null_read_and_write() {
    let rows = |script: &str| {
        let out = sh(script, &[]);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{script}: {}",
            text(&out.stderr)
        );
        let listed = text(&out.stdout);
        let mut lines: Vec<String> = listed.lines().map(str::to_string).collect();
        assert!(
            lines.first().is_some_and(|p| p.starts_with('p')),
            "{listed}"
        );
        lines.remove(0);
        lines
    };
    // Both closed: `f0`, access `u`, type `CHR`, name `/dev/null`; and 2.
    assert_eq!(
        rows("exec \"$1\" -n -P -a -p $$ -d 0,2 -F fatn <&- 2>&-"),
        [
            "f0",
            "au",
            "tCHR",
            "n/dev/null",
            "f2",
            "au",
            "tCHR",
            "n/dev/null"
        ]
    );
    // Stdin alone: 0 is `/dev/null` read and write, 2 the pipe it was.
    assert_eq!(
        rows("exec \"$1\" -n -P -a -p $$ -d 0,2 -F fatn <&-"),
        [
            "f0",
            "au",
            "tCHR",
            "n/dev/null",
            "f2",
            "aw",
            "tFIFO",
            "npipe"
        ]
    );
    // Stderr alone, with stdin a file opened for reading: 0 stays `r`.
    assert_eq!(
        rows("exec \"$1\" -n -P -a -p $$ -d 0,2 -F fatn </dev/null 2>&-"),
        [
            "f0",
            "ar",
            "tCHR",
            "n/dev/null",
            "f2",
            "au",
            "tCHR",
            "n/dev/null"
        ]
    );
    // The flags the C's `open("/dev/null", O_RDWR)` has, by name.
    let out = sh("exec \"$1\" -n -P +f g -a -p $$ -d 0 <&-", &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let table = text(&out.stdout);
    let row = table.lines().nth(1).unwrap_or_default();
    let cells: Vec<&str> = row.split_whitespace().collect();
    assert_eq!(
        cells.get(3..6),
        Some(&["0u", "CHR", "RW,LG"][..]),
        "{table}"
    );
    assert_eq!(cells.last(), Some(&"/dev/null"), "{table}");
}

/// Where `/dev/null` cannot be opened for want of a descriptor, the run
/// ends there, exit 1, with nothing said, whatever it was asked (measured
/// on the C under `ulimit -n 3` with stdin closed: `-v`, `-h`, an option
/// that is none, a listing). lsof-rs had printed its version and exited 0,
/// and listed, or said `can't fopen(/proc/mounts, "r"): Too many open
/// files`.
///
/// Stdin is closed first, so that the loader has one number below the limit
/// to map the libraries through; the C's loop then opens `/dev/null` on 0
/// and fails at its second `open()`.
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation)"
)]
fn no_descriptor_for_dev_null_ends_the_run_in_silence() {
    for args in [
        "-v",
        "-h",
        "-W",
        "-F '?'",
        "-n -P -a -p $$ -d 0",
        "-n -P -i",
        "-n -P /",
        "--lsof-rs-bounded-fs-helper",
    ] {
        for limit in [3, 2, 1] {
            let script = format!("exec <&-; ulimit -n {limit}; exec \"$1\" {args}");
            ended_in_silence(&sh(&script, &[]), &script);
        }
    }
    // Stdout closed instead: `/dev/null` goes on 1, and the next fails.
    let out = sh("exec >&-; ulimit -n 3; exec \"$1\" -v", &[]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stderr.is_empty(), "{}", text(&out.stderr));
    // Stderr closed: `/dev/null` goes on 2, which ends the loop, and the
    // run goes on with its messages going nowhere (the C exits 0 too).
    let out = sh("exec 2>&-; ulimit -n 3; exec \"$1\" -v", &[]);
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty(), "{}", text(&out.stdout));
    // And one more descriptor is room enough for the loop's own.
    let out = sh("exec <&-; ulimit -n 4; exec \"$1\" -v", &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).starts_with("lsof-rs "),
        "{}",
        text(&out.stderr)
    );
}

/// The sizes of the sections of `elf`, a 64-bit little-endian ELF file,
/// whose type is `wanted`; `None` for any other file.
fn section_sizes(elf: &[u8], wanted: u32) -> Option<Vec<u64>> {
    let u16_at = |at: usize| Some(u16::from_le_bytes(elf.get(at..at + 2)?.try_into().ok()?));
    let u32_at = |at: usize| Some(u32::from_le_bytes(elf.get(at..at + 4)?.try_into().ok()?));
    let u64_at = |at: usize| Some(u64::from_le_bytes(elf.get(at..at + 8)?.try_into().ok()?));
    // `\x7fELF`, `ELFCLASS64`, `ELFDATA2LSB`.
    if elf.get(..6)? != b"\x7fELF\x02\x01" {
        return None;
    }
    let table = usize::try_from(u64_at(0x28)?).ok()?;
    let (entry, count) = (usize::from(u16_at(0x3a)?), usize::from(u16_at(0x3c)?));
    let mut sizes = Vec::new();
    for i in 0..count {
        let header = table.checked_add(i.checked_mul(entry)?)?;
        if u32_at(header.checked_add(4)?)? == wanted {
            sizes.push(u64_at(header.checked_add(0x20)?)?);
        }
    }
    Some(sizes)
}

/// The constructors of the program are the ones `lsof-sigpipe`'s safety
/// argument names: the C start-up files' own (`frame_dummy`, where there is
/// one), std's, which stores `argc`, `argv` and `envp`, and lsof-sigpipe's.
/// Closing the descriptors the process was started with is sound because
/// no other code of the program has run by then; a fourth entry in
/// `.init_array`, or a `.preinit_array`, is a constructor that argument
/// does not know: read it (does it open a descriptor and keep it?) before
/// this number is raised.
#[test]
#[cfg_attr(miri, ignore = "it reads the binary cargo built")]
fn the_binary_has_no_constructor_the_safety_argument_does_not_name() {
    const SHT_INIT_ARRAY: u32 = 14;
    const SHT_PREINIT_ARRAY: u32 = 16;
    let elf = std::fs::read(LSOF).expect("read the binary");
    let Some(init) = section_sizes(&elf, SHT_INIT_ARRAY) else {
        eprintln!("skipped: not a 64-bit little-endian ELF binary");
        return;
    };
    let entries: u64 = init.iter().map(|size| size / 8).sum();
    assert!(
        (2..=3).contains(&entries),
        ".init_array holds {entries} constructors"
    );
    assert_eq!(
        section_sizes(&elf, SHT_PREINIT_ARRAY),
        Some(Vec::new()),
        "a .preinit_array"
    );
}

/// How this host makes a mount namespace for a test, as `unshare`'s words:
/// as root, or as the root of a user namespace of its own; or why it
/// cannot, where neither can mount there.
fn namespace() -> Result<Vec<&'static str>, String> {
    let works = |argv: &[&str]| {
        Command::new(argv[0])
            .args(&argv[1..])
            .arg("sh")
            .arg("-c")
            .arg("mount -t tmpfs none /mnt 2>/dev/null || mount -t tmpfs none /tmp")
            .output()
            .is_ok_and(|o| o.status.success())
    };
    let as_root: &[&str] = &["unshare", "-m", "--propagation", "private"];
    let as_user: &[&str] = &["unshare", "-r", "-m", "--propagation", "private"];
    if works(as_root) {
        Ok(as_root.to_vec())
    } else if works(as_user) {
        Ok(as_user.to_vec())
    } else {
        Err("no mount namespace: not root, and no user namespace".into())
    }
}

/// `script` in a mount namespace of its own, `$L` the binary; its stdout.
fn in_namespace(unshare: &[&str], script: &str) -> String {
    let out = Command::new("timeout")
        .args(["-k", "5", "60"])
        .args(unshare)
        .arg("sh")
        .arg("-c")
        .arg(format!("L='{LSOF}'; cd /; {script}"))
        .env("RES_OPTIONS", "attempts:0")
        .output()
        .expect("run the namespace");
    assert!(
        out.status.success(),
        "the namespace's script failed: {}",
        text(&out.stderr)
    );
    text(&out.stdout)
}

/// Whether this host has an `strace` that can make `close_range(2)` fail,
/// as a kernel before 5.9 or a seccomp filter would.
fn can_inject() -> bool {
    Command::new("strace")
        .args(["-o", "/dev/null", "-e", "trace=none"])
        .args(["-e", "inject=close_range:error=ENOSYS", "true"])
        .output()
        .is_ok_and(|o| o.status.success())
}

/// The `close()` calls of `trace`, an `strace -e trace=close` log, made
/// after the `close_range()` that failed: each number and whether it was
/// open.
fn closes_after_close_range(trace: &str) -> Vec<(u32, bool)> {
    trace
        .lines()
        .skip_while(|l| !l.starts_with("close_range("))
        .filter_map(|l| {
            let rest = l.strip_prefix("close(")?;
            let (fd, result) = rest.split_once(')')?;
            Some((fd.parse().ok()?, result.trim_start().starts_with("= 0")))
        })
        .collect()
}

/// Where `close_range(2)` is not there, the descriptors `/proc/self/fd`
/// lists are closed one by one, as the C's `closefrom_shim()` and glibc's
/// `closefrom()` close them (measured on the C with the same injected
/// `ENOSYS`: `openat("/proc/self/fd/")`, `getdents64()`, `close(3)`,
/// `close(4)`, `close(9)`), and no number that is not open is tried.
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation)"
)]
fn without_close_range_the_listed_descriptors_are_closed() {
    if !can_inject() {
        eprintln!("skipped: no strace that can inject an error");
        return;
    }
    let dir = Scratch::new("no-close-range");
    let file = dir.0.join("probe");
    std::fs::write(&file, "").expect("write the probe");
    let trace = dir.0.join("trace");
    let out = Command::new("strace")
        .arg("-o")
        .arg(&trace)
        .args(["-e", "trace=close_range,close"])
        .args(["-e", "inject=close_range:error=ENOSYS"])
        .args(["sh", "-c"])
        .arg("exec \"$1\" -n -P -t -- \"$2\" 3<\"$2\" 4<\"$2\" 9<\"$2\"")
        .arg("sh")
        .arg(LSOF)
        .arg(&file)
        .env("RES_OPTIONS", "attempts:0")
        .output()
        .expect("run strace");
    // The file is found in no process, lsof's own and its helper's among
    // them: status 1, and nothing printed.
    found_nothing(&out, "under strace");
    let log = std::fs::read_to_string(&trace).expect("the trace");
    assert!(
        log.lines()
            .any(|l| l.starts_with("close_range(3, 4294967295, 0)") && l.contains("= -1 ENOSYS")),
        "{log}"
    );
    let closes = closes_after_close_range(&log);
    // The three it was handed are closed, in the listing's order, and no
    // number that was not open is tried before the last of them: a walk of
    // the listing, not of the numbers. (With nothing else handed down the
    // calls are `close(3)`, `close(4)`, `close(9)` and the listing's own,
    // `close(5)`.)
    let at = |fd: u32| closes.iter().position(|&c| c == (fd, true));
    let (Some(three), Some(four), Some(nine)) = (at(3), at(4), at(9)) else {
        panic!("3, 4 and 9 were not all closed: {log}");
    };
    assert!(three < four && four < nine, "{log}");
    assert!(closes.iter().take(nine + 2).all(|&(_, open)| open), "{log}");
}

/// With neither `close_range(2)` nor `/proc`, every number from 3 to the
/// descriptor limit is closed, and to 52 where the limit is lower, as the
/// C's shim closes them (`MaxFd` is at least 53, `main.c:173-174`). Then
/// the run ends at the mount table it cannot open.
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation)"
)]
fn without_close_range_or_proc_every_number_is_closed() {
    let unshare = match namespace() {
        Ok(argv) if can_inject() => argv,
        _ => {
            eprintln!("skipped: no mount namespace, or no strace that can inject an error");
            return;
        }
    };
    let dir = Scratch::new("sweep");
    let file = dir.0.join("probe");
    std::fs::write(&file, "").expect("write the probe");
    for (limit, last) in [(20, 52), (64, 63)] {
        let trace = dir.0.join(format!("trace-{limit}"));
        let got = in_namespace(
            &unshare,
            &format!(
                "mount -t tmpfs none /proc || {{ echo skip; exit 0; }}\n\
                 ulimit -n {limit}\n\
                 strace -o '{trace}' -e trace=close_range,close \
                 -e inject=close_range:error=ENOSYS \
                 sh -c 'exec \"$1\" -n -P -p 1 9<\"$2\"' sh \"$L\" '{file}' 2>&1\n\
                 echo \"rc=$?\"\n",
                trace = trace.display(),
                file = file.display(),
            ),
        );
        if got == "skip\n" {
            eprintln!("skipped: no tmpfs can be mounted over /proc here");
            return;
        }
        assert_eq!(
            got, "lsof: can't fopen(/proc/mounts, \"r\"): No such file or directory\nrc=1\n",
            "limit {limit}"
        );
        let log = std::fs::read_to_string(&trace).expect("the trace");
        let closes = closes_after_close_range(&log);
        let swept: Vec<u32> = closes.iter().map(|&(fd, _)| fd).take(last - 2).collect();
        assert_eq!(
            swept,
            (3..=last as u32).collect::<Vec<_>>(),
            "limit {limit}: {log}"
        );
        // The one that was open among them is the one lsof was handed; and
        // the next call is the `/dev/null` loop's own close of 3.
        assert!(closes.contains(&(9, true)), "limit {limit}: {log}");
        assert_eq!(
            closes.get(last - 2),
            Some(&(3, true)),
            "limit {limit}: {log}"
        );
    }
}

/// With no `/dev/null` at all every run ends at once, exit 1, with nothing
/// on either stream, before an option is read (measured on the C with a
/// tmpfs over `/dev`). lsof-rs had printed its version (exit 0), listed
/// under `-b` (exit 0), said `can't fork` where it needed its helper, and,
/// with a standard descriptor closed as well, died of `SIGABRT` inside the
/// Rust runtime's own start-up (exit 134).
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation)"
)]
fn no_dev_null_ends_every_run_in_silence() {
    let unshare = match namespace() {
        Ok(argv) => argv,
        Err(why) => {
            eprintln!("skipped: {why}");
            return;
        }
    };
    // Each case's status, then what it wrote to both streams, between
    // brackets; a closed stream is closed for lsof alone.
    let got = in_namespace(
        &unshare,
        r#"mount -t tmpfs none /dev || { echo skip; exit 0; }
run() { out=$("$@" 2>&1); echo "$?[$out]"; }
run "$L" -v
run "$L" -h
run "$L" -W
run "$L" -n -P -p $$ -a -d 0
run "$L" -n -P -b -w -p $$ -a -d cwd
run "$L" -n -P -i
run "$L" -n -P /
out=$("$L" -v 2>&1 <&-); echo "$?[$out]"
out=$("$L" -n -P -p 1 2>&-); echo "$?[$out]"
out=$("$L" -v <&- 2>&-); echo "$?[$out]"
"$L" -v >&- 2>&-; echo "$?[]"
"#,
    );
    if got == "skip\n" {
        eprintln!("skipped: no tmpfs can be mounted over /dev here");
        return;
    }
    let lines: Vec<&str> = got.lines().collect();
    assert_eq!(lines, ["1[]"; 11], "{got}");
}

/// A `/dev/null` that is there and cannot be opened for writing ends the
/// run the same way: a regular file of mode 0444 in its place, lsof run as
/// a user who is not root (measured on the C: exit 1, nothing said; lsof-rs
/// had printed its version). Root only: it changes user.
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation)"
)]
fn a_dev_null_that_cannot_be_written_ends_the_run_too() {
    let root = std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix("Uid:").map(str::to_string))
        .is_some_and(|l| l.split_whitespace().nth(1) == Some("0"));
    let setpriv = Command::new("setpriv")
        .args([
            "--reuid",
            "65534",
            "--regid",
            "65534",
            "--clear-groups",
            "true",
        ])
        .output()
        .is_ok_and(|o| o.status.success());
    let unshare = match namespace() {
        Ok(argv) if root && setpriv => argv,
        _ => {
            eprintln!("skipped: not root, or no setpriv, or no mount namespace");
            return;
        }
    };
    let got = in_namespace(
        &unshare,
        r#"mount -t tmpfs none /dev || exit 3
: > /dev/null; chmod 0444 /dev/null; chmod 0755 /dev
as() { setpriv --reuid 65534 --regid 65534 --clear-groups "$@"; }
run() { out=$("$@" 2>&1); echo "$?[$out]"; }
run as "$L" -v
run as "$L" -n -P -p $$ -a -d cwd
run as "$L" -n -P -b -w -p $$ -a -d cwd
run as "$L" -W
# Root may write it whatever its mode: the run goes on.
out=$("$L" -v 2>&1); echo "$?[${out%% *}]"
"#,
    );
    let lines: Vec<&str> = got.lines().collect();
    assert_eq!(lines, ["1[]", "1[]", "1[]", "1[]", "0[lsof-rs]"], "{got}");
}

/// With no `/proc`, a run that names a path, a `+d`/`+D` or an `-e` ends in
/// the C's words for the mount table it cannot open, exit 1 (measured on
/// the C with a tmpfs over `/proc`): the C's child is a fork, which needs
/// no `/proc`, so the C goes on to the table and ends there. lsof-rs, whose
/// helper is `/proc/self/exe`, had said `can't fork: No such file or
/// directory` (DIVERGENCES 175).
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation)"
)]
fn without_proc_the_run_ends_at_the_mount_table() {
    let unshare = match namespace() {
        Ok(argv) => argv,
        Err(why) => {
            eprintln!("skipped: {why}");
            return;
        }
    };
    let got = in_namespace(
        &unshare,
        r#"mount -t tmpfs none /proc || { echo skip; exit 0; }
run() { out=$("$@" 2>&1); echo "$?[$out]"; }
run "$L" -n -P /etc/hostname
run "$L" -n -P /nonexistent
run "$L" -n -P +d /etc
run "$L" -n -P +D /etc -x
run "$L" -n -P -e /proc
run "$L" -n -P -e /proc -p 1
run "$L" -n -P -p 1
run "$L" -n -P -O /etc/hostname
run "$L" -n -P -i
"#,
    );
    if got == "skip\n" {
        eprintln!("skipped: no tmpfs can be mounted over /proc here");
        return;
    }
    let table = "1[lsof: can't fopen(/proc/mounts, \"r\"): No such file or directory]";
    let lines: Vec<&str> = got.lines().collect();
    // `-i` alone reads no table, in either: nothing listed, exit 1.
    let mut want = vec![table; 8];
    want.push("1[]");
    assert_eq!(lines, want, "{got}");
}

/// A mount supplement is asked of `access(2)`, the **real** user's rights,
/// before it is read, as the C asks (`is_readable()`): a file the caller
/// cannot read is `WARNING: access F: Permission denied` and none of its
/// lines is quoted, though lsof's effective user could read it; and one the
/// caller may read and the effective user may not is the C's `can't
/// open(F)` (both measured on the C with `setpriv --ruid` and `--euid`).
/// lsof-rs had read the first, quoting its lines in `no path: "…"`, and
/// called the second an access warning (DIVERGENCES 172). Root only.
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation)"
)]
fn a_supplement_is_read_only_where_the_real_user_may_read_it() {
    let as_user = |which: &str, args: &[&str]| {
        Command::new("setpriv")
            .args([which, "65534"])
            .arg(LSOF)
            .args(args)
            .env("RES_OPTIONS", "attempts:0")
            .output()
    };
    if !as_user("--ruid", &["-v"]).is_ok_and(|o| o.status.success()) {
        eprintln!("skipped: not root, or no setpriv");
        return;
    }
    let dir = Scratch::new("supplement");
    let secret = dir.0.join("secret.sup");
    std::fs::write(&secret, "topsecret-line-one\nroot:$6$fakehash:1:0\n").expect("write");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }
    let file = secret.to_str().expect("a UTF-8 temp directory");
    let args = [
        "-n", "-P", "-e", "/proc", "+m", file, "-a", "-p", "1", "-d", "0",
    ];
    // What a run says of the supplement, and of `/proc`, which `-e` leaves
    // to it: the lines that name the file. (A host may have mounts the user
    // cannot `stat`, each a warning of its own; and the device assumed is
    // what the last `stat` left, the host's.)
    let said = |out: &Output| -> Vec<String> {
        text(&out.stderr)
            .lines()
            .filter(|l| l.contains(file))
            .map(|l| match l.split_once("assuming dev=") {
                Some((head, tail)) => {
                    let rest = tail.split_once(' ').map_or("", |(_, rest)| rest);
                    format!("{head}assuming dev=N {rest}")
                }
                None => l.to_string(),
            })
            .collect()
    };
    let assumed = format!("lsof: assuming dev=N for /proc from {file}");
    // The real user is not root: refused by `access()`, and unread.
    let out = as_user("--ruid", &args).expect("run setpriv");
    let err = text(&out.stderr);
    assert_eq!(
        said(&out),
        [
            format!("lsof: WARNING: access {file}: Permission denied"),
            assumed.clone()
        ],
        "{err}"
    );
    assert!(
        !err.contains("topsecret") && !err.contains("fakehash"),
        "{err}"
    );
    // The real user is root and the effective one is not: `access()`
    // passes, and the open fails, in the open's words.
    let out = as_user("--euid", &args).expect("run setpriv");
    assert_eq!(
        said(&out),
        [
            format!("lsof: can't open({file}): Permission denied"),
            assumed.clone()
        ],
        "{}",
        text(&out.stderr)
    );
    // Root, real and effective, reads it and says what its lines lack.
    let out = Command::new(LSOF)
        .args(args)
        .env("RES_OPTIONS", "attempts:0")
        .output()
        .expect("run lsof");
    assert_eq!(
        said(&out),
        [
            format!("lsof: {file} line 1: no path: \"topsecret-line-one\""),
            format!("lsof: {file} line 2: no path: \"root:$6$fakehash:1:0\""),
            assumed
        ],
        "{}",
        text(&out.stderr)
    );
}
