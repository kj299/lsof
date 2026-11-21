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
    said_in(&text(&out.stderr))
}

/// [`said`], of a run's stderr as text.
fn said_in(stderr: &str) -> Vec<String> {
    stderr
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
    // error, of `/proc/PID/fd/9`, where the C's PID is its child's, which
    // made the `stat`, and lsof-rs's is lsof's own (row 89). (`/dev/fd` is
    // asked where it is the usual link to `/proc/self/fd`.)
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

/// What the tripwire below reads of the binary: a 64-bit little-endian ELF
/// file's sections, the functions its `.init_array` slots point at, by
/// symbol, and the shared objects it asks for. Pure Rust, over the bytes;
/// every read is checked, and a file that is not such an ELF file is `None`.
mod elf {
    pub const SHT_SYMTAB: u32 = 2;
    pub const SHT_RELA: u32 = 4;
    pub const SHT_DYNAMIC: u32 = 6;
    pub const SHT_INIT_ARRAY: u32 = 14;
    pub const SHT_PREINIT_ARRAY: u32 = 16;
    /// `R_X86_64_RELATIVE` and `R_AARCH64_RELATIVE`: the slot is the load
    /// address plus the addend.
    const RELATIVE: [u64; 2] = [8, 1027];
    const STT_FUNC: u8 = 2;
    const DT_NEEDED: u64 = 1;

    pub struct Section {
        pub name: String,
        pub kind: u32,
        pub addr: u64,
        pub offset: usize,
        pub size: usize,
        pub link: usize,
    }

    fn u16_at(elf: &[u8], at: usize) -> Option<u16> {
        Some(u16::from_le_bytes(
            elf.get(at..at.checked_add(2)?)?.try_into().ok()?,
        ))
    }

    fn u32_at(elf: &[u8], at: usize) -> Option<u32> {
        Some(u32::from_le_bytes(
            elf.get(at..at.checked_add(4)?)?.try_into().ok()?,
        ))
    }

    fn u64_at(elf: &[u8], at: usize) -> Option<u64> {
        Some(u64::from_le_bytes(
            elf.get(at..at.checked_add(8)?)?.try_into().ok()?,
        ))
    }

    /// The NUL-terminated string at `at` of the string table `table`.
    fn string(elf: &[u8], table: &Section, at: usize) -> Option<String> {
        let all = elf.get(table.offset..table.offset.checked_add(table.size)?)?;
        let text = all.get(at..)?.split(|&b| b == 0).next()?;
        Some(String::from_utf8_lossy(text).into_owned())
    }

    /// The section headers; `None` for a file that is not ELF, 64-bit and
    /// little-endian (`\x7fELF`, `ELFCLASS64`, `ELFDATA2LSB`).
    pub fn sections(elf: &[u8]) -> Option<Vec<Section>> {
        if elf.get(..6)? != b"\x7fELF\x02\x01" {
            return None;
        }
        let table = usize::try_from(u64_at(elf, 0x28)?).ok()?;
        let entry = usize::from(u16_at(elf, 0x3a)?);
        let count = usize::from(u16_at(elf, 0x3c)?);
        let names = usize::from(u16_at(elf, 0x3e)?);
        let mut found = Vec::new();
        for i in 0..count {
            let at = table.checked_add(i.checked_mul(entry)?)?;
            found.push((
                u32_at(elf, at)?,
                Section {
                    name: String::new(),
                    kind: u32_at(elf, at + 4)?,
                    addr: u64_at(elf, at + 0x10)?,
                    offset: usize::try_from(u64_at(elf, at + 0x18)?).ok()?,
                    size: usize::try_from(u64_at(elf, at + 0x20)?).ok()?,
                    link: usize::try_from(u32_at(elf, at + 0x28)?).ok()?,
                },
            ));
        }
        let name_of: Vec<Option<String>> = found
            .iter()
            .map(|(at, _)| string(elf, &found.get(names)?.1, usize::try_from(*at).ok()?))
            .collect();
        Some(
            found
                .into_iter()
                .zip(name_of)
                .map(|((_, section), name)| Section {
                    name: name.unwrap_or_default(),
                    ..section
                })
                .collect(),
        )
    }

    /// Whether the file has a symbol table to name a function by.
    pub fn has_symbols(sections: &[Section]) -> bool {
        sections.iter().any(|s| s.kind == SHT_SYMTAB && s.size > 0)
    }

    /// Each `.init_array` slot, in order: the address of the function the
    /// loader calls, and the names the symbol table gives a function at
    /// that address (none where the file is stripped). The address is the
    /// slot's `RELATIVE` relocation's addend where it has one, as in a
    /// position-independent executable, and else what the slot holds.
    pub fn constructors(elf: &[u8], sections: &[Section]) -> Option<Vec<(u64, Vec<String>)>> {
        let mut slots = Vec::new();
        for s in sections.iter().filter(|s| s.kind == SHT_INIT_ARRAY) {
            for i in 0..s.size / 8 {
                let held = u64_at(elf, s.offset.checked_add(i * 8)?)?;
                slots.push((s.addr.checked_add(u64::try_from(i * 8).ok()?)?, held));
            }
        }
        for rela in sections.iter().filter(|s| s.kind == SHT_RELA) {
            for i in 0..rela.size / 24 {
                let at = rela.offset.checked_add(i * 24)?;
                let (place, info) = (u64_at(elf, at)?, u64_at(elf, at + 8)?);
                if RELATIVE.contains(&(info & 0xffff_ffff)) {
                    if let Some(slot) = slots.iter_mut().find(|(addr, _)| *addr == place) {
                        slot.1 = u64_at(elf, at + 16)?;
                    }
                }
            }
        }
        let mut named: Vec<(u64, Vec<String>)> = slots
            .iter()
            .map(|&(_, target)| (target, Vec::new()))
            .collect();
        for symtab in sections.iter().filter(|s| s.kind == SHT_SYMTAB) {
            let strings = sections.get(symtab.link)?;
            for i in 0..symtab.size / 24 {
                let at = symtab.offset.checked_add(i * 24)?;
                let (name, info, value) =
                    (u32_at(elf, at)?, *elf.get(at + 4)?, u64_at(elf, at + 8)?);
                if info & 0xf != STT_FUNC {
                    continue;
                }
                for (target, names) in named.iter_mut().filter(|(t, _)| *t == value) {
                    let _ = target;
                    names.push(string(elf, strings, usize::try_from(name).ok()?)?);
                }
            }
        }
        Some(named)
    }

    /// The shared objects the file asks the loader for: its `DT_NEEDED`s.
    pub fn needed(elf: &[u8], sections: &[Section]) -> Option<Vec<String>> {
        let mut libs = Vec::new();
        for dynamic in sections.iter().filter(|s| s.kind == SHT_DYNAMIC) {
            let strings = sections.get(dynamic.link)?;
            for i in 0..dynamic.size / 16 {
                let at = dynamic.offset.checked_add(i * 16)?;
                if u64_at(elf, at)? == DT_NEEDED {
                    let name = usize::try_from(u64_at(elf, at + 8)?).ok()?;
                    libs.push(string(elf, strings, name)?);
                }
            }
        }
        Some(libs)
    }
}

/// What an `.init_array` entry is, by the names of the function it points
/// at: one of the constructors `lsof-sigpipe`'s safety argument names, or
/// `None`.
fn constructor(names: &[String]) -> Option<&'static str> {
    let any = |test: &dyn Fn(&str) -> bool| names.iter().any(|n| test(n));
    if any(&|n| n == "frame_dummy") {
        // The C start-up files' (`crtbegin`): registers nothing here.
        Some("frame_dummy")
    } else if any(&|n| n == "__do_init") {
        // The same file's on musl (compiler-rt's `crtbegin`).
        Some("__do_init")
    } else if any(&|n| n.contains("3std") && n.contains("ARGV_INIT_ARRAY")) {
        // std's, on glibc: it stores `argc` and `argv`.
        Some("std")
    } else if any(&|n| n.contains("lsof_sigpipe") && n.contains("capture")) {
        Some("lsof-sigpipe")
    } else {
        None
    }
}

/// The constructors of the program are the ones `lsof-sigpipe`'s safety
/// argument names, each by its symbol, and no other: closing the
/// descriptors the process was started with is sound because no other code
/// of the program has run by then, and a constructor is code that has.
///
/// On glibc: `frame_dummy` (the C start-up files'), std's, which stores
/// `argc` and `argv`, and `lsof_sigpipe::capture`. On musl: `__do_init`
/// (the start-up files') and `capture`; std has none there. Each
/// `.init_array` slot is resolved to its function, through its `RELATIVE`
/// relocation where the binary is position-independent, and the function
/// to its name in the symbol table, which the binary a test is given has
/// (the release profile strips it: there the count alone is held, and the
/// test says so). There is no `.preinit_array` and no `.ctors`. And the
/// shared objects the binary asks for are the C library's own and the
/// compiler's unwinder, since a shared object's constructors run before
/// the program's and are not in this file.
///
/// What this does not see: a shared object loaded later (an NSS module),
/// which runs after the descriptors are closed and so cannot be closed
/// under; the two test binaries the constructor also runs in; FreeBSD.
#[test]
#[cfg_attr(miri, ignore = "it reads the binary cargo built")]
fn the_binary_has_no_constructor_the_safety_argument_does_not_name() {
    /// What to do about a failure, in every message.
    const READ_THIS: &str = "An instrumented build (`-C instrument-coverage`, \
        `cargo llvm-cov`, a sanitizer) adds its runtime's own constructor, and a \
        sanitizer a `.preinit_array`: run this test on a plain build, and do not \
        loosen it. Anything else new here is code that runs before \
        `lsof_sigpipe::capture` closes the descriptors the process was started \
        with: read what it opens and keeps, and change `lsof-sigpipe`'s safety \
        argument and THREAT-MODEL.md with this test.";
    /// The C library's own objects, which every dynamic program loads, and
    /// the compiler's unwinder: none opens a descriptor it keeps (measured
    /// with `strace`: nothing is open past 2 when `capture` runs).
    const DEPENDENCIES: &[&str] = &[
        "libc.so.6",
        "libgcc_s.so.1",
        "ld-linux-x86-64.so.2",
        "ld-linux-aarch64.so.1",
        "libm.so.6",
        "libpthread.so.0",
        "libdl.so.2",
        "librt.so.1",
    ];
    let expected: &[&str] = if cfg!(target_env = "gnu") {
        &["frame_dummy", "lsof-sigpipe", "std"]
    } else if cfg!(target_env = "musl") {
        &["__do_init", "lsof-sigpipe"]
    } else {
        eprintln!("skipped: the constructors of this C library are not known to the test");
        return;
    };
    let bytes = std::fs::read(LSOF).expect("read the binary");
    let Some(sections) = elf::sections(&bytes) else {
        eprintln!("skipped: not a 64-bit little-endian ELF binary");
        return;
    };
    for s in &sections {
        assert!(
            !(s.kind == elf::SHT_PREINIT_ARRAY && s.size > 0),
            "the binary has a .preinit_array. {READ_THIS}"
        );
        assert!(
            !(s.name == ".ctors" && s.size > 0),
            "the binary has a .ctors. {READ_THIS}"
        );
    }
    let entries = elf::constructors(&bytes, &sections).expect("read .init_array");
    assert_eq!(
        entries.len(),
        expected.len(),
        ".init_array holds {} constructors, not {}: {entries:x?}. {READ_THIS}",
        entries.len(),
        expected.len()
    );
    if elf::has_symbols(&sections) {
        let mut found = Vec::new();
        for (target, names) in &entries {
            match constructor(names) {
                Some(known) => found.push(known),
                None => panic!(
                    "the .init_array entry at {target:#x} is {names:?}, which is no \
                     constructor the safety argument names. {READ_THIS}"
                ),
            }
        }
        found.sort_unstable();
        assert_eq!(found, expected, "{entries:x?}. {READ_THIS}");
    } else {
        eprintln!(
            "no symbol table in {LSOF} (a stripped build): only the number of \
             constructors, {}, was held, not what each is",
            entries.len()
        );
    }
    let needed = elf::needed(&bytes, &sections).expect("read .dynamic");
    for lib in &needed {
        assert!(
            DEPENDENCIES.contains(&lib.as_str()),
            "the binary asks for the shared object {lib}, whose constructors run \
             before the program's and are not in this file. {READ_THIS}"
        );
    }
    if cfg!(target_env = "musl") {
        assert_eq!(needed, [] as [String; 0], "a static binary asks for none");
    }
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

/// Whether this host's `strace` can leave a call untraced at no cost
/// (`--seccomp-bpf`): tracing a million `close()` calls otherwise takes
/// most of a minute.
fn can_filter() -> bool {
    Command::new("strace")
        .args(["-f", "--seccomp-bpf", "-o", "/dev/null"])
        .args(["-e", "trace=close_range", "true"])
        .output()
        .is_ok_and(|o| o.status.success())
}

/// With neither `close_range(2)` nor `/proc/self/fd`, every number from 3
/// up to 1,048,576 is closed, whatever the descriptor limit is: a
/// descriptor opened under a higher soft limit keeps its number when the
/// limit is lowered, and a sweep that ended at the limit, as the C's shim
/// ends its own (`MaxFd`), left it open (measured: descriptor 15,000 under
/// a soft limit of 1,024). The C as built never gets there: glibc's
/// `closefrom()` aborts where it cannot open `/proc/self/fd`.
///
/// Both failures are injected with `strace`: `ENOSYS` for `close_range()`,
/// and `ENOENT` for the one `openat()` that is the constructor's, found by
/// its number in a first run that injects `ENOSYS` alone. `/proc` is left
/// as it is, so lsof can then list itself: with descriptor 9 handed down
/// below a soft limit of 64, and 200 above it, neither is a row, and
/// descriptor 0, which it keeps, is.
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation)"
)]
fn without_close_range_or_proc_every_number_is_closed() {
    let bash = Command::new("bash")
        .args(["-c", "exec 200</dev/null"])
        .status()
        .is_ok_and(|s| s.success());
    if !can_inject() || !can_filter() || !bash {
        eprintln!("skipped: no bash, or no strace that can inject an error and filter by seccomp");
        return;
    }
    let dir = Scratch::new("sweep");
    // `-b -w`: no helper is started, so the one process traced is lsof.
    let script = "exec 9</dev/null 200</dev/null; ulimit -S -n 64 || exit 2; \
                  exec \"$1\" -n -P -b -w -a -p $$ -d 0,9,200 -F f";
    let run = |trace: &std::path::Path, inject: &[String]| {
        let mut cmd = Command::new("strace");
        cmd.args(["-f", "--seccomp-bpf", "-o"])
            .arg(trace)
            .args(["-e", "trace=close_range,openat"]);
        for i in inject {
            cmd.args(["-e", i]);
        }
        cmd.args(["bash", "-c", script, "bash", LSOF])
            .env("RES_OPTIONS", "attempts:0")
            .output()
            .expect("run strace")
    };
    let opens = |trace: &std::path::Path| -> Vec<String> {
        std::fs::read_to_string(trace)
            .expect("the trace")
            .lines()
            .filter_map(|l| {
                l.split_once(' ')
                    .map(|(_pid, call)| call.trim_start().to_string())
            })
            .filter(|call| call.starts_with("openat("))
            .collect()
    };
    let own_listing = |call: &str| call.starts_with("openat(AT_FDCWD, \"/proc/self/fd\", ");
    // The descriptors of lsof's own rows, of the three asked about.
    let rows = |out: &Output| -> Vec<String> {
        text(&out.stdout)
            .lines()
            .filter(|l| l.starts_with('f'))
            .map(str::to_string)
            .collect()
    };
    // Without `close_range()` alone: the listing is read, and both are closed.
    let first = dir.0.join("trace-1");
    let enosys = "inject=close_range:error=ENOSYS".to_string();
    let out = run(&first, std::slice::from_ref(&enosys));
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(rows(&out), ["f0"], "{}", text(&out.stdout));
    let calls = opens(&first);
    let nth = calls
        .iter()
        .position(|c| own_listing(c))
        .expect("the constructor opened /proc/self/fd")
        + 1;
    // And without that listing either: the same `openat()` fails.
    let second = dir.0.join("trace-2");
    let out = run(
        &second,
        &[enosys, format!("inject=openat:error=ENOENT:when={nth}")],
    );
    let calls = opens(&second);
    let refused = calls.get(nth - 1).expect("as many calls as before");
    assert!(
        own_listing(refused) && refused.contains("= -1 ENOENT") && refused.contains("INJECTED"),
        "the call refused was not the constructor's: {refused}"
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(
        rows(&out),
        ["f0"],
        "a descriptor lsof was handed is still open: {}",
        text(&out.stdout)
    );
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

/// What a run that ended made of itself: its status, stdout and stderr.
type Ended = (Option<i32>, String, String);

/// `script` in a mount namespace of its own, `$L` the binary, given `secs`
/// seconds and 2 GiB of address space: what it made of itself, or `None`
/// where it had to be killed. The script ends in `exec`, so that the
/// process killed is lsof. Nothing is piped: a run that waits is not
/// waited on past its limit, and one that reads without end (the states
/// these tests make are the ones where the C does) is stopped by its own.
fn in_namespace_within(unshare: &[&str], script: &str, dir: &Scratch, secs: u64) -> Option<Ended> {
    let (out, err) = (dir.0.join("stdout"), dir.0.join("stderr"));
    let create = |p: &std::path::Path| std::fs::File::create(p).expect("a file for the output");
    let mut child = Command::new(unshare[0])
        .args(&unshare[1..])
        .arg("sh")
        .arg("-c")
        .arg(format!(
            "L='{LSOF}'; cd /; ulimit -v 2097152 2>/dev/null; {script}"
        ))
        .env("RES_OPTIONS", "attempts:0")
        .stdin(std::process::Stdio::null())
        .stdout(create(&out))
        .stderr(create(&err))
        .spawn()
        .expect("run the namespace");
    let limit = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    let status = loop {
        match child.try_wait().expect("wait for the namespace") {
            Some(status) => break status,
            None if std::time::Instant::now() >= limit => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            None => std::thread::sleep(std::time::Duration::from_millis(10)),
        }
    };
    let read = |p: &std::path::Path| text(&std::fs::read(p).expect("the output"));
    Some((status.code(), read(&out), read(&err)))
}

/// Where `/dev/null` is a FIFO no run waits on it, as the C waits on
/// nothing there: the C opens it once, for reading and writing, which never
/// waits on a FIFO (`main.c:178`), and lsof-rs's start-up does the same.
/// lsof-rs then opened it once more for its helper's descriptor 2, for
/// writing alone, and waited for a reader for ever: every run that started
/// the helper hung (measured: `rc=124` where the C lists).
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation)"
)]
fn a_fifo_for_dev_null_holds_no_run() {
    let unshare = match namespace() {
        Ok(argv) => argv,
        Err(why) => {
            eprintln!("skipped: {why}");
            return;
        }
    };
    let dir = Scratch::new("fifo-null");
    let dev = dir.0.join("dev");
    std::fs::create_dir(&dev).expect("a directory to put over /dev");
    let made = Command::new("mkfifo")
        .args(["-m", "666"])
        .arg(dev.join("null"))
        .status()
        .is_ok_and(|s| s.success());
    if !made {
        eprintln!("skipped: no mkfifo");
        return;
    }
    // A listing (the mount table is read through the helper) and a path,
    // which list lsof's own working directory; and a `+d`, which starts
    // the helper while the options are read, and has only to end.
    for (args, lists) in [
        ("-n -P -a -p $$ -d cwd -F n", true),
        ("-n -P -a -p $$ -d cwd -F n /", true),
        ("-n -P -t +d /dev", false),
    ] {
        let ended = in_namespace_within(
            &unshare,
            &format!(
                "mount --bind '{}' /dev || {{ echo skip; exit 0; }}; exec \"$L\" {args}",
                dev.display()
            ),
            &dir,
            30,
        );
        let Some((status, out, err)) = ended else {
            panic!("`{args}` waited on the FIFO /dev/null");
        };
        if out == "skip\n" {
            eprintln!("skipped: nothing can be bound over /dev here");
            return;
        }
        assert_eq!(said_in(&err), [] as [String; 0], "{args}");
        if lists {
            assert_eq!(status, Some(0), "{args}: {err}");
            let mut lines = out.lines();
            assert!(
                lines.next().is_some_and(|p| p.starts_with('p')),
                "{args}: {out}"
            );
            assert_eq!(lines.next(), Some("n/"), "{args}: {out}");
        } else {
            assert!(matches!(status, Some(0 | 1)), "{args}: {status:?} {err}");
        }
    }
}

/// Whatever else is where `/dev/null` should be and cannot be opened for
/// reading and writing ends every run at once, exit 1, with nothing said,
/// as the C's `Error()` ends it: a directory, a link to nothing, a link to
/// itself, a socket (each measured on the C).
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation)"
)]
fn what_cannot_be_opened_as_dev_null_ends_the_run_in_silence() {
    let unshare = match namespace() {
        Ok(argv) => argv,
        Err(why) => {
            eprintln!("skipped: {why}");
            return;
        }
    };
    let dir = Scratch::new("null-shapes");
    let shape = |name: &str| {
        let dev = dir.0.join(name);
        std::fs::create_dir(&dev).expect("a directory to put over /dev");
        dev
    };
    let directory = shape("directory");
    std::fs::create_dir(directory.join("null")).expect("a directory");
    let dangling = shape("dangling");
    std::os::unix::fs::symlink("/dev/nowhere", dangling.join("null")).expect("a link");
    let looped = shape("loop");
    std::os::unix::fs::symlink("/dev/null", looped.join("null")).expect("a link");
    let socket = shape("socket");
    let _listener = std::os::unix::net::UnixListener::bind(socket.join("null")).expect("a socket");
    for dev in [&directory, &dangling, &looped, &socket] {
        for args in ["-v", "-n -P -a -p $$ -d cwd", "-W"] {
            let ended = in_namespace_within(
                &unshare,
                &format!(
                    "mount --bind '{}' /dev || {{ echo skip; exit 0; }}; exec \"$L\" {args}",
                    dev.display()
                ),
                &dir,
                30,
            );
            let what = format!("{} {args}", dev.display());
            let Some((status, out, err)) = ended else {
                panic!("{what}: the run did not end");
            };
            if out == "skip\n" {
                eprintln!("skipped: nothing can be bound over /dev here");
                return;
            }
            assert_eq!(
                (status, out.as_str(), err.as_str()),
                (Some(1), "", ""),
                "{what}"
            );
        }
    }
}

/// The helper's descriptor 2 is `/dev/null` open for reading and writing,
/// `2u` in lsof's own listing of it (DIVERGENCES 123): what lsof's start-up
/// has already opened without waiting, where a second open for writing
/// alone, `2w`, waited on a FIFO. (The C's child has nothing on 2.) The
/// helper is the process named as lsof is whose parent is lsof.
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation)"
)]
fn the_helpers_descriptor_two_is_dev_null_read_and_write() {
    let name: String = std::path::Path::new(LSOF)
        .file_name()
        .and_then(|n| n.to_str())
        .expect("the binary's name")
        .chars()
        .take(15)
        .collect();
    let child = Command::new("sh")
        .args([
            "-c",
            "exec \"$1\" -n -P -a -c \"$2\" -d 2 -R -F pRfatn",
            "sh",
            LSOF,
        ])
        .arg(&name)
        .env("RES_OPTIONS", "attempts:0")
        .current_dir("/")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("run sh");
    let lsof = child.id().to_string();
    let out = child.wait_with_output().expect("wait for lsof");
    assert_eq!(out.status.code(), Some(0));
    // Each process set: `p`, `R`, then `f`, `a`, `t` and `n` for its file.
    let listed = text(&out.stdout);
    let mut helpers = Vec::new();
    let mut set: Vec<&str> = Vec::new();
    for line in listed.lines().chain(["p"]) {
        if line.starts_with('p') {
            if set
                .iter()
                .any(|l| l.strip_prefix('R') == Some(lsof.as_str()))
            {
                helpers.push(set.clone());
            }
            set.clear();
        }
        set.push(line);
    }
    assert_eq!(
        helpers.len(),
        1,
        "one process whose parent is lsof: {listed}"
    );
    assert_eq!(
        helpers[0].get(2..),
        Some(&["f2", "au", "tCHR", "n/dev/null"][..]),
        "{listed}"
    );
}

/// With no `/proc` the C cannot tell a file's offset, and says so where it
/// was asked for one: it probes for it once its file arguments are entered
/// and before it reads the mount table (`initialize()`, `dproc.c:630-664`),
/// and drops what `+f` selected after that (`main.c:1279-1286`). So `-o`
/// is `WARNING: can't report offset; disregarding -o.` before the table's
/// own line, `+f g` is `WARNING: can't report file flags; disregarding
/// +f.` only where the run gets past the table (`-i`), `-w` and `-t` mute
/// both, an `-o` with digits asks for nothing, `-F` with `o` asks as `-o`
/// does, and a run with a path argument ends at the table first. Each line
/// measured on the C; lsof-rs made no probe and said neither (DIVERGENCES
/// 177).
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation)"
)]
fn with_no_proc_dash_o_and_plus_f_are_disregarded_in_the_cs_words() {
    let unshare = match namespace() {
        Ok(argv) => argv,
        Err(why) => {
            eprintln!("skipped: {why}");
            return;
        }
    };
    const OFFSET: &str = "lsof: WARNING: can't report offset; disregarding -o.";
    const FLAGS: &str = "lsof: WARNING: can't report file flags; disregarding +f.";
    const TABLE: &str = "lsof: can't fopen(/proc/mounts, \"r\"): No such file or directory";
    let dir = Scratch::new("probe");
    for (args, lines) in [
        ("-n -P -i -o", &[OFFSET][..]),
        ("-n -P -i +f g", &[FLAGS]),
        ("-n -P -i +f G", &[FLAGS]),
        ("-n -P -i -o +f g", &[OFFSET, FLAGS]),
        ("-n -P -i -o -w", &[]),
        ("-n -P -i +f g -w", &[]),
        ("-n -P -i -o +f g -t", &[]),
        ("-n -P -i -o 10", &[]),
        ("-n -P -i -o -o 10", &[OFFSET]),
        ("-n -P -i -F o", &[OFFSET]),
        ("-n -P -i -F G", &[]),
        ("-n -P -i -F", &[]),
        ("-n -P -i +f g -f g", &[]),
        ("-n -P -i +f g -f g -F G", &[FLAGS]),
        ("-n -P -i", &[]),
        ("-n -P -o", &[OFFSET, TABLE]),
        ("-n -P +f g", &[TABLE]),
        ("-n -P -o +f g -p 1", &[OFFSET, TABLE]),
        ("-n -P -i -o +m", &[OFFSET, TABLE]),
        ("-n -P -i +f g +m", &[FLAGS, TABLE]),
        ("-n -P -o /", &[TABLE]),
        ("-n -P -o -e /proc", &[TABLE]),
        ("-n -P -o +d /", &[TABLE]),
    ] {
        let ended = in_namespace_within(
            &unshare,
            &format!("mount -t tmpfs none /proc || {{ echo skip; exit 0; }}; exec \"$L\" {args}"),
            &dir,
            30,
        );
        let Some((status, out, err)) = ended else {
            panic!("`{args}` did not end");
        };
        if out == "skip\n" {
            eprintln!("skipped: no tmpfs can be mounted over /proc here");
            return;
        }
        assert_eq!(status, Some(1), "{args}: {err}");
        assert_eq!(out, "", "{args}");
        assert_eq!(err.lines().collect::<Vec<_>>(), lines, "{args}");
    }
}

/// The probe needs two descriptors at once, `/` and its own `fdinfo`: under
/// a limit that leaves one (`ulimit -n 4`, nothing else open) it fails in
/// the C, and here, and both say so (measured; the one limit where the two
/// had differed). And where it succeeds, which is everywhere else, `-o`
/// and `+f g` are what they were: no word, an `OFFSET` column, a
/// `FILE-FLAG` column.
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation)"
)]
fn the_offset_probe_fails_under_a_limit_of_four_and_nowhere_else() {
    let limited = "exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-; ulimit -n 4 || exit 2; exec \"$@\"";
    for (args, line) in [
        (
            &["-n", "-P", "-i", "-o"][..],
            Some("lsof: WARNING: can't report offset; disregarding -o."),
        ),
        (
            &["-n", "-P", "-i", "+f", "g"],
            Some("lsof: WARNING: can't report file flags; disregarding +f."),
        ),
        (&["-n", "-P", "-i", "-o", "-w"], None),
        (&["-n", "-P", "-i"], None),
    ] {
        let out = Command::new("sh")
            .args(["-c", limited, "sh", LSOF])
            .args(args)
            .env("RES_OPTIONS", "attempts:0")
            .current_dir("/")
            .stdin(std::process::Stdio::null())
            .output()
            .expect("run sh");
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert_eq!(text(&out.stdout), "", "{args:?}");
        assert_eq!(said(&out), line.into_iter().collect::<Vec<_>>(), "{args:?}");
    }
    for (option, column) in [("-o", " OFFSET "), ("+fg", " FILE-FLAG ")] {
        let out = sh("exec \"$1\" -n -P \"$2\" -a -p $$ -d cwd", &[option]);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{option}: {}",
            text(&out.stderr)
        );
        assert_eq!(said(&out), [] as [String; 0], "{option}");
        let listed = text(&out.stdout);
        let header = listed.lines().next().unwrap_or_default();
        assert!(header.contains(column), "{option}: {header}");
    }
}

/// Where `/proc` is not procfs and a FIFO is where the mount table should
/// be, no run waits on it. The C's `fopen()` waits for a writer for ever
/// (measured, every run that reads the table). lsof-rs opens the table
/// without waiting and refuses a FIFO in the C's words for a table it
/// cannot open, with the reason the kernel gives for a socket there: the
/// table itself (`-p 1`, `+m`), and the question asked of it where the
/// helper cannot start (a path, an `-e`, a `+d`), which the commit that
/// added the question had made a wait.
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation)"
)]
fn a_fifo_for_the_mount_table_holds_no_run() {
    let unshare = match namespace() {
        Ok(argv) => argv,
        Err(why) => {
            eprintln!("skipped: {why}");
            return;
        }
    };
    let dir = Scratch::new("fifo-mounts");
    for args in [
        "-n -P -p 1",
        "-n -P /",
        "-n -P -e /proc",
        "-n -P +d /",
        "-n -P +m",
    ] {
        // Once the FIFO is there nothing but lsof runs: a tool that links
        // libselinux reads `/proc/mounts` as it starts, and waits.
        let ended = in_namespace_within(
            &unshare,
            &format!(
                "mount -t tmpfs none /proc || {{ echo skip; exit 0; }}; \
                 mkfifo /proc/mounts || {{ echo skip; exit 0; }}; exec \"$L\" {args}"
            ),
            &dir,
            30,
        );
        let Some((status, out, err)) = ended else {
            panic!("`{args}` waited on the FIFO /proc/mounts");
        };
        if out == "skip\n" {
            eprintln!("skipped: no tmpfs can be mounted over /proc here, or no mkfifo");
            return;
        }
        assert_eq!(
            (status, out.as_str(), err.as_str()),
            (
                Some(1),
                "",
                "lsof: can't fopen(/proc/mounts, \"r\"): No such device or address\n"
            ),
            "{args}"
        );
    }
}

/// A device where the mount table should be is no table unless it is
/// empty. `/dev/zero` there is one line that never ends: the C's
/// `getmntent()` reads it into a buffer that grows until memory runs out
/// (measured: 4.47 GB in five seconds, for which the kernel killed another
/// process), and under a memory limit it reads on for ever. lsof-rs reads
/// one byte of a device and refuses one that has a byte to give, in the
/// words it has for a table it cannot open: here under an address-space
/// limit of 256 MiB, which a reader of the device would not stay within,
/// and a time limit. `/dev/null` there, which is how a file is masked, is
/// the empty table the C reads it as (measured: nothing listed, nothing
/// said, exit 1 for the process that is not there). And a regular file
/// with no end in sight, a sparse GiB of NULs with no newline, is read to
/// the table's cap of 64 MiB and no further, within the same limits: no
/// whole line, no mount (DIVERGENCES 129, 175).
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation)"
)]
fn a_device_for_the_mount_table_is_no_table_unless_it_is_empty() {
    let unshare = match namespace() {
        Ok(argv) => argv,
        Err(why) => {
            eprintln!("skipped: {why}");
            return;
        }
    };
    let dir = Scratch::new("device-mounts");
    const REFUSED: &str = "lsof: can't fopen(/proc/mounts, \"r\"): No such device or address\n";
    for (device, args, said) in [
        ("/dev/zero", "-n -P -p 1", REFUSED),
        ("/dev/zero", "-n -P /", REFUSED),
        ("/dev/zero", "-n -P -e /proc", REFUSED),
        ("/dev/urandom", "-n -P -p 1", REFUSED),
        ("/dev/null", "-n -P -p 1", ""),
        ("/dev/null", "-n -P -b -p 1", ""),
        ("sparse", "-n -P -p 1", ""),
    ] {
        let make = if device == "sparse" {
            "truncate -s 1G /proc/mounts".to_string()
        } else {
            format!("ln -s {device} /proc/mounts")
        };
        let ended = in_namespace_within(
            &unshare,
            &format!(
                "mount -t tmpfs none /proc || {{ echo skip; exit 0; }}; \
                 {make} || {{ echo skip; exit 0; }}; \
                 ulimit -v 262144 || {{ echo skip; exit 0; }}; exec \"$L\" {args}"
            ),
            &dir,
            30,
        );
        let Some((status, out, err)) = ended else {
            panic!("{device} as /proc/mounts: `{args}` did not end");
        };
        if out == "skip\n" {
            eprintln!("skipped: no tmpfs can be mounted over /proc here");
            return;
        }
        assert_eq!(
            (status, out.as_str(), err.as_str()),
            (Some(1), "", said),
            "{device} as /proc/mounts: {args}"
        );
    }
}

/// Where the probe fails and the run lists all the same, no row has an
/// offset or a flag: the column is the size's, headed `SIZE`; `-F` prints
/// neither `o` nor `G`; JSON has neither `offset` nor `flags`
/// (`Lf->off_def`, `dnode.c:774-783`; `Fsv = 0`, `main.c:1285`;
/// DIVERGENCES 177). The probe's one `open("/")` is refused by `strace`
/// (`-P /`, lsof alone traced, not its helper); the C's output, measured
/// the same way, is the same line for line.
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation)"
)]
fn where_the_probe_fails_no_row_has_an_offset_or_flags() {
    if !can_inject() {
        eprintln!("skipped: no strace that can inject an error");
        return;
    }
    let dir = Scratch::new("probe-rows");
    let file = dir.0.join("handed");
    std::fs::write(&file, "0123456789").expect("write the file");
    let run = |args: &str| {
        let out = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "exec < \"$1\"; strace -o /dev/null -P / -e trace=openat \
                 -e inject=openat:error=EACCES \"$0\" -n -P -a -p $$ -d 0 {args}"
            ))
            .arg(LSOF)
            .arg(&file)
            .env("RES_OPTIONS", "attempts:0")
            .current_dir("/")
            .output()
            .expect("run strace");
        assert_eq!(out.status.code(), Some(0), "{args}: {}", text(&out.stderr));
        out
    };
    // The shell, which waits, holds the file on 0, and is the process
    // listed. The table: both warnings, then a size where the offset was
    // asked for.
    let out = run("-o +f g");
    assert_eq!(
        said(&out),
        [
            "lsof: WARNING: can't report offset; disregarding -o.",
            "lsof: WARNING: can't report file flags; disregarding +f."
        ]
    );
    let listed = text(&out.stdout);
    let mut lines = listed.lines();
    let header: Vec<&str> = lines
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .collect();
    assert_eq!(
        header,
        ["COMMAND", "PID", "USER", "FD", "TYPE", "DEVICE", "SIZE", "NODE", "NAME"],
        "{listed}"
    );
    let row: Vec<&str> = lines
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .collect();
    assert_eq!(row.get(3..5), Some(&["0r", "REG"][..]), "{listed}");
    assert_eq!(row.get(6), Some(&"10"), "the size: {listed}");
    // `-F`: the size, and neither an offset nor the flags.
    let out = run("-w -o +f G -F pfosG");
    let fields: Vec<String> = text(&out.stdout)
        .lines()
        .filter(|l| !l.starts_with('p'))
        .map(str::to_string)
        .collect();
    assert_eq!(fields, ["f0", "s10"], "{}", text(&out.stdout));
    assert_eq!(said(&out), [] as [String; 0]);
    // JSON: the same.
    let out = run("-w -o +f g -J");
    let json = text(&out.stdout);
    assert!(
        json.contains("\"fd\":\"0\"") && json.contains("\"size\":"),
        "{json}"
    );
    assert!(
        !json.contains("\"offset\"") && !json.contains("\"flags\""),
        "{json}"
    );
}

/// The probe asks `/proc/self/fdinfo`, not `/proc/<its pid>/fdinfo` as the
/// C does: in a pid namespace whose `/proc` is the outer one, lsof's pid
/// there names another process, and the C's probe fails (measured: both
/// warnings and a `SIZE` column, `unshare -p -f` without `--mount-proc`),
/// where lsof-rs's succeeds and offsets are told (DIVERGENCES 177; the
/// Linux audit's row 164 for the C's failure).
#[test]
#[cfg_attr(
    miri,
    ignore = "miri cannot spawn a process (posix_spawn is an unsupported operation)"
)]
fn the_probe_succeeds_in_a_pid_namespace_with_the_outer_proc() {
    let works = Command::new("unshare")
        .args(["-p", "-f", "true"])
        .status()
        .is_ok_and(|s| s.success());
    if !works {
        eprintln!("skipped: no pid namespace can be made here");
        return;
    }
    let out = Command::new("unshare")
        .args(["-p", "-f", "sh", "-c"])
        .arg("exec \"$0\" -n -P -o +f g -a -p 1 -d cwd")
        .arg(LSOF)
        .env("RES_OPTIONS", "attempts:0")
        .current_dir("/")
        .output()
        .expect("run unshare");
    assert_eq!(said(&out), [] as [String; 0]);
    let listed = text(&out.stdout);
    let header = listed.lines().next().unwrap_or_default();
    assert!(
        header.contains(" FILE-FLAG ") && header.contains(" OFFSET "),
        "{listed}"
    );
}
