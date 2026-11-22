//! What the binary does on FreeBSD that only a FreeBSD host can show: the
//! points where it reads the mount table and starts its bounded-calls
//! helper, which are the C's (DIVERGENCES 182), its tasks (141), and `-D`
//! (148). Each was measured against the C lsof on FreeBSD 14.5; the
//! side-by-side itself is `differential/freebsd-check.sh`.
#![cfg(target_os = "freebsd")]

use std::process::{Command, Output};

fn lsof(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lsof"))
        .args(["-n", "-P"])
        .args(args)
        .output()
        .expect("run lsof")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// `lsof -n -P -R -F pR` and `args`, with the PID it ran as: what it wrote,
/// and the PIDs of the processes it listed whose parent it is.
fn listing_its_children(args: &[&str]) -> (Output, Vec<u32>) {
    let child = Command::new(env!("CARGO_BIN_EXE_lsof"))
        .args(["-n", "-P", "-R", "-F", "pR"])
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("run lsof");
    let lsof = child.id();
    let out = child.wait_with_output().expect("wait for lsof");
    let mut children = Vec::new();
    let mut pid = None;
    for line in text(&out.stdout).lines() {
        if let Some(p) = line.strip_prefix('p') {
            pid = p.parse::<u32>().ok();
        } else if let (Some(r), Some(p)) = (line.strip_prefix('R'), pid) {
            if r.parse::<u32>().ok() == Some(lsof) {
                children.push(p);
            }
        }
    }
    (out, children)
}

/// A run that names no path reads no mount table and starts no helper: the
/// lsof it lists has no child, and `-b` has nothing to avoid.
#[test]
fn a_run_with_no_path_starts_no_helper_and_reads_no_mount() {
    let (out, children) = listing_its_children(&["-c", "lsof"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("\np"), "it lists itself");
    assert_eq!(children, [], "it has no helper");
    for args in [
        &["-b", "-p", "1"][..],
        &["-b", "-N"],
        &["-b", "-U"],
        &["-b", "-i"],
        &["-b", "-K", "i", "-p", "1"],
    ] {
        let out = lsof(args);
        assert_eq!(text(&out.stderr), "", "{args:?}");
    }
}

/// A path argument reads the table and starts the helper, as the C forks
/// its child: lsof lists its own child.
#[test]
fn a_path_argument_starts_the_helper() {
    let (_, children) = listing_its_children(&["-c", "lsof", "/"]);
    assert_eq!(children.len(), 1, "its helper: {children:?}");
    // And under `-b` each call it would have made is said to be avoided.
    let out = lsof(&["-b", "/"]);
    let err = text(&out.stderr);
    assert!(
        err.starts_with("lsof: avoiding readlink(/): -b was specified.\n"),
        "{err}"
    );
}

/// The helper's descriptor 2 is `/dev/null` as lsof opened it, for reading
/// and writing (DIVERGENCES 144): a run that names `/dev/null` lists it,
/// `2u`, where the C's child has no descriptor 2.
///
/// Not yet run: the FreeBSD host this file was measured on was lost before
/// this test's first run there. The row it was written from is the one
/// measured before the change, `lsof PID USER 2w VCHR 0,20 0t0 20
/// /dev/null`, and `-F`'s lines are the shared renderer's.
#[test]
fn the_helpers_descriptor_2_is_dev_null_open_both_ways() {
    let child = Command::new(env!("CARGO_BIN_EXE_lsof"))
        .args([
            "-n", "-P", "-R", "-F", "pRfan", "-a", "-c", "lsof", "-d", "2",
        ])
        .arg("/dev/null")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("run lsof");
    let lsof = child.id();
    let out = child.wait_with_output().expect("wait for lsof");
    let listed = text(&out.stdout);
    // One set a process: the one whose parent is this lsof is its helper.
    let mut sets: Vec<Vec<&str>> = Vec::new();
    for line in listed.lines() {
        if line.starts_with('p') {
            sets.push(Vec::new());
        }
        if let Some(set) = sets.last_mut() {
            set.push(line);
        }
    }
    let parent = format!("R{lsof}");
    let helper: Vec<&Vec<&str>> = sets
        .iter()
        .filter(|s| s.contains(&parent.as_str()))
        .collect();
    assert_eq!(helper.len(), 1, "{listed}");
    assert_eq!(
        helper[0].iter().skip(2).copied().collect::<Vec<_>>(),
        ["f2", "au", "n/dev/null"],
        "{listed}"
    );
}

/// `-K`: every thread of a process is listed with its TID, in a TID column
/// and no TASKCMD; `-F` gives `K` after `p`.
#[test]
fn dash_k_lists_each_thread_with_its_tid() {
    // This test binary has more than one thread (the harness's, and this
    // test's).
    let me = std::process::id().to_string();
    let out = lsof(&["-K", "-a", "-p", &me, "-d", "cwd"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let table = text(&out.stdout);
    let header = table.lines().next().unwrap_or_default();
    assert!(header.starts_with("COMMAND"), "{table}");
    assert!(
        header.contains(" TID ") && !header.contains("TASKCMD"),
        "{header}"
    );
    assert!(table.lines().count() >= 3, "two threads at least: {table}");
    let out = lsof(&["-K", "-a", "-p", &me, "-d", "cwd", "-F", "pK"]);
    let fields = text(&out.stdout);
    let tids: Vec<u32> = fields
        .lines()
        .filter_map(|l| l.strip_prefix('K'))
        .filter_map(|t| t.parse().ok())
        .collect();
    assert!(
        tids.len() >= 2 && tids.iter().all(|&t| t >= 100_000),
        "{fields}"
    );
    assert_eq!(
        fields.lines().filter(|l| *l == format!("p{me}")).count(),
        tids.len(),
        "a process set for each thread: {fields}"
    );
    // Without `-K`, and under `-K i`: the process, once, and no TID.
    for args in [
        &["-a", "-p", &me, "-d", "cwd"][..],
        &["-K", "i", "-a", "-p", &me, "-d", "cwd"],
    ] {
        let out = lsof(args);
        let table = text(&out.stdout);
        assert_eq!(table.lines().count(), 2, "{args:?}: {table}");
        assert!(!table.contains(" TID "), "{table}");
    }
}

/// `-D`: read as the C reads it, and no cache file is read or written.
#[test]
fn dash_d_is_read_and_no_cache_file_is_written() {
    let out = lsof(&["-D", "?"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(text(&out.stdout), "");
    assert_eq!(
        text(&out.stderr),
        "Device cache file read-only paths:\n    none\nDevice cache file write paths:\n    none\n"
    );
    let dir = std::env::temp_dir().join(format!("lsof-rs-dcache-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    let me = std::process::id().to_string();
    for letter in ["b", "u", "r"] {
        let value = format!("{letter}{}", dir.join("cache").display());
        let out = lsof(&["-D", &value, "-a", "-p", &me, "-d", "cwd"]);
        assert!(out.status.success(), "{letter}: {}", text(&out.stderr));
        assert_eq!(text(&out.stderr), "", "{letter}");
        assert_eq!(text(&out.stdout).lines().count(), 2, "{letter}");
    }
    assert_eq!(
        std::fs::read_dir(&dir).map(Iterator::count).ok(),
        Some(0),
        "no cache file was written"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let out = lsof(&["-D", "x"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).starts_with("lsof: unknown -D option: x\n"));
}

/// The letters FreeBSD's C lacks are illegal, and `-M` is read.
#[test]
fn the_option_letters_are_freebsds() {
    for (args, line) in [
        (&["-X"][..], "lsof: illegal option character: X\n"),
        (&["-E"], "lsof: illegal option character: E\n"),
        (&["-e", "/tmp"], "lsof: illegal option character: e\n"),
        (&["-Z"], "lsof: illegal option character: Z\n"),
        (
            &["-s", "UDP:Idle"],
            "lsof: unknown -s protocol: \"UDP:Idle\"\n",
        ),
    ] {
        let out = lsof(args);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert!(
            text(&out.stderr).starts_with(line),
            "{args:?}: {}",
            text(&out.stderr)
        );
    }
    let me = std::process::id().to_string();
    for m in ["-M", "+M"] {
        let out = lsof(&[m, "-a", "-p", &me, "-d", "cwd"]);
        assert!(out.status.success(), "{m}: {}", text(&out.stderr));
        assert_eq!(text(&out.stdout).lines().count(), 2, "{m}");
    }
}
