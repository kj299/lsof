//! A socket's host and port named end to end on Linux (DIVERGENCES 154), in
//! a place CI runs: an unprivileged user namespace with a mount and a
//! network namespace of its own, whose /etc/hosts, /etc/services,
//! /etc/nsswitch.conf and /etc/resolv.conf are the test's (bound over the
//! host's inside the namespace only), and whose network is a loopback that
//! is down: nothing can leave it, and `attempts:0` asks no server besides.
//! The C names the listener `two:r38tcp` (gethostbyaddr() and
//! getservbyport() over those files); `-n`, `-P` and `+n +P` after them
//! turn each half off and on again. Skipped, saying why, where the host
//! has no unprivileged user namespaces or no python3 to hold the socket.
#![cfg(target_os = "linux")]

use std::process::Command;

const HOLDER: &str = "import socket,sys,time,os
t=socket.socket(); t.bind(('127.0.0.2',54901)); t.listen(1)
open(sys.argv[1],'w').close()
time.sleep(60)";

/// Each of `runs`' lsof argv (after `-a -p PID -i`), run inside the
/// namespace: its stdout, or `None` where the namespace cannot be made.
fn inside(runs: &[&[&str]]) -> Option<Vec<String>> {
    let works = Command::new("unshare")
        .args(["--user", "--map-root-user", "--mount", "--net", "true"])
        .status()
        .is_ok_and(|s| s.success());
    if !works {
        eprintln!("skipped: no unprivileged user namespace here");
        return None;
    }
    if !Command::new("python3")
        .args(["-c", "pass"])
        .status()
        .is_ok_and(|s| s.success())
    {
        eprintln!("skipped: no python3 to hold the socket");
        return None;
    }
    let dir = std::env::temp_dir().join(format!("lsof-rs-names-it-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for (name, text) in [
        ("hosts", "127.0.0.1 localhost\n127.0.0.2 two\n"),
        ("services", "r38tcp 54901/tcp\n"),
        (
            "nsswitch.conf",
            "passwd: files\nhosts: files dns\nservices: files\n",
        ),
        ("resolv.conf", "nameserver 127.0.0.1\noptions attempts:0\n"),
        ("holder.py", HOLDER),
    ] {
        std::fs::write(dir.join(name), text).unwrap();
    }
    let mut script = String::from(
        "set -e\ncd \"$1\"\nfor f in hosts services nsswitch.conf resolv.conf; do mount --bind \"$f\" \"/etc/$f\"; done\n\
         python3 holder.py ready & H=$!\n\
         i=0; while [ ! -e ready ]; do i=$((i+1)); [ $i -lt 400 ] || exit 3; sleep 0.05; done\n",
    );
    for (i, argv) in runs.iter().enumerate() {
        script.push_str(&format!(
            "RES_OPTIONS=attempts:0 \"$2\" {} -a -p $H -i > out{i} 2>&1 || true\n",
            argv.join(" ")
        ));
    }
    script.push_str("kill $H\n");
    let status = Command::new("unshare")
        .args([
            "--user",
            "--map-root-user",
            "--mount",
            "--net",
            "sh",
            "-c",
            &script,
            "sh",
        ])
        .arg(&dir)
        .arg(env!("CARGO_BIN_EXE_lsof"))
        .status()
        .expect("run the namespace");
    assert!(status.success(), "the namespace's script: {status:?}");
    let outs = (0..runs.len())
        .map(|i| std::fs::read_to_string(dir.join(format!("out{i}"))).unwrap())
        .collect();
    std::fs::remove_dir_all(&dir).unwrap();
    Some(outs)
}

#[test]
#[cfg_attr(miri, ignore = "it starts processes in a namespace of their own")]
fn a_socket_is_named_by_default_from_the_namespaces_own_files() {
    let runs: &[&[&str]] = &[
        &[],
        &["-n"],
        &["-P"],
        &["-n", "-P", "+n", "+P"],
        &["-n", "-P"],
    ];
    let Some(outs) = inside(runs) else {
        return;
    };
    let name = |out: &str| -> String {
        out.lines()
            .find(|l| l.contains("(LISTEN)"))
            .and_then(|l| l.split_whitespace().rev().nth(1))
            .unwrap_or_default()
            .to_string()
    };
    assert_eq!(name(&outs[0]), "two:r38tcp", "{}", outs[0]);
    assert_eq!(name(&outs[1]), "127.0.0.2:r38tcp", "{}", outs[1]);
    assert_eq!(name(&outs[2]), "two:54901", "{}", outs[2]);
    assert_eq!(name(&outs[3]), "two:r38tcp", "{}", outs[3]);
    assert_eq!(name(&outs[4]), "127.0.0.2:54901", "{}", outs[4]);
}
