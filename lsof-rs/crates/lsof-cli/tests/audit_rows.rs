//! Two rows of the Linux backend seen end to end in the built binary,
//! where no unit test of the backend can pin them (DIVERGENCES 159, 166):
//!
//! * lsof's own rows. The C holds `/proc` open for the whole of its walk
//!   and `/proc/PID/fd` while it reads a process's links, so its listing of
//!   itself has a `DIR` row for each; lsof-rs opened and shut both before a
//!   row was made, and had neither. Inside the test binary other threads
//!   hold `/proc` open at any moment, so only a process of lsof's own shows
//!   which rows are its own.
//! * a ping socket's row, which comes from `/proc/net/icmp`: a table that
//!   is empty unless the network namespace lets someone open a ping socket,
//!   which this one is made to (an unprivileged user namespace with a
//!   network namespace of its own, as `names.rs` makes one). Skipped,
//!   saying why, where the host has no such namespaces, no python3 to hold
//!   the sockets, or no ping sockets.
#![cfg(target_os = "linux")]

use std::process::{Command, Stdio};

/// An `-F` listing as its file sets: for each `f` line, the descriptor and
/// then every other field of that file, by its letter.
fn file_sets(out: &str) -> Vec<Vec<(char, String)>> {
    let mut sets: Vec<Vec<(char, String)>> = Vec::new();
    for line in out.lines() {
        let mut chars = line.chars();
        let Some(letter) = chars.next() else { continue };
        let value = chars.as_str().to_string();
        match letter {
            'p' => {}
            'f' => sets.push(vec![('f', value)]),
            _ => {
                if let Some(set) = sets.last_mut() {
                    set.push((letter, value));
                }
            }
        }
    }
    sets
}

fn field(set: &[(char, String)], letter: char) -> Option<&str> {
    set.iter()
        .find(|(l, _)| *l == letter)
        .map(|(_, v)| v.as_str())
}

/// lsof run as the process whose pid it is told to list: `exec` makes the
/// shell's process lsof's, so `$$` is lsof's own pid. Returns that pid, the
/// exit status and both streams.
fn lsof_of_itself(args: &str) -> (u32, bool, String, String) {
    let child = Command::new("sh")
        .args(["-c", &format!("exec \"$0\" -n -P {args}")])
        .arg(env!("CARGO_BIN_EXE_lsof"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("sh");
    let pid = child.id();
    let out = child.wait_with_output().expect("lsof");
    (
        pid,
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Measured against the C in a PID namespace of its own (`unshare -n -p -f
/// --mount-proc lsof -n -P -a -p 1 -d 0-9`): `3r DIR … /proc` and `4r DIR …
/// /proc/1/fd`, the `opendir(PROCFS)` of `gather_proc_info()` and the
/// `opendir(Dpath)` of `process_id()`, both still open when the rows are
/// made. lsof-rs has the same two rows (the second at another number, past
/// the helper's pipes: DIVERGENCES 123).
#[test]
#[cfg_attr(miri, ignore = "it starts a process")]
fn lsof_lists_its_own_proc_and_fd_directories() {
    let (pid, ok, out, err) = lsof_of_itself("-F fatn -p $$");
    assert!(ok, "{out}{err}");
    assert!(
        out.lines().any(|l| l == format!("p{pid}")),
        "its own process: {out}{err}"
    );
    let sets = file_sets(&out);
    for name in ["/proc".to_string(), format!("/proc/{pid}/fd")] {
        let rows: Vec<_> = sets
            .iter()
            .filter(|s| field(s, 'n') == Some(name.as_str()))
            .collect();
        assert_eq!(rows.len(), 1, "one row named {name}: {out}{err}");
        let row = rows[0];
        assert_eq!(field(row, 't'), Some("DIR"), "{name}: {out}");
        assert_eq!(field(row, 'a'), Some("r"), "{name}: {out}");
        let fd = field(row, 'f').unwrap();
        assert!(
            fd.parse::<u32>().is_ok_and(|n| n > 2),
            "{name} is a descriptor of its own, {fd}: {out}"
        );
    }
    // And no descriptor it could not read: each link was read while the
    // directory that lists it was open.
    assert!(!out.contains("(readlink:"), "{out}");
}

/// So `lsof /proc`, every open file on that file system, finds lsof itself,
/// as the C's does (measured: exit status 0, and its own two rows).
#[test]
#[cfg_attr(miri, ignore = "it starts a process")]
fn lsof_finds_itself_on_the_proc_file_system() {
    let (pid, ok, out, err) = lsof_of_itself("-t -a -p $$ /proc");
    assert!(ok, "{out}{err}");
    assert_eq!(out, format!("{pid}\n"), "{err}");
}

/// A new directory for one test's files, `lsof-rs-<tag>-<pid>-<n>` in the
/// target's own temp directory, not the shared one: made by `mkdir` with
/// mode 0700, which fails on anything already there, then checked to be a
/// directory owned by this process's effective uid. The script it holds is
/// run, so no one else may have made or be able to change it.
fn fresh_dir(tag: &str) -> std::path::PathBuf {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let euid: u32 = std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|v| v.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .expect("an effective uid");
    let base = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"));
    for n in 0..64 {
        let dir = base.join(format!("lsof-rs-{tag}-{}-{n}", std::process::id()));
        match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => {
                let md = std::fs::symlink_metadata(&dir).unwrap();
                assert!(md.is_dir() && md.uid() == euid && md.mode() & 0o077 == 0);
                return dir;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => panic!("mkdir {}: {e}", dir.display()),
        }
    }
    panic!("no fresh directory under {}", base.display());
}

/// Holds a ping socket bound to 127.0.0.1 with id 4242 at descriptor 20,
/// which the kernel lists in `/proc/net/icmp`, and one never used at 21,
/// which is in no table.
const PING_HOLDER: &str = "import fcntl,os,socket,struct,sys,time
s=socket.socket()
f=struct.unpack('16sH',fcntl.ioctl(s,0x8913,struct.pack('16sH',b'lo',0).ljust(40,b'\\0'))[:18])[1]
fcntl.ioctl(s,0x8914,struct.pack('16sH',b'lo',f|1).ljust(40,b'\\0')); s.close()
open('/proc/sys/net/ipv4/ping_group_range','w').write('0 0')
def at(s,n):
    fd=s.detach(); os.dup2(fd,n); os.close(fd)
def ping(): return socket.socket(socket.AF_INET,socket.SOCK_DGRAM,socket.IPPROTO_ICMP)
b=ping(); b.bind(('127.0.0.1',4242)); at(b,20)
at(ping(),21)
open(sys.argv[1],'w').close()
time.sleep(60)";

/// Each of `runs`' lsof argv (before `-F ftn -a -p PID -d 20,21`), run in a
/// network namespace where the holder has its ping sockets: its stdout and
/// its stderr, or `None` where that cannot be arranged.
fn beside_ping_sockets(runs: &[&[&str]]) -> Option<Vec<(String, String)>> {
    let works = Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "true"])
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
        eprintln!("skipped: no python3 to hold the sockets");
        return None;
    }
    let dir = fresh_dir("ping");
    std::fs::write(dir.join("holder.py"), PING_HOLDER).unwrap();
    // 7: the holder went away before it was ready, which is a namespace
    // that will not have ping sockets (`/proc/sys` read-only, or a kernel
    // built without them).
    let mut script = String::from(
        "set -e\ncd \"$1\"\npython3 holder.py ready 2> holder.err & H=$!\n\
         trap 'kill $H 2>/dev/null' EXIT\n\
         i=0; while [ ! -e ready ]; do i=$((i+1)); [ $i -lt 400 ] || exit 3; \
         kill -0 $H 2>/dev/null || exit 7; sleep 0.05; done\n",
    );
    for (i, argv) in runs.iter().enumerate() {
        script.push_str(&format!(
            "timeout 30 \"$2\" -n -P {} -F ftn -a -p $H -d 20,21 > out{i} 2> err{i} || true\n",
            argv.join(" ")
        ));
    }
    let status = Command::new("unshare")
        .args([
            "--user",
            "--map-root-user",
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
    if status.code() == Some(7) {
        eprintln!(
            "skipped: no ping sockets in a namespace of its own here: {}",
            std::fs::read_to_string(dir.join("holder.err"))
                .unwrap_or_default()
                .trim()
        );
        let _ = std::fs::remove_dir_all(&dir);
        return None;
    }
    assert!(status.success(), "the namespace's script: {status:?}");
    let outs = (0..runs.len())
        .map(|i| {
            let read = |f: &str| std::fs::read_to_string(dir.join(format!("{f}{i}"))).unwrap();
            (read("out"), read("err"))
        })
        .collect();
    std::fs::remove_dir_all(&dir).unwrap();
    Some(outs)
}

/// Measured against the C in the same namespace: the bound socket is TYPE
/// `icmp`, named by the table's two addresses, with `-X` as without it
/// (`get_icmp()` has no `Fxopt` test); the one never used is in no table,
/// and is `sock`, named by the kernel, or under `-X` by lsof.
#[test]
#[cfg_attr(miri, ignore = "it starts processes in a namespace of their own")]
fn a_ping_socket_is_an_icmp_row_with_and_without_dash_x() {
    let runs: &[&[&str]] = &[&[], &["-X"]];
    let Some(outs) = beside_ping_sockets(runs) else {
        return;
    };
    let rows = |out: &str| -> Vec<String> {
        out.lines()
            .filter(|l| !l.starts_with('p'))
            .map(str::to_string)
            .collect()
    };
    assert_eq!(
        rows(&outs[0].0),
        [
            "f20",
            "ticmp",
            "n0100007F:1092->00000000:0000",
            "f21",
            "tsock",
            "nprotocol: PING"
        ],
        "{:?}",
        outs[0]
    );
    assert_eq!(
        rows(&outs[1].0),
        [
            "f20",
            "ticmp",
            "n0100007F:1092->00000000:0000",
            "f21",
            "tsock",
            "ncan't identify protocol (-X specified)"
        ],
        "{:?}",
        outs[1]
    );
}
