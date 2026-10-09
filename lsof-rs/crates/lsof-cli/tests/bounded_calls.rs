//! The bounded file-system calls against a file system that does not answer
//! (DIVERGENCES 94, 110): what the differential cannot hold, because the C
//! itself hangs there. A FUSE server that reads every `stat` of its root and
//! never answers (`differential/fuse_hang.py`, hold mode) is mounted in a
//! mount namespace of the test's own, and lsof-rs is run inside it.
//!
//! Root only — mounting needs it — and skipped, saying why, where it cannot
//! run: no root, no `/dev/fuse` or one that cannot be mounted, no `unshare`,
//! no python3, or a kernel that would abort a held request by itself
//! (`fs.fuse.*request_timeout`), which would make a hang end for the wrong
//! reason. Nothing is mounted outside the private namespace, and no process
//! the test starts keeps a directory, file or mapping on the mount: the
//! process lsof is asked about sits in `/`. The helpers lsof-rs kills there
//! do hold what their calls opened, and anything on the host that `stat`s
//! their descriptors waits until the teardown aborts the connection
//! (DIVERGENCES 123), so every case is short and always torn down.
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::Command;

/// One FUSE case at a time. A whole-host run `stat`s every process's files,
/// and another case's `lsof -O` waiting on its own mount holds the `O_PATH`
/// descriptor its `stat` opened there (DIVERGENCES 119): run beside it, the
/// scan would wait for that case's teardown.
static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Why this host cannot run the FUSE cases, if it cannot.
fn unavailable() -> Option<String> {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let euid = status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|l| l.split_whitespace().nth(1));
    if euid != Some("0") {
        return Some("not root".into());
    }
    if !Path::new("/dev/fuse").exists() {
        return Some("no /dev/fuse".into());
    }
    for name in ["default_request_timeout", "max_request_timeout"] {
        let v = std::fs::read_to_string(format!("/proc/sys/fs/fuse/{name}")).unwrap_or_default();
        if !matches!(v.trim(), "" | "0") {
            return Some(format!(
                "fs.fuse.{name} is {}: the kernel would end a hang",
                v.trim()
            ));
        }
    }
    let works = |argv: &[&str]| {
        Command::new(argv[0])
            .args(&argv[1..])
            .output()
            .is_ok_and(|o| o.status.success())
    };
    if !works(&["unshare", "-m", "--propagation", "private", "true"]) {
        return Some("no `unshare -m`".into());
    }
    if !works(&["python3", "-c", "pass"]) {
        return Some("no python3".into());
    }
    None
}

/// A directory of the test's own, removed when it goes out of scope.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let tmp = std::fs::canonicalize(std::env::temp_dir()).expect("a temp directory");
        let dir = tmp.join(format!("lsof-rs-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("fuse")).expect("make a scratch directory");
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A process to list that holds nothing on the mount: `sleep`, in `/`.
struct Sleeper(std::process::Child);

impl Drop for Sleeper {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Run `body` (shell) in a private mount namespace with the FUSE server
/// mounted at `$FUSE` in `mode`, its log at `$LOG`, and lsof at `$LSOF`,
/// then take the server down, which aborts the connection and frees every
/// caller still waiting on it. Every line `body` prints as `key=value` comes
/// back; `None`, said, where FUSE could not be mounted after all (a
/// `/dev/fuse` that is there but does not work), which is a reason to skip,
/// not a failure.
fn in_namespace(dir: &Scratch, mode: &str, body: &str) -> Option<Vec<(String, String)>> {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../differential/fuse_hang.py");
    let script = format!(
        r#"set -u
cd /
BASE='{base}'; FUSE='{fuse}'; LOG='{log}'; LSOF='{lsof}'
python3 -I '{fixture}' "$FUSE" {mode} --ready '{ready}' --log "$LOG" --lifetime 60 &
srv=$!
i=0
while [ ! -e '{ready}' ]; do
    i=$((i+1))
    if [ $i -gt 200 ] || ! kill -0 $srv 2>/dev/null; then
        echo error=no-fuse; kill $srv 2>/dev/null; exit 0
    fi
    sleep 0.05
done
now() {{ date +%s%N; }}
# The state of every lsof-rs helper in this mount namespace: what this test
# started, and nothing another run on the host did.
ns=$(readlink /proc/$$/ns/mnt)
helpers() {{
    for p in /proc/[0-9]*; do
        [ "$(readlink $p/ns/mnt 2>/dev/null)" = "$ns" ] || continue
        [ "$(tr '\0' '\n' < $p/cmdline 2>/dev/null | sed -n 2p)" = '{helper_arg}' ] || continue
        cut -d' ' -f3 $p/stat 2>/dev/null
    done | tr -d '\n'
}}
{body}
kill $srv; wait $srv
i=0
while [ -n "$(helpers)" ] && [ $i -lt 40 ]; do i=$((i+1)); sleep 0.05; done
echo "after_teardown=$(helpers)"
"#,
        base = dir.0.display(),
        fuse = dir.0.join("fuse").display(),
        log = dir.0.join("fuse.log").display(),
        lsof = env!("CARGO_BIN_EXE_lsof"),
        fixture = fixture.display(),
        ready = dir.0.join("ready").display(),
        helper_arg = "--lsof-rs-bounded-fs-helper",
    );
    let out = Command::new("timeout")
        .args([
            "-k",
            "5",
            "90",
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
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let got: Vec<(String, String)> = text
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    if got.iter().any(|(k, v)| k == "error" && v == "no-fuse") {
        eprintln!("skipped: FUSE could not be mounted here");
        return None;
    }
    Some(got)
}

fn get<'a>(got: &'a [(String, String)], key: &str) -> &'a str {
    got.iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
        .unwrap_or_else(|| panic!("no {key} in {got:?}"))
}

/// The C hangs here, forever (its timeout works once per run, and here it
/// never fires: DIVERGENCES 118). lsof-rs gives the mount point's `stat` its
/// two seconds, drops the mount, and lists the process: it exits within the
/// limit, its stdout reaches EOF and it is reaped while the server still
/// holds the request — no thread of it waits on the file system. The helper
/// it killed waits there instead, in `D`, until the connection is aborted.
#[test]
#[cfg_attr(miri, ignore = "miri cannot spawn a process")]
fn a_mount_that_never_answers_costs_the_limit_and_the_run_ends() {
    if let Some(why) = unavailable() {
        eprintln!("skipped: {why}");
        return;
    }
    let dir = Scratch::new("fuse-hold");
    let sleeper = Sleeper(
        Command::new("sleep")
            .arg("120")
            .current_dir("/")
            .spawn()
            .expect("start a sleeper"),
    );
    let pid = sleeper.0.id();
    let Some(got) = in_namespace(
        &dir,
        "--mode hold",
        &format!(
            r#"t0=$(now)
out=$("$LSOF" -S 2 -a -d cwd -p {pid} 2>'{err}')
rc=$?
t1=$(now)
echo "rc=$rc"
echo "ms=$(( (t1 - t0) / 1000000 ))"
echo "rows=$(printf '%s\n' "$out" | grep -c '^sleep ')"
echo "server_alive=$(kill -0 $srv 2>/dev/null && echo yes || echo no)"
echo "held=$(grep -c HELD "$LOG")"
echo "torn_down=$(grep -c teardown "$LOG")"
echo "helpers=$(helpers)"
"#,
            err = dir.0.join("err").display(),
        ),
    ) else {
        return;
    };
    assert_eq!(get(&got, "rc"), "0", "{got:?}");
    let ms: u64 = get(&got, "ms").parse().unwrap();
    assert!((2000..3500).contains(&ms), "took {ms} ms: {got:?}");
    assert_eq!(
        get(&got, "rows"),
        "1",
        "the sleeper's cwd is listed: {got:?}"
    );
    // The run was over while the request was still held.
    assert_eq!(get(&got, "server_alive"), "yes");
    assert_eq!(get(&got, "held"), "1", "{got:?}");
    assert_eq!(get(&got, "torn_down"), "0");
    assert_eq!(
        get(&got, "helpers"),
        "D",
        "one killed helper, waiting: {got:?}"
    );
    assert_eq!(get(&got, "after_teardown"), "", "the abort frees it");
    // Nothing on stderr yet: the warning the C prints for a mount it cannot
    // `stat` is DIVERGENCES 87's.
    assert_eq!(std::fs::read(dir.0.join("err")).unwrap(), b"");
    drop(sleeper);
}

/// A slow file system that answers within the limit is waited for, and
/// nothing is said: the answer is the C's, with no warning and no helper
/// killed. Under `-O` the call is lsof's own and has no limit: an answer
/// that comes after `-S` is taken, where the C crashes (DIVERGENCES 119),
/// and on a mount that never answers it is still waiting long after `-S`
/// would have ended it — the risk the C documents.
#[test]
#[cfg_attr(miri, ignore = "miri cannot spawn a process")]
fn an_answer_in_time_is_taken_and_dash_o_has_no_limit() {
    if let Some(why) = unavailable() {
        eprintln!("skipped: {why}");
        return;
    }
    let pid = |s: &Sleeper| s.0.id();
    let sleeper = Sleeper(
        Command::new("sleep")
            .arg("120")
            .current_dir("/")
            .spawn()
            .expect("start a sleeper"),
    );
    let dir = Scratch::new("fuse-delay");
    let Some(got) = in_namespace(
        &dir,
        "--mode delay --delay 1",
        &format!(
            r#"t0=$(now)
out=$("$LSOF" -S 3 -a -d cwd -p {pid} 2>'{err}')
rc=$?
t1=$(now)
echo "rc=$rc"
echo "ms=$(( (t1 - t0) / 1000000 ))"
echo "rows=$(printf '%s\n' "$out" | grep -c '^sleep ')"
echo "helpers=$(helpers)"
"#,
            pid = pid(&sleeper),
            err = dir.0.join("err").display(),
        ),
    ) else {
        return;
    };
    assert_eq!(get(&got, "rc"), "0", "{got:?}");
    let ms: u64 = get(&got, "ms").parse().unwrap();
    assert!((1000..2900).contains(&ms), "took {ms} ms: {got:?}");
    assert_eq!(get(&got, "rows"), "1", "{got:?}");
    assert_eq!(get(&got, "helpers"), "", "no helper was killed: {got:?}");
    assert_eq!(std::fs::read(dir.0.join("err")).unwrap(), b"");

    // `-O` on an answer that outlives `-S`: the C crashes when it comes
    // (DIVERGENCES 119); lsof-rs waits for it and lists.
    let dir = Scratch::new("fuse-late-O");
    let Some(got) = in_namespace(
        &dir,
        "--mode delay --delay 3",
        &format!(
            r#"t0=$(now)
out=$("$LSOF" -O -S 2 -a -d cwd -p {pid} 2>'{err}')
rc=$?
t1=$(now)
echo "rc=$rc"
echo "ms=$(( (t1 - t0) / 1000000 ))"
echo "rows=$(printf '%s\n' "$out" | grep -c '^sleep ')"
"#,
            pid = pid(&sleeper),
            err = dir.0.join("err").display(),
        ),
    ) else {
        return;
    };
    assert_eq!(get(&got, "rc"), "0", "{got:?}");
    let ms: u64 = get(&got, "ms").parse().unwrap();
    assert!((3000..4500).contains(&ms), "took {ms} ms: {got:?}");
    assert_eq!(get(&got, "rows"), "1", "{got:?}");
    assert_eq!(std::fs::read(dir.0.join("err")).unwrap(), b"");

    let dir = Scratch::new("fuse-hold-O");
    let Some(got) = in_namespace(
        &dir,
        "--mode hold",
        &format!(
            r#""$LSOF" -O -S 2 -a -d cwd -p {pid} >/dev/null 2>&1 &
lp=$!
sleep 4
echo "waiting=$(cut -d' ' -f3 /proc/$lp/stat 2>/dev/null)"
echo "helpers=$(helpers)"
"#,
            pid = pid(&sleeper),
        ),
    ) else {
        return;
    };
    let state = get(&got, "waiting");
    assert!(
        state == "S" || state == "D",
        "-O was not still waiting after 4 s: {got:?}"
    );
    assert_eq!(get(&got, "helpers"), "", "-O starts no helper: {got:?}");
    assert_eq!(get(&got, "after_teardown"), "");
    drop(sleeper);
}

/// What a killed helper leaves behind costs nothing. Waiting on the mount's
/// `stat`, a helper holds the `O_PATH` descriptor it opened, and once killed
/// it keeps it until the connection is aborted; a scan that `stat`ed
/// `/proc/HELPER/fd/3` would wait there too. Measured before the fix: a
/// plain `lsof -S 2` dropped the mount after two seconds and then hung on
/// its own helper's descriptor until it was killed, and so did a path
/// argument that survived and a `+D` over the mount's parent. Now each run
/// costs the limit once per call that times out: the whole host twice in a
/// row (the second run finds the first's helper, still waiting, and skips
/// what it opened too); a `+D` whose walk meets the mount, warning `can't
/// lstat` after the table's limit and its own; and two path arguments, one
/// on the mount, which costs a second limit after the table's, and one that
/// is listed.
#[test]
#[cfg_attr(miri, ignore = "miri cannot spawn a process")]
fn a_killed_helper_holds_nothing_a_scan_waits_on() {
    if let Some(why) = unavailable() {
        eprintln!("skipped: {why}");
        return;
    }
    let dir = Scratch::new("fuse-trap");
    // Run through the dynamic loader, a helper's command line is not the one
    // another run knows it by; lsof still knows its own by their pids.
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap_or_default();
    let loader = maps
        .lines()
        .find_map(|l| {
            let path = l.split_whitespace().nth(5)?;
            let name = path.rsplit('/').next()?;
            (name.starts_with("ld-") && name.contains(".so")).then(|| path.to_string())
        })
        .unwrap_or_default();
    let Some(got) = in_namespace(
        &dir,
        "--mode hold",
        &format!(
            r#"run() {{
    t0=$(now)
    out=$($LOADER "$LSOF" -S 2 "$@" 2>'{err}')
    rc=$?
    t1=$(now)
    echo "$name.rc=$rc"
    echo "$name.ms=$(( (t1 - t0) / 1000000 ))"
    echo "$name.lines=$(printf '%s\n' "$out" | grep -c .)"
    echo "$name.err=$(tr '\n' '|' < '{err}')"
}}
LOADER=
name=host1 run -n -P
name=host2 run -n -P
name=walk run +D "$BASE"
name=args run -n -P "$FUSE/." /dev/null
LOADER='{loader}'
if [ -n "$LOADER" ]; then name=loader run -n -P; fi
echo "helpers=$(helpers)"
"#,
            err = dir.0.join("err").display(),
        ),
    ) else {
        return;
    };
    let ms = |name: &str| -> u64 { get(&got, &format!("{name}.ms")).parse().unwrap() };
    if !loader.is_empty() {
        assert_eq!(get(&got, "loader.rc"), "0", "{got:?}");
        assert!((2000..3500).contains(&ms("loader")), "{got:?}");
    }
    for host in ["host1", "host2"] {
        assert_eq!(get(&got, &format!("{host}.rc")), "0", "{got:?}");
        assert!((2000..3500).contains(&ms(host)), "{host}: {got:?}");
        let lines: u64 = get(&got, &format!("{host}.lines")).parse().unwrap();
        assert!(lines > 1, "{host} listed nothing: {got:?}");
        assert_eq!(get(&got, &format!("{host}.err")), "", "{got:?}");
    }
    // The table's limit (read at the `+D`), then the walk's `lstat`'s.
    assert!((4000..5500).contains(&ms("walk")), "{got:?}");
    let fuse = dir.0.join("fuse");
    assert_eq!(
        get(&got, "walk.err"),
        format!(
            "lsof: WARNING: can't lstat({}): Connection timed out|",
            fuse.display()
        ),
        "{got:?}"
    );
    // The table's limit, then the argument's.
    assert!((4000..5500).contains(&ms("args")), "{got:?}");
    assert_eq!(get(&got, "args.rc"), "1", "{got:?}");
    assert_eq!(
        get(&got, "args.err"),
        format!(
            "lsof: status error on {}/.: Connection timed out|",
            fuse.display()
        ),
        "{got:?}"
    );
    let lines: u64 = get(&got, "args.lines").parse().unwrap();
    assert!(lines > 1, "/dev/null listed nothing: {got:?}");
    // One killed helper per call that timed out, each still waiting (the
    // loader's is not counted: its command line is the loader's).
    assert_eq!(get(&got, "helpers"), "DDDDDD", "{got:?}");
    assert_eq!(get(&got, "after_teardown"), "", "the abort frees them");
}

/// A link whose `readlink` the file system never answers (its `stat`s
/// answer): the C's `Readlink()` makes that call in its child, under its
/// alarm, and so does lsof-rs, through its helper — for a path argument and
/// for a `+D` directory alike — and after it the `stat` that follows the link
/// meets the same `READLINK`. Each costs `-S`: the argument is a status
/// error, the `+D` the warning and the usage, both within twice the limit.
/// No differential case can hold this: the C hangs at its second call
/// (DIVERGENCES 118).
#[test]
#[cfg_attr(miri, ignore = "miri cannot spawn a process")]
fn a_link_that_never_reads_costs_the_limit_per_call() {
    if let Some(why) = unavailable() {
        eprintln!("skipped: {why}");
        return;
    }
    let dir = Scratch::new("fuse-readlink");
    let Some(got) = in_namespace(
        &dir,
        "--mode hold --hang-op readlink --symlink lnk=/etc",
        &format!(
            r#"run() {{
    t0=$(now)
    "$LSOF" -S 2 "$@" >/dev/null 2>'{err}'
    rc=$?
    t1=$(now)
    echo "$name.rc=$rc"
    echo "$name.ms=$(( (t1 - t0) / 1000000 ))"
    echo "$name.err=$(tr '\n' '|' < '{err}')"
}}
name=arg run "$FUSE/lnk"
name=dir run +D "$FUSE/lnk"
echo "held=$(grep -c 'READLINK.*HELD' "$LOG")"
"#,
            err = dir.0.join("err").display(),
        ),
    ) else {
        return;
    };
    let lnk = dir.0.join("fuse/lnk");
    for name in ["arg", "dir"] {
        assert_eq!(get(&got, &format!("{name}.rc")), "1", "{got:?}");
        let ms: u64 = get(&got, &format!("{name}.ms")).parse().unwrap();
        assert!((4000..5500).contains(&ms), "{name}: {got:?}");
    }
    assert_eq!(
        get(&got, "arg.err"),
        format!(
            "lsof: status error on {}: Connection timed out|",
            lnk.display()
        ),
        "{got:?}"
    );
    assert_eq!(
        get(&got, "dir.err"),
        format!(
            "lsof: WARNING: can't stat({}): Connection timed out|Try 'lsof -h' for usage.|",
            lnk.display()
        ),
        "{got:?}"
    );
    assert_eq!(get(&got, "held"), "4", "two calls each: {got:?}");
}
