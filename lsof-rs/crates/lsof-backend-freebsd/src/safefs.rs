//! The bounded file-system calls on FreeBSD: the C's `doinchild()`
//! (`lib/misc.c:256-470`), which makes `statsafely()`'s `stat`,
//! `lstatsafely()`'s `lstat` and `Readlink()`'s `readlink` in a child it
//! forks once and keeps, under `alarm(TmLimit)`, and kills on a timeout
//! (DIVERGENCES 144).
//!
//! The safe equivalent, with no `unsafe` and no `fork()` of a threaded
//! process: a helper that is this binary, re-executed with [`HELPER_ARG`],
//! started by the first call that needs it and kept, asked one call at a
//! time over its stdin and answering over its stdout. Each answer must come
//! within `-S` seconds; one that does not is `ETIMEDOUT`, as the C's, and
//! the helper is killed and replaced by the next call, as the C's child is.
//! A helper that is killed while the file system holds it cannot die until
//! the file system lets it go; it is not waited for (that would wait as
//! long), only told apart from the next ([`FsCalls::helper_pids`]).
//!
//! What it serves is `lsof_core`'s own in-process calls, so a bounded call
//! and an `-O` one give the same answer. The C's timeout works once a run
//! (DIVERGENCES 118); here every call is bounded, as on Linux.
//!
//! The protocol, both ways little-endian and length-prefixed, every length
//! bounded before anything is allocated for it:
//!
//! * a request is a kind byte (`s` stat, `l` lstat, `r` readlink, `d` the
//!   names in a directory), a `u32` length and the path's bytes;
//! * an answer is `0` and the result, or `1` and the `errno` as an `i32`. A
//!   stat is eight numbers; a link a `u32` length and its bytes; a listing a
//!   `u32` count and that many of the same.
//!
//! The helper writes [`HELLO`] first, and the caller reads past anything
//! before it, so what a test harness prints before the helper's code runs is
//! no answer.

use std::cell::RefCell;
use std::ffi::OsString;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::Duration;

use lsof_core::safefs::{
    lost_child, name_too_long, read_dir_now, readlink_now, stat_now, timed_out, FileStat, FsCalls,
    MAX_NAME, READ_DIR_MAX_BYTES, READ_DIR_MAX_NAMES,
};

/// The argument that makes the binary the helper: no option of lsof's, and
/// no word a user types.
pub const HELPER_ARG: &str = "--lsof-rs-freebsd-bounded-calls-helper";

/// The helper's first line: what tells its answers from anything printed
/// before it.
pub const HELLO: &[u8] = b"lsof-rs freebsd helper 1\n";

/// At most this many bytes before [`HELLO`] are read past.
const BEFORE_HELLO: usize = 64 << 10;

const STAT: u8 = b's';
const LSTAT: u8 = b'l';
const READLINK: u8 = b'r';
const READ_DIR: u8 = b'd';

/// One request, as bytes.
pub fn request(kind: u8, path: &Path) -> io::Result<Vec<u8>> {
    let p = path.as_os_str().as_bytes();
    if p.len() > MAX_NAME {
        return Err(name_too_long());
    }
    let mut out = Vec::with_capacity(5 + p.len());
    out.push(kind);
    out.extend_from_slice(
        &u32::try_from(p.len())
            .map_err(|_| name_too_long())?
            .to_le_bytes(),
    );
    out.extend_from_slice(p);
    Ok(out)
}

fn read_u32(r: &mut (impl Read + ?Sized)) -> io::Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn read_u64(r: &mut (impl Read + ?Sized)) -> io::Result<u64> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

/// `len` bytes, where `len` is at most `max`: a longer length is nonsense,
/// refused before anything is allocated for it.
fn read_bytes(r: &mut impl Read, max: usize) -> io::Result<Vec<u8>> {
    let len = usize::try_from(read_u32(r)?).map_err(|_| name_too_long())?;
    if len > max {
        return Err(name_too_long());
    }
    let mut b = vec![0u8; len];
    r.read_exact(&mut b)?;
    Ok(b)
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    // Every length sent is bounded by `MAX_NAME` first.
    out.extend_from_slice(&u32::try_from(b.len()).unwrap_or(u32::MAX).to_le_bytes());
    out.extend_from_slice(b);
}

/// What the helper answers a request with.
#[derive(Debug, PartialEq, Eq)]
pub enum Answer {
    Stat(FileStat),
    Link(OsString),
    Names(Vec<OsString>),
}

/// An answer, as bytes.
pub fn answer(result: &io::Result<Answer>) -> Vec<u8> {
    let mut out = Vec::new();
    match result {
        Err(e) => {
            out.push(1);
            out.extend_from_slice(&e.raw_os_error().unwrap_or(0).to_le_bytes());
        }
        Ok(Answer::Stat(st)) => {
            out.push(0);
            for v in [st.dev, st.ino, st.rdev, st.nlink, st.size] {
                out.extend_from_slice(&v.to_le_bytes());
            }
            for v in [st.mode, st.uid, st.gid] {
                out.extend_from_slice(&v.to_le_bytes());
            }
        }
        Ok(Answer::Link(t)) => {
            out.push(0);
            put_bytes(&mut out, t.as_bytes());
        }
        Ok(Answer::Names(names)) => {
            out.push(0);
            out.extend_from_slice(&u32::try_from(names.len()).unwrap_or(0).to_le_bytes());
            for n in names {
                put_bytes(&mut out, n.as_bytes());
            }
        }
    }
    out
}

/// Read one answer to a request of `kind`: `Err` where the bytes are not
/// one (`UnexpectedEof` where they are only not one yet), else the answer,
/// which is the call's error where the helper sent its `errno`. An `errno`
/// of 0, or a length past its bound, is no answer.
pub fn read_answer(r: &mut impl Read, kind: u8) -> io::Result<io::Result<Answer>> {
    let bad = || io::Error::new(io::ErrorKind::InvalidData, "no answer");
    let mut status = [0u8; 1];
    r.read_exact(&mut status)?;
    match status[0] {
        0 => {}
        1 => {
            let mut b = [0u8; 4];
            r.read_exact(&mut b)?;
            return match i32::from_le_bytes(b) {
                n if n > 0 => Ok(Err(io::Error::from_raw_os_error(n))),
                _ => Err(bad()),
            };
        }
        _ => return Err(bad()),
    }
    let bytes = |r: &mut dyn Read| -> io::Result<Vec<u8>> {
        let len = usize::try_from(read_u32(r)?).map_err(|_| bad())?;
        if len > MAX_NAME {
            return Err(bad());
        }
        let mut b = vec![0u8; len];
        r.read_exact(&mut b)?;
        Ok(b)
    };
    Ok(Ok(match kind {
        STAT | LSTAT => {
            let mut n = [0u64; 5];
            for v in &mut n {
                *v = read_u64(r)?;
            }
            let mut m = [0u32; 3];
            for v in &mut m {
                *v = read_u32(r)?;
            }
            Answer::Stat(FileStat {
                dev: n[0],
                ino: n[1],
                rdev: n[2],
                nlink: n[3],
                size: n[4],
                mode: m[0],
                uid: m[1],
                gid: m[2],
            })
        }
        READLINK => Answer::Link(OsString::from_vec(bytes(r)?)),
        READ_DIR => {
            let count = usize::try_from(read_u32(r)?).map_err(|_| bad())?;
            if count > READ_DIR_MAX_NAMES {
                return Err(bad());
            }
            let mut names = Vec::new();
            let mut total = 0usize;
            for _ in 0..count {
                let n = bytes(r)?;
                total = total.saturating_add(n.len());
                if total > READ_DIR_MAX_BYTES {
                    return Err(bad());
                }
                names.push(OsString::from_vec(n));
            }
            Answer::Names(names)
        }
        _ => return Err(bad()),
    }))
}

/// Serve requests from `input`, answering on `output`, until `input` ends or
/// says something that is no request. The helper's whole life.
pub fn serve_on(input: &mut impl Read, output: &mut impl Write) -> i32 {
    if output
        .write_all(HELLO)
        .and_then(|()| output.flush())
        .is_err()
    {
        return 1;
    }
    loop {
        let mut kind = [0u8; 1];
        if input.read_exact(&mut kind).is_err() {
            return 0;
        }
        let Ok(path) = read_bytes(input, MAX_NAME) else {
            return 1;
        };
        let path = PathBuf::from(OsString::from_vec(path));
        let result = match kind[0] {
            STAT => stat_now(&path, true).map(Answer::Stat),
            LSTAT => stat_now(&path, false).map(Answer::Stat),
            READLINK => readlink_now(&path).map(Answer::Link),
            READ_DIR => read_dir_now(&path).map(Answer::Names),
            _ => return 1,
        };
        if output
            .write_all(&answer(&result))
            .and_then(|()| output.flush())
            .is_err()
        {
            return 1;
        }
    }
}

/// The helper: serve stdin and stdout.
pub fn serve() -> i32 {
    serve_on(&mut io::stdin().lock(), &mut io::stdout().lock())
}

/// A helper that is running: where to ask, where its answers come.
struct Running {
    child: Child,
    stdin: ChildStdin,
    answers: Receiver<Vec<u8>>,
}

/// What the run's helpers are: the one asked now, and those killed.
#[derive(Default)]
struct State {
    running: Option<Running>,
    killed: Vec<Child>,
    /// The helper could not be started: told once, then every call fails.
    note: Option<String>,
}

/// The bounded calls, through a helper started from `program` and `args`.
pub struct Helper {
    program: PathBuf,
    args: Vec<OsString>,
    /// Set in the helper's environment, beside what it inherits.
    env: Vec<(OsString, OsString)>,
    /// Whether a helper that cannot be started ends the run, as the C's
    /// failed `pipe()` or `fork()` does; else every call fails, and that is
    /// told once.
    fatal: bool,
    state: RefCell<State>,
}

impl Helper {
    /// The helper this binary is: itself, with [`HELPER_ARG`].
    pub fn new() -> Self {
        let program = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("lsof"));
        let mut h = Helper::with_command(program, vec![HELPER_ARG.into()]);
        h.fatal = true;
        h
    }

    /// A helper started as `program args…`.
    pub fn with_command(program: PathBuf, args: Vec<OsString>) -> Self {
        Helper {
            program,
            args,
            env: Vec::new(),
            fatal: false,
            state: RefCell::new(State::default()),
        }
    }

    /// The same, with `key` set to `value` in the helper's environment.
    #[cfg(test)]
    fn with_env(mut self, key: &str, value: &str) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    fn start(&self) -> io::Result<Running> {
        let mut child = Command::new(&self.program)
            .args(&self.args)
            .envs(self.env.iter().map(|(k, v)| (k, v)))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            let _ = child.kill();
            return Err(lost_child());
        };
        let (tx, answers) = mpsc::channel();
        // The reader: past what comes before `HELLO`, then each answer's
        // bytes as they come, until the helper's stdout ends. It owns the
        // pipe, so a helper the file system holds holds only it.
        std::thread::spawn(move || {
            let mut r = BufReader::new(stdout);
            if !skip_to_hello(&mut r) {
                return;
            }
            loop {
                let buf = match r.fill_buf() {
                    Ok([]) | Err(_) => return,
                    Ok(b) => b.to_vec(),
                };
                r.consume(buf.len());
                if tx.send(buf).is_err() {
                    return;
                }
            }
        });
        Ok(Running {
            child,
            stdin,
            answers,
        })
    }

    /// One call, given `limit` seconds.
    fn call(&self, kind: u8, path: &Path, limit: u32) -> io::Result<Answer> {
        let req = request(kind, path)?;
        let mut state = self.state.borrow_mut();
        if state.note.is_some() {
            return Err(lost_child());
        }
        if state.running.is_none() {
            match self.start() {
                Ok(r) => state.running = Some(r),
                Err(e) => {
                    let line = format!("lsof: {}", cannot_start(&e));
                    if self.fatal {
                        // The C's `Error()`: stdout flushed, then 1.
                        lsof_core::safefs::to_stderr(&line);
                        lsof_core::safefs::exit(1);
                    }
                    state.note = Some(line);
                    return Err(lost_child());
                }
            }
        }
        let Some(run) = state.running.as_mut() else {
            return Err(lost_child());
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(u64::from(limit.max(1)));
        let mut got = Vec::new();
        // `Ok` is what the helper answered (an error among them); `Err` that
        // it did not answer, in time or at all.
        let outcome: Result<io::Result<Answer>, io::Error> = if run
            .stdin
            .write_all(&req)
            .and_then(|()| run.stdin.flush())
            .is_err()
        {
            Err(lost_child())
        } else {
            loop {
                match read_answer(&mut io::Cursor::new(&got[..]), kind) {
                    Ok(a) => break Ok(a),
                    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {}
                    Err(_) => break Err(lost_child()),
                }
                let left = deadline.saturating_duration_since(std::time::Instant::now());
                match run.answers.recv_timeout(left) {
                    Ok(b) => got.extend_from_slice(&b),
                    Err(RecvTimeoutError::Timeout) => break Err(timed_out()),
                    Err(RecvTimeoutError::Disconnected) => break Err(lost_child()),
                }
            }
        };
        if outcome.is_err() {
            // Timed out or lost: this helper is done with, and the next call
            // starts another, as the C's `childx()` and next `fork()` do.
            if let Some(mut r) = state.running.take() {
                let _ = r.child.kill();
                state.killed.push(r.child);
            }
        }
        state
            .killed
            .retain_mut(|c| matches!(c.try_wait(), Ok(None)));
        outcome.and_then(|a| a)
    }
}

/// What lsof says when no helper can be started, in the C's words for the
/// step that failed (`lib/misc.c:302-306, 357-361`): `can't open pipes` where
/// a limit on descriptors stopped it (`EMFILE`, `ENFILE`: 24 and 23 in
/// FreeBSD's `sys/errno.h`), else `can't fork`.
pub fn cannot_start(e: &io::Error) -> String {
    let what = match e.raw_os_error() {
        Some(23 | 24) => "can't open pipes",
        _ => "can't fork",
    };
    format!("{what}: {}", lsof_core::backend::errno_text(e))
}

impl Default for Helper {
    fn default() -> Self {
        Self::new()
    }
}

/// Read past what comes before [`HELLO`], at most [`BEFORE_HELLO`] bytes of
/// it; `false` where it never came.
fn skip_to_hello(r: &mut impl BufRead) -> bool {
    let mut line = Vec::new();
    let mut read = 0usize;
    while read <= BEFORE_HELLO {
        line.clear();
        match r
            .by_ref()
            .take(BEFORE_HELLO as u64 + 1)
            .read_until(b'\n', &mut line)
        {
            Ok(0) | Err(_) => return false,
            Ok(n) => read += n,
        }
        if line.ends_with(HELLO) {
            return true;
        }
    }
    false
}

impl FsCalls for Helper {
    fn stat(&self, path: &Path, limit: u32) -> io::Result<FileStat> {
        match self.call(STAT, path, limit)? {
            Answer::Stat(st) => Ok(st),
            _ => Err(lost_child()),
        }
    }

    fn lstat(&self, path: &Path, limit: u32) -> io::Result<FileStat> {
        match self.call(LSTAT, path, limit)? {
            Answer::Stat(st) => Ok(st),
            _ => Err(lost_child()),
        }
    }

    fn readlink(&self, path: &Path, limit: u32) -> io::Result<OsString> {
        match self.call(READLINK, path, limit)? {
            Answer::Link(t) => Ok(t),
            _ => Err(lost_child()),
        }
    }

    fn read_dir(&self, path: &Path, limit: u32) -> io::Result<Vec<OsString>> {
        match self.call(READ_DIR, path, limit)? {
            Answer::Names(n) => Ok(n),
            _ => Err(lost_child()),
        }
    }

    fn helper_pids(&self) -> Vec<u32> {
        let mut state = self.state.borrow_mut();
        state
            .killed
            .retain_mut(|c| matches!(c.try_wait(), Ok(None)));
        state
            .running
            .iter()
            .map(|r| r.child.id())
            .chain(state.killed.iter().map(Child::id))
            .collect()
    }

    fn note(&self) -> Option<String> {
        self.state.borrow_mut().note.take()
    }
}

impl Drop for Helper {
    /// The helper is idle; closing its stdin ends it, and it is reaped.
    fn drop(&mut self) {
        let state = self.state.get_mut();
        if let Some(r) = state.running.take() {
            drop(r.stdin);
            let mut child = r.child;
            let _ = child.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn served(requests: &[Vec<u8>]) -> Vec<u8> {
        let input: Vec<u8> = requests.concat();
        let mut out = Vec::new();
        assert_eq!(serve_on(&mut &input[..], &mut out), 0);
        assert!(out.starts_with(HELLO));
        out.split_off(HELLO.len())
    }

    #[test]
    #[cfg_attr(miri, ignore = "stats the real file system")]
    fn each_call_is_answered_as_it_is_made_in_process() {
        let dir = std::env::temp_dir().join(format!("lsof-rs-fb-safefs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("f"), b"abc").unwrap();
        std::os::unix::fs::symlink("f", dir.join("l")).unwrap();
        let out = served(&[
            request(STAT, &dir.join("l")).unwrap(),
            request(LSTAT, &dir.join("l")).unwrap(),
            request(READLINK, &dir.join("l")).unwrap(),
            request(READ_DIR, &dir).unwrap(),
            request(STAT, &dir.join("missing")).unwrap(),
        ]);
        let mut r = &out[..];
        let st = read_answer(&mut r, STAT).unwrap().unwrap();
        assert_eq!(st, Answer::Stat(stat_now(&dir.join("f"), true).unwrap()));
        let lst = read_answer(&mut r, LSTAT).unwrap().unwrap();
        assert_eq!(lst, Answer::Stat(stat_now(&dir.join("l"), false).unwrap()));
        assert_eq!(
            read_answer(&mut r, READLINK).unwrap().unwrap(),
            Answer::Link("f".into())
        );
        let Answer::Names(mut names) = read_answer(&mut r, READ_DIR).unwrap().unwrap() else {
            panic!("a listing");
        };
        names.sort();
        assert_eq!(names, ["f", "l"]);
        let gone = read_answer(&mut r, STAT).unwrap().unwrap_err();
        assert_eq!(gone.kind(), io::ErrorKind::NotFound);
        assert!(r.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_answer_cut_short_or_out_of_bounds_is_none() {
        let st = answer(&Ok(Answer::Stat(FileStat::default())));
        for n in 0..st.len() {
            let e = read_answer(&mut &st[..n], STAT).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof, "{n} bytes");
        }
        // A link longer than any path, a listing of more names than any
        // listing holds, an errno of 0, an unknown status.
        let mut long = vec![0u8];
        long.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            read_answer(&mut &long[..], READLINK).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            read_answer(&mut &long[..], READ_DIR).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        // One byte past the longest name is refused as such, not read for.
        let mut just = vec![0u8];
        just.extend_from_slice(&(MAX_NAME as u32 + 1).to_le_bytes());
        assert_eq!(
            read_answer(&mut &just[..], READLINK).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        for bad in [&[1u8, 0, 0, 0, 0][..], &[7u8]] {
            assert_eq!(
                read_answer(&mut &bad[..], STAT).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
        // An errno is the call's error.
        let e = answer(&Err(io::Error::from_raw_os_error(13)));
        let got = read_answer(&mut &e[..], STAT).unwrap().unwrap_err();
        assert_eq!(got.raw_os_error(), Some(13));
        // A request for a path no call takes, and one the helper refuses.
        let p = PathBuf::from(OsString::from_vec(vec![b'a'; MAX_NAME + 1]));
        assert!(request(STAT, &p).is_err());
        let mut out = Vec::new();
        assert_eq!(serve_on(&mut &b"x\x00\x00\x00\x00"[..], &mut out), 1);
        assert_eq!(serve_on(&mut &b"s\xff\xff\xff\xff"[..], &mut Vec::new()), 1);
    }

    #[test]
    fn what_comes_before_hello_is_read_past_and_no_hello_is_none() {
        let mut r = io::Cursor::new([&b"running 1 test\n"[..], HELLO, b"rest"].concat());
        assert!(skip_to_hello(&mut r));
        let mut rest = String::new();
        r.read_to_string(&mut rest).unwrap();
        assert_eq!(rest, "rest");
        assert!(!skip_to_hello(&mut io::Cursor::new(b"nothing\n".to_vec())));
        assert!(!skip_to_hello(&mut io::Cursor::new(vec![
            b'x';
            BEFORE_HELLO + 10
        ])));
    }

    /// A helper that never answers: the call is `ETIMEDOUT` after its limit,
    /// the helper is killed and listed until it is gone, and the next call
    /// starts another. One that ends at once: `ECHILD`.
    #[test]
    #[cfg_attr(miri, ignore = "starts processes")]
    fn a_helper_that_does_not_answer_times_out_and_is_replaced() {
        let h = Helper::with_command("sleep".into(), vec!["30".into()]);
        let e = h.stat(Path::new("/"), 1).unwrap_err();
        assert!(lsof_core::safefs::is_timed_out(&e), "{e}");
        assert!(h.state.borrow().running.is_none());
        let e = h.lstat(Path::new("/"), 1).unwrap_err();
        assert!(lsof_core::safefs::is_timed_out(&e));
        // Both killed; reaped once they are gone.
        for _ in 0..200 {
            if h.helper_pids().is_empty() {
                break;
            }
            std::thread::yield_now();
        }
        let gone = Helper::with_command("true".into(), Vec::new());
        assert_eq!(
            gone.readlink(Path::new("/"), 5).unwrap_err().raw_os_error(),
            lost_child().raw_os_error()
        );
        let none = Helper::with_command("/nonexistent/lsof-rs-helper".into(), Vec::new());
        assert!(none.read_dir(Path::new("/"), 5).is_err());
        assert!(none
            .note()
            .is_some_and(|n| n.starts_with("lsof: can't fork: ")));
        assert!(cannot_start(&io::Error::from_raw_os_error(24)).starts_with("can't open pipes: "));
        assert!(none.note().is_none(), "told once");
    }

    /// The whole round trip through a real helper process: this test binary,
    /// run as the helper by `helper_entry` below.
    #[test]
    #[cfg_attr(miri, ignore = "starts processes")]
    fn a_real_helper_answers_each_call() {
        let exe = std::env::current_exe().unwrap();
        let h = Helper::with_command(
            exe,
            vec![
                "--exact".into(),
                "safefs::tests::helper_entry".into(),
                "--nocapture".into(),
                "--test-threads=1".into(),
                "--include-ignored".into(),
            ],
        )
        // The entry serves only where it is asked to.
        .with_env("LSOF_RS_FB_HELPER_TEST", "1");
        let root = h.stat(Path::new("/"), 30).unwrap();
        assert_eq!(root, stat_now(Path::new("/"), true).unwrap());
        let e = h.stat(Path::new("/lsof-rs-no-such-path"), 30).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
        assert!(h.read_dir(Path::new("/"), 30).unwrap().len() > 1);
        assert_eq!(h.helper_pids().len(), 1, "one helper, kept");
    }

    #[test]
    #[ignore = "the helper of a_real_helper_answers_each_call"]
    fn helper_entry() {
        if std::env::var_os("LSOF_RS_FB_HELPER_TEST").is_some() {
            std::process::exit(serve());
        }
    }
}
