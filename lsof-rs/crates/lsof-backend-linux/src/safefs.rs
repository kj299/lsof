//! The helper process that bounds lsof-rs's file-system calls on Linux: the
//! C's `doinchild()` (`lib/misc.c`), for [`lsof_core::safefs`].
//!
//! # Why a process
//!
//! A `stat` of a path on a file system that does not answer sleeps in the
//! kernel, and no signal ends a FUSE wait the daemon has read; a fatal one
//! makes it uninterruptible (measured on 6.18 with a raw-`/dev/fuse` server,
//! `differential/fuse_hang.py`). So the call cannot be bounded in lsof's own
//! process. Nor in a thread lsof gives up on: measured, a process whose
//! abandoned thread waits on such a request is not reaped after `main`
//! returns, or after `process::exit`, and its stdout never reaches EOF until
//! the FUSE connection is aborted — a `$(lsof …)` would hang anyway. A child
//! process that is killed and left unwaited does not hold lsof: lsof exits
//! at once, and the child waits in the kernel on its own until the file
//! system answers or goes away (as the C's child would).
//!
//! # How
//!
//! One helper per run, started at the first call: this binary again,
//! `/proc/self/exe` with [`HELPER_ARG`] (and, where lsof was run by naming
//! the dynamic loader, the loader's words: [`helper_args`]), which
//! `lsof-cli`'s `main` checks before anything else and hands to [`serve`]. Its stdin and stdout are
//! pipes, as the C's child's are (fds 0 and 1, FIFOs, in lsof's own
//! listing), its stderr `/dev/null`, its environment empty; its working
//! directory is lsof's, as the forked child's is, so a relative path names
//! what it names for lsof; it takes its parent's command name, so lsof lists
//! it as `lsof` too. Each call is a request on the pipe and a reply within
//! `-S` seconds. One that does not come in time gets the helper killed
//! (SIGKILL) and dropped unwaited, the call fails with `ETIMEDOUT` —
//! `Connection timed out`, the C's words — and the next call starts a fresh
//! helper. A pipe read cannot be given a timeout in std, so a thread reads
//! the replies and the call waits on a channel; a pipe read is
//! interruptible, so that thread never holds lsof's exit as a thread blocked
//! on the file system would.
//!
//! The C's child forks; this one execs, so it differs from it where lsof
//! lists itself (DIVERGENCES 123): it has a `/dev/null` on fd 2, an fd lsof
//! was started with and that is not close-on-exec is its too (std cannot
//! close it without `unsafe`), and while it waits on a call it holds the
//! `O_PATH` descriptor (or the directory) the call opened. A helper killed
//! there keeps that descriptor until the file system answers, and whoever
//! `stat`s it through `/proc/PID/fd` waits as it does; lsof-rs itself never
//! does ([`HelperFds`]).
//!
//! # The protocol
//!
//! Binary, little-endian, every length checked before anything is allocated
//! on either side. A frame is a kind byte, a `u32` length, and that many
//! bytes, at most [`MAX_FRAME`]:
//!
//! * the helper greets first: `h`, [`MAGIC`] and the [`PROTOCOL`] version;
//! * a request is `S` (stat), `L` (lstat), `R` (readlink) or `D` (read a
//!   directory), and the path's bytes, whatever they are;
//! * a reply is `s` and a stat record ([`STAT_LEN`] bytes), `l` and a link's
//!   target, or `x` and an `errno`; a directory is `n` frames of names (each
//!   a `u16` length and its bytes, never empty, nor any frame), then `e`.
//!   Names come in a frame at least every [`FLUSH_EVERY`], so the limit
//!   bounds each wait for the system, not the whole of a large directory.

use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::io::{self, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use lsof_core::safefs::{
    lost_child, name_too_long, stat_now, timed_out, FileStat, FsCalls, MAX_NAME,
    READ_DIR_MAX_BYTES, READ_DIR_MAX_NAMES,
};

/// The argument that makes this binary the helper rather than lsof. Long and
/// unlike any option, so no command line a user types means it; `main` looks
/// for it as the first argument, before it parses anything.
pub const HELPER_ARG: &str = "--lsof-rs-bounded-fs-helper";

/// The helper's greeting, so lsof knows the process on the pipe is its own.
pub const MAGIC: &[u8; 8] = b"lsofrsFS";

/// The protocol's version, in the greeting: a change to any frame changes it.
pub const PROTOCOL: u32 = 1;

/// The largest frame either side sends or accepts: a request's path, a
/// reply's payload. A path longer than this is refused before it is sent
/// (`ENAMETOOLONG`; the kernel takes 4096 bytes).
pub const MAX_FRAME: usize = 1 << 16;

/// A stat record's size on the pipe: `dev`, `ino`, `rdev`, `nlink`, `size`
/// as `u64`, then `mode`, `uid`, `gid` as `u32`.
pub const STAT_LEN: usize = 5 * 8 + 3 * 4;

/// How long the helper holds names before it sends them: the wait a `-S`
/// limit measures is for the system, never for a frame that is filling.
pub const FLUSH_EVERY: Duration = Duration::from_millis(100);

const OP_STAT: u8 = b'S';
const OP_LSTAT: u8 = b'L';
const OP_READLINK: u8 = b'R';
const OP_READ_DIR: u8 = b'D';

const R_HELLO: u8 = b'h';
const R_STAT: u8 = b's';
const R_LINK: u8 = b'l';
const R_NAMES: u8 = b'n';
const R_END: u8 = b'e';
const R_ERROR: u8 = b'x';

/// The `errno` a reply carries for an error that has none (std's own, such
/// as a path with a NUL): `EINVAL`.
const EINVAL: i32 = 22;

// ------------------------------------------------------------- the wire --

/// One frame, as [`read_frame`] reads it.
pub type Frame = (u8, Vec<u8>);

/// A frame's bytes: its kind, its length, its payload. `payload` is at most
/// [`MAX_FRAME`]: every caller checks it first.
pub fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(kind);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// One frame from `r`, if its kind is one of `kinds` and its length at most
/// [`MAX_FRAME`]; `None` at the end of the stream, on a read error, and for
/// a frame that is neither: nothing is allocated for a length past the
/// limit, and the stream is not read further.
pub fn read_frame(r: &mut impl Read, kinds: &[u8]) -> Option<Frame> {
    let mut head = [0u8; 5];
    r.read_exact(&mut head).ok()?;
    let len = u32::from_le_bytes([head[1], head[2], head[3], head[4]]) as usize;
    if !kinds.contains(&head[0]) || len > MAX_FRAME {
        return None;
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).ok()?;
    Some((head[0], payload))
}

/// The greeting's payload.
pub fn hello() -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&PROTOCOL.to_le_bytes());
    out
}

/// A stat record's bytes.
pub fn encode_stat(st: &FileStat) -> Vec<u8> {
    let mut out = Vec::with_capacity(STAT_LEN);
    for n in [st.dev, st.ino, st.rdev, st.nlink, st.size] {
        out.extend_from_slice(&n.to_le_bytes());
    }
    for n in [st.mode, st.uid, st.gid] {
        out.extend_from_slice(&n.to_le_bytes());
    }
    out
}

/// A stat record from its bytes, if there are exactly [`STAT_LEN`].
pub fn decode_stat(b: &[u8]) -> Option<FileStat> {
    if b.len() != STAT_LEN {
        return None;
    }
    let u64_at = |i: usize| {
        let mut n = [0u8; 8];
        n.copy_from_slice(&b[i * 8..i * 8 + 8]);
        u64::from_le_bytes(n)
    };
    let u32_at = |i: usize| {
        let mut n = [0u8; 4];
        n.copy_from_slice(&b[40 + i * 4..44 + i * 4]);
        u32::from_le_bytes(n)
    };
    Some(FileStat {
        dev: u64_at(0),
        ino: u64_at(1),
        rdev: u64_at(2),
        nlink: u64_at(3),
        size: u64_at(4),
        mode: u32_at(0),
        uid: u32_at(1),
        gid: u32_at(2),
    })
}

/// An error's `errno` as a reply carries it.
fn encode_error(e: &io::Error) -> Vec<u8> {
    e.raw_os_error().unwrap_or(EINVAL).to_le_bytes().to_vec()
}

/// An error from the four bytes a reply carries.
fn decode_error(b: &[u8]) -> Option<io::Error> {
    let n: [u8; 4] = b.try_into().ok()?;
    Some(io::Error::from_raw_os_error(i32::from_le_bytes(n)))
}

/// The names in an `n` frame, appended to `names`; `None` if the frame is
/// empty, a length runs past it, a name is empty or longer than
/// [`MAX_NAME`], or the listing would pass [`READ_DIR_MAX_NAMES`] names or
/// [`READ_DIR_MAX_BYTES`] bytes — none of which the helper sends. An empty
/// frame, or an empty name, would let a listing go on for ever at no cost
/// to either limit.
fn decode_names(mut b: &[u8], names: &mut Vec<OsString>, bytes: &mut usize) -> Option<()> {
    if b.is_empty() {
        return None;
    }
    while !b.is_empty() {
        let len = usize::from(u16::from_le_bytes([*b.first()?, *b.get(1)?]));
        let name = b.get(2..2 + len)?;
        if len == 0 || len > MAX_NAME || names.len() == READ_DIR_MAX_NAMES {
            return None;
        }
        *bytes += len;
        if *bytes > READ_DIR_MAX_BYTES {
            return None;
        }
        names.push(OsStr::from_bytes(name).to_os_string());
        b = &b[2 + len..];
    }
    Some(())
}

// ---------------------------------------------------------- the helper --

/// The helper's `main`: serve requests on stdin and stdout until stdin ends.
/// It refuses, and says why on stderr, unless both are pipes: that is how
/// lsof starts it, and nothing else should talk to it. Returns the exit
/// status.
pub fn serve() -> i32 {
    for fd in [0, 1] {
        let ok = std::fs::read_link(format!("/proc/self/fd/{fd}"))
            .is_ok_and(|t| t.as_os_str().as_bytes().starts_with(b"pipe:["));
        if !ok {
            eprintln!("lsof: {HELPER_ARG} is lsof-rs's own, started by lsof; not an option");
            return 2;
        }
    }
    let view = View::of_this_process();
    // The command name lsof lists, which exec set to `exe`: its parent's, as
    // the C's forked child inherits it. Cosmetic, so a failure is ignored.
    if let Some(pids) = view.pids {
        if let Ok(name) = std::fs::read(format!("/proc/{}/comm", pids.lsof)) {
            let _ = std::fs::write("/proc/self/comm", name.strip_suffix(b"\n").unwrap_or(&name));
        }
    }
    serve_on(&mut io::stdin().lock(), &mut io::stdout().lock(), &view)
}

/// The helper's pid and lsof's, as the procfs at `/proc` numbers them: what
/// `/proc/self` reads as for each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pids {
    pub helper: u32,
    pub lsof: u32,
}

/// What the helper needs to name a path as lsof would: the two pids, where
/// `/proc` has them, and the working directory it shares with lsof.
#[derive(Clone, Debug, Default)]
pub struct View {
    pub pids: Option<Pids>,
    pub cwd: Vec<u8>,
}

impl View {
    /// This process's, read once when it starts serving. Each pid is the one
    /// procfs gives, not `getpid()`'s: in a pid namespace that shares the
    /// host's `/proc` the two differ, and `/proc/<getpid()>` is someone
    /// else. Its own is what `/proc/self` reads as; lsof's is its parent's,
    /// field 4 of `/proc/self/stat`, which procfs gives in its own namespace
    /// too. `None` without a procfs that numbers both: then nothing is
    /// respelt.
    pub fn of_this_process() -> Self {
        let helper = std::fs::read_link("/proc/self")
            .ok()
            .and_then(|t| t.to_str()?.parse::<u32>().ok());
        let lsof = std::fs::read("/proc/self/stat").ok().and_then(|s| {
            // `pid (comm) state ppid ...`; a comm may hold `) `, so after the last.
            let at = s.iter().rposition(|&b| b == b')')?;
            let ppid = s[at + 1..]
                .split(|&b| b == b' ')
                .filter(|f| !f.is_empty())
                .nth(1)?;
            std::str::from_utf8(ppid).ok()?.parse::<u32>().ok()
        });
        View {
            pids: helper.zip(lsof).map(|(helper, lsof)| Pids { helper, lsof }),
            cwd: std::env::current_dir()
                .map(|d| d.into_os_string().into_vec())
                .unwrap_or_default(),
        }
    }
}

/// Whether `path` may lead through `/proc/self` or `/proc/thread-self`: a
/// component named so, or `..`, or a start in `/proc` or `/dev` (`/dev/fd`,
/// `/dev/stdin`, `/proc/net` are links there) — the working directory's
/// start, for a relative path. Read from the bytes alone, so that a path
/// that cannot costs nothing.
fn may_lead_through_self(path: &[u8], cwd: &[u8]) -> bool {
    fn parts(p: &[u8]) -> impl Iterator<Item = &[u8]> {
        p.split(|&b| b == b'/')
            .filter(|c| !c.is_empty() && *c != b".")
    }
    if parts(path).any(|c| matches!(c, b"self" | b"thread-self" | b"..")) {
        return true;
    }
    let first = if path.first() == Some(&b'/') {
        parts(path).next()
    } else {
        parts(cwd).next().or(parts(path).next())
    };
    matches!(first, Some(b"proc" | b"dev"))
}

/// Whether a link's target goes through a component named `self` or
/// `thread-self`, as `/dev/fd`'s `/proc/self/fd` does.
fn names_a_self(target: &[u8]) -> bool {
    target
        .split(|&b| b == b'/')
        .any(|c| matches!(c, b"self" | b"thread-self"))
}

/// `path` as the helper must name it to reach what lsof would reach there.
///
/// `/proc/self` and `/proc/thread-self` name whoever looks, and that must be
/// lsof, not its helper. The C's child looks for itself, so `lsof
/// /proc/self/fd/0` is a status error on the child's pipe (DIVERGENCES 89, a
/// C-DEFECT lsof-rs does not reproduce). However the path spells its way
/// there — `/proc//self`, `//proc/./self`, `/proc/self/../self`, `self`
/// from `/proc`, a link to either (`/dev/fd`, `/dev/stdin`, `/proc/net`) —
/// it is read here as `Readlink()` reads a path (`lsof_core::readlink`),
/// with two changes: a `self` or `thread-self` that reads as the helper's own
/// is replaced by lsof's pid (its main thread for the helper's), and a link
/// is replaced by its target only when that target goes through one of the
/// two; any other link is left as it stands, for the kernel to follow as it
/// would have. Putting a link's target where the link was is what the kernel
/// does with it, so nothing else about the path changes. With `whole`, the
/// path itself is read (a `stat` follows its last link, a directory is
/// listed); without, all but its last component, since `lstat` and
/// `readlink` look at a last link itself. Only a path that may lead there
/// (`may_lead_through_self`) is read; a link made elsewhere by a user into
/// `/proc/self` is followed by the helper's kernel, as the C's child follows
/// it. `None` when nothing changes.
pub fn as_lsof_names_it(path: &[u8], whole: bool, view: &View) -> Option<Vec<u8>> {
    let pids = view.pids?;
    if !may_lead_through_self(path, &view.cwd) {
        return None;
    }
    // Readlink()'s components run from a `/` to the next; the last one's
    // `/` starts it. A trailing `/` makes `lstat` follow the last link too.
    let lead_len = if whole || path.ends_with(b"/") {
        path.len()
    } else {
        path.iter().rposition(|&b| b == b'/').unwrap_or(0)
    };
    let (lead, last) = path.split_at(lead_len);
    let respelt = lsof_core::readlink::resolve_with(lead, |prefix| {
        let target = std::fs::read_link(OsStr::from_bytes(prefix))
            .ok()?
            .into_os_string()
            .into_vec();
        let lsofs = as_lsof_reads_it(prefix, target.clone(), pids);
        (lsofs != target || names_a_self(&target)).then_some(lsofs)
    })
    .ok()?;
    (respelt != lead).then(|| [respelt.as_slice(), last].concat())
}

/// The target of the link at `path`, as lsof would read it: what the
/// helper's `/proc/self` and `/proc/thread-self` read (its pid, its thread)
/// is lsof's (see [`as_lsof_names_it`]). Only those two names, and only a
/// target that is the helper's own as procfs spells it, are changed.
pub fn as_lsof_reads_it(path: &[u8], target: Vec<u8>, pids: Pids) -> Vec<u8> {
    let name = path.rsplit(|&b| b == b'/').next().unwrap_or(path);
    let (helper, lsof) = (pids.helper.to_string(), pids.lsof.to_string());
    match name {
        b"self" if target == helper.as_bytes() => lsof.into_bytes(),
        b"thread-self" if target == format!("{helper}/task/{helper}").as_bytes() => {
            format!("{lsof}/task/{lsof}").into_bytes()
        }
        _ => target,
    }
}

/// [`serve`] over any pair of streams: the greeting, then one reply (or one
/// listing) per request, each written whole and flushed. Ends at the end of
/// `input` (0), or at a malformed request or a failed write (1).
pub fn serve_on(input: &mut impl Read, output: &mut impl Write, view: &View) -> i32 {
    let send = |out: &mut dyn Write, bytes: &[u8]| out.write_all(bytes).and_then(|()| out.flush());
    if send(output, &frame(R_HELLO, &hello())).is_err() {
        return 1;
    }
    loop {
        // The end of stdin, even inside a frame, is lsof saying it is done.
        let mut head = [0u8; 5];
        match input.read_exact(&mut head) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return 0,
            Err(_) => return 1,
        }
        let op = head[0];
        let len = u32::from_le_bytes([head[1], head[2], head[3], head[4]]) as usize;
        if ![OP_STAT, OP_LSTAT, OP_READLINK, OP_READ_DIR].contains(&op) || len > MAX_FRAME {
            return 1;
        }
        let mut path = vec![0u8; len];
        if input.read_exact(&mut path).is_err() {
            return 1;
        }
        let lsofs = as_lsof_names_it(&path, matches!(op, OP_STAT | OP_READ_DIR), view);
        let path = Path::new(OsStr::from_bytes(lsofs.as_deref().unwrap_or(&path)));
        let sent = match op {
            OP_STAT | OP_LSTAT => {
                let reply = match stat_now(path, op == OP_STAT) {
                    Ok(st) => frame(R_STAT, &encode_stat(&st)),
                    Err(e) => frame(R_ERROR, &encode_error(&e)),
                };
                send(output, &reply)
            }
            OP_READLINK => {
                let reply = match std::fs::read_link(path) {
                    Ok(t) if t.as_os_str().len() <= MAX_FRAME => {
                        let t = t.into_os_string().into_vec();
                        let t = match view.pids {
                            Some(pids) => as_lsof_reads_it(path.as_os_str().as_bytes(), t, pids),
                            None => t,
                        };
                        frame(R_LINK, &t)
                    }
                    Ok(_) => frame(R_ERROR, &encode_error(&name_too_long())),
                    Err(e) => frame(R_ERROR, &encode_error(&e)),
                };
                send(output, &reply)
            }
            _ => list(path, &mut |bytes| send(output, bytes)),
        };
        if sent.is_err() {
            return 1;
        }
    }
}

/// A directory's names, sent in `n` frames and ended by `e`, or one `x` if
/// it cannot be opened: what [`lsof_core::safefs::read_dir_now`] returns,
/// in pieces, so that each wait for the system is bounded and not the whole.
fn list(path: &Path, send: &mut dyn FnMut(&[u8]) -> io::Result<()>) -> io::Result<()> {
    match std::fs::read_dir(path) {
        Ok(entries) => send_names(entries.map_while(Result::ok).map(|e| e.file_name()), send),
        Err(e) => send(&frame(R_ERROR, &encode_error(&e))),
    }
}

/// [`list`]'s frames for names as the system gives them: a frame as soon as
/// [`FLUSH_EVERY`] has passed since the last (or the frame is full), so that
/// a listing the system gives slowly reaches lsof in pieces, each within its
/// limit, and the end. A name that is empty or longer than [`MAX_NAME`] is
/// left out, as [`lsof_core::safefs::read_dir_now`] leaves it; so no frame
/// is ever empty.
fn send_names(
    names: impl Iterator<Item = OsString>,
    send: &mut dyn FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<()> {
    let mut chunk = Vec::new();
    let (mut count, mut bytes) = (0usize, 0usize);
    let mut since = Instant::now();
    for name in names {
        let name = name.as_bytes();
        if name.is_empty() || name.len() > MAX_NAME {
            continue;
        }
        if count == READ_DIR_MAX_NAMES || bytes + name.len() > READ_DIR_MAX_BYTES {
            break;
        }
        if chunk.len() + 2 + name.len() > MAX_FRAME {
            send(&frame(R_NAMES, &chunk))?;
            chunk.clear();
            since = Instant::now();
        }
        count += 1;
        bytes += name.len();
        chunk.extend_from_slice(&(name.len() as u16).to_le_bytes());
        chunk.extend_from_slice(name);
        if since.elapsed() >= FLUSH_EVERY {
            send(&frame(R_NAMES, &chunk))?;
            chunk.clear();
            since = Instant::now();
        }
    }
    if !chunk.is_empty() {
        send(&frame(R_NAMES, &chunk))?;
    }
    send(&frame(R_END, &[]))
}

// ---------------------------------------------------------- lsof's side --

/// A started helper: the child, its stdin, and the replies its reader
/// thread passes on.
struct Live {
    child: Child,
    to: ChildStdin,
    from: Receiver<Option<Frame>>,
}

/// Why an exchange failed: the time ran out, or the helper went away or said
/// something that is not a reply. Either way it is not used again.
enum Failure {
    TimedOut,
    Lost,
}

/// What a caller makes of one reply frame.
enum Step<T> {
    /// The answer.
    Done(io::Result<T>),
    /// More frames to come (a directory).
    More,
    /// Not a reply to this request.
    Bad,
}

impl Live {
    /// The next frame within `wait`.
    fn next(&self, wait: Duration) -> Result<Frame, Failure> {
        match self.from.recv_timeout(wait) {
            Ok(Some(frame)) => Ok(frame),
            Ok(None) | Err(RecvTimeoutError::Disconnected) => Err(Failure::Lost),
            Err(RecvTimeoutError::Timeout) => Err(Failure::TimedOut),
        }
    }

    /// One request, and its reply frames, each within `wait`, until `take`
    /// has its answer.
    fn exchange<T>(
        &mut self,
        op: u8,
        path: &[u8],
        wait: Duration,
        take: &mut dyn FnMut(u8, Vec<u8>) -> Step<T>,
    ) -> Result<io::Result<T>, Failure> {
        self.to
            .write_all(&frame(op, path))
            .and_then(|()| self.to.flush())
            .map_err(|_| Failure::Lost)?;
        loop {
            let (kind, payload) = self.next(wait)?;
            match take(kind, payload) {
                Step::Done(answer) => return Ok(answer),
                Step::More => continue,
                Step::Bad => return Err(Failure::Lost),
            }
        }
    }
}

/// A reader thread for a helper's stdout: every frame, then `None` at its
/// end or at anything that is not a frame. It stops once the receiver is
/// gone; until the helper's stdout closes it waits in a pipe `read`, which a
/// signal ends, so it never holds lsof's exit.
fn reader(mut from: ChildStdout) -> io::Result<Receiver<Option<Frame>>> {
    let (tx, rx) = mpsc::sync_channel(4);
    std::thread::Builder::new()
        .name("lsof-safefs".into())
        .spawn(move || loop {
            let frame = read_frame(
                &mut from,
                &[R_HELLO, R_STAT, R_LINK, R_NAMES, R_END, R_ERROR],
            );
            let last = frame.is_none();
            if tx.send(frame).is_err() || last {
                break;
            }
        })?;
    Ok(rx)
}

/// How a helper is started: the command, ready but for spawning.
pub type Launcher = Box<dyn Fn() -> Command + Send + Sync>;

/// What to do when no helper can be started: in lsof, the C's words for the
/// step that failed ([`cannot_start`]: `can't open pipes` or `can't fork`)
/// and exit 1.
pub type OnFailure = Box<dyn Fn(&io::Error) + Send + Sync>;

/// The helper's command line and surroundings, `program` with `args`: stdin
/// and stdout pipes, stderr `/dev/null`, no environment. Its working
/// directory is lsof's, as a forked child's is: a relative path is sent as
/// it was given, and names for the helper what it names for lsof. (Sending it
/// through `/proc/<lsof>/cwd` instead had needed the helper to see lsof's
/// `/proc` entry, which it may not — lsof run from a binary its user may
/// execute but not read is not dumpable, and the link is `Permission
/// denied` — and to know lsof's pid as procfs numbers it, which in a pid
/// namespace sharing the host's `/proc` it did not: it named another
/// process's directory.)
pub fn helper_command(program: impl AsRef<OsStr>, args: &[&OsStr]) -> Command {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    cmd
}

/// How this process was started: `/proc/self/cmdline`'s words, which keep a
/// dynamic loader's, and the arguments `main` was given, which do not.
fn words() -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let started = std::fs::read("/proc/self/cmdline").unwrap_or_default();
    // NUL-terminated words: the last NUL leaves an empty one behind it.
    let mut started: Vec<Vec<u8>> = started.split(|&b| b == 0).map(<[u8]>::to_vec).collect();
    started.pop();
    let given = std::env::args_os().map(OsString::into_vec).collect();
    (started, given)
}

/// Where lsof was run by naming the dynamic loader, `ld.so [ITS OPTIONS]
/// lsof ...`, as a binary on a `noexec` mount is, the loader's options:
/// `given` (`words`) ends `started` and is shorter, and what comes before
/// it, but the loader itself, is its. `None` for a program run by name.
pub fn loader_options<'a>(started: &'a [Vec<u8>], given: &[Vec<u8>]) -> Option<&'a [Vec<u8>]> {
    let cut = started.len().checked_sub(given.len())?;
    (cut > 0 && !given.is_empty() && started[cut..] == *given).then(|| &started[1..cut])
}

/// The arguments the helper is started with, after `/proc/self/exe`:
/// [`HELPER_ARG`] alone, or, run through the loader ([`loader_options`]), the
/// loader's options, the program, and [`HELPER_ARG`], since `/proc/self/exe`
/// is then the loader (measured: it refused the argument and every run ended
/// `can't fork`).
pub fn helper_args(started: &[Vec<u8>], given: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut args = Vec::new();
    if let Some(options) = loader_options(started, given) {
        args.extend(options.iter().cloned());
        args.push(given[0].clone());
    }
    args.push(HELPER_ARG.as_bytes().to_vec());
    args
}

/// The file this program was loaded from, as `(st_dev, st_ino)`, and the
/// command name a process running it has: `/proc/self/exe`'s and
/// `/proc/self/comm`'s, or, run through the loader, the program's — the file
/// at the path the loader was given, and that path's last component, cut to
/// the kernel's 15 bytes — since the loader is then this process's.
fn this_program() -> (Option<(u64, u64)>, Vec<u8>) {
    let (started, given) = words();
    let (file, name) = match loader_options(&started, &given) {
        Some(_) => {
            let path = &given[0];
            let base = path.rsplit(|&b| b == b'/').next().unwrap_or(path);
            (
                Path::new(OsStr::from_bytes(path)).to_path_buf(),
                base[..base.len().min(15)].to_vec(),
            )
        }
        None => {
            let comm = std::fs::read("/proc/self/comm").unwrap_or_default();
            let comm = comm.strip_suffix(b"\n").unwrap_or(&comm).to_vec();
            (Path::new("/proc/self/exe").to_path_buf(), comm)
        }
    };
    (identity(&file), name)
}

/// A file's `(st_dev, st_ino)`, following links: whether two names are the
/// same file.
fn identity(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|m| (m.dev(), m.ino()))
}

/// The descriptors a scan must not `stat`: those an lsof-rs helper opened
/// for a call. A helper waiting on a call holds what it opened for it — an
/// `O_PATH` descriptor on the path a `stat` was asked about (decision 3: the
/// only `stat` std makes that mounts no automount point), or the directory a
/// listing reads — and a helper killed there keeps it until the file system
/// answers. `stat`ing `/proc/PID/fd/N` follows it there and waits too:
/// measured, `lsof -S 2` beside a mount that never answers dropped the
/// mount, then hung on its own killed helper's fd 3. The C's child holds no
/// such descriptor (it calls `stat(2)` on the path).
///
/// Every descriptor a helper opens is close-on-exec, as std opens them all;
/// its pipes, its `/dev/null` and what it inherited from lsof are not (a
/// descriptor `dup2()` puts in place, or one that survived the exec, never
/// is). So a helper's close-on-exec descriptors are what a scan skips: not
/// `stat`ed, and not listed (DIVERGENCES 123).
#[derive(Clone, Debug, Default)]
pub struct HelperFds {
    pids: HashSet<u32>,
}

impl HelperFds {
    /// The helpers among `procs` (pid and command name): `own`, the ones this
    /// run started, and any other process that runs this program — its
    /// `/proc/PID/exe` the file lsof's is (`this_program`) — with
    /// [`HELPER_ARG`] for its one argument, which is a helper another run left
    /// waiting. Only a process named as lsof's program is named is asked. A
    /// program that only calls itself a helper, by its arguments, is not one:
    /// it must be this file. (A helper another run started through the
    /// loader has the loader's words too, and is not known by them.)
    pub fn among<'a>(own: &[u32], procs: impl IntoIterator<Item = (u32, &'a str)>) -> Self {
        let mut pids: HashSet<u32> = own.iter().copied().collect();
        let (mine, name) = this_program();
        for (pid, command) in procs {
            if name.is_empty() || command.as_bytes() != name || pids.contains(&pid) {
                continue;
            }
            let Ok(argv) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
                continue;
            };
            let argv: Vec<&[u8]> = argv.split(|&b| b == 0).collect();
            if argv.len() == 3
                && argv[1] == HELPER_ARG.as_bytes()
                && argv[2].is_empty()
                && mine.is_some()
                && identity(Path::new(&format!("/proc/{pid}/exe"))) == mine
            {
                pids.insert(pid);
            }
        }
        HelperFds { pids }
    }

    /// Whether `pid`'s descriptor with these open `flags` (fdinfo's, `None`
    /// where they could not be read) is one a helper opened, and so one not
    /// to `stat`. Flags that could not be read are taken to say so for any
    /// descriptor past the three a helper is started with.
    pub fn skips(&self, pid: u32, fd: u64, flags: Option<u32>) -> bool {
        self.pids.contains(&pid) && flags.map_or(fd > 2, |f| f & O_CLOEXEC != 0)
    }
}

/// `O_CLOEXEC`, as fdinfo's `flags:` shows it: `02000000`, this host's
/// `asm-generic/fcntl.h` and the libc crate's table (0.2.186) for every
/// architecture `lsof_core::safefs` knows; sparc's alone differs. Measured,
/// a helper's `O_PATH` fd shows `012000000`.
const O_CLOEXEC: u32 = 0o2_000_000;

/// The bounded calls, made by a helper process ([`FsCalls`]): lsof-cli's
/// `main` makes one per run and nothing else does — under `cargo test` this
/// binary is the test harness, which serves nothing, so every unit test uses
/// [`lsof_core::InProcess`] or a launcher of its own.
pub struct Helper {
    state: Mutex<State>,
    launch: Launcher,
    on_failure: OnFailure,
}

#[derive(Default)]
struct State {
    live: Option<Live>,
    /// Helpers killed and not yet reaped: each is waited for, without
    /// blocking, at the next call, so a long `-r` run collects them.
    killed: Vec<Child>,
}

impl State {
    /// Kill the helper and drop it unwaited — its stdin, its replies and
    /// all. Killed first: a helper still in a call must not be left to
    /// finish it, and dropping its stdin alone would not stop one that
    /// waits on a file system.
    fn abandon(&mut self) {
        if let Some(mut live) = self.live.take() {
            let _ = live.child.kill();
            self.killed.push(live.child);
        }
    }

    fn reap(&mut self) {
        self.killed
            .retain_mut(|c| !matches!(c.try_wait(), Ok(Some(_))));
    }
}

impl Helper {
    /// The helper lsof starts: `/proc/self/exe`, the running binary itself
    /// whatever has since happened to its path, with [`HELPER_ARG`]; and if
    /// none can be started, the C's words and exit 1 ([`cannot_start`]).
    ///
    /// Not the binary's path (`current_exe()`), which would have given the
    /// helper the command name `lsof` by itself: that runs whatever file is
    /// at the path when the helper starts — a removed or upgraded binary, or
    /// one put there by someone who can write the directory — where
    /// `/proc/self/exe` can only be this one. The helper takes its parent's
    /// command name instead (see [`serve`]).
    ///
    /// Run through the dynamic loader, `/proc/self/exe` is the loader, and
    /// the helper is started the way lsof was ([`helper_args`]).
    pub fn new() -> Self {
        let (started, given) = words();
        let args: Vec<OsString> = helper_args(&started, &given)
            .into_iter()
            .map(OsString::from_vec)
            .collect();
        Helper::with_launcher(
            Box::new(move || {
                let args: Vec<&OsStr> = args.iter().map(OsString::as_os_str).collect();
                helper_command("/proc/self/exe", &args)
            }),
            Box::new(|e| {
                eprintln!("lsof: {}", cannot_start(e));
                std::process::exit(1);
            }),
        )
    }

    /// A helper started by `launch`, with `on_failure` for one that cannot
    /// be: what the tests use to start a helper that misbehaves.
    pub fn with_launcher(launch: Launcher, on_failure: OnFailure) -> Self {
        Helper {
            state: Mutex::new(State::default()),
            launch,
            on_failure,
        }
    }

    /// End the run's helper: close its stdin, which it takes as the end,
    /// and reap it. It has answered every call it was asked, so it is
    /// waiting on the pipe and goes at once; one that has not within a
    /// second is killed.
    pub fn finish(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(live) = state.live.take() {
            let Live { mut child, to, .. } = live;
            drop(to);
            let began = Instant::now();
            while matches!(child.try_wait(), Ok(None)) && began.elapsed() < Duration::from_secs(1) {
                std::thread::sleep(Duration::from_millis(1));
            }
            if matches!(child.try_wait(), Ok(None)) {
                let _ = child.kill();
                state.killed.push(child);
            }
        }
        state.reap();
    }

    /// The helpers this run has started and not yet reaped: the live one,
    /// and the killed ones still waiting on a file system. A reaped one is
    /// not among them, so its pid, which another process may since have
    /// been given, is not either.
    pub fn pids(&self) -> Vec<u32> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.reap();
        state
            .live
            .iter()
            .map(|l| &l.child)
            .chain(state.killed.iter())
            .map(Child::id)
            .collect()
    }

    /// Start a helper, and take its greeting within `wait`, into `state`.
    /// One that does not greet as lsof-rs's helper of this [`PROTOCOL`] is
    /// killed, and no call is made of it.
    fn start(&self, state: &mut State, wait: Duration) -> io::Result<()> {
        let mut child = (self.launch)().spawn()?;
        let (Some(to), Some(from)) = (child.stdin.take(), child.stdout.take()) else {
            let _ = child.kill();
            state.killed.push(child);
            return Err(lost_child());
        };
        let from = match reader(from) {
            Ok(rx) => rx,
            Err(e) => {
                let _ = child.kill();
                state.killed.push(child);
                return Err(e);
            }
        };
        let live = Live { child, to, from };
        let greeting = live.next(wait);
        state.live = Some(live);
        match greeting {
            Ok((R_HELLO, payload)) if payload == hello() => Ok(()),
            failed => {
                state.abandon();
                Err(match failed {
                    Err(Failure::TimedOut) => timed_out(),
                    _ => lost_child(),
                })
            }
        }
    }

    /// One call: the request, its reply within `limit` seconds per frame,
    /// and on a timeout or a broken helper, a fresh helper next time.
    fn call<T>(
        &self,
        op: u8,
        path: &Path,
        limit: u32,
        mut take: impl FnMut(u8, Vec<u8>) -> Step<T>,
    ) -> io::Result<T> {
        let path = path.as_os_str().as_bytes();
        if path.len() > MAX_FRAME {
            return Err(name_too_long());
        }
        let wait = Duration::from_secs(u64::from(limit));
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.reap();
        if state.live.is_none() {
            if let Err(e) = self.start(&mut state, wait) {
                (self.on_failure)(&e);
                return Err(e);
            }
        }
        let Some(live) = state.live.as_mut() else {
            return Err(lost_child());
        };
        match live.exchange(op, path, wait, &mut take) {
            Ok(answer) => answer,
            Err(failure) => {
                state.abandon();
                Err(match failure {
                    Failure::TimedOut => timed_out(),
                    Failure::Lost => lost_child(),
                })
            }
        }
    }

    fn stat_call(&self, op: u8, path: &Path, limit: u32) -> io::Result<FileStat> {
        self.call(op, path, limit, |kind, payload| match kind {
            R_STAT => decode_stat(&payload).map_or(Step::Bad, |st| Step::Done(Ok(st))),
            R_ERROR => decode_error(&payload).map_or(Step::Bad, |e| Step::Done(Err(e))),
            _ => Step::Bad,
        })
    }
}

/// What lsof says when no helper can be started, in the C's words for the
/// step that failed (`lib/misc.c:302-306, 357-361`): `can't open pipes` for
/// its `pipe()`, `can't fork` for its `fork()`. std's spawn makes the pipes
/// first, and only a limit on descriptors fails there (`EMFILE`, `ENFILE`:
/// 24 and 23 in `errno-base.h` on every Linux architecture). Measured:
/// `ulimit -n 5` makes the C say `can't open pipes: Too many open files`.
pub fn cannot_start(e: &io::Error) -> String {
    let what = match e.raw_os_error() {
        Some(23 | 24) => "can't open pipes",
        _ => "can't fork",
    };
    format!("{what}: {}", lsof_core::errno_text(e))
}

impl Default for Helper {
    fn default() -> Self {
        Self::new()
    }
}

impl FsCalls for Helper {
    fn stat(&self, path: &Path, limit: u32) -> io::Result<FileStat> {
        self.stat_call(OP_STAT, path, limit)
    }

    fn lstat(&self, path: &Path, limit: u32) -> io::Result<FileStat> {
        self.stat_call(OP_LSTAT, path, limit)
    }

    fn readlink(&self, path: &Path, limit: u32) -> io::Result<OsString> {
        self.call(OP_READLINK, path, limit, |kind, payload| match kind {
            R_LINK => Step::Done(Ok(OsString::from_vec(payload))),
            R_ERROR => decode_error(&payload).map_or(Step::Bad, |e| Step::Done(Err(e))),
            _ => Step::Bad,
        })
    }

    fn helper_pids(&self) -> Vec<u32> {
        self.pids()
    }

    fn read_dir(&self, path: &Path, limit: u32) -> io::Result<Vec<OsString>> {
        let mut names = Vec::new();
        let mut bytes = 0usize;
        self.call(OP_READ_DIR, path, limit, |kind, payload| match kind {
            R_NAMES => match decode_names(&payload, &mut names, &mut bytes) {
                Some(()) => Step::More,
                None => Step::Bad,
            },
            R_END if payload.is_empty() => Step::Done(Ok(std::mem::take(&mut names))),
            R_ERROR => decode_error(&payload).map_or(Step::Bad, |e| Step::Done(Err(e))),
            _ => Step::Bad,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// A scratch directory of the test's own, removed when it goes.
    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("lsof-rs-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("a scratch directory");
            Scratch(dir)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Every reply `serve_on` wrote, the greeting first.
    fn replies(mut out: &[u8]) -> Vec<Frame> {
        let mut frames = Vec::new();
        while let Some(f) = read_frame(
            &mut out,
            &[R_HELLO, R_STAT, R_LINK, R_NAMES, R_END, R_ERROR],
        ) {
            frames.push(f);
        }
        assert!(out.is_empty(), "{} bytes left over", out.len());
        frames
    }

    /// The protocol round trip, served in-process: a path of any bytes in,
    /// the same answers [`lsof_core::safefs`]'s in-process calls give out.
    #[test]
    #[cfg_attr(miri, ignore = "it asks the host's file system, slowly under miri")]
    fn a_request_of_any_bytes_gets_the_answer_an_in_process_call_gets() {
        let dir = Scratch::new("safefs-wire");
        let base = dir.0.as_os_str().as_bytes().to_vec();
        let named = |tail: &[u8]| [base.as_slice(), tail].concat();
        // A file whose name is not UTF-8, and a link whose target is not.
        let odd = named(b"/n\xff\x1b");
        std::fs::write(OsStr::from_bytes(&odd), b"x").unwrap();
        std::os::unix::fs::symlink(
            OsStr::from_bytes(b"t\xfe"),
            OsStr::from_bytes(&named(b"/l")),
        )
        .unwrap();
        let mut input = Vec::new();
        input.extend(frame(OP_STAT, &odd));
        input.extend(frame(OP_LSTAT, &named(b"/l")));
        input.extend(frame(OP_READLINK, &named(b"/l")));
        input.extend(frame(OP_READ_DIR, &base));
        input.extend(frame(OP_STAT, &named(b"/nope")));
        input.extend(frame(OP_READ_DIR, &named(b"/nope")));
        let mut out = Vec::new();
        assert_eq!(
            serve_on(&mut input.as_slice(), &mut out, &View::of_this_process()),
            0,
            "ends at the end of its input"
        );
        let got = replies(&out);
        assert_eq!(got[0], (R_HELLO, hello()));
        let want = stat_now(Path::new(OsStr::from_bytes(&odd)), true).unwrap();
        assert_eq!(got[1], (R_STAT, encode_stat(&want)));
        assert_eq!(decode_stat(&got[1].1), Some(want));
        assert!(decode_stat(&got[2].1).unwrap().is_symlink(), "lstat");
        assert_eq!(got[3], (R_LINK, b"t\xfe".to_vec()));
        assert_eq!(got[4].0, R_NAMES);
        let (mut names, mut bytes) = (Vec::new(), 0);
        decode_names(&got[4].1, &mut names, &mut bytes).unwrap();
        names.sort();
        assert_eq!(names, [OsStr::new("l"), OsStr::from_bytes(b"n\xff\x1b")]);
        assert_eq!(got[5], (R_END, Vec::new()));
        assert_eq!(
            decode_error(&got[6].1).unwrap().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(got[7].0, R_ERROR, "a directory that cannot be opened");
        assert_eq!(got.len(), 8);
    }

    /// A request the helper does not know, or one longer than a frame, ends
    /// it: nothing is allocated for a length it will not take.
    #[test]
    fn a_malformed_request_ends_the_helper() {
        for bad in [frame(b'Q', b"/"), {
            let mut f = vec![OP_STAT];
            f.extend_from_slice(&u32::MAX.to_le_bytes());
            f
        }] {
            let mut out = Vec::new();
            assert_eq!(serve_on(&mut bad.as_slice(), &mut out, &View::default()), 1);
            assert_eq!(replies(&out), [(R_HELLO, hello())]);
        }
    }

    /// This process's pid as `/proc` numbers it, which a helper is.
    fn own_pid() -> u32 {
        std::fs::read_link("/proc/self")
            .unwrap()
            .to_str()
            .unwrap()
            .parse()
            .unwrap()
    }

    /// `/proc/self` read by the helper names lsof, as it does when lsof
    /// reads it (DIVERGENCES 89), however the path spells its way there:
    /// served, with a `sleep` standing in for lsof, and as the rule.
    #[test]
    #[cfg_attr(miri, ignore = "miri cannot read /proc links")]
    fn proc_self_is_lsof_not_its_helper() {
        let lsof = std::process::Command::new("sleep")
            .arg("30")
            .stdin(std::fs::File::open("/dev/null").unwrap())
            .spawn()
            .unwrap();
        let view = View {
            pids: Some(Pids {
                helper: own_pid(),
                lsof: lsof.id(),
            }),
            cwd: b"/".to_vec(),
        };
        let dev_fd = std::fs::read_link("/dev/fd").is_ok_and(|t| t == Path::new("/proc/self/fd"));
        let mut spellings: Vec<&[u8]> = vec![
            b"/proc/self/fd/0",
            b"/proc//self/fd/0",
            b"/proc/./self/fd/0",
            b"//proc/self/fd/0",
            b"/proc/self/../self/fd/0",
        ];
        if dev_fd {
            spellings.extend([&b"/dev/fd/0"[..], b"/dev//fd/0", b"/dev/./fd/0"]);
        }
        let mut input = Vec::new();
        for p in &spellings {
            // `Readlink()`'s reading of each, and the `stat` that follows it.
            input.extend(frame(OP_READLINK, p));
            input.extend(frame(OP_STAT, p));
        }
        input.extend(frame(OP_READLINK, b"/proc/self"));
        input.extend(frame(OP_READLINK, b"/proc//self"));
        input.extend(frame(OP_STAT, b"/proc/self"));
        input.extend(frame(OP_LSTAT, b"/proc/self"));
        let mut out = Vec::new();
        serve_on(&mut input.as_slice(), &mut out, &view);
        let got = replies(&out);
        let null = stat_now(Path::new("/dev/null"), true).unwrap();
        for (i, p) in spellings.iter().enumerate() {
            let shown = String::from_utf8_lossy(p);
            assert_eq!(
                got[1 + 2 * i],
                (R_LINK, b"/dev/null".to_vec()),
                "{shown}: lsof's fd 0, not the helper's"
            );
            assert_eq!(
                decode_stat(&got[2 + 2 * i].1).map(|st| (st.rdev, st.ino)),
                Some((null.rdev, null.ino)),
                "{shown}"
            );
        }
        let at = 1 + 2 * spellings.len();
        let pid = lsof.id().to_string().into_bytes();
        assert_eq!(got[at], (R_LINK, pid.clone()));
        assert_eq!(got[at + 1], (R_LINK, pid), "a `/proc//self` too");
        let st = decode_stat(&got[at + 2].1).unwrap();
        let want = stat_now(Path::new(&format!("/proc/{}", lsof.id())), true).unwrap();
        assert_eq!(st.ino, want.ino, "stat of /proc/self is lsof's directory");
        assert!(
            decode_stat(&got[at + 3].1).unwrap().is_symlink(),
            "lstat looks at the link itself"
        );
        let mut lsof = lsof;
        let _ = lsof.kill();
        let _ = lsof.wait();

        // The rule, with a pid that need not exist.
        let me = Pids {
            helper: own_pid(),
            lsof: 4242,
        };
        let view = View {
            pids: Some(me),
            cwd: b"/home".to_vec(),
        };
        let names = |p: &[u8], whole| as_lsof_names_it(p, whole, &view);
        assert_eq!(
            names(b"/proc/self/fd/0", false).as_deref(),
            Some(&b"/proc/4242/fd/0"[..])
        );
        assert_eq!(
            names(b"/proc//self/fd/0", true).as_deref(),
            Some(&b"/proc/4242/fd/0"[..])
        );
        assert_eq!(
            names(b"/proc/self/../self/fd", true).as_deref(),
            Some(&b"/proc/4242/../4242/fd"[..])
        );
        assert_eq!(
            names(b"/proc/self", true).as_deref(),
            Some(&b"/proc/4242"[..])
        );
        assert_eq!(names(b"/proc/self", false), None, "the link itself");
        assert_eq!(
            names(b"/proc/self/", false).as_deref(),
            Some(&b"/proc/4242/"[..]),
            "a trailing slash follows it"
        );
        if dev_fd {
            assert_eq!(
                names(b"/dev//fd/3", false).as_deref(),
                Some(&b"/proc/4242/fd/3"[..])
            );
        }
        if std::fs::read_link("/proc/net").is_ok_and(|t| t == Path::new("self/net")) {
            assert_eq!(
                names(b"/proc/net/tcp", true).as_deref(),
                Some(&b"/proc/4242/net/tcp"[..])
            );
        }
        // Read on the main thread, `thread-self` names it; on another, that one.
        let main = format!("{0}/task/{0}", me.helper);
        if std::fs::read_link("/proc/thread-self").is_ok_and(|t| t == Path::new(&main)) {
            assert_eq!(
                names(b"/proc/thread-self/fd", true).as_deref(),
                Some(&b"/proc/4242/task/4242/fd"[..])
            );
        }
        for plain in [
            &b"/etc/passwd"[..],
            b"/proc/1/cwd/x",
            b"/dev/null",
            b"rel/self",
            b"/",
            b"",
        ] {
            assert_eq!(
                names(plain, true),
                None,
                "{:?}",
                String::from_utf8_lossy(plain)
            );
        }
        assert_eq!(
            as_lsof_names_it(b"/proc/self/fd", true, &View::default()),
            None,
            "no pids, nothing respelt"
        );
        let me = Pids { helper: 7, lsof: 9 };
        assert_eq!(as_lsof_reads_it(b"/proc/self", b"7".to_vec(), me), b"9");
        assert_eq!(as_lsof_reads_it(b"/proc//self", b"7".to_vec(), me), b"9");
        assert_eq!(as_lsof_reads_it(b"self", b"7".to_vec(), me), b"9");
        assert_eq!(
            as_lsof_reads_it(b"/proc/thread-self", b"7/task/7".to_vec(), me),
            b"9/task/9"
        );
        // Another process's, another name, another target: as they are.
        assert_eq!(as_lsof_reads_it(b"/proc/self", b"8".to_vec(), me), b"8");
        assert_eq!(as_lsof_reads_it(b"/x/myself", b"7".to_vec(), me), b"7");
        assert_eq!(
            as_lsof_reads_it(b"/proc/thread-self", b"7/task/8".to_vec(), me),
            b"7/task/8"
        );
    }

    /// Only a path that may lead through `/proc/self` is read for it: one
    /// that starts in `/proc` or `/dev` (the working directory's start, for
    /// a relative one), or holds `self`, `thread-self` or `..`.
    #[test]
    fn only_a_path_that_may_lead_through_self_is_read_for_it() {
        for (path, cwd, may) in [
            (&b"/usr/lib/x"[..], &b"/"[..], false),
            (b"/proc/1/fd", b"/", true),
            (b"//dev/./fd/0", b"/", true),
            (b"fd/0", b"/dev", true),
            (b"fd/0", b"/home", false),
            (b"proc/1", b"/", true),
            (b"lib", b"/usr", false),
            (b"x/../y", b"/home", true),
            (b"/home/self", b"/", true),
            (b"thread-self", b"/", true),
            (b"/home/selfish", b"/", false),
            (b"", b"/home", false),
        ] {
            assert_eq!(
                may_lead_through_self(path, cwd),
                may,
                "{:?} from {:?}",
                String::from_utf8_lossy(path),
                String::from_utf8_lossy(cwd)
            );
        }
    }

    /// The pids are procfs's: the helper's what `/proc/self` reads as, lsof's
    /// its parent's in `/proc/self/stat`.
    #[test]
    #[cfg_attr(miri, ignore = "miri cannot read /proc")]
    fn the_pids_are_the_ones_proc_gives() {
        let view = View::of_this_process();
        let pids = view.pids.expect("a /proc that numbers this process");
        assert_eq!(pids.helper, own_pid());
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let ppid = status
            .lines()
            .find_map(|l| l.strip_prefix("PPid:"))
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap();
        assert_eq!(pids.lsof, ppid);
        assert_eq!(
            view.cwd,
            std::env::current_dir().unwrap().into_os_string().into_vec()
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "miri's strerror is not the C library's")]
    fn a_helper_that_cannot_start_is_said_in_the_cs_words() {
        assert_eq!(
            cannot_start(&io::Error::from_raw_os_error(24)),
            "can't open pipes: Too many open files"
        );
        assert_eq!(
            cannot_start(&io::Error::from_raw_os_error(11)),
            "can't fork: Resource temporarily unavailable"
        );
        assert_eq!(
            cannot_start(&lost_child()),
            "can't fork: No child processes"
        );
    }

    /// Started by name, the helper takes [`HELPER_ARG`] alone; started
    /// through the loader, the loader's options and the program come first,
    /// as lsof's own words had them.
    #[test]
    fn the_helper_is_started_the_way_lsof_was() {
        let arg = HELPER_ARG.as_bytes().to_vec();
        let words =
            |w: &[&str]| -> Vec<Vec<u8>> { w.iter().map(|s| s.as_bytes().to_vec()).collect() };
        assert_eq!(
            helper_args(&words(&["lsof", "-p", "1"]), &words(&["lsof", "-p", "1"])),
            std::slice::from_ref(&arg)
        );
        assert_eq!(
            helper_args(
                &words(&["/lib64/ld.so", "./lsof", "/dev/null"]),
                &words(&["./lsof", "/dev/null"])
            ),
            [b"./lsof".to_vec(), arg.clone()]
        );
        assert_eq!(
            helper_args(
                &words(&["/lib64/ld.so", "--library-path", "/x", "lsof", ""]),
                &words(&["lsof", ""])
            ),
            [
                b"--library-path".to_vec(),
                b"/x".to_vec(),
                b"lsof".to_vec(),
                arg.clone()
            ]
        );
        // Words that do not end as `main`'s do, or are no longer: by name.
        for (started, given) in [
            (words(&["a", "b"]), words(&["c"])),
            (words(&["a"]), words(&["a", "b"])),
            (words(&[]), words(&["lsof"])),
            (words(&["ld.so", "lsof"]), words(&[])),
        ] {
            assert_eq!(helper_args(&started, &given), std::slice::from_ref(&arg));
        }
    }

    /// A scan skips the descriptors a helper opened for a call — its
    /// close-on-exec ones — and only a helper's.
    #[test]
    #[cfg_attr(miri, ignore = "miri cannot read /proc links")]
    fn a_scan_skips_what_a_helper_opened_and_nothing_else() {
        let fds = HelperFds {
            pids: [42].into_iter().collect(),
        };
        // The pipes and `/dev/null` it was started with; an fd it inherited.
        assert!(!fds.skips(42, 0, Some(0)));
        assert!(!fds.skips(42, 1, Some(0o1)));
        assert!(!fds.skips(42, 2, Some(0o100002)));
        assert!(!fds.skips(42, 5, Some(0o100000)));
        // The `O_PATH` descriptor it holds while it waits on a `stat`, measured.
        assert!(fds.skips(42, 3, Some(0o12_000_000)));
        assert!(fds.skips(42, 4, Some(0o2_200_000)), "a directory it lists");
        // Flags it could not read: past its first three, taken as its own.
        assert!(fds.skips(42, 3, None));
        assert!(!fds.skips(42, 2, None));
        // Anyone else's: never.
        assert!(!fds.skips(41, 3, Some(0o12_000_000)));
        assert!(!HelperFds::default().skips(42, 3, None));
        // The helpers are this run's, and another run's only when they run
        // this file with the one argument: this test process is neither.
        let me = own_pid();
        let found = HelperFds::among(&[7], [(me, "lsof"), (1, "init")]);
        assert_eq!(found.pids, [7].into_iter().collect());
    }

    #[test]
    fn frames_are_checked_before_anything_is_allocated() {
        let mut huge = vec![R_STAT];
        huge.extend_from_slice(&(MAX_FRAME as u32 + 1).to_le_bytes());
        assert_eq!(read_frame(&mut huge.as_slice(), &[R_STAT]), None);
        assert_eq!(
            read_frame(&mut frame(R_LINK, b"x").as_slice(), &[R_STAT]),
            None,
            "a kind not asked for"
        );
        assert_eq!(
            read_frame(&mut &frame(R_STAT, b"abc")[..6], &[R_STAT]),
            None,
            "cut short"
        );
        assert_eq!(decode_stat(&[0; STAT_LEN - 1]), None);
        assert_eq!(decode_error(&[0; 3]).map(|e| e.kind()), None);
        let mut names = Vec::new();
        let mut bytes = 0;
        assert_eq!(
            decode_names(&[5, 0, b'a'], &mut names, &mut bytes),
            None,
            "a length past the frame"
        );
        let long = [
            &(MAX_NAME as u16 + 1).to_le_bytes()[..],
            &vec![b'a'; MAX_NAME + 1],
        ]
        .concat();
        assert_eq!(
            decode_names(&long, &mut names, &mut bytes),
            None,
            "a name past MAX_NAME"
        );
        let st = FileStat {
            dev: 1,
            ino: u64::MAX,
            rdev: 3,
            mode: 0o20_644,
            nlink: 5,
            size: 6,
            uid: 7,
            gid: u32::MAX,
        };
        assert_eq!(decode_stat(&encode_stat(&st)), Some(st));
    }

    /// A launcher for `sh -c SCRIPT`, set up as the real helper is, that
    /// counts its starts.
    fn fake(script: String, starts: &Arc<AtomicUsize>) -> Helper {
        let starts = Arc::clone(starts);
        Helper::with_launcher(
            Box::new(move || {
                starts.fetch_add(1, Ordering::SeqCst);
                helper_command("/bin/sh", &[OsStr::new("-c"), OsStr::new(&script)])
            }),
            Box::new(|_| {}),
        )
    }

    /// `printf`'s spelling of `bytes`.
    fn octal(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("\\{b:03o}")).collect()
    }

    fn greeting() -> String {
        octal(&frame(R_HELLO, &hello()))
    }

    /// `/proc/PID/stat`'s state letter, or `None` once the process is gone.
    fn state(pid: u32) -> Option<char> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        stat.rsplit(") ").next()?.chars().next()
    }

    /// Whether `pid` has been killed: a zombie not yet reaped, or gone —
    /// never still sleeping. Waits up to two seconds for the signal to land.
    fn dead(pid: u32) -> bool {
        let deadline = Instant::now() + Duration::from_secs(2);
        while state(pid).is_some_and(|s| s != 'Z') && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        matches!(state(pid), None | Some('Z'))
    }

    fn pid_in(file: &Path) -> u32 {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(pid) = std::fs::read_to_string(file)
                .ok()
                .and_then(|s| s.trim().parse().ok())
            {
                return pid;
            }
            assert!(
                Instant::now() < deadline,
                "the fake helper never wrote its pid"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// A helper that greets and never answers: the call fails with
    /// `ETIMEDOUT` within its limit (plus the margin a loaded host needs),
    /// the helper has been KILLED — dropping its pipe alone would leave this
    /// one sleeping — and the next call starts a fresh one.
    #[test]
    #[cfg_attr(miri, ignore = "miri cannot spawn a process")]
    fn a_call_that_outlives_its_limit_times_out_and_the_helper_is_replaced() {
        let dir = Scratch::new("safefs-timeout");
        let pidfile = dir.0.join("pid");
        let script = format!(
            "echo $$ > '{}'; printf '{}'; exec sleep 100",
            pidfile.display(),
            greeting()
        );
        let starts = Arc::new(AtomicUsize::new(0));
        let helper = fake(script, &starts);
        let began = Instant::now();
        let e = helper.stat(Path::new("/"), 1).unwrap_err();
        let took = began.elapsed();
        assert_eq!(e.raw_os_error(), Some(110), "{e}");
        assert_eq!(lsof_core::errno_text(&e), "Connection timed out");
        assert!(
            took >= Duration::from_secs(1) && took < Duration::from_millis(1500),
            "{took:?}"
        );
        let first = pid_in(&pidfile);
        assert!(dead(first), "the timed-out helper was left running");
        std::fs::remove_file(&pidfile).unwrap();
        assert_eq!(starts.load(Ordering::SeqCst), 1);
        let e = helper.lstat(Path::new("/"), 1).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(110));
        assert_eq!(
            starts.load(Ordering::SeqCst),
            2,
            "the next call starts a fresh helper"
        );
        let second = pid_in(&pidfile);
        assert_ne!(first, second);
        // ...and reaps the one killed before it.
        assert_eq!(state(first), None, "the killed helper was never reaped");
        assert!(dead(second), "the second timed-out helper was left running");
        helper.finish();
    }

    /// A reply that is not one — too long, of the wrong kind, a greeting of
    /// another program — is refused without being taken in: the call fails
    /// with `ECHILD`, the helper is killed, and the next call starts another.
    #[test]
    #[cfg_attr(miri, ignore = "miri cannot spawn a process")]
    fn a_reply_that_is_not_one_is_refused_and_the_helper_replaced() {
        let oversized = {
            let mut f = vec![R_STAT];
            f.extend_from_slice(&u32::MAX.to_le_bytes());
            f
        };
        for (what, reply) in [
            ("an oversized frame", oversized),
            ("a reply of another kind", frame(R_LINK, b"/x")),
            ("a stat record cut short", frame(R_STAT, &[0; STAT_LEN - 1])),
        ] {
            let script = format!("printf '{}{}'; exec sleep 100", greeting(), octal(&reply));
            let starts = Arc::new(AtomicUsize::new(0));
            let helper = fake(script, &starts);
            let began = Instant::now();
            let e = helper.stat(Path::new("/"), 5).unwrap_err();
            assert_eq!(e.raw_os_error(), Some(10), "{what}: {e}");
            assert!(
                began.elapsed() < Duration::from_secs(4),
                "{what}: waited for the limit"
            );
            helper.stat(Path::new("/"), 5).unwrap_err();
            assert_eq!(starts.load(Ordering::SeqCst), 2, "{what}");
        }
        // A greeting from another program, or another protocol: no helper,
        // and the process that gave it is killed, not left running.
        let failures = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&failures);
        let mut other = frame(R_HELLO, &hello());
        let at = 5 + MAGIC.len();
        other[at] ^= 1;
        let dir = Scratch::new("safefs-foreign");
        let pidfile = dir.0.join("pid");
        let script = format!(
            "echo $$ > '{}'; printf '{}'; exec sleep 100",
            pidfile.display(),
            octal(&other)
        );
        let helper = Helper::with_launcher(
            Box::new(move || helper_command("/bin/sh", &[OsStr::new("-c"), OsStr::new(&script)])),
            Box::new(move |_| {
                seen.fetch_add(1, Ordering::SeqCst);
            }),
        );
        assert_eq!(
            helper.stat(Path::new("/"), 5).unwrap_err().raw_os_error(),
            Some(10)
        );
        assert_eq!(failures.load(Ordering::SeqCst), 1, "can't fork");
        assert!(
            dead(pid_in(&pidfile)),
            "the foreign greeter was left running"
        );
        helper.finish();
        // One that cannot be started at all.
        let failures = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&failures);
        let helper = Helper::with_launcher(
            Box::new(|| helper_command("/nonexistent/lsof", &[])),
            Box::new(move |_| {
                seen.fetch_add(1, Ordering::SeqCst);
            }),
        );
        let e = helper.readlink(Path::new("/"), 5).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
        assert_eq!(failures.load(Ordering::SeqCst), 1);
    }

    /// A helper that never greets is waited for no longer than the limit:
    /// `ETIMEDOUT`, and the process killed.
    #[test]
    #[cfg_attr(miri, ignore = "miri cannot spawn a process")]
    fn a_helper_that_never_greets_costs_the_limit_and_is_killed() {
        let dir = Scratch::new("safefs-mute");
        let pidfile = dir.0.join("pid");
        let script = format!("echo $$ > '{}'; exec sleep 100", pidfile.display());
        let starts = Arc::new(AtomicUsize::new(0));
        let helper = fake(script, &starts);
        let began = Instant::now();
        let e = helper.stat(Path::new("/"), 1).unwrap_err();
        let took = began.elapsed();
        assert_eq!(e.raw_os_error(), Some(110), "{e}");
        assert!(
            took >= Duration::from_secs(1) && took < Duration::from_millis(1500),
            "{took:?}"
        );
        assert!(dead(pid_in(&pidfile)), "the mute helper was left running");
        helper.finish();
    }

    /// A path longer than a frame is refused before anything is started.
    #[test]
    #[cfg_attr(miri, ignore = "miri cannot spawn a process")]
    fn a_path_no_frame_can_carry_starts_no_helper() {
        let starts = Arc::new(AtomicUsize::new(0));
        let helper = fake("exit 0".into(), &starts);
        let long = OsString::from_vec(vec![b'a'; MAX_FRAME + 1]);
        let e = helper.stat(Path::new(&long), 5).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(36), "{e}");
        assert_eq!(starts.load(Ordering::SeqCst), 0);
    }

    /// A listing is bounded frame by frame: names that come slowly, each
    /// frame within the limit, are taken whole however long the listing
    /// takes; a wait longer than the limit between two frames is
    /// `ETIMEDOUT`; and an empty frame, which costs neither of a listing's
    /// limits and so could keep one going for ever, is refused.
    #[test]
    #[cfg_attr(miri, ignore = "miri cannot spawn a process")]
    fn a_listing_is_bounded_frame_by_frame() {
        let names = |n: &[&[u8]]| -> Vec<u8> {
            let mut b = Vec::new();
            for name in n {
                b.extend_from_slice(&(name.len() as u16).to_le_bytes());
                b.extend_from_slice(name);
            }
            frame(R_NAMES, &b)
        };
        let (a, b, c) = (names(&[b"a"]), names(&[b"b"]), names(&[b"c"]));
        let end = frame(R_END, &[]);
        // Each reads lsof's pipe to its end, so `finish` ends it at once.
        let script = |gap: &str| {
            format!(
                "printf '{}{}'; sleep {gap}; printf '{}'; sleep {gap}; printf '{}{}'; exec cat >/dev/null",
                greeting(),
                octal(&a),
                octal(&b),
                octal(&c),
                octal(&end)
            )
        };
        let starts = Arc::new(AtomicUsize::new(0));
        let helper = fake(script("0.6"), &starts);
        let began = Instant::now();
        let got = helper.read_dir(Path::new("/"), 1).unwrap();
        assert!(
            began.elapsed() > Duration::from_secs(1),
            "longer than the limit in all"
        );
        assert_eq!(got, ["a", "b", "c"]);
        helper.finish();
        let helper = fake(script("1.6"), &starts);
        let began = Instant::now();
        let e = helper.read_dir(Path::new("/"), 1).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(110), "{e}");
        assert!(began.elapsed() < Duration::from_millis(1500));
        helper.finish();
        let empty = format!(
            "printf '{}{}{}'; exec cat >/dev/null",
            greeting(),
            octal(&frame(R_NAMES, &[])),
            octal(&end)
        );
        let helper = fake(empty, &starts);
        let e = helper.read_dir(Path::new("/"), 5).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(10), "an empty frame: {e}");
        helper.finish();
    }

    /// The helper sends names as they come, a frame once [`FLUSH_EVERY`] has
    /// passed: a listing the system gives slowly reaches lsof in pieces,
    /// each within the limit. A name that is empty or past [`MAX_NAME`] is
    /// not sent.
    #[test]
    fn names_that_come_slowly_are_sent_as_they_come() {
        let slow = (0..5).map(|i| {
            std::thread::sleep(Duration::from_millis(60));
            OsString::from(format!("n{i}"))
        });
        let odd = [
            OsString::new(),
            OsString::from_vec(vec![b'x'; MAX_NAME + 1]),
        ];
        let mut frames = Vec::new();
        send_names(slow.chain(odd), &mut |bytes| {
            frames.push(bytes.to_vec());
            Ok(())
        })
        .unwrap();
        let frames = replies(&frames.concat());
        let (mut names, mut bytes) = (Vec::new(), 0);
        for (kind, payload) in &frames[..frames.len() - 1] {
            assert_eq!(*kind, R_NAMES);
            decode_names(payload, &mut names, &mut bytes).unwrap();
        }
        assert_eq!(frames.last(), Some(&(R_END, Vec::new())));
        assert!(frames.len() >= 3, "sent only at the end: {frames:?}");
        assert_eq!(names, ["n0", "n1", "n2", "n3", "n4"]);
    }

    /// A listing that would pass either cap, or that holds an empty name or
    /// frame, is refused, so a reply cannot make lsof hold more than a walk
    /// takes, nor keep it reading at no cost.
    #[test]
    #[cfg_attr(miri, ignore = "a million names, slowly under miri")]
    fn a_listing_past_its_caps_is_refused() {
        let one = [&1u16.to_le_bytes()[..], b"a"].concat();
        let mut bytes = 0;
        assert_eq!(decode_names(&[], &mut Vec::new(), &mut bytes), None);
        assert_eq!(decode_names(&[0, 0], &mut Vec::new(), &mut bytes), None);
        let mut names = vec![OsString::new(); READ_DIR_MAX_NAMES - 1];
        assert_eq!(decode_names(&one, &mut names, &mut bytes), Some(()));
        assert_eq!(names.len(), READ_DIR_MAX_NAMES);
        assert_eq!(
            decode_names(&one, &mut names, &mut bytes),
            None,
            "one name too many"
        );
        let mut bytes = READ_DIR_MAX_BYTES - 1;
        assert_eq!(decode_names(&one, &mut Vec::new(), &mut bytes), Some(()));
        assert_eq!(
            decode_names(&one, &mut Vec::new(), &mut bytes),
            None,
            "one byte too many"
        );
    }

    /// The helper holds its two pipes and `/dev/null`, and nothing else lsof
    /// had open — but what lsof itself was given without close-on-exec,
    /// which std cannot close (DIVERGENCES 123); its working directory is
    /// lsof's, as a forked child's is, and its environment is empty.
    #[test]
    #[cfg_attr(miri, ignore = "miri cannot spawn a process")]
    fn the_helper_holds_its_pipes_and_dev_null_and_works_where_lsof_does() {
        let dir = Scratch::new("safefs-fds");
        // Something open here that the helper must not have.
        let _held = std::fs::File::create(dir.0.join("held")).unwrap();
        let pidfile = dir.0.join("pid");
        // The shell's own environment, as it was given, before `exec`
        // (dash exports `PWD` to what it runs).
        let envfile = dir.0.join("env");
        let script = format!(
            "cat /proc/$$/environ > '{}'; echo $$ > '{}'; printf '{}'; exec sleep 100",
            envfile.display(),
            pidfile.display(),
            greeting()
        );
        let starts = Arc::new(AtomicUsize::new(0));
        let helper = fake(script, &starts);
        // Not a call: just the start, which the first call makes.
        let mut state_ = helper.state.lock().unwrap();
        helper.start(&mut state_, Duration::from_secs(5)).unwrap();
        drop(state_);
        let pid = pid_in(&pidfile);
        let deadline = Instant::now() + Duration::from_secs(5);
        while std::fs::read(format!("/proc/{pid}/comm")).ok().as_deref() != Some(b"sleep\n") {
            assert!(Instant::now() < deadline, "the fake never exec'd sleep");
            std::thread::sleep(Duration::from_millis(5));
        }
        // What this process holds without close-on-exec, from fdinfo's flags.
        let inherited: Vec<String> = std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter(|fd| fd.parse::<u32>().is_ok_and(|n| n > 2))
            .filter(|fd| {
                std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}")).is_ok_and(|info| {
                    info.lines()
                        .find_map(|l| l.strip_prefix("flags:"))
                        .and_then(|f| u32::from_str_radix(f.trim(), 8).ok())
                        .is_some_and(|f| f & 0o2_000_000 == 0)
                })
            })
            .collect();
        let mut fds: Vec<(String, String)> = std::fs::read_dir(format!("/proc/{pid}/fd"))
            .unwrap()
            .filter_map(|e| {
                let e = e.ok()?;
                let target = std::fs::read_link(e.path()).ok()?;
                Some((
                    e.file_name().into_string().ok()?,
                    target.to_string_lossy().into_owned(),
                ))
            })
            .filter(|(fd, _)| !inherited.contains(fd))
            .collect();
        fds.sort();
        assert_eq!(fds.len(), 3, "{fds:?}");
        assert!(fds[0].0 == "0" && fds[0].1.starts_with("pipe:["), "{fds:?}");
        assert!(fds[1].0 == "1" && fds[1].1.starts_with("pipe:["), "{fds:?}");
        assert_eq!(fds[2], ("2".to_string(), "/dev/null".to_string()));
        assert_eq!(
            std::fs::read_link(format!("/proc/{pid}/cwd")).unwrap(),
            std::env::current_dir().unwrap()
        );
        assert_eq!(std::fs::read(&envfile).unwrap(), b"", "an environment");
        let _ = starts;
        helper.finish();
    }

    /// At the end of the run the helper's stdin is closed and it is reaped:
    /// one that ends at that leaves nothing behind.
    #[test]
    #[cfg_attr(miri, ignore = "miri cannot spawn a process")]
    fn finish_ends_an_idle_helper_and_reaps_it() {
        let dir = Scratch::new("safefs-finish");
        let pidfile = dir.0.join("pid");
        // Greets, answers one stat with an error, then reads to the end.
        let script = format!(
            "echo $$ > '{}'; printf '{}{}'; exec cat > /dev/null",
            pidfile.display(),
            greeting(),
            octal(&frame(R_ERROR, &2i32.to_le_bytes()))
        );
        let starts = Arc::new(AtomicUsize::new(0));
        let helper = fake(script, &starts);
        let e = helper.stat(Path::new("/"), 5).unwrap_err();
        assert_eq!(
            e.kind(),
            io::ErrorKind::NotFound,
            "the helper's errno, as it sent it"
        );
        let pid = pid_in(&pidfile);
        let began = Instant::now();
        helper.finish();
        assert!(began.elapsed() < Duration::from_secs(1));
        assert_eq!(state(pid), None, "not reaped");
    }

    /// The real helper refuses to serve on anything but pipes.
    #[test]
    #[cfg_attr(miri, ignore = "miri cannot read /proc/self/fd links")]
    fn the_helper_serves_only_on_pipes() {
        // Under `cargo test` stdout is a pipe or a file and stdin is whatever
        // the runner gave, never both pipes from lsof — unless it is: then
        // this asks nothing.
        let piped = [0, 1].iter().all(|fd| {
            std::fs::read_link(format!("/proc/self/fd/{fd}"))
                .is_ok_and(|t| t.as_os_str().as_bytes().starts_with(b"pipe:["))
        });
        if !piped {
            assert_eq!(serve(), 2);
        }
    }
}
