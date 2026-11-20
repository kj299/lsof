//! The bounded file-system calls on FreeBSD: the C's `doinchild()`
//! (`lib/misc.c:256-470`), which makes `statsafely()`'s `stat`,
//! `lstatsafely()`'s `lstat` and `Readlink()`'s `readlink` in a child it
//! forks once and keeps, under `alarm(TmLimit)`, and kills on a timeout
//! (DIVERGENCES 144).
//!
//! The safe equivalent, with no `fork()` of a threaded process, built as
//! the Linux helper is (`lsof-backend-linux`'s `safefs`): a helper that is
//! this binary, re-executed with [`HELPER_ARG`], started by the first call
//! that needs it and kept, asked one call at a time over its stdin and
//! answering over its stdout. Each wait for the system must end within `-S`
//! seconds; one that does not is `ETIMEDOUT` (`Operation timed out`, as the
//! C's), and the helper is killed and replaced by the next call, as the C's
//! child is. A helper that is killed while the file system holds it cannot
//! die until the file system lets it go; it is not waited for (that would
//! wait as long), only told apart from the next ([`FsCalls::helper_pids`]),
//! and at most [`MAX_WAITING`] of them may wait at once.
//!
//! What it serves is `lsof_core`'s own in-process calls, so a bounded call
//! and an `-O` one give the same answer. The C's timeout works once a run
//! (DIVERGENCES 118); here every call is bounded, as on Linux.
//!
//! # The helper
//!
//! The executable lsof is running, by the path the kernel gives for it
//! (`current_exe()`), with nothing else to fall back on: a run whose path
//! cannot be found starts no helper and ends `can't fork`, as one whose
//! `fork()` fails. Its environment is empty, its stdin and stdout pipes
//! (it refuses to serve unless both are: [`serve`]), its stderr `/dev/null`,
//! and it closes every other descriptor it was given (`closefrom(3)`; the
//! C's child closes from 2, `closefrom_shim(ctx, 2)` at `lib/misc.c:345`, so
//! it has no stderr where this one has `/dev/null`, as the Linux helper
//! does: DIVERGENCES 123). It greets with the build it is
//! ([`token`]), and a greeting that is not this build's is refused: the
//! helper is killed, and the run ends `can't fork`.
//!
//! # The protocol
//!
//! Binary, little-endian, every length checked before anything is allocated
//! on either side. After one line, [`HELLO`] (what a test harness prints
//! before it is read past), each message is a frame: a kind byte, a `u32`
//! length, and that many bytes, at most [`MAX_FRAME`]:
//!
//! * the helper greets first: `h` and [`hello`]'s payload;
//! * a request is `S` (stat), `L` (lstat), `R` (readlink) or `D` (list a
//!   directory) and the path's bytes, at most [`MAX_NAME`];
//! * a reply is `s` and a stat record ([`STAT_LEN`] bytes), `l` and a link's
//!   target (at most [`MAX_NAME`]), or `x` and an `errno` (an error with
//!   none is sent as `EINVAL`); a directory is `n` frames of names (each a
//!   `u16` length and its bytes, never empty, nor any frame), then `e`.
//!   Names come in a frame at least every [`FLUSH_EVERY`], so the limit
//!   bounds each wait for the system, not the whole of a large directory.
//!
//! Every frame is taken exactly as its kind says (a stat record of
//! [`STAT_LEN`] bytes, an `errno` of four, an empty `e`), and a frame that
//! is waiting before a request is sent is no answer to it: the helper that
//! sent it is replaced.

use std::cell::RefCell;
use std::ffi::{OsStr, OsString};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, TryRecvError};
use std::time::{Duration, Instant};

use lsof_core::safefs::{
    lost_child, name_too_long, readlink_now, stat_now, timed_out, would_block, FileStat, FsCalls,
    MAX_NAME, READ_DIR_MAX_BYTES, READ_DIR_MAX_NAMES,
};

/// The argument that makes the binary the helper: no option of lsof's, and
/// no word a user types.
pub const HELPER_ARG: &str = "--lsof-rs-freebsd-bounded-calls-helper";

/// The helper's first line: what tells its frames from anything printed
/// before it.
pub const HELLO: &[u8] = b"lsof-rs freebsd helper 2\n";

/// The greeting's first bytes, so lsof knows the process on the pipe is its
/// own.
pub const MAGIC: &[u8; 8] = b"lsofrsFB";

/// The protocol's version, in the greeting: a change to any frame changes it.
pub const PROTOCOL: u32 = 2;

/// At most this many killed helpers may still be waiting, unreaped, on file
/// systems that do not answer before lsof starts no more: each holds a pipe
/// and a reader thread of lsof's until its call ends. Past the cap each
/// call fails at once with `EAGAIN` (`Resource temporarily unavailable`),
/// and one warning says why ([`FsCalls::note`]); once one of them is
/// reaped, calls are made again. Linux's cap, for Linux's reasons.
pub const MAX_WAITING: usize = 16;

/// The largest frame either side sends or accepts.
pub const MAX_FRAME: usize = 1 << 16;

/// A stat record's size on the pipe: `dev`, `ino`, `rdev`, `nlink`, `size`
/// as `u64`, then `mode`, `uid`, `gid` as `u32`.
pub const STAT_LEN: usize = 5 * 8 + 3 * 4;

/// How long the helper holds names before it sends them: the wait a `-S`
/// limit measures is for the system, never for a frame that is filling.
pub const FLUSH_EVERY: Duration = Duration::from_millis(100);

/// At most this many bytes before [`HELLO`] are read past.
const BEFORE_HELLO: usize = 64 << 10;

/// How many frames the reader thread may hold that lsof has not taken: what
/// a helper can make lsof hold between two calls.
const QUEUED: usize = 4;

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

const REPLIES: [u8; 6] = [R_HELLO, R_STAT, R_LINK, R_NAMES, R_END, R_ERROR];

/// The `errno` a reply carries for an error that has none (std's own, such
/// as a path with a NUL): `EINVAL`, 22 in FreeBSD's `sys/errno.h` as in
/// Linux's.
const EINVAL: i32 = 22;

// ------------------------------------------------------------- the wire --

/// One frame, as [`read_frame`] reads it.
pub type Frame = (u8, Vec<u8>);

/// A frame's bytes: its kind, its length, its payload. `payload` is at most
/// [`MAX_FRAME`]: every caller bounds it first.
pub fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(kind);
    out.extend_from_slice(
        &u32::try_from(payload.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
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
    let len = usize::try_from(u32::from_le_bytes([head[1], head[2], head[3], head[4]])).ok()?;
    if !kinds.contains(&head[0]) || len > MAX_FRAME {
        return None;
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).ok()?;
    Some((head[0], payload))
}

/// The build a helper is, as its greeting carries it: lsof-rs's version and
/// the identity of the executable at `exe` — its `(st_dev, st_ino)`, size
/// and modification time — so that a binary put at lsof's path since lsof
/// started (an upgrade, or someone who can write the directory) is not
/// taken for lsof's own helper. Not a hash of the code: two builds of the
/// same version written to the same file with the same size and time would
/// pass, which no installation does.
pub fn token(exe: &Path) -> io::Result<Vec<u8>> {
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::metadata(exe)?;
    let mut out = env!("CARGO_PKG_VERSION").as_bytes().to_vec();
    out.push(0);
    for n in [md.dev(), md.ino(), md.size()] {
        out.extend_from_slice(&n.to_le_bytes());
    }
    for n in [md.mtime(), md.mtime_nsec()] {
        out.extend_from_slice(&n.to_le_bytes());
    }
    Ok(out)
}

/// The greeting's payload: [`MAGIC`], [`PROTOCOL`], and the build's
/// [`token`].
pub fn hello(token: &[u8]) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&PROTOCOL.to_le_bytes());
    out.extend_from_slice(token);
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

/// An error's `errno` as a reply carries it; `EINVAL` for one with none.
pub fn encode_error(e: &io::Error) -> Vec<u8> {
    e.raw_os_error()
        .filter(|&n| n > 0)
        .unwrap_or(EINVAL)
        .to_le_bytes()
        .to_vec()
}

/// An error from the four bytes a reply carries; `None` for any other
/// length, or an `errno` no error has (0 or less), which the helper never
/// sends.
pub fn decode_error(b: &[u8]) -> Option<io::Error> {
    let n: [u8; 4] = b.try_into().ok()?;
    let n = i32::from_le_bytes(n);
    (n > 0).then(|| io::Error::from_raw_os_error(n))
}

/// The names in an `n` frame, appended to `names`; `None` if the frame is
/// empty, a length runs past it, a name is empty or longer than
/// [`MAX_NAME`], or the listing would pass [`READ_DIR_MAX_NAMES`] names or
/// [`READ_DIR_MAX_BYTES`] bytes — none of which the helper sends. Each frame
/// is read once, as it comes: a listing costs what its bytes do.
pub fn decode_names(mut b: &[u8], names: &mut Vec<OsString>, bytes: &mut usize) -> Option<()> {
    if b.is_empty() {
        return None;
    }
    while !b.is_empty() {
        let len = usize::from(u16::from_le_bytes([*b.first()?, *b.get(1)?]));
        let name = b.get(2..2 + len)?;
        if len == 0 || len > MAX_NAME || names.len() >= READ_DIR_MAX_NAMES {
            return None;
        }
        *bytes = bytes.checked_add(len)?;
        if *bytes > READ_DIR_MAX_BYTES {
            return None;
        }
        names.push(OsStr::from_bytes(name).to_os_string());
        b = &b[2 + len..];
    }
    Some(())
}

// ---------------------------------------------------------- the helper --

/// Whether `fd` is a pipe (a FIFO, as FreeBSD's `fstat` shows a pipe), asked
/// of a duplicate of it that is closed again: std's own calls.
pub fn is_pipe(fd: BorrowedFd<'_>) -> bool {
    use std::os::unix::fs::FileTypeExt;
    fd.try_clone_to_owned()
        .map(std::fs::File::from)
        .and_then(|f| f.metadata())
        .is_ok_and(|m| m.file_type().is_fifo())
}

/// What the helper says when it is run by hand: the Linux helper's words.
pub fn not_an_option() -> String {
    format!("lsof: {HELPER_ARG} is lsof-rs's own, started by lsof; not an option")
}

/// The helper's `main`: serve requests on stdin and stdout until stdin
/// ends. It refuses, and says why on stderr, unless both are pipes: that is
/// how lsof starts it, and nothing else should talk to it. Then, as the C's
/// child does (`closefrom_shim()`, `lib/misc.c:345`), it closes every
/// descriptor past stderr it was given, which an exec keeps where lsof's
/// own were not close-on-exec. Returns the exit status.
pub fn serve() -> i32 {
    if !is_pipe(io::stdin().as_fd()) || !is_pipe(io::stdout().as_fd()) {
        lsof_core::safefs::to_stderr(&not_an_option());
        return 2;
    }
    #[cfg(target_os = "freebsd")]
    crate::sys::close_from(3);
    let token = std::env::current_exe()
        .and_then(|exe| token(&exe))
        .unwrap_or_default();
    serve_on(&mut io::stdin().lock(), &mut io::stdout().lock(), &token)
}

/// [`serve`] over any pair of streams: [`HELLO`] and the greeting, then one
/// reply (or one listing) per request, each written whole and flushed. Ends
/// at the end of `input` (0), or at a malformed request or a failed write
/// (1).
pub fn serve_on(input: &mut impl Read, output: &mut impl Write, token: &[u8]) -> i32 {
    let send = |out: &mut dyn Write, bytes: &[u8]| out.write_all(bytes).and_then(|()| out.flush());
    let greeting = [HELLO, &frame(R_HELLO, &hello(token))].concat();
    if send(output, &greeting).is_err() {
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
        let Ok(len) = usize::try_from(u32::from_le_bytes([head[1], head[2], head[3], head[4]]))
        else {
            return 1;
        };
        if ![OP_STAT, OP_LSTAT, OP_READLINK, OP_READ_DIR].contains(&op) || len > MAX_NAME {
            return 1;
        }
        let mut path = vec![0u8; len];
        if input.read_exact(&mut path).is_err() {
            return 1;
        }
        let path = PathBuf::from(OsString::from_vec(path));
        let sent = match op {
            OP_STAT | OP_LSTAT => {
                let reply = match stat_now(&path, op == OP_STAT) {
                    Ok(st) => frame(R_STAT, &encode_stat(&st)),
                    Err(e) => frame(R_ERROR, &encode_error(&e)),
                };
                send(output, &reply)
            }
            OP_READLINK => {
                let reply = match readlink_now(&path) {
                    // Bounded as every length on the pipe is.
                    Ok(t) if t.len() <= MAX_NAME => frame(R_LINK, t.as_bytes()),
                    Ok(_) => frame(R_ERROR, &encode_error(&name_too_long())),
                    Err(e) => frame(R_ERROR, &encode_error(&e)),
                };
                send(output, &reply)
            }
            _ => match std::fs::read_dir(&path) {
                Ok(entries) => send_names(
                    entries.map_while(Result::ok).map(|e| e.file_name()),
                    &mut |bytes| send(output, bytes),
                ),
                Err(e) => send(output, &frame(R_ERROR, &encode_error(&e))),
            },
        };
        if sent.is_err() {
            return 1;
        }
    }
}

/// A directory's names as `n` frames and the `e` that ends them: a frame as
/// soon as [`FLUSH_EVERY`] has passed since the last (or the frame is
/// full), so that a listing the system gives slowly reaches lsof in pieces,
/// each within its limit. What [`lsof_core::safefs::read_dir_now`] returns,
/// in pieces: an entry the system fails to read ends the listing, a name
/// longer than [`MAX_NAME`] (or empty, which no file system gives) is left
/// out, and past [`READ_DIR_MAX_NAMES`] names or [`READ_DIR_MAX_BYTES`]
/// bytes the rest are; so no frame is ever empty.
pub fn send_names(
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
        // At most `MAX_NAME`, 4096: a `u16`.
        chunk.extend_from_slice(&u16::try_from(name.len()).unwrap_or(0).to_le_bytes());
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

/// A frame as the reader thread passes it on: when the reader began to wait
/// for it (once it had passed the one before on, so never while lsof had
/// not taken what it held), when it had it, and the frame.
pub struct Arrival {
    pub ready: Instant,
    pub at: Instant,
    pub frame: Frame,
}

/// Why an exchange failed: the time ran out, or the helper went away or said
/// something that is not a reply. Either way it is not used again.
#[derive(Debug, PartialEq, Eq)]
pub enum Failure {
    TimedOut,
    Lost,
}

/// The next frame from `from`, waited for within `wait`, and taken only if
/// the system took no longer than `wait` to give it: from when the reader
/// could read it, or `floor` (when the request was sent) if that is later,
/// to when it had it. So a frame that came too late is a timeout even when
/// it is already waiting, as one that is still to come is.
pub fn next(
    from: &Receiver<Option<Arrival>>,
    floor: Instant,
    wait: Duration,
) -> Result<Frame, Failure> {
    match from.recv_timeout(wait) {
        Ok(Some(a)) => {
            if a.at.saturating_duration_since(a.ready.max(floor)) > wait {
                Err(Failure::TimedOut)
            } else {
                Ok(a.frame)
            }
        }
        Ok(None) | Err(RecvTimeoutError::Disconnected) => Err(Failure::Lost),
        Err(RecvTimeoutError::Timeout) => Err(Failure::TimedOut),
    }
}

/// A started helper: the child, its stdin, and the frames its reader thread
/// passes on.
struct Live {
    child: Child,
    to: ChildStdin,
    from: Receiver<Option<Arrival>>,
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
    /// Whether anything is waiting that no request asked for: a frame left
    /// over from the last answer, or the helper's end.
    fn has_leftovers(&self) -> bool {
        !matches!(self.from.try_recv(), Err(TryRecvError::Empty))
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
        let floor = Instant::now();
        loop {
            let (kind, payload) = next(&self.from, floor, wait)?;
            match take(kind, payload) {
                Step::Done(answer) => return Ok(answer),
                Step::More => continue,
                Step::Bad => return Err(Failure::Lost),
            }
        }
    }
}

/// A reader thread for a helper's stdout: past what comes before [`HELLO`],
/// then every frame, then `None` at its end or at anything that is not a
/// frame. The channel holds at most [`QUEUED`] frames. It stops once the
/// receiver is gone; until the helper's stdout closes it waits in a pipe
/// `read`, which never holds lsof's exit. A thread that cannot be started
/// is an error, which ends the run as a `fork()` that fails does.
fn reader(from: ChildStdout) -> io::Result<Receiver<Option<Arrival>>> {
    let (tx, rx) = mpsc::sync_channel(QUEUED);
    std::thread::Builder::new()
        .name("lsof-safefs".into())
        .spawn(move || {
            let mut r = BufReader::new(from);
            if !skip_to_hello(&mut r) {
                let _ = tx.send(None);
                return;
            }
            loop {
                let ready = Instant::now();
                let frame = read_frame(&mut r, &REPLIES);
                let at = Instant::now();
                let Some(frame) = frame else {
                    let _ = tx.send(None);
                    return;
                };
                if tx.send(Some(Arrival { ready, at, frame })).is_err() {
                    return;
                }
            }
        })?;
    Ok(rx)
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

/// How a helper is started: the command, ready but for spawning, or why
/// there is none.
pub type Launcher = Box<dyn Fn() -> io::Result<Command>>;

/// What to do when no helper can be started: in lsof, the C's words for the
/// step that failed ([`cannot_start`]) and exit 1.
pub type OnFailure = Box<dyn Fn(&io::Error)>;

/// The helper's command line and surroundings, `program` with `args`: stdin
/// and stdout pipes, stderr `/dev/null`, no environment. Its working
/// directory is lsof's, as a forked child's is.
pub fn helper_command(program: impl AsRef<OsStr>, args: &[&OsStr]) -> Command {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    cmd
}

/// An error as another value, the same `errno` or words: what a launcher
/// hands back each time it is asked.
fn again(e: &io::Error) -> io::Error {
    match e.raw_os_error() {
        Some(n) => io::Error::from_raw_os_error(n),
        None => io::Error::new(e.kind(), e.to_string()),
    }
}

/// What the run's helpers are: the one asked now, and those killed.
#[derive(Default)]
struct State {
    live: Option<Live>,
    /// Helpers killed and not yet reaped: each is waited for, without
    /// blocking, at the next call. Never more than the cap and the one a
    /// call has just killed.
    killed: Vec<Child>,
    /// Whether the cap has refused a call yet, and whether the warning that
    /// says so is still to be given ([`FsCalls::note`]): once a run.
    full: bool,
    untold: bool,
}

impl State {
    /// Kill the helper and drop it unwaited — its stdin, its replies and
    /// all. Killed first: a helper still in a call must not be left to
    /// finish it.
    fn abandon(&mut self) {
        if let Some(mut live) = self.live.take() {
            let _ = live.child.kill();
            self.killed.push(live.child);
        }
    }

    /// Wait, without blocking, for those killed: the gone are forgotten, so
    /// that a pid another process may since have been given is not kept.
    fn reap(&mut self) {
        self.killed
            .retain_mut(|c| !matches!(c.try_wait(), Ok(Some(_))));
    }
}

/// The bounded calls, through a helper ([`FsCalls`]): lsof-cli's `main`
/// makes one per run ([`Helper::new`]); the tests make theirs with
/// [`Helper::with_launcher`].
pub struct Helper {
    state: RefCell<State>,
    launch: Launcher,
    on_failure: OnFailure,
    /// The greeting a helper of this build gives ([`hello`]).
    greeting: Vec<u8>,
    /// [`MAX_WAITING`], or a test's own.
    cap: usize,
}

impl Helper {
    /// The helper lsof starts: the executable lsof is running, by the path
    /// the kernel gives for it, with [`HELPER_ARG`], expected to greet as
    /// this build ([`token`], taken now, as the run starts); if none can be
    /// started, the C's words and exit 1 ([`cannot_start`]). No path
    /// (`current_exe()` failing) is no helper, never a search of `PATH`.
    pub fn new() -> Self {
        let exe = std::env::current_exe().and_then(|p| token(&p).map(|t| (p, t)));
        let greeting = exe.as_ref().map(|(_, t)| hello(t)).unwrap_or_default();
        let launch: Launcher = Box::new(move || match &exe {
            Ok((program, _)) => Ok(helper_command(program, &[OsStr::new(HELPER_ARG)])),
            Err(e) => Err(again(e)),
        });
        Helper::with_launcher(
            launch,
            Box::new(|e| {
                // The C's `Error()`: stdout flushed, then 1.
                lsof_core::safefs::to_stderr(&format!("lsof: {}", cannot_start(e)));
                lsof_core::safefs::exit(1);
            }),
            greeting,
        )
    }

    /// A helper started by `launch`, greeting with `greeting`, and
    /// `on_failure` for one that cannot be started: what the tests use.
    pub fn with_launcher(launch: Launcher, on_failure: OnFailure, greeting: Vec<u8>) -> Self {
        Helper {
            state: RefCell::new(State::default()),
            launch,
            on_failure,
            greeting,
            cap: MAX_WAITING,
        }
    }

    /// The same helper with another cap on killed helpers still waiting
    /// ([`MAX_WAITING`]): what the tests use to reach it.
    pub fn with_cap(mut self, cap: usize) -> Self {
        self.cap = cap;
        self
    }

    /// Start a helper, and take its greeting within `wait`, into `state`.
    /// One that does not greet as this build's helper is killed, and no call
    /// is made of it.
    fn start(&self, state: &mut State, wait: Duration) -> io::Result<()> {
        let mut child = (self.launch)()?.spawn()?;
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
        let greeting = next(&from, Instant::now(), wait);
        state.live = Some(Live { child, to, from });
        match greeting {
            Ok((R_HELLO, payload)) if payload == self.greeting => Ok(()),
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
        if path.len() > MAX_NAME {
            return Err(name_too_long());
        }
        let wait = Duration::from_secs(u64::from(limit.max(1)));
        let mut state = self.state.borrow_mut();
        state.reap();
        // A helper that has said what no request asked is not asked again.
        if state.live.as_ref().is_some_and(Live::has_leftovers) {
            state.abandon();
        }
        if state.live.is_none() && state.killed.len() >= self.cap {
            // No new helper, and so no pipe or thread more: the call fails
            // at once, and the run is told once.
            if !state.full {
                state.full = true;
                state.untold = true;
            }
            return Err(would_block());
        }
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
                // Timed out or lost: this helper is done with, and the next
                // call starts another, as the C's `childx()` and next
                // `fork()` do.
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

    /// End the run's helper: close its stdin, which it takes as the end,
    /// and reap it. It has answered every call it was asked, so it is
    /// waiting on the pipe and goes at once; one that has not within a
    /// second is killed.
    pub fn finish(&self) {
        let mut state = self.state.borrow_mut();
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

impl FsCalls for Helper {
    fn stat(&self, path: &Path, limit: u32) -> io::Result<FileStat> {
        self.stat_call(OP_STAT, path, limit)
    }

    fn lstat(&self, path: &Path, limit: u32) -> io::Result<FileStat> {
        self.stat_call(OP_LSTAT, path, limit)
    }

    fn readlink(&self, path: &Path, limit: u32) -> io::Result<OsString> {
        self.call(OP_READLINK, path, limit, |kind, payload| match kind {
            R_LINK if payload.len() <= MAX_NAME => Step::Done(Ok(OsString::from_vec(payload))),
            R_ERROR => decode_error(&payload).map_or(Step::Bad, |e| Step::Done(Err(e))),
            _ => Step::Bad,
        })
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

    fn helper_pids(&self) -> Vec<u32> {
        let mut state = self.state.borrow_mut();
        state.reap();
        state
            .live
            .iter()
            .map(|l| &l.child)
            .chain(state.killed.iter())
            .map(Child::id)
            .collect()
    }

    /// Once the cap has refused a call ([`MAX_WAITING`]): the one warning,
    /// the Linux helper's.
    fn note(&self) -> Option<String> {
        let mut state = self.state.borrow_mut();
        if !state.untold {
            return None;
        }
        state.untold = false;
        Some(format!(
            "lsof: WARNING: {} killed helpers still wait on file systems that do not \
             answer; no call is made while they do.\n      \
             Output information may be incomplete.",
            self.cap
        ))
    }
}

impl Drop for Helper {
    /// The helper is idle; closing its stdin ends it, and it is reaped.
    fn drop(&mut self) {
        self.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;
    use std::sync::mpsc::SyncSender;

    /// The token the scripted helpers greet with.
    const TEST_TOKEN: &[u8] = b"a test build";

    /// A scratch directory of the test's own, removed when it goes.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("lsof-rs-fb-{name}-{}", std::process::id()));
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

    /// Every frame `serve_on` wrote after its line, the greeting first.
    fn replies(out: &[u8]) -> Vec<Frame> {
        let mut out = out.strip_prefix(HELLO).expect("the line first");
        let mut frames = Vec::new();
        while let Some(f) = read_frame(&mut out, &REPLIES) {
            frames.push(f);
        }
        assert!(out.is_empty(), "{} bytes left over", out.len());
        frames
    }

    fn served(input: &[u8]) -> (i32, Vec<Frame>) {
        let mut out = Vec::new();
        let rc = serve_on(&mut &input[..], &mut out, TEST_TOKEN);
        (rc, replies(&out))
    }

    /// The protocol round trip, served in-process: the same answers
    /// `lsof_core::safefs`'s in-process calls give.
    #[test]
    #[cfg_attr(miri, ignore = "stats the real file system")]
    fn each_call_is_answered_as_it_is_made_in_process() {
        let dir = Scratch::new("wire");
        let d = &dir.0;
        std::fs::write(d.join("f"), b"abc").unwrap();
        std::os::unix::fs::symlink("f", d.join("l")).unwrap();
        let req = |op, p: &Path| frame(op, p.as_os_str().as_bytes());
        let input = [
            req(OP_STAT, &d.join("l")),
            req(OP_LSTAT, &d.join("l")),
            req(OP_READLINK, &d.join("l")),
            req(OP_READ_DIR, d),
            req(OP_STAT, &d.join("missing")),
            req(OP_READ_DIR, &d.join("missing")),
        ]
        .concat();
        let (rc, got) = served(&input);
        assert_eq!(rc, 0, "ends at the end of its input");
        assert_eq!(got[0], (R_HELLO, hello(TEST_TOKEN)));
        let st = stat_now(&d.join("f"), true).unwrap();
        assert_eq!(got[1], (R_STAT, encode_stat(&st)));
        assert_eq!(decode_stat(&got[1].1), Some(st));
        assert!(decode_stat(&got[2].1).unwrap().is_symlink(), "lstat");
        assert_eq!(got[3], (R_LINK, b"f".to_vec()));
        assert_eq!(got[4].0, R_NAMES);
        let (mut names, mut bytes) = (Vec::new(), 0);
        decode_names(&got[4].1, &mut names, &mut bytes).unwrap();
        names.sort();
        assert_eq!(names, ["f", "l"]);
        assert_eq!(bytes, 2);
        assert_eq!(got[5], (R_END, Vec::new()));
        assert_eq!(
            decode_error(&got[6].1).unwrap().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(got[7].0, R_ERROR, "a directory that cannot be opened");
        assert_eq!(got.len(), 8);
    }

    /// A request the helper does not know, or a path longer than any it
    /// takes, ends it: nothing is allocated for a length it will not take.
    #[test]
    fn a_malformed_request_ends_the_helper() {
        let long = {
            let mut f = vec![OP_STAT];
            f.extend_from_slice(&u32::MAX.to_le_bytes());
            f
        };
        let just = {
            let mut f = vec![OP_STAT];
            f.extend_from_slice(&(MAX_NAME as u32 + 1).to_le_bytes());
            f.extend(vec![b'a'; MAX_NAME + 1]);
            f
        };
        for bad in [frame(b'Q', b"/"), long, just] {
            let (rc, got) = served(&bad);
            assert_eq!(rc, 1);
            assert_eq!(got, [(R_HELLO, hello(TEST_TOKEN))]);
        }
        // Cut short inside a request is lsof gone: 0.
        assert_eq!(served(&[OP_STAT, 1]).0, 0);
    }

    /// Each frame is taken exactly as its kind says, and an error with no
    /// `errno` is sent as `EINVAL`, never as the 0 no error has.
    #[test]
    fn a_frame_is_taken_exactly_and_an_errno_is_never_zero() {
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
        let rec = encode_stat(&st);
        assert_eq!(rec.len(), STAT_LEN);
        assert_eq!(decode_stat(&rec), Some(st));
        assert_eq!(decode_stat(&rec[..STAT_LEN - 1]), None, "cut short");
        assert_eq!(decode_stat(&[rec.clone(), vec![0]].concat()), None, "past");
        assert_eq!(decode_error(&[13, 0, 0]).map(|e| e.kind()), None);
        assert_eq!(decode_error(&[13, 0, 0, 0, 0]).map(|e| e.kind()), None);
        assert_eq!(decode_error(&0i32.to_le_bytes()).map(|e| e.kind()), None);
        assert_eq!(decode_error(&(-1i32).to_le_bytes()).map(|e| e.kind()), None);
        assert_eq!(
            decode_error(&13i32.to_le_bytes()).and_then(|e| e.raw_os_error()),
            Some(13)
        );
        let none = io::Error::new(io::ErrorKind::InvalidInput, "no errno");
        assert_eq!(encode_error(&none), EINVAL.to_le_bytes());
        assert_eq!(
            encode_error(&io::Error::from_raw_os_error(2)),
            2i32.to_le_bytes()
        );
        // A frame past the limit is refused unread, and so is one of a kind
        // not asked for.
        let mut big = vec![R_STAT];
        big.extend_from_slice(&(MAX_FRAME as u32 + 1).to_le_bytes());
        assert!(read_frame(&mut &big[..], &REPLIES).is_none());
        let mut at_limit = vec![R_LINK];
        at_limit.extend_from_slice(&(MAX_FRAME as u32).to_le_bytes());
        at_limit.extend(vec![b'a'; MAX_FRAME]);
        assert!(read_frame(&mut &at_limit[..], &REPLIES).is_some());
        assert!(read_frame(&mut &frame(OP_STAT, b"/")[..], &REPLIES).is_none());
    }

    /// A listing that would pass either cap, or that holds an empty name or
    /// frame, or a name past `MAX_NAME`, is refused.
    #[test]
    #[cfg_attr(miri, ignore = "a million names, slowly under miri")]
    fn a_listing_past_its_caps_is_refused() {
        let one = [&1u16.to_le_bytes()[..], b"a"].concat();
        let mut bytes = 0;
        assert_eq!(decode_names(&[], &mut Vec::new(), &mut bytes), None);
        assert_eq!(decode_names(&[0, 0], &mut Vec::new(), &mut bytes), None);
        assert_eq!(
            decode_names(&[5, 0, b'a'], &mut Vec::new(), &mut bytes),
            None
        );
        let long = [
            &(MAX_NAME as u16 + 1).to_le_bytes()[..],
            &vec![b'a'; MAX_NAME + 1],
        ]
        .concat();
        assert_eq!(decode_names(&long, &mut Vec::new(), &mut bytes), None);
        let longest = [&(MAX_NAME as u16).to_le_bytes()[..], &vec![b'a'; MAX_NAME]].concat();
        assert_eq!(decode_names(&longest, &mut Vec::new(), &mut 0), Some(()));
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

    /// The helper sends names as they come, a frame once `FLUSH_EVERY` has
    /// passed, and no more than the caps: a name that is empty or past
    /// `MAX_NAME` is not sent, and past `READ_DIR_MAX_NAMES` names or
    /// `READ_DIR_MAX_BYTES` bytes the rest are not.
    #[test]
    #[cfg_attr(miri, ignore = "sleeps, and a million names")]
    fn names_are_sent_as_they_come_and_no_more_than_the_caps() {
        let slow = (0..5).map(|i| {
            std::thread::sleep(Duration::from_millis(60));
            OsString::from(format!("n{i}"))
        });
        let odd = [
            OsString::new(),
            OsString::from_vec(vec![b'x'; MAX_NAME + 1]),
        ];
        let listed = |names: &mut dyn Iterator<Item = OsString>| {
            let mut out = Vec::new();
            send_names(names, &mut |bytes| {
                out.push(bytes.to_vec());
                Ok(())
            })
            .unwrap();
            let all = [HELLO.to_vec(), out.concat()].concat();
            let frames = replies(&all);
            let (mut names, mut bytes) = (Vec::new(), 0);
            for (kind, payload) in &frames[..frames.len() - 1] {
                assert_eq!(*kind, R_NAMES);
                decode_names(payload, &mut names, &mut bytes).unwrap();
            }
            assert_eq!(frames.last(), Some(&(R_END, Vec::new())));
            (frames.len(), names, bytes)
        };
        let (frames, names, _) = listed(&mut slow.chain(odd));
        assert!(frames >= 3, "sent only at the end: {frames}");
        assert_eq!(names, ["n0", "n1", "n2", "n3", "n4"]);
        // The caps, one past each.
        let (_, names, _) = listed(&mut (0..=READ_DIR_MAX_NAMES).map(|_| OsString::from("a")));
        assert_eq!(names.len(), READ_DIR_MAX_NAMES);
        let wide = OsString::from_vec(vec![b'w'; MAX_NAME]);
        let fit = READ_DIR_MAX_BYTES / MAX_NAME;
        let (_, names, bytes) = listed(&mut std::iter::repeat_n(wide, fit + 1));
        assert_eq!(names.len(), fit);
        assert_eq!(bytes, fit * MAX_NAME);
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
        // Many short lines before it, within the bound, are read past.
        let lines = [b"x\n".repeat(1000), HELLO.to_vec()].concat();
        assert!(skip_to_hello(&mut io::Cursor::new(lines)));
    }

    fn arrival(tx: &SyncSender<Option<Arrival>>, ready: Instant, after: Duration) {
        tx.send(Some(Arrival {
            ready,
            at: ready + after,
            frame: (R_END, Vec::new()),
        }))
        .unwrap();
    }

    /// The limit is on each wait for the system, measured where the reader
    /// had the frame: one that took longer is a timeout even when it is
    /// already waiting in the channel; one in time is taken, however long
    /// ago the request was sent; and the wait is from the request when the
    /// reader was ready before it.
    #[test]
    fn a_frame_that_came_too_late_times_out_even_when_it_is_waiting() {
        let (tx, rx) = mpsc::sync_channel(QUEUED);
        let wait = Duration::from_secs(2);
        let t0 = Instant::now();
        arrival(&tx, t0, Duration::from_secs(3));
        assert_eq!(next(&rx, t0, wait), Err(Failure::TimedOut));
        arrival(&tx, t0, Duration::from_millis(1900));
        assert_eq!(next(&rx, t0, wait), Ok((R_END, Vec::new())));
        // Ready long before the request: measured from the request.
        arrival(&tx, t0, Duration::from_secs(5));
        assert_eq!(
            next(&rx, t0 + Duration::from_secs(4), wait),
            Ok((R_END, Vec::new()))
        );
        arrival(&tx, t0, Duration::from_secs(5));
        assert_eq!(
            next(&rx, t0 + Duration::from_secs(2), wait),
            Err(Failure::TimedOut)
        );
        tx.send(None).unwrap();
        assert_eq!(next(&rx, t0, wait), Err(Failure::Lost));
        drop(tx);
        assert_eq!(next(&rx, t0, wait), Err(Failure::Lost));
        let (_tx, rx) = mpsc::sync_channel::<Option<Arrival>>(1);
        let began = Instant::now();
        assert_eq!(
            next(&rx, began, Duration::from_millis(50)),
            Err(Failure::TimedOut)
        );
        assert!(began.elapsed() >= Duration::from_millis(50));
    }

    /// `printf`'s spelling of `bytes`.
    fn octal(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("\\{b:03o}")).collect()
    }

    fn greeting() -> String {
        octal(&[HELLO, &frame(R_HELLO, &hello(TEST_TOKEN))].concat())
    }

    /// A helper of `sh -c SCRIPT`, set up as the real one is, that counts
    /// its starts and its failures to start.
    fn fake(script: String, starts: &Rc<Cell<usize>>, failed: &Rc<Cell<usize>>) -> Helper {
        let (starts, failed) = (Rc::clone(starts), Rc::clone(failed));
        Helper::with_launcher(
            Box::new(move || {
                starts.set(starts.get() + 1);
                Ok(helper_command(
                    "/bin/sh",
                    &[OsStr::new("-c"), OsStr::new(&script)],
                ))
            }),
            Box::new(move |_| failed.set(failed.get() + 1)),
            hello(TEST_TOKEN),
        )
    }

    fn counters() -> (Rc<Cell<usize>>, Rc<Cell<usize>>) {
        (Rc::new(Cell::new(0)), Rc::new(Cell::new(0)))
    }

    /// Whether `pid` is gone or a zombie, by `kill -0`'s and `ps`'s
    /// portable answers: waited for up to five seconds.
    fn dead(pid: u32) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let state = Command::new("ps")
                .args(["-o", "stat=", "-p", &pid.to_string()])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_default();
            if state.is_empty() || state.starts_with('Z') {
                return true;
            }
            if Instant::now() > deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
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
            assert!(Instant::now() < deadline, "the fake never wrote its pid");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Until `helper_pids` is empty, or five seconds: whether it emptied.
    fn all_reaped(h: &Helper) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !h.helper_pids().is_empty() {
            if Instant::now() > deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        true
    }

    /// A helper that greets and never answers: the call is `ETIMEDOUT`
    /// within its limit, the helper is killed and listed until it is reaped,
    /// the next call starts another, and a reaped one is not listed.
    #[test]
    #[cfg_attr(miri, ignore = "starts processes")]
    fn a_call_that_outlives_its_limit_times_out_and_the_helper_is_replaced() {
        let dir = Scratch::new("timeout");
        let pidfile = dir.0.join("pid");
        let script = format!(
            "echo $$ > '{}'; printf '{}'; exec sleep 100",
            pidfile.display(),
            greeting()
        );
        let (starts, failed) = counters();
        let h = fake(script, &starts, &failed);
        let began = Instant::now();
        let e = h.stat(Path::new("/"), 1).unwrap_err();
        let took = began.elapsed();
        assert!(lsof_core::safefs::is_timed_out(&e), "{e}");
        assert!(
            took >= Duration::from_secs(1) && took < Duration::from_secs(3),
            "{took:?}"
        );
        let first = pid_in(&pidfile);
        assert!(dead(first), "the timed-out helper was left running");
        assert!(h.state.borrow().live.is_none());
        std::fs::remove_file(&pidfile).unwrap();
        let e = h.lstat(Path::new("/"), 1).unwrap_err();
        assert!(lsof_core::safefs::is_timed_out(&e));
        assert_eq!(starts.get(), 2, "the next call starts a fresh helper");
        let second = pid_in(&pidfile);
        assert_ne!(first, second);
        assert!(dead(second));
        // Both killed; reaped once they are gone, and then not listed.
        assert!(all_reaped(&h), "{:?}", h.helper_pids());
        assert!(h.state.borrow().killed.is_empty());
        assert_eq!(failed.get(), 0);
    }

    /// Past `MAX_WAITING` killed helpers still waiting, a call starts no
    /// helper and fails at once with `EAGAIN`; the warning is given once;
    /// once one is reaped, calls are made again.
    #[test]
    #[cfg_attr(miri, ignore = "starts processes")]
    fn past_the_cap_of_waiting_helpers_a_call_fails_at_once_and_says_so_once() {
        assert_eq!(MAX_WAITING, 16);
        let (starts, failed) = counters();
        let h = fake(
            format!("printf '{}'; exec sleep 100", greeting()),
            &starts,
            &failed,
        )
        .with_cap(2);
        assert!(h.note().is_none(), "nothing to say yet");
        let stand_ins: Vec<Child> = (0..2)
            .map(|_| Command::new("sleep").arg("100").spawn().expect("a sleeper"))
            .collect();
        let mut pids: Vec<u32> = stand_ins.iter().map(Child::id).collect();
        h.state.borrow_mut().killed.extend(stand_ins);
        let began = Instant::now();
        for _ in 0..3 {
            let e = h.stat(Path::new("/"), 5).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::WouldBlock, "{e}");
        }
        assert!(h.read_dir(Path::new("/"), 5).is_err());
        assert!(began.elapsed() < Duration::from_secs(2));
        assert_eq!(starts.get(), 0, "no helper was started");
        let note = h.note().expect("the cap is said");
        assert!(
            note.starts_with("lsof: WARNING: 2 killed helpers"),
            "{note}"
        );
        assert!(note.ends_with("\n      Output information may be incomplete."));
        assert!(h.note().is_none(), "once");
        let mut waiting = h.helper_pids();
        waiting.sort_unstable();
        pids.sort_unstable();
        assert_eq!(waiting, pids, "the waiting ones stay known to a scan");
        // One goes: the next call is made, by a fresh helper, and times out.
        {
            let mut st = h.state.borrow_mut();
            let _ = st.killed[0].kill();
            let _ = st.killed[0].wait();
        }
        let e = h.lstat(Path::new("/"), 1).unwrap_err();
        assert!(lsof_core::safefs::is_timed_out(&e), "{e}");
        assert_eq!(starts.get(), 1);
        let _ = h.stat(Path::new("/"), 1);
        assert!(h.note().is_none(), "once a run");
        for c in h.state.borrow_mut().killed.iter_mut() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    /// A reply that is not one — too long, of the wrong kind, a record cut
    /// short or with bytes past it, an errno of 0 — is refused without being
    /// taken in: `ECHILD`, the helper is killed, the next call starts
    /// another. So is a frame left over from the last answer.
    #[test]
    #[cfg_attr(miri, ignore = "starts processes")]
    fn a_reply_that_is_not_one_is_refused_and_the_helper_replaced() {
        let oversized = {
            let mut f = vec![R_STAT];
            f.extend_from_slice(&u32::MAX.to_le_bytes());
            f
        };
        let st = encode_stat(&FileStat::default());
        for (what, reply) in [
            ("an oversized frame", oversized),
            ("a reply of another kind", frame(R_LINK, b"/x")),
            (
                "a stat record cut short",
                frame(R_STAT, &st[..STAT_LEN - 1]),
            ),
            (
                "a stat record with more",
                frame(R_STAT, &[&st[..], b"x"].concat()),
            ),
            ("an errno of 0", frame(R_ERROR, &0i32.to_le_bytes())),
        ] {
            let script = format!("printf '{}{}'; exec sleep 100", greeting(), octal(&reply));
            let (starts, failed) = counters();
            let h = fake(script, &starts, &failed);
            let began = Instant::now();
            let e = h.stat(Path::new("/"), 5).unwrap_err();
            assert_eq!(e.raw_os_error(), lost_child().raw_os_error(), "{what}: {e}");
            assert!(began.elapsed() < Duration::from_secs(4), "{what}: waited");
            h.stat(Path::new("/"), 5).unwrap_err();
            assert_eq!(starts.get(), 2, "{what}");
            assert_eq!(failed.get(), 0, "{what}");
        }
        // A link longer than any path is no link; the longest is one.
        for (len, ok) in [(MAX_NAME + 1, false), (MAX_NAME, true)] {
            let link = frame(R_LINK, &vec![b'a'; len]);
            let script = format!("printf '{}{}'; exec sleep 100", greeting(), octal(&link));
            let (starts, failed) = counters();
            let h = fake(script, &starts, &failed);
            let got = h.readlink(Path::new("/l"), 5);
            assert_eq!(got.is_ok(), ok, "{len}");
            if !ok {
                let e = got.unwrap_err();
                assert_eq!(e.raw_os_error(), lost_child().raw_os_error());
            }
        }
    }

    /// A frame waiting before the request is sent is no answer to it, nor
    /// is a helper whose end is waiting: the helper is killed and the call
    /// made of a fresh one.
    #[test]
    #[cfg_attr(miri, ignore = "starts processes")]
    fn a_frame_before_the_request_replaces_the_helper() {
        let st = encode_stat(&FileStat {
            ino: 7,
            ..FileStat::default()
        });
        let script = format!(
            "printf '{}{}'; exec cat >/dev/null",
            greeting(),
            octal(&frame(R_STAT, &st))
        );
        for leftover in [Some(Some((R_STAT, vec![0u8; STAT_LEN]))), Some(None), None] {
            let (starts, failed) = counters();
            let h = fake(script.clone(), &starts, &failed);
            // A helper whose reader the test is: what it says is the test's.
            let mut child = Command::new("sleep")
                .arg("100")
                .stdin(Stdio::piped())
                .spawn()
                .unwrap();
            let pid = child.id();
            let to = child.stdin.take().unwrap();
            let (tx, from) = mpsc::sync_channel(QUEUED);
            match leftover.clone() {
                Some(Some(frame)) => {
                    let now = Instant::now();
                    tx.send(Some(Arrival {
                        ready: now,
                        at: now,
                        frame,
                    }))
                    .unwrap();
                }
                Some(None) => tx.send(None).unwrap(),
                None => drop(tx),
            }
            h.state.borrow_mut().live = Some(Live { child, to, from });
            assert_eq!(h.stat(Path::new("/"), 5).unwrap().ino, 7, "{leftover:?}");
            assert_eq!(starts.get(), 1, "a fresh helper: {leftover:?}");
            assert!(dead(pid), "the one with leftovers was killed");
            assert_eq!(failed.get(), 0);
        }
    }

    /// A greeting from another build or program, or none: no helper, the
    /// process killed, and the failure is the run's (`can't fork`). One that
    /// cannot be started at all, or has no path: the same.
    #[test]
    #[cfg_attr(miri, ignore = "starts processes")]
    fn a_helper_of_another_build_is_refused_and_killed() {
        let dir = Scratch::new("foreign");
        let pidfile = dir.0.join("pid");
        let other = [HELLO, &frame(R_HELLO, &hello(b"another build"))].concat();
        let script = format!(
            "echo $$ > '{}'; printf '{}'; exec sleep 100",
            pidfile.display(),
            octal(&other)
        );
        let (starts, failed) = counters();
        let h = fake(script, &starts, &failed);
        let e = h.stat(Path::new("/"), 5).unwrap_err();
        assert_eq!(e.raw_os_error(), lost_child().raw_os_error(), "{e}");
        assert_eq!(failed.get(), 1, "can't fork");
        assert!(
            dead(pid_in(&dir.0.join("pid"))),
            "the foreign greeter ran on"
        );
        // No greeting within the limit: ETIMEDOUT, killed.
        std::fs::remove_file(&pidfile).unwrap();
        let mute = format!("echo $$ > '{}'; exec sleep 100", pidfile.display());
        let (starts, failed) = counters();
        let h = fake(mute, &starts, &failed);
        let began = Instant::now();
        let e = h.stat(Path::new("/"), 1).unwrap_err();
        assert!(lsof_core::safefs::is_timed_out(&e), "{e}");
        assert!(began.elapsed() < Duration::from_secs(3));
        assert_eq!(failed.get(), 1);
        assert!(dead(pid_in(&pidfile)), "the mute helper ran on");
        // Not startable, or no program at all.
        for launch in [
            Box::new(|| Ok(helper_command("/nonexistent/lsof-rs-helper", &[]))) as Launcher,
            Box::new(|| Err(io::Error::from_raw_os_error(2))),
        ] {
            let failed = Rc::new(Cell::new(0));
            let seen = Rc::clone(&failed);
            let h = Helper::with_launcher(
                launch,
                Box::new(move |_| seen.set(seen.get() + 1)),
                hello(TEST_TOKEN),
            );
            let e = h.readlink(Path::new("/"), 5).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::NotFound);
            assert_eq!(failed.get(), 1);
        }
        assert!(cannot_start(&io::Error::from_raw_os_error(24)).starts_with("can't open pipes: "));
        assert!(cannot_start(&io::Error::from_raw_os_error(23)).starts_with("can't open pipes: "));
        assert!(cannot_start(&io::Error::from_raw_os_error(2)).starts_with("can't fork: "));
        assert_eq!(
            again(&io::Error::from_raw_os_error(2)).raw_os_error(),
            Some(2)
        );
        assert_eq!(again(&io::Error::other("w")).to_string(), "w");
    }

    /// A path longer than any the helper takes is refused before anything
    /// is started.
    #[test]
    #[cfg_attr(miri, ignore = "starts processes")]
    fn a_path_no_request_can_carry_starts_no_helper() {
        let (starts, failed) = counters();
        let h = fake("exit 0".into(), &starts, &failed);
        let long = OsString::from_vec(vec![b'a'; MAX_NAME + 1]);
        let e = h.stat(Path::new(&long), 5).unwrap_err();
        assert_eq!(e.raw_os_error(), name_too_long().raw_os_error(), "{e}");
        let longest = OsString::from_vec(vec![b'a'; MAX_NAME]);
        let _ = h.stat(Path::new(&longest), 5);
        assert_eq!(starts.get(), 1, "the longest path is asked");
    }

    /// A listing is bounded frame by frame: names that come slowly, each
    /// frame within the limit, are taken whole however long the listing
    /// takes; a wait longer than the limit between two frames is a timeout;
    /// an empty frame, which costs neither of a listing's caps, is refused.
    #[test]
    #[cfg_attr(miri, ignore = "starts processes")]
    fn a_listing_is_bounded_frame_by_frame() {
        let names = |n: &[u8]| frame(R_NAMES, &[&[1u8, 0][..], n].concat());
        let (a, b, c) = (names(b"a"), names(b"b"), names(b"c"));
        let end = frame(R_END, &[]);
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
        let (starts, failed) = counters();
        let h = fake(script("0.7"), &starts, &failed);
        let began = Instant::now();
        let got = h.read_dir(Path::new("/"), 1).unwrap();
        assert!(
            began.elapsed() > Duration::from_secs(1),
            "longer than the limit in all"
        );
        assert_eq!(got, ["a", "b", "c"]);
        let h = fake(script("2.5"), &starts, &failed);
        let began = Instant::now();
        let e = h.read_dir(Path::new("/"), 1).unwrap_err();
        assert!(lsof_core::safefs::is_timed_out(&e), "{e}");
        assert!(began.elapsed() < Duration::from_secs(2));
        let empty = format!(
            "printf '{}{}{}'; exec cat >/dev/null",
            greeting(),
            octal(&frame(R_NAMES, &[])),
            octal(&end)
        );
        let h = fake(empty, &starts, &failed);
        let e = h.read_dir(Path::new("/"), 5).unwrap_err();
        assert_eq!(e.raw_os_error(), lost_child().raw_os_error(), "{e}");
        assert_eq!(failed.get(), 0);
    }

    /// The helper's environment is empty, and its stdin and stdout are
    /// pipes.
    #[test]
    #[cfg_attr(miri, ignore = "starts processes")]
    fn the_helper_has_no_environment_and_pipes() {
        let dir = Scratch::new("env");
        let out = dir.0.join("out");
        let script = format!(
            "echo \"${{HOME-none}} ${{CARGO_MANIFEST_DIR-none}}\" > '{}'; printf '{}'; exec cat >/dev/null",
            out.display(),
            greeting()
        );
        let (starts, failed) = counters();
        let h = fake(script, &starts, &failed);
        let mut state = h.state.borrow_mut();
        h.start(&mut state, Duration::from_secs(5)).unwrap();
        drop(state);
        let deadline = Instant::now() + Duration::from_secs(5);
        let said = loop {
            match std::fs::read_to_string(&out) {
                Ok(s) if s.ends_with('\n') => break s,
                _ => {}
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        };
        // `cargo test` gives this process both.
        assert!(std::env::var_os("CARGO_MANIFEST_DIR").is_some());
        assert_eq!(said, "none none\n");
        // What `serve` asks of its stdin and stdout.
        let mut child = helper_command("cat", &[]).spawn().unwrap();
        assert!(is_pipe(child.stdin.as_ref().unwrap().as_fd()));
        assert!(is_pipe(child.stdout.as_ref().unwrap().as_fd()));
        drop(child.stdin.take());
        let _ = child.wait();
        let file = std::fs::File::create(dir.0.join("f")).unwrap();
        assert!(!is_pipe(file.as_fd()));
    }

    /// lsof's own helper is the running executable by its path, with
    /// `HELPER_ARG` alone and no environment, and is expected to greet as
    /// this build: `token` of that executable, taken when the run starts.
    #[test]
    #[cfg_attr(miri, ignore = "stats the test binary")]
    fn lsofs_helper_is_this_executable_greeting_as_this_build() {
        let h = Helper::new();
        let exe = std::env::current_exe().unwrap();
        assert_eq!(h.greeting, hello(&token(&exe).unwrap()));
        assert_eq!(h.cap, MAX_WAITING);
        let cmd = (h.launch)().unwrap();
        assert_eq!(cmd.get_program(), exe.as_os_str());
        assert_eq!(cmd.get_args().collect::<Vec<_>>(), [OsStr::new(HELPER_ARG)]);
        // A token is the version and the file: another file, another token.
        let dir = Scratch::new("token");
        let (a, b) = (dir.0.join("a"), dir.0.join("b"));
        std::fs::write(&a, b"x").unwrap();
        std::fs::write(&b, b"x").unwrap();
        let ta = token(&a).unwrap();
        assert!(ta.starts_with(env!("CARGO_PKG_VERSION").as_bytes()));
        assert_ne!(ta, token(&b).unwrap());
        assert_eq!(ta, token(&a).unwrap());
        std::fs::write(&a, b"xy").unwrap();
        assert_ne!(ta, token(&a).unwrap(), "rewritten");
        assert!(token(&dir.0.join("none")).is_err());
        let hi = hello(b"t");
        assert_eq!(&hi[..8], MAGIC);
        assert_eq!(&hi[8..12], &PROTOCOL.to_le_bytes());
        assert_eq!(&hi[12..], b"t");
    }

    /// The test binary, run as a helper by `helper_entry`.
    fn this_binary(mode: &str) -> Launcher {
        let mode = mode.to_string();
        Box::new(move || {
            let exe = std::env::current_exe()?;
            let mut cmd = helper_command(
                exe,
                &[
                    OsStr::new("--exact"),
                    OsStr::new("safefs::tests::helper_entry"),
                    OsStr::new("--nocapture"),
                    OsStr::new("--test-threads=1"),
                    OsStr::new("--include-ignored"),
                ],
            );
            // The entry serves only where it is asked to.
            cmd.env("LSOF_RS_FB_HELPER_TEST", &mode);
            Ok(cmd)
        })
    }

    fn this_build() -> Vec<u8> {
        hello(&token(&std::env::current_exe().unwrap()).unwrap())
    }

    /// The whole round trip through a real helper process: this test binary,
    /// greeting as this build.
    #[test]
    #[cfg_attr(miri, ignore = "starts processes")]
    fn a_real_helper_answers_each_call() {
        let h = Helper::with_launcher(
            this_binary("serve"),
            Box::new(|e| panic!("no helper: {e}")),
            this_build(),
        );
        let root = h.stat(Path::new("/"), 30).unwrap();
        assert_eq!(root, stat_now(Path::new("/"), true).unwrap());
        let e = h.stat(Path::new("/lsof-rs-no-such-path"), 30).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
        assert!(h.read_dir(Path::new("/"), 30).unwrap().len() > 1);
        assert_eq!(h.helper_pids().len(), 1, "one helper, kept");
        h.finish();
        assert!(h.helper_pids().is_empty(), "ended and reaped");
    }

    /// A large listing that flows is taken whole under `-S 2`, at a cost
    /// that grows with its size, not its square: 400,000 names, which took
    /// 17 seconds when every chunk re-read the answer from its start. One
    /// that flows and then stops is a timeout within the limit of the stop.
    #[test]
    #[cfg_attr(miri, ignore = "starts processes")]
    fn a_large_listing_flows_and_a_stall_after_it_times_out() {
        let h = Helper::with_launcher(
            this_binary("big"),
            Box::new(|e| panic!("no helper: {e}")),
            this_build(),
        );
        let began = Instant::now();
        let got = h.read_dir(Path::new("/"), 2).unwrap();
        assert_eq!(got.len(), BIG);
        assert_eq!(got[BIG - 1], format!("name{:016}", BIG - 1).as_str());
        assert!(
            began.elapsed() < Duration::from_secs(30),
            "{:?}",
            began.elapsed()
        );
        let h = Helper::with_launcher(
            this_binary("stall"),
            Box::new(|e| panic!("no helper: {e}")),
            this_build(),
        );
        let began = Instant::now();
        let e = h.read_dir(Path::new("/"), 2).unwrap_err();
        assert!(lsof_core::safefs::is_timed_out(&e), "{e}");
        assert!(
            began.elapsed() < Duration::from_secs(30),
            "{:?}",
            began.elapsed()
        );
    }

    /// The helper refuses a stdin or stdout that is no pipe, and says why.
    #[test]
    #[cfg_attr(miri, ignore = "starts processes")]
    fn the_helper_refuses_what_is_no_pipe() {
        let mut cmd = this_binary("serve")().unwrap();
        let out = cmd
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2));
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains(&not_an_option()), "{err}");
    }

    const BIG: usize = 400_000;

    #[test]
    #[ignore = "the helper of the tests above"]
    fn helper_entry() {
        let Some(mode) = std::env::var_os("LSOF_RS_FB_HELPER_TEST") else {
            return;
        };
        if mode == "serve" {
            std::process::exit(serve());
        }
        let mut out = io::stdout().lock();
        let token = token(&std::env::current_exe().unwrap()).unwrap();
        out.write_all(&[HELLO, &frame(R_HELLO, &hello(&token))].concat())
            .unwrap();
        out.flush().unwrap();
        let mut input = io::stdin().lock();
        let mut head = [0u8; 5];
        input.read_exact(&mut head).unwrap();
        let mut path = vec![0u8; u32::from_le_bytes([head[1], head[2], head[3], head[4]]) as usize];
        input.read_exact(&mut path).unwrap();
        let names = (0..BIG).map(|i| OsString::from(format!("name{i:016}")));
        let mut send = |b: &[u8]| out.write_all(b).and_then(|()| out.flush());
        if mode == "big" {
            send_names(names, &mut send).unwrap();
        } else {
            // The names, and never the end.
            for name in names.take(1000) {
                let n = name.as_bytes();
                send(&frame(
                    R_NAMES,
                    &[&(n.len() as u16).to_le_bytes()[..], n].concat(),
                ))
                .unwrap();
            }
        }
        let _ = io::copy(&mut input, &mut io::sink());
        std::process::exit(0);
    }
}
