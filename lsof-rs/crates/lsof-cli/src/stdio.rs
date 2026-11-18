//! Standard output as the C's glibc stdio writes it (DIVERGENCES 36, 152).
//!
//! The C lsof never looks at a write's result: it `printf()`s into stdout's
//! buffer, `fflush()`es it before each `-r` sleep (the result cast away) and
//! leaves the rest to `exit()`, whose flush does not change the status.
//! glibc's stdio makes one `write(2)` attempt for each full buffer and each
//! flush, and, where it fails, drops what it held and goes on: the next
//! output fills a new buffer. So the C on `/dev/full` lists, prints nothing
//! about it and exits 0 (1 on a search failure), and with `SIGPIPE` ignored
//! or blocked a closed pipe is the same (measured). With `SIGPIPE` at its
//! default the kernel kills the C at the write that meets a closed pipe;
//! lsof-rs puts the default back where it was inherited
//! (`lsof_sigpipe`, from `main`), and is killed at the same write.
//!
//! [`Stdio`] is that buffer: `st_blksize` of stdout's file, at most
//! `BUFSIZ` (8192), so 4096 on a pipe (glibc's `_IO_file_doallocate()`),
//! line-buffered on a terminal; a write that fills it writes it, and whole
//! blocks past it go straight out (`_IO_new_file_xsputn()`); a failed write
//! empties it and the rest of that call's bytes are dropped, as glibc's
//! short count drops them. It never reports an error, so nothing a caller
//! does with the result can change what the run prints or how it ends.
//! Memory is the one buffer, and a failing write is never retried, so no
//! loop spins on a dead reader: `-r` still sleeps between its cycles.
//!
//! Off Unix (Windows), where there is no `SIGPIPE` to inherit, a closed pipe
//! still ends the run as it did, exit 141, the status a shell shows for the
//! signal; every other failure is dropped as above.

use std::io::{self, Write};
use std::sync::Mutex;

/// glibc's `BUFSIZ`.
pub const BUFSIZ: usize = 8192;

/// The size glibc gives a stream's buffer: `st_blksize` where it is below
/// `BUFSIZ`, else `BUFSIZ` (`_IO_file_doallocate()`).
pub fn buffer_size(blksize: Option<u64>) -> usize {
    match blksize {
        Some(b) if b > 0 && b < BUFSIZ as u64 => usize::try_from(b).unwrap_or(BUFSIZ),
        _ => BUFSIZ,
    }
}

/// A stdio stream over `raw`, the file itself, written unbuffered.
pub struct Stdio<W: Write> {
    raw: W,
    buf: Vec<u8>,
    cap: usize,
    line: bool,
    /// Whether a write has failed (`_IO_ERR_SEEN`). Kept, never acted on, as
    /// the C never calls `ferror()`.
    pub err_seen: bool,
    /// End the run with 141 where a write meets a closed pipe (off Unix).
    exit_on_broken_pipe: bool,
}

impl<W: Write> Stdio<W> {
    /// A stream with a buffer of `cap` bytes, line-buffered if `line`.
    pub fn new(raw: W, cap: usize, line: bool) -> Self {
        let cap = cap.max(1);
        Stdio {
            raw,
            buf: Vec::with_capacity(cap),
            cap,
            line,
            err_seen: false,
            exit_on_broken_pipe: !cfg!(unix),
        }
    }

    /// `_IO_new_file_write()`: one `write(2)` after another until `data` is
    /// out or one fails; how much went out.
    fn emit(&mut self, data: &[u8]) -> usize {
        let mut done = 0usize;
        while done < data.len() {
            match self.raw.write(data.get(done..).unwrap_or_default()) {
                Ok(0) => {
                    self.err_seen = true;
                    break;
                }
                Ok(n) => done = done.saturating_add(n),
                Err(e) => {
                    if self.exit_on_broken_pipe && e.kind() == io::ErrorKind::BrokenPipe {
                        std::process::exit(141);
                    }
                    self.err_seen = true;
                    break;
                }
            }
        }
        done
    }

    /// `_IO_do_write()` of the buffer: written, and emptied whatever
    /// happened. Whether all of it went out.
    fn write_buffer(&mut self) -> bool {
        let held = std::mem::take(&mut self.buf);
        let done = self.emit(&held);
        let all = done == held.len();
        self.buf = held;
        self.buf.clear();
        all
    }

    /// `fputs()`, `printf()`: `data` into the stream as
    /// `_IO_new_file_xsputn()` puts it.
    pub fn put(&mut self, data: &[u8]) {
        let space = self.cap.saturating_sub(self.buf.len());
        let mut count = space;
        let mut must_flush = false;
        if self.line && space >= data.len() {
            if let Some(nl) = data.iter().rposition(|&b| b == b'\n') {
                count = nl.saturating_add(1);
                must_flush = true;
            }
        }
        let (now, mut rest) = data.split_at(count.min(data.len()));
        self.buf.extend_from_slice(now);
        if rest.is_empty() && !must_flush {
            return;
        }
        // The full buffer out (`_IO_OVERFLOW`); where that fails the rest of
        // this call's bytes are dropped, as glibc's short count drops them.
        if !self.write_buffer() {
            return;
        }
        // Whole blocks straight out, the remainder into the buffer.
        let block = self.cap;
        let whole = rest.len() - if block >= 128 { rest.len() % block } else { 0 };
        if whole > 0 {
            let (blocks, tail) = rest.split_at(whole);
            if self.emit(blocks) < whole {
                return;
            }
            rest = tail;
        }
        self.buf.extend_from_slice(rest);
    }

    /// `fflush()`: what the buffer holds, written in one attempt, then
    /// emptied.
    pub fn flush_now(&mut self) {
        if !self.buf.is_empty() {
            self.write_buffer();
        }
    }

    /// What the buffer holds now.
    pub fn held(&self) -> &[u8] {
        &self.buf
    }
}

impl<W: Write> Write for Stdio<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.put(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flush_now();
        Ok(())
    }
}

/// The raw standard output: the descriptor itself (a duplicate of fd 1, the
/// same open file), so that no other buffer stands between [`Stdio`] and it.
type Raw = Box<dyn Write + Send>;

/// File descriptor 1 itself, written through `write(2)` (Linux).
#[cfg(target_os = "linux")]
struct Fd1;

#[cfg(target_os = "linux")]
impl Write for Fd1 {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        lsof_backend_linux::write_stdout(data)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn open_raw() -> (Raw, usize, bool) {
    use std::io::IsTerminal;
    let line = std::io::stdout().is_terminal();
    let size = buffer_size(lsof_backend_linux::stdout_blksize());
    (Box::new(Fd1), size, line)
}

/// Elsewhere on Unix a duplicate of descriptor 1, the same open file.
#[cfg(all(unix, not(target_os = "linux")))]
fn open_raw() -> (Raw, usize, bool) {
    use std::io::IsTerminal;
    use std::os::fd::AsFd;
    use std::os::unix::fs::MetadataExt;
    match std::io::stdout().as_fd().try_clone_to_owned() {
        Ok(fd) => {
            let file = std::fs::File::from(fd);
            let blksize = file.metadata().ok().map(|m| m.blksize());
            let line = file.is_terminal();
            (Box::new(file), buffer_size(blksize), line)
        }
        Err(_) => {
            let out = std::io::stdout();
            let line = out.is_terminal();
            (Box::new(out), BUFSIZ, line)
        }
    }
}

/// Off Unix, std's standard output.
#[cfg(not(unix))]
fn open_raw() -> (Raw, usize, bool) {
    use std::io::IsTerminal;
    let out = std::io::stdout();
    let line = out.is_terminal();
    (Box::new(out), 4096, line)
}

static STDOUT: Mutex<Option<Stdio<Raw>>> = Mutex::new(None);

/// Standard output, made as glibc makes stdout's buffer, at the first
/// output. Each write is [`Stdio::put`]: it never fails.
pub struct Stdout;

impl Write for Stdout {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        with(|s| s.put(data));
        Ok(data.len())
    }
    /// `fflush(stdout)`.
    fn flush(&mut self) -> io::Result<()> {
        with(Stdio::flush_now);
        Ok(())
    }
}

fn with(f: impl FnOnce(&mut Stdio<Raw>)) {
    let mut slot = STDOUT.lock().unwrap_or_else(|p| p.into_inner());
    let s = slot.get_or_insert_with(|| {
        let (raw, cap, line) = open_raw();
        Stdio::new(raw, cap, line)
    });
    f(s);
}

/// `exit(code)`: stdout flushed, as `exit()` flushes it, whatever that
/// gives, then the process ends with `code`.
pub fn exit(code: i32) -> ! {
    flush();
    std::process::exit(code)
}

/// `fflush(stdout)` where stdout has been written to.
pub fn flush() {
    let mut slot = STDOUT.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(s) = slot.as_mut() {
        s.flush_now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file that records each write and fails those `fail` says.
    struct Log {
        writes: Vec<Vec<u8>>,
        fail: Box<dyn FnMut(usize) -> Option<io::ErrorKind>>,
    }

    impl Write for Log {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            let n = self.writes.len();
            self.writes.push(data.to_vec());
            match (self.fail)(n) {
                Some(kind) => Err(kind.into()),
                None => Ok(data.len()),
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn log(fail: impl FnMut(usize) -> Option<io::ErrorKind> + 'static) -> Log {
        Log {
            writes: Vec::new(),
            fail: Box::new(fail),
        }
    }

    fn lens(s: &Stdio<Log>) -> Vec<usize> {
        s.raw.writes.iter().map(Vec::len).collect()
    }

    #[test]
    fn the_buffer_is_st_blksize_up_to_bufsiz() {
        assert_eq!(buffer_size(Some(4096)), 4096);
        assert_eq!(buffer_size(Some(512)), 512);
        assert_eq!(buffer_size(Some(8192)), 8192);
        assert_eq!(buffer_size(Some(65536)), 8192);
        assert_eq!(buffer_size(Some(0)), 8192);
        assert_eq!(buffer_size(None), 8192);
    }

    /// One write a full buffer, as glibc's: 4351 bytes are 4096 then 255,
    /// the 255 only at the flush (measured with strace on the C: `write(1,
    /// …, 4096)`, then the rest at `fflush()`).
    #[test]
    fn a_full_buffer_is_one_write_and_the_rest_waits_for_the_flush() {
        let mut s = Stdio::new(log(|_| None), 4096, false);
        for chunk in vec![b'x'; 4351].chunks(100) {
            s.put(chunk);
        }
        assert_eq!(lens(&s), [4096]);
        s.flush_now();
        assert_eq!(lens(&s), [4096, 255]);
        s.flush_now();
        assert_eq!(lens(&s), [4096, 255], "nothing held, nothing written");
        // Exactly full: not written until the next byte comes.
        let mut s = Stdio::new(log(|_| None), 128, false);
        s.put(&[b'x'; 128]);
        assert!(lens(&s).is_empty());
        s.put(b"9");
        assert_eq!(lens(&s), [128]);
        assert_eq!(s.held(), b"9");
    }

    /// A long write: the buffer, then whole blocks straight out, then the
    /// remainder kept.
    #[test]
    fn whole_blocks_go_straight_out() {
        let mut s = Stdio::new(log(|_| None), 128, false);
        s.put(b"ab");
        s.put(&[b'y'; 400]);
        assert_eq!(lens(&s), [128, 256]);
        assert_eq!(s.held().len(), 18);
        // Under 128 bytes a block, glibc writes all the rest at once.
        let mut s = Stdio::new(log(|_| None), 16, false);
        s.put(&[b'y'; 40]);
        assert_eq!(lens(&s), [16, 24]);
        assert!(s.held().is_empty());
    }

    /// A failed write empties the buffer and drops the rest of that call;
    /// the next writes are attempted again, as glibc's are, and nothing is
    /// reported (`/dev/full`, EPIPE under an ignored `SIGPIPE`).
    #[test]
    fn a_failed_write_drops_the_buffer_and_goes_on() {
        let mut s = Stdio::new(
            log(|n| (n == 0).then_some(io::ErrorKind::StorageFull)),
            128,
            false,
        );
        s.put(&[b'a'; 200]);
        assert_eq!(lens(&s), [128]);
        assert!(s.held().is_empty(), "the rest of the call dropped");
        assert!(s.err_seen);
        s.put(&[b'b'; 129]);
        assert_eq!(lens(&s), [128, 128]);
        assert_eq!(s.held(), b"b");
        // Always failing: one attempt a buffer, never a retry.
        let mut s = Stdio::new(log(|_| Some(io::ErrorKind::BrokenPipe)), 4096, false);
        if cfg!(unix) {
            for _ in 0..3 {
                for chunk in vec![b'x'; 4351].chunks(100) {
                    s.put(chunk);
                }
                s.flush_now();
            }
            // The 4 bytes of the write that filled the buffer past its end
            // are dropped with it: 4351 - 4100 = 251 are left for the flush.
            assert_eq!(lens(&s), [4096, 251, 4096, 251, 4096, 251]);
        }
        // Through `Write`: never an error.
        let mut s = Stdio::new(log(|_| Some(io::ErrorKind::StorageFull)), 4, false);
        assert!(s.write_all(b"0123456789").is_ok());
        assert!(s.flush().is_ok());
    }

    /// A short write: what went out stays out; the rest is dropped.
    #[test]
    fn a_short_write_keeps_what_went_out() {
        struct Short(Vec<Vec<u8>>);
        impl Write for Short {
            fn write(&mut self, d: &[u8]) -> io::Result<usize> {
                self.0.push(d.to_vec());
                if self.0.len() == 1 {
                    Ok(d.len() / 2)
                } else {
                    Err(io::ErrorKind::StorageFull.into())
                }
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut s = Stdio::new(Short(Vec::new()), 128, false);
        s.put(&[b'z'; 130]);
        let w: Vec<usize> = s.raw.0.iter().map(Vec::len).collect();
        assert_eq!(w, [128, 64]);
        assert!(s.held().is_empty());
    }

    /// On a terminal, line-buffered: a write with a newline goes out
    /// through its last newline.
    #[test]
    fn a_terminal_is_line_buffered() {
        let mut s = Stdio::new(log(|_| None), 4096, true);
        s.put(b"abc");
        assert!(lens(&s).is_empty());
        s.put(b"de\nfg");
        assert_eq!(s.raw.writes, [b"abcde\n".to_vec()]);
        assert_eq!(s.held(), b"fg");
    }
}
