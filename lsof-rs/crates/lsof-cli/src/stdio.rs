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
//! [`Stdio`] is that stream, glibc 2.39's own output path ported: a buffer
//! of `st_blksize` of stdout's file, at most `BUFSIZ` (8192), so 4096 on a
//! pipe (glibc's `_IO_file_doallocate()`), line-buffered on a terminal; and
//! the three ways the C writes to it, each as glibc makes it —
//! [`Stdio::printf`] (`vfprintf()`), [`Stdio::fputs`] and [`Stdio::puts`]
//! (`_IO_new_file_xsputn()`) and [`Stdio::putc`] — because which bytes a
//! failed write takes with it (the rest of the call it was made in), and
//! where a terminal's writes end, follow the calls and not only the bytes.
//! The renderers hand it the C's calls (`lsof_core::render::Calls`): each
//! `write()` to [`Stdout`] is one `printf()`. It never reports an error, so
//! nothing a caller does with the result can change what the run prints or
//! how it ends. Memory is the one buffer and a 128-byte stage, and a failing
//! write is never retried, so no loop spins on a dead reader: `-r` still
//! sleeps between its cycles.
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

/// A stdio stream over `raw`, the file itself, written unbuffered: glibc
/// 2.39's `FILE` as `libio/fileops.c` and `libio/genops.c` drive it for
/// output, with its pointers as offsets into one buffer of `cap` bytes,
/// allocated at the first overflow as `_IO_doallocbuf()` allocates it.
///
/// The C writes through three kinds of call, and each is ported as glibc
/// makes it, because which bytes a failed write takes with it, and on a
/// terminal where each `write(2)` ends, depend on the call:
/// [`Stdio::printf`] (`vfprintf()` through `__printf_buffer_to_file`:
/// straight into the stream's buffer while it has room, else a 128-byte
/// stage or a one-byte one), [`Stdio::fputs`] (`_IO_new_file_xsputn()`) and
/// [`Stdio::putc`] (`_IO_putc_unlocked()`). A failed write empties the
/// buffer and ends the call it happened in: what is left of that call is
/// dropped, as glibc's short count drops it, and the next call starts anew.
pub struct Stdio<W: Write> {
    raw: W,
    buf: Vec<u8>,
    cap: usize,
    /// `_IO_LINE_BUF`.
    line: bool,
    /// `_IO_CURRENTLY_PUTTING`.
    putting: bool,
    /// `_IO_write_base`, `_IO_write_ptr`, `_IO_write_end`: offsets in
    /// `buf`, all 0 (NULL) until it is allocated.
    base: usize,
    ptr: usize,
    end: usize,
    /// Whether a write has failed (`_IO_ERR_SEEN`). Kept, never acted on, as
    /// the C never calls `ferror()`.
    pub err_seen: bool,
    /// End the run with 141 where a write meets a closed pipe (off Unix).
    exit_on_broken_pipe: bool,
}

/// `PRINTF_BUFFER_SIZE_TO_FILE_STAGE`: the stage `vfprintf()` collects into
/// where the stream's buffer has no room (`include/printf_buffer.h`).
const STAGE: usize = 128;

impl<W: Write> Stdio<W> {
    /// A stream with a buffer of `cap` bytes, line-buffered if `line`.
    pub fn new(raw: W, cap: usize, line: bool) -> Self {
        Stdio {
            raw,
            buf: Vec::new(),
            cap: cap.max(1),
            line,
            putting: false,
            base: 0,
            ptr: 0,
            end: 0,
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

    /// `new_do_write()`: `data` written, then the buffer emptied whatever
    /// happened; how much went out.
    fn new_do_write(&mut self, data: Option<&[u8]>) -> usize {
        let count = match data {
            Some(d) => self.emit(d),
            None => {
                let held = std::mem::take(&mut self.buf);
                let n = self.emit(held.get(self.base..self.ptr).unwrap_or_default());
                self.buf = held;
                n
            }
        };
        self.base = 0;
        self.ptr = 0;
        self.end = if self.line { 0 } else { self.cap };
        count
    }

    /// `_IO_do_write()` of what the buffer holds (`_IO_do_flush()`): nothing
    /// done where it holds nothing; whether all of it went out.
    fn do_flush(&mut self) -> bool {
        let to_do = self.ptr.saturating_sub(self.base);
        to_do == 0 || self.new_do_write(None) == to_do
    }

    /// `_IO_new_file_overflow()`: the buffer made (at the first output),
    /// then, for `None` (`EOF`), what it holds written; for a byte, the
    /// buffer written if it is full, the byte put, and the buffer written
    /// again after a newline on a terminal. Whether that worked.
    fn overflow(&mut self, ch: Option<u8>) -> bool {
        if !self.putting || self.buf.is_empty() {
            if self.buf.is_empty() {
                self.buf = vec![0; self.cap];
            }
            self.ptr = 0;
            self.base = 0;
            self.end = self.cap;
            self.putting = true;
            if self.line {
                self.end = self.ptr;
            }
        }
        let Some(c) = ch else {
            return self.do_flush();
        };
        if self.ptr == self.cap && !self.do_flush() {
            return false;
        }
        if let Some(slot) = self.buf.get_mut(self.ptr) {
            *slot = c;
        }
        self.ptr = self.ptr.saturating_add(1);
        if self.line && c == b'\n' {
            return self.do_flush();
        }
        true
    }

    /// Copy `data` into the buffer at its write pointer (the caller has
    /// checked the room).
    fn copy_in(&mut self, data: &[u8]) {
        let at = self.ptr;
        if let Some(dst) = self.buf.get_mut(at..at.saturating_add(data.len())) {
            dst.copy_from_slice(data);
        }
        self.ptr = at.saturating_add(data.len());
    }

    /// `_IO_default_xsputn()`: what room there is, then a byte at a time
    /// through [`Stdio::overflow`]; how many bytes went in.
    fn default_xsputn(&mut self, data: &[u8]) -> usize {
        let mut i = 0usize;
        loop {
            if self.ptr < self.end {
                let n = (self.end - self.ptr).min(data.len() - i);
                self.copy_in(&data[i..i + n]);
                i += n;
            }
            let Some(&c) = data.get(i) else {
                break;
            };
            if !self.overflow(Some(c)) {
                break;
            }
            i += 1;
        }
        i
    }

    /// `_IO_new_file_xsputn()` (`fputs()`, `fwrite()`, `puts()`'s string):
    /// the room the buffer has (on a terminal, up to the call's last newline
    /// where it all fits), the buffer written, whole blocks straight out,
    /// the rest through `_IO_default_xsputn()`. Whether all of `data`
    /// went in.
    pub fn fputs(&mut self, data: &[u8]) -> bool {
        let n = data.len();
        if n == 0 {
            return true;
        }
        let mut to_do = n;
        let mut must_flush = false;
        let mut count = 0usize;
        if self.line && self.putting {
            count = self.cap.saturating_sub(self.ptr);
            if count >= n {
                if let Some(nl) = data.iter().rposition(|&b| b == b'\n') {
                    count = nl + 1;
                    must_flush = true;
                }
            }
        } else if self.end > self.ptr {
            count = self.end - self.ptr;
        }
        let mut s = 0usize;
        if count > 0 {
            let count = count.min(to_do);
            self.copy_in(&data[..count]);
            s = count;
            to_do -= count;
        }
        if to_do > 0 || must_flush {
            if !self.overflow(None) {
                return false;
            }
            let block = self.cap;
            let do_write = to_do - if block >= 128 { to_do % block } else { 0 };
            if do_write > 0 {
                let c = self.new_do_write(Some(&data[s..s + do_write]));
                to_do -= c;
                if c < do_write {
                    return false;
                }
            }
            if to_do > 0 {
                to_do -= self.default_xsputn(&data[s + do_write..]);
            }
        }
        to_do == 0
    }

    /// `_IO_putc_unlocked()` (`putc()`, `putchar()`): into the buffer where
    /// it has room, else through `_IO_new_file_overflow()`.
    pub fn putc(&mut self, c: u8) {
        if self.ptr >= self.end {
            self.overflow(Some(c));
        } else {
            self.copy_in(&[c]);
        }
    }

    /// `puts()`: the string through [`Stdio::fputs`], then, where all of it
    /// went in, a newline through [`Stdio::putc`].
    pub fn puts(&mut self, data: &[u8]) {
        if self.fputs(data) {
            self.putc(b'\n');
        }
    }

    /// One `printf()` whose output is `data`: `vfprintf()` through
    /// `__printf_buffer_to_file` (`stdio-common/printf_buffer_to_file.c`).
    /// While the stream's buffer has room the bytes go straight into it;
    /// once it is full, a one-byte stage, whose byte goes in through
    /// `__overflow()` when the next comes or the call ends; where the
    /// buffer has no room at the start (a terminal's never has), a 128-byte
    /// stage, put through [`Stdio::fputs`] each time it fills and at the
    /// end. A write that fails ends the call.
    pub fn printf(&mut self, data: &[u8]) {
        enum Mode {
            Direct,
            Stage(usize),
            One(Option<u8>),
        }
        let mut stage = [0u8; STAGE];
        // `__printf_buffer_to_file_switch()`.
        let switch = |s: &Self| {
            if s.ptr < s.end {
                Mode::Direct
            } else {
                Mode::Stage(0)
            }
        };
        let mut mode = switch(self);
        let mut i = 0usize;
        loop {
            match mode {
                Mode::Direct => {
                    let n = (self.end - self.ptr).min(data.len() - i);
                    self.copy_in(&data[i..i + n]);
                    i += n;
                    if i == data.len() {
                        return;
                    }
                    // The stream's buffer is full: a one-byte stage.
                    mode = Mode::One(None);
                }
                Mode::Stage(len) => {
                    let n = (STAGE - len).min(data.len() - i);
                    stage[len..len + n].copy_from_slice(&data[i..i + n]);
                    i += n;
                    let len = len + n;
                    if !self.fputs(&stage[..len]) {
                        return;
                    }
                    if i == data.len() {
                        return;
                    }
                    mode = switch(self);
                }
                Mode::One(held) => {
                    let Some(c) = held else {
                        match data.get(i) {
                            Some(&c) => {
                                i += 1;
                                mode = Mode::One(Some(c));
                                continue;
                            }
                            None => return,
                        }
                    };
                    if !self.overflow(Some(c)) || i == data.len() {
                        return;
                    }
                    mode = switch(self);
                }
            }
        }
    }

    /// `fflush()` (`_IO_new_file_sync()`): what the buffer holds, written in
    /// one attempt, then emptied.
    pub fn flush_now(&mut self) {
        if self.ptr > self.base {
            self.do_flush();
        }
    }

    /// What the buffer holds now.
    pub fn held(&self) -> &[u8] {
        self.buf.get(self.base..self.ptr).unwrap_or_default()
    }
}

impl<W: Write> Write for Stdio<W> {
    /// One `printf()`.
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.printf(data);
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

/// Elsewhere on Unix descriptor 1 itself, written through a duplicate made
/// for each write and closed after it (the same open file), so that lsof
/// holds no descriptor of its own between writes, as the C, which writes
/// through descriptor 1, holds none. A duplicate kept open for the run was
/// lsof's `3w` in its own listing from the second `-r` cycle on (the parity
/// review of the FreeBSD work, finding 7). Where no duplicate can be made
/// (every descriptor taken), std's standard output, flushed at once.
#[cfg(all(unix, not(target_os = "linux")))]
struct Fd1;

#[cfg(all(unix, not(target_os = "linux")))]
impl Write for Fd1 {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        use std::os::fd::AsFd;
        match std::io::stdout().as_fd().try_clone_to_owned() {
            Ok(fd) => std::fs::File::from(fd).write(data),
            Err(_) => {
                let mut out = std::io::stdout();
                let n = out.write(data)?;
                out.flush()?;
                Ok(n)
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn open_raw() -> (Raw, usize, bool) {
    use std::io::IsTerminal;
    use std::os::fd::AsFd;
    use std::os::unix::fs::MetadataExt;
    // The buffer's size and whether it is a line's, from a duplicate
    // closed again at once.
    let blksize = std::io::stdout()
        .as_fd()
        .try_clone_to_owned()
        .ok()
        .and_then(|fd| std::fs::File::from(fd).metadata().ok())
        .map(|m| m.blksize());
    let line = std::io::stdout().is_terminal();
    let size = buffer_size(blksize);
    (Box::new(Fd1), size, line)
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
/// output. Each write is one [`Stdio::printf`]: it never fails.
pub struct Stdout;

impl Write for Stdout {
    /// One `printf()`.
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        with(|s| s.printf(data));
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

/// `puts(s)` on standard output.
pub fn puts(data: &[u8]) {
    with(|s| s.puts(data));
}

/// `putchar(c)` on standard output.
pub fn putc(c: u8) {
    with(|s| s.putc(c));
}

/// `fputs(s, stdout)`.
pub fn fputs(data: &[u8]) {
    with(|s| {
        s.fputs(data);
    });
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

    /// Every expectation below is what glibc 2.39 does with the same calls
    /// on a stream given a buffer of that size with `setvbuf()`, writing to
    /// a file, its write results set with `strace -e inject=write:...`
    /// (measured; a driver compared this port with it over 850 random call
    /// sequences, line- and fully-buffered, failures injected, and found no
    /// difference in the bytes or the writes).
    fn calls(s: &mut Stdio<Log>, calls: &[(&str, &[u8])]) {
        for (kind, data) in calls {
            match *kind {
                "printf" => s.printf(data),
                "fputs" => {
                    s.fputs(data);
                }
                "putc" => s.putc(data[0]),
                "puts" => s.puts(data),
                _ => s.flush_now(),
            }
        }
    }

    fn fail_first(n: usize) -> Option<io::ErrorKind> {
        (n == 0).then_some(io::ErrorKind::WouldBlock)
    }

    /// One write a full buffer: 4351 bytes in `printf()`s of 100 are 4096
    /// then, at the flush, 255; a second flush writes nothing.
    #[test]
    fn a_full_buffer_is_one_write_and_the_rest_waits_for_the_flush() {
        let mut s = Stdio::new(log(|_| None), 4096, false);
        for chunk in vec![b'x'; 4351].chunks(100) {
            s.printf(chunk);
        }
        assert_eq!(lens(&s), [4096]);
        s.flush_now();
        s.flush_now();
        assert_eq!(lens(&s), [4096, 255]);
    }

    /// `fputs()` writes whole blocks past the buffer in one write;
    /// `printf()` a buffer at a time. The first call of all goes through
    /// the 128-byte stage, so a first `printf()` of 128 into a 128-byte
    /// buffer is one block, written at once.
    #[test]
    fn fputs_writes_whole_blocks_and_printf_a_buffer_at_a_time() {
        let mut s = Stdio::new(log(|_| None), 128, false);
        calls(&mut s, &[("fputs", b"ab"), ("fputs", &[b'y'; 400])]);
        assert_eq!(lens(&s), [128, 256]);
        assert_eq!(s.held().len(), 18);
        let mut s = Stdio::new(log(|_| None), 128, false);
        calls(&mut s, &[("printf", b"ab"), ("printf", &[b'y'; 400])]);
        assert_eq!(lens(&s), [128, 128, 128]);
        assert_eq!(s.held().len(), 18);
        let mut s = Stdio::new(log(|_| None), 128, false);
        s.printf(&[b'y'; 128]);
        assert_eq!(lens(&s), [128]);
        // Under 128 bytes a block, glibc writes all the rest at once.
        let mut s = Stdio::new(log(|_| None), 16, false);
        s.fputs(&[b'y'; 40]);
        assert_eq!(lens(&s), [40]);
        // A `printf()` with room in the buffer fills it directly, then goes
        // on a byte at a time through the overflow: a buffer a write, where
        // the 128-byte stage (an `fputs()`) would write the rest whole.
        let mut s = Stdio::new(log(|_| None), 16, false);
        calls(&mut s, &[("printf", b"ab"), ("printf", &[b'y'; 40])]);
        assert_eq!(lens(&s), [2, 16, 16]);
        assert_eq!(s.held().len(), 8);
    }

    /// A failed write empties the buffer and ends its call: the rest of a
    /// `printf()` is dropped, where a `putc()` loses its one byte and the
    /// next call starts anew. Nothing is reported (`/dev/full`, EPIPE under
    /// an ignored `SIGPIPE`, EAGAIN).
    #[test]
    fn a_failed_write_drops_the_buffer_and_the_rest_of_its_call() {
        let mut s = Stdio::new(log(fail_first), 128, false);
        calls(
            &mut s,
            &[
                ("printf", &[b'a'; 100]),
                ("printf", &[b'b'; 100]),
                ("printf", &[b'c'; 10]),
            ],
        );
        assert_eq!(lens(&s), [128]);
        assert_eq!(s.held(), [b'c'; 10]);
        assert!(s.err_seen);
        let mut s = Stdio::new(log(fail_first), 128, false);
        let b: &[u8] = b"b";
        calls(
            &mut s,
            &[
                ("printf", &[b'a'; 128]),
                ("putc", b),
                ("putc", b),
                ("putc", b),
            ],
        );
        assert_eq!(s.held(), b"bbb");
        // `puts()` adds no newline to a string that did not all go in.
        let mut s = Stdio::new(log(fail_first), 128, false);
        calls(&mut s, &[("printf", &[b'a'; 100]), ("puts", &[b'm'; 40])]);
        assert_eq!(s.held(), b"");
        let mut s = Stdio::new(log(|_| None), 128, false);
        calls(&mut s, &[("puts", b"mark")]);
        assert_eq!(s.held(), b"mark\n");
        // Always failing: one attempt a buffer, never a retry.
        let mut s = Stdio::new(log(|_| Some(io::ErrorKind::StorageFull)), 4096, false);
        for _ in 0..3 {
            for chunk in vec![b'x'; 4351].chunks(100) {
                s.printf(chunk);
            }
            s.flush_now();
        }
        // The 4 bytes of the `printf()` whose overflow failed go with it:
        // 4351 - 4100 = 251 are left for the flush.
        assert_eq!(lens(&s), [4096, 251, 4096, 251, 4096, 251]);
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
        s.fputs(&[b'z'; 130]);
        let w: Vec<usize> = s.raw.0.iter().map(Vec::len).collect();
        // `_IO_new_file_write()` goes on after a short count, and stops at
        // the error.
        assert_eq!(w, [128, 64]);
        assert!(s.held().is_empty());
    }

    /// On a terminal, line-buffered: a byte at a time through the overflow,
    /// a write at each newline; a call that fits goes out through its last
    /// newline in one write; a `printf()` goes through the 128-byte stage.
    #[test]
    fn a_terminal_is_line_buffered_as_glibc_writes_it() {
        let mut s = Stdio::new(log(|_| None), 4096, true);
        s.printf(b"ab\ncd\nef");
        assert_eq!(lens(&s), [3, 3]);
        assert_eq!(s.held(), b"ef");
        s.printf(b"gh\nij\nkl");
        assert_eq!(lens(&s), [3, 3, 8]);
        assert_eq!(s.held(), b"kl");
        let mut s = Stdio::new(log(|_| None), 4096, true);
        for c in b"ab\ncd\nef" {
            s.putc(*c);
        }
        assert_eq!(lens(&s), [3, 3]);
        let big = b"12345\n".repeat(30);
        let mut s = Stdio::new(log(|_| None), 64, true);
        calls(
            &mut s,
            &[("fputs", &[b'x'; 10]), ("fputs", &big), ("fputs", b"zz")],
        );
        assert_eq!(lens(&s), [10, 64, 116]);
        let mut s = Stdio::new(log(|_| None), 4096, true);
        s.printf(&big);
        // The first 128 bytes a byte at a time (the buffer is made in that
        // overflow), the next 52 as one call that fits: one write.
        let mut want = vec![6; 21];
        want.push(54);
        assert_eq!(lens(&s), want);
    }
}
