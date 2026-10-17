//! JSON renderers: `-J`, one document, and `-j`, JSON Lines.
//!
//! The C has had both since its PR #353 (2026-03), and this is its schema,
//! measured against it key by key (`src/print.c:1896-2175`): `-J` prints
//! `{"lsof_version":V,"processes":[...]}` on one line, each process with a
//! `files` array; `-j` prints one object per file, the process's keys and then
//! the file's, with no envelope. Every key is one `-F` letter, printed when
//! that letter is selected and its value is known, never as `null`; with no
//! `-F` selection, the C's default set is printed, with the file flags and
//! every TCP/TPI member forced on ([`JsonOpts`]).
//!
//! Where lsof-rs differs from the C it does so on purpose, each a C-DEFECT
//! row in DIVERGENCES: an Internet row has a `name` (the `-F n` text), where
//! the C prints none; DEL, the C1 controls and U+2028/U+2029 are escaped,
//! where the C writes them raw; a uid is unsigned (row 68).
//!
//! Hand-written to keep `lsof-core` dependency-free, and written into the
//! caller's sink one process at a time rather than built whole.

use std::io::{self, Write};

use crate::model::{FdType, FileType, OpenFile, Process};
use crate::render::escape::is_unprintable_unicode;
use crate::render::fflags::{self, FileFlags};
use crate::render::fields::field_is_default;
use crate::render::{access_code, device_text, lock_code, node_is_protocol, tcp_info_socket};
use crate::selection::TcpInfoFlags;

/// What a JSON run prints, resolved from its options by the CLI.
#[derive(Clone, Copy, Debug)]
pub struct JsonOpts<'a> {
    /// The `-F` letters selected, or `None` for the C's default set
    /// ([`field_is_default`]). `pid` is printed either way, as the C's `p` is
    /// always selected.
    pub only: Option<&'a [char]>,
    /// Which `tcp_info` members are printed: `-T`'s selection under an
    /// explicit `-F`, all of them by default (`select_default_fields()` ORs
    /// `TCPTPI_ALL` in after every option is read, so `-J -Tq` is `-J`).
    pub tcp_show: TcpInfoFlags,
    /// How `flags` is printed (`print_fflags()`), or not at all.
    pub file_flags: FileFlags,
    /// `-l`: no `login` key, as the C prints none then.
    pub numeric_ids: bool,
    /// `lsof_version`: lsof-rs's own version, never the C's it follows.
    pub version: &'a str,
}

impl JsonOpts<'_> {
    fn want(&self, c: char) -> bool {
        self.only
            .map_or_else(|| field_is_default(c), |s| s.contains(&c))
    }
}

/// Append `s` as a JSON string, quotes included: the C's
/// `json_puts_escaped()` (`print.c:103-146`) — `\"`, `\\`, `\b`, `\f`, `\n`,
/// `\r`, `\t`, any other C0 control as `\u` and four lowercase hex digits —
/// and, where the C passes them raw, DEL, the C1 controls and U+2028/U+2029
/// the same way: a document is read on terminals too (U+009B is the 8-bit
/// CSI), and the two separators end a line to JavaScript and to some
/// line-oriented readers of `-j`. A decoder recovers the same string
/// (DIVERGENCES, the escape row).
fn push_str(o: &mut String, s: &str) {
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\u{8}' => o.push_str("\\b"),
            '\u{c}' => o.push_str("\\f"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if is_unprintable_unicode(c) => {
                // Infallible: a String sink.
                let _ = std::fmt::Write::write_fmt(o, format_args!("\\u{:04x}", u32::from(c)));
            }
            c => o.push(c),
        }
    }
    o.push('"');
}

/// One object's members, comma-joined as they are added.
struct Members<'o> {
    out: &'o mut String,
    first: bool,
}

impl<'o> Members<'o> {
    fn new(out: &'o mut String) -> Self {
        Self { out, first: true }
    }

    fn key(&mut self, k: &str) -> &mut String {
        if !self.first {
            self.out.push(',');
        }
        self.first = false;
        self.out.push('"');
        self.out.push_str(k);
        self.out.push_str("\":");
        self.out
    }

    fn str(&mut self, k: &str, v: &str) {
        push_str(self.key(k), v);
    }

    fn num(&mut self, k: &str, v: impl std::fmt::Display) {
        let o = self.key(k);
        // Infallible: a String sink.
        let _ = std::fmt::Write::write_fmt(o, format_args!("{v}"));
    }
}

/// The process's keys, in the C's order (`json_print_proc_fields()`,
/// `print.c:2049-2093`): pid, tid, task_cmd, pgid, ppid, command, uid, login.
fn proc_members(m: &mut Members<'_>, p: &Process, o: &JsonOpts<'_>) {
    m.num("pid", p.pid);
    if o.want('K') {
        if let Some(tid) = p.tid {
            m.num("tid", tid);
        }
    }
    if o.want('M') {
        if let Some(tc) = &p.task_command {
            m.str("task_cmd", tc);
        }
    }
    if o.want('g') {
        if let Some(pgid) = p.pgid {
            m.num("pgid", pgid);
        }
    }
    if o.want('R') {
        if let Some(ppid) = p.ppid {
            m.num("ppid", ppid);
        }
    }
    // The full command: `+c` cuts the table's column alone.
    if o.want('c') {
        m.str("command", &p.command);
    }
    // Unsigned, where the C casts it to int (DIVERGENCES 68).
    if o.want('u') {
        if let Some(uid) = p.uid {
            m.num("uid", uid);
        }
    }
    if o.want('L') && !o.numeric_ids {
        if let Some(login) = &p.user {
            m.str("login", login);
        }
    }
}

/// The file's keys, in the C's order (`json_print_file()`,
/// `print.c:1911-2043`), each from the same value `-F` prints for its letter.
fn file_members(m: &mut Members<'_>, f: &OpenFile, o: &JsonOpts<'_>) {
    if o.want('f') {
        match f.fd {
            FdType::Handle(n) => m.str("fd", &n.to_string()),
            _ => m.str("fd", &f.fd.code()),
        }
    }
    // A blank access or lock letter is no key, where `-F` prints a space.
    if o.want('a') {
        if let Some(a) = access_code(f) {
            m.str("access", a.encode_utf8(&mut [0; 4]));
        }
    }
    if o.want('l') {
        if let Some(l) = lock_code(f) {
            m.str("lock", l.encode_utf8(&mut [0; 4]));
        }
    }
    if o.want('t') && f.file_type.has_code() {
        m.str("type", &f.file_type.code());
    }
    if o.want('d') {
        if let Some(d) = device_text(f) {
            m.str("device", d);
        }
    }
    // From `fs_device` itself: a socket's and an `-e` row's too, which the C
    // prints, though no path argument ever compares them.
    if o.want('D') {
        if let Some(dev) = f.fs_device {
            m.str("device_number", &format!("0x{dev:x}"));
        }
    }
    if o.want('r') {
        if let Some(rdev) = f.rdev {
            m.str("raw_device", &format!("0x{:x}", rdev.get()));
        }
    }
    if o.want('s') {
        if let Some(s) = f.size {
            m.str("size", &s.to_string());
        }
    }
    // Plain decimal whatever `-o` says: the C prints it `PRIu64`
    // (`print.c:1965-1970`), not as the table's `0t`/`0x`.
    if o.want('o') {
        if let Some(off) = f.offset {
            m.str("offset", &off.to_string());
        }
    }
    let protocol = node_is_protocol(f);
    if o.want('i') && !protocol {
        if let Some(n) = &f.node {
            m.str("inode", n);
        }
    }
    if o.want('k') {
        if let Some(n) = f.links {
            m.num("nlink", n);
        }
    }
    if o.want('P') && protocol {
        if let Some(n) = &f.node {
            m.str("protocol", n);
        }
    }
    if o.want('G') {
        if let Some(g) = f.file_flags.filter(|&g| fflags::shown(g, o.file_flags)) {
            m.str("flags", &fflags::text(g, o.file_flags));
        }
    }
    // The C's `Lf->nm`, never its addition (`(readlink: …)`, `(-e FS)`, …),
    // and none for `NOFD`, whose NAME is all addition.
    if o.want('n') {
        if let Some(n) = f.base_name() {
            m.str("name", n);
        }
    }
    if o.want('T') {
        if let Some(sock) = tcp_info_socket(f) {
            let t = m.key("tcp_info");
            t.push('{');
            let mut tm = Members::new(t);
            // Never a unix row's: the C's writer reads a state the unix path
            // never sets, and prints `{}` (measured, DIVERGENCES 91).
            if o.tcp_show.state && f.file_type != FileType::Unix {
                if let Some(st) = sock.shown_state() {
                    tm.str("state", st.as_str());
                }
            }
            if let Some(tcp) = &sock.tcp {
                if o.tcp_show.queue {
                    if let Some(q) = tcp.recv_queue {
                        tm.num("recv_queue", q);
                    }
                    if let Some(q) = tcp.send_queue {
                        tm.num("send_queue", q);
                    }
                }
                if o.tcp_show.window {
                    if let Some(w) = tcp.recv_window {
                        tm.num("read_window", w);
                    }
                }
            }
            t.push('}');
        }
    }
}

/// `-J`: `{"lsof_version":V,"processes":[...]}` and a newline, written to `w`
/// one process at a time. A process with no file left prints nothing, as in
/// the C; an empty result is the envelope alone.
pub fn write_aggregated<W: Write + ?Sized>(
    w: &mut W,
    procs: &[Process],
    o: &JsonOpts<'_>,
) -> io::Result<()> {
    let mut buf = String::from("{\"lsof_version\":");
    push_str(&mut buf, o.version);
    buf.push_str(",\"processes\":[");
    let mut first = true;
    for p in procs.iter().filter(|p| !p.files.is_empty()) {
        if !first {
            buf.push(',');
        }
        first = false;
        buf.push('{');
        let mut m = Members::new(&mut buf);
        proc_members(&mut m, p, o);
        m.key("files").push('[');
        for (i, f) in p.files.iter().enumerate() {
            if i > 0 {
                buf.push(',');
            }
            buf.push('{');
            file_members(&mut Members::new(&mut buf), f, o);
            buf.push('}');
        }
        buf.push_str("]}");
        w.write_all(buf.as_bytes())?;
        buf.clear();
    }
    buf.push_str("]}\n");
    w.write_all(buf.as_bytes())
}

/// `-j`: one object per file, the process's keys and then the file's, each
/// ending in a newline; no envelope and no version.
pub fn write_lines<W: Write + ?Sized>(
    w: &mut W,
    procs: &[Process],
    o: &JsonOpts<'_>,
) -> io::Result<()> {
    let mut head = String::new();
    let mut buf = String::new();
    for p in procs {
        head.clear();
        proc_members(&mut Members::new(&mut head), p, o);
        for f in &p.files {
            buf.clear();
            buf.push('{');
            buf.push_str(&head);
            let mut m = Members {
                out: &mut buf,
                first: head.is_empty(),
            };
            file_members(&mut m, f, o);
            buf.push_str("}\n");
            w.write_all(buf.as_bytes())?;
        }
    }
    Ok(())
}

/// [`write_aggregated`] into a `String`.
pub fn render_aggregated(procs: &[Process], o: &JsonOpts<'_>) -> String {
    let mut v = Vec::new();
    // A Vec sink cannot fail, and every byte written came from a `str`.
    let _ = write_aggregated(&mut v, procs, o);
    String::from_utf8(v).unwrap_or_default()
}

/// [`write_lines`] into a `String`.
pub fn render_lines(procs: &[Process], o: &JsonOpts<'_>) -> String {
    let mut v = Vec::new();
    // A Vec sink cannot fail, and every byte written came from a `str`.
    let _ = write_lines(&mut v, procs, o);
    String::from_utf8(v).unwrap_or_default()
}
