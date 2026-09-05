//! Default human-readable table renderer.
//!
//! Columns match classic lsof: `COMMAND PID [PPID] USER FD TYPE DEVICE SIZE/OFF
//! NODE NAME` (PPID only with `-R`). Numeric columns are right-aligned; the rest
//! are left-aligned; columns are padded to the widest cell.
//!
//! COMMAND, USER and NAME are escaped through [`Escaper`] before they are
//! measured or printed, as lsof's `print.c` does with `safestrprt()`: a process
//! or file named with an ESC sequence must not drive the terminal of whoever
//! runs lsof. Column widths are computed on the escaped text, so a `^[` counts
//! as the two columns it occupies.

use crate::model::{AccessMode, FdType, FileType, OpenFile, Process};
use crate::render::Escaper;
use crate::selection::{TcpInfoFlags, DEFAULT_COMMAND_WIDTH};

/// The `-T` annotation the table appends to a socket's NAME: **one**
/// parenthesised group, space-separated, e.g. `" (LISTEN QR=0 QS=12)"`.
///
/// One group, not one per fact — the C's `print_tcptpi()` opens the paren on
/// whichever item prints first and closes it once at the end. The order is
/// fixed by that function and does not follow the order of the `-T` letters:
/// state, then read queue, then send queue.
///
/// `show` selects; it does not add. A row whose selected facts are all absent
/// still gets the **separator space**, and nothing after it: `print.c` writes
/// that space before calling `print_tcptpi()`, on the strength of `Ftcptpi`
/// being non-zero and the row being a resolved socket, and only then discovers
/// there is nothing to print. `lsof -T f` on Linux leaves one on every socket
/// row for exactly this reason. Reproduced rather than tidied — a byte-diff of
/// the two binaries should be clean, and the differential's normalizer strips
/// trailing whitespace, so a golden test is what holds it.
///
/// AF_UNIX rows need no special case here even though the C has one: its
/// `print_unix()` honours only the state, and a unix row never carries queues,
/// so selecting them yields nothing on its own.
fn tcp_suffix(f: &OpenFile, show: TcpInfoFlags) -> String {
    let Some(sock) = f.socket.as_ref() else {
        return String::new();
    };
    if !show.any() {
        return String::new();
    }
    let mut parts: Vec<String> = Vec::new();
    if show.state {
        if let Some(st) = sock.state {
            parts.push(st.as_str().to_string());
        }
    }
    if let Some(tcp) = sock.tcp.as_ref() {
        if show.window {
            if let Some(w) = tcp.recv_window {
                parts.push(format!("Win={w}"));
            }
        }
        if show.queue {
            if let Some(q) = tcp.recv_queue {
                parts.push(format!("QR={q}"));
            }
            if let Some(q) = tcp.send_queue {
                parts.push(format!("QS={q}"));
            }
        }
    }
    // The separator, then the group if there turned out to be one.
    let mut out = String::from(" ");
    if !parts.is_empty() {
        out.push('(');
        out.push_str(&parts.join(" "));
        out.push(')');
    }
    out
}

/// Render the FD cell, e.g. `cwd`, `txt`, `3u`, or `3uW` — handle value,
/// access character, then the lock character when the file is locked.
fn fd_cell(f: &OpenFile) -> String {
    let mut s = match f.fd {
        FdType::Handle(n) => {
            if f.access == AccessMode::Unknown {
                n.to_string()
            } else {
                format!("{}{}", n, f.access.code())
            }
        }
        _ => f.fd.code(),
    };
    if let Some(lock) = f.lock {
        s.push(lock.code());
    }
    s
}

/// Render the SIZE/OFF cell. By default prefer size; with `prefer_offset`
/// (lsof `-o`) prefer the file offset, shown as `0t<dec>`.
fn size_off_cell(f: &OpenFile, prefer_offset: bool) -> String {
    let off = f.offset.map(|o| format!("0t{o}"));
    let sz = f.size.map(|s| s.to_string());
    if prefer_offset {
        off.or(sz).unwrap_or_default()
    } else {
        sz.or(off).unwrap_or_default()
    }
}

/// `-t`: unique PIDs, ascending, one per line.
fn render_terse(procs: &[Process]) -> String {
    let mut pids: Vec<u32> = procs.iter().map(|p| p.pid).collect();
    pids.sort_unstable();
    pids.dedup();
    let mut s = String::new();
    for pid in pids {
        s.push_str(&pid.to_string());
        s.push('\n');
    }
    s
}

/// How the table is drawn. Every field is one lsof option, named, because the
/// list had grown to six positional `bool`s and an `Option` — a shape where
/// transposing two of them compiles and silently renders the wrong table.
///
/// [`TableOpts::new`] is a plain `lsof` run: no `-t`/`-R`/`-o`/`-L`, the
/// default 9-character COMMAND cap, and `-T`'s state-only default.
#[derive(Clone, Copy, Debug)]
pub struct TableOpts {
    /// `-t`: unique PIDs, one per line, nothing else.
    pub terse: bool,
    /// `-R`: a PPID column after PID.
    pub show_ppid: bool,
    /// `-o`: SIZE/OFF prefers the file offset.
    pub show_offset: bool,
    /// `-L`: an NLINK column.
    pub show_links: bool,
    /// `+c`: the COMMAND cap in printed characters, `None` for `+c 0` (no cap).
    /// This is the C's `CmdLim`, which is a cap on each row's *contribution* to
    /// the column width, not the width itself — see [`render`].
    pub command_width: Option<usize>,
    /// `-T`: which TCP/TPI facts a socket row's NAME is annotated with.
    pub tcp_show: TcpInfoFlags,
    /// The platform's backslash rule.
    pub esc: Escaper,
}

impl TableOpts {
    /// A plain `lsof` run on `esc`'s platform.
    pub fn new(esc: Escaper) -> Self {
        Self {
            terse: false,
            show_ppid: false,
            show_offset: false,
            show_links: false,
            command_width: Some(DEFAULT_COMMAND_WIDTH),
            tcp_show: TcpInfoFlags::DEFAULT,
            esc,
        }
    }
}

/// Render `procs` as the default table (or terse list when `opts.terse`).
///
/// The COMMAND column is sized the way the C's `print_proc()` does it, in two
/// passes, and the distinction matters whenever `+c` is small: each row
/// contributes `min(escaped length, +c)` to the width, the column is at least
/// as wide as its `COMMAND` header, and the **cut happens at that final width**
/// rather than at the `+c` number. So `+c 5` still prints seven characters —
/// `CmdColW` starts at `strlen("COMMAND")` and `safestrprtn(cp, CmdColW, …)`
/// is what truncates.
pub fn render(procs: &[Process], opts: TableOpts) -> String {
    let TableOpts {
        terse,
        show_ppid,
        show_offset,
        show_links,
        command_width,
        tcp_show,
        esc,
    } = opts;
    if terse {
        return render_terse(procs);
    }

    // Pass one over the COMMAND column: the width every cell is then cut to.
    let cmd_cut = procs.iter().fold("COMMAND".len(), |w, p| {
        let len = esc.command(&p.command).len();
        w.max(command_width.map_or(len, |n| len.min(n)))
    });

    // Build the column header set (PPID optional).
    let mut headers: Vec<&str> = vec!["COMMAND", "PID"];
    if show_ppid {
        headers.push("PPID");
    }
    headers.extend(["USER", "FD", "TYPE", "DEVICE", "SIZE/OFF"]);
    if show_links {
        headers.push("NLINK");
    }
    headers.extend(["NODE", "NAME"]);
    let right = ["PID", "PPID", "SIZE/OFF", "NLINK"];

    let row_for = |p: &Process, f: &OpenFile| -> Vec<String> {
        // Escaped and cut the way the C's safestrprtn() does it:
        // whitespace-free, pure ASCII, and a cut that never leaves half an
        // escape at the end of the cell. `cmd_cut` is the column width from
        // pass one, not the `+c` number.
        let cmd = esc.command_truncated(&p.command, cmd_cut);
        let mut r = vec![cmd, p.pid.to_string()];
        if show_ppid {
            r.push(p.ppid.map(|v| v.to_string()).unwrap_or_default());
        }
        r.push(
            p.user
                .as_deref()
                .map(|u| esc.text(u).into_owned())
                .unwrap_or_default(),
        );
        r.push(fd_cell(f));
        r.push(f.file_type.code());
        r.push(f.device.clone().unwrap_or_default());
        r.push(size_off_cell(f, show_offset));
        if show_links {
            r.push(f.links.map(|n| n.to_string()).unwrap_or_default());
        }
        r.push(f.node.clone().unwrap_or_default());
        // `-T q/w` extended TCP info renders as a NAME suffix in the table
        // only; machine formats carry it structured (`-F` T tokens, JSON keys).
        // The suffix is generated here, so only the name itself is escaped.
        let mut name = esc.text(&f.name).into_owned();
        // The `-T` annotation is a *table* decoration: `-F` reports the same
        // facts as `TST=`/`TQR=`/`TQS=` tokens and JSON as its own keys, so it
        // is appended here rather than stored in the name.
        name.push_str(&tcp_suffix(f, tcp_show));
        r.push(name);
        r
    };

    let mut rows: Vec<Vec<String>> = Vec::new();
    for p in procs {
        if p.files.is_empty() {
            // A selected process with no displayed files still gets a line so it
            // shows up (NAME left blank), mirroring lsof.
            let blank = OpenFile {
                fs_device: None,
                file_flags: None,
                lock: None,
                fd: FdType::Unknown,
                access: AccessMode::Unknown,
                file_type: FileType::Unknown,
                name: String::new(),
                device: None,
                size: None,
                offset: None,
                node: None,
                links: None,
                socket: None,
            };
            rows.push(row_for(p, &blank));
        }
        for f in &p.files {
            rows.push(row_for(p, f));
        }
    }

    // Nothing matched: emit nothing at all (no bare header), like lsof.
    if rows.is_empty() {
        return String::new();
    }

    let ncols = headers.len();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for r in &rows {
        for (i, cell) in r.iter().enumerate() {
            widths[i] = widths[i].max(cell.len());
        }
    }

    let mut out = String::new();
    let mut emit = |cells: &[String]| {
        for (i, cell) in cells.iter().enumerate() {
            if i == ncols - 1 {
                out.push_str(cell); // NAME: no trailing padding
            } else if right.contains(&headers[i]) {
                out.push_str(&format!("{cell:>width$} ", width = widths[i]));
            } else {
                out.push_str(&format!("{cell:<width$} ", width = widths[i]));
            }
        }
        out.push('\n');
    };

    let header_cells: Vec<String> = headers.iter().map(|h| h.to_string()).collect();
    emit(&header_cells);
    for r in &rows {
        emit(r);
    }
    out
}
