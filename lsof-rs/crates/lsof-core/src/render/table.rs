//! Default human-readable table renderer.
//!
//! Columns match classic lsof: `COMMAND PID [TID TASKCMD] [PPID] [PGID] USER FD
//! TYPE DEVICE SIZE/OFF [NLINK] NODE NAME`, and so does their layout, which is
//! `print.c`'s byte for byte (DIVERGENCES 35): every column is right-aligned
//! except COMMAND and TASKCMD, NAME is not padded at all, one space separates
//! each pair, and the FD cell is the descriptor right-aligned with its access
//! and lock characters after it — see [`Col`].
//!
//! COMMAND, USER and NAME are escaped through [`Escaper`] before they are
//! measured or printed, as lsof's `print.c` does with `safestrprt()`: a process
//! or file named with an ESC sequence must not drive the terminal of whoever
//! runs lsof. Column widths are computed on the escaped text, so a `^[` counts
//! as the two columns it occupies.

use std::io::{self, Write};

use crate::model::{AccessMode, FdType, FileType, OpenFile, Process, Protocol};
use crate::render::{offset_text, Escaper, DEFAULT_OFFSET_DIGITS};
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
    // Only a row the C keeps a TCP/TPI record for: `Lf->lts.type >= 0`, which
    // the Linux dialect sets for TCP, UDP and AF_UNIX sockets and for nothing
    // else. A packet, raw or ICMP row gets no separator — measured once the
    // differential compared whitespace (DIVERGENCES 35): lsof-rs had ended
    // every packet-socket NAME with a space the C does not print.
    let annotated =
        matches!(sock.protocol, Protocol::Tcp | Protocol::Udp) || f.file_type == FileType::Unix;
    if !annotated {
        return String::new();
    }
    let mut parts: Vec<String> = Vec::new();
    if show.state {
        if let Some(st) = sock.shown_state() {
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

/// The FD cell's name part: `cwd`, `txt`, `NOFD`, or the descriptor number.
fn fd_name(f: &OpenFile) -> String {
    match f.fd {
        FdType::Handle(n) => n.to_string(),
        _ => f.fd.code(),
    }
}

/// The FD cell's two trailing characters, always both present: the access
/// letter and the lock letter, each a space when there is none — `print.c`'s
/// `%c%c` after the descriptor. A lock on a file whose access is unknown shows
/// `-` in the access place, as the C does, so the lock is never read as one.
///
/// Only a numbered descriptor shows an access letter. The C prints the field
/// for every row, but no named one (`cwd`, `txt`, `mem`, …) ever has an
/// access mode there; a backend that records one for them is not shown it.
fn fd_mode(f: &OpenFile) -> String {
    let access = match (&f.fd, f.access) {
        (FdType::Handle(_), mode) if mode != AccessMode::Unknown => mode.code(),
        _ => ' ',
    };
    match f.lock {
        None => format!("{access} "),
        Some(lock) => {
            let access = if access == ' ' { '-' } else { access };
            format!("{access}{}", lock.code())
        }
    }
}

/// `-H`: a byte count the way the C's `human_readable_size()` writes it
/// (`print.c`), which is not the same as any common `-h` implementation and is
/// reproduced here rather than approximated.
///
/// Under 1024 the raw count gets a `B` suffix (`0B`, `1023B`). At or above it,
/// the C walks powers of 1024 and formats `%.1lf` with a one-letter suffix.
/// Two details of that walk are load-bearing:
///
/// * **The divide is integer, then floating.** `(sz / (unit / 1024)) / 1024.0`
///   truncates before it scales, so `2125328` is `2.0M` rather than `2.03M`.
/// * **The suffix is chosen before rounding**, so a size just under a boundary
///   renders as `1024.0K` — not `1.0M`. `1048575`, `1073741823` and
///   `1099511627775` all do this, and the oracle confirms it; rounding first
///   would be tidier and wrong.
///
/// Ties round half-to-even, as C's `%.1lf` does under the default rounding
/// mode: `174336` is exactly `170.25` KiB and prints `170.2K`.
pub(crate) fn human_size(sz: u64) -> String {
    const BASE: u64 = 1024;
    const SUFFIX: [&str; 6] = ["K", "M", "G", "T", "P", "E"];
    if sz < BASE {
        return format!("{sz}B");
    }
    let (mut unit, mut upper, mut i) = (BASE, BASE * BASE, 0usize);
    while i < SUFFIX.len() - 1 {
        if sz < upper {
            break;
        }
        unit = upper;
        // The C lets this overflow on the last pass and never reads it; keep
        // the same control flow without the panic.
        upper = upper.saturating_mul(BASE);
        i += 1;
    }
    let val = (sz / (unit / BASE)) as f64 / BASE as f64;
    format!("{val:.1}{}", SUFFIX[i])
}

/// The one column lsof spends on size **or** offset, in its three modes —
/// `print.c`'s header choice and cell test, measured against the C:
///
/// | mode | header | a row with a size | a row with only an offset | neither |
/// |---|---|---|---|---|
/// | default | `SIZE/OFF` | the size | the offset | blank |
/// | `-o` | `OFFSET` | **its offset**, or blank | the offset | blank |
/// | `-s` | `SIZE` | the size | **blank** | blank |
///
/// The `-o` column is not "prefer the offset": `cwd`, `rtd`, `txt` and `mem`
/// have a size and no offset (there is no fdinfo behind them), and the C
/// leaves them blank rather than falling back. lsof-rs fell back and kept the
/// `SIZE/OFF` header, which read as a size column (DIVERGENCES 6).
///
/// `human` is `-H`, and it scales **only the size**: the C humanises inside
/// the `sz_def` branch alone, so an offset stays `0t<dec>` under `-H`.
fn size_off_cell(f: &OpenFile, mode: SizeOff, human: bool, digits: usize) -> String {
    if mode != SizeOff::Offset {
        if let Some(s) = f.size {
            return if human { human_size(s) } else { s.to_string() };
        }
    }
    if mode != SizeOff::Size {
        if let Some(o) = f.offset {
            return offset_text(o, digits);
        }
    }
    String::new()
}

/// Which of the three SIZE/OFF modes a run is in — `-o`, `-s`, or neither.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SizeOff {
    Both,
    Offset,
    Size,
}

impl SizeOff {
    fn header(self) -> &'static str {
        match self {
            SizeOff::Both => "SIZE/OFF",
            SizeOff::Offset => "OFFSET",
            SizeOff::Size => "SIZE",
        }
    }
}

/// `-t`: unique PIDs, ascending, one per line.
fn render_terse(w: &mut dyn Write, procs: &[Process]) -> io::Result<()> {
    let mut pids: Vec<u32> = procs.iter().map(|p| p.pid).collect();
    pids.sort_unstable();
    pids.dedup();
    for pid in pids {
        writeln!(w, "{pid}")?;
    }
    Ok(())
}

/// Every row the table prints, in order: each file of each process, and one
/// blank row for a selected process with no displayed files (it still gets a
/// line, NAME left blank, as lsof prints it).
fn rows_of<'a>(
    procs: &'a [Process],
    blank: &'a OpenFile,
) -> impl Iterator<Item = (&'a Process, &'a OpenFile)> + 'a {
    procs.iter().flat_map(move |p| {
        let files: &'a [OpenFile] = if p.files.is_empty() {
            std::slice::from_ref(blank)
        } else {
            &p.files
        };
        files.iter().map(move |f| (p, f))
    })
}

/// How one column is laid out — its `print.c` format.
///
/// Every column the C prints is `%*s` or `%*d`, right-aligned, except COMMAND
/// and TASKCMD, which `safestrprtn()` pads on the right. Each is preceded by
/// one space, NAME included, and none is followed by one: a row whose NAME is
/// empty ends in that space. Two columns bend the rule, and the C's output
/// shows both:
///
/// * **FD** is two cells glued together: the descriptor right-aligned in the
///   width of the longest one, then its two mode characters (see [`fd_mode`]).
///   The C sizes it as `FdColW = max(strlen("FD"), len(fd) + 2)` and prints
///   the title in `FdColW - 2`, so the title does not widen the column: when
///   every descriptor is one character the `FD` title overruns its field by
///   one and pushes the rest of the header right, measured with `-d 0-9`.
/// * **NLINK**'s cell is formatted `" %ld"`, leading space included, before it
///   is measured and right-aligned — so the column is one wider than its
///   widest count whenever that count is five digits or more.
#[derive(Clone, Copy)]
struct Col {
    title: &'static str,
    right: bool,
    /// Whether the title counts toward the width (the C's `strlen(TTL)` seed).
    seeded: bool,
    /// Printed straight after the previous cell, with no separating space.
    glued: bool,
}

impl Col {
    const fn right(title: &'static str) -> Self {
        Self {
            title,
            right: true,
            seeded: true,
            glued: false,
        }
    }
    const fn left(title: &'static str) -> Self {
        Self {
            title,
            right: false,
            seeded: true,
            glued: false,
        }
    }
}

/// The descriptor half of FD: right-aligned, and not widened by its title.
const FD_NAME: Col = Col {
    title: "FD",
    right: true,
    seeded: false,
    glued: false,
};

/// The mode half of FD: two characters, glued to the descriptor, untitled —
/// its two header spaces are the two it takes in every row.
const FD_MODE: Col = Col {
    title: "",
    right: false,
    seeded: false,
    glued: true,
};

/// One line: every cell but NAME padded to its column's width the column's
/// way, NAME written as it is. Straight to `w` — `format!` per cell would
/// allocate a string only to copy it into the output.
fn emit_line<S: AsRef<str>>(
    w: &mut dyn Write,
    cells: &[S],
    widths: &[usize],
    cols: &[Col],
) -> io::Result<()> {
    let last = cols.len() - 1;
    for (i, cell) in cells.iter().enumerate() {
        let cell = cell.as_ref();
        if i > 0 && !cols[i].glued {
            w.write_all(b" ")?;
        }
        if i == last {
            w.write_all(cell.as_bytes())?; // NAME: never padded
        } else if cols[i].right {
            write!(w, "{cell:>width$}", width = widths[i])?;
        } else {
            write!(w, "{cell:<width$}", width = widths[i])?;
        }
    }
    w.write_all(b"\n")
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
    /// `-g`: a PGID column, after PPID when both are shown (`print.c`).
    pub show_pgid: bool,
    /// `-o`: the column shows offsets only, headed `OFFSET`. Wins over
    /// [`TableOpts::show_size`], though the parser never lets both through.
    pub show_offset: bool,
    /// `-s` with no value: the column shows sizes only, headed `SIZE`.
    pub show_size: bool,
    /// `-o <digits>`: offsets longer than this many decimal digits print in
    /// hex; 0 is no limit. [`DEFAULT_OFFSET_DIGITS`] otherwise.
    pub offset_digits: usize,
    /// `-H`: render the SIZE cell as a human-readable byte count. Affects the
    /// table only — the C leaves `-F` and its JSON untouched, and so does this.
    pub human_size: bool,
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
            show_pgid: false,
            show_offset: false,
            show_size: false,
            offset_digits: DEFAULT_OFFSET_DIGITS,
            human_size: false,
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
    let mut buf = Vec::new();
    render_to(&mut buf, procs, opts).expect("writing to a Vec cannot fail");
    String::from_utf8(buf).expect("every cell is a String, so the table is UTF-8")
}

/// [`render`], written to `w` as it goes.
///
/// Two passes over the rows, and neither keeps them: the first sizes every
/// column, the second formats each line again and writes it. That is how the
/// C does it — `print.c` sizes its columns over `Lproc[]` and then prints each
/// line with `printf` — and it is not how this function used to: it built a
/// `Vec<Vec<String>>` of every cell of every row, then a `String` of the whole
/// output, and only then printed. At 1079 processes that was a second and a
/// third full copy of the table held beside the rows themselves — 7 MB of cell
/// headers alone, plus 2 MB of text and the per-cell allocator overhead
/// (DIVERGENCES 30). Formatting a row twice costs CPU; holding it costs memory
/// for the rest of the run, and a table grows with the host.
pub fn render_to(w: &mut dyn Write, procs: &[Process], opts: TableOpts) -> io::Result<()> {
    let TableOpts {
        terse,
        show_ppid,
        show_pgid,
        show_offset,
        show_size,
        offset_digits,
        human_size,
        show_links,
        command_width,
        tcp_show,
        esc,
    } = opts;
    if terse {
        return render_terse(w, procs);
    }

    // Pass one over the COMMAND column: the width every cell is then cut to.
    let cmd_cut = procs.iter().fold("COMMAND".len(), |w, p| {
        let len = esc.command(&p.command).len();
        w.max(command_width.map_or(len, |n| len.min(n)))
    });
    // TASKCMD gets its OWN width by the same algorithm — `print.c` seeds
    // `TaskCmdColW` from `strlen(TASKCMDTTL)` and grows it over `Lp->tcmd`,
    // capped per entry by `TaskCmdLim`, which `+c` sets alongside `CmdLim`.
    // Sharing `cmd_cut` truncated a thread name against the *command* column:
    // a `python3` with a 22-character escaped thread name printed 6 characters
    // of it under `+c 0`, where the C prints all 22.
    let task_cut = procs
        .iter()
        .fold("TASKCMD".len(), |w, p| match &p.task_command {
            Some(c) => {
                let len = esc.command(c).len();
                w.max(command_width.map_or(len, |n| len.min(n)))
            }
            None => w,
        });

    // The columns, in `print.c`'s order.
    let mut cols: Vec<Col> = vec![Col::left("COMMAND"), Col::right("PID")];
    // `-K`: TID and TASKCMD appear only when some entry is a task, which is
    // how the C decides (`print.c` sets TaskPrtTid/TaskPrtCmd while sizing).
    // A run that asked for tasks and found none — a single-threaded process —
    // therefore looks exactly like a run that did not ask.
    let show_tasks = procs.iter().any(|p| p.tid.is_some());
    if show_tasks {
        cols.push(Col::right("TID"));
        cols.push(Col::left("TASKCMD"));
    }
    if show_ppid {
        cols.push(Col::right("PPID"));
    }
    if show_pgid {
        cols.push(Col::right("PGID"));
    }
    let size_off = if show_offset {
        SizeOff::Offset
    } else if show_size {
        SizeOff::Size
    } else {
        SizeOff::Both
    };
    cols.extend([
        Col::right("USER"),
        FD_NAME,
        FD_MODE,
        Col::right("TYPE"),
        Col::right("DEVICE"),
        Col::right(size_off.header()),
    ]);
    if show_links {
        cols.push(Col::right("NLINK"));
    }
    cols.extend([Col::right("NODE"), Col::left("NAME")]);

    let row_for = |p: &Process, f: &OpenFile| -> Vec<String> {
        // Escaped and cut the way the C's safestrprtn() does it:
        // whitespace-free, pure ASCII, and a cut that never leaves half an
        // escape at the end of the cell. `cmd_cut` is the column width from
        // pass one, not the `+c` number.
        let cmd = esc.command_truncated(&p.command, cmd_cut);
        let mut r = vec![cmd, p.pid.to_string()];
        if show_tasks {
            // The process's own row leaves both cells blank; only a task fills
            // them. TASKCMD is a command name, so it is escaped and cut the
            // same way COMMAND is — but at `task_cut`, its own column width.
            r.push(p.tid.map(|t| t.to_string()).unwrap_or_default());
            r.push(match &p.task_command {
                Some(c) => esc.command_truncated(c, task_cut),
                None => String::new(),
            });
        }
        if show_ppid {
            r.push(p.ppid.map(|v| v.to_string()).unwrap_or_default());
        }
        if show_pgid {
            r.push(p.pgid.map(|v| v.to_string()).unwrap_or_default());
        }
        // A name, escaped; or, where there is none, the number the way the
        // C's `printuid()` writes it — right-aligned in `USERPRTL` (8) columns
        // before the column's own alignment, so a numeric USER column is
        // never narrower than eight.
        r.push(match (&p.user, p.uid) {
            (Some(u), _) => esc.text(u).into_owned(),
            (None, Some(uid)) => format!("{uid:>8}"),
            (None, None) => String::new(),
        });
        r.push(fd_name(f));
        r.push(fd_mode(f));
        r.push(f.file_type.code());
        r.push(f.device.clone().unwrap_or_default());
        r.push(size_off_cell(f, size_off, human_size, offset_digits));
        if show_links {
            // `" %ld"`: the C measures the count with a space in front of it.
            r.push(f.links.map(|n| format!(" {n}")).unwrap_or_default());
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

    // Pass two: size every column. Each row is formatted, measured and
    // dropped; nothing here outlives its own iteration. A column starts at its
    // title's width, as the C's `print_init()` seeds it — except FD's two
    // halves, which only their cells size.
    let mut widths: Vec<usize> = cols
        .iter()
        .map(|c| if c.seeded { c.title.len() } else { 0 })
        .collect();
    let mut any = false;
    for (p, f) in rows_of(procs, &blank) {
        any = true;
        for (i, cell) in row_for(p, f).iter().enumerate() {
            widths[i] = widths[i].max(cell.len());
        }
    }
    // Nothing matched: emit nothing at all (no bare header), like lsof.
    if !any {
        return Ok(());
    }

    // Pass three: print. The same `row_for`, so a line cannot disagree with
    // the width it was measured at.
    let titles: Vec<&str> = cols.iter().map(|c| c.title).collect();
    emit_line(w, &titles, &widths, &cols)?;
    for (p, f) in rows_of(procs, &blank) {
        emit_line(w, &row_for(p, f), &widths, &cols)?;
    }
    Ok(())
}
