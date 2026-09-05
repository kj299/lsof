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

/// Render the FD cell, e.g. `cwd`, `txt`, or `3u` (handle value + access char).
fn fd_cell(f: &OpenFile) -> String {
    match f.fd {
        FdType::Handle(n) => {
            if f.access == AccessMode::Unknown {
                n.to_string()
            } else {
                format!("{}{}", n, f.access.code())
            }
        }
        _ => f.fd.code(),
    }
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

/// Render `procs` as the default table (or terse list when `terse`). `show_ppid`
/// adds a PPID column after PID (lsof `-R`); `show_offset` makes SIZE/OFF prefer
/// the file offset (lsof `-o`); `command_width` caps COMMAND at that many
/// printed characters (lsof `+c`, counted after escaping, like the C); `esc`
/// chooses the platform's backslash rule.
pub fn render(
    procs: &[Process],
    terse: bool,
    show_ppid: bool,
    show_offset: bool,
    command_width: Option<usize>,
    show_links: bool,
    esc: Escaper,
) -> String {
    if terse {
        return render_terse(procs);
    }

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
        // The command is escaped (and, under `+c`, cut) the way the C's
        // safestrprtn() does it: whitespace-free, pure ASCII, and a cap that
        // never leaves half an escape at the end of the cell.
        let cmd = match command_width {
            Some(n) => esc.command_truncated(&p.command, n),
            None => esc.command(&p.command).into_owned(),
        };
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
        if let Some(tcp) = f.socket.as_ref().and_then(|s| s.tcp.as_ref()) {
            name.push_str(&tcp.table_suffix());
        }
        r.push(name);
        r
    };

    let mut rows: Vec<Vec<String>> = Vec::new();
    for p in procs {
        if p.files.is_empty() {
            // A selected process with no displayed files still gets a line so it
            // shows up (NAME left blank), mirroring lsof.
            let blank = OpenFile {
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
