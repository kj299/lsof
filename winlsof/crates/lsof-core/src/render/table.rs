//! Default human-readable table renderer.
//!
//! Columns match classic lsof: `COMMAND PID [PPID] USER FD TYPE DEVICE SIZE/OFF
//! NODE NAME` (PPID only with `-R`). Numeric columns are right-aligned; the rest
//! are left-aligned; columns are padded to the widest cell.

use crate::model::{AccessMode, FdType, FileType, OpenFile, Process};

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
/// the file offset (lsof `-o`).
pub fn render(procs: &[Process], terse: bool, show_ppid: bool, show_offset: bool) -> String {
    if terse {
        return render_terse(procs);
    }

    // Build the column header set (PPID optional).
    let mut headers: Vec<&str> = vec!["COMMAND", "PID"];
    if show_ppid {
        headers.push("PPID");
    }
    headers.extend(["USER", "FD", "TYPE", "DEVICE", "SIZE/OFF", "NODE", "NAME"]);
    let right = ["PID", "PPID", "SIZE/OFF"];

    let row_for = |p: &Process, f: &OpenFile| -> Vec<String> {
        let mut r = vec![p.command.clone(), p.pid.to_string()];
        if show_ppid {
            r.push(p.ppid.map(|v| v.to_string()).unwrap_or_default());
        }
        r.push(p.user.clone().unwrap_or_default());
        r.push(fd_cell(f));
        r.push(f.file_type.code().to_string());
        r.push(f.device.clone().unwrap_or_default());
        r.push(size_off_cell(f, show_offset));
        r.push(f.node.clone().unwrap_or_default());
        r.push(f.name.clone());
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
                socket: None,
            };
            rows.push(row_for(p, &blank));
        }
        for f in &p.files {
            rows.push(row_for(p, f));
        }
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
