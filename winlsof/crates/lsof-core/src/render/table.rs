//! Default human-readable table renderer.
//!
//! Columns match classic lsof: `COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE
//! NAME`. Numeric columns (PID, SIZE/OFF) are right-aligned; the rest are
//! left-aligned; columns are padded to the widest cell.

use crate::model::{AccessMode, FdType, OpenFile, Process};

const HEADERS: [&str; 9] = [
    "COMMAND", "PID", "USER", "FD", "TYPE", "DEVICE", "SIZE/OFF", "NODE", "NAME",
];
// Right-aligned columns by index (PID, SIZE/OFF).
const RIGHT: [usize; 2] = [1, 6];

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

/// Render the SIZE/OFF cell: prefer size, else an offset as `0t<dec>`.
fn size_off_cell(f: &OpenFile) -> String {
    if let Some(sz) = f.size {
        sz.to_string()
    } else if let Some(off) = f.offset {
        format!("0t{off}")
    } else {
        String::new()
    }
}

fn row_for(p: &Process, f: &OpenFile) -> [String; 9] {
    [
        p.command.clone(),
        p.pid.to_string(),
        p.user.clone().unwrap_or_default(),
        fd_cell(f),
        f.file_type.code().to_string(),
        f.device.clone().unwrap_or_default(),
        size_off_cell(f),
        f.node.clone().unwrap_or_default(),
        f.name.clone(),
    ]
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

/// Render `procs` as the default table (or terse list when `terse`).
pub fn render(procs: &[Process], terse: bool) -> String {
    if terse {
        return render_terse(procs);
    }

    let mut rows: Vec<[String; 9]> = Vec::new();
    for p in procs {
        if p.files.is_empty() {
            // A selected process with no displayed files still gets a line so
            // it shows up (NAME left blank), mirroring lsof.
            let blank = OpenFile {
                fd: FdType::Unknown,
                access: AccessMode::Unknown,
                file_type: crate::model::FileType::Unknown,
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

    // Column widths from headers + all cells (NAME is last; no trailing pad).
    let mut widths = HEADERS.map(|h| h.len());
    for r in &rows {
        for (i, cell) in r.iter().enumerate() {
            widths[i] = widths[i].max(cell.len());
        }
    }

    let mut out = String::new();
    let emit = |out: &mut String, cells: &[String; 9]| {
        for (i, cell) in cells.iter().enumerate() {
            let last = i == cells.len() - 1;
            if last {
                out.push_str(cell);
            } else if RIGHT.contains(&i) {
                out.push_str(&format!("{cell:>width$}", width = widths[i]));
                out.push(' ');
            } else {
                out.push_str(&format!("{cell:<width$}", width = widths[i]));
                out.push(' ');
            }
        }
        out.push('\n');
    };

    let header_cells: [String; 9] = HEADERS.map(String::from);
    emit(&mut out, &header_cells);
    for r in &rows {
        emit(&mut out, r);
    }
    out
}
