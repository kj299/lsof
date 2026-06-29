//! JSON renderers (`-J` aggregated object, `-j` JSON Lines).
//!
//! Hand-written to keep `lsof-core` dependency-free; the shape mirrors lsof's
//! own JSON so existing consumers keep working.

use crate::model::{AccessMode, FdType, OpenFile, Process};

/// Escape a string as a JSON string body (without surrounding quotes).
fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

/// A quoted, escaped JSON string literal.
fn qs(s: &str) -> String {
    format!("\"{}\"", esc(s))
}

fn fd_code(f: &OpenFile) -> String {
    match f.fd {
        FdType::Handle(n) => n.to_string(),
        _ => f.fd.code(),
    }
}

/// The comma-separated `"key":value` members of one file object.
fn file_members(f: &OpenFile) -> Vec<String> {
    let mut m = vec![
        format!("\"fd\":{}", qs(&fd_code(f))),
        format!("\"type\":{}", qs(f.file_type.code())),
        format!("\"name\":{}", qs(&f.name)),
    ];
    if f.access != AccessMode::Unknown {
        m.push(format!("\"access\":{}", qs(&f.access.code().to_string())));
    }
    if let Some(d) = &f.device {
        m.push(format!("\"device\":{}", qs(d)));
    }
    if let Some(s) = f.size {
        m.push(format!("\"size\":{s}"));
    }
    if let Some(n) = &f.node {
        m.push(format!("\"node\":{}", qs(n)));
    }
    if let Some(n) = f.links {
        m.push(format!("\"links\":{n}"));
    }
    if let Some(sock) = &f.socket {
        m.push(format!("\"protocol\":{}", qs(sock.protocol.as_str())));
        if let Some(a) = sock.local {
            m.push(format!("\"local\":{}", qs(&a.to_string())));
        }
        if let Some(a) = sock.remote {
            m.push(format!("\"remote\":{}", qs(&a.to_string())));
        }
        if let Some(st) = sock.state {
            m.push(format!("\"state\":{}", qs(st.as_str())));
        }
    }
    m
}

/// Process-level `"key":value` members (without the `files` array).
fn proc_members(p: &Process) -> Vec<String> {
    let mut m = vec![
        format!("\"pid\":{}", p.pid),
        format!("\"command\":{}", qs(&p.command)),
    ];
    if let Some(ppid) = p.ppid {
        m.push(format!("\"ppid\":{ppid}"));
    }
    if let Some(u) = &p.user {
        m.push(format!("\"user\":{}", qs(u)));
    }
    m
}

/// `-J`: a single object `{"processes":[{...,"files":[...]}]}`.
pub fn render_aggregated(procs: &[Process]) -> String {
    let mut objs = Vec::new();
    for p in procs {
        let files: Vec<String> = p
            .files
            .iter()
            .map(|f| format!("{{{}}}", file_members(f).join(",")))
            .collect();
        let mut members = proc_members(p);
        members.push(format!("\"files\":[{}]", files.join(",")));
        objs.push(format!("{{{}}}", members.join(",")));
    }
    format!("{{\"processes\":[{}]}}", objs.join(","))
}

/// `-j`: JSON Lines — one flattened object per file, prefixed with its process.
pub fn render_lines(procs: &[Process]) -> String {
    let mut out = String::new();
    for p in procs {
        let pm = proc_members(p);
        for f in &p.files {
            let mut members = pm.clone();
            members.extend(file_members(f));
            out.push_str(&format!("{{{}}}\n", members.join(",")));
        }
    }
    out
}
