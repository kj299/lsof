#![no_main]

// Fuzz lsof-core's JSON renderers (`render::json`, the C's `-J`/`-j` schema).
//
// COMMAND is set by the process itself, the login by whoever named the
// account, the task command by the thread, and NAME by whoever created the
// file; `name_addition` is a length a backend recorded, which may lie past
// the name or inside a character. From arbitrary bytes for all of them,
// checked under both forms:
//
//   - `-j` writes exactly one `\n` per file, and `-J` one in all;
//   - no output holds a raw control character (C0, DEL, C1) or U+2028/U+2029;
//   - a small JSON string decoder, written here so the target needs no new
//     dependency, recovers command, login, task_cmd and the name exactly as
//     `OpenFile::base_name` gives it;
//   - nothing panics.

use libfuzzer_sys::fuzz_target;
use lsof_core::render::json::{self, JsonOpts};
use lsof_core::render::FileFlags;
use lsof_core::{AccessMode, FdType, FileType, OpenFile, Process, TcpInfoFlags};

fn holds_control(s: &str) -> bool {
    s.chars()
        .any(|c| (c.is_control() && c != '\n') || c == '\u{2028}' || c == '\u{2029}')
}

/// The string value of `"key":"…"` at its first occurrence, decoded.
fn string_at(doc: &str, key: &str) -> Option<String> {
    let start = doc.find(&format!("\"{key}\":\""))? + key.len() + 4;
    let mut out = String::new();
    let mut it = doc[start..].chars();
    while let Some(c) = it.next() {
        match c {
            '"' => return Some(out),
            '\\' => match it.next()? {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                '/' => out.push('/'),
                'b' => out.push('\u{8}'),
                'f' => out.push('\u{c}'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                'u' => {
                    let hex: String = it.by_ref().take(4).collect();
                    out.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
                }
                _ => return None,
            },
            c => out.push(c),
        }
    }
    None
}

fuzz_target!(|data: &[u8]| {
    let (head, rest) = match data.split_first_chunk::<2>() {
        Some(x) => x,
        None => return,
    };
    let text = String::from_utf8_lossy(rest);
    let mut parts = text.splitn(4, '\u{0}');
    let command = parts.next().unwrap_or_default().to_string();
    let login = parts.next().unwrap_or_default().to_string();
    let task = parts.next().unwrap_or_default().to_string();
    let name = parts.next().unwrap_or_default().to_string();
    let file = OpenFile {
        fd: FdType::Handle(3),
        access: AccessMode::Read,
        file_type: FileType::Regular,
        name,
        device: None,
        size: Some(1),
        offset: Some(2),
        node: Some("4".into()),
        links: Some(1),
        lock: None,
        fs_device: Some(5),
        rdev: None,
        file_flags: Some(0),
        socket: None,
        name_addition: std::num::NonZeroU16::new(u16::from_le_bytes(*head)),
    };
    let p = Process {
        pid: 1,
        ppid: Some(0),
        command: command.clone(),
        user: Some(login.clone()),
        tid: Some(2),
        task_command: Some(task.clone()),
        uid: Some(0),
        pgid: Some(1),
        endpoint_peer: false,
        unlisted: false,
        files: vec![file.clone(), file.clone()],
    };
    let o = JsonOpts {
        only: None,
        tcp_show: TcpInfoFlags::default(),
        file_flags: FileFlags::Names,
        numeric_ids: false,
        version: "0",
    };
    let procs = [p];
    let lines = json::render_lines(&procs, &o);
    let doc = json::render_aggregated(&procs, &o);
    assert_eq!(lines.matches('\n').count(), 2, "{lines:?}");
    assert_eq!(doc.matches('\n').count(), 1, "{doc:?}");
    for out in [&lines, &doc] {
        assert!(!holds_control(out), "a raw control: {out:?}");
        assert_eq!(string_at(out, "command").as_deref(), Some(command.as_str()));
        assert_eq!(string_at(out, "login").as_deref(), Some(login.as_str()));
        assert_eq!(string_at(out, "task_cmd").as_deref(), Some(task.as_str()));
        assert_eq!(string_at(out, "name").as_deref(), file.base_name());
    }
});
