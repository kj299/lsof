#![no_main]

// Fuzz the Linux backend's `/proc/<pid>/status` parser (lsof-backend-linux,
// `process::parse_status`).
//
// This is the one parser in the backend whose input an unprivileged local user
// controls outright: `Name:` is whatever the process set with
// prctl(PR_SET_NAME) — 15 bytes of anything, including `)`, `:`, newlines'
// neighbours, and non-UTF-8. The backend already chose `status` over `stat`
// to defeat the classic ") " splitting trap; this target holds the rest of the
// line to the same standard. Contract: no panic on arbitrary bytes, and a
// faithful decode of the kernel's own escaping (`\n`, `\\`) and nothing else.

use libfuzzer_sys::fuzz_target;
use lsof_backend_linux::fuzz_api::parse_status;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let (command, _ppid, _uid) = parse_status(&text);
    // The command came from a single `Name:` line, so `str::lines` guarantees
    // the LINE held no '\n'. The parser then undoes the kernel's escaping of
    // that line — `\n` (two characters) back to a newline, `\\` back to `\` —
    // because the C reads the comm raw from `stat` and both binaries must
    // escape the same bytes in the renderer. So a newline in the command is
    // legitimate exactly when the input spelled one the kernel's way; a newline
    // from anywhere else would be `lines()` leaking. The renderer, not this
    // parser, keeps it off the terminal (lsof-core `render::escape`).
    //
    // History, because this target has been wrong twice and the parser never:
    // the first draft asserted "no '\r'", disproved in seconds by
    // `Name:PPid:\rd:Uid:` (the kernel escapes only '\n' and '\\' here, so a
    // bare '\r' is faithful). The second asserted "no '\n'" after the parser
    // learned to decode `\n`, and CI's 45-second smoke disproved that with
    // `Name:Nad\\..\name:..` — a target must be re-run whenever the contract
    // of the code under it changes, not only when it is new.
    if command.contains('\n') {
        assert!(
            text.contains("\\n"),
            "command holds a newline the input never spelled as \\n: {command:?}"
        );
    }
    // Every newline is decoded from a `\n`, and the decode never invents text:
    // the command is never longer than the value it came from.
    let newlines = command.matches('\n').count();
    let spelled = text.matches("\\n").count();
    assert!(newlines <= spelled, "{newlines} newlines from {spelled} escapes: {command:?}");
    assert!(command.len() <= text.len(), "decode grew the text: {command:?}");
});
