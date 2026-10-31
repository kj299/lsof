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
// faithful decode of the kernel's own escaping (`\n`, `\\`) and nothing else,
// a decoded newline then being the C's `?`.

use libfuzzer_sys::fuzz_target;
use lsof_backend_linux::fuzz_api::parse_status;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let command = parse_status(&text).command;
    // The command came from a single `Name:` line, split on '\n', so
    // the LINE held no '\n'. The parser then undoes the kernel's escaping of
    // that line — `\n` (two characters) back to a newline, `\\` back to `\` —
    // because the C reads the comm raw from `stat` and both binaries must
    // escape the same bytes in the renderer — and then makes each newline a
    // `?`, as the C does (below). A newline in the command would be a decode
    // that skipped that step, or `lines()` leaking. The renderer, not this
    // parser, keeps every other control off the terminal (lsof-core
    // `render::escape`).
    //
    // History, because this target has been wrong three times and the parser
    // never — the third time it did not even compile, because `parse_status`
    // grew from a tuple into a struct and nothing in `cargo test` builds this
    // crate. `cargo fuzz build` is now part of the verification sweep:
    // the first draft asserted "no '\r'", disproved in seconds by
    // `Name:PPid:\rd:Uid:` (the kernel escapes only '\n' and '\\' here, so a
    // bare '\r' is faithful). The second asserted "no '\n'" after the parser
    // learned to decode `\n`, and CI's 45-second smoke disproved that with
    // `Name:Nad\\..\name:..` (a newline the input spelled `\n`, which was
    // then the command's) — a target must be re-run whenever the contract
    // of the code under it changes, not only when it is new.
    //
    // The fourth contract, 2026-10-30 (DIVERGENCES 58): a decoded newline is
    // then replaced with `?`, as the C's `read_id_stat()` replaces each one
    // in the comm it reads from `stat`. So the command holds no newline at
    // all, however the input spelled one, and the `?` keeps it no longer
    // than the value it came from.
    assert!(!command.contains('\n'), "a newline survived: {command:?}");
    assert!(command.len() <= text.len(), "decode grew the text: {command:?}");
});
