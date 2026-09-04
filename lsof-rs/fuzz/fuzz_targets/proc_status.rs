#![no_main]

// Fuzz the Linux backend's `/proc/<pid>/status` parser (lsof-backend-linux,
// `process::parse_status`).
//
// This is the one parser in the backend whose input an unprivileged local user
// controls outright: `Name:` is whatever the process set with
// prctl(PR_SET_NAME) — 15 bytes of anything, including `)`, `:`, newlines'
// neighbours, and non-UTF-8. The backend already chose `status` over `stat`
// to defeat the classic ") " splitting trap; this target holds the rest of the
// line to the same standard. Contract: no panic on arbitrary bytes.

use libfuzzer_sys::fuzz_target;
use lsof_backend_linux::fuzz_api::parse_status;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let (command, _ppid, _uid) = parse_status(&text);
    // The command came from a single `Name:` line: `str::lines` guarantees it
    // holds no '\n'. That is the parser's whole contract about its shape. A
    // first draft of this target also asserted "no '\r'", and the fuzzer
    // disproved it in seconds with `Name:PPid:\rd:Uid:` — a bare '\r' mid-line
    // survives `lines()` and `trim()`, and the kernel does not escape it in
    // /proc/<pid>/status (only '\n' and '\\'). That is not a parser bug: the
    // parser must be faithful. Whether the RENDERER should escape control
    // characters in COMMAND — the C's safestrprt() does — is recorded in
    // DIVERGENCES.md as a decision, because it changes shared output.
    assert!(
        !command.contains('\n'),
        "command leaked a newline, which lines() must prevent: {command:?}"
    );
});
