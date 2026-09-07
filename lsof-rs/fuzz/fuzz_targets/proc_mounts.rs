#![no_main]

// Fuzz the Linux backend's `/proc/self/mounts` parser (lsof-backend-linux,
// `mounts::parse_mounts`).
//
// The mount table decides which path arguments name a FILE SYSTEM, and a file
// system argument selects every open file on it — so a mis-parse here does not
// fail closed, it silently widens or narrows what a query returns. The fields
// are kernel-written but attacker-influenced on any host where users may mount,
// and the kernel escapes space, tab, newline and backslash as `\OOO`, so the
// decoder is real logic and not a split on whitespace.
// Contract: no panic on arbitrary bytes (PLAYBOOK Phase 4 gate 3, LESSONS #021).

use libfuzzer_sys::fuzz_target;
use lsof_backend_linux::fuzz_api::parse_mounts;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let rows = parse_mounts(&text);

    // Never more rows than lines: every row comes from one line, and no line
    // may produce two.
    assert!(
        rows.len() <= text.lines().count(),
        "{} rows from {} lines",
        rows.len(),
        text.lines().count()
    );
    for r in &rows {
        // A row with an empty mounted-on directory would match the empty path
        // argument and, through it, whatever filesystem it carried. The parser
        // drops those rather than emitting them.
        assert!(!r.dir.is_empty(), "empty mount dir from {text:?}");
        // Decoding only ever shortens: `\040` (4 bytes) becomes one, and
        // nothing is invented. Compared in bytes, since the decode is bytewise
        // and a lossy UTF-8 replacement can be longer than the byte it stands
        // for — so the bound is on the source line, not on the field.
        assert!(
            r.dir.len() <= text.len() && r.source.len() <= text.len(),
            "decode grew the text: {r:?}"
        );
    }
});
