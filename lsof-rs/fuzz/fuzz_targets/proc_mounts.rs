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
use lsof_backend_linux::fuzz_api::{parse_mounts, resolve_table};
use lsof_core::{Blocking, ExemptFs, MountRequest, SafeFs};

fuzz_target!(|data: &[u8]| {
    // Bytes, as the kernel writes them: only space, tab, newline and backslash
    // are escaped, so any other byte of a mount point's name arrives raw.
    let rows = parse_mounts(data);
    let lines = data.split(|&b| b == b'\n').count();

    // Never more rows than lines: every row comes from one line, and no line
    // may produce two.
    assert!(rows.len() <= lines, "{} rows from {lines} lines", rows.len());
    for r in &rows {
        // A row with an empty mounted-on directory would match the empty path
        // argument and, through it, whatever filesystem it carried. The parser
        // drops those rather than emitting them.
        assert!(!r.dir.is_empty(), "empty mount dir from {data:?}");
        // Decoding only ever shortens: `\040` (4 bytes) becomes one, and
        // nothing is invented.
        assert!(
            r.dir.len() <= data.len() && r.source.len() <= data.len(),
            "decode grew the text: {r:?}"
        );
    }

    // The table the C's `readmnt()` makes of those lines, under `-b` and
    // `-w`: no call reaches a file system and nothing is said, so the bytes
    // drive the skips, the `-e`/`+e` match and the duplicate rule alone. The
    // first line's directory is exempt, `+e` or `-e` by the input's parity.
    // Under `-b` every other mount fails its `stat` and is dropped, and an
    // exempt one is recorded once, with no device.
    let quiet = SafeFs::in_process().with(
        Blocking {
            avoid: true,
            ..Blocking::default()
        },
        false,
    );
    let exempt = rows
        .first()
        .map(|r| ExemptFs {
            path: r.dir.clone(),
            plus: data.len() % 2 == 0,
        })
        .into_iter()
        .collect();
    let table = resolve_table(&rows, &MountRequest { exempt }, &quiet);
    assert!(table.entries.len() <= 1, "{table:?}");
    assert!(table.entries.iter().all(|m| m.device.is_none()), "{table:?}");
    assert!(table.has_nfs <= 2);
});
