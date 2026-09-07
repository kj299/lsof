#![no_main]

// Fuzz the Linux backend's `/proc/<pid>/maps` parser (lsof-backend-linux,
// `maps::parse_maps`) — the source of the `mem` and `DEL` rows.
//
// The kit's rule is one target per text-parsing module. This one earns it
// twice over: a maps path is *the rest of the line*, so it may contain spaces
// and any byte a filename may contain, and the kernel appends its own
// " (deleted)" marker to it — a name a user controls can therefore end in that
// exact string. Contract: no panic on arbitrary bytes, and no invention.

use libfuzzer_sys::fuzz_target;
use lsof_backend_linux::fuzz_api::parse_maps;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let maps = parse_maps(&text);

    // Never more rows than lines: the parser only ever drops or dedups.
    assert!(
        maps.len() <= text.lines().count(),
        "parser invented rows: {} from {} lines",
        maps.len(),
        text.lines().count()
    );

    let mut seen = Vec::new();
    for m in &maps {
        // Only file-backed mappings, and a path is absolute. `[heap]`,
        // `[vdso]` and anonymous mappings must never reach a row.
        assert!(m.path.starts_with('/'), "not an absolute path: {:?}", m.path);
        // The kernel appends exactly ONE " (deleted)", and the parser removes
        // exactly one — as the C does (`dproc.c`: a single NUL store, not a
        // loop). So a path that still ends with the marker after parsing is
        // CORRECT whenever the flag is set: it is a file whose real name ends
        // that way. Measured, not assumed — a file named `lib (deleted)`,
        // unlinked while mapped, reads back from the kernel as
        //     .../lib (deleted) (deleted)
        // and both binaries print `.../lib (deleted)` for its DEL row.
        //
        // The invariant that IS true is the pairing: the marker survives only
        // when the parser reports having stripped one. (This assertion used to
        // forbid the suffix outright and fired on ` (deleted) (deleted)` —
        // over-strong, and it accused a parser that was matching the C.)
        assert!(
            m.deleted || !m.path.ends_with(" (deleted)"),
            "the deleted marker leaked into the name without the flag: {:?}",
            m.path
        );
        // DEVICE is rendered decimal `major,minor`, never the hex the maps
        // line carries.
        let (maj, min) = m
            .device
            .split_once(',')
            .unwrap_or_else(|| panic!("device not `maj,min`: {:?}", m.device));
        assert!(
            maj.bytes().all(|b| b.is_ascii_digit()) && min.bytes().all(|b| b.is_ascii_digit()),
            "device is not decimal: {:?}",
            m.device
        );
        // One row per file: (device, inode) is the identity, and it is unique
        // across the result however many segments the input mapped.
        let key = (m.device.clone(), m.inode);
        assert!(!seen.contains(&key), "duplicate mapping for {key:?}");
        seen.push(key);
    }
});
