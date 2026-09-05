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
        // The kernel's marker is metadata, not part of the name — a row must
        // never carry it, however the input was shaped.
        assert!(
            !m.path.ends_with(" (deleted)"),
            "the deleted marker leaked into the name: {:?}",
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
