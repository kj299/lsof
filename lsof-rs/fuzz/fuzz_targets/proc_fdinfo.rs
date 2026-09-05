#![no_main]

// Fuzz the Linux backend's per-fd text parsers (lsof-backend-linux, `files`):
// `/proc/<pid>/fdinfo/<fd>` (`flags:`, `pos:`, and the anon-inode identities
// `eventfd-id:`, `Pid:`, `tfd:`) and the magic-link target that becomes the
// NAME cell (`pipe:[N]`, `socket:[N]`, `anon_inode:<kind>`, a path, or
// anything a future kernel invents). Contract: no panic on arbitrary bytes.

use libfuzzer_sys::fuzz_target;
use lsof_backend_linux::fuzz_api::{name_for_target, parse_fdinfo, FdInfo};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let info = parse_fdinfo(&text);

    // The C caps an eventpoll's fd list at 32 and marks the cut; going past it
    // would grow the NAME cell without bound on a hostile fdinfo.
    assert!(info.tfds.len() <= 32, "tfd list is uncapped: {}", info.tfds.len());
    assert!(
        info.tfds.windows(2).all(|w| w[0] <= w[1]),
        "tfd list must be sorted: {:?}",
        info.tfds
    );

    // The NAME mapping rewrites exactly two shapes: a pipe target, and an
    // anon-inode target (whose `anon_inode:` prefix is dropped). Everything
    // else passes through verbatim; pin that so a future broadening shows up
    // here first.
    let name = name_for_target(&text, &info);
    if text.starts_with("pipe:[") && text.ends_with(']') {
        assert_eq!(name, "pipe");
    } else if let Some(kind) = text.strip_prefix("anon_inode:") {
        // EXACTLY ONE prefix is dropped, which is not the same as "the result
        // never starts with anon_inode:". CI's first run of this target found
        // the difference with `anon_inode:anon_inode:3:...`, whose kind is
        // legitimately `anon_inode:3:...` — the C takes everything after the
        // first colon too, so the parser was right and this assertion was
        // wrong. Third time a target's invariant, not the code, was the bug
        // (LESSONS #023).
        assert_ne!(name, text.as_ref(), "the prefix must be dropped");
        // Only the three enriched kinds may differ from the bare kind, and
        // each keeps the kind as its stem.
        if name != kind {
            let stem = kind.trim_end_matches(']');
            assert!(
                name.starts_with(stem),
                "{name:?} is not an enrichment of {kind:?}"
            );
        }
    } else {
        assert_eq!(name, text.as_ref(), "other targets pass through verbatim");
    }

    for line in text.lines() {
        let _ = parse_fdinfo(line);
        let _ = name_for_target(line, &FdInfo::default());
    }
});
