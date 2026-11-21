#![no_main]

// Fuzz the Linux backend's per-fd text parsers (lsof-backend-linux, `files`):
// `/proc/<pid>/fdinfo/<fd>` (`flags:`, `pos:`, and the anon-inode identities
// `eventfd-id:`, `Pid:`, `tfd:`) and the magic-link target that becomes the
// NAME cell (`pipe:[N]`, `socket:[N]`, `net:[N]`, `anon_inode:<kind>`,
// `pidfd:[N]`, a path, or anything a future kernel invents). Contract: no
// panic on arbitrary bytes.

use libfuzzer_sys::fuzz_target;
use lsof_backend_linux::fuzz_api::{name_for_target, parse_fdinfo, FdInfo, LinkNode};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let info = parse_fdinfo(&text);

    // The C keeps at most 32 of an eventpoll's fds (and marks the list once
    // it holds that many); going past it would grow the NAME cell without
    // bound on a hostile fdinfo.
    assert!(info.tfds.len() <= 32, "tfd list is uncapped: {}", info.tfds.len());
    assert!(
        info.tfds.windows(2).all(|w| w[0] <= w[1]),
        "tfd list must be sorted: {:?}",
        info.tfds
    );
    // Each number is the C's `int`: never below its -1, and no id or pid is
    // kept where the C keeps -1.
    assert!(info.tfds.iter().all(|&fd| fd >= -1), "{:?}", info.tfds);
    assert!(info.eventfd_id.is_none_or(|id| id >= 0));
    assert!(info.pidfd_pid.is_none_or(|pid| pid >= 0));
    assert!(info.tty_index.is_none_or(|i| i <= i32::MAX as u32));
    // `ULLONG_MAX` is the C's "no position".
    assert_ne!(info.pos, Some(u64::MAX));

    // The NAME mapping, as the C's `getlinksrc()` and `process_id()` make
    // it: a path is the name whole; anything else is cut at its first
    // colon, and what follows the colon names the row only where the node
    // is an anonymous inode (its kind, which fdinfo may enrich) or a
    // regular file whose source is `pidfd`. Pinned for every node kind, so
    // a future broadening shows up here first.
    for node in [LinkNode::Regular, LinkNode::Anon, LinkNode::Other] {
        let name = name_for_target(&text, &info, node);
        if text.starts_with('/') {
            assert_eq!(name, text.as_ref(), "a path passes through verbatim");
            continue;
        }
        let Some((source, rest)) = text.split_once(':') else {
            assert_eq!(name, text.as_ref(), "no colon, nothing to cut");
            continue;
        };
        match node {
            // EXACTLY ONE prefix is dropped, which is not the same as "the
            // result never starts with anon_inode:". CI's first run of this
            // target found the difference with `anon_inode:anon_inode:3:...`,
            // whose kind is legitimately `anon_inode:3:...` — the C takes
            // everything after the first colon too, so the parser was right
            // and this assertion was wrong. Third time a target's
            // invariant, not the code, was the bug (LESSONS #023).
            LinkNode::Anon if !rest.is_empty() => {
                // Only the three enriched kinds may differ from the bare
                // kind, and each keeps the kind as its stem.
                if name != rest {
                    let stem = rest.trim_end_matches(']');
                    assert!(
                        name.starts_with(stem),
                        "{name:?} is not an enrichment of {rest:?}"
                    );
                }
            }
            LinkNode::Regular if !rest.is_empty() && source == "pidfd" => {
                assert!(
                    name.starts_with("[pidfd:") && name.ends_with(']'),
                    "{name:?} is not a pidfd's name"
                );
            }
            _ => assert_eq!(name, source, "anything else is the link's source"),
        }
    }

    for line in text.lines() {
        let _ = parse_fdinfo(line);
        for node in [LinkNode::Regular, LinkNode::Anon, LinkNode::Other] {
            let _ = name_for_target(line, &FdInfo::default(), node);
        }
    }
});
