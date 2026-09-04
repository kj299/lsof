#![no_main]

// Fuzz the Linux backend's per-fd text parsers (lsof-backend-linux, `files`):
// `/proc/<pid>/fdinfo/<fd>` (`flags:` and `pos:` lines) and the magic-link
// target that becomes the NAME cell (`pipe:[N]`, `socket:[N]`, a path, or
// anything a future kernel invents). Contract: no panic on arbitrary bytes.

use libfuzzer_sys::fuzz_target;
use lsof_backend_linux::fuzz_api::{name_for_target, parse_fdinfo};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = parse_fdinfo(&text);

    // The NAME mapping has exactly one rewrite rule; pin it as an invariant so
    // a future "helpful" broadening shows up here first.
    let name = name_for_target(&text);
    let is_pipe = text.starts_with("pipe:[") && text.ends_with(']');
    if is_pipe {
        assert_eq!(name, "pipe");
    } else {
        assert_eq!(name, text.as_ref(), "non-pipe targets pass through verbatim");
    }
    for line in text.lines() {
        let _ = parse_fdinfo(line);
        let _ = name_for_target(line);
    }
});
