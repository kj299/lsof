#![no_main]

// Fuzz the Linux backend's `/etc/passwd` parser (lsof-backend-linux,
// `users::parse_passwd`), which stands in for getpwuid so the crate needs no
// libc. The file is root-owned but only as well-formed as its last editor left
// it — a truncated line, a uid that is not a number, a stray colon. The USER
// column must degrade to the numeric uid, never to a panic. Contract: no panic
// on arbitrary bytes.

use libfuzzer_sys::fuzz_target;
use lsof_backend_linux::fuzz_api::parse_passwd;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let map = parse_passwd(&text);
    // Every entry came from a line whose third field parsed as u32 and whose
    // first field existed; the map can never hold more entries than lines.
    assert!(map.len() <= text.lines().count());
});
