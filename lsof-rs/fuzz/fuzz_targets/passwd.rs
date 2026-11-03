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
    // Bytes, as glibc reads the file (DIVERGENCES 70).
    let map = parse_passwd(data);
    // Every entry came from a line glibc's rules accept; the map can never
    // hold more entries than lines, nor a name past LOGINML (32) bytes.
    assert!(map.len() <= data.split(|&b| b == b'\n').count());
    assert!(map.values().all(|n| n.len() <= 32));
});
