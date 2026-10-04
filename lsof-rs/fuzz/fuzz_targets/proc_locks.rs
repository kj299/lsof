#![no_main]

// Fuzz the Linux backend's `/proc/locks` parser (lsof-backend-linux,
// `locks::parse_locks`) — the source of the lock character on the FD cell.
//
// A wrong lock character is worse than none: it claims a process holds a lock
// it does not, which is exactly the question this column exists to answer. So
// the contract is no panic, and no guessing — every field must parse or the
// line is skipped.

use libfuzzer_sys::fuzz_target;
use lsof_backend_linux::fuzz_api::parse_locks;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let table = parse_locks(&text);

    assert!(
        table.len() <= text.lines().count(),
        "invented locks: {} from {} lines",
        table.len(),
        text.lines().count()
    );
    // The key is numbers now — pid, `makedev()` device, inode — so its form
    // needs no checking; what is left to check is the character.
    for kind in table.values() {
        assert!(
            matches!(kind.code(), 'r' | 'R' | 'w' | 'W'),
            "unexpected lock character: {:?}",
            kind.code()
        );
    }
});
