#![no_main]

use libfuzzer_sys::fuzz_target;

// The hand-rolled lsof-rs option parser takes untrusted argv and must NEVER
// panic: it may only return `Ok(Action)` or `Err(String)`. Split the fuzz bytes
// into arguments on NUL boundaries (so multi-argument command lines are
// explored, including empty args and non-UTF-8 turned lossy) and parse.
//
// And an error must never carry a control character to the terminal: every
// argument a message quotes is escaped (DIVERGENCES 112, 122). One parse's
// error may hold several, each printed after `lsof: `, so it is split there;
// no other newline, and no other control character (U+2028 and U+2029, which
// glibc's `iswprint()` rejects too, included), may remain.
fuzz_target!(|data: &[u8]| {
    let argv: Vec<String> = data
        .split(|&b| b == 0)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect();
    if let Err(e) = lsof_cli::args::parse(argv) {
        for piece in e.split("\nlsof: ") {
            assert!(
                !piece
                    .chars()
                    .any(|c| c.is_control() || c == '\u{2028}' || c == '\u{2029}'),
                "an error holds a control character: {e:?}"
            );
        }
    }
});
