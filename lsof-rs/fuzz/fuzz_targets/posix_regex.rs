#![no_main]

// Fuzz `-c /regex/[bix]` (lsof-core, `posix_regex`; DIVERGENCES 38): a
// POSIX regular expression typed on the command line is read by glibc's
// grammar, written in the `regex` crate's syntax, compiled under a size
// limit and run over a command name another process chose. Contract, on
// arbitrary bytes for both: no panic, no hang (the engine is linear, and
// the libFuzzer `-timeout` holds it to that), bounded memory (the size
// limit; `-rss_limit_mb`), and whatever the translator accepts the engine
// accepts too, but for a program past the size limit — so that nothing typed
// reaches the engine as syntax of its own.

use libfuzzer_sys::fuzz_target;
use lsof_core::posix_regex::{translate, CommandRegex, RegexError};

fuzz_target!(|data: &[u8]| {
    // The first byte picks the flags; a NUL parts the expression from the
    // command (neither can hold one: both come from C strings).
    let Some((&flags, rest)) = data.split_first() else {
        return;
    };
    let (extended, icase) = (flags & 1 == 0, flags & 2 != 0);
    let mut parts = rest.splitn(2, |&b| b == 0);
    let expression = parts.next().unwrap_or_default();
    let command = parts.next().unwrap_or_default();
    let translated = translate(expression, extended, icase);
    match CommandRegex::new(expression, extended, icase) {
        Ok(regex) => {
            assert!(translated.is_ok());
            assert_eq!(regex.expression(), expression);
            // Deterministic, and the same for a copy.
            let hit = regex.is_match(command);
            assert_eq!(regex.clone().is_match(command), hit);
            // The empty expression matches everything.
            if expression.is_empty() {
                assert!(hit);
            }
        }
        // The engine refuses nothing the translator wrote, but for size.
        Err(RegexError::Size) => {}
        Err(e) => assert_eq!(translated.err(), Some(e)),
    }
    // Every refusal has its text, on one line and printable.
    if let Err(e) = translate(expression, extended, icase) {
        assert!(!e.text().is_empty());
        assert!(e.text().bytes().all(|b| (0x20..0x7f).contains(&b)));
    }
});
