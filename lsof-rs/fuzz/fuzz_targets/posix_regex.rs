#![no_main]

// Fuzz `-c /regex/[bix]` (lsof-core, `posix_regex`; DIVERGENCES 38): a
// POSIX regular expression typed on the command line is read by glibc's
// grammar, written in the `regex` crate's syntax and compiled under a size
// limit, or, with a back-reference or past the crate's bounds, run by
// lsof-rs's own engine, over a command name another process chose.
// Contract, on arbitrary bytes for both: no panic, no hang (the crate is
// linear, the own engine polynomial in the command and bounded by its
// search budget, and the libFuzzer `-timeout` holds both to that, at 64 KB
// of input too: CI's default length holds the fuzzer to 4 KB, so the unit
// tests carry the long expressions that once took it past its timeout),
// bounded memory (`-rss_limit_mb`); whatever the translator accepts an
// engine accepts too, so that nothing typed reaches either as syntax of its
// own; and the two engines give the same answer for every expression the
// crate runs, so that the own engine is held to the crate's, which is held
// to glibc's by the table of `lsof-core/tests/posix_regex.rs`; and on a
// command of a few bytes, the own engine's search says what a plain
// exhaustive search over every way of matching says (`oracle`), which is
// what holds the search for a back-reference to its definition, a search
// that ran out of its budget included (it says no match, so it must be
// one that has none); and on a command as long as a Linux name, a search
// that ran out of its budget or its memory finds no match given four
// times both either, so that no match is missed for want of a budget a
// little larger (the kind of miss a review found on 15-byte names).

use libfuzzer_sys::fuzz_target;
use lsof_core::posix_regex::{
    translate, CommandRegex, ORACLE_COMMAND_MAX, OWN_COMMAND_MAX, SEARCH_BUDGET,
};

/// The longest command matched: the longest process name Linux has; and,
/// for a short expression, the longest the own engine searches, so that
/// its bounds are reached (THREAT-MODEL.md has what a long one costs there).
const COMMAND_MAX: usize = 64;
const SHORT_EXPRESSION: usize = 8;

/// How many steps the exhaustive search may take: past them it says
/// nothing.
const ORACLE_STEPS: u64 = 100_000;

/// The longest command a search past its budget is asked again of, with
/// four times the budget: a Linux name.
const AGAIN_MAX: usize = 16;

fuzz_target!(|data: &[u8]| {
    // The first byte picks the flags; a NUL parts the expression from the
    // command (neither can hold one: both come from C strings).
    let Some((&flags, rest)) = data.split_first() else {
        return;
    };
    let (extended, icase) = (flags & 1 == 0, flags & 2 != 0);
    let mut parts = rest.splitn(2, |&b| b == 0);
    let expression = parts.next().unwrap_or_default();
    // A command is a process's name: 15 bytes on Linux (64 for a kernel
    // thread), 19 on FreeBSD, an image's name on Windows. A match is linear
    // in it and in the program, at worst about a millisecond a byte under
    // the size limit (THREAT-MODEL.md), so the timeout is held to commands
    // of the lengths there are.
    let command = parts.next().unwrap_or_default();
    // Past the longest Linux name, for a short expression, the own engine
    // alone: the crate is linear in the command, and its cost for a long
    // one is THREAT-MODEL.md's, not this target's to time.
    let long = command.get(..OWN_COMMAND_MAX).unwrap_or(command);
    if long.len() > COMMAND_MAX && expression.len() <= SHORT_EXPRESSION {
        if let Ok(own) = CommandRegex::new_own(expression, extended, icase) {
            let hit = own.is_match(long);
            assert_eq!(own.clone().is_match(long), hit);
        }
    }
    let command = command.get(..COMMAND_MAX).unwrap_or(command);
    let translated = translate(expression, extended, icase);
    let own = CommandRegex::new_own(expression, extended, icase);
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
            // The own engine says what the crate says.
            let own = own.expect("the own engine takes what the crate takes");
            assert_eq!(own.is_match(command), hit);
            // And what every way of matching says, where that is quick to
            // ask: a search past its budget says no match, so it must be
            // one where there is none.
            if command.len() <= ORACLE_COMMAND_MAX {
                if let Some(every) = own.oracle(command, ORACLE_STEPS) {
                    let (found, _) = own.search_steps(command);
                    assert_eq!(found, every);
                    assert_eq!(hit, every);
                }
            }
            // A search that ran out finds no match with four times as much.
            if command.len() <= AGAIN_MAX {
                let (answer, _) = own.search_with_budget(command, SEARCH_BUDGET);
                if answer.is_none() {
                    let (more, _) = own.search_with_budget(command, 4 * SEARCH_BUDGET);
                    assert_ne!(more, Some(true));
                }
            }
        }
        // Neither engine refuses what the translator wrote.
        Err(e) => {
            assert_eq!(translated.err(), Some(e));
            assert_eq!(own.err(), Some(e));
        }
    }
    // Every refusal has its text, on one line and printable.
    if let Err(e) = translate(expression, extended, icase) {
        assert!(!e.text().is_empty());
        assert!(e.text().bytes().all(|b| (0x20..0x7f).contains(&b)));
    }
});
