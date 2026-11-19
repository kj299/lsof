//! `-c /regex/`: lsof-core's reading of a POSIX regular expression against
//! glibc's own answers (DIVERGENCES 38).
//!
//! `posix_regex_glibc.txt` holds what glibc 2.39's `regcomp()` and
//! `regexec()` said of 1,500 expressions, each against 62 commands, under
//! `LC_ALL=C.UTF-8` with the flags lsof gives them: for every construct of
//! both syntaxes, every way one is refused, bytes that are no character, and
//! 900 expressions made at random. lsof-rs must say the same of each, but
//! for what DIVERGENCES 38 records: a back-reference glibc takes is refused,
//! and a word operator beside a byte that is no character is not asked.

use lsof_core::posix_regex::CommandRegex;

const TABLE: &str = include_str!("posix_regex_glibc.txt");

fn unhex(text: &str) -> Vec<u8> {
    if text == "-" {
        return Vec::new();
    }
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn every_expression_is_read_as_glibc_reads_it() {
    let mut lines = TABLE.lines().filter(|l| !l.starts_with('#'));
    let commands: Vec<Vec<u8>> = lines
        .next()
        .and_then(|l| l.strip_prefix("H "))
        .expect("the commands")
        .split(' ')
        .map(unhex)
        .collect();
    assert_eq!(commands.len(), 62);
    // Under miri, which interprets the engine's compiler, a sample.
    let step = if cfg!(miri) { 300 } else { 1 };
    let (mut cases, mut back_references) = (0, 0);
    for line in lines.step_by(step) {
        let mut fields = line.splitn(3, ' ');
        let expression = unhex(fields.next().expect("an expression"));
        let flags = fields.next().expect("flags");
        let want = fields.next().expect("glibc's answer");
        let shown = String::from_utf8_lossy(&expression).into_owned();
        cases += 1;
        let (extended, icase) = (!flags.contains('b'), flags.contains('i'));
        // Each expression by both engines: the `regex` crate where it can,
        // and lsof-rs's own, which answers for the rest.
        for own in [false, true] {
            let regex = if own {
                CommandRegex::new_own(&expression, extended, icase)
            } else {
                CommandRegex::new(&expression, extended, icase)
            };
            if let Some(text) = want.strip_prefix('!') {
                assert_eq!(
                    regex.as_ref().err().map(|e| e.text()),
                    Some(text),
                    "{shown:?} {flags}"
                );
                continue;
            }
            let regex = match regex {
                Ok(regex) => regex,
                Err(e) => panic!("{shown:?} {flags}: glibc takes it, lsof-rs says {e:?}"),
            };
            back_references += usize::from(
                !own && expression
                    .windows(2)
                    .any(|w| w[0] == b'\\' && w[1].is_ascii_digit() && w[1] != b'0'),
            );
            let word_operator = [&b"\\b"[..], b"\\B", b"\\<", b"\\>"]
                .iter()
                .any(|op| expression.windows(2).any(|w| w == *op));
            for (command, want) in commands.iter().zip(want.chars()) {
                if word_operator && std::str::from_utf8(command).is_err() {
                    continue;
                }
                assert_eq!(
                    regex.is_match(command),
                    want == '1',
                    "{shown:?} {flags} against {:?} (own engine: {own})",
                    String::from_utf8_lossy(command)
                );
            }
        }
    }
    if !cfg!(miri) {
        assert_eq!(cases, 1500);
        assert!(
            back_references >= 6,
            "the expressions with a back-reference"
        );
    }
}

const BACK_REFERENCES: &str = include_str!("posix_regex_backref.txt");

/// An expression with a back-reference matches where some way of binding
/// its groups gives a match, as POSIX has it. glibc's search answers the
/// same here but for the matches it misses (and in this table never finds
/// one that is not there; DIVERGENCES 38 has some it does find).
#[test]
fn a_back_reference_matches_where_some_binding_of_the_groups_does() {
    let mut lines = BACK_REFERENCES.lines().filter(|l| !l.starts_with('#'));
    let commands: Vec<Vec<u8>> = lines
        .next()
        .and_then(|l| l.strip_prefix("H "))
        .expect("the commands")
        .split(' ')
        .map(unhex)
        .collect();
    assert_eq!(commands.len(), 68);
    // Under miri, which interprets every step, a sample.
    let step = if cfg!(miri) { 50 } else { 1 };
    let (mut cases, mut missed) = (0, 0);
    for line in lines.step_by(step) {
        let fields: Vec<&str> = line.split(' ').collect();
        let [expression, flags, every, glibc] = fields[..] else {
            panic!("{line}");
        };
        let expression = unhex(expression);
        let shown = String::from_utf8_lossy(&expression).into_owned();
        let regex = CommandRegex::new(&expression, !flags.contains('b'), false)
            .unwrap_or_else(|e| panic!("{shown:?} {flags}: {e:?}"));
        cases += 1;
        missed += usize::from(every != glibc);
        for ((command, want), theirs) in commands.iter().zip(every.chars()).zip(glibc.chars()) {
            // In this table glibc finds no match that is not there.
            assert!(theirs == want || theirs == '0', "{shown:?} {flags}");
            assert_eq!(
                regex.is_match(command),
                want == '1',
                "{shown:?} {flags} against {:?}",
                String::from_utf8_lossy(command)
            );
        }
    }
    if !cfg!(miri) {
        assert_eq!((cases, missed), (500, 10));
    }
}
