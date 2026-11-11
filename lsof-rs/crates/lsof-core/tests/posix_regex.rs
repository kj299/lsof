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

use lsof_core::posix_regex::{CommandRegex, RegexError};

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
        let regex = CommandRegex::new(&expression, !flags.contains('b'), flags.contains('i'));
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
            // What glibc takes and lsof-rs does not.
            Err(RegexError::BackReference) => {
                back_references += 1;
                continue;
            }
            Err(e) => panic!("{shown:?} {flags}: glibc takes it, lsof-rs says {e:?}"),
        };
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
                "{shown:?} {flags} against {:?}",
                String::from_utf8_lossy(command)
            );
        }
    }
    if !cfg!(miri) {
        assert_eq!(cases, 1500);
        assert_eq!(back_references, 6, "the expressions glibc takes alone");
    }
}
