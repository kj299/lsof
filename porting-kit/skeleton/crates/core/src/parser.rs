//! Example parser — the input surface a fuzzer will hammer. The contract that
//! makes the Rust port safer than the C: **it never panics on arbitrary input.**
//! No `unwrap()`, no `expect()`, no unchecked slice indexing on untrusted data —
//! every failure is a returned `Err`. This is the property the fuzz target
//! (harnesses/fuzz) verifies and the property C string parsers routinely violate.

use crate::model::Record;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseError {
    MissingSeparator { line: usize },
    EmptyKey { line: usize },
}

/// Parse `key = value` lines into records. Total over all inputs: any `&str`
/// (including empty, huge, or control-byte-laden) yields `Ok` or a typed `Err`,
/// never a panic.
pub fn parse(input: &str) -> Result<Vec<Record>, ParseError> {
    let mut out = Vec::new();
    for (i, raw) in input.lines().enumerate() {
        // `saturating_add`, not `+`: the workspace this skeleton ships denies
        // `clippy::arithmetic_side_effects`, and a template must pass the gates
        // it configures or every copy starts red. The skeleton should MODEL its
        // own lint, not violate it.
        let lineno = i.saturating_add(1);
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or(ParseError::MissingSeparator { line: lineno })?;
        let key = key.trim();
        if key.is_empty() {
            return Err(ParseError::EmptyKey { line: lineno });
        }
        out.push(Record::new(key, value.trim()));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic() {
        let r = parse("a = 1\n# comment\nb = two").unwrap();
        assert_eq!(r, vec![Record::new("a", "1"), Record::new("b", "two")]);
    }

    #[test]
    fn errors_are_typed_not_panics() {
        assert_eq!(parse("noeq"), Err(ParseError::MissingSeparator { line: 1 }));
        assert_eq!(parse(" = v"), Err(ParseError::EmptyKey { line: 1 }));
    }

    #[test]
    fn never_panics_on_hostile_input() {
        // The fuzz property, as a unit test: these must not panic.
        for s in ["", "=", "\0\0\0", "k=", &"x".repeat(100_000), "é=ü"] {
            let _ = parse(s);
        }
    }
}
