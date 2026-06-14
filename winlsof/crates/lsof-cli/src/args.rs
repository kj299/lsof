//! lsof-compatible option parsing for the MVP switch set.
//!
//! Supported: `-p` (PIDs), `-i` (Internet, with `[46][proto][@host][:port]`),
//! `-u` (users), `-c` (command), `-a` (AND), `-n` / `-P` (no host/port resolve),
//! `-t` (terse), `-F[fields]` (field output, `-F0` = NUL), `-J` / `-j` (JSON),
//! and `-v` / `-h`. Flags may be clustered (e.g. `-ai`); value options take the
//! rest of the token or the next argument (e.g. `-p123` or `-p 123`).

use lsof_core::render::Format;
use lsof_core::{Protocol, Selection};

/// What the CLI should do after parsing.
#[derive(Debug)]
pub enum Action {
    Help,
    Version,
    Run {
        selection: Selection,
        format: Format,
    },
}

/// Parse the argument list (excluding argv[0]).
pub fn parse(args: Vec<String>) -> Result<Action, String> {
    let mut sel = Selection::default();
    let mut format = Format::Table;
    let mut want_help = false;
    let mut want_version = false;

    let mut i = 0;
    while i < args.len() {
        let tok = &args[i];
        if tok == "--help" {
            want_help = true;
            i += 1;
            continue;
        }
        if tok == "--version" {
            want_version = true;
            i += 1;
            continue;
        }

        let Some(body) = tok.strip_prefix('-') else {
            return Err(format!(
                "path/name arguments are not yet supported in this MVP: {tok:?}"
            ));
        };
        if body.is_empty() {
            return Err("a lone '-' is not a valid option".to_string());
        }

        let chars: Vec<char> = body.chars().collect();
        let mut j = 0;
        while j < chars.len() {
            let c = chars[j];
            match c {
                'a' => sel.and_mode = true,
                'n' => sel.no_host_resolve = true,
                'P' => sel.no_port_resolve = true,
                't' => sel.terse = true,
                'J' => format = Format::Json,
                'j' => format = Format::JsonLines,
                'v' | 'V' => want_version = true,
                'h' | '?' => want_help = true,
                'F' => {
                    let rest: String = chars[j + 1..].iter().collect();
                    format = Format::Fields {
                        nul: rest.contains('0'),
                    };
                    j = chars.len();
                    continue;
                }
                'i' => {
                    let rest: String = chars[j + 1..].iter().collect();
                    parse_inet(&mut sel, &rest)?;
                    j = chars.len();
                    continue;
                }
                'p' | 'u' | 'c' => {
                    let rest: String = chars[j + 1..].iter().collect();
                    let value = if !rest.is_empty() {
                        rest
                    } else {
                        i += 1;
                        if i >= args.len() {
                            return Err(format!("option -{c} requires a value"));
                        }
                        args[i].clone()
                    };
                    apply_value(&mut sel, c, &value)?;
                    j = chars.len();
                    continue;
                }
                other => return Err(format!("unsupported option: -{other}")),
            }
            j += 1;
        }
        i += 1;
    }

    if want_help {
        return Ok(Action::Help);
    }
    if want_version {
        return Ok(Action::Version);
    }
    Ok(Action::Run {
        selection: sel,
        format,
    })
}

fn apply_value(sel: &mut Selection, opt: char, value: &str) -> Result<(), String> {
    match opt {
        'p' => {
            for t in value
                .split(|ch: char| ch == ',' || ch.is_whitespace())
                .filter(|s| !s.is_empty())
            {
                match t.parse::<u32>() {
                    Ok(p) => sel.pids.push(p),
                    Err(_) => return Err(format!("invalid pid: {t}")),
                }
            }
        }
        'u' => {
            for t in value.split(',').filter(|s| !s.is_empty()) {
                sel.users.push(t.to_string());
            }
        }
        'c' => sel.commands.push(value.to_string()),
        _ => unreachable!(),
    }
    Ok(())
}

/// Parse an `-i` spec: `[46][tcp|udp][@host][:port]`. An empty spec means "all
/// Internet files".
fn parse_inet(sel: &mut Selection, spec: &str) -> Result<(), String> {
    sel.inet.enabled = true;
    let mut s = spec;

    match s.chars().next() {
        Some('4') => {
            sel.inet.family = Some(4);
            s = &s[1..];
        }
        Some('6') => {
            sel.inet.family = Some(6);
            s = &s[1..];
        }
        _ => {}
    }

    let low = s.to_ascii_lowercase();
    if low.starts_with("tcp") {
        sel.inet.proto = Some(Protocol::Tcp);
        s = &s[3..];
    } else if low.starts_with("udp") {
        sel.inet.proto = Some(Protocol::Udp);
        s = &s[3..];
    }

    let (host, port) = if let Some(at) = s.find('@') {
        let after = &s[at + 1..];
        match after.find(':') {
            Some(colon) => (Some(&after[..colon]), Some(&after[colon + 1..])),
            None => (Some(after), None),
        }
    } else if let Some(colon) = s.find(':') {
        (None, Some(&s[colon + 1..]))
    } else {
        (None, None)
    };

    if let Some(h) = host {
        if !h.is_empty() {
            sel.inet.host = Some(h.to_string());
        }
    }
    if let Some(p) = port {
        if !p.is_empty() {
            // Numeric ports only in the MVP; named services are ignored.
            if let Ok(n) = p.parse::<u16>() {
                sel.inet.port = Some(n);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(argv: &[&str]) -> (Selection, Format) {
        match parse(argv.iter().map(|s| s.to_string()).collect()).unwrap() {
            Action::Run { selection, format } => (selection, format),
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn flags_and_values() {
        let (sel, fmt) = run(&["-a", "-n", "-P", "-p", "123,456", "-c", "ssh"]);
        assert!(sel.and_mode && sel.no_host_resolve && sel.no_port_resolve);
        assert_eq!(sel.pids, vec![123, 456]);
        assert_eq!(sel.commands, vec!["ssh".to_string()]);
        assert_eq!(fmt, Format::Table);
    }

    #[test]
    fn attached_value_and_clustered_flags() {
        let (sel, _) = run(&["-ai", "-p123"]);
        assert!(sel.and_mode);
        assert!(sel.inet.enabled);
        assert_eq!(sel.pids, vec![123]);
    }

    #[test]
    fn inet_spec() {
        let (sel, _) = run(&["-iTCP@127.0.0.1:443"]);
        assert!(sel.inet.enabled);
        assert_eq!(sel.inet.proto, Some(Protocol::Tcp));
        assert_eq!(sel.inet.host.as_deref(), Some("127.0.0.1"));
        assert_eq!(sel.inet.port, Some(443));
    }

    #[test]
    fn inet_family_and_port_only() {
        let (sel, _) = run(&["-i6", "-i:53"]);
        assert!(sel.inet.enabled);
        assert_eq!(sel.inet.port, Some(53));
    }

    #[test]
    fn field_and_json_formats() {
        assert_eq!(run(&["-F0"]).1, Format::Fields { nul: true });
        assert_eq!(run(&["-F"]).1, Format::Fields { nul: false });
        assert_eq!(run(&["-J"]).1, Format::Json);
        assert_eq!(run(&["-j"]).1, Format::JsonLines);
    }

    #[test]
    fn help_and_version() {
        assert!(matches!(parse(vec!["-h".into()]).unwrap(), Action::Help));
        assert!(matches!(parse(vec!["-v".into()]).unwrap(), Action::Version));
    }

    #[test]
    fn unknown_option_errors() {
        assert!(parse(vec!["-Z".into()]).is_err());
    }
}
