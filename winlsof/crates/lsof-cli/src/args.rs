//! lsof-compatible option parsing for the MVP switch set.
//!
//! Supported: `-p` (PIDs), `-i` (Internet, with `[46][proto][@host][:port]`),
//! `-u` (users), `-c` (command), `-d` (FD filter), `-a` (AND), `-n` / `-P`
//! (host/port resolution), `-R` (PPID column), `-o` (file offset), `-t`
//! (terse), `-V` (verbose),
//! `-F[fields]` (field output, `-F0` = NUL), `-J` / `-j` (JSON), `-r` (repeat),
//! and `-v` / `-h`. Flags may be clustered (e.g. `-ai`); value options take the
//! rest of the token or the next argument (e.g. `-p123` or `-p 123`). A bare
//! path argument is an exact-file lookup; `+D`/`+d <dir>` is a directory-tree
//! lookup.

use lsof_core::render::Format;
use lsof_core::selection::StateFilter;
use lsof_core::{FdFilter, FdKind, FdSpec, Protocol, Selection, TcpInfoFlags};

/// What the CLI should do after parsing.
#[derive(Debug)]
// Built once per invocation, then matched once — the size gap between the unit
// variants and `Run` is irrelevant here, and boxing would only add an alloc.
#[allow(clippy::large_enum_variant)]
pub enum Action {
    Help,
    Version,
    Run {
        selection: Selection,
        format: Format,
        repeat: Option<u64>,
        show_ppid: bool,
        show_offset: bool,
    },
}

/// Parse the argument list (excluding argv[0]).
pub fn parse(args: Vec<String>) -> Result<Action, String> {
    let mut sel = Selection::default();
    let mut format = Format::Table;
    let mut want_help = false;
    let mut want_version = false;
    let mut repeat: Option<u64> = None;
    let mut show_ppid = false;
    let mut show_offset = false;

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
        if tok == "--etw" {
            sel.use_etw = true;
            i += 1;
            continue;
        }
        if tok == "--unicode" {
            sel.unicode_output = true;
            i += 1;
            continue;
        }
        if tok == "--ascii" {
            // Explicit opt-out; redundant with the default, kept for symmetry.
            sel.unicode_output = false;
            i += 1;
            continue;
        }
        // `--` ends option parsing; remaining tokens are paths.
        if tok == "--" {
            i += 1;
            while i < args.len() {
                sel.paths.push(args[i].clone());
                i += 1;
            }
            break;
        }

        if let Some(plus) = tok.strip_prefix('+') {
            // `+d` / `+D <path>`: directory / path lookup.
            // `+c <n>`: cap COMMAND column width to <n>.
            // `+w`: enable warnings (the default; inverse of `-w`).
            let mut chars = plus.chars();
            match chars.next() {
                Some('d') | Some('D') => {
                    let rest: String = chars.collect();
                    let value = if !rest.is_empty() {
                        rest
                    } else {
                        i += 1;
                        if i >= args.len() {
                            return Err("option +D requires a path".to_string());
                        }
                        args[i].clone()
                    };
                    sel.dir_trees.push(value);
                }
                Some('c') => {
                    let rest: String = chars.collect();
                    let value = if !rest.is_empty() {
                        rest
                    } else {
                        i += 1;
                        if i >= args.len() {
                            return Err("option +c requires a width".to_string());
                        }
                        args[i].clone()
                    };
                    let n: usize = value
                        .parse()
                        .map_err(|_| format!("invalid +c width: {value}"))?;
                    sel.command_width = Some(n);
                }
                Some('w') => sel.suppress_warnings = false,
                Some('L') => {
                    // `+L <count>`: drop files whose link count is >= <count>.
                    // Implies the NLINK column, mirroring lsof.
                    let rest: String = chars.collect();
                    let value = if !rest.is_empty() {
                        rest
                    } else {
                        i += 1;
                        if i >= args.len() {
                            return Err("option +L requires a count".to_string());
                        }
                        args[i].clone()
                    };
                    let n: u32 = value
                        .parse()
                        .map_err(|_| format!("invalid +L count: {value}"))?;
                    sel.max_links = Some(n);
                    sel.show_links = true;
                }
                _ => return Err(format!("unsupported option: {tok}")),
            }
            i += 1;
            continue;
        }

        let Some(body) = tok.strip_prefix('-') else {
            // A bare argument is a path/name to look up.
            sel.paths.push(tok.clone());
            i += 1;
            continue;
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
                'r' => {
                    let rest: String = chars[j + 1..].iter().collect();
                    repeat = Some(if rest.is_empty() {
                        15
                    } else {
                        match rest.parse::<u64>() {
                            Ok(n) => n,
                            Err(_) => return Err(format!("invalid -r delay: {rest}")),
                        }
                    });
                    j = chars.len();
                    continue;
                }
                'J' => format = Format::Json,
                'j' => format = Format::JsonLines,
                'R' => show_ppid = true,
                'o' => show_offset = true,
                'v' => want_version = true,
                'V' => sel.verbose = true,
                'h' | '?' => want_help = true,
                'l' => sel.numeric_ids = true,
                'L' => sel.show_links = true,
                'Q' => sel.quiet = true,
                'w' => sel.suppress_warnings = true,
                'O' => { /* `-O` ("avoid fork"): Unix-specific perf hint; accept
                     and document as a no-op for portability. */
                }
                'T' => {
                    // `-T [fqsw]`: TCP info on socket rows. f=follow (no-op for
                    // a snapshot), q=queue, s=state, w=window. Bare `-T`
                    // defaults to queue+state, matching lsof.
                    let rest: String = chars[j + 1..].iter().collect();
                    let mut flags = TcpInfoFlags::default();
                    if rest.is_empty() {
                        flags.queue = true;
                        flags.state = true;
                    } else {
                        for ch in rest.chars() {
                            match ch {
                                'f' => {}
                                'q' => flags.queue = true,
                                's' => flags.state = true,
                                'w' => flags.window = true,
                                other => return Err(format!("invalid -T sub-option: {other}")),
                            }
                        }
                    }
                    sel.tcp_info = Some(flags);
                    j = chars.len();
                    continue;
                }
                'K' => {
                    // `-K [i]`: list each process's threads as `task` rows.
                    // lsof's optional arg selects task mode; we always list
                    // all threads of in-scope processes, so any attached value
                    // is consumed and ignored (and `-Ki` doesn't misparse the
                    // `i` as the `-i` inet flag).
                    sel.list_tasks = true;
                    j = chars.len();
                    continue;
                }
                'F' => {
                    let rest: Vec<char> = chars[j + 1..].to_vec();
                    let nul = rest.contains(&'0');
                    let only: Vec<char> = rest.into_iter().filter(|c| *c != '0').collect();
                    format = Format::Fields {
                        nul,
                        only: (!only.is_empty()).then_some(only),
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
                'd' => {
                    let rest: String = chars[j + 1..].iter().collect();
                    let value = if !rest.is_empty() {
                        rest
                    } else {
                        i += 1;
                        if i >= args.len() {
                            return Err("option -d requires a value".to_string());
                        }
                        args[i].clone()
                    };
                    sel.fd_filter = Some(parse_fd_filter(&value)?);
                    j = chars.len();
                    continue;
                }
                'p' | 'u' | 'c' | 'g' => {
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
                's' => {
                    let rest: String = chars[j + 1..].iter().collect();
                    let value = if !rest.is_empty() {
                        rest
                    } else {
                        i += 1;
                        if i >= args.len() {
                            return Err("option -s requires a [proto:state] value".to_string());
                        }
                        args[i].clone()
                    };
                    sel.state_filter = Some(parse_state_filter(&value)?);
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
        repeat,
        show_ppid,
        show_offset,
    })
}

/// Parse a `-d` FD filter spec: comma-separated terms, each a named FD
/// (`cwd`/`rtd`/`txt`/`mem`), a numeric handle, or a `a-b` range; a leading `^`
/// excludes.
fn parse_fd_filter(value: &str) -> Result<FdFilter, String> {
    let mut filter = FdFilter::default();
    for term in value.split(',').filter(|s| !s.is_empty()) {
        let (exclude, body) = match term.strip_prefix('^') {
            Some(rest) => (true, rest),
            None => (false, term),
        };
        let spec = match body {
            "cwd" => FdSpec::Named(FdKind::Cwd),
            "rtd" => FdSpec::Named(FdKind::Rtd),
            "txt" => FdSpec::Named(FdKind::Txt),
            "mem" => FdSpec::Named(FdKind::Mem),
            _ => {
                if let Some((a, b)) = body.split_once('-') {
                    let a = a
                        .parse::<u64>()
                        .map_err(|_| format!("invalid -d range: {body}"))?;
                    let b = b
                        .parse::<u64>()
                        .map_err(|_| format!("invalid -d range: {body}"))?;
                    FdSpec::Range(a, b)
                } else {
                    let n = body
                        .parse::<u64>()
                        .map_err(|_| format!("invalid -d term: {body}"))?;
                    FdSpec::Num(n)
                }
            }
        };
        if exclude {
            filter.exclude.push(spec);
        } else {
            filter.include.push(spec);
        }
    }
    Ok(filter)
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
        'g' => {
            // Windows extension: `-g <ppid>[,<ppid>...]` selects processes
            // whose PPID is in the list (no PGID on Windows). See
            // docs/feature-parity-plan.md.
            for t in value
                .split(|ch: char| ch == ',' || ch.is_whitespace())
                .filter(|s| !s.is_empty())
            {
                match t.parse::<u32>() {
                    Ok(p) => sel.ppid_filter.push(p),
                    Err(_) => return Err(format!("invalid -g ppid: {t}")),
                }
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

/// Parse a `-s [proto:][state[,state...]]` value into a [`StateFilter`].
/// Accepts `TCP:LISTEN`, `TCP:LISTEN,ESTABLISHED`, `TCP:^TIME_WAIT`, or a
/// bare proto like `TCP:` (proto-only filter, any state).
fn parse_state_filter(value: &str) -> Result<StateFilter, String> {
    let (proto, states_part) = match value.find(':') {
        Some(idx) => {
            let p = &value[..idx];
            let s = &value[idx + 1..];
            let proto = match p.to_ascii_lowercase().as_str() {
                "" => None,
                "tcp" => Some(Protocol::Tcp),
                "udp" => Some(Protocol::Udp),
                other => return Err(format!("invalid -s protocol: {other}")),
            };
            (proto, s)
        }
        None => (None, value),
    };
    let mut filter = StateFilter {
        proto,
        ..Default::default()
    };
    for term in states_part.split(',').filter(|s| !s.is_empty()) {
        if let Some(rest) = term.strip_prefix('^') {
            filter.exclude.push(rest.to_string());
        } else {
            filter.include.push(term.to_string());
        }
    }
    Ok(filter)
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
            Action::Run {
                selection, format, ..
            } => (selection, format),
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
        assert_eq!(
            run(&["-F0"]).1,
            Format::Fields {
                nul: true,
                only: None
            }
        );
        assert_eq!(
            run(&["-F"]).1,
            Format::Fields {
                nul: false,
                only: None
            }
        );
        assert_eq!(
            run(&["-Fn"]).1,
            Format::Fields {
                nul: false,
                only: Some(vec!['n'])
            }
        );
        assert_eq!(run(&["-J"]).1, Format::Json);
        assert_eq!(run(&["-j"]).1, Format::JsonLines);
    }

    #[test]
    fn help_and_version() {
        assert!(matches!(parse(vec!["-h".into()]).unwrap(), Action::Help));
        assert!(matches!(parse(vec!["-v".into()]).unwrap(), Action::Version));
    }

    fn repeat(argv: &[&str]) -> Option<u64> {
        match parse(argv.iter().map(|s| s.to_string()).collect()).unwrap() {
            Action::Run { repeat, .. } => repeat,
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn repeat_flag() {
        assert_eq!(repeat(&["-r"]), Some(15));
        assert_eq!(repeat(&["-r5"]), Some(5));
        assert_eq!(repeat(&[]), None);
        assert!(parse(vec!["-rx".into()]).is_err());
    }

    fn paths(argv: &[&str]) -> Vec<String> {
        match parse(argv.iter().map(|s| s.to_string()).collect()).unwrap() {
            Action::Run { selection, .. } => selection.paths,
            other => panic!("expected Run, got {other:?}"),
        }
    }

    fn dirs(argv: &[&str]) -> Vec<String> {
        match parse(argv.iter().map(|s| s.to_string()).collect()).unwrap() {
            Action::Run { selection, .. } => selection.dir_trees,
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn bare_path_vs_plus_d() {
        assert_eq!(paths(&["C:\\f.txt"]), vec!["C:\\f.txt".to_string()]);
        assert!(dirs(&["C:\\f.txt"]).is_empty());
        assert_eq!(dirs(&["+D", "C:\\tmp"]), vec!["C:\\tmp".to_string()]);
        assert_eq!(dirs(&["+dC:\\x"]), vec!["C:\\x".to_string()]);
        assert!(paths(&["+D", "C:\\tmp"]).is_empty());
    }

    #[test]
    fn fd_filter_parsing() {
        let (sel, _) = run(&["-d", "cwd,txt,1-3,^5"]);
        let f = sel.fd_filter.expect("fd filter");
        assert_eq!(
            f.include,
            vec![
                FdSpec::Named(FdKind::Cwd),
                FdSpec::Named(FdKind::Txt),
                FdSpec::Range(1, 3),
            ]
        );
        assert_eq!(f.exclude, vec![FdSpec::Num(5)]);
        assert!(parse(vec!["-d".into(), "bogus".into()]).is_err());
    }

    #[test]
    fn ppid_and_verbose() {
        let show_ppid = match parse(vec!["-R".into()]).unwrap() {
            Action::Run { show_ppid, .. } => show_ppid,
            other => panic!("expected Run, got {other:?}"),
        };
        assert!(show_ppid);
        let (sel, _) = run(&["-V"]);
        assert!(sel.verbose);
        // -v is version, distinct from -V (verbose).
        assert!(matches!(parse(vec!["-v".into()]).unwrap(), Action::Version));
    }

    #[test]
    fn unknown_option_errors() {
        assert!(parse(vec!["-Z".into()]).is_err());
    }
}
