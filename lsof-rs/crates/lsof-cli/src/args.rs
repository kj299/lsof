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

use lsof_core::render::{Format, DEFAULT_OFFSET_DIGITS};
use lsof_core::selection::StateFilter;
use lsof_core::{
    CommandMatch, CommandWidth, EndpointMode, FdFilter, FdKind, FdSpec, FilesystemArgs, Protocol,
    Selection, TaskMode, TcpInfoFlags,
};

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
        columns: Columns,
    },
}

/// What the table's columns show. Pure presentation: nothing here selects a
/// row, which is why it lives beside the [`Selection`] rather than in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Columns {
    /// `-R`: a PPID column after PID.
    pub ppid: bool,
    /// `-g` on a platform with process groups: a PGID column after PPID.
    pub pgid: bool,
    /// `-o`: the SIZE/OFF column shows offsets and only offsets, headed
    /// `OFFSET` — a row with no offset leaves it blank rather than falling
    /// back to its size.
    pub offset: bool,
    /// `-s` with no value: sizes and only sizes, headed `SIZE`.
    pub size: bool,
    /// `-o <digits>`: how many decimal digits an offset may have before it is
    /// printed in hex instead (the C's `OffDecDig`); 0 means no limit.
    pub offset_digits: usize,
}

impl Default for Columns {
    fn default() -> Self {
        Self {
            ppid: false,
            pgid: false,
            offset: false,
            size: false,
            offset_digits: DEFAULT_OFFSET_DIGITS,
        }
    }
}

/// A run of ASCII digits as a count, saturating rather than wrapping. The C
/// accumulates `-o`'s digits in an `int` and overflows it (undefined
/// behaviour); any limit past the 20 digits a 64-bit offset can have means
/// "never hex", and so does the saturated value.
fn digits_value(digits: &str) -> usize {
    digits.bytes().fold(0usize, |n, b| {
        n.saturating_mul(10).saturating_add(usize::from(b - b'0'))
    })
}

/// Parse the argument list (excluding argv[0]).
pub fn parse(mut args: Vec<String>) -> Result<Action, String> {
    let mut sel = Selection::default();
    let mut format = Format::Table;
    let mut want_help = false;
    let mut want_version = false;
    let mut repeat: Option<u64> = None;
    let mut columns = Columns::default();
    // `-F` with an explicit `o` letter switches the C's `Foffset` on too
    // (`main.c`, `if (i == LSOF_FIX_OFFSET) Foffset = 1`) — so it collides
    // with a bare `-s` exactly as `-o` does. A bare `-F` selects the field
    // without that side effect.
    let mut fields_offset = false;
    // `-c`'s comparison. The C's case-sensitive prefix everywhere it has an
    // oracle; the Windows port keeps the forgiving match its image names were
    // designed around (see `CommandMatch`).
    if cfg!(windows) {
        sel.command_match = CommandMatch::Forgiving;
    }

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
                // `+d` is ONE level (the directory and its immediate entries);
                // `+D` descends the whole tree. lsof distinguishes them.
                Some(c @ ('d' | 'D')) => {
                    let rest: String = chars.collect();
                    let value = if !rest.is_empty() {
                        rest
                    } else {
                        i += 1;
                        if i >= args.len() {
                            return Err(format!("option +{c} requires a path"));
                        }
                        args[i].clone()
                    };
                    if c == 'd' {
                        sel.dirs_one_level.push(value);
                    } else {
                        sel.dir_trees.push(value);
                    }
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
                    // The C refuses a width wider than the longest command name
                    // the system can report, rather than accepting a number it
                    // could never fill.
                    if let Some(max) = MAX_COMMAND_WIDTH {
                        if n > max {
                            return Err(format!("+c {n} > what system provides ({max})"));
                        }
                    }
                    sel.command_width = if n == 0 {
                        CommandWidth::Unlimited
                    } else {
                        CommandWidth::Chars(n)
                    };
                }
                Some('T') => {
                    // `+T` is `-T`'s inverse only in the no-letter case: with
                    // letters, `main.c` reads them identically and the `+`/`-`
                    // prefix is never consulted.
                    let rest: String = chars.collect();
                    sel.tcp_info_opt = Some(take_tcp_info(rest, &args, &mut i, true)?);
                }
                Some('f') => {
                    // `+f` forces every path argument to be a file system, and
                    // widens what counts as one to any mount source, not just
                    // a block device. Same reservation about `+f[cfgGn]`.
                    let rest: String = chars.collect();
                    if !rest.is_empty() {
                        return Err(format!(
                            "unsupported kernel file structure selection: {rest}"
                        ));
                    }
                    sel.filesystem_args = FilesystemArgs::AlwaysFilesystem;
                }
                Some('w') => sel.suppress_warnings = false,
                Some('E') => sel.endpoints = Some(EndpointMode::Files),
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
                'R' => columns.ppid = true,
                'o' => {
                    // `-o [digits]`. The value is optional and only ever
                    // digits (`main.c`): digits set the offset digit limit,
                    // and anything else means there was no value — bare `-o`,
                    // with the text given back to be parsed again. So `-ot`
                    // is `-o -t`, `-o3t` is `-o3 -t`, and `-o /file` is `-o`
                    // and a file name. Note that a limit does NOT switch the
                    // offset column on: `-o 5` keeps SIZE/OFF.
                    let rest: String = chars[j + 1..].iter().collect();
                    if !rest.is_empty() {
                        let digits: String =
                            rest.chars().take_while(char::is_ascii_digit).collect();
                        if digits.is_empty() {
                            columns.offset = true;
                        } else {
                            columns.offset_digits = digits_value(&digits);
                            // The letters after the digits are options again.
                            j += 1 + digits.len();
                            continue;
                        }
                    } else if let Some(next) = args.get(i + 1) {
                        let digits: String =
                            next.chars().take_while(char::is_ascii_digit).collect();
                        if digits.is_empty() {
                            // Not a value — including `-x`-style words, which
                            // are the next option.
                            columns.offset = true;
                        } else {
                            columns.offset_digits = digits_value(&digits);
                            let leftover = next[digits.len()..].to_string();
                            if leftover.is_empty() {
                                i += 1;
                            } else {
                                // `-o 3t`: the C resumes option scanning in
                                // the middle of the word, so what follows the
                                // digits is read as option letters.
                                args[i + 1] = format!("-{leftover}");
                            }
                        }
                        j = chars.len();
                        continue;
                    } else {
                        columns.offset = true;
                    }
                }
                'v' => want_version = true,
                'V' => sel.verbose = true,
                'h' | '?' => want_help = true,
                'l' => sel.numeric_ids = true,
                'L' => sel.show_links = true,
                'H' => sel.human_size = true,
                'X' => sel.skip_inet_tables = true,
                'N' => sel.nfs_only = true,
                'Z' => {
                    // `-Z [context]`. The value is attached or the next word,
                    // and a word that opens an option is not one — the same
                    // rule `-K` uses (`main.c`: `*GOv != '-' && *GOv != '+'`).
                    let rest: String = chars[j + 1..].iter().collect();
                    let list = sel.selinux.get_or_insert_with(Vec::new);
                    if !rest.is_empty() {
                        list.push(rest);
                    } else if let Some(next) = args.get(i + 1) {
                        if !next.starts_with(['-', '+']) {
                            list.push(next.clone());
                            i += 1;
                        }
                    }
                    j = chars.len();
                    continue;
                }
                'e' => {
                    // `-e s` / `+e s`. The value may be attached or the next
                    // word, and the C takes that word WHATEVER it is — a
                    // missing value is reported by quoting what it found:
                    // `lsof: -e not followed by a file system path: "-p"`.
                    let rest: String = chars[j + 1..].iter().collect();
                    let value = if !rest.is_empty() {
                        rest
                    } else {
                        match args.get(i + 1) {
                            Some(next) if !next.starts_with(['-', '+']) => {
                                i += 1;
                                next.clone()
                            }
                            other => {
                                return Err(format!(
                                    "-e not followed by a file system path: {:?}",
                                    other.map(String::as_str).unwrap_or("")
                                ))
                            }
                        }
                    };
                    sel.exempt_fs.push(value);
                    j = chars.len();
                    continue;
                }
                'x' => {
                    // `-x [fl]`: bare is both (`main.c`'s XO_ALL), otherwise
                    // each letter adds one. An unknown letter is fatal, and
                    // the C names it — `lsof: unknown cross-over option: q`.
                    let rest: String = chars[j + 1..].iter().collect();
                    if rest.is_empty() {
                        sel.cross_filesystems = true;
                        sel.cross_symlinks = true;
                    } else {
                        for c in rest.chars() {
                            match c {
                                'f' => sel.cross_filesystems = true,
                                'l' => sel.cross_symlinks = true,
                                other => return Err(format!("unknown cross-over option: {other}")),
                            }
                        }
                    }
                    j = chars.len();
                    continue;
                }
                'U' => sel.unix_only = true,
                // `-E` after `+E` must not downgrade the "also show peer
                // files" mode — lsof treats +E as a superset of -E.
                'E' => {
                    if sel.endpoints != Some(EndpointMode::Files) {
                        sel.endpoints = Some(EndpointMode::Info);
                    }
                }
                'Q' => sel.quiet = true,
                'w' => sel.suppress_warnings = true,
                'f' => {
                    // `-f` alone forces every path argument to be a plain
                    // file. The C also spells kernel-file-structure selection
                    // `-f[cfgGn]`, which lsof-rs does not implement and which
                    // is not what a bare `-f` means; a value here is a request
                    // for that, so it is rejected rather than silently read as
                    // the path-argument switch.
                    let rest: String = chars[j + 1..].iter().collect();
                    if !rest.is_empty() {
                        return Err(format!(
                            "unsupported kernel file structure selection: {rest}"
                        ));
                    }
                    sel.filesystem_args = FilesystemArgs::NeverFilesystem;
                    j = chars.len();
                    continue;
                }
                'O' => { /* `-O` ("avoid fork"): Unix-specific perf hint; accept
                     and document as a no-op for portability. */
                }
                'T' => {
                    let rest: String = chars[j + 1..].iter().collect();
                    sel.tcp_info_opt = Some(take_tcp_info(rest, &args, &mut i, false)?);
                    j = chars.len();
                    continue;
                }
                'K' => {
                    // `-K` lists each process's threads as their own entries;
                    // `-K i` is the opposite — it removes tasks from the
                    // default selection, which is where they otherwise come
                    // from. The value may be attached (`-Ki`) or separate
                    // (`-K i`), like `-T`. Consuming it also keeps `-Ki` from
                    // misparsing the `i` as the `-i` inet flag.
                    //
                    // The separate form takes the next word WHATEVER it is,
                    // unless it opens an option (`main.c`: `if (!GOv || *GOv
                    // == '-' || *GOv == '+')` pushes the token back, else it
                    // must be `i`). So `-K x` and `-K /var/log` are usage
                    // errors, not a bare `-K` plus a name — taking only a
                    // literal `i` turned `lsof -K /var/log` into a whole-host
                    // task listing where the C exits 1.
                    let rest: String = chars[j + 1..].iter().collect();
                    let value = if !rest.is_empty() {
                        Some(rest)
                    } else {
                        match args.get(i + 1) {
                            Some(next) if !next.starts_with(['-', '+']) => {
                                i += 1;
                                Some(next.clone())
                            }
                            _ => None,
                        }
                    };
                    match value {
                        None => sel.tasks = TaskMode::Always,
                        // `strcasecmp`, so `-K I` is `-K i`.
                        Some(v) if v.eq_ignore_ascii_case("i") => sel.tasks = TaskMode::Never,
                        Some(v) => return Err(format!("-K not followed by i (but by {v})")),
                    }
                    j = chars.len();
                    continue;
                }
                'F' => {
                    let rest: Vec<char> = chars[j + 1..].to_vec();
                    let nul = rest.contains(&'0');
                    let only: Vec<char> = rest.into_iter().filter(|c| *c != '0').collect();
                    fields_offset |= only.contains(&'o');
                    // The C's field table gives some letters a side effect:
                    // selecting one also switches on the collection it needs
                    // (`store.c` — `T` carries `Ftcptpi |= TCPTPI_ALL`). That is
                    // why bare `-F` prints `TQR=`/`TQS=` with no `-T` at all.
                    // Linux compiles the window block out of `print_tcptpi()`
                    // and rejects `-T w`, so "all" is state + queues there.
                    // The other side effects (`k`→nlink, `g`/`R`→pgid/ppid,
                    // `o`→offset) are no-ops here: those values are always
                    // gathered, so the field prints whenever it has one.
                    if only.is_empty() || only.contains(&'T') {
                        let t = sel.tcp_info_opt.get_or_insert(TcpInfoFlags::default());
                        t.state = true;
                        t.queue = true;
                    }
                    format = Format::Fields {
                        nul,
                        only: (!only.is_empty()).then_some(only),
                    };
                    j = chars.len();
                    continue;
                }
                'i' => {
                    // `-i [spec]`: the spec is attached or the next word, and
                    // a word that opens an option is not one (`main.c`). So
                    // `-i :80` is the spec `:80` — lsof-rs had read it as a
                    // bare `-i` and a file called `:80`.
                    let rest: String = chars[j + 1..].iter().collect();
                    let spec = if !rest.is_empty() {
                        rest
                    } else {
                        match args.get(i + 1) {
                            Some(next) if !next.starts_with(['-', '+']) => {
                                i += 1;
                                next.clone()
                            }
                            _ => String::new(),
                        }
                    };
                    parse_inet(&mut sel, &spec)?;
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
                'g' => {
                    // `-g [pgids]`: the value is optional, attached or the
                    // next word, and a word that opens an option is not one
                    // (`main.c`). With or without it, `-g` adds the PGID
                    // column; with it, it also selects by process group.
                    let rest: String = chars[j + 1..].iter().collect();
                    let value = if !rest.is_empty() {
                        Some(rest)
                    } else {
                        match args.get(i + 1) {
                            Some(next) if !next.starts_with(['-', '+']) => {
                                i += 1;
                                Some(next.clone())
                            }
                            _ => None,
                        }
                    };
                    apply_g(&mut sel, &mut columns, value.as_deref())?;
                    j = chars.len();
                    continue;
                }
                's' => {
                    // `-s [p:s]`: with a value it is a TCP/UDP state filter;
                    // without one it is the SIZE column (`main.c`: `if (!GOv
                    // || *GOv == '-' || *GOv == '+') Fsize = 1`). The value is
                    // attached or the next word, and a word that opens an
                    // option is not one — so `-s -o` is a bare `-s` and a
                    // `-o`, not a state filter spelled `-o`. lsof-rs had taken
                    // the next word unconditionally: `lsof -s -p 1` looked for
                    // a file called `1`, and `lsof -s -o` silently filtered
                    // every socket out by a state named `-o`.
                    let rest: String = chars[j + 1..].iter().collect();
                    let value = if !rest.is_empty() {
                        Some(rest)
                    } else {
                        match args.get(i + 1) {
                            Some(next) if !next.starts_with(['-', '+']) => {
                                i += 1;
                                Some(next.clone())
                            }
                            _ => None,
                        }
                    };
                    match value {
                        Some(v) => sel.state_filter = Some(parse_state_filter(&v)?),
                        None => columns.size = true,
                    }
                    j = chars.len();
                    continue;
                }
                other => return Err(format!("unsupported option: -{other}")),
            }
            j += 1;
        }
        i += 1;
    }

    // The C refuses a PID or PGID that is both selected and excluded
    // (`lib/lsof.c`), and enters each only once — `-p 5,5` is one search
    // item, reported once if it is not found.
    dedup_ids(&mut sel.pids, &sel.pid_excludes, "PID")?;
    dedup_ids(&mut sel.pgids, &sel.pgid_excludes, "PGID")?;
    // Checked after the loop because the two may come in either order. `-o 5`
    // is only a digit limit and does not count; `-Fo` does (see above).
    if (columns.offset || fields_offset) && columns.size {
        return Err("-o and -s are mutually exclusive".to_string());
    }
    if want_help {
        return Ok(Action::Help);
    }
    if want_version {
        return Ok(Action::Version);
    }
    // `-X` stops the inet tables being read, so `-i` has nothing left to
    // select on. The C refuses the pair outright rather than silently
    // returning nothing — measured: `lsof -X -i` exits 1 with this text.
    // Checked after the loop because the two may arrive in either order and
    // in either clustering (`-Xi`, `-i -X`, `-aXi`).
    if sel.skip_inet_tables && sel.inet.enabled {
        return Err("-i is useless when -X is specified.".to_string());
    }
    // `-x` only means anything to a `+d`/`+D` expansion, and the C refuses it
    // alone rather than accepting a switch that would do nothing
    // (`main.c:1122`). Checked here so the two may arrive in either order.
    if (sel.cross_filesystems || sel.cross_symlinks)
        && sel.dirs_one_level.is_empty()
        && sel.dir_trees.is_empty()
    {
        return Err("-x must accompany +d or +D".to_string());
    }
    Ok(Action::Run {
        selection: sel,
        format,
        repeat,
        columns,
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

/// A `-p`/`-g` list: comma- or space-separated IDs, each optionally `^`
/// for an exclusion. `what` names the list in the error.
fn parse_id_list(value: &str, what: &str) -> Result<Vec<(bool, u32)>, String> {
    value
        .split(|ch: char| ch == ',' || ch.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(|t| {
            let (excl, id) = match t.strip_prefix('^') {
                Some(rest) => (true, rest),
                None => (false, t),
            };
            id.parse::<u32>()
                .map(|n| (excl, n))
                .map_err(|_| format!("invalid {what}: {t}"))
        })
        .collect()
}

/// Order-preserving de-duplication of an inclusion list, and the C's refusal
/// of an ID that is also excluded: `lsof: PID 1 has been included and
/// excluded.`, measured.
fn dedup_ids(ids: &mut Vec<u32>, excludes: &[u32], what: &str) -> Result<(), String> {
    let mut seen = std::collections::HashSet::new();
    ids.retain(|id| seen.insert(*id));
    match ids.iter().find(|id| excludes.contains(id)) {
        Some(id) => Err(format!("{what} {id} has been included and excluded.")),
        None => Ok(()),
    }
}

fn apply_value(sel: &mut Selection, opt: char, value: &str) -> Result<(), String> {
    match opt {
        'p' => {
            for (excl, pid) in parse_id_list(value, "pid")? {
                if excl {
                    sel.pid_excludes.push(pid);
                } else {
                    sel.pids.push(pid);
                }
            }
        }
        // `-u ^name` and `-c ^name` are negations, not selections: they
        // exclude absolutely and take no part in the OR/AND rule (Lsof.8).
        // Names are resolved to IDs after parsing, by the backend that knows
        // how (see `main.rs`); here they are only split.
        'u' => {
            for t in value.split(',').filter(|s| !s.is_empty()) {
                match t.strip_prefix('^') {
                    Some("") => return Err("option -u^ requires a name".to_string()),
                    Some(name) => sel.user_excludes.push(name.to_string()),
                    None => sel.users.push(t.to_string()),
                }
            }
        }
        'c' => {
            // `enter_cmd()`: a value that opens an option is a missing value,
            // and one that opens with `/` is a regular expression
            // (`main.c`: `if (GOv && (*GOv == '/'))`). lsof-rs has no regex
            // engine, and reading `/re/` as a literal command name matched
            // nothing, silently — so it is refused, loudly, instead.
            if value.starts_with(['-', '+']) {
                return Err("missing -c option value".to_string());
            }
            if value.starts_with('/') {
                return Err(format!(
                    "-c {value}: regular expressions (-c /RE/) are not implemented"
                ));
            }
            let (excl, name) = match value.strip_prefix('^') {
                Some("") => return Err("option -c^ requires a name".to_string()),
                Some(name) => (true, name),
                None => (false, value),
            };
            // A name longer than the kernel keeps can never match, and the C
            // says so rather than accepting it (`lsof_select_process()`).
            if let Some(max) = MAX_COMMAND_WIDTH {
                if name.len() > max {
                    return Err(format!(
                        "\"-c {name}\" length ({}) > what system provides ({max})",
                        name.len()
                    ));
                }
            }
            let (this, other) = if excl {
                (&mut sel.command_excludes, &sel.commands)
            } else {
                (&mut sel.commands, &sel.command_excludes)
            };
            if other.iter().any(|o| o == name) {
                return Err(format!("-c^{name} and -c{name} conflict."));
            }
            this.push(name.to_string());
        }
        _ => unreachable!(),
    }
    Ok(())
}

/// `-g`, with or without its value.
///
/// Where processes have groups this is the C's option: the PGID column, and
/// with a value, selection by process group — `-g 42` lists group 42, `-g ^42`
/// excludes it, and an unmatched group is a search item (`process group ID
/// not located`). lsof-rs had read it as a *parent* PID on every platform,
/// so on Linux `-g <pgid>` selected the wrong processes, `-g ^N` was an error,
/// and a bare `-g` was refused. Windows has no process groups and keeps the
/// PPID reading, which is its own extension (`docs/feature-parity-plan.md`).
fn apply_g(sel: &mut Selection, columns: &mut Columns, value: Option<&str>) -> Result<(), String> {
    if cfg!(windows) {
        let Some(value) = value else {
            return Err("option -g requires a value".to_string());
        };
        for (excl, ppid) in parse_id_list(value, "-g ppid")? {
            if excl {
                return Err(format!("invalid -g ppid: ^{ppid}"));
            }
            sel.ppid_filter.push(ppid);
        }
        return Ok(());
    }
    columns.pgid = true;
    for (excl, pgid) in parse_id_list(value.unwrap_or(""), "process group ID")? {
        if excl {
            sel.pgid_excludes.push(pgid);
        } else {
            sel.pgids.push(pgid);
        }
    }
    Ok(())
}

/// The widest `+c` this platform accepts, mirroring the C's `MAXSYSCMDL` —
/// "what system provides". Linux's dialect pins it to 15, the kernel's
/// `char comm[16]` minus the NUL, and rejects anything wider. Windows has no
/// such ceiling on an image name, so nothing is rejected there.
#[cfg(target_os = "linux")]
const MAX_COMMAND_WIDTH: Option<usize> = Some(15);
#[cfg(not(target_os = "linux"))]
const MAX_COMMAND_WIDTH: Option<usize> = None;

/// Whether this platform can report a socket's receive window, which is what
/// decides whether `-T w` is a valid letter.
///
/// The C compiles the letter in per dialect (`HASTCPTPIW`) and its Linux
/// dialect does not define it, so `lsof -T w` there is a hard error rather
/// than a request that quietly returns nothing. Windows reads the window from
/// per-connection EStats, so it is real there.
#[cfg(target_os = "linux")]
const HAS_TCP_WINDOW: bool = false;
#[cfg(not(target_os = "linux"))]
const HAS_TCP_WINDOW: bool = true;

/// Read a `-T` / `+T` option's value, from the same token or the next one.
///
/// The C declares `-T` as taking a value (`T:` in its option string), so
/// `lsof -T q` consumes `q` — and `lsof -T /some/path` consumes the path and
/// then rejects `/` as a sub-option letter. Its `GetOpt` falls back to the
/// no-value meaning only when the value is absent or itself looks like an
/// option, which is why `lsof -T -i` is a bare `-T` followed by `-i`.
fn take_tcp_info(
    attached: String,
    args: &[String],
    i: &mut usize,
    plus: bool,
) -> Result<TcpInfoFlags, String> {
    if !attached.is_empty() {
        return parse_tcp_info(&attached, plus);
    }
    match args.get(*i + 1) {
        Some(next) if !next.starts_with('-') && !next.starts_with('+') => {
            *i += 1;
            parse_tcp_info(next, plus)
        }
        _ => parse_tcp_info("", plus),
    }
}

/// Parse the letters of a `-T` / `+T` option.
///
/// The letters **select**: the C zeroes `Ftcptpi` before ORing them in, so
/// `-T q` is queues *instead of* the state, not as well as it. With no letters
/// the prefix decides — `-T` selects nothing, `+T` restores the state-only
/// default.
fn parse_tcp_info(letters: &str, plus: bool) -> Result<TcpInfoFlags, String> {
    if letters.is_empty() {
        return Ok(if plus {
            TcpInfoFlags::DEFAULT
        } else {
            TcpInfoFlags::default()
        });
    }
    let mut flags = TcpInfoFlags::default();
    for ch in letters.chars() {
        match ch {
            'f' => flags.options = true,
            'q' => flags.queue = true,
            's' => flags.state = true,
            'w' if HAS_TCP_WINDOW => flags.window = true,
            other => {
                return Err(format!("unsupported TCP/TPI info selection: {other}"));
            }
        }
    }
    Ok(flags)
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

/// Parse an `-i` spec: `[46][proto][@host][:ports]`. An empty one, or one
/// that is only `4` or `6`, is the bare form — every Internet file — and
/// anything else is an address specification of its own (see
/// [`lsof_core::InetFilter`]).
///
/// What the C resolves and lsof-rs does not is refused, not guessed: a host
/// NAME (`@localhost`) and a service NAME (`:http`). lsof-rs never resolves
/// names (DIVERGENCES, "Deliberate, and staying"), and it had been reading
/// both as a pattern that matched nothing (a host) or as no constraint at all
/// (a service, and a port range) — so `-i:http` listed every Internet file,
/// measured, where the C lists port 80.
fn parse_inet(sel: &mut Selection, spec: &str) -> Result<(), String> {
    let text = spec.to_string();
    let mut s = spec;
    let mut family = None;
    match s.chars().next() {
        Some('4') => {
            family = Some(4);
            s = &s[1..];
        }
        Some('6') => {
            family = Some(6);
            s = &s[1..];
        }
        _ => {}
    }
    if s.is_empty() {
        sel.inet.add_all(family);
        return Ok(());
    }
    sel.inet.enabled = true;
    // An address spec with no version of its own takes the bare form's, if
    // one came before it (`arg.c`: `else if (Fnet) ft = FnetTy`).
    if family.is_none() && sel.inet.all {
        family = sel.inet.all_family;
    }

    let low = s.to_ascii_lowercase();
    let mut proto = None;
    for (name, p) in [
        ("tcp", Protocol::Tcp),
        ("udp", Protocol::Udp),
        // ETW-only families (no IP Helper table): the filter implies the AFD
        // capture — see InetFilter::needs_etw. `-iICMP` covers v4 + v6 ICMP;
        // narrow with the `[46]` prefix (`-i6ICMP`), like TCP/UDP.
        ("icmp", Protocol::Other("ICMP")),
        ("raw", Protocol::Other("RAW")),
    ] {
        if low.starts_with(name) {
            proto = Some(p);
            s = &s[name.len()..];
            break;
        }
    }

    let mut host = None;
    if let Some(after) = s.strip_prefix('@') {
        // `[::1]` brackets an IPv6 address, whose colons are not the port's.
        let (h, rest) = if let Some(inner) = after.strip_prefix('[') {
            let close = inner
                .find(']')
                .ok_or_else(|| format!("unterminated [ in: -i {text}"))?;
            (&inner[..close], &inner[close + 1..])
        } else {
            match after.find(':') {
                Some(c) => (&after[..c], &after[c..]),
                None => (after, ""),
            }
        };
        if !h.is_empty() {
            let ip: std::net::IpAddr = h.parse().map_err(|_| {
                format!("host names are not resolved: -i {text} (give the address)")
            })?;
            // An all-zero address is no constraint at all to the C
            // (`is_nw_addr()` skips the comparison when every byte is 0).
            if !ip.is_unspecified() {
                host = Some(ip);
            }
        }
        s = rest;
    }

    let mut ports = Vec::new();
    if let Some(list) = s.strip_prefix(':') {
        for part in list.split(',').filter(|p| !p.is_empty()) {
            let num = |t: &str| -> Result<u16, String> {
                if t.bytes().all(|b| b.is_ascii_digit()) {
                    t.parse::<u16>()
                        .map_err(|_| format!("port out of range in: -i {text}"))
                } else {
                    Err(format!(
                        "service names are not resolved: -i {text} (give the port number)"
                    ))
                }
            };
            let range = match part.split_once('-') {
                Some((lo, hi)) => (num(lo)?, num(hi)?),
                None => {
                    let p = num(part)?;
                    (p, p)
                }
            };
            if range.0 > range.1 {
                return Err(format!("bad port range in: -i {text}"));
            }
            ports.push(range);
        }
    } else if !s.is_empty() {
        return Err(format!("unknown protocol name ({s}) in: -i {text}"));
    }

    sel.inet.specs.push(lsof_core::InetSpec {
        text,
        proto,
        family,
        ports,
        host,
    });
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

    /// Parse and hand back the column choices, or the error.
    fn columns(argv: &[&str]) -> Result<(Columns, Selection), String> {
        match parse(argv.iter().map(|s| s.to_string()).collect())? {
            Action::Run {
                columns, selection, ..
            } => Ok((columns, selection)),
            other => panic!("expected Run, got {other:?}"),
        }
    }

    /// `-o [digits]`, every spelling measured against the C (DIVERGENCES 6).
    /// The value is only ever digits; anything else is given back to be
    /// parsed again, which is what makes `-ot` and `-o /file` work.
    #[test]
    fn dash_o_takes_only_digits_and_gives_the_rest_back() {
        let (c, _) = columns(&["-o"]).unwrap();
        assert!(c.offset && c.offset_digits == 8);
        // A digit limit alone does NOT switch the OFFSET column on.
        for argv in [&["-o5"][..], &["-o", "5"][..]] {
            let (c, _) = columns(argv).unwrap();
            assert!(!c.offset && c.offset_digits == 5, "{argv:?}");
        }
        let (c, _) = columns(&["-o0", "-o"]).unwrap();
        assert!(c.offset && c.offset_digits == 0, "-o0 is no limit");
        // What follows the digits is option letters again, attached or not.
        for argv in [&["-o3t"][..], &["-o", "3t"][..], &["-ot"][..]] {
            let (_, sel) = columns(argv).unwrap();
            assert!(sel.terse, "{argv:?}");
        }
        // A word that is not digits is not the value.
        let (c, sel) = columns(&["-o", "/tmp/x"]).unwrap();
        assert!(c.offset && sel.paths == ["/tmp/x"]);
        let (c, sel) = columns(&["-o", "-p", "1"]).unwrap();
        assert!(c.offset && sel.pids == [1]);
        // The C overflows an int here; this saturates, which means "no hex".
        let (c, _) = columns(&["-o", "99999999999999999999999999"]).unwrap();
        assert_eq!(c.offset_digits, usize::MAX);
    }

    /// `-s` is the SIZE column without a value and a state filter with one —
    /// and a word that opens an option is not a value.
    #[test]
    fn dash_s_alone_is_the_size_column() {
        let (c, sel) = columns(&["-s"]).unwrap();
        assert!(c.size && sel.state_filter.is_none());
        // lsof-rs had read `-p` as the state and `1` as a file name.
        let (c, sel) = columns(&["-s", "-p", "1"]).unwrap();
        assert!(c.size && sel.pids == [1] && sel.paths.is_empty());
        for argv in [&["-sTCP:LISTEN"][..], &["-s", "TCP:LISTEN"][..]] {
            let (c, sel) = columns(argv).unwrap();
            assert!(!c.size && sel.state_filter.is_some(), "{argv:?}");
        }
    }

    /// `main.c:1091`: `-o` and `-s` cannot both be given, in either order —
    /// and `-Fo` counts as `-o`, because selecting the `o` field sets the same
    /// flag. A bare `-F` and a digit limit do not.
    #[test]
    fn dash_o_and_dash_s_are_mutually_exclusive() {
        for argv in [
            &["-o", "-s"][..],
            &["-s", "-o"][..],
            &["-os"][..],
            &["-Fo", "-s"][..],
            &["-s", "-Ffo"][..],
        ] {
            assert_eq!(
                columns(argv).err().as_deref(),
                Some("-o and -s are mutually exclusive"),
                "{argv:?}"
            );
        }
        for argv in [
            &["-F", "-s"][..],
            &["-o5", "-s"][..],
            &["-o", "-sTCP:LISTEN"][..],
        ] {
            assert!(columns(argv).is_ok(), "{argv:?}");
        }
    }

    /// `-c`'s argument rules, each measured against the C: a value that opens
    /// an option is missing, one that opens with `/` is a regex (refused, not
    /// read literally), a name the kernel could never hold is refused, and the
    /// same name selected and excluded is a conflict.
    #[test]
    fn dash_c_refuses_what_could_never_match() {
        let err = |argv: &[&str]| parse(argv.iter().map(|s| s.to_string()).collect()).err();
        assert_eq!(
            err(&["-c", "-p"]).as_deref(),
            Some("missing -c option value")
        );
        assert!(err(&["-c", "/pyt/"]).is_some_and(|e| e.contains("not implemented")));
        assert_eq!(
            err(&["-c", "sleep", "-c", "^sleep"]).as_deref(),
            Some("-c^sleep and -csleep conflict.")
        );
        assert_eq!(
            err(&["-c", "^sleep", "-c", "sleep"]).as_deref(),
            Some("-c^sleep and -csleep conflict.")
        );
        // A prefix of the other is not the same name, and is no conflict.
        assert!(err(&["-c", "sle", "-c", "^sleep"]).is_none());
        if cfg!(target_os = "linux") {
            // `comm` holds 15 bytes; the C refuses 16 with this text, for an
            // exclusion too (and names it without the `^`).
            for argv in [
                &["-c", "abcdefghijklmnop"][..],
                &["-c", "^abcdefghijklmnop"][..],
            ] {
                assert_eq!(
                    err(argv).as_deref(),
                    Some("\"-c abcdefghijklmnop\" length (16) > what system provides (15)")
                );
            }
            assert!(err(&["-c", "abcdefghijklmno"]).is_none(), "15 is fine");
        }
    }

    /// `-p ^N` excludes, a repeated PID is one item, and one both selected and
    /// excluded is refused — `lsof: PID 1 has been included and excluded.`
    #[test]
    fn dash_p_takes_exclusions_and_refuses_contradictions() {
        let (sel, _) = run(&["-p", "^1,2", "-p", "2,3"]);
        assert_eq!(sel.pid_excludes, [1]);
        assert_eq!(sel.pids, [2, 3], "the repeat is dropped, order kept");
        let err = parse(vec!["-p".into(), "1".into(), "-p".into(), "^1".into()]).err();
        assert_eq!(
            err.as_deref(),
            Some("PID 1 has been included and excluded.")
        );
    }

    /// `-g` is the C's process-group option wherever there are process groups:
    /// the PGID column always, and with a value, selection (`^` excludes).
    #[cfg(not(windows))]
    #[test]
    fn dash_g_selects_process_groups_and_adds_the_column() {
        let (c, sel) = columns(&["-g"]).unwrap();
        assert!(c.pgid && sel.pgids.is_empty() && sel.ppid_filter.is_empty());
        // A word that opens an option is not the value.
        let (c, sel) = columns(&["-g", "-p", "1"]).unwrap();
        assert!(c.pgid && sel.pgids.is_empty() && sel.pids == [1]);
        let (c, sel) = columns(&["-g", "5,^6"]).unwrap();
        assert!(c.pgid && sel.pgids == [5] && sel.pgid_excludes == [6]);
        assert!(sel.ppid_filter.is_empty(), "not the Windows PPID extension");
        let (_, sel) = columns(&["-g7"]).unwrap();
        assert_eq!(sel.pgids, [7]);
        let err = parse(vec!["-g".into(), "1,^1".into()]).err();
        assert_eq!(
            err.as_deref(),
            Some("PGID 1 has been included and excluded.")
        );
    }

    /// Windows has no process groups; `-g` there is its PPID extension.
    #[cfg(windows)]
    #[test]
    fn dash_g_on_windows_selects_children_of_a_ppid() {
        let (c, sel) = columns(&["-g", "4"]).unwrap();
        assert!(!c.pgid && sel.ppid_filter == [4] && sel.pgids.is_empty());
        assert!(columns(&["-g"]).is_err());
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

    /// `-K`'s argument rule, measured against the C (`main.c` case 'K'):
    /// the next word is taken as the argument UNLESS it opens an option, and
    /// the comparison is `strcasecmp`. Both halves were wrong: lsof-rs took
    /// only a literal `i`, so `-K I` was rejected and `-K /some/path` became a
    /// bare `-K` plus a name — a whole-host task listing where the C exits 1.
    #[test]
    fn dash_k_argument_rule() {
        let bare = |argv: &[&str]| run(argv).0.tasks;
        // No argument at all, and an argument that opens an option: bare `-K`.
        assert_eq!(bare(&["-K"]), TaskMode::Always);
        assert_eq!(bare(&["-K", "-p", "1"]), TaskMode::Always);
        assert_eq!(bare(&["-K", "+c", "0"]), TaskMode::Always);
        // The `-p 1` after a bare `-K` is still parsed as an option, not eaten.
        assert_eq!(run(&["-K", "-p", "1"]).0.pids, vec![1]);
        // `i`, attached or separate, in either case.
        for argv in [
            &["-Ki"][..],
            &["-K", "i"][..],
            &["-KI"][..],
            &["-K", "I"][..],
        ] {
            assert_eq!(bare(argv), TaskMode::Never, "{argv:?}");
        }
        // Anything else is a usage error — and is CONSUMED, so it never
        // reaches `paths`. A path argument is the case that matters: it is
        // the one that used to parse as a name and list the whole host.
        for argv in [
            &["-K", "x"][..],
            &["-Kx"][..],
            &["-K", "ii"][..],
            &["-K", "/etc/passwd"][..],
        ] {
            let err = parse(argv.iter().map(|s| s.to_string()).collect())
                .expect_err(&format!("{argv:?} must be rejected"));
            assert!(err.contains("-K not followed by i"), "{argv:?}: {err}");
        }
    }

    #[test]
    fn inet_spec() {
        let (sel, _) = run(&["-iTCP@127.0.0.1:443"]);
        assert!(sel.inet.enabled && !sel.inet.all);
        let s = &sel.inet.specs[0];
        assert_eq!(s.text, "TCP@127.0.0.1:443");
        assert_eq!(s.proto, Some(Protocol::Tcp));
        assert_eq!(s.host, Some("127.0.0.1".parse().unwrap()));
        assert_eq!(s.ports, [(443, 443)]);
    }

    #[test]
    fn inet_family_and_port_only() {
        // A bare `-i6`, then a spec that inherits its version, as the C's
        // `enter_network_address()` has it.
        let (sel, _) = run(&["-i6", "-i:53"]);
        assert!(sel.inet.all && sel.inet.all_family == Some(6));
        assert_eq!(sel.inet.specs.len(), 1);
        assert_eq!(sel.inet.specs[0].family, Some(6));
        assert_eq!(sel.inet.specs[0].ports, [(53, 53)]);
    }

    /// Every `-i` is kept, not just the last: `-i :80 -i :443` is two
    /// specifications, ORed — lsof-rs had let each overwrite the one before.
    /// And the spec may be the next word, unless that word opens an option.
    #[test]
    fn every_dash_i_is_its_own_specification() {
        let (sel, _) = run(&["-i", ":80", "-i:443", "-i", "-p", "1"]);
        let texts: Vec<&str> = sel.inet.specs.iter().map(|s| s.text.as_str()).collect();
        assert_eq!(texts, [":80", ":443"]);
        assert!(sel.inet.all, "the last -i was bare");
        assert_eq!(sel.pids, [1]);
        let (sel, _) = run(&["-i:22,80,1000-2000"]);
        assert_eq!(sel.inet.specs[0].ports, [(22, 22), (80, 80), (1000, 2000)]);
        let (sel, _) = run(&["-i6@[::1]:80"]);
        assert_eq!(sel.inet.specs[0].host, Some("::1".parse().unwrap()));
        assert_eq!(sel.inet.specs[0].family, Some(6));
        // An all-zero address constrains nothing, to the C.
        assert_eq!(run(&["-i@0.0.0.0:80"]).0.inet.specs[0].host, None);
    }

    /// `-i4`, `-i6` and a bare `-i` combine the C's asymmetric way.
    #[test]
    fn bare_dash_i_versions_combine_as_the_cs_do() {
        for (argv, want) in [
            (&["-i4"][..], Some(4)),
            (&["-i4", "-i6"][..], None),
            (&["-i4", "-i"][..], None),
            (&["-i", "-i4"][..], Some(4)),
            (&["-i6", "-i6"][..], Some(6)),
        ] {
            let (sel, _) = run(argv);
            assert!(sel.inet.all, "{argv:?}");
            assert_eq!(sel.inet.all_family, want, "{argv:?}");
        }
    }

    /// What the C resolves and lsof-rs does not is refused rather than
    /// matched wrongly: `-i:http` had listed every Internet file.
    #[test]
    fn names_the_c_would_resolve_are_refused() {
        let err = |a: &str| parse(vec![a.to_string()]).err().unwrap_or_default();
        assert!(err("-i:http").contains("service names are not resolved"));
        assert!(err("-i@localhost").contains("host names are not resolved"));
        assert!(err("-i:70000").contains("out of range"));
        assert!(err("-i:9-1").contains("bad port range"));
        assert!(err("-iSCTP").contains("unknown protocol"));
        assert!(err("-i@[::1").contains("unterminated"));
    }

    #[test]
    fn inet_etw_families_icmp_raw() {
        // Roadmap §5 P3: RAW/ICMP are ETW-only families; the spec accepts
        // them like tcp/udp (case-insensitive, family prefix composes) and
        // the parsed filter reports that it implies the ETW capture.
        let (sel, _) = run(&["-iICMP"]);
        assert_eq!(sel.inet.specs[0].proto, Some(Protocol::Other("ICMP")));
        assert!(sel.inet.needs_etw());

        let (sel, _) = run(&["-i6icmp"]);
        assert_eq!(sel.inet.specs[0].family, Some(6));
        assert_eq!(sel.inet.specs[0].proto, Some(Protocol::Other("ICMP")));

        let (sel, _) = run(&["-iRAW"]);
        assert_eq!(sel.inet.specs[0].proto, Some(Protocol::Other("RAW")));
        assert!(sel.inet.needs_etw());

        // TCP/UDP/plain -i never imply the capture.
        assert!(!run(&["-iTCP"]).0.inet.needs_etw());
        assert!(!run(&["-i"]).0.inet.needs_etw());
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
        assert!(paths(&["+D", "C:\\tmp"]).is_empty());
    }

    #[test]
    fn plus_d_is_one_level_and_plus_d_upper_is_the_tree() {
        // lsof distinguishes them: `+d` reports the directory and its
        // immediate entries, `+D` descends the whole tree. They were parsed
        // into one list, which both missed rows and invented them.
        let one = |a: &[&str]| run(a).0.dirs_one_level;
        assert_eq!(one(&["+dC:\\x"]), vec!["C:\\x".to_string()]);
        assert_eq!(one(&["+d", "C:\\x"]), vec!["C:\\x".to_string()]);
        assert!(dirs(&["+d", "C:\\x"]).is_empty(), "+d is not a tree");
        assert!(one(&["+D", "C:\\x"]).is_empty(), "+D is not one level");
        // The error text names the option the user actually typed.
        assert!(parse(vec!["+d".into()])
            .unwrap_err()
            .contains("+d requires a path"));
        assert!(parse(vec!["+D".into()])
            .unwrap_err()
            .contains("+D requires a path"));
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
            Action::Run { columns, .. } => columns.ppid,
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
        // `-y` and `-Y` are `illegal option character` to the C on this
        // dialect too, so they are stable markers for "not an option at all".
        // This test used to name `-Z`, which was unsupported until P4
        // implemented its gate — a rejection test pinned to a letter is a
        // rejection test that expires the day the letter is implemented.
        for o in ["-y", "-Y", "-M"] {
            assert!(parse(vec![o.into()]).is_err(), "{o} should be rejected");
        }
        // And the letters P4 added are NOT rejected any more.
        for o in ["-X", "-N", "-Z"] {
            assert!(parse(vec![o.into()]).is_ok(), "{o} should parse");
        }
    }

    #[test]
    fn endpoint_modes() {
        assert_eq!(run(&["-E"]).0.endpoints, Some(EndpointMode::Info));
        assert_eq!(run(&["+E"]).0.endpoints, Some(EndpointMode::Files));
        // +E is a superset of -E: a later -E must not downgrade it.
        assert_eq!(run(&["+E", "-E"]).0.endpoints, Some(EndpointMode::Files));
        assert_eq!(run(&["-E", "+E"]).0.endpoints, Some(EndpointMode::Files));
        assert_eq!(run(&[]).0.endpoints, None);
    }

    #[test]
    fn user_filter_parses() {
        // `-u` takes a value, either attached or as the next argument, and
        // accepts a comma-separated list like lsof's other selectors.
        assert_eq!(run(&["-u", "alice"]).0.users, vec!["alice"]);
        assert_eq!(run(&["-ualice"]).0.users, vec!["alice"]);
        assert_eq!(
            run(&["-u", "alice,EXAMPLE\\bob"]).0.users,
            vec!["alice", "EXAMPLE\\bob"]
        );
        assert!(run(&[]).0.users.is_empty());
    }
    #[test]
    fn dash_x_and_dash_i_together_are_fatal_in_every_spelling() {
        // Measured: `lsof -X -i` exits 1 with exactly this line. -X stops the
        // inet tables being read, so -i would select against nothing; the C
        // refuses rather than silently returning an empty set.
        let want = "-i is useless when -X is specified.";
        for argv in [
            vec!["-X", "-i"],
            vec!["-i", "-X"],
            vec!["-Xi"],
            vec!["-aXi"],
            vec!["-X", "-iTCP"],
        ] {
            let got = parse(argv.iter().map(|s| s.to_string()).collect());
            match got {
                Err(e) => assert_eq!(e, want, "for {argv:?}"),
                Ok(_) => panic!("{argv:?} should be rejected"),
            }
        }
    }

    #[test]
    fn dash_x_alone_is_accepted_and_selects_nothing() {
        // The flag suppresses a lookup; it is not a selector, so it must not
        // turn a whole-host run into a filtered one.
        match parse(vec!["-X".to_string()]).unwrap() {
            Action::Run { selection, .. } => {
                assert!(selection.skip_inet_tables);
                assert!(!selection.inet.enabled, "-X must not imply -i");
                assert!(selection.pids.is_empty());
            }
            other => panic!("unexpected action: {other:?}"),
        }
    }
    #[test]
    fn dash_x_needs_a_directory_argument_and_known_letters() {
        // Both contracts measured against the C, message for message.
        assert_eq!(
            parse(vec!["-x".into(), "-p".into(), "1".into()]).unwrap_err(),
            "-x must accompany +d or +D"
        );
        assert_eq!(
            parse(vec!["-xq".into(), "+d".into(), "/tmp".into()]).unwrap_err(),
            "unknown cross-over option: q"
        );
        // A known letter alongside an unknown one still fails, and names the
        // unknown one — the C loops over the value rather than testing it whole.
        assert_eq!(
            parse(vec!["-xfz".into(), "+d".into(), "/tmp".into()]).unwrap_err(),
            "unknown cross-over option: z"
        );
        // `+D` satisfies it too, and the check is order-independent.
        assert!(parse(vec!["+D".into(), "/tmp".into(), "-x".into()]).is_ok());
    }

    #[test]
    fn dash_x_letters_select_the_two_cross_overs_independently() {
        // Bare -x is XO_ALL; each letter is one half. Measured: `-x f` does
        // NOT follow a symlink (the oracle skipped the link either way), and
        // `-x l` does.
        let flags = |a: &[&str]| match parse(a.iter().map(|s| s.to_string()).collect()).unwrap() {
            Action::Run { selection, .. } => {
                (selection.cross_filesystems, selection.cross_symlinks)
            }
            other => panic!("unexpected action: {other:?}"),
        };
        assert_eq!(
            flags(&["-x", "+d", "/tmp"]),
            (true, true),
            "bare -x is both"
        );
        assert_eq!(flags(&["-xf", "+d", "/tmp"]), (true, false));
        assert_eq!(flags(&["-xl", "+d", "/tmp"]), (false, true));
        assert_eq!(flags(&["-xfl", "+d", "/tmp"]), (true, true));
        assert_eq!(flags(&["+d", "/tmp"]), (false, false), "default is neither");
    }
    #[test]
    fn dash_z_takes_an_optional_context_the_way_dash_k_does() {
        let sel = |a: &[&str]| match parse(a.iter().map(|s| s.to_string()).collect()).unwrap() {
            Action::Run { selection, .. } => selection.selinux,
            other => panic!("unexpected action: {other:?}"),
        };
        // Bare -Z is Some(empty): given, with no context filter.
        assert_eq!(sel(&["-Z"]), Some(vec![]));
        // Attached and separate both take the value.
        assert_eq!(sel(&["-Zunconfined_u"]), Some(vec!["unconfined_u".into()]));
        assert_eq!(
            sel(&["-Z", "unconfined_u"]),
            Some(vec!["unconfined_u".into()])
        );
        // A word that opens an option is NOT the value (`main.c`'s rule), so
        // `-Z -p 1` is a bare -Z plus a -p, not a context named "-p".
        assert_eq!(sel(&["-Z", "-p", "1"]), Some(vec![]));
        // Repeats accumulate, as the C's hash of context arguments does.
        assert_eq!(
            sel(&["-Z", "a", "-Z", "b"]),
            Some(vec!["a".into(), "b".into()])
        );
        // Absent stays None — the gate must not fire on a run that never said -Z.
        assert_eq!(sel(&["-p", "1"]), None);
    }
}
