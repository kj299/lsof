//! lsof-compatible option parsing, read the way the C's `main.c` reads it.
//!
//! The options are the ones `lsof -h` lists (`usage()` in `main.rs`). Flags may
//! be clustered (e.g. `-ai`); a value option takes the rest of the token or the
//! next argument (e.g. `-p123` or `-p 123`), and an optional value is taken
//! from the next argument only when that argument does not open an option. A
//! bare path argument names a file; `+d <dir>` names a directory and its
//! entries, `+D <dir>` the whole tree beneath it.

use std::ffi::OsString;

use lsof_core::model::tcp_state_table;
use lsof_core::readlink::ReadlinkError;
use lsof_core::render::fields::{field_is_default, field_known, FIELD_TABLE};
use lsof_core::render::{Escaper, FileFlags, Format, DEFAULT_OFFSET_DIGITS};
use lsof_core::safefs::{TMLIMIT, TMLIMMIN};
use lsof_core::selection::StateFilter;
use lsof_core::{
    errno_text, CommandMatch, CommandWidth, DirArg, EndpointMode, FdFilter, FdKind, FdSpec,
    FilesystemArgs, Protocol, SafeFs, Selection, TaskMode, TcpInfoFlags,
};

/// What the CLI should do after parsing.
#[derive(Debug)]
// Built once per invocation, then matched once — the size gap between the unit
// variants and `Run` is irrelevant here, and boxing would only add an alloc.
#[allow(clippy::large_enum_variant)]
pub enum Action {
    Help,
    /// `-F ?`: the field letters, and nothing else.
    FieldHelp,
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
    /// `+L`: an NLINK column after SIZE/OFF. `-L` turns it off again — the
    /// C's `Fnlink`, which the prefix sets and nothing else does.
    pub nlink: bool,
    /// `+f g` / `+f G`: the open file's flags, by name or in hex, in a
    /// FILE-FLAG column and in `-F`'s `G` field (DIVERGENCES 46).
    pub file_flags: FileFlags,
}

impl Default for Columns {
    fn default() -> Self {
        Self {
            ppid: false,
            pgid: false,
            offset: false,
            size: false,
            offset_digits: DEFAULT_OFFSET_DIGITS,
            nlink: false,
            file_flags: FileFlags::Off,
        }
    }
}

/// What every `-F` chose, accumulated as the C accumulates it: its
/// `FieldSel[].st` flags are only ever set and its `Terminator` only ever
/// set to NUL, so a later `-F` adds to an earlier one rather than replacing
/// it.
#[derive(Debug, Default)]
struct FieldChoice {
    /// A bare `-F`, or `-F0`: the C's default set, every letter lsof-rs
    /// prints but `r`.
    defaults: bool,
    /// The letters named, less `0`.
    letters: Vec<char>,
    /// A `0` somewhere: NUL terminators.
    nul: bool,
}

impl FieldChoice {
    fn format(&self) -> Format {
        let only = if !self.defaults {
            Some(self.letters.clone())
        } else if self.letters.iter().all(|&c| field_is_default(c)) {
            None
        } else {
            // The default set and a letter it leaves out (`-F -Fr`, which the
            // C prints with the raw device number): spell the set out, since
            // no list means the default set alone.
            Some(
                FIELD_TABLE
                    .iter()
                    .filter(|f| f.default)
                    .map(|f| f.id)
                    .chain(self.letters.iter().copied())
                    .collect(),
            )
        };
        Format::Fields {
            nul: self.nul,
            only,
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

/// Parse the argument list (excluding `argv[0]`), examining a `+d`/`+D`
/// directory in this process and warning on stderr: what the tests and the
/// fuzz target use. `lsof` itself parses with [`parse_with`], over its
/// bounded layer.
pub fn parse(args: Vec<String>) -> Result<Action, String> {
    parse_with(args, &SafeFs::in_process())
}

/// Parse the argument list (excluding `argv[0]`). A `+d`/`+D` directory is
/// examined where it stands, as the C's `enter_dir()` examines it, through
/// `fs` under the `-b`, `-O`, `-S` and `-w` given before it; a warning the C
/// prints while it parses (`-S time (N) changed to 2`, `avoiding stat(P)`)
/// goes to `fs`'s sink at once, before any error the parse then returns.
pub fn parse_with(mut args: Vec<String>, fs: &SafeFs) -> Result<Action, String> {
    let mut sel = Selection::default();
    let mut format = Format::Table;
    let mut want_help = false;
    let mut want_version = false;
    let mut repeat: Option<u64> = None;
    let mut columns = Columns::default();
    // Every `-s TCP:` state, across all the `-s` options: the C's tables are
    // global, so two `-s` make one filter (lsof-rs kept the last one).
    let mut states = StateFilter::default();
    // `-F` with an explicit `o` letter switches the C's `Foffset` on too
    // (`main.c`, `if (i == LSOF_FIX_OFFSET) Foffset = 1`) — so it collides
    // with a bare `-s` exactly as `-o` does. A bare `-F` selects the field
    // without that side effect.
    let mut fields_offset = false;
    let mut fields = FieldChoice::default();
    let mut field_help = false;
    // The C's `Fsv & FSV_FG` and `FsvFlagX`, which `-F` and the letters of
    // `-f`/`+f` set in argument order: whether the flags are shown, and
    // whether in hex. Folded into `columns.file_flags` once every option is
    // read.
    let mut flags_shown = false;
    let mut flags_hex = false;
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

        // An option word is a cluster of letters under one prefix, `-` or `+`,
        // and the C's `GetOpt` treats the prefix as no more than a flag it
        // hands each letter: `+wa` is `+w` then `+a`, and a letter whose case
        // never consults the prefix means under `+` what it means under `-`.
        // lsof-rs read one letter per `+` word and dropped the rest, so
        // `lsof +wa -p P -d 3` ORed where the C ANDs: 28 rows where the C
        // lists one, measured.
        let (plus, body) = match (tok.strip_prefix('+'), tok.strip_prefix('-')) {
            (Some(body), _) => (true, body),
            (None, Some(body)) => (false, body),
            (None, None) => {
                // A bare argument is a path/name to look up.
                sel.paths.push(tok.clone());
                i += 1;
                continue;
            }
        };
        if body.is_empty() {
            return Err(if plus {
                "unsupported option: +".to_string()
            } else {
                "a lone '-' is not a valid option".to_string()
            });
        }
        let prefix = if plus { '+' } else { '-' };

        let chars: Vec<char> = body.chars().collect();
        let mut j = 0;
        while j < chars.len() {
            let c = chars[j];
            match c {
                // The C gives these a `+` meaning lsof-rs does not implement
                // (`+n`/`+P` resolve names, `+r` repeats until nothing is
                // open, `+e` still reads links, and `+J`/`+j` are errors there
                // too), so the `+` spelling is refused rather than read as the
                // `-` one.
                'n' | 'P' | 'r' | 'e' | 'J' | 'j' if plus => {
                    return Err(format!("unsupported option: +{c}"))
                }
                // `+d` is ONE level (the directory and its immediate entries);
                // `+D` descends the whole tree. lsof distinguishes them. Both
                // are checked here, at the option, as the C's `enter_dir()`
                // runs where it meets them (see [`enter_dir`]).
                'd' | 'D' if plus => {
                    let rest: String = chars[j + 1..].iter().collect();
                    // With no word left the C's `enter_dir()` gets no path,
                    // and says so in its own words, muted by `-w`.
                    let value = if !rest.is_empty() {
                        rest
                    } else {
                        i += 1;
                        args.get(i).cloned().unwrap_or_default()
                    };
                    let dir = enter_dir(&value, c == 'D', &sel, fs)?;
                    sel.dir_args.push(dir);
                    if c == 'd' {
                        sel.dirs_one_level.push(value);
                    } else {
                        sel.dir_trees.push(value);
                    }
                    j = chars.len();
                    continue;
                }
                // `+c <n>`: cap the COMMAND column at n characters.
                'c' if plus => {
                    let rest: String = chars[j + 1..].iter().collect();
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
                    j = chars.len();
                    continue;
                }
                'a' => sel.and_mode = true,
                'n' => sel.no_host_resolve = true,
                'P' => sel.no_port_resolve = true,
                // The C's `-t` sets `Fwarn` as well, which is what makes an
                // unreadable file leave no row — and a process with nothing
                // else, no PID (DIVERGENCES 37). `+w` after it undoes that.
                't' => {
                    sel.terse = true;
                    sel.omit_unreadable = true;
                }
                'r' => {
                    // `-r [t]`: the delay is attached or the next word, and a
                    // word that opens an option is not one (`main.c`) — so
                    // `lsof -r 2 -p P` repeats every two seconds. lsof-rs had
                    // taken only an attached delay, and looked for a file
                    // called `2`. Only the leading digits are the delay; the C
                    // then reads `c<count>` and `m<format>`, which lsof-rs
                    // refuses rather than half-reads, and gives anything else
                    // back as options, the way `-o` does.
                    if let Some((word, _)) = value_word(&chars, j, &args, i) {
                        let digits = word.chars().take_while(char::is_ascii_digit).count();
                        if word[digits..]
                            .trim_start_matches(' ')
                            .starts_with(['c', 'm'])
                        {
                            return Err(format!(
                                "-r {word}: a repeat count (c) and marker format (m) are not supported"
                            ));
                        }
                    }
                    let delay = take_digits(&chars, &mut j, &mut args, &mut i, prefix);
                    repeat = Some(delay.map_or(15, |d| digits_value(&d) as u64));
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
                    match take_digits(&chars, &mut j, &mut args, &mut i, prefix) {
                        Some(digits) => columns.offset_digits = digits_value(&digits),
                        None => columns.offset = true,
                    }
                    continue;
                }
                'v' => want_version = true,
                'V' => sel.verbose = true,
                'h' | '?' => want_help = true,
                'l' => sel.numeric_ids = true,
                'L' => {
                    // `-L` / `+L [n]` (`main.c`, DIVERGENCES 41). The prefix
                    // switches the NLINK column — `-L` OFF, which is the
                    // default, and `+L` on — and only `+L` takes a count:
                    // `+L n` also selects files with fewer than n links. lsof-rs
                    // had read `-L` as "show" and refused a bare `+L`.
                    columns.nlink = plus;
                    if !plus
                        && value_word(&chars, j, &args, i)
                            .is_some_and(|(word, _)| word.starts_with(|d: char| d.is_ascii_digit()))
                    {
                        return Err("no number may follow -L".to_string());
                    }
                    match take_digits(&chars, &mut j, &mut args, &mut i, prefix) {
                        Some(digits) => sel.max_links = Some(digits_value(&digits) as u64),
                        // With no count the C sets `Nlink = 0` and leaves the
                        // selection flag an earlier `+L n` raised, so `+L1 -L`
                        // selects nothing at all rather than everything.
                        None => {
                            if let Some(limit) = sel.max_links.as_mut() {
                                *limit = 0;
                            }
                        }
                    }
                    continue;
                }
                'H' => sel.human_size = true,
                // `-X` toggles (`main.c`: `Fxopt = Fxopt ? 0 : 1`), under
                // either prefix, so `-X -X` is off again and `-X -X -i` is
                // no conflict (DIVERGENCES 45): the C judges `-i` against
                // the value every `-X` leaves.
                'X' => sel.skip_inet_tables = !sel.skip_inet_tables,
                'N' => sel.nfs_only = true,
                'Z' => {
                    // `-Z [context]`. The value is attached or the next word,
                    // and a word that opens an option is not one — the same
                    // rule `-K` uses (`main.c`: `*GOv != '-' && *GOv != '+'`).
                    let context = optional_value(&chars, j, &args, &mut i);
                    let list = sel.selinux.get_or_insert_with(Vec::new);
                    list.extend(context);
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
                    // A file system path starts with `/`, or it is the
                    // missing value's error: `-e dev/` and `-e ""` are
                    // `-e not followed by a file system path: "dev/"`, exit 1
                    // (measured), where lsof-rs had exempted every file for
                    // an empty one.
                    if !value.starts_with('/') {
                        return Err(format!("-e not followed by a file system path: {value:?}"));
                    }
                    // Without its trailing slashes, and once, as
                    // `enter_efsys()` keeps it: `-e /dev/shm/` is printed
                    // `(-e /dev/shm)`, and reported `"-e /dev/shm" is not a
                    // mounted file system.` (both measured). `/` stays `/`.
                    let trimmed = match value.trim_end_matches('/') {
                        "" => "/",
                        t => t,
                    };
                    if !sel.exempt_fs.iter().any(|e| e == trimmed) {
                        sel.exempt_fs.push(trimmed.to_string());
                    }
                    j = chars.len();
                    continue;
                }
                'x' => {
                    // `-x [fl]`: bare is both (`main.c`'s XO_ALL), otherwise
                    // each letter adds one. An unknown letter is fatal, and
                    // the C names it — `lsof: unknown cross-over option: q`.
                    // The letters may be the next word (`-x f`), and a word
                    // that opens an option is not one, so `-x /tmp` is that
                    // error rather than a bare `-x` and a file name.
                    match optional_value(&chars, j, &args, &mut i) {
                        None => {
                            sel.cross_filesystems = true;
                            sel.cross_symlinks = true;
                        }
                        Some(letters) => {
                            for c in letters.chars() {
                                match c {
                                    'f' => sel.cross_filesystems = true,
                                    'l' => sel.cross_symlinks = true,
                                    other => {
                                        return Err(format!("unknown cross-over option: {other}"))
                                    }
                                }
                            }
                        }
                    }
                    j = chars.len();
                    continue;
                }
                'U' => sel.unix_only = true,
                // `+E` also lists the peers' own files. `-E` after `+E` must
                // not downgrade that — lsof treats +E as a superset of -E.
                'E' => {
                    if plus {
                        sel.endpoints = Some(EndpointMode::Files);
                    } else if sel.endpoints != Some(EndpointMode::Files) {
                        sel.endpoints = Some(EndpointMode::Info);
                    }
                }
                'Q' => sel.quiet = true,
                // `-w` leaves out what cannot be read and mutes the warnings;
                // `+w` restores both (the default).
                'w' => {
                    sel.suppress_warnings = !plus;
                    sel.omit_unreadable = !plus;
                }
                'f' => {
                    // `-f` alone forces every path argument to be a plain
                    // file; `+f` forces it to be a file system, and widens
                    // what counts as one to any mount source, not just a block
                    // device. With letters it is the C's kernel file-structure
                    // option instead, and leaves the path arguments alone. The
                    // letters may be the next word, and a word that opens an
                    // option is not one (`main.c`), so `lsof -f /dev/null` is
                    // refused, as the C refuses it (`unknown file struct
                    // option: /`), and the path goes after `--`.
                    match optional_value(&chars, j, &args, &mut i) {
                        None => {
                            sel.filesystem_args = if plus {
                                FilesystemArgs::AlwaysFilesystem
                            } else {
                                FilesystemArgs::NeverFilesystem
                            }
                        }
                        // Of the file-structure values Linux has only the
                        // flags: `+` shows them and `-` hides them, and the
                        // last of `g` (by name) and `G` (in hex) says how
                        // (`main.c`: `FsvFlagX = (*GOv == 'G')`, DIVERGENCES
                        // 46). Any other letter is the C's error, and so are
                        // these where no flags are recorded.
                        Some(letters) => {
                            for c in letters.chars() {
                                match c {
                                    'g' | 'G' if HAS_FILE_FLAGS => {
                                        flags_shown = plus;
                                        flags_hex = c == 'G';
                                    }
                                    other => {
                                        return Err(format!("unknown file struct option: {other}"))
                                    }
                                }
                            }
                        }
                    }
                    j = chars.len();
                    continue;
                }
                // `-b`/`+b`: make no call that can block (`main.c`: the
                // prefix is not consulted). It beats `-O` (DIVERGENCES 94).
                'b' => sel.blocking.avoid = true,
                // `-O`: make those calls in-process, with no time limit; `+O`
                // undoes it, and the last one wins (`main.c`:
                // `lsof_avoid_forking(ctx, (GOp == '-') ? 1 : 0)`, measured
                // by counting forks: `-O +O` forks, `+O -O` does not).
                'O' => sel.blocking.in_process = !plus,
                'S' => {
                    // `-S [t]` / `+S [t]`, the prefix ignored: the seconds a
                    // bounded call may take. The value is `-o`'s shape
                    // (`main.c`): only leading digits, and none, or a word
                    // that opens an option, is the default, 15. Below 2 it is
                    // raised to 2 with a warning printed there and then,
                    // whatever `-w` or `-t` say, once per such `-S` (all
                    // measured). The C sums the digits in an `int` and
                    // wraps: `-S 4294967295` warns `(-1)`, `-S 4294967297`
                    // warns `(1)`. Here they stop at `INT_MAX`, a C-DEFECT
                    // not reproduced (DIVERGENCES 121), and a limit that
                    // large waits as long as the system does (no deadline is
                    // computed that could overflow).
                    let digits = take_digits(&chars, &mut j, &mut args, &mut i, prefix);
                    sel.blocking.limit = match digits {
                        None => TMLIMIT,
                        Some(d) => {
                            let n = digits_value(&d).min(i32::MAX as usize) as u32;
                            if n < TMLIMMIN {
                                fs.tell(&format!(
                                    "lsof: WARNING: -S time ({n}) changed to {TMLIMMIN}"
                                ));
                                TMLIMMIN
                            } else {
                                n
                            }
                        }
                    };
                    continue;
                }
                // `+T` is `-T`'s inverse only in the no-letter case: with
                // letters, `main.c` reads them identically and the prefix is
                // never consulted.
                'T' => {
                    let letters = optional_value(&chars, j, &args, &mut i).unwrap_or_default();
                    sel.tcp_info_opt = Some(parse_tcp_info(&letters, plus)?);
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
                    match optional_value(&chars, j, &args, &mut i) {
                        None => sel.tasks = TaskMode::Always,
                        // `strcasecmp`, so `-K I` is `-K i`.
                        Some(v) if v.eq_ignore_ascii_case("i") => sel.tasks = TaskMode::Never,
                        Some(v) => return Err(format!("-K not followed by i (but by {v})")),
                    }
                    j = chars.len();
                    continue;
                }
                'F' => {
                    // `-F [f]`: the list is attached or the next word, and a
                    // word that opens an option is not one (`main.c`) — so
                    // `lsof -F pn` selects `p` and `n`, where lsof-rs had
                    // looked for a file called `pn` (DIVERGENCES 43). `?`
                    // alone lists the letters; any other letter the C's table
                    // lacks is fatal, where lsof-rs had printed `-Fpx` as
                    // `-Fp`. Every `-F` adds to the one choice, as the C's
                    // `FieldSel[].st` flags do: `-Fn -Fp` is `p` and `n`, and
                    // a `0` anywhere keeps NUL terminators.
                    let value = optional_value(&chars, j, &args, &mut i);
                    let this_defaults = match value.as_deref() {
                        Some("?") => {
                            field_help = true;
                            j = chars.len();
                            continue;
                        }
                        // Bare, or `0` alone: the C's default set.
                        None | Some("0") => true,
                        Some(list) => {
                            if let Some(bad) = list.chars().find(|f| !field_known(*f)) {
                                return Err(format!("unknown field: {bad}"));
                            }
                            false
                        }
                    };
                    let letters = value.as_deref().unwrap_or("");
                    fields.nul |= letters.contains('0');
                    // `-F` shows the flags, in hex, when it selects `G`: the
                    // default set does, and so does the letter (`main.c`:
                    // `Ffield = FsvFlagX = 1`, and `G`'s `FieldSel` entry sets
                    // `FSV_FG`). A `+f g` after it asks for names instead.
                    if this_defaults || letters.contains('G') {
                        flags_shown = true;
                        flags_hex = true;
                    }
                    if this_defaults {
                        fields.defaults = true;
                    } else {
                        fields.letters.extend(letters.chars().filter(|f| *f != '0'));
                        fields_offset |= letters.contains('o');
                    }
                    // The C's field table gives some letters a side effect:
                    // selecting one also switches on the collection it needs
                    // (`store.c` — `T` carries `Ftcptpi |= TCPTPI_ALL`). That is
                    // why bare `-F` prints `TQR=`/`TQS=` with no `-T` at all.
                    // Linux compiles the window block out of `print_tcptpi()`
                    // and rejects `-T w`, so "all" is state + queues there.
                    // The other side effects (`k`→nlink, `g`/`R`→pgid/ppid,
                    // `o`→offset) are no-ops here: those values are always
                    // gathered, so the field prints whenever it has one. The
                    // effect belongs to the `-F` that names the letter: a
                    // `-T q` between two `-F`s narrows what the first chose,
                    // and a later `-Fn` must not widen it back.
                    if this_defaults || letters.contains('T') {
                        let t = sel.tcp_info_opt.get_or_insert(TcpInfoFlags::default());
                        t.state = true;
                        t.queue = true;
                    }
                    format = fields.format();
                    j = chars.len();
                    continue;
                }
                'i' => {
                    // `-i [spec]`: the spec is attached or the next word, and
                    // a word that opens an option is not one (`main.c`). So
                    // `-i :80` is the spec `:80` — lsof-rs had read it as a
                    // bare `-i` and a file called `:80`.
                    let spec = optional_value(&chars, j, &args, &mut i).unwrap_or_default();
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
                    // Each `-d` extends the one list, as the C's `Fdl` grows:
                    // lsof-rs kept only the last (DIVERGENCES 51).
                    let quiet = sel.omit_unreadable;
                    enter_fd_list(&mut sel.fd_filter, &value, quiet)?;
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
                    let value = optional_value(&chars, j, &args, &mut i);
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
                    match optional_value(&chars, j, &args, &mut i) {
                        Some(v) => parse_state_spec(&mut states, &v)?,
                        None => columns.size = true,
                    }
                    j = chars.len();
                    continue;
                }
                other => return Err(format!("unsupported option: {prefix}{other}")),
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
    // A UID both selected and excluded, found as the C finds it: while it
    // parses, so before `-h` or `-v` is acted on. A login name waits for the
    // backend to resolve it (DIVERGENCES 73).
    let uid = |v: &String| {
        (!v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
            .then(|| v.parse::<u32>().ok())
            .flatten()
    };
    if let Some(both) = sel
        .users
        .iter()
        .filter_map(uid)
        .find(|u| sel.user_excludes.iter().filter_map(uid).any(|x| x == *u))
    {
        return Err(format!("UID {both} has been included and excluded."));
    }
    // A state both included and excluded, from any two `-s` options. The C
    // checks this once every option is read and names the state as its table
    // spells it, first by table order.
    if let Some(both) = tcp_state_table()
        .iter()
        .find(|st| states.include.contains(st) && states.exclude.contains(st))
    {
        return Err(format!(
            "can't include and exclude TCP state: {}",
            both.as_str()
        ));
    }
    if !states.include.is_empty() || !states.exclude.is_empty() {
        sel.state_filter = Some(states);
    }
    columns.file_flags = match (flags_shown, flags_hex) {
        (false, _) => FileFlags::Off,
        (true, false) => FileFlags::Names,
        (true, true) => FileFlags::Hex,
    };
    // Checked after the loop because the two may come in either order. `-o 5`
    // is only a digit limit and does not count; `-Fo` does (see above).
    if (columns.offset || fields_offset) && columns.size {
        return Err("-o and -s are mutually exclusive".to_string());
    }
    if want_help {
        return Ok(Action::Help);
    }
    if field_help {
        return Ok(Action::FieldHelp);
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
    // `-a` with nothing to AND is a usage error, and the run never starts:
    // `main.c` refuses `-a` when its selection flags are all clear
    // (DIVERGENCES 50). Exclusions set none, so `-a -p ^1` or `-a -K i` is
    // refused too, where lsof-rs had listed the whole host.
    if sel.and_mode && sel.specified().is_empty() {
        return Err("no select options to AND via -a".to_string());
    }
    Ok(Action::Run {
        selection: sel,
        format,
        repeat,
        columns,
    })
}

/// A `+d`/`+D` directory, checked as the C's `enter_dir()` checks it
/// (`arg.c`), where the option stands: the C expands it while it parses.
///
/// The directory is spelt by `Readlink()` (DIVERGENCES 63), then `stat`ed,
/// each through the bounded layer under the `-b`, `-O` and `-S` given so far
/// — under `-b` neither is made, and the C says so (DIVERGENCES 94). That one
/// `stat` is all the walk knows of the directory ([`DirArg::stat`],
/// DIVERGENCES 111). A value that is empty or starts an option, one
/// `Readlink()` gives up on, one that cannot be `stat`ed (a timeout and `-b`
/// included) and one that is no directory each end the run, as a usage
/// error: before anything is listed, `-Q` or not, and ahead of `-h` and `-v`.
/// lsof-rs had warned and carried on (DIVERGENCES 74). The message is muted
/// by a `-w` or `-t` given before the option, the C's `Fwarn` as it stands
/// then, and the run still ends; and the `-x` given so far is the one its
/// walk obeys (DIVERGENCES 75), as are the `-b`, `-O` and `-S`.
fn enter_dir(value: &str, recursive: bool, sel: &Selection, fs: &SafeFs) -> Result<DirArg, String> {
    let warn = !sel.omit_unreadable;
    let said = |message: String| if warn { message } else { String::new() };
    let esc = Escaper::for_host();
    // The C's own words, for `+D` too.
    if value.is_empty() || value.starts_with('+') || value.starts_with('-') {
        return Err(said("+d not followed by a directory path".to_string()));
    }
    let fs = fs.with(sel.blocking, warn);
    let dir = resolve_dir(value, &fs).map_err(|e| said(e.message(&esc.text(value))))?;
    let shown = || esc.bytes(dir.as_encoded_bytes()).into_owned();
    match fs.stat(std::path::Path::new(&dir)) {
        Err(e) => Err(said(format!(
            "WARNING: can't stat({}): {}",
            shown(),
            errno_text(&e)
        ))),
        Ok(st) if !st.is_dir() => Err(said(format!("WARNING: not a directory: {}", shown()))),
        // The C keeps this one `stat` for the walk (`arg.c:905,915`), so the
        // walk does not ask again (DIVERGENCES 111).
        Ok(st) => Ok(DirArg {
            recursive,
            dir,
            cross_filesystems: sel.cross_filesystems,
            cross_symlinks: sel.cross_symlinks,
            warn,
            blocking: sel.blocking,
            stat: st,
        }),
    }
}

/// A `+d`/`+D` directory as the C spells it: its `Readlink()`. Windows has no
/// such reading, and keeps it as typed.
#[cfg(unix)]
fn resolve_dir(value: &str, fs: &SafeFs) -> Result<OsString, ReadlinkError> {
    lsof_core::readlink::resolve(value.as_ref(), fs)
}

#[cfg(not(unix))]
fn resolve_dir(value: &str, _fs: &SafeFs) -> Result<OsString, ReadlinkError> {
    Ok(value.into())
}

/// One `-d` option's list, entered as `enter_fd()` enters it (`arg.c`), into
/// the run's one list: every `-d` adds to it. A leading `^` excludes, and an
/// empty item (`,`, or a `^` alone) enters nothing. The list is all
/// inclusions or all exclusions: an item of the other kind, in this option or
/// an earlier one, is refused (`exclude in an include -d list: ^4`). Under
/// `-w` or `-t` (the C's `Fwarn`) the refusal says nothing, and still ends the
/// run, so the error comes back empty.
fn enter_fd_list(filter: &mut Option<FdFilter>, value: &str, quiet: bool) -> Result<(), String> {
    if value.is_empty() {
        return Err("no file descriptor specified".to_string());
    }
    for item in value.split(',') {
        let (exclude, body) = match item.strip_prefix('^') {
            Some(rest) => (true, rest),
            None => (false, item),
        };
        if body.is_empty() {
            continue;
        }
        // A range is checked first (`ckfd_range()`), then the list's kind,
        // then a name (`enter_fd_lst()`): the C's order, and so its message.
        let range = match body.rfind('-') {
            Some(dash) => Some(fd_range(body, dash)?),
            None => None,
        };
        let f = filter.get_or_insert_with(FdFilter::default);
        let excluding = if !f.exclude.is_empty() {
            Some(true)
        } else if !f.include.is_empty() {
            Some(false)
        } else {
            None
        };
        if let Some(was) = excluding.filter(|was| *was != exclude) {
            if quiet {
                return Err(String::new());
            }
            let kind = |x: bool| if x { "exclude" } else { "include" };
            let shown = match range {
                Some((lo, hi)) => format!("{lo}-{hi}"),
                None => body.to_string(),
            };
            return Err(format!(
                "{} in an {} -d list: {}{shown}",
                kind(exclude),
                kind(was),
                if exclude { "^" } else { "" }
            ));
        }
        let spec = match range {
            Some((lo, hi)) => FdSpec::Range(lo, hi),
            None => fd_named(body)?,
        };
        // A repeat is kept, not looked for: matching takes the first hit, and
        // a search per item made a long list quadratic to enter.
        if exclude {
            f.exclude.push(spec);
        } else {
            f.include.push(spec);
        }
    }
    Ok(())
}

/// `ckfd_range()`: digits on both sides of an item's last `-`, the low end
/// below the high one. `3-3` is refused, and `1-` is a high end of 0.
fn fd_range(item: &str, dash: usize) -> Result<(u64, u64), String> {
    let shown = Escaper::for_host().text(item);
    if dash == 0 {
        return Err(format!("illegal FD range for -d: {shown}"));
    }
    let number = |digits: &str| {
        if digits.bytes().all(|b| b.is_ascii_digit()) {
            fd_number(digits, item)
        } else {
            Err(format!("non-digit in -d FD range: {shown}"))
        }
    };
    let lo = number(&item[..dash])?;
    let hi = number(&item[dash + 1..])?;
    if lo >= hi {
        return Err(format!("-d FD range's low >= its high: {shown}"));
    }
    Ok((lo, hi))
}

/// A `-d` number, all digits, of at most `INT_MAX`. The C sums the digits in
/// an `int` with no overflow check, so a larger one wraps: `-d 4294967299` is
/// fd 3 to it. Refused here instead, a C-DEFECT not reproduced.
fn fd_number(digits: &str, item: &str) -> Result<u64, String> {
    const INT_MAX: u64 = i32::MAX as u64;
    digits
        .bytes()
        .try_fold(0u64, |n, b| {
            let n = n * 10 + u64::from(b - b'0');
            (n <= INT_MAX).then_some(n)
        })
        .ok_or_else(|| {
            format!(
                "-d FD number exceeds INT_MAX: {}",
                Escaper::for_host().text(item)
            )
        })
}

/// The names of FD kinds the C's table has for dialects other than Linux's
/// (`enter_fd_lst()`). It accepts them anywhere, and here no row carries one,
/// so each selects nothing, as it selects nothing from the C on Linux.
const OTHER_DIALECTS_FD_NAMES: [&str; 10] = [
    "err", "pd", "ltx", "fp", "twd", "ctty", "jd.", "v86", "m86", "mmap",
];

/// An `-d` item that is not a range: a number, or a name from the C's table.
/// `fd` is every numbered descriptor, 0 to `INT_MAX`.
fn fd_named(name: &str) -> Result<FdSpec, String> {
    if name.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(FdSpec::Num(fd_number(name, name)?));
    }
    Ok(match name {
        "cwd" => FdSpec::Named(FdKind::Cwd),
        "rtd" => FdSpec::Named(FdKind::Rtd),
        "txt" => FdSpec::Named(FdKind::Txt),
        "mem" => FdSpec::Named(FdKind::Mem),
        // The rows that carry these: a deleted mapping, a process whose fd
        // directory could not be opened, and one whose kind is unknown.
        "DEL" => FdSpec::Named(FdKind::Del),
        "NOFD" => FdSpec::Named(FdKind::NoFd),
        "unk" => FdSpec::Named(FdKind::Unknown),
        "fd" => FdSpec::Range(0, i32::MAX as u64),
        _ => match OTHER_DIALECTS_FD_NAMES.iter().find(|n| **n == name) {
            Some(n) => FdSpec::Named(FdKind::OtherDialect(n)),
            None => return Err("invalid fd type given in -d option".to_string()),
        },
    })
}

/// A `-p` or `-g` list, read as `enter_id()` reads it (`arg.c`): items
/// separated by `,` and nothing else, each digits after an optional `^`. An
/// empty item is ID 0, so `-p ,` asks for PID 0 and `-p ^` excludes it, and a
/// trailing comma ends the list (DIVERGENCES 49). Anything else, a space
/// included, makes the whole argument illegal: `illegal process ID: 1 2`. An
/// ID too large for 32 bits is too, where the C's `int` wraps it.
fn parse_id_list(value: &str, what: &str) -> Result<Vec<(bool, u32)>, String> {
    let mut ids = Vec::new();
    let mut rest = value;
    while !rest.is_empty() {
        let (item, tail) = rest.split_once(',').unwrap_or((rest, ""));
        let (excl, digits) = match item.strip_prefix('^') {
            Some(rest) => (true, rest),
            None => (false, item),
        };
        let id = if digits.is_empty() {
            Some(0)
        } else if digits.bytes().all(|b| b.is_ascii_digit()) {
            digits.parse::<u32>().ok()
        } else {
            None
        };
        let Some(id) = id else {
            // `safestrprt(p, …)`: the whole argument, escaped.
            return Err(format!(
                "illegal {what}: {}",
                Escaper::for_host().text(value)
            ));
        };
        ids.push((excl, id));
        rest = tail;
    }
    Ok(ids)
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
            for (excl, pid) in parse_id_list(value, "process ID")? {
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
        //
        // The list is `-p`'s (`enter_uid()`), so an empty item is UID 0:
        // `-u ,` selects root and `-u ^` excludes it (DIVERGENCES 69). An item
        // longer than a login name may be, `LOGINML` bytes after its `^`, is
        // refused whatever it holds, digits included.
        'u' => {
            let mut rest = value;
            while !rest.is_empty() {
                let (item, tail) = rest.split_once(',').unwrap_or((rest, ""));
                let (excl, name) = match item.strip_prefix('^') {
                    Some(name) => (true, name),
                    None => (false, item),
                };
                if name.len() > LOGINML {
                    return Err(format!(
                        "-u login name > {LOGINML} characters: {}",
                        Escaper::for_host().text(item)
                    ));
                }
                let name = if name.is_empty() { "0" } else { name };
                if excl {
                    sel.user_excludes.push(name.to_string());
                } else {
                    sel.users.push(name.to_string());
                }
                rest = tail;
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

/// The longest login name the C takes from `-u`, `LOGINML` (`common.h`).
const LOGINML: usize = 32;

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

/// Whether this platform records an open file's flags, which is what decides
/// whether `g` and `G` are letters of `-f`/`+f`.
///
/// Linux reads them from `fdinfo`. Windows has none to read, and a dialect of
/// the C without them compiles the letters out (`HASNOFSFLAGS`), so `+f g`
/// there is refused rather than answered with a column that is always blank.
#[cfg(target_os = "linux")]
const HAS_FILE_FLAGS: bool = true;
#[cfg(not(target_os = "linux"))]
const HAS_FILE_FLAGS: bool = false;

/// The word an option's optional value would be, as the C's `GetOpt` offers
/// it to every option whose rule letter carries a `:` — the rest of this
/// word, or else the next word — and whether it is the next word. Nothing is
/// consumed.
///
/// The next word is not offered when it opens an option, because every such
/// option gives it back (`main.c`: `if (!GOv || *GOv == '-' || *GOv == '+')`).
/// That is the whole rule: `lsof -T q` takes `q`, `lsof -T /some/path` takes
/// the path and then rejects `/` as a letter, and `lsof -T -i` is a bare `-T`
/// followed by `-i`. `--` opens an option too, and ends the options after.
fn value_word(chars: &[char], j: usize, args: &[String], i: usize) -> Option<(String, bool)> {
    if j + 1 < chars.len() {
        return Some((chars[j + 1..].iter().collect(), false));
    }
    args.get(i + 1)
        .filter(|next| !next.starts_with(['-', '+']))
        .map(|next| (next.clone(), true))
}

/// [`value_word`], taken: the next word is consumed when it is the value.
fn optional_value(chars: &[char], j: usize, args: &[String], i: &mut usize) -> Option<String> {
    let (word, next) = value_word(chars, j, args, *i)?;
    if next {
        *i += 1;
    }
    Some(word)
}

/// An optional value whose meaning is its leading digits — `-o`, `-r`, `-S`
/// and `+L` each read theirs digit by digit and stop at the first that is
/// not one (`main.c`) — taken, with what follows the digits given back, and
/// the scan left where the C's `GetOpt` resumes:
///
/// * attached (`-o3t`), the letters after the digits are options again, so
///   the cluster goes on at the first of them — at the value's first letter
///   when there are no digits at all (`-ot` is `-o -t`);
/// * the next word (`-o 3t`) is taken only when it opens with a digit, and
///   what follows its digits is read as option letters under the same
///   prefix, as the C resumes in the middle of the word. A next word with no
///   digits is not consumed at all: `-o /file` is `-o` and a file name.
fn take_digits(
    chars: &[char],
    j: &mut usize,
    args: &mut [String],
    i: &mut usize,
    prefix: char,
) -> Option<String> {
    if *j + 1 < chars.len() {
        let digits: String = chars[*j + 1..]
            .iter()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        *j += 1 + digits.len();
        return (!digits.is_empty()).then_some(digits);
    }
    *j = chars.len();
    let next = args.get(*i + 1)?;
    let digits: String = next.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return None;
    }
    let leftover = next[digits.len()..].to_string();
    if leftover.is_empty() {
        *i += 1;
    } else {
        args[*i + 1] = format!("{prefix}{leftover}");
    }
    Some(digits)
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

/// Add one `-s <protocol>:<states>` value to `filter`, as the C's
/// `enter_state_spec()` (`src/arg.c`) does, with its messages.
///
/// * The protocol is `TCP:` or `UDP:`, in any case, colon included; anything
///   else is `unknown -s protocol: "<value>"`.
/// * A state is a name from [`tcp_state_table`] in any case, `^` excluding
///   it. An unknown name, an empty one (`TCP:A,,B`) and the same name twice
///   in one list — across `-s` options too, since the C's tables are global
///   — are each fatal.
/// * `UDP:` with names is refused with the message the man page promises for
///   a protocol whose states are unavailable. The C on Linux has a UDP table
///   whose first slot is empty and `strcasecmp`s it: every `-s UDP:<state>`
///   is a segfault, measured (DIVERGENCES 32). Windows has no UDP states.
fn parse_state_spec(filter: &mut StateFilter, value: &str) -> Result<(), String> {
    let lower = value.get(..4).map(str::to_ascii_lowercase);
    let proto = match lower.as_deref() {
        Some("tcp:") => "TCP",
        Some("udp:") => "UDP",
        _ => return Err(format!("unknown -s protocol: \"{value}\"")),
    };
    let names = &value[4..];
    if names.is_empty() {
        return Err(format!("no {proto} state names in: {value}"));
    }
    if proto == "UDP" {
        return Err(format!("no UDP state names available: {value}"));
    }
    for term in names.split(',') {
        let (exclude, name) = match term.strip_prefix('^') {
            Some(rest) => (true, rest),
            None => (false, term),
        };
        if name.is_empty() {
            return Err(format!("NULL TCP state name in: {value}"));
        }
        let Some(state) = tcp_state_table()
            .iter()
            .copied()
            .find(|st| st.as_str().eq_ignore_ascii_case(name))
        else {
            return Err(format!("unknown TCP state name: {name}"));
        };
        let list = if exclude {
            &mut filter.exclude
        } else {
            &mut filter.include
        };
        if list.contains(&state) {
            let which = if exclude { "exclusion" } else { "inclusion" };
            return Err(format!("duplicate TCP {which}: {name}"));
        }
        list.push(state);
    }
    Ok(())
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

    /// A directory every host has: the parser checks a `+d`/`+D` where it
    /// stands, as the C's `enter_dir()` does, so a made-up one is an error.
    fn a_dir() -> String {
        std::env::temp_dir().to_string_lossy().into_owned()
    }

    /// Parse and hand back the column choices, or the error.
    /// `-e` (DIVERGENCES 98, 105): a file system path, or the missing
    /// value's error; kept without its trailing slashes, and once.
    #[test]
    fn dash_e_takes_a_path_once_without_its_trailing_slashes() {
        let fs = |argv: &[&str]| columns(argv).map(|(_, s)| s.exempt_fs);
        assert_eq!(fs(&["-e", "/dev/shm/"]).unwrap(), ["/dev/shm"]);
        assert_eq!(fs(&["-e", "///"]).unwrap(), ["/"]);
        assert_eq!(
            fs(&["-e", "/dev", "-e", "/", "-e", "/dev/"]).unwrap(),
            ["/dev", "/"],
            "a repeat keeps its first place"
        );
        assert_eq!(
            fs(&["-e", ""]).unwrap_err(),
            r#"-e not followed by a file system path: """#
        );
        assert_eq!(
            fs(&["-e", "dev/"]).unwrap_err(),
            r#"-e not followed by a file system path: "dev/""#
        );
    }

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

    /// `-s TCP:<states>`, every message measured against the C
    /// (`enter_state_spec()`, and `main.c`'s include/exclude check). lsof-rs
    /// had taken any text as a state and kept only the last `-s`, so a typo
    /// listed nothing and exited 0.
    #[test]
    fn dash_s_takes_the_cs_state_names_and_refuses_the_rest() {
        use lsof_core::TcpState::{Close, Established, Listen, TimeWait};
        let states = |argv: &[&str]| columns(argv).map(|(_, sel)| sel.state_filter);
        // Case is unimportant; lists and repeated options accumulate.
        let f = states(&["-stcp:listen,^Time_Wait", "-sTCP:ESTABLISHED"])
            .unwrap()
            .expect("a filter");
        assert_eq!(f.include, [Listen, Established]);
        assert_eq!(f.exclude, [TimeWait]);
        if cfg!(not(windows)) {
            // The Linux names, which are not Windows': CLOSE and SYN_RECV.
            assert_eq!(states(&["-sTCP:close"]).unwrap().unwrap().include, [Close]);
            assert_eq!(
                states(&["-sTCP:SYN_RCVD"]).err().as_deref(),
                Some("unknown TCP state name: SYN_RCVD")
            );
        }
        for (argv, err) in [
            (&["-sXYZ:LISTEN"][..], "unknown -s protocol: \"XYZ:LISTEN\""),
            (&["-s", "LISTEN"][..], "unknown -s protocol: \"LISTEN\""),
            (
                &["-s", "/etc/hostname"][..],
                "unknown -s protocol: \"/etc/hostname\"",
            ),
            (&["-sTCP:"][..], "no TCP state names in: TCP:"),
            (&["-sUDP:"][..], "no UDP state names in: UDP:"),
            (
                &["-sTCP:LISTEN,,CLOSING"][..],
                "NULL TCP state name in: TCP:LISTEN,,CLOSING",
            ),
            (&["-sTCP:NOPE"][..], "unknown TCP state name: NOPE"),
            (
                &["-sTCP:LISTEN,listen"][..],
                "duplicate TCP inclusion: listen",
            ),
            (
                &["-sTCP:^LISTEN", "-sTCP:^LISTEN"][..],
                "duplicate TCP exclusion: LISTEN",
            ),
            (
                &["-sTCP:listen", "-sTCP:^LISTEN"][..],
                "can't include and exclude TCP state: LISTEN",
            ),
            // Where the C segfaults (DIVERGENCES 32): the man page's message
            // for a protocol whose states are unavailable.
            (
                &["-sUDP:Idle"][..],
                "no UDP state names available: UDP:Idle",
            ),
            (&["-sudp:^x"][..], "no UDP state names available: udp:^x"),
        ] {
            assert_eq!(states(argv).err().as_deref(), Some(err), "{argv:?}");
        }
    }

    /// The C's `-t` sets `Fwarn`, `-w` sets it and `+w` clears it, the last
    /// one winning — measured: `-t +w` lists an unreadable process, `+w -t`
    /// does not (DIVERGENCES 37). `-t` must not silence the Windows privilege
    /// hint, which is the other thing `-w` does.
    #[test]
    fn dash_t_and_dash_w_leave_unreadable_files_out_and_plus_w_after_restores() {
        let omit = |argv: &[&str]| columns(argv).unwrap().1.omit_unreadable;
        assert!(!omit(&[]));
        assert!(omit(&["-w"]) && omit(&["-t"]) && omit(&["+w", "-t"]));
        assert!(!omit(&["-t", "+w"]) && !omit(&["-w", "+w"]));
        let (_, sel) = columns(&["-t"]).unwrap();
        assert!(!sel.suppress_warnings, "-t keeps the privilege hint");
    }

    #[test]
    fn dash_d_names_the_rows_the_c_names() {
        let (_, sel) = columns(&["-d", "NOFD,DEL,unk"]).unwrap();
        let fd = sel.fd_filter.expect("a filter");
        assert_eq!(
            fd.include,
            [
                FdSpec::Named(FdKind::NoFd),
                FdSpec::Named(FdKind::Del),
                FdSpec::Named(FdKind::Unknown)
            ]
        );
        // `fd` is every numbered descriptor. Another dialect's name is no
        // error, and selects nothing here.
        let (_, sel) = columns(&["-d", "fd,ltx"]).unwrap();
        assert_eq!(
            sel.fd_filter.expect("a filter").include,
            [
                FdSpec::Range(0, i32::MAX as u64),
                FdSpec::Named(FdKind::OtherDialect("ltx"))
            ]
        );
        assert_eq!(
            columns(&["-d", "foo"]).unwrap_err(),
            "invalid fd type given in -d option"
        );
    }

    /// `-d` as `enter_fd()` reads it (DIVERGENCES 51): every `-d` adds to one
    /// list, and the list is of one kind.
    #[test]
    fn dash_d_lists_add_up_and_never_mix() {
        let fd = |argv: &[&str]| columns(argv).map(|(_, sel)| sel.fd_filter);
        let f = fd(&["-d", "3", "-d", "4"]).unwrap().unwrap();
        assert_eq!(f.include, [FdSpec::Num(3), FdSpec::Num(4)]);
        let f = fd(&["-d", "^cwd", "-d", "^rtd"]).unwrap().unwrap();
        assert_eq!(
            f.exclude,
            [FdSpec::Named(FdKind::Cwd), FdSpec::Named(FdKind::Rtd)]
        );
        // An item of the other kind, in one list or across two, is refused,
        // and named: a range as the C reads it.
        assert_eq!(
            fd(&["-d", "3,^4"]).unwrap_err(),
            "exclude in an include -d list: ^4"
        );
        assert_eq!(
            fd(&["-d", "^4", "-d", "3"]).unwrap_err(),
            "include in an exclude -d list: 3"
        );
        assert_eq!(
            fd(&["-d", "cwd", "-d", "^01-02"]).unwrap_err(),
            "exclude in an include -d list: ^1-2"
        );
        // ...in silence once `-w` or `-t` has been given, still refused.
        assert_eq!(fd(&["-t", "-d", "3,^4"]).unwrap_err(), "");
        assert_eq!(fd(&["-w", "-d", "3,^4"]).unwrap_err(), "");
        assert_eq!(
            fd(&["-d", "3,^4", "-t"]).unwrap_err(),
            "exclude in an include -d list: ^4"
        );
        // An empty item enters nothing, so no list at all.
        assert_eq!(fd(&["-d", ","]).unwrap(), None);
        assert_eq!(fd(&["-d", "^"]).unwrap(), None);
        assert_eq!(fd(&["-d", ""]).unwrap_err(), "no file descriptor specified");
        // A range: digits on both sides of the last `-`, low below high.
        assert_eq!(
            fd(&["-d", "3-3"]).unwrap_err(),
            "-d FD range's low >= its high: 3-3"
        );
        assert_eq!(
            fd(&["-d", "^3-1"]).unwrap_err(),
            "-d FD range's low >= its high: 3-1"
        );
        assert_eq!(
            fd(&["-d", "1-"]).unwrap_err(),
            "-d FD range's low >= its high: 1-"
        );
        assert_eq!(
            fd(&["-d", "-3"]).unwrap_err(),
            "illegal FD range for -d: -3"
        );
        assert_eq!(
            fd(&["-d", "1-2-3"]).unwrap_err(),
            "non-digit in -d FD range: 1-2-3"
        );
        assert_eq!(
            fd(&["-d", "01"]).unwrap().unwrap().include,
            [FdSpec::Num(1)]
        );
        // A number is at most `INT_MAX`: the C's `int` wraps a larger one.
        assert_eq!(
            fd(&["-d", "2147483647"]).unwrap().unwrap().include,
            [FdSpec::Num(2147483647)]
        );
        for item in [
            "2147483648",
            "4294967299",
            "0-2147483648",
            "99999999999999999999-1",
        ] {
            assert_eq!(
                fd(&["-d", item]).unwrap_err(),
                format!("-d FD number exceeds INT_MAX: {item}")
            );
        }
        // An argument these messages quote comes back escaped.
        assert_eq!(
            fd(&["-d", "1-2\x1b"]).unwrap_err(),
            "non-digit in -d FD range: 1-2^["
        );
    }

    /// A UID both selected and excluded ends the run before `-h` or `-v` is
    /// acted on, as the C finds it while it parses `-u`. Login names are
    /// resolved later, by the backend (DIVERGENCES 73).
    #[test]
    fn a_uid_selected_and_excluded_beats_help_and_version() {
        let both = Err("UID 0 has been included and excluded.".to_string());
        for argv in [
            &["-u", ",^", "-h"][..],
            &["-h", "-u", ",^"],
            &["-u", "^,0", "-v"],
            &["-u", "0,^00"],
        ] {
            let got = parse(argv.iter().map(|s| s.to_string()).collect()).map(|_| ());
            assert_eq!(got, both, "{argv:?}");
        }
        assert!(matches!(
            parse(vec!["-u".into(), "0,^root".into(), "-h".into()]),
            Ok(Action::Help)
        ));
    }

    /// `-p`, `-g` and `-u` lists as the C reads them (DIVERGENCES 49, 69):
    /// items split by `,` alone, an empty one ID 0, a `^` alone excluding 0,
    /// and a trailing comma ending the list.
    #[test]
    fn an_empty_id_list_item_is_id_zero() {
        let sel = |argv: &[&str]| columns(argv).map(|(_, s)| s);
        assert_eq!(sel(&["-p", ","]).unwrap().pids, [0]);
        assert_eq!(sel(&["-p", ",7"]).unwrap().pids, [0, 7]);
        assert_eq!(sel(&["-p", "7,"]).unwrap().pids, [7]);
        assert_eq!(sel(&["-p", "7,,7"]).unwrap().pids, [7, 0]);
        let s = sel(&["-p", "^", "-p", "7"]).unwrap();
        assert_eq!((s.pids, s.pid_excludes), (vec![7], vec![0]));
        assert!(sel(&["-p", ""]).unwrap().pids.is_empty());
        for bad in ["1 2", "1^2", "x", "4294967296"] {
            assert_eq!(
                sel(&["-p", bad]).unwrap_err(),
                format!("illegal process ID: {bad}")
            );
        }
        assert_eq!(
            sel(&["-p", ",^"]).unwrap_err(),
            "PID 0 has been included and excluded."
        );
        #[cfg(not(windows))]
        {
            assert_eq!(sel(&["-g", ","]).unwrap().pgids, [0]);
            assert_eq!(sel(&["-g", "^", "-p", "7"]).unwrap().pgid_excludes, [0]);
            assert_eq!(
                sel(&["-g", "1 2"]).unwrap_err(),
                "illegal process group ID: 1 2"
            );
        }
        // `-u`: UID 0 is the name `0` until the backend resolves it.
        assert_eq!(sel(&["-u", ","]).unwrap().users, ["0"]);
        assert_eq!(sel(&["-u", ",65534"]).unwrap().users, ["0", "65534"]);
        assert_eq!(sel(&["-u", "^"]).unwrap().user_excludes, ["0"]);
        assert_eq!(sel(&["-u", "0,"]).unwrap().users, ["0"]);
        assert!(sel(&["-u", ""]).unwrap().users.is_empty());
        // At most `LOGINML` bytes, its `^` aside, whatever they are.
        let long = "0".repeat(33);
        assert_eq!(
            sel(&["-u", &long]).unwrap_err(),
            format!("-u login name > 32 characters: {long}")
        );
        assert_eq!(sel(&["-u", &long[1..]]).unwrap().users, [&long[1..]]);
        let excl = format!("^{}", &long[1..]);
        assert_eq!(sel(&["-u", &excl]).unwrap().user_excludes, [&long[1..]]);
        // The refusal quotes the item escaped.
        let hostile = format!("{}\x1b[2J", "a".repeat(30));
        assert_eq!(
            sel(&["-u", &hostile]).unwrap_err(),
            format!("-u login name > 32 characters: {}^[[2J", "a".repeat(30))
        );
    }

    /// `-a` with nothing to AND is refused, as the C refuses it (DIVERGENCES
    /// 50). Exclusions select nothing; `-d ^x`, `-K` and `+L0` select.
    #[test]
    fn dash_a_needs_something_to_and() {
        let err = |argv: &[&str]| columns(argv).err();
        let refused = Some("no select options to AND via -a".to_string());
        for argv in [
            &["-a"][..],
            &["-a", "-K", "i"],
            &["-a", "-K", "-K", "i"],
            &["-a", "-p", "^1"],
            &["-a", "-c", "^x"],
            &["-a", "-u", "^nobody"],
            &["-a", "-d", ","],
            &["-a", "+L"],
            &["-a", "-n", "-P", "-l"],
        ] {
            assert_eq!(err(argv), refused, "{argv:?}");
        }
        for argv in [
            &["-a", "-d", "^cwd"][..],
            &["-a", "-K"],
            &["-a", "-K", "i", "-K"],
            &["-a", "+L0"],
            &["-a", "-U"],
            &["-a", "-i"],
            &["-a", "-p", "^1", "-p", "2"],
            &["-a", "-u", "^nobody", "-u", "root"],
            &["-a", "/x"],
            &["-a", "+d", a_dir().as_str()],
        ] {
            assert_eq!(err(argv), None, "{argv:?}");
        }
        #[cfg(target_os = "linux")]
        {
            assert_eq!(err(&["-a", "-s", "TCP:LISTEN"]), refused);
            assert_eq!(err(&["-a", "-g", "^1"]), refused);
            assert_eq!(err(&["-a", "-g"]), refused);
            assert_eq!(err(&["-a", "-N"]), None);
        }
        // Help comes first, as in the C.
        assert!(matches!(
            parse(vec!["-a".into(), "-h".into()]),
            Ok(Action::Help)
        ));
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

    /// The C accumulates `-r`'s digits in an `int` (main.c:779-783) and wraps:
    /// `-r 4294967297` repeats every second, as `-r 1` does (measured: 4
    /// `=======` markers in 3.5 s from both). lsof-rs saturates; a regression
    /// to a plain `n * 10 + d` would panic here, as it would in the release
    /// build, which checks overflow. The count saturates at `usize::MAX`
    /// (`digits_value`): `u64::MAX` on a 64-bit target, 4294967295 on a 32-bit
    /// one (run under miri for i686-unknown-linux-gnu).
    #[test]
    fn repeat_interval_saturates_rather_than_wrapping() {
        let saturated = Some(usize::MAX as u64);
        assert_eq!(repeat(&["-r99999999999999999999"]), saturated);
        assert_eq!(repeat(&["-r", "99999999999999999999"]), saturated);
        #[cfg(target_pointer_width = "64")]
        assert_eq!(repeat(&["-r4294967297"]), Some(4294967297));
        #[cfg(target_pointer_width = "32")]
        assert_eq!(repeat(&["-r4294967297"]), saturated);
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
        let d = a_dir();
        assert_eq!(dirs(&["+D", &d]), vec![d.clone()]);
        assert!(paths(&["+D", &d]).is_empty());
    }

    /// Parse as `lsof` does, over the in-process layer, and hand back what
    /// the parse printed on the way (the `-S` warning, `-b`'s messages).
    fn parse_saying(argv: &[&str]) -> (Result<Action, String>, Vec<String>) {
        let said = std::cell::RefCell::new(Vec::new());
        let say = |l: &str| said.borrow_mut().push(l.to_string());
        let fs = SafeFs::new(&lsof_core::InProcess, &say);
        let got = parse_with(argv.iter().map(|s| s.to_string()).collect(), &fs);
        (got, said.into_inner())
    }

    /// The `-b`/`-O`/`-S` a run ends with, and what the parse printed.
    fn blocking(argv: &[&str]) -> (lsof_core::Blocking, Vec<String>) {
        match parse_saying(argv) {
            (Ok(Action::Run { selection, .. }), said) => (selection.blocking, said),
            (other, _) => panic!("expected Run for {argv:?}, got {other:?}"),
        }
    }

    /// `-S [t]`, every spelling measured against the C (DIVERGENCES 94): the
    /// value is only leading digits, attached or the next word; none, or a
    /// word that opens an option, is 15; what follows the digits is options
    /// again; the last `-S` wins, and `+S` is `-S`.
    #[test]
    fn dash_s_upper_takes_its_seconds_as_the_c_does() {
        let limit = |argv: &[&str]| blocking(argv).0.limit;
        assert_eq!(limit(&[]), 15);
        assert_eq!(limit(&["-S"]), 15);
        assert_eq!(limit(&["-S", "-p", "1"]), 15);
        assert_eq!(limit(&["-S", "2"]), 2);
        assert_eq!(limit(&["-S2"]), 2);
        assert_eq!(limit(&["-S", "00000000000000000000000000002"]), 2);
        assert_eq!(limit(&["-S", "3", "-S"]), 15);
        assert_eq!(limit(&["-S", "3", "-S", "5"]), 5);
        assert_eq!(limit(&["+S", "7"]), 7);
        assert_eq!(limit(&["+S7"]), 7);
        // What follows the digits is option letters under the same prefix.
        for argv in [&["-S", "3t"][..], &["-S3t"]] {
            let (got, _) = parse_saying(argv);
            match got {
                Ok(Action::Run { selection, .. }) => {
                    assert!(selection.terse && selection.blocking.limit == 3, "{argv:?}")
                }
                other => panic!("{argv:?}: {other:?}"),
            }
        }
        assert_eq!(
            parse_saying(&["-Sx", "-p", "1"]).0.err().as_deref(),
            Some("-x must accompany +d or +D")
        );
        // A word with no digits is not the value: it is a name, and the
        // limit is the default.
        let (got, _) = parse_saying(&["-S", "x"]);
        match got {
            Ok(Action::Run { selection, .. }) => {
                assert_eq!(
                    (selection.blocking.limit, selection.paths),
                    (15, vec!["x".into()])
                )
            }
            other => panic!("{other:?}"),
        }
        // `--` opens an option, so it is not the value: what follows is names.
        let (got, _) = parse_saying(&["-S", "--", "-p", "1"]);
        match got {
            Ok(Action::Run { selection, .. }) => {
                assert_eq!(selection.paths, ["-p", "1"]);
                assert_eq!(selection.blocking.limit, 15);
            }
            other => panic!("{other:?}"),
        }
        // `-S -1`: a bare `-S`, then `-1`, which is no option (the C says
        // `illegal option character: 1`).
        assert_eq!(
            parse_saying(&["-S", "-1"]).0.err().as_deref(),
            Some("unsupported option: -1")
        );
    }

    /// Below 2 the limit is 2, with the C's warning, printed while the parse
    /// runs and whatever `-w` or `-t` say, once for each such `-S`.
    #[test]
    fn dash_s_upper_below_two_warns_whatever_dash_w_says() {
        let warn = |n: u32| format!("lsof: WARNING: -S time ({n}) changed to 2");
        assert_eq!(
            blocking(&["-S", "0"]),
            (
                lsof_core::Blocking {
                    limit: 2,
                    ..Default::default()
                },
                vec![warn(0)]
            )
        );
        assert_eq!(blocking(&["-S1"]).1, [warn(1)]);
        for argv in [
            &["-w", "-S", "1"][..],
            &["-S", "1", "-w"],
            &["-t", "-S", "1"],
            &["-wS1"],
            &["-S1w"],
        ] {
            assert_eq!(
                blocking(argv),
                (
                    lsof_core::Blocking {
                        limit: 2,
                        ..Default::default()
                    },
                    vec![warn(1)]
                ),
                "{argv:?}"
            );
        }
        assert_eq!(blocking(&["-S", "1", "-S", "0"]).1, [warn(1), warn(0)]);
        assert!(
            blocking(&["-S", "2"]).1.is_empty(),
            "2 is the minimum, not below it"
        );
        // Printed before an error the parse then finds, as the C prints it.
        let (got, said) = parse_saying(&["-S", "0x"]);
        assert_eq!(got.err().as_deref(), Some("-x must accompany +d or +D"));
        assert_eq!(said, [warn(0)]);
    }

    /// The C sums `-S`'s digits in an `int`: `4294967295` is -1 and warns,
    /// `4294967297` is 1 and warns, `99999999999` is 1215752191 (all
    /// measured, `strace -e alarm` for the last).
    /// lsof-rs stops at `INT_MAX` and says nothing (DIVERGENCES 121), and a
    /// limit that large computes no deadline that could overflow.
    #[test]
    fn dash_s_upper_saturates_where_the_c_wraps() {
        for v in [
            "2147483647",
            "2147483648",
            "4294967295",
            "4294967297",
            "99999999999",
            "99999999999999999999",
        ] {
            let (b, said) = blocking(&["-S", v]);
            assert_eq!(b.limit, i32::MAX as u32, "{v}");
            assert!(said.is_empty(), "{v}: {said:?}");
        }
    }

    /// `-b` and `+b` avoid; `-O` makes the calls in-process and `+O` undoes
    /// it, the last one winning; `-b` beats `-O` whichever comes first
    /// (measured: `-bO` and `-Ob` both make no call).
    #[test]
    fn dash_b_and_dash_o_upper_set_the_mode_as_the_c_does() {
        let b = |argv: &[&str]| {
            let b = blocking(argv).0;
            (b.avoid, b.in_process)
        };
        assert_eq!(b(&[]), (false, false));
        assert_eq!(b(&["-b"]), (true, false));
        assert_eq!(b(&["+b"]), (true, false));
        assert_eq!(b(&["-O"]), (false, true));
        assert_eq!(b(&["+O"]), (false, false));
        assert_eq!(b(&["-O", "+O"]), (false, false));
        assert_eq!(b(&["+O", "-O"]), (false, true));
        assert_eq!(b(&["-bO"]), (true, true));
        assert_eq!(b(&["-Ob"]), (true, true));
        // A -b says nothing while it parses, a run with no path named.
        assert!(blocking(&["-b", "-p", "1"]).1.is_empty());
    }

    /// A `+d`/`+D` is examined where it stands, under the `-b`, `-O`, `-S`
    /// and `-w` given before it, and its walk keeps them (DIVERGENCES 94):
    /// `-b +d D` ends the run, after the C's two `avoiding` lines, and `-w`
    /// mutes all three; `+d D -b` changes nothing for it.
    #[test]
    fn a_plus_d_is_examined_under_the_options_before_it() {
        let d = a_dir();
        let (got, said) = parse_saying(&["-b", "+d", &d]);
        // `Resource temporarily unavailable`, in the C library's words (miri's
        // shim adds its own `(os error 11)`, so the text is asked for).
        let eagain = errno_text(&lsof_core::safefs::would_block());
        assert_eq!(
            got.err(),
            Some(format!("WARNING: can't stat({d}): {eagain}"))
        );
        // Windows reads no links there (`resolve_dir`), so it avoids none.
        let mut avoided = Vec::new();
        if cfg!(unix) {
            avoided.push(format!("lsof: avoiding readlink({d}): -b was specified."));
        }
        avoided.push(format!("lsof: avoiding stat({d}): -b was specified."));
        assert_eq!(said, avoided);
        let (got, said) = parse_saying(&["-w", "-b", "+D", &d]);
        assert_eq!(got.err().as_deref(), Some(""));
        assert!(said.is_empty(), "{said:?}");
        let (got, said) = parse_saying(&["+d", &d, "-b", "-S", "9"]);
        let Ok(Action::Run { selection, .. }) = got else {
            panic!("{got:?}")
        };
        assert!(said.is_empty(), "{said:?}");
        assert_eq!(
            selection.dir_args[0].blocking,
            lsof_core::Blocking::default()
        );
        assert!(selection.blocking.avoid && selection.blocking.limit == 9);
        let held = |argv: &[&str]| {
            run(argv)
                .0
                .dir_args
                .iter()
                .map(|a| a.blocking)
                .collect::<Vec<_>>()
        };
        let at = |limit, in_process| lsof_core::Blocking {
            avoid: false,
            in_process,
            limit,
        };
        assert_eq!(
            held(&["-S", "4", "+d", &d, "-O", "-S", "6", "+D", &d, "+O"]),
            [at(4, false), at(6, true)]
        );
    }

    /// The C expands a `+d`/`+D` where it stands, so each keeps the `-x` and
    /// the `-w`/`-t` given before it, and none after (DIVERGENCES 75).
    #[test]
    fn a_plus_d_keeps_the_switches_given_before_it() {
        let d = a_dir();
        let held = |argv: &[&str]| {
            run(argv)
                .0
                .dir_args
                .iter()
                .map(|a| (a.cross_filesystems, a.cross_symlinks, a.warn))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            held(&["-x", "f", "+d", &d, "-x", "l", "+D", &d, "-w"]),
            [(true, false, true), (true, true, true)]
        );
        assert_eq!(held(&["+d", &d, "-x"]), [(false, false, true)]);
        assert_eq!(held(&["-w", "+d", &d]), [(false, false, false)]);
        assert_eq!(held(&["-t", "+D", &d]), [(false, false, false)]);
        assert_eq!(held(&["-w", "+w", "+d", &d]), [(false, false, true)]);
    }

    /// The one `stat` that examined a `+d`/`+D` directory is kept for its
    /// walk, which asks nothing more of the directory but its listing: the
    /// C's `statsafely(dn)` (`arg.c:876`) is its `ddev` and its identity
    /// (`arg.c:905,915`; DIVERGENCES 111). Its device, inode and type are
    /// compared; its link count and size may change under a test that runs
    /// beside others in the same directory.
    #[test]
    fn a_plus_d_keeps_the_stat_that_examined_it() {
        let d = a_dir();
        let want = lsof_core::safefs::stat_now(std::path::Path::new(&d), true).unwrap();
        for opt in ["+d", "+D"] {
            let got = run(&[opt, &d]).0.dir_args[0].stat;
            assert_eq!(
                (got.dev, got.ino, got.mode),
                (want.dev, want.ino, want.mode)
            );
            assert!(got.is_dir(), "{opt}");
        }
    }

    #[test]
    fn plus_d_is_one_level_and_plus_d_upper_is_the_tree() {
        // lsof distinguishes them: `+d` reports the directory and its
        // immediate entries, `+D` descends the whole tree. They were parsed
        // into one list, which both missed rows and invented them.
        let one = |a: &[&str]| run(a).0.dirs_one_level;
        let d = a_dir();
        assert_eq!(one(&[&format!("+d{d}")]), vec![d.clone()]);
        assert_eq!(one(&["+d", &d]), vec![d.clone()]);
        assert!(dirs(&["+d", &d]).is_empty(), "+d is not a tree");
        assert!(one(&["+D", &d]).is_empty(), "+D is not one level");
        let walks = |a: &[&str]| run(a).0.dir_args;
        assert!(!walks(&["+d", &d])[0].recursive);
        assert!(walks(&["+D", &d])[0].recursive);
        // With nothing after it, the C's own words, for `+D` too, and an
        // earlier `-w` mutes them.
        for argv in [&["+d"][..], &["+D"]] {
            assert_eq!(
                parse(argv.iter().map(|s| s.to_string()).collect()).unwrap_err(),
                "+d not followed by a directory path"
            );
        }
        assert_eq!(parse(vec!["-w".into(), "+D".into()]).unwrap_err(), "");
    }

    #[test]
    fn fd_filter_parsing() {
        let (sel, _) = run(&["-d", "cwd,txt,1-3"]);
        let f = sel.fd_filter.expect("fd filter");
        assert_eq!(
            f.include,
            vec![
                FdSpec::Named(FdKind::Cwd),
                FdSpec::Named(FdKind::Txt),
                FdSpec::Range(1, 3),
            ]
        );
        assert!(f.exclude.is_empty());
        let (sel, _) = run(&["-d", "^5,^cwd"]);
        let f = sel.fd_filter.expect("fd filter");
        assert_eq!(f.exclude, vec![FdSpec::Num(5), FdSpec::Named(FdKind::Cwd)]);
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

    /// `-X` toggles, as the C's `Fxopt` does, whatever the prefix (DIVERGENCES
    /// 45), and `-i` is refused only when the last `-X` left it on. Measured:
    /// `lsof -X -X -i` lists the Internet files and exits 0.
    #[test]
    fn dash_x_upper_toggles_and_dash_i_is_judged_on_the_final_value() {
        let skip = |argv: &[&str]| columns(argv).unwrap().1.skip_inet_tables;
        assert!(!skip(&[]));
        assert!(skip(&["-X"]) && skip(&["+X"]));
        assert!(!skip(&["-X", "-X"]) && !skip(&["-XX"]) && !skip(&["-X", "+X"]));
        assert!(skip(&["-X", "-X", "-X"]) && skip(&["-XXX"]));
        for argv in [
            &["-X", "-X", "-i"][..],
            &["-X", "-i", "-X"][..],
            &["-aXXi"][..],
        ] {
            assert!(columns(argv).is_ok(), "{argv:?}: -X was toggled off");
        }
        assert_eq!(
            columns(&["-X", "-X", "-X", "-i"]).unwrap_err(),
            "-i is useless when -X is specified."
        );
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
            parse(vec!["-xq".into(), "+d".into(), a_dir()]).unwrap_err(),
            "unknown cross-over option: q"
        );
        // A known letter alongside an unknown one still fails, and names the
        // unknown one — the C loops over the value rather than testing it whole.
        assert_eq!(
            parse(vec!["-xfz".into(), "+d".into(), a_dir()]).unwrap_err(),
            "unknown cross-over option: z"
        );
        // `+D` satisfies it too, and the check is order-independent.
        assert!(parse(vec!["+D".into(), a_dir(), "-x".into()]).is_ok());
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
        let d = a_dir();
        assert_eq!(flags(&["-x", "+d", &d]), (true, true), "bare -x is both");
        assert_eq!(flags(&["-xf", "+d", &d]), (true, false));
        assert_eq!(flags(&["-xl", "+d", &d]), (false, true));
        assert_eq!(flags(&["-xfl", "+d", &d]), (true, true));
        assert_eq!(flags(&["+d", &d]), (false, false), "default is neither");
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

    /// `-L` / `+L [n]`, every spelling measured against the C (DIVERGENCES
    /// 41): the prefix switches the column, only `+` takes a count, and a word
    /// that is not a count is given back.
    #[test]
    fn dash_l_hides_the_nlink_column_and_plus_l_shows_it() {
        let links = |argv: &[&str]| {
            let (cols, sel) = columns(argv).unwrap();
            (cols.nlink, sel.max_links)
        };
        assert_eq!(links(&[]), (false, None), "off by default");
        assert_eq!(links(&["-L"]), (false, None), "-L is the default, OFF");
        assert_eq!(links(&["+L"]), (true, None), "+L alone shows it");
        assert_eq!(links(&["+L1"]), (true, Some(1)));
        assert_eq!(
            links(&["+L", "1"]),
            (true, Some(1)),
            "the count may be the next word"
        );
        assert_eq!(
            links(&["+L", "-a", "-p", "1"]),
            (true, None),
            "an option is not a count"
        );
        assert_eq!(links(&["+L", "--", "/x"]), (true, None));
        assert_eq!(links(&["+L", "99999999999999999999999"]).1, Some(u64::MAX));
        // A count, then more: the letters after the digits are options again,
        // under the same prefix — `+L1a` is `+L1 -a`, and so is `+L 1a`.
        for argv in [&["+L1a"][..], &["+L", "1a"][..]] {
            let (cols, sel) = columns(argv).unwrap();
            assert!(cols.nlink && sel.and_mode, "{argv:?}");
            assert_eq!(sel.max_links, Some(1), "{argv:?}");
            assert!(sel.paths.is_empty(), "{argv:?}");
        }
        // A word that is no count is not consumed: a file name, or letters.
        // ...under the prefix the count came with: `+L 1w` is `+L1 +w`, which
        // restores the warnings `-w` muted, where `-w` would mute them again.
        let (_, sel) = columns(&["-w", "+L", "1w"]).unwrap();
        assert!(
            !sel.suppress_warnings && !sel.omit_unreadable,
            "+L 1w is +L1 +w"
        );
        assert_eq!(sel.max_links, Some(1));
        assert_eq!(columns(&["+L", "foo"]).unwrap().1.paths, vec!["foo"]);
        assert_eq!(columns(&["-L", "foo"]).unwrap().1.paths, vec!["foo"]);
        assert!(
            columns(&["-La", "-p", "1"]).unwrap().1.and_mode,
            "-La is -L -a"
        );
        // Only `+` takes a count, attached or not.
        for argv in [&["-L1"][..], &["-L", "1"][..], &["-L", "1a"][..]] {
            assert_eq!(
                columns(argv).unwrap_err(),
                "no number may follow -L",
                "{argv:?}"
            );
        }
        // A count-less `-L`/`+L` after a count sets it to 0 and keeps the
        // selection: `+L1 -L` selects nothing, it does not select everything.
        assert_eq!(links(&["+L1", "-L"]), (false, Some(0)));
        assert_eq!(links(&["+L1", "+L"]), (true, Some(0)));
        assert_eq!(
            links(&["+L1", "+L2"]),
            (true, Some(2)),
            "the last count wins"
        );
        assert_eq!(links(&["-L", "+L3"]), (true, Some(3)));
    }

    /// A `+` word is a cluster, as a `-` word is, and a letter the C reads the
    /// same under either prefix means the same thing (`+wa` is `+w -a`).
    /// lsof-rs had read one letter per `+` word and dropped the rest.
    #[test]
    fn a_plus_word_is_a_cluster_of_options() {
        let (_, sel) = columns(&["+wa", "-p", "1"]).unwrap();
        assert!(sel.and_mode && !sel.suppress_warnings && !sel.omit_unreadable);
        let (_, sel) = columns(&["-w", "+aw", "-p", "1"]).unwrap();
        assert!(sel.and_mode && !sel.suppress_warnings, "+aw is -a +w");
        let (_, sel) = columns(&["+Ea", "-p", "1"]).unwrap();
        assert_eq!(sel.endpoints, Some(EndpointMode::Files));
        assert!(sel.and_mode);
        assert_eq!(columns(&["+p", "1"]).unwrap().1.pids, vec![1]);
        // `+E` then `-E` keeps the wider mode (the C's `FeptE` only grows).
        assert_eq!(
            columns(&["+E", "-E"]).unwrap().1.endpoints,
            Some(EndpointMode::Files)
        );
        // What the C gives a `+` meaning lsof-rs lacks is refused, never read
        // as the `-` meaning — and the refusal names the `+` spelling.
        for (o, want) in [
            ("+n", "unsupported option: +n"),
            ("+P", "unsupported option: +P"),
            ("+r", "unsupported option: +r"),
            ("+e", "unsupported option: +e"),
            ("+J", "unsupported option: +J"),
            ("+aq", "unsupported option: +q"),
            ("+", "unsupported option: +"),
        ] {
            assert_eq!(columns(&[o]).unwrap_err(), want, "{o}");
        }
        assert_eq!(columns(&["-q"]).unwrap_err(), "unsupported option: -q");
    }

    /// `-F [f]` (DIVERGENCES 43): the list may be the next word, only the C's
    /// letters are fields, `?` lists them, and every `-F` adds to one choice.
    #[test]
    fn dash_f_takes_its_list_as_the_next_word_and_accumulates() {
        let fields = |argv: &[&str]| run(argv).1;
        let only = |nul: bool, letters: Option<&str>| Format::Fields {
            nul,
            only: letters.map(|l| l.chars().collect()),
        };
        assert_eq!(fields(&["-F", "pL"]), only(false, Some("pL")));
        assert!(run(&["-F", "pL"]).0.paths.is_empty(), "not a file name");
        assert_eq!(
            fields(&["-F", "0"]),
            only(true, None),
            "`0` alone is the default set"
        );
        assert_eq!(
            fields(&["-F", "-a", "-p", "1"]),
            only(false, None),
            "an option is not a list"
        );
        assert!(run(&["-F", "-a", "-p", "1"]).0.and_mode);
        assert_eq!(
            fields(&["-F00"]),
            only(true, Some("")),
            "NUL, and `p` alone"
        );
        assert_eq!(fields(&["-F0p"]), only(true, Some("p")));
        // Accumulated, as `FieldSel[].st` is.
        assert_eq!(fields(&["-Fn", "-Fp"]), only(false, Some("np")));
        assert_eq!(fields(&["-F", "-Fn"]), only(false, None));
        assert_eq!(fields(&["-Fn", "-F"]), only(false, None));
        assert_eq!(fields(&["-F0", "-Fn"]), only(true, None));
        assert_eq!(fields(&["-Fn", "-F0"]), only(true, None));
        assert_eq!(fields(&["-Fn", "-J"]), Format::Json, "the last format wins");
        // `?` lists the letters, attached or not, and nothing else happens.
        for argv in [&["-F?"][..], &["-F", "?"][..], &["-F", "?", "-p", "1"][..]] {
            assert!(
                matches!(
                    parse(argv.iter().map(|s| s.to_string()).collect()),
                    Ok(Action::FieldHelp)
                ),
                "{argv:?}"
            );
        }
        // A letter the C's table lacks is fatal and named, first one first.
        for (argv, want) in [
            (&["-Fpx"][..], "unknown field: x"),
            (&["-F", "/tmp"][..], "unknown field: /"),
            (&["-F", "p677"][..], "unknown field: 6"),
            (&["-Fp?"][..], "unknown field: ?"),
        ] {
            assert_eq!(
                parse(argv.iter().map(|s| s.to_string()).collect()).unwrap_err(),
                want
            );
        }
        // `r` is outside the default set (DIVERGENCES 47): `-F -Fr` is the set
        // spelt out with `r` added, in either order, and `-Fr` is `r` alone.
        let with_r = |argv: &[&str]| match run(argv).1 {
            Format::Fields { only: Some(l), .. } => l,
            other => panic!("{argv:?}: {other:?}"),
        };
        for argv in [&["-F", "-Fr"][..], &["-Fr", "-F"][..]] {
            let l = with_r(argv);
            assert!(
                l.contains(&'r') && l.contains(&'n') && l.contains(&'D'),
                "{argv:?}: {l:?}"
            );
            assert!(!l.contains(&'Z') && !l.contains(&'z'), "{argv:?}: {l:?}");
        }
        assert_eq!(with_r(&["-Fr"]), vec!['r']);
        assert_eq!(
            fields(&["-F", "-Fk"]),
            only(false, None),
            "k is a default letter"
        );
        // Every letter the C accepts is accepted, including the ones that
        // print nothing here.
        assert!(parse(vec!["-F0CDFGKLMNPRSTZacdfgiklmnoprstuz".into()]).is_ok());
        // `T`'s side effect belongs to the `-F` that names it: a later `-Fn`
        // must not widen a `-T q` back to the state as well.
        let tcp = |argv: &[&str]| {
            let t = run(argv).0.tcp_info_opt.unwrap();
            (t.state, t.queue)
        };
        assert_eq!(tcp(&["-F"]), (true, true));
        assert_eq!(tcp(&["-F", "-Tq"]), (false, true));
        assert_eq!(tcp(&["-Tq", "-F"]), (true, true));
        assert_eq!(tcp(&["-FT", "-Tq", "-Fn"]), (false, true));
        assert!(run(&["-Fn"]).0.tcp_info_opt.is_none());
    }

    /// `-r [t]`: the delay may be the next word, only its leading digits are
    /// the delay, and what follows them is given back — `lsof -r 2` had looked
    /// for a file called `2`.
    #[test]
    fn dash_r_takes_its_delay_as_the_next_word() {
        assert_eq!(repeat(&["-r", "2"]), Some(2));
        assert!(paths(&["-r", "2"]).is_empty());
        assert_eq!(repeat(&["-r", "-p", "1"]), Some(15));
        assert_eq!(repeat(&["-r", "abc"]), Some(15));
        assert_eq!(
            paths(&["-r", "abc"]),
            vec!["abc"],
            "no digits: not consumed"
        );
        for argv in [&["-r2a", "-p", "1"][..], &["-r", "2a", "-p", "1"][..]] {
            let (_, sel) = columns(argv).unwrap();
            assert!(sel.and_mode, "{argv:?} is -r2 -a");
            assert_eq!(repeat(argv), Some(2), "{argv:?}");
        }
        // The C's count and marker suffixes are refused, never half-read.
        for argv in [&["-r5c3"][..], &["-r", "5m%T"][..], &["-r", "c3"][..]] {
            assert!(
                parse(argv.iter().map(|s| s.to_string()).collect())
                    .unwrap_err()
                    .contains("not supported"),
                "{argv:?}"
            );
        }
    }

    /// `-x [fl]` and `-f`/`+f`: a value may be the next word, and one that
    /// opens an option is not one — so `-x /tmp` and `-f /dev/null` are the
    /// C's errors, not a bare switch and a file name.
    #[test]
    fn dash_x_and_dash_f_take_their_value_as_the_next_word() {
        let xover = |argv: &[&str]| {
            let (_, sel) = columns(argv).unwrap();
            (sel.cross_filesystems, sel.cross_symlinks)
        };
        let d = a_dir();
        assert_eq!(xover(&["+d", &d, "-x", "f"]), (true, false));
        assert_eq!(xover(&["+d", &d, "-x", "l"]), (false, true));
        assert_eq!(xover(&["-x", "+d", &d]), (true, true));
        assert_eq!(
            columns(&["+d", &d, "-x", "/tmp"]).unwrap_err(),
            "unknown cross-over option: /"
        );
        assert_eq!(
            columns(&["-f", "/dev/null"]).unwrap_err(),
            "unknown file struct option: /"
        );
        assert_eq!(
            columns(&["+f", "/dev/null"]).unwrap_err(),
            "unknown file struct option: /"
        );
        // `g` is the C's file-flags letter (DIVERGENCES 46): `-f g` hides the
        // flags, which is the default, and leaves the path arguments alone.
        // Where no flags are recorded it is a letter the platform lacks. The
        // platform is named, not `HAS_FILE_FLAGS`, so a wrong constant fails.
        if cfg!(target_os = "linux") {
            let (cols, sel) = columns(&["-f", "g"]).unwrap();
            assert_eq!(cols.file_flags, FileFlags::Off);
            assert_eq!(sel.filesystem_args, FilesystemArgs::default());
        } else {
            assert_eq!(
                columns(&["-f", "g"]).unwrap_err(),
                "unknown file struct option: g"
            );
        }
        let (_, sel) = columns(&["-f", "--", "/dev/null"]).unwrap();
        assert_eq!(sel.filesystem_args, FilesystemArgs::NeverFilesystem);
        assert_eq!(sel.paths, vec!["/dev/null"]);
        let (_, sel) = columns(&["+f", "--", "/dev/null"]).unwrap();
        assert_eq!(sel.filesystem_args, FilesystemArgs::AlwaysFilesystem);
    }

    /// `-f`/`+f` with `g` or `G`, and `-F`, in argument order, as the C reads
    /// them (DIVERGENCES 46): `+` shows the flags and `-` hides them, the last
    /// of `g` and `G` chooses names or hex, and `-F` shows them in hex when it
    /// selects `G`. Every pair measured.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_file_flags_are_shown_as_the_last_option_says() {
        let flags = |argv: &[&str]| columns(argv).unwrap().0.file_flags;
        assert_eq!(flags(&[]), FileFlags::Off);
        assert_eq!(flags(&["+fg"]), FileFlags::Names);
        assert_eq!(flags(&["+f", "g"]), FileFlags::Names, "the next word");
        assert_eq!(flags(&["+fG"]), FileFlags::Hex);
        assert_eq!(flags(&["+fgG"]), FileFlags::Hex, "the last letter decides");
        assert_eq!(flags(&["+fGg"]), FileFlags::Names);
        assert_eq!(flags(&["+fg", "-fg"]), FileFlags::Off);
        assert_eq!(flags(&["-fG", "+fg"]), FileFlags::Names);
        assert_eq!(flags(&["-F"]), FileFlags::Hex);
        assert_eq!(flags(&["-FG"]), FileFlags::Hex);
        assert_eq!(flags(&["-Fn"]), FileFlags::Off, "no G, no flags");
        assert_eq!(flags(&["-F", "+fg"]), FileFlags::Names);
        assert_eq!(flags(&["+fg", "-F"]), FileFlags::Hex);
        assert_eq!(flags(&["-F", "-fG"]), FileFlags::Off);
        assert_eq!(flags(&["-F", "+fG"]), FileFlags::Hex);
        // A bare `-f`/`+f` is the path-argument switch and leaves the flags be.
        let (cols, sel) = columns(&["+fg", "-f"]).unwrap();
        assert_eq!(cols.file_flags, FileFlags::Names);
        assert_eq!(sel.filesystem_args, FilesystemArgs::NeverFilesystem);
        let (_, sel) = columns(&["+fg"]).unwrap();
        assert_eq!(sel.filesystem_args, FilesystemArgs::default());
        // Linux compiles the other file-structure letters out.
        for (argv, want) in [
            (&["+fgx"][..], "unknown file struct option: x"),
            (&["+fc"][..], "unknown file struct option: c"),
            (&["-fn"][..], "unknown file struct option: n"),
        ] {
            assert_eq!(columns(argv).unwrap_err(), want, "{argv:?}");
        }
    }

    /// Where the backend records no flags (Windows), `g` and `G` are refused
    /// under either prefix, as a C dialect without them refuses them: asking
    /// for the flags is an error, not a FILE-FLAG column of blanks. A bare
    /// `-f`/`+f` is still the path-argument switch.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn the_file_flags_letters_are_refused_where_none_are_recorded() {
        for (argv, want) in [
            (&["+fg"][..], "unknown file struct option: g"),
            (&["+f", "G"][..], "unknown file struct option: G"),
            (&["-fg"][..], "unknown file struct option: g"),
        ] {
            assert_eq!(columns(argv).unwrap_err(), want, "{argv:?}");
        }
        let (cols, sel) = columns(&["+f", "--", "x"]).unwrap();
        assert_eq!(cols.file_flags, FileFlags::Off);
        assert_eq!(sel.filesystem_args, FilesystemArgs::AlwaysFilesystem);
    }
}
