//! lsof-compatible option parsing, read the way the C's `main.c` reads it.
//!
//! The options are the ones `lsof -h` lists (`usage()` in `main.rs`). Flags may
//! be clustered (e.g. `-ai`); a value option takes the rest of the token or the
//! next argument (e.g. `-p123` or `-p 123`), and an optional value is taken
//! from the next argument only when that argument does not open an option. A
//! bare path argument names a file; `+d <dir>` names a directory and its
//! entries, `+D <dir>` the whole tree beneath it.

use std::ffi::OsString;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use lsof_core::model::tcp_state_table;
use lsof_core::readlink::ReadlinkError;
use lsof_core::render::fields::{field_is_default, field_known, FIELD_TABLE};
use lsof_core::render::{Escaper, FileFlags, Format, JsonFormat, DEFAULT_OFFSET_DIGITS};
use lsof_core::safefs::{TMLIMIT, TMLIMMIN};
use lsof_core::selection::StateFilter;
use lsof_core::{
    errno_text, CommandMatch, CommandWidth, DirArg, EndpointMode, ExemptFs, FdFilter, FdKind,
    FdSpec, FilesystemArgs, MountRequest, MountTable, Protocol, SafeFs, Selection, TaskMode,
    TcpInfoFlags, UidSel, UserLookup,
};

/// What the CLI should do after parsing.
#[derive(Debug)]
// Built once per invocation, then matched once — the size gap between the unit
// variants and `Run` is irrelevant here, and boxing would only add an alloc.
#[allow(clippy::large_enum_variant)]
pub enum Action {
    /// `-h`, `-F ?` and `-v`, whichever were given: each is printed, on
    /// stderr, and nothing is listed ([`Reports`]).
    Report(Reports),
    Run {
        selection: Selection,
        format: Format,
        repeat: Option<u64>,
        columns: Columns,
        /// The mount table, when the parse read it: at the first `+d`/`+D`,
        /// or for the `-e` check, where the C reads it ([`parse_with`]).
        /// `None` is a table not read yet.
        mounts: Option<MountTable>,
    },
}

/// What `-h` (or `-?`), `-F ?` and `-v` ask for. The C's `usage()` acts on
/// all three at once, in this order whatever order they were given in: the
/// help, then the field letters, then the version (`usage.c`; measured, `-v
/// -h` and `-h -v -F ?` print each, exit 0). Given with an option error, the
/// help and the field letters are still printed after the error, and the
/// version after them, and the run exits 1; with neither, the error ends the
/// run with the usage hint alone, the version unprinted (`-W -h -v` prints the
/// error, the help and the version; `-W -v` the error; measured).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Reports {
    /// `-h` or `-?`.
    pub help: bool,
    /// `-F ?`.
    pub field_help: bool,
    /// `-v`.
    pub version: bool,
}

impl Reports {
    /// `-h` alone.
    pub const HELP: Reports = Reports {
        help: true,
        field_help: false,
        version: false,
    };
    /// `-F ?` alone.
    pub const FIELD_HELP: Reports = Reports {
        help: false,
        field_help: true,
        version: false,
    };
    /// `-v` alone.
    pub const VERSION: Reports = Reports {
        help: false,
        field_help: false,
        version: true,
    };

    /// Whether any was asked for.
    pub fn any(&self) -> bool {
        self.help || self.field_help || self.version
    }
}

/// What reads the mount table for the parser, under the options in force
/// where it is read ([`lsof_core::Backend::mount_table`]).
pub type MountReader<'a> = &'a dyn Fn(&MountRequest, &SafeFs) -> MountTable;

/// The mount table, read through `mounts` under the options as `sel` holds
/// them where it is read: its `-e`/`+e` list, which it neither `stat`s nor,
/// for `+e`, reads the links of, and the `-b`, `-O`, `-S` and `-w` the
/// bounded layer `fs` is viewed under. The parser reads it so at the first
/// `+d`/`+D` and for the `-e` check, and `lsof` at the first path argument or
/// before it lists.
pub fn read_mount_table(sel: &Selection, fs: &SafeFs, mounts: MountReader<'_>) -> MountTable {
    let req = MountRequest {
        exempt: sel.exempt_fs.clone(),
    };
    mounts(&req, &fs.with(sel.blocking, !sel.omit_unreadable))
}

/// What the parse asks the host where the C asks it while it reads its
/// options, so that what it answers is an option error in the C's order,
/// found before `-h`, `-v` or `-F ?` is acted on (DIVERGENCES 114):
/// `enter_uid()` looks each `-u` login up as it meets it (`can't get UID for
/// X`), and `-Z` is refused where it stands when SELinux is not enabled
/// (`-Z limited to SELinux`, `main.c:1005`). `lsof -h -u nosuch` and
/// `lsof -Z -h` exit 1 with the error and no help, measured.
#[derive(Clone, Copy)]
pub struct HostChecks<'a> {
    /// `-u`'s values, each looked up as it is read
    /// ([`lsof_core::Backend::lookup_user`]).
    pub lookup_user: &'a dyn Fn(&str) -> UserLookup,
    /// Whether SELinux is enabled: the C's `CntxStatus`.
    pub selinux_enabled: &'a dyn Fn() -> bool,
}

impl HostChecks<'static> {
    /// Nothing asked of any host: each `-u` value is kept as typed
    /// ([`UserLookup::ByName`]) and SELinux is taken to be enabled, so `-Z`
    /// is read for its value alone. What [`parse`] and [`parse_with`] use.
    pub const DEFERRED: HostChecks<'static> = HostChecks {
        lookup_user: &kept_as_typed,
        selinux_enabled: &selinux_assumed,
    };
}

/// [`HostChecks::DEFERRED`]'s user lookup.
fn kept_as_typed(_: &str) -> UserLookup {
    UserLookup::ByName
}

/// [`HostChecks::DEFERRED`]'s SELinux answer.
fn selinux_assumed() -> bool {
    true
}

/// The table [`parse`] reads: none. A test or a fuzz input holding `+d /` or
/// `-e /` examines no host mount, in-process and with no time limit, and
/// none that does not answer can hold it.
fn no_mounts(_: &MountRequest, _: &SafeFs) -> MountTable {
    MountTable::default()
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
    /// printed in hex instead (the C's `OffDecDig`, an `int`, wrapped as the
    /// C wraps it); 0 means no limit.
    pub offset_digits: i32,
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

/// What `-J`/`-j` print, from what `-F`, `-T` and `-f` chose (`main.c:1163-1179`).
///
/// With a `-F` selection — any letter but `p` and `m`, a `0`, or a bare `-F`
/// — JSON prints those fields, as `-F` would, under `-T` and `-f` as they
/// stand. Without one, the C applies its default set once every option is
/// read (`select_default_fields()`), which also forces the file flags on
/// (in hex only if the last of `-f`'s `g`/`G` was `G`, so `-J -fg` is `-J`)
/// and every TCP/TPI member, so `-J -Tq` is `-J` (measured). Those members
/// are what Linux must collect, the queues included; Windows keeps what
/// `-T` asked for, since its extended statistics write per-connection state
/// and need Administrator.
fn json_format(
    fields: &FieldChoice,
    lines: bool,
    flags_hex: bool,
    file_flags: FileFlags,
    sel: &mut Selection,
) -> Format {
    let has_fields =
        fields.defaults || fields.nul || fields.letters.iter().any(|c| !matches!(c, 'p' | 'm'));
    if has_fields {
        let only = match fields.format() {
            Format::Fields { only, .. } => only,
            _ => None,
        };
        return Format::Json(JsonFormat {
            lines,
            only,
            file_flags,
            tcp_show: sel.tcp_info(),
        });
    }
    if cfg!(target_os = "linux") {
        let t = sel.tcp_info_opt.get_or_insert(TcpInfoFlags::default());
        t.state = true;
        t.queue = true;
    }
    Format::Json(JsonFormat {
        lines,
        only: None,
        file_flags: if flags_hex {
            FileFlags::Hex
        } else {
            FileFlags::Names
        },
        tcp_show: TcpInfoFlags {
            state: true,
            queue: true,
            window: true,
            options: false,
        },
    })
}

/// A run of ASCII digits as a count, saturating rather than wrapping: `-r`'s
/// delay, `+L`'s count and `-S`'s limit, which the C accumulates in an `int`
/// and overflows. `-o`'s count is the exception, wrapped as the C wraps it
/// ([`offset_digits_value`]).
fn digits_value(digits: &str) -> usize {
    digits.bytes().fold(0usize, |n, b| {
        n.saturating_mul(10).saturating_add(usize::from(b - b'0'))
    })
}

/// `-o`'s digits as the C's `main.c` sums them: `i = (i * 10) + digit` in an
/// `int`, which wraps. Reproduced, wrap included (DIVERGENCES 117): unlike
/// `-S`'s or `-r`'s, which would set a time, this number only chooses how an
/// offset is spelt, and the C's choice past `INT_MAX - 2` (every offset in
/// hex, zero as `0`) is measured and harmless to follow — `-o 4294967296`
/// wraps to 0, no limit, and `-o 4294967297` to 1. The wrap is explicit, so
/// the release build's overflow checks never see it.
fn offset_digits_value(digits: &str) -> i32 {
    digits.bytes().fold(0i32, |n, b| {
        n.wrapping_mul(10)
            .wrapping_add(i32::from(b.wrapping_sub(b'0')))
    })
}

/// A user-supplied argument as an error message quotes it: escaped, as the
/// C's `safestrprt(…, 1)` prints it (lib/misc.c:1385-1453), so that no byte
/// of it can drive the terminal of whoever reads the message. Where the C
/// prints such an argument raw (`%s`, `%c`: `-i`'s protocol, host and
/// service, the option letters, `-K`, `-s`, `-c`'s conflict, `-e`, the `-d`
/// mixture), that is a C-DEFECT not reproduced (DIVERGENCES 112, 122).
/// Every message that quotes an argument goes through this or [`quoting`],
/// and `no_option_error_holds_a_control_character` holds every option to it.
fn shown(arg: &str) -> std::borrow::Cow<'_, str> {
    Escaper::for_host().text(arg)
}

/// [`shown`] for an argument kept as bytes (a path `Readlink()` spelt).
fn shown_bytes(arg: &[u8]) -> std::borrow::Cow<'_, str> {
    Escaper::for_host().bytes(arg)
}

/// An error message that ends with the argument it quotes: `message`, then
/// `arg` [`shown`], the C's `fprintf(stderr, message); safestrprt(arg, …)`.
fn quoting(message: &str, arg: &str) -> String {
    format!("{message}{}", shown(arg))
}

/// Parse the argument list (excluding `argv[0]`), examining a `+d`/`+D`
/// directory in this process and warning on stderr, and reading no mount
/// table: what the tests and the fuzz target use. `lsof` itself parses with
/// [`parse_with`], over its bounded layer and the host's table.
pub fn parse(args: Vec<String>) -> Result<Action, String> {
    parse_with(args, &SafeFs::in_process(), &no_mounts)
}

/// Parse the argument list (excluding `argv[0]`). A `+d`/`+D` directory is
/// examined where it stands, as the C's `enter_dir()` examines it, through
/// `fs` under the `-b`, `-O`, `-S` and `-w` given before it; a warning the C
/// prints while it parses (`-S time (N) changed to 2`, `avoiding stat(P)`)
/// goes to `fs`'s sink at once, before any error the parse then returns.
///
/// The mount table is read through `mounts` where the C reads it while it
/// parses: at the first `+d`/`+D` whose directory checked out (its
/// `ck_file_arg()`, `arg.c:915`), under the options and the `-e`/`+e` list
/// as they stand there; else for the `-e` check, once every option is read
/// (`main.c:1137-1160`). Its warnings come where the C's do: `+d D -S 0`
/// prints them before the `-S` warning, `-S 0 +d D` after, `+d D -w` prints
/// them and `-w +d D` does not (measured). The table goes back with the run
/// ([`Action::Run`]); a run that needs it and read none here reads it later.
pub fn parse_with(
    args: Vec<String>,
    fs: &SafeFs,
    mounts: MountReader<'_>,
) -> Result<Action, String> {
    parse_with_host(args, fs, mounts, &HostChecks::DEFERRED)
}

/// [`parse_with`], asking `host` what the C asks while it parses: each `-u`
/// login is looked up where it is read and each `-Z` checked against
/// SELinux, their errors reported in option order with the parse's others,
/// before `-h`, `-v` or `-F ?` is acted on ([`HostChecks`]). What `lsof`
/// itself parses with.
pub fn parse_with_host(
    args: Vec<String>,
    fs: &SafeFs,
    mounts: MountReader<'_>,
    host: &HostChecks<'_>,
) -> Result<Action, String> {
    parse_reporting(args, fs, mounts, host)
        .0
        .map_err(|e| e.to_string())
}

/// [`parse_with_host`], and the [`Reports`] the options read asked for,
/// which `lsof` still acts on when the parse ends in an error, as the C's
/// `usage()` does: `-W -h` prints the error and then the help, exit 1. They
/// are the ones read before the parse ended: an error that ends it at once
/// (DIVERGENCES 83) leaves a later `-h` unread.
pub fn parse_reporting(
    args: Vec<String>,
    fs: &SafeFs,
    mounts: MountReader<'_>,
    host: &HostChecks<'_>,
) -> (Result<Action, ParseError>, Reports) {
    let mut reports = Reports::default();
    let parsed = parse_errors(args, fs, mounts, host, &mut reports);
    (parsed, reports)
}

/// [`parse_with_host`], with what `-h`, `-F ?` and `-v` ask for left in
/// `reports`.
fn parse_errors(
    args: Vec<String>,
    fs: &SafeFs,
    mounts: MountReader<'_>,
    host: &HostChecks<'_>,
    reports: &mut Reports,
) -> Result<Action, ParseError> {
    // What the C reports while it reads the options and reads on after
    // (`+J is not supported`), before whatever ends the parse: measured,
    // `-o -s +J` prints the `+J` line first.
    let mut early = Early::default();
    let parsed = parse_options(args, fs, mounts, host, &mut early, reports);
    let last = match parsed {
        Ok(action) if early.is_empty() => return Ok(action),
        Ok(_) => String::new(),
        Err(e) => e,
    };
    Err(ParseError { early, last })
}

/// A parse that ended in an error: the lines the C printed as it read on
/// (DIVERGENCES 149), then the error that ended the parse, if it was not
/// made in silence. Each is printed after `lsof: `; [`ParseError::each_line`]
/// formats them one at a time, so that a long argument list of letters that
/// are no options costs its own size and not a line of text per letter, as
/// the C, which prints each where it meets it, does not hold them at all.
/// Its `Display` is every line joined with `\nlsof: `.
#[derive(Debug)]
pub struct ParseError {
    early: Early,
    last: String,
}

impl ParseError {
    /// Hand `line` each line in order, without its `lsof: `. The error that
    /// ended the parse is one line here even when it holds several
    /// (`errors.join("\nlsof: ")`); one made in silence under `-w` or `-t` is
    /// none.
    pub fn each_line(&self, mut line: impl FnMut(&str)) {
        self.early.each_line(&mut line);
        if !self.last.is_empty() {
            line(&self.last);
        }
    }
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut first = true;
        let mut out = Ok(());
        self.each_line(|l| {
            if out.is_ok() {
                out = if first {
                    f.write_str(l)
                } else {
                    write!(f, "\nlsof: {l}")
                };
                first = false;
            }
        });
        out
    }
}

/// The errors the C reports and reads on after, kept no larger than the
/// arguments that made them and formatted only when printed. A letter that is
/// no option, the common case and the one an argument list can hold millions
/// of (`-WWWW…`), is the letter itself in `codes`; every other line is
/// [`Early::ESC`] and a code there, its text, if it has one, in `texts`,
/// each preceded by its length and a `:`. One `String` per line had cost
/// about 130 times the argument list's size (237 MB for 1.8 MB of `-W…`,
/// where the C peaks at 7 MB).
#[derive(Debug, Default)]
struct Early {
    codes: String,
    texts: String,
}

impl Early {
    /// Opens a code in `codes`; a NUL letter is `ESC ESC`.
    const ESC: char = '\0';

    fn is_empty(&self) -> bool {
        self.codes.is_empty()
    }

    /// `illegal option character: X`, `X` escaped (DIVERGENCES 122).
    fn illegal(&mut self, c: char) {
        if c == Self::ESC {
            self.codes.push(Self::ESC);
        }
        self.codes.push(c);
    }

    /// `colon is an illegal option character.`
    fn colon(&mut self) {
        self.codes.push(Self::ESC);
        self.codes.push(':');
    }

    /// `+J is not supported`, `+j` the same.
    fn plus_json(&mut self, c: char) {
        self.codes.push(Self::ESC);
        self.codes.push(if c == 'j' { 'j' } else { 'J' });
    }

    /// `can't get UID for NAME`, `name` as shown.
    fn no_uid(&mut self, name: &str) {
        self.codes.push(Self::ESC);
        self.codes.push('U');
        self.text(name);
    }

    /// Any other line, as given.
    fn line(&mut self, line: &str) {
        self.codes.push(Self::ESC);
        self.codes.push('T');
        self.text(line);
    }

    fn text(&mut self, text: &str) {
        self.texts.push_str(&text.len().to_string());
        self.texts.push(':');
        self.texts.push_str(text);
    }

    /// Hand `line` each line in order, formatted in one buffer reused.
    fn each_line(&self, line: &mut impl FnMut(&str)) {
        let mut buf = String::new();
        let mut texts = self.texts.as_str();
        let mut next_text = || {
            let (len, rest) = texts.split_once(':').unwrap_or(("0", ""));
            let len = len.parse::<usize>().unwrap_or(0).min(rest.len());
            let (text, rest) = rest.split_at_checked(len).unwrap_or((rest, ""));
            texts = rest;
            text
        };
        let mut codes = self.codes.chars();
        while let Some(c) = codes.next() {
            buf.clear();
            // The letter of an `illegal option character` line, or `None`
            // when `buf` holds another kind of line.
            let letter = match (c == Self::ESC).then(|| codes.next()) {
                None => Some(c),
                Some(None) => break,
                Some(Some(':')) => {
                    buf.push_str("colon is an illegal option character.");
                    None
                }
                Some(Some(j @ ('J' | 'j'))) => {
                    buf.push('+');
                    buf.push(j);
                    buf.push_str(" is not supported");
                    None
                }
                Some(Some('U')) => {
                    buf.push_str("can't get UID for ");
                    buf.push_str(next_text());
                    None
                }
                Some(Some('T')) => {
                    buf.push_str(next_text());
                    None
                }
                // `ESC ESC`: a NUL letter.
                Some(Some(other)) => Some(other),
            };
            if let Some(letter) = letter {
                buf.push_str(&quoting(
                    "illegal option character: ",
                    letter.encode_utf8(&mut [0; 4]),
                ));
            }
            line(&buf);
        }
    }

    /// Hand each line to `line`, and forget them.
    fn drain(&mut self, mut line: impl FnMut(&str)) {
        self.each_line(&mut line);
        self.codes.clear();
        self.texts.clear();
    }
}

/// [`parse_with`], with the errors the C reports and reads on after left in
/// `early`.
fn parse_options(
    mut args: Vec<String>,
    fs: &SafeFs,
    mounts: MountReader<'_>,
    host: &HostChecks<'_>,
    early: &mut Early,
    reports: &mut Reports,
) -> Result<Action, String> {
    let mut sel = Selection::default();
    // Whether errors were printed already, ahead of a line the parse printed
    // itself ([`tell_early`]).
    let mut told = false;
    // The C's `readmnt()` reads once, where it is first needed (`dmnt.c`:
    // `if (Lmi || Lmist) return (Lmi)`).
    let mut table: Option<MountTable> = None;
    let read_table = |sel: &Selection| read_mount_table(sel, fs, mounts);
    // `-F` given at all, and `-J`/`-j`: the C's `Ffield` and its `Fjson`
    // and `Fjsonl`, independent of each other, so `-F` and `-J` combine in
    // either order (`-J -Fpcfn` is `-Fpcfn -J`, measured).
    let mut fields_given = false;
    let mut json_doc = false;
    let mut json_lines = false;
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
                // open), so the `+` spelling is refused rather than read as
                // the `-` one.
                // `+J`/`+j`: the C says so and reads on (`main.c:567-584`).
                'J' | 'j' if plus => early.plus_json(c),
                // A `-` inside a word is no option letter to the C's
                // `GetOpt`: it says so and reads on through the word, so
                // `--help` is that error, then `-h`, then `-e lp` (`-e not
                // followed by a file system path: "lp"`), exit 1, and
                // `--version` the same with `-v` and `-e rsion` (measured).
                // lsof-rs had taken both as GNU-style long options and exited
                // 0 (DIVERGENCES 114).
                '-' => early.illegal('-'),
                // `+m` is the C's mount supplement (`[+m [m]]`, exit 0 on
                // Linux, measured), which lsof-rs does not write: refused
                // here, before `-m`'s arm below could read the rest of the
                // word as letters (`+mfoo` as `-f -o -o`).
                'n' | 'P' | 'r' | 'm' if plus => {
                    return Err(quoting("unsupported option: +", &c.to_string()))
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
                    tell_early(fs, early, &mut told);
                    let dir = enter_dir(&value, c == 'D', &sel, fs)?;
                    // The C reads its mount table here, at the first `+d`/`+D`
                    // whose directory checked out (`ck_file_arg()` from
                    // `enter_dir()`, `arg.c:915`), under the `-b`, `-O`,
                    // `-S`, `-w` and `-e`/`+e` given so far.
                    if table.is_none() {
                        table = Some(read_table(&sel));
                    }
                    sel.dir_args.push(dir);
                    if c == 'd' {
                        sel.dirs_one_level.push(value);
                    } else {
                        sel.dir_trees.push(value);
                    }
                    j = chars.len();
                    continue;
                }
                // `+c <n>`: cap the COMMAND column at n characters. The
                // value is attached or the next word, whatever it is; one
                // that is missing, empty or opens with anything but a digit
                // is the C's `+c not followed by width number`, which quotes
                // nothing (`main.c:316-326`; measured for `+c` last, `+c ''`,
                // `+c x`, `+cx` and `+c -p`). Then `atoi()`: the leading
                // digits are the width and the rest is ignored, so `+c 1x`
                // is `+c 1` (measured), the digits saturating where `atoi()`
                // wraps (DIVERGENCES 121).
                'c' if plus => {
                    let rest: String = chars[j + 1..].iter().collect();
                    let value = if !rest.is_empty() {
                        Some(rest)
                    } else {
                        i += 1;
                        args.get(i).cloned()
                    };
                    let digits = value.as_deref().map_or("", |v| {
                        &v[..v.bytes().take_while(u8::is_ascii_digit).count()]
                    });
                    if digits.is_empty() {
                        return Err("+c not followed by width number".to_string());
                    }
                    let n = digits_value(digits);
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
                                "-r {}: a repeat count (c) and marker format (m) are not supported",
                                shown(&word)
                            ));
                        }
                    }
                    let delay = take_digits(&chars, &mut j, &mut args, &mut i, prefix);
                    repeat = Some(delay.map_or(15, |d| digits_value(&d) as u64));
                    continue;
                }
                'J' => json_doc = true,
                'j' => json_lines = true,
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
                        Some(digits) => columns.offset_digits = offset_digits_value(&digits),
                        None => columns.offset = true,
                    }
                    continue;
                }
                'v' => reports.version = true,
                'V' => sel.verbose = true,
                'h' | '?' => reports.help = true,
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
                    if (host.selinux_enabled)() {
                        // `-Z [context]`. The value is attached or the next
                        // word, and a word that opens an option is not one —
                        // the same rule `-K` uses (`main.c`: `*GOv != '-' &&
                        // *GOv != '+'`).
                        let context = optional_value(&chars, j, &args, &mut i);
                        let list = sel.selinux.get_or_insert_with(Vec::new);
                        list.extend(context);
                    } else {
                        // Refused where it stands, and the parse reads on
                        // (`err = 1`). `GetOpt` hands `-Z` its value, attached
                        // or the next word whatever it opens with (`"Z:"`),
                        // `--` aside, and only the enabled branch gives a word
                        // back: `-Z -h` and `-Z -u nosuch` print this line
                        // alone, `-h -Z` prints it and no help (measured).
                        early.line("-Z limited to SELinux");
                        if j + 1 == chars.len() && args.get(i + 1).is_some_and(|w| w != "--") {
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
                    // With no word at all the C quotes a null pointer,
                    // `"(null)"` (undefined behaviour, a C-DEFECT): here
                    // `""`.
                    let rest: String = chars[j + 1..].iter().collect();
                    let value = if !rest.is_empty() {
                        rest
                    } else {
                        match args.get(i + 1) {
                            Some(next) if !next.starts_with(['-', '+']) => {
                                i += 1;
                                next.clone()
                            }
                            other => other.cloned().unwrap_or_default(),
                        }
                    };
                    tell_early(fs, early, &mut told);
                    enter_exempt(&mut sel, &value, plus, fs)?;
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
                                        return Err(quoting(
                                            "unknown cross-over option: ",
                                            &other.to_string(),
                                        ))
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
                                        return Err(quoting(
                                            "unknown file struct option: ",
                                            &other.to_string(),
                                        ))
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
                                tell_early(fs, early, &mut told);
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
                    // A value, even an empty one (`+T ''`), is letters: none
                    // selects nothing, whatever the prefix (DIVERGENCES 116).
                    let letters = optional_value(&chars, j, &args, &mut i);
                    sel.tcp_info_opt = Some(parse_tcp_info(letters.as_deref(), plus)?);
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
                        Some(v) => {
                            return Err(format!("-K not followed by i (but by {})", shown(&v)))
                        }
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
                            reports.field_help = true;
                            j = chars.len();
                            continue;
                        }
                        // Bare, or `0` alone: the C's default set.
                        None | Some("0") => true,
                        Some(list) => {
                            if let Some(bad) = list.chars().find(|f| !field_known(*f)) {
                                return Err(quoting("unknown field: ", &bad.to_string()));
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
                    fields_given = true;
                    j = chars.len();
                    continue;
                }
                'i' => {
                    // `-i [spec]`: the spec is attached or the next word, and
                    // a word that opens an option is not one (`main.c`). So
                    // `-i :80` is the spec `:80` — lsof-rs had read it as a
                    // bare `-i` and a file called `:80`. No spec is the bare
                    // form; an empty one (`-i ''`) is a spec, and incomplete.
                    let spec = optional_value(&chars, j, &args, &mut i);
                    parse_inet(&mut sel, spec.as_deref())?;
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
                    if c == 'u' {
                        enter_users(&mut sel, &value, host, early)?;
                    } else {
                        apply_value(&mut sel, c, &value)?;
                    }
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
                // Letters the C knows and lsof-rs does not implement, each
                // a value option to the C's `GetOpt` (`"D:"`, `"m:"`, and
                // `"k:"` on FreeBSD): the C says so, takes the rest of the
                // word or else the next word, whatever it is, as the value,
                // and reads on (`err = 1`). Measured on Linux: `-D -W -Y` and
                // `-m -W -Y` say their line and `illegal option character:
                // Y`, the `-W` taken as the value; `-Dfoo -W` and `-mfoo -W`
                // say both. `-D`'s words are the C's own on Linux, which keeps
                // no device cache; `-m`'s are `-m not supported` there, the
                // C's too, and on FreeBSD all three keep lsof-rs's
                // `unsupported option` (DIVERGENCES 148).
                // `--` is no value to `GetOpt` here either, as for `-Z`:
                // `-D -- -W` is `-D`'s line alone, `-W` a name (measured).
                'D' | 'm' if !plus => {
                    if c == 'm' && !cfg!(target_os = "freebsd") {
                        early.line("-m not supported");
                    } else {
                        early.line(&format!("unsupported option: -{c}"));
                    }
                    if j + 1 == chars.len() && args.get(i + 1).is_some_and(|w| w != "--") {
                        i += 1;
                    }
                    j = chars.len();
                    continue;
                }
                'k' if cfg!(target_os = "freebsd") => {
                    early.line(&format!("unsupported option: {prefix}k"));
                    if j + 1 == chars.len() && args.get(i + 1).is_some_and(|w| w != "--") {
                        i += 1;
                    }
                    j = chars.len();
                    continue;
                }
                // A letter that is no option: the C's `GetOpt` says so in
                // these words, without the prefix, and reads on, through
                // the rest of the word too (`err = 2`, `main.c:1924-1932`).
                // Every error it then finds is printed, and the run ends in
                // `usage()`, exit 1: measured, `-Wz` is two lines, `-Wp` the
                // `W` line and then `-p`'s missing value, `-o -s -W` the `W`
                // line and then `-o and -s are mutually exclusive`, `+W` the
                // same as `-W`, and a colon is its own sentence. lsof-rs had
                // said `unsupported option: -W` and stopped (DIVERGENCES
                // 149). The letter is escaped where the C prints it raw
                // (DIVERGENCES 122), and is a character, where the C prints
                // each byte of one on a line of its own (`-é` is two lines).
                ':' => early.colon(),
                other => early.illegal(other),
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
    // What the C finds wrong once every option is read, it reports all of,
    // in its order (`main.c:1060-1160`), and only then acts on `-h`, `-v` or
    // `-F ?`, or ends the run: `lsof -o -s -x -e /nosuch` prints three errors,
    // `-e /nosuch -h` and `-hx` exit 1 without the help (measured;
    // DIVERGENCES 83, 115). Main prints the first `lsof: `.
    let mut errors: Vec<String> = Vec::new();
    // A state both included and excluded, from any two `-s` options, each
    // named as the C's table spells it, in table order (measured: `LISTEN`
    // and `ESTABLISHED` both, `ESTABLISHED` first, the kernel's 1 before 10).
    for both in tcp_state_table()
        .iter()
        .filter(|st| states.include.contains(st) && states.exclude.contains(st))
    {
        errors.push(format!(
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
        errors.push("-o and -s are mutually exclusive".to_string());
    }
    // `-J` and `-j` set the C's `Ffield` too, so they are refused with `-t`
    // in `-F`'s words as well as their own (`main.c:1095`, measured).
    let json = json_doc || json_lines;
    if (fields_given || json) && sel.terse {
        errors.push("-F and -t are mutually exclusive".to_string());
    }
    //
    // `-x` only means anything to a `+d`/`+D` expansion, and the C refuses it
    // alone rather than accepting a switch that would do nothing
    // (`main.c:1122`). Checked here so the two may arrive in either order.
    if (sel.cross_filesystems || sel.cross_symlinks)
        && sel.dirs_one_level.is_empty()
        && sel.dir_trees.is_empty()
    {
        errors.push("-x must accompany +d or +D".to_string());
    }
    if json_doc && json_lines {
        errors.push("-J and -j are mutually exclusive".to_string());
    }
    if json && sel.terse {
        errors.push("-J/-j and -t are mutually exclusive".to_string());
    }
    //
    // Each `-e`/`+e` must name a mounted file system, which the C checks
    // last, whatever came before (`main.c:1137-1160`): it reads the table
    // here if no `+d` did, `-h` or `-v` or not, and checks only a table that
    // holds something (`if ((mp = readmnt(ctx)))`) — under `-b`, which
    // records an `-e` mount alone, `-b -e /nosuch` exits 0. A path is
    // compared exactly with each directory as `Readlink()` spelt it, and
    // every one that names none is reported, the last given first (the C
    // prepends to its list): measured, `-e /nosuch1 -e /nosuch2` says
    // `/nosuch2` first. The path is the one stored, `-e`'s through
    // `Readlink()` and the word `-e` for `+e` too (`"-e /nonexist/x"` for a
    // link to it); escaped, where the C prints it raw (DIVERGENCES 122).
    if !sel.exempt_fs.is_empty() {
        if table.is_none() {
            // The C prints each error where it finds it, so those found so
            // far come before what the table says as it is read: measured,
            // `-e /nosuch -x f` prints `-x must accompany +d or +D`, then a
            // mount's `can't stat()` warning, then the `-e` error.
            tell_early(fs, early, &mut told);
            for e in errors.drain(..) {
                fs.tell(&format!("lsof: {e}"));
                told = true;
            }
        }
        let table = table.get_or_insert_with(|| read_table(&sel));
        if !table.entries.is_empty() {
            for e in sel.exempt_fs.iter().rev() {
                if !table.entries.iter().any(|m| m.dir == e.path) {
                    errors.push(format!(
                        "\"-e {}\" is not a mounted file system.",
                        shown_bytes(e.path.as_encoded_bytes())
                    ));
                }
            }
        }
    }
    // An error the C reported and read on after (`err = 1`: `+J`, a `-`
    // in a word or any letter that is no option, `-D`, `-m`, `-Z` without
    // SELinux, an unknown `-u` login) ends the run
    // here too, in `usage()`, before the checks below are made: `+J -a` and
    // `-u nosuch -X -i` print their first line alone (measured). Main prints
    // what `early` holds.
    if told || !errors.is_empty() || !early.is_empty() {
        return Err(errors.join("\nlsof: "));
    }
    if reports.any() {
        return Ok(Action::Report(*reports));
    }
    // `-X` stops the inet tables being read, so `-i` has nothing left to
    // select on. The C refuses the pair outright rather than silently
    // returning nothing — measured: `lsof -X -i` exits 1 with this text.
    // Checked after the loop because the two may arrive in either order and
    // in either clustering (`-Xi`, `-i -X`, `-aXi`).
    if sel.skip_inet_tables && sel.inet.enabled {
        return Err("-i is useless when -X is specified.".to_string());
    }
    // `-a` with nothing to AND is a usage error, and the run never starts:
    // `main.c` refuses `-a` when its selection flags are all clear
    // (DIVERGENCES 50). Exclusions set none, so `-a -p ^1` or `-a -K i` is
    // refused too, where lsof-rs had listed the whole host.
    if sel.and_mode && sel.specified().is_empty() {
        return Err("no select options to AND via -a".to_string());
    }
    let format = if json {
        json_format(&fields, json_lines, flags_hex, columns.file_flags, &mut sel)
    } else if fields_given {
        fields.format()
    } else {
        Format::Table
    };
    Ok(Action::Run {
        selection: sel,
        format,
        repeat,
        columns,
        mounts: table,
    })
}

/// One `-e`/`+e`, entered as the C's `enter_efsys()` enters it (`arg.c:576-629`)
/// where the option stands. The value must be a path from the root, for `+e`
/// too, or it is `-e not followed by a file system path: "V"` (escaped, where
/// the C prints it raw, DIVERGENCES 122); `-e`'s is spelt by `Readlink()`,
/// through `fs` under the `-b`, `-O`, `-S` and `-w` given so far, so `-b -e
/// /dev/shm` says `avoiding readlink(/dev/shm)` there and `-e /dev/shm -b`
/// does not, and a value `Readlink()` gives up on is its message; `+e`'s is
/// kept as typed. Either message is muted by a `-w` or `-t` given before the
/// option, the C's `Fwarn` as it stands then, and still ends the run (all
/// measured). Then the trailing slashes go (`/` stays `/`), and a path entered
/// already is not entered again: the first keeps its sign (`+e X -e X` is
/// `+e`'s). On Windows the value is kept as typed, as `+d`'s is.
fn enter_exempt(sel: &mut Selection, value: &str, plus: bool, fs: &SafeFs) -> Result<(), String> {
    let at = AtOption::new(sel, fs);
    if !value.starts_with('/') {
        return Err(at.said(format!(
            "-e not followed by a file system path: \"{}\"",
            shown(value)
        )));
    }
    let path = if plus {
        OsString::from(value)
    } else {
        at.readlink(value)?
    };
    let path = without_trailing_slashes(path);
    if !sel.exempt_fs.iter().any(|e| e.path == path) {
        sel.exempt_fs.push(ExemptFs { path, plus });
    }
    Ok(())
}

/// `path` less the slashes that end it, keeping one: `enter_efsys()`'s
/// "Remove terminating `/' characters from paths longer than one".
fn without_trailing_slashes(path: OsString) -> OsString {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        let mut bytes = path.into_vec();
        while bytes.len() > 1 && bytes.last() == Some(&b'/') {
            bytes.pop();
        }
        OsString::from_vec(bytes)
    }
    #[cfg(not(unix))]
    match path.into_string() {
        Ok(mut s) => {
            while s.len() > 1 && s.ends_with('/') {
                s.pop();
            }
            s.into()
        }
        Err(p) => p,
    }
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
    let at = AtOption::new(sel, fs);
    // The C's own words, for `+D` too.
    if value.is_empty() || value.starts_with('+') || value.starts_with('-') {
        return Err(at.said("+d not followed by a directory path".to_string()));
    }
    let dir = at.readlink(value)?;
    let shown = || at.esc.bytes(dir.as_encoded_bytes()).into_owned();
    match at.fs.stat(std::path::Path::new(&dir)) {
        Err(e) => Err(at.said(format!(
            "WARNING: can't stat({}): {}",
            shown(),
            errno_text(&e)
        ))),
        Ok(st) if !st.is_dir() => Err(at.said(format!("WARNING: not a directory: {}", shown()))),
        // The C keeps this one `stat` for the walk (`arg.c:905,915`), so the
        // walk does not ask again (DIVERGENCES 111).
        Ok(st) => Ok(DirArg {
            recursive,
            dir,
            cross_filesystems: sel.cross_filesystems,
            cross_symlinks: sel.cross_symlinks,
            warn: at.warn,
            blocking: sel.blocking,
            stat: st,
        }),
    }
}

/// What an option that names a path (`+d`/`+D`, `-e`) is read under where it
/// stands, as the C reads it there: its `Fwarn` as it is then, which makes
/// an error it would print said in silence (the error comes back empty, and
/// still ends the run), and the bounded layer under the `-b`, `-O`, `-S` and
/// `-w` given so far.
struct AtOption<'a> {
    warn: bool,
    fs: SafeFs<'a>,
    esc: Escaper,
}

impl<'a> AtOption<'a> {
    fn new(sel: &Selection, fs: &SafeFs<'a>) -> Self {
        let warn = !sel.omit_unreadable;
        AtOption {
            warn,
            fs: fs.with(sel.blocking, warn),
            esc: Escaper::for_host(),
        }
    }

    /// `message`, unless the C would say it in silence.
    fn said(&self, message: String) -> String {
        if self.warn {
            message
        } else {
            String::new()
        }
    }

    /// `value` as `Readlink()` spells it, or the C's message for why it
    /// gave up, naming `value` escaped.
    fn readlink(&self, value: &str) -> Result<OsString, String> {
        resolve_dir(value, &self.fs).map_err(|e| self.said(e.message(&self.esc.text(value))))
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
            // The item escaped, where the C prints it raw (`arg.c`,
            // `enter_fd_lst()`: `%s`), a C-DEFECT not reproduced
            // (DIVERGENCES 122).
            let item = match range {
                Some((lo, hi)) => format!("{lo}-{hi}"),
                None => shown(body).into_owned(),
            };
            return Err(format!(
                "{} in an {} -d list: {}{item}",
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
    if dash == 0 {
        return Err(quoting("illegal FD range for -d: ", item));
    }
    let number = |digits: &str| {
        if digits.bytes().all(|b| b.is_ascii_digit()) {
            fd_number(digits, item)
        } else {
            Err(quoting("non-digit in -d FD range: ", item))
        }
    };
    let lo = number(&item[..dash])?;
    let hi = number(&item[dash + 1..])?;
    if lo >= hi {
        return Err(quoting("-d FD range's low >= its high: ", item));
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
        .ok_or_else(|| quoting("-d FD number exceeds INT_MAX: ", item))
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
            return Err(quoting(&format!("illegal {what}: "), value));
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

/// The errors the parse has found and read on after, printed now through
/// `fs`'s sink, ahead of a line the parse is about to print itself — the
/// `-S` warning, what a `+d`/`+D` or an `-e` says as it is examined, the
/// mount table's lines — since the C prints each where it meets it:
/// measured, `-Zx -S 0` says `-Z limited to SELinux` before `-S time (0)
/// changed to 2`, and `-S 0 -Z` after. `told` records that the run is to end.
fn tell_early(fs: &SafeFs, early: &mut Early, told: &mut bool) {
    early.drain(|e| {
        fs.tell(&format!("lsof: {e}"));
        *told = true;
    });
}

/// `-u`'s list, entered as the C's `enter_uid()` enters it: item by item,
/// each login looked up where it is read ([`HostChecks::lookup_user`]).
///
/// `-u ^name` is a negation, not a selection: it excludes absolutely and
/// takes no part in the OR/AND rule (Lsof.8). The list is `-p`'s, so an
/// empty item is UID 0: `-u ,` selects root and `-u ^` excludes it
/// (DIVERGENCES 69). An item longer than a login name may be, `LOGINML`
/// bytes after its `^`, is refused whatever it holds, digits included.
///
/// A name the host does not know is the C's `can't get UID for X`, an error
/// the parse reports and reads on after (`err = 1`), so `-h -u nosuch`
/// exits 1 without the help (DIVERGENCES 114). A UID entered once on each
/// side ends the parse at that item, as `lsof_select_uid()` makes the C's
/// `Error()` exit there: `UID 0 has been included and excluded.` Each UID is
/// entered once, its first spelling kept. A platform that selects by name
/// ([`UserLookup::ByName`]) keeps the item as typed.
fn enter_users(
    sel: &mut Selection,
    value: &str,
    host: &HostChecks<'_>,
    early: &mut Early,
) -> Result<(), String> {
    let mut rest = value;
    while !rest.is_empty() {
        let (item, tail) = rest.split_once(',').unwrap_or((rest, ""));
        let (excl, name) = match item.strip_prefix('^') {
            Some(name) => (true, name),
            None => (false, item),
        };
        if name.len() > LOGINML {
            // The C echoes the item with `safestrprtn()`, which has no
            // multibyte path: `é` is `\xc3\xa9` even under C.UTF-8
            // (measured), where `shown()` keeps it. Its cut at the item's
            // length is not reproduced (DIVERGENCES 133).
            let mut echo = String::new();
            for c in shown(item).chars() {
                if c.is_ascii() {
                    echo.push(c);
                } else {
                    for b in c.to_string().bytes() {
                        echo.push_str(&format!("\\x{b:02x}"));
                    }
                }
            }
            return Err(format!("-u login name > {LOGINML} characters: {echo}"));
        }
        let name = if name.is_empty() { "0" } else { name };
        match (host.lookup_user)(name) {
            UserLookup::Uid(uid) => {
                let other_side = if excl {
                    sel.uids.iter().any(|s| s.uid == uid)
                } else {
                    sel.uid_excludes.contains(&uid)
                };
                if other_side {
                    return Err(format!("UID {uid} has been included and excluded."));
                }
                if excl {
                    if !sel.uid_excludes.contains(&uid) {
                        sel.uid_excludes.push(uid);
                    }
                } else if !sel.uids.iter().any(|s| s.uid == uid) {
                    let login =
                        (!name.bytes().all(|b| b.is_ascii_digit())).then(|| name.to_string());
                    sel.uids.push(UidSel { uid, login });
                }
            }
            UserLookup::Unknown => early.no_uid(&shown(name)),
            UserLookup::ByName => {
                if excl {
                    sel.user_excludes.push(name.to_string());
                } else {
                    sel.users.push(name.to_string());
                }
            }
        }
        rest = tail;
    }
    Ok(())
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
                    "-c {}: regular expressions (-c /RE/) are not implemented",
                    shown(value)
                ));
            }
            let (excl, name) = match value.strip_prefix('^') {
                Some("") => return Err("option -c^ requires a name".to_string()),
                Some(name) => (true, name),
                None => (false, value),
            };
            // A name longer than the kernel keeps can never match, and the C
            // says so rather than accepting it (`lsof_select_process()`),
            // quoting the name with `safestrprt(…, 2)`: a space is `\x20`
            // there, as in COMMAND (`lib/lsof.c:178-182`, measured).
            if let Some(max) = MAX_COMMAND_WIDTH {
                if name.len() > max {
                    return Err(format!(
                        "\"-c {}\" length ({}) > what system provides ({max})",
                        Escaper::for_host().text_spaced(name),
                        name.len()
                    ));
                }
            }
            let (this, other) = if excl {
                (&mut sel.command_excludes, &sel.commands)
            } else {
                (&mut sel.commands, &sel.command_excludes)
            };
            // Found here, at the option, as the C finds it: its
            // `lsof_select_process()` refuses the second name as it is
            // entered (`lib/lsof.c:155-165`), so `main.c:1042`'s check once
            // every option is read never finds one. The C then reads on, as
            // after any error in its loop; lsof-rs stops (DIVERGENCES 83).
            if other.iter().any(|o| o == name) {
                let name = shown(name);
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
/// FreeBSD's dialect sets it to `MAXCOMLEN` (`dlsof.h`), 19: `ki_comm` is
/// `COMMLEN + 1` bytes.
#[cfg(target_os = "freebsd")]
const MAX_COMMAND_WIDTH: Option<usize> = Some(19);
#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
const MAX_COMMAND_WIDTH: Option<usize> = None;

/// Whether this platform can report a socket's receive window, which is what
/// decides whether `-T w` is a valid letter.
///
/// The C compiles the letter in per dialect (`HASTCPTPIW`) and its Linux
/// dialect does not define it, so `lsof -T w` there is a hard error rather
/// than a request that quietly returns nothing. Windows reads the window from
/// per-connection EStats, so it is real there.
/// FreeBSD's dialect does not define `HASTCPTPIW` either (`machine.h`).
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
const HAS_TCP_WINDOW: bool = false;
#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
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
///   An **empty** next word is the exception: the C takes it as the value
///   (it does not open with `-` or `+`), finds no digits and nothing after
///   them to give back, and so consumes it — `-o ''` is `-o`, and `''` is no
///   path (DIVERGENCES 116).
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
    if next.is_empty() {
        *i += 1;
        return None;
    }
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
/// `-T q` is queues *instead of* the state, not as well as it. With no value
/// the prefix decides — `-T` selects nothing, `+T` restores the state-only
/// default. An empty value is a value with no letters (`main.c` tests `GOv`
/// for NULL, not for empty): `+T ''` selects nothing, like `-T`, and a unix
/// socket loses its `(CONNECTED)` (DIVERGENCES 116, measured).
fn parse_tcp_info(letters: Option<&str>, plus: bool) -> Result<TcpInfoFlags, String> {
    let Some(letters) = letters else {
        return Ok(if plus {
            TcpInfoFlags::DEFAULT
        } else {
            TcpInfoFlags::default()
        });
    };
    let mut flags = TcpInfoFlags::default();
    for ch in letters.chars() {
        match ch {
            'f' => flags.options = true,
            'q' => flags.queue = true,
            's' => flags.state = true,
            'w' if HAS_TCP_WINDOW => flags.window = true,
            other => {
                return Err(quoting(
                    "unsupported TCP/TPI info selection: ",
                    &other.to_string(),
                ));
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
        _ => return Err(format!("unknown -s protocol: \"{}\"", shown(value))),
    };
    let names = &value[4..];
    if names.is_empty() {
        return Err(quoting(&format!("no {proto} state names in: "), value));
    }
    if proto == "UDP" {
        return Err(quoting("no UDP state names available: ", value));
    }
    for term in names.split(',') {
        let (exclude, name) = match term.strip_prefix('^') {
            Some(rest) => (true, rest),
            None => (false, term),
        };
        if name.is_empty() {
            return Err(quoting("NULL TCP state name in: ", value));
        }
        let Some(state) = tcp_state_table()
            .iter()
            .copied()
            .find(|st| st.as_str().eq_ignore_ascii_case(name))
        else {
            return Err(quoting("unknown TCP state name: ", name));
        };
        let list = if exclude {
            &mut filter.exclude
        } else {
            &mut filter.include
        };
        if list.contains(&state) {
            let which = if exclude { "exclusion" } else { "inclusion" };
            return Err(quoting(&format!("duplicate TCP {which}: "), name));
        }
        list.push(state);
    }
    Ok(())
}

/// The most address specifications the C takes, across every `-i`:
/// `MAXNWAD` (`lib/common.h:359`), counted in its units ([`parse_inet`]).
const MAXNWAD: usize = 100;

/// Parse an `-i` spec, `[46][proto][@host][:ports]`, as the C's
/// `enter_network_address()` parses it (`arg.c:1189-1611`), in its order and
/// with its words. No spec (`-i` alone, or before a word that opens an
/// option), and one that is only `4` or `6`, is the bare form — every
/// Internet file; anything else is an address specification of its own (see
/// [`lsof_core::InetFilter`]), `-i ''` included.
///
/// * A leading `4` or `6` is the spec's version; with none, a bare form given
///   before lends it its own (`else if (Fnet) ft = FnetTy`).
/// * The protocol is the whole word up to `@` or `:`, `tcp`, `udp` or
///   `udplite` in any case: `tcpx` is `unknown protocol name (tcpx)`. `icmp`
///   and `raw` are the Windows port's own (ETW families) and nothing on
///   Linux, where the C refuses them (measured; DIVERGENCES 108).
/// * After `@`, an IPv4 address is the C's `isIPv4addr()` ([`ipv4_addr`]:
///   decimal, leading zeros allowed); `[` takes the text up to the LAST `]`
///   as an IPv6 address, never all zero, a v4-mapped one being that IPv4
///   address; an address of the version the spec excludes is prohibited.
///   Anything else is a host name, which the C looks up and lsof-rs never
///   does: refused, not guessed (DIVERGENCES 38). So are the numeric forms
///   glibc reads without DNS (`@127.1`).
/// * The ports are `:` and then entries split by `,`: digits, or a range of
///   them, each entry checked and entered from left to right, so the first
///   error is the leftmost's. A range's end below its start (`:1-`, `:5-1`)
///   and anything but digits after the first digit are `unacceptable port
///   specification`; an empty entry, `invalid service name`. A port past
///   65535 is no error: it matches nothing (the C's `int`). A service name
///   is refused as a host name is: `-i:http` had listed every Internet file,
///   where the C lists port 80.
/// * A spec with no protocol, no address (or `0.0.0.0`) and no port is
///   `incomplete`; and past [`MAXNWAD`] entries, counting each port entry as
///   one and a spec with none as one, as `enter_nwad()` enters them, the
///   spec that crosses it is refused.
///
/// Each message is the C's, quoting the spec as the C does, escaped
/// ([`quoting`]), and the token in parentheses too, which the C prints raw
/// (DIVERGENCES 112, 122).
fn parse_inet(sel: &mut Selection, spec: Option<&str>) -> Result<(), String> {
    // `main.c:586-593`: no value, or one that opens an option, is `Fnet = 1;
    // FnetTy = 0`.
    let Some(spec) = spec else {
        sel.inet.add_all(None);
        return Ok(());
    };
    let unacceptable_address = || quoting("unacceptable Internet address in: -i ", spec);
    let unacceptable_port = || quoting("unacceptable port specification in: -i ", spec);
    let mut s = spec;
    let mut family = None;
    if let Some(rest) = s.strip_prefix(['4', '6']) {
        family = Some(if s.starts_with('4') { 4 } else { 6 });
        if rest.is_empty() {
            sel.inet.add_all(family);
            return Ok(());
        }
        s = rest;
    } else if sel.inet.all {
        family = sel.inet.all_family;
    }

    let mut proto = None;
    if !s.is_empty() && !s.starts_with(['@', ':']) {
        let end = s.find(['@', ':']).unwrap_or(s.len());
        let token = &s[..end];
        proto = Some(inet_protocol(token).ok_or_else(|| {
            format!(
                "unknown protocol name ({}) in: -i {}",
                shown(token),
                shown(spec)
            )
        })?);
        s = &s[end..];
    }

    let mut host = None;
    if let Some(after) = s.strip_prefix('@') {
        if after.is_empty() || after.starts_with(':') {
            return Err(unacceptable_address());
        }
        if let Some((octets, rest)) = ipv4_addr(after) {
            if family == Some(6) {
                return Err(quoting("IPv4 addresses are prohibited: -i ", spec));
            }
            host = Some(IpAddr::V4(octets));
            s = rest;
        } else if let Some(inner) = after.strip_prefix('[') {
            if family == Some(4) {
                return Err(quoting("IPv6 addresses are prohibited: -i ", spec));
            }
            // `strrchr()`: the last `]`, so `[::1]]` is no address.
            let close = inner.rfind(']').ok_or_else(unacceptable_address)?;
            // Rust's reading of an IPv6 address is glibc's `inet_pton()`'s:
            // the two agree on 20,045 strings (measured).
            let ip: Ipv6Addr = inner[..close].parse().map_err(|_| unacceptable_address())?;
            if ip.is_unspecified() {
                return Err(unacceptable_address());
            }
            host = Some(match ip.to_ipv4_mapped() {
                Some(_) if family == Some(6) => {
                    return Err(quoting("IPv4 addresses are prohibited: -i ", spec))
                }
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(ip),
            });
            s = &inner[close + 1..];
        } else {
            return Err(quoting("host names are not resolved: -i ", spec) + " (give the address)");
        }
    }
    // An all-zero address is no constraint at all to the C (`is_nw_addr()`
    // skips the comparison when every byte is 0), and no address to its
    // incomplete-specification check.
    let host = host.filter(|ip| !ip.is_unspecified());

    // What every earlier `-i` entered, in `enter_nwad()`'s units.
    let mut entries: usize = sel.inet.specs.iter().map(|s| s.ports.len().max(1)).sum();
    let mut enter = |ports: &mut Vec<(u32, u32)>, range: Option<(u32, u32)>| {
        if range.is_none() && proto.is_none() && host.is_none() {
            return Err(quoting(
                "incomplete Internet address specification: -i ",
                spec,
            ));
        }
        if entries >= MAXNWAD {
            return Err(quoting(
                &format!("network address limit ({MAXNWAD}) exceeded: -i "),
                spec,
            ));
        }
        entries += 1;
        ports.extend(range);
        Ok(())
    };
    let mut ports = Vec::new();
    if s.is_empty() {
        enter(&mut ports, None)?;
    } else {
        let list = match s.strip_prefix(':') {
            Some(list) if !list.is_empty() => list.as_bytes(),
            _ => return Err(unacceptable_port()),
        };
        // `arg.c:1461-1580`, one entry a pass. A port's digits saturate
        // where the C's `int` wraps (DIVERGENCES 121).
        let mut at = 0;
        while at < list.len() {
            let (mut start, mut end, mut range) = (0u32, 0u32, false);
            // The entry's start, and after a `-` the range's end.
            while let Some(&c) = list.get(at) {
                if !c.is_ascii_digit() {
                    // A service name runs to the next `,` and may hold a `-`:
                    // none at all is the C's `invalid service name`.
                    if c == b',' {
                        return Err(quoting("invalid service name: -i ", spec));
                    }
                    return Err(quoting("service names are not resolved: -i ", spec)
                        + " (give the port number)");
                }
                while let Some(&c) = list.get(at) {
                    match c {
                        b',' => break,
                        b'-' if range => return Err(unacceptable_port()),
                        b'-' => {
                            range = true;
                            break;
                        }
                        b'0'..=b'9' => {
                            let n = if range { &mut end } else { &mut start };
                            *n = n.saturating_mul(10).saturating_add(u32::from(c - b'0'));
                            at += 1;
                        }
                        _ => return Err(unacceptable_port()),
                    }
                }
                match list.get(at) {
                    None | Some(b',') => break,
                    // The `-`: the range's end follows, if anything does.
                    Some(_) => at += 1,
                }
            }
            if !range {
                end = start;
            }
            if end < start {
                return Err(unacceptable_port());
            }
            enter(&mut ports, Some((start, end)))?;
            // Past the `,` that ended the entry: a trailing one ends the list.
            at += 1;
        }
    }

    sel.inet.enabled = true;
    sel.inet.specs.push(lsof_core::InetSpec {
        text: spec.to_string(),
        proto,
        family,
        ports,
        host,
    });
    Ok(())
}

/// An `-i` protocol, as the C compares it: the whole word, in any case
/// (`strcasecmp()`, `arg.c:1295-1303`).
fn inet_protocol(token: &str) -> Option<Protocol> {
    let is = |name: &str| token.eq_ignore_ascii_case(name);
    Some(if is("tcp") {
        Protocol::Tcp
    } else if is("udp") {
        Protocol::Udp
    } else if is("udplite") {
        Protocol::UdpLite
    // ETW-only families (no IP Helper table): the filter implies the AFD
    // capture — see InetFilter::needs_etw. `-iICMP` covers v4 + v6 ICMP;
    // narrow with the `[46]` prefix (`-i6ICMP`), like TCP/UDP.
    } else if cfg!(windows) && is("icmp") {
        Protocol::Other("ICMP")
    } else if cfg!(windows) && is("raw") {
        Protocol::Other("RAW")
    } else {
        return None;
    })
}

/// The C's `isIPv4addr()` (`arg.c:2075-2141`): from a leading digit to `:`
/// or the end, exactly four decimal octets of at most 255 between three
/// dots, a leading zero no octal (`0177.0.0.1` is 177.0.0.1, measured). The
/// address, and what follows it; `None` for anything else, which the C then
/// takes for a host name. The octets saturate where the C's `int` wraps.
fn ipv4_addr(s: &str) -> Option<(Ipv4Addr, &str)> {
    let end = s.find(':').unwrap_or(s.len());
    let (text, rest) = s.split_at(end);
    if !text.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    let mut octets = [0u8; 4];
    let mut parts = text.split('.');
    for octet in &mut octets {
        let part = parts.next()?;
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let value = part.bytes().fold(0u32, |v, b| {
            v.saturating_mul(10).saturating_add(u32::from(b - b'0'))
        });
        *octet = u8::try_from(value).ok()?;
    }
    parts
        .next()
        .is_none()
        .then_some((Ipv4Addr::from(octets), rest))
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
        let fs = |argv: &[&str]| {
            columns(argv).map(|(_, s)| {
                s.exempt_fs
                    .into_iter()
                    .map(|e| e.path.into_string().unwrap())
                    .collect::<Vec<_>>()
            })
        };
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

    /// An empty next word is an optional value, as the C's `GetOpt` offers it
    /// (it does not open with `-` or `+`), and the options whose value is
    /// digits or letters take it as one with none (DIVERGENCES 116, every one
    /// measured): it is consumed, never a path, and `+T ''` selects no TCP
    /// information at all, where `+T` alone restores the state.
    #[test]
    fn an_empty_word_is_an_empty_optional_value() {
        let tcp = |argv: &[&str]| columns(argv).unwrap().1.tcp_info();
        assert_eq!(tcp(&["+T", ""]), TcpInfoFlags::default(), "+T ''");
        assert_eq!(tcp(&["-T", ""]), TcpInfoFlags::default(), "-T ''");
        assert_eq!(tcp(&["-T", "+T"]), TcpInfoFlags::DEFAULT, "+T alone");
        assert_eq!(tcp(&["+T"]), TcpInfoFlags::DEFAULT);
        for argv in [
            &["-o", ""][..],
            &["-S", ""],
            &["-L", ""],
            &["+L", ""],
            &["-r", ""],
            &["-o", "", "-S", ""],
        ] {
            let (c, sel) = columns(argv).unwrap();
            assert!(sel.paths.is_empty(), "{argv:?}: '' is no path");
            if argv[0] == "-o" {
                assert!(c.offset && c.offset_digits == 8, "{argv:?}");
            }
        }
        let (_, sel) = columns(&["-S", ""]).unwrap();
        assert_eq!(sel.blocking.limit, 15, "no digits is the default");
        let (c, sel) = columns(&["+L", ""]).unwrap();
        assert!(c.nlink && sel.max_links.is_none(), "+L '' is +L");
        assert_eq!(repeat(&["-r", ""]), Some(15));
        // Only an empty word: one with no digits is still given back.
        let (c, sel) = columns(&["-o", "x"]).unwrap();
        assert!(c.offset && sel.paths == ["x"]);
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
        // The C sums the digits in an int and wraps, and so does this
        // (DIVERGENCES 117): past INT_MAX - 2 every offset prints in hex.
        let (c, _) = columns(&["-o", "99999999999999999999999999"]).unwrap();
        assert_eq!(c.offset_digits, 0xE3FF_FFFF_u32 as i32);
        for (typed, int) in [
            ("2147483645", 2147483645),
            ("2147483646", 2147483646),
            ("2147483648", i32::MIN),
            ("4294967295", -1),
            ("4294967296", 0),
            ("4294967297", 1),
            ("9999999999", 1410065407),
        ] {
            let (c, _) = columns(&["-o", typed]).unwrap();
            assert_eq!(c.offset_digits, int, "-o {typed}");
        }
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
            Ok(Action::Report(Reports::HELP))
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
        // `safestrprtn()` has no multibyte path: a printable `é` is its bytes
        // in hex, as the C prints it under C.UTF-8 (measured), and a C1
        // control is as `shown()` has it.
        let accented = format!("{}é\u{9b}b", "a".repeat(30));
        assert_eq!(
            sel(&["-u", &accented]).unwrap_err(),
            format!(
                "-u login name > 32 characters: {}\\xc3\\xa9\\xc2\\x9bb",
                "a".repeat(30)
            )
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
            Ok(Action::Report(Reports::HELP))
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
        // Found at the option, where the C finds it, not once every option
        // is read: the first line is the C's either way round, and a name
        // excluded twice is one conflict (measured). Its later errors are
        // lost, as after every error found in the loop: `-c^x -cx -x` says
        // nothing of `-x`, where the C adds `-x must accompany +d or +D`
        // (DIVERGENCES 83).
        for (argv, first) in [
            (&["-c^x", "-cx", "-x", "q"][..], "-c^x and -cx conflict."),
            (
                &["-x", "q", "-c^x", "-cx"][..],
                "unknown cross-over option: q",
            ),
            (&["-c^x", "-c^x", "-cx"][..], "-c^x and -cx conflict."),
            (&["-c^x", "-cx", "-x"][..], "-c^x and -cx conflict."),
            (&["-c^x", "-cx", "-o", "-s"][..], "-c^x and -cx conflict."),
        ] {
            assert_eq!(err(argv).as_deref(), Some(first), "{argv:?}");
        }
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
        // No spec is the bare form; an empty one is a spec, and incomplete.
        assert!(run(&["-i"]).0.inet.all);
        assert_eq!(
            parse(vec!["-i".into(), String::new()]).unwrap_err(),
            "incomplete Internet address specification: -i "
        );
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
    /// matched wrongly: `-i:http` had listed every Internet file. A host name
    /// is any address that is not the C's own IPv4 or bracketed IPv6 form,
    /// numeric shorthand glibc reads without DNS included (DIVERGENCES 38).
    #[test]
    fn names_the_c_would_resolve_are_refused() {
        let err = |a: &str| parse(vec![a.to_string()]).err().unwrap_or_default();
        for spec in [
            ":http", "TCP:http", ":1-http", ":-1", ":1--2", ":x-y", ":80,http",
        ] {
            assert_eq!(
                err(&format!("-i{spec}")),
                format!("service names are not resolved: -i {spec} (give the port number)")
            );
        }
        for spec in [
            "@localhost",
            "@127.1",
            "@1.2.3",
            "@1.2.3.4x",
            "@1.2.3.256",
            "@0x7f.0.0.1",
        ] {
            assert_eq!(
                err(&format!("-i{spec}")),
                format!("host names are not resolved: -i {spec} (give the address)")
            );
        }
        // Accepted now, as the C accepts it: a port is the C's `int`.
        assert!(err("-i:70000").is_empty());
        assert_eq!(err("-i:9-1"), "unacceptable port specification in: -i :9-1");
        assert_eq!(err("-iSCTP"), "unknown protocol name (SCTP) in: -i SCTP");
        assert_eq!(err("-i@[::1"), "unacceptable Internet address in: -i @[::1");
    }

    /// Every `-i` refusal in the C's words, each measured against the C 4.99.6
    /// under C.UTF-8, the argument escaped as its `safestrprt()` escapes it,
    /// and the protocol in parentheses too, which the C prints raw
    /// (DIVERGENCES 112, 122).
    #[test]
    fn dash_i_errors_are_the_cs_words_and_escape_the_argument() {
        let err = |argv: &[&str]| {
            parse(argv.iter().map(|s| s.to_string()).collect())
                .err()
                .unwrap_or_else(|| panic!("{argv:?} must be refused"))
        };
        let address = "unacceptable Internet address in: -i ";
        let port = "unacceptable port specification in: -i ";
        for (spec, want) in [
            ("@[1::\x1b[2J", format!("{address}@[1::^[[2J")),
            ("@", format!("{address}@")),
            ("@:80", format!("{address}@:80")),
            ("6@", format!("{address}6@")),
            ("tcp@", format!("{address}tcp@")),
            ("tcp@:80", format!("{address}tcp@:80")),
            ("@[", format!("{address}@[")),
            ("@[]", format!("{address}@[]")),
            ("@[::]", format!("{address}@[::]")),
            ("@[::]:80", format!("{address}@[::]:80")),
            ("@[zz::1]", format!("{address}@[zz::1]")),
            ("@[1:2:3]", format!("{address}@[1:2:3]")),
            ("@[::1]]:80", format!("{address}@[::1]]:80")),
            ("@[1::\u{9b}", format!("{address}@[1::\\xc2\\x9b")),
            ("@[1::\u{e9}", format!("{address}@[1::\u{e9}")),
            (
                "6@1.2.3.4",
                "IPv4 addresses are prohibited: -i 6@1.2.3.4".into(),
            ),
            (
                "6@[::ffff:1.2.3.4]",
                "IPv4 addresses are prohibited: -i 6@[::ffff:1.2.3.4]".into(),
            ),
            (
                "6@[::ffff:0.0.0.0]",
                "IPv4 addresses are prohibited: -i 6@[::ffff:0.0.0.0]".into(),
            ),
            (
                "4@[::1]",
                "IPv6 addresses are prohibited: -i 4@[::1]".into(),
            ),
            ("4@[", "IPv6 addresses are prohibited: -i 4@[".into()),
            (":", format!("{port}:")),
            ("4:", format!("{port}4:")),
            ("TCP:", format!("{port}TCP:")),
            ("@1.2.3.4:", format!("{port}@1.2.3.4:")),
            ("@[::1]x", format!("{port}@[::1]x")),
            (":1x", format!("{port}:1x")),
            (":1-", format!("{port}:1-")),
            (":5-1", format!("{port}:5-1")),
            (":1-2-3", format!("{port}:1-2-3")),
            (":1\r", format!("{port}:1\\r")),
            (":1x,y", format!("{port}:1x,y")),
            (":,80", "invalid service name: -i :,80".into()),
            (":80,,81", "invalid service name: -i :80,,81".into()),
            (":,\x1b[2J", "invalid service name: -i :,^[[2J".into()),
            (":1,,\x1b", "invalid service name: -i :1,,^[".into()),
            // An octet's digits saturate where the C's `int` wraps
            // (4294967297 is 1 to it): too large, so no IPv4 address, and a
            // host name (DIVERGENCES 121).
            (
                "@4294967297.0.0.1",
                "host names are not resolved: -i @4294967297.0.0.1 (give the address)".into(),
            ),
            (
                "@99999999999.0.0.1",
                "host names are not resolved: -i @99999999999.0.0.1 (give the address)".into(),
            ),
            (":1-,5", "invalid service name: -i :1-,5".into()),
            ("", "incomplete Internet address specification: -i ".into()),
            (
                "@0.0.0.0",
                "incomplete Internet address specification: -i @0.0.0.0".into(),
            ),
            (
                "@[::ffff:0.0.0.0]",
                "incomplete Internet address specification: -i @[::ffff:0.0.0.0]".into(),
            ),
            ("foo:80", "unknown protocol name (foo) in: -i foo:80".into()),
            (
                "foo@1.2.3.4",
                "unknown protocol name (foo) in: -i foo@1.2.3.4".into(),
            ),
            ("tcpx", "unknown protocol name (tcpx) in: -i tcpx".into()),
            ("tcp6", "unknown protocol name (tcp6) in: -i tcp6".into()),
            ("46", "unknown protocol name (6) in: -i 46".into()),
            (
                "TCP :80",
                "unknown protocol name (TCP ) in: -i TCP :80".into(),
            ),
            (
                "a\x1b[2J",
                "unknown protocol name (a^[[2J) in: -i a^[[2J".into(),
            ),
            (
                ":a\x1b[2J",
                "service names are not resolved: -i :a^[[2J (give the port number)".into(),
            ),
            (
                "@h\x1b[2J.invalid",
                "host names are not resolved: -i @h^[[2J.invalid (give the address)".into(),
            ),
        ] {
            assert_eq!(err(&["-i", spec]), want, "{spec:?}");
        }
        // The version a bare form lends a spec with none of its own, and two
        // versions that widen it back to both (measured).
        assert_eq!(
            err(&["-i4", "-i", "@[::1]"]),
            "IPv6 addresses are prohibited: -i @[::1]"
        );
        assert_eq!(
            err(&["-i", "-i4", "-i", "@[::1]"]),
            "IPv6 addresses are prohibited: -i @[::1]"
        );
        assert_eq!(
            err(&["-i6", "-i", "@1.2.3.4"]),
            "IPv4 addresses are prohibited: -i @1.2.3.4"
        );
        // Entries are judged from left to right: the first bad one names the
        // error.
        assert_eq!(err(&["-i", ":,1x"]), "invalid service name: -i :,1x");
        assert_eq!(err(&["-i", ":1x,,"]), format!("{port}:1x,,"));
    }

    /// What the C accepts, which lsof-rs refused (measured, in OR form against
    /// a sleeper, `-p S -i SPEC`).
    #[test]
    fn dash_i_accepts_what_the_c_accepts() {
        let spec = |argv: &[&str]| run(argv).0.inet.specs.pop().expect("one spec");
        assert_eq!(spec(&["-i", ":99999"]).ports, [(99999, 99999)]);
        assert_eq!(spec(&["-i", ":1-65536"]).ports, [(1, 65536)]);
        assert_eq!(spec(&["-i", ":0-"]).ports, [(0, 0)]);
        assert_eq!(spec(&["-i", ":80,"]).ports, [(80, 80)]);
        // Past `u32` the digits saturate, where the C's `int` wraps
        // (`:4294967376` is its port 80): a port nothing has.
        assert_eq!(spec(&["-i", ":4294967376"]).ports, [(u32::MAX, u32::MAX)]);
        for argv in [&["-i", "udplite"][..], &["-i", "UDPLITE:53"][..]] {
            assert_eq!(spec(argv).proto, Some(Protocol::UdpLite), "{argv:?}");
        }
        assert_eq!(spec(&["-i", "4tcp"]).proto, Some(Protocol::Tcp));
        assert_eq!(spec(&["-i", "TCP"]).proto, Some(Protocol::Tcp));
        for (arg, want) in [
            ("@127.000.000.001", "127.0.0.1"),
            ("@01.2.3.4", "1.2.3.4"),
            ("@0177.0.0.1", "177.0.0.1"),
            ("@[::ffff:1.2.3.4]", "1.2.3.4"),
            ("@[::1]:80", "::1"),
            ("@[::1]", "::1"),
        ] {
            assert_eq!(
                spec(&["-i", arg]).host,
                Some(want.parse().unwrap()),
                "{arg}"
            );
        }
        let zero = spec(&["-i", "TCP@0.0.0.0"]);
        assert_eq!((zero.host, zero.proto), (None, Some(Protocol::Tcp)));
        let zero = spec(&["-i", "@0.0.0.0:80"]);
        assert_eq!((zero.host, zero.ports), (None, vec![(80, 80)]));
        // `-i4 -i6` is both versions again, so an IPv6 address is allowed.
        assert_eq!(spec(&["-i4", "-i6", "-i", "@[::1]"]).family, None);
        assert_eq!(spec(&["-i6", "-i", "-i", "@1.2.3.4"]).family, None);
    }

    /// `MAXNWAD`: 100 entries in all, each port entry one and a spec without
    /// ports one, the spec that crosses it named (measured).
    #[test]
    fn dash_i_has_the_cs_100_address_limit() {
        let list = |n: u32| (1..=n).map(|p| p.to_string()).collect::<Vec<_>>().join(",");
        let limit = "network address limit (100) exceeded: -i ";
        assert_eq!(
            run(&["-i", &format!(":{}", list(100))]).0.inet.specs[0]
                .ports
                .len(),
            100
        );
        let l101 = format!(":{}", list(101));
        assert_eq!(
            parse(vec!["-i".into(), l101.clone()]).unwrap_err(),
            format!("{limit}{l101}")
        );
        let singles: Vec<String> = (1..=101).map(|p| format!("-i:{p}")).collect();
        assert_eq!(parse(singles[..100].to_vec()).map(|_| ()), Ok(()));
        assert_eq!(parse(singles).unwrap_err(), format!("{limit}:101"));
        // A spec with no port is one entry too (`enter_nwad()` once): 100
        // `-i tcp` are accepted and the 101st refused, as the C does
        // (measured).
        let tcps: Vec<String> = (0..101).flat_map(|_| ["-i".into(), "tcp".into()]).collect();
        assert_eq!(parse(tcps[..200].to_vec()).map(|_| ()), Ok(()));
        assert_eq!(parse(tcps).unwrap_err(), format!("{limit}tcp"));
        let argv = |tail: &str| {
            vec![
                "-i".to_string(),
                format!(":{}", list(100)),
                "-i".into(),
                tail.into(),
            ]
        };
        assert_eq!(parse(argv("TCP")).unwrap_err(), format!("{limit}TCP"));
        // The bare forms enter nothing.
        assert!(parse(argv("4")).is_ok());
        // The entry's own error comes first; the limit, before a later one's.
        let l100x = format!(":{},1x", list(100));
        assert_eq!(
            parse(vec!["-i".into(), l100x.clone()]).unwrap_err(),
            format!("unacceptable port specification in: -i {l100x}")
        );
        let l101x = format!(":{},1x", list(101));
        assert_eq!(
            parse(vec!["-i".into(), l101x.clone()]).unwrap_err(),
            format!("{limit}{l101x}")
        );
    }

    /// `icmp` and `raw` are the Windows port's ETW families; on Linux they are
    /// no protocol to the C, which types a raw socket `raw` and never selects
    /// one by `-i` (measured; DIVERGENCES 108).
    #[cfg(not(windows))]
    #[test]
    fn icmp_and_raw_are_not_protocols_on_linux() {
        for p in ["icmp", "ICMP", "raw", "6icmp", "RAW:1"] {
            let token = p.trim_start_matches('6').split(':').next().unwrap();
            assert_eq!(
                parse(vec!["-i".into(), p.into()]).unwrap_err(),
                format!("unknown protocol name ({token}) in: -i {p}")
            );
        }
        // UDP-Lite is a table Linux reads, and implies no capture.
        assert!(!run(&["-iudplite"]).0.inet.needs_etw());
    }

    #[cfg(windows)]
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

        // TCP/UDP/UDP-Lite/plain -i never imply the capture.
        assert!(!run(&["-iTCP"]).0.inet.needs_etw());
        assert!(!run(&["-iudplite"]).0.inet.needs_etw());
        assert!(!run(&["-i"]).0.inet.needs_etw());
    }

    /// `+c` with no width, an empty one or one that opens with anything but
    /// a digit is the C's `+c not followed by width number`, which quotes
    /// nothing; `+c 1x` is `atoi()`'s 1 (all measured).
    #[test]
    fn plus_c_takes_atois_width_and_quotes_nothing() {
        let err = |argv: &[&str]| parse(argv.iter().map(|s| s.to_string()).collect()).err();
        for argv in [
            &["+c"][..],
            &["+c", ""][..],
            &["+c", "x"][..],
            &["+cx"][..],
            &["+c", "-p", "1"][..],
            &["+c", "\x1b[2J"][..],
            &["+c", " 1"][..],
        ] {
            assert_eq!(
                err(argv).as_deref(),
                Some("+c not followed by width number"),
                "{argv:?}"
            );
        }
        let width = |argv: &[&str]| run(argv).0.command_width;
        assert_eq!(width(&["+c", "1x"]), CommandWidth::Chars(1));
        assert_eq!(width(&["+c1\x1b[2J"]), CommandWidth::Chars(1));
        assert_eq!(width(&["+c", "0"]), CommandWidth::Unlimited);
        if cfg!(target_os = "linux") {
            assert_eq!(
                err(&["+c", "16x"]).as_deref(),
                Some("+c 16 > what system provides (15)")
            );
        }
    }

    /// The `-c` length message quotes the name with `safestrprt(…, 2)`: a
    /// space is `\x20` and a control byte escaped, é raw (measured).
    #[cfg(target_os = "linux")]
    #[test]
    fn the_c_length_message_is_safestrprt_flags_2() {
        let err = |v: &str| parse(vec!["-c".into(), v.into()]).unwrap_err();
        assert_eq!(
            err("aaaaaaaaaaaaaa\x1b[2J"),
            "\"-c aaaaaaaaaaaaaa^[[2J\" length (18) > what system provides (15)"
        );
        assert_eq!(
            err("a ba ba ba ba ba b"),
            "\"-c a\\x20ba\\x20ba\\x20ba\\x20ba\\x20ba\\x20b\" length (18) > what system provides (15)"
        );
        assert_eq!(
            err("\u{e9} a\\\x7f\u{9b}bbbbbbbbbbb"),
            "\"-c \u{e9}\\x20a\\\\\\x7f\\xc2\\x9bbbbbbbbbbbb\" length (19) > what system provides (15)"
        );
    }

    /// No option's error, and no line a parse tells its sink, holds a control
    /// character (U+2028 and U+2029 included): every argument a message
    /// quotes is escaped, where the C prints several raw (DIVERGENCES 112,
    /// 122). Every letter, known or not, under both prefixes, its value
    /// attached and as the next word; then the conflicts and the lines said
    /// while parsing. A parse's error may hold several, joined by
    /// `"\nlsof: "`, and no other newline.
    #[test]
    fn no_option_error_holds_a_control_character() {
        let long = format!("{}\x1b[2J", "a".repeat(40));
        let hostile = [
            "\x1b[2J",
            "a\x1b[2J",
            "1\x1b[2J",
            "TCP:\x1b",
            "TCP:LISTEN,\x1b",
            "UDP:\x1b",
            "^x\x1b",
            "^\x1b",
            "/x\x1b[2J",
            "/no\x1b[2Jsuch/",
            "\r",
            "\x7f",
            "\u{9b}",
            "\u{2028}",
            "\u{2029}x",
            ":1\x1b",
            "@[1::\x1b",
            "@h\x1b",
            "4\x1b",
            "m\x1b",
            "1-\x1b",
            "c\x1b",
            ",\x1b[2J",
            "1,,\x1b",
            ":,\x1b[2J",
            ":1,,\x1b",
            long.as_str(),
        ];
        let bad = |s: &str| {
            s.chars()
                .any(|c| c.is_control() || c == '\u{2028}' || c == '\u{2029}')
        };
        let check = |argv: Vec<String>| {
            let said = std::cell::RefCell::new(Vec::new());
            let sink = |l: &str| said.borrow_mut().push(l.to_string());
            let fs = SafeFs::new(&lsof_core::InProcess, &sink);
            // A table that holds `/` alone, so that an `-e` of anything else
            // is the not-mounted error.
            let reader = |_: &MountRequest, _: &SafeFs| MountTable {
                entries: vec![lsof_core::MountEntry {
                    dir: "/".into(),
                    device: Some(1),
                    source_resolved: None,
                    source_is_block: false,
                    kind: lsof_core::MountKind::Regular,
                }],
                ..MountTable::default()
            };
            if let Err(e) = parse_with(argv.clone(), &fs, &reader) {
                for piece in e.split("\nlsof: ") {
                    assert!(!bad(piece), "{argv:?}: {e:?}");
                }
            }
            for line in said.into_inner() {
                assert!(!bad(&line), "{argv:?} said {line:?}");
            }
        };
        for letter in ('a'..='z').chain('A'..='Z').chain(['?', '0', '\x1b']) {
            for prefix in ['-', '+'] {
                for value in hostile {
                    check(vec![format!("{prefix}{letter}{value}")]);
                    check(vec![format!("{prefix}{letter}"), value.to_string()]);
                    // After `-b`, the `+d`/`-e` paths are named as avoided.
                    check(vec![
                        "-b".into(),
                        format!("{prefix}{letter}"),
                        value.to_string(),
                    ]);
                }
            }
        }
        for value in hostile {
            let v = value.to_string();
            for argv in [
                vec!["-c".into(), v.clone(), "-c".into(), format!("^{v}")],
                vec!["-c".into(), format!("^{v}"), "-c".into(), v.clone()],
                vec!["-d".into(), format!("1,^{v}")],
                vec!["-d".into(), format!("^1,{v}")],
                vec![
                    "-s".into(),
                    format!("TCP:{v}"),
                    "-s".into(),
                    format!("TCP:^{v}"),
                ],
                vec!["-e".into(), v.clone(), "-e".into(), format!("/{v}")],
                vec!["+e".into(), format!("/{v}"), "-x".into(), "q".into()],
                vec!["-S".into(), "0".into(), "+d".into(), v.clone()],
                vec!["-i".into(), format!(":{v}"), "-i".into(), format!("{v}@1")],
            ] {
                check(argv);
            }
        }
        // The joined post-loop errors, each piece on its own (item 91).
        for argv in [
            &["-o", "-s", "-J", "-t"][..],
            &["-J", "-j", "-t"],
            &["+J", "+j"],
            &["-J", "-t", "-e", "/nosuch"],
        ] {
            check(argv.iter().map(|s| s.to_string()).collect());
        }
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
        assert!(matches!(
            run(&["-J"]).1,
            Format::Json(JsonFormat { lines: false, .. })
        ));
        assert!(matches!(
            run(&["-j"]).1,
            Format::Json(JsonFormat { lines: true, .. })
        ));
    }

    fn json(argv: &[&str]) -> JsonFormat {
        match run(argv).1 {
            Format::Json(j) => j,
            other => panic!("{argv:?}: {other:?}"),
        }
    }

    fn refused(argv: &[&str]) -> String {
        parse(argv.iter().map(|s| s.to_string()).collect()).unwrap_err()
    }

    /// `-J`/`-j` and `-t` (and `-F` and `-t`, DIVERGENCES 90), `-J` and `-j`,
    /// and `+J`/`+j`: the C's words, in its order (`main.c:1091-1133`), each
    /// found and all reported, joined as main prints them (measured).
    #[test]
    fn json_refusals_are_the_cs_in_its_order() {
        let ft = "-F and -t are mutually exclusive";
        let jt = "-J/-j and -t are mutually exclusive";
        let jj = "-J and -j are mutually exclusive";
        let os = "-o and -s are mutually exclusive";
        let x = "-x must accompany +d or +D";
        let joined = |v: &[&str]| v.join("\nlsof: ");
        for argv in [
            &["-J", "-t"][..],
            &["-t", "-J"],
            &["-j", "-t"],
            &["-J", "-Fp0", "-t"],
        ] {
            assert_eq!(refused(argv), joined(&[ft, jt]), "{argv:?}");
        }
        for argv in [&["-F", "-t"][..], &["-t", "-F"], &["-tF"], &["-Fp", "-t"]] {
            assert_eq!(refused(argv), ft, "{argv:?}");
        }
        for argv in [&["-J", "-j"][..], &["-j", "-J"], &["-Jj"]] {
            assert_eq!(refused(argv), jj, "{argv:?}");
        }
        assert_eq!(refused(&["-J", "-j", "-t"]), joined(&[ft, jj, jt]));
        assert_eq!(refused(&["-o", "-s", "-J", "-t"]), joined(&[os, ft, jt]));
        assert_eq!(refused(&["-J", "-t", "-x"]), joined(&[ft, x, jt]));
        // `+J`/`+j` are said where they are met, and the parse reads on.
        assert_eq!(refused(&["+J"]), "+J is not supported");
        assert_eq!(refused(&["+j"]), "+j is not supported");
        assert_eq!(
            refused(&["+J", "+j"]),
            joined(&["+J is not supported", "+j is not supported"])
        );
        assert_eq!(
            refused(&["-o", "-s", "+J"]),
            joined(&["+J is not supported", os])
        );
        assert_eq!(refused(&["+J", "-h"]), "+J is not supported");
        assert_eq!(
            refused(&["+J", "-q"]),
            joined(&["+J is not supported", "illegal option character: q"])
        );
        // Repeating one is not a conflict.
        assert!(!json(&["-J", "-J"]).lines);
        assert!(json(&["-j", "-j"]).lines);
    }

    /// `-F` and `-J`/`-j` combine in either order: the C keeps `-F`'s choice
    /// and the JSON switch apart (`-J -Fpcfn` is `-Fpcfn -J`, measured). A
    /// selection is any letter but `p` and `m`, a `0` or a bare `-F`
    /// (`main.c:1163-1179`); without one, the default set.
    #[test]
    fn dash_f_selects_json_fields_in_either_order() {
        let only = |argv: &[&str]| json(argv).only;
        let letters = |l: &str| Some(l.chars().collect::<Vec<_>>());
        assert_eq!(only(&["-J", "-Fpcfn"]), letters("pcfn"));
        assert_eq!(only(&["-Fpcfn", "-J"]), letters("pcfn"));
        assert_eq!(only(&["-j", "-Fc"]), letters("c"));
        assert!(json(&["-j", "-Fc"]).lines);
        for argv in [
            &["-J"][..],
            &["-J", "-Fp"],
            &["-J", "-Fpm"],
            &["-J", "-Fm"],
            &["-J", "-F"],
        ] {
            assert_eq!(only(argv), None, "{argv:?}");
        }
        assert_eq!(only(&["-J", "-Fp0"]), letters("p"));
        assert_eq!(only(&["-J", "-F0"]), None);
        // -F alone is still -F.
        assert!(matches!(run(&["-Fn"]).1, Format::Fields { .. }));
    }

    /// `tcp_info`'s members: every one by default, whatever `-T` says, and
    /// collected on Linux; under a `-F` selection, `-T` as given.
    #[test]
    fn json_tcp_info_members_follow_the_cs_defaults() {
        let all = TcpInfoFlags {
            state: true,
            queue: true,
            window: true,
            options: false,
        };
        for argv in [
            &["-J"][..],
            &["-J", "-T"],
            &["-J", "-Tq"],
            &["-J", "-Ts"],
            &["-T", "-j"],
        ] {
            assert_eq!(json(argv).tcp_show, all, "{argv:?}");
        }
        #[cfg(target_os = "linux")]
        {
            let t = run(&["-J", "-T"]).0.tcp_info();
            assert!(t.state && t.queue, "the queues are read: {t:?}");
        }
        let fq = json(&["-J", "-FpfT", "-Tq"]).tcp_show;
        assert!(fq.queue && !fq.state, "{fq:?}");
        assert_eq!(json(&["-J", "-F", "-T"]).tcp_show, TcpInfoFlags::default());
        let ft = json(&["-J", "-F"]).tcp_show;
        assert!(ft.state && ft.queue, "{ft:?}");
    }

    /// `flags`: always shown by default, by name unless the last `-f`/`+f`
    /// letter was `G` (`-J -fg` is `-J`); under a `-F` selection, as `-F`
    /// shows them (measured).
    #[test]
    fn json_file_flags_follow_the_cs_defaults() {
        let ff = |argv: &[&str]| json(argv).file_flags;
        assert_eq!(ff(&["-J"]), FileFlags::Names);
        assert_eq!(ff(&["-J", "-F"]), FileFlags::Hex);
        assert_eq!(ff(&["-J", "-FG"]), FileFlags::Hex);
        // The -f letters exist only where file flags are recorded; elsewhere
        // they are refused (the_file_flags_letters_are_refused_where_none_are_recorded).
        if cfg!(target_os = "linux") {
            assert_eq!(ff(&["-J", "+fG"]), FileFlags::Hex);
            assert_eq!(ff(&["-J", "-fG"]), FileFlags::Hex);
            assert_eq!(ff(&["+fG", "-J"]), FileFlags::Hex);
            assert_eq!(ff(&["-J", "-fg"]), FileFlags::Names);
            assert_eq!(ff(&["-J", "+fg"]), FileFlags::Names);
            assert_eq!(ff(&["-J", "-F", "-fg"]), FileFlags::Off);
        }
    }

    #[test]
    fn help_and_version() {
        assert!(matches!(
            parse(vec!["-h".into()]).unwrap(),
            Action::Report(Reports::HELP)
        ));
        assert!(matches!(
            parse(vec!["-v".into()]).unwrap(),
            Action::Report(Reports::VERSION)
        ));
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
        let got = parse_with(
            argv.iter().map(|s| s.to_string()).collect(),
            &fs,
            &no_mounts,
        );
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
            Some("illegal option character: 1")
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
        assert!(matches!(
            parse(vec!["-v".into()]).unwrap(),
            Action::Report(Reports::VERSION)
        ));
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
            // `+m`'s value, if any, is never read as letters (`+mfoo` is not
            // `-f -o -o`); the refusal ends the parse (DIVERGENCES 149).
            ("+m", "unsupported option: +m"),
            ("+mfoo", "unsupported option: +m"),
            ("+J", "+J is not supported"),
            ("+aq", "illegal option character: q"),
            ("+", "unsupported option: +"),
        ] {
            assert_eq!(columns(&[o]).unwrap_err(), want, "{o}");
        }
        assert_eq!(columns(&["-q"]).unwrap_err(), "illegal option character: q");
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
        assert!(
            matches!(fields(&["-Fn", "-J"]), Format::Json(JsonFormat { only: Some(ref l), .. }) if *l == ['n']),
            "-F selects JSON's fields"
        );
        // `?` lists the letters, attached or not, and nothing else happens.
        for argv in [&["-F?"][..], &["-F", "?"][..], &["-F", "?", "-p", "1"][..]] {
            assert!(
                matches!(
                    parse(argv.iter().map(|s| s.to_string()).collect()),
                    Ok(Action::Report(Reports::FIELD_HELP))
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

    /// Parse over the in-process layer with `table` for the host's mount
    /// table, and hand back what the parse printed, each table read as a
    /// line naming the `-e`/`+e` list and options it was read under, and the
    /// lines the table itself says (`say`).
    fn parse_over(
        argv: &[&str],
        table: &[&str],
        say: &[&str],
    ) -> (Result<Action, String>, Vec<String>) {
        let said = std::cell::RefCell::new(Vec::new());
        let sink = |l: &str| said.borrow_mut().push(l.to_string());
        let fs = SafeFs::new(&lsof_core::InProcess, &sink);
        let reader = |req: &MountRequest, fs: &SafeFs| {
            let exempt: Vec<String> = req
                .exempt
                .iter()
                .map(|e| {
                    format!(
                        "{}{}",
                        if e.plus { '+' } else { '-' },
                        e.path.to_string_lossy()
                    )
                })
                .collect();
            fs.tell(&format!(
                "READ exempt={exempt:?} warn={} avoid={}",
                fs.warns(),
                fs.blocking().avoid
            ));
            for l in say {
                if fs.warns() {
                    fs.tell(l);
                }
            }
            MountTable {
                entries: table
                    .iter()
                    .map(|d| lsof_core::MountEntry {
                        dir: (*d).into(),
                        device: Some(1),
                        source_resolved: Some("src".into()),
                        source_is_block: false,
                        kind: lsof_core::MountKind::Regular,
                    })
                    .collect(),
                ..MountTable::default()
            }
        };
        let got = parse_with(argv.iter().map(|s| s.to_string()).collect(), &fs, &reader);
        (got, said.into_inner())
    }

    /// The C reads its mount table iff some `-e`/`+e` was given or the run is
    /// not `-i` alone (`Selinet`): every form below measured by counting
    /// the C's `alarm(15)` calls (none, or one per request of its child), the
    /// negated and value-less ones included (DIVERGENCES 110). Linux's
    /// alone: only it has a mount table, and the Windows parser reads `-g` as
    /// parent PIDs, with a value it requires.
    #[cfg(target_os = "linux")]
    #[test]
    fn needs_mount_table_is_the_cs_selinet() {
        let d = a_dir();
        let no_table: &[&[&str]] = &[
            &["-i"],
            &["-i", "TCP:22"],
            &["-i", "@127.0.0.1"],
            &["-i", "4"],
            &["-i", "UDP"],
            &["-n", "-P", "-i", ":22"],
            &["-i", "-s", "TCP:LISTEN"],
            &["-i", "-T"],
            &["-t", "-i"],
            &["-a", "-i"],
            &["-i", "-p", "^1"],
            &["-i", "-u", "^root"],
            &["-i", "-c", "^x"],
            &["-i", "-g", "^1"],
            &["-i", "-g"],
            &["-i", "-K", "i"],
            &["-i", "+L"],
            &["-i", "-E"],
            &["-i", "+E"],
            &["-i", "-w", "-n", "-P", "-l", "-R", "-o", "-T"],
        ];
        let table: &[&[&str]] = &[
            &["-i", "-d", "^3"],
            &["-i", "-g", "1"],
            &["-i", "-K"],
            &["-i", "-U"],
            &["-i", "-N"],
            &["-i", "-e", "/x"],
            &["-i", "+e", "/x"],
            &["-i", "+L1"],
            &["-i", "-p", "1"],
            &["-i", "-a", "-p", "1"],
            &["-i", "-u", "0"],
            &["-i", "-c", "x"],
            &["/dev/null", "-i"],
            &["-s", "TCP:LISTEN"],
            &["-U"],
            &["-t"],
            &["-N"],
            &["-t", "-p", "1"],
            &["-f", "--", "/"],
            &["+f", "--", "/dev"],
            &["+d", &d],
            &["-i", "+D", &d],
            &[],
        ];
        let needs = |argv: &[&str]| match parse(argv.iter().map(|s| s.to_string()).collect()) {
            Ok(Action::Run { selection, .. }) => selection.needs_mount_table(),
            other => panic!("{argv:?}: {other:?}"),
        };
        for argv in no_table {
            assert!(!needs(argv), "{argv:?} reads no table in the C");
        }
        for argv in table {
            assert!(needs(argv), "{argv:?} reads the table in the C");
        }
        // `-i -x f` is no table case: a usage error in both.
        assert_eq!(
            parse(vec!["-i".into(), "-x".into(), "f".into()]).unwrap_err(),
            "-x must accompany +d or +D"
        );
    }

    /// `-e` is spelt by `Readlink()` where it stands, under the `-b` and `-w`
    /// given before it; `+e` is taken as typed; a path entered twice keeps
    /// the sign it was first given (DIVERGENCES 88; measured).
    #[cfg(unix)]
    #[test]
    fn dash_e_reads_its_links_and_plus_e_does_not() {
        let tmp = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let dir = tmp.join(format!("lsof-rs-args-e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::os::unix::fs::symlink("/nonexist/x", dir.join("bad")).unwrap();
        std::os::unix::fs::symlink("l2", dir.join("l1")).unwrap();
        std::os::unix::fs::symlink("l1", dir.join("l2")).unwrap();
        let bad = dir.join("bad").to_string_lossy().into_owned();
        let l1 = dir.join("l1").to_string_lossy().into_owned();
        let exempt = |argv: &[&str]| match parse_over(argv, &[], &[]) {
            (Ok(Action::Run { selection, .. }), _) => selection
                .exempt_fs
                .into_iter()
                .map(|e| (e.path.into_string().unwrap(), e.plus))
                .collect::<Vec<_>>(),
            other => panic!("{argv:?}: {other:?}"),
        };
        assert_eq!(exempt(&["-e", &bad]), [("/nonexist/x".to_string(), false)]);
        assert_eq!(exempt(&["+e", &bad]), [(bad.clone(), true)]);
        assert_eq!(
            exempt(&["+e", "/m/", "-e", "/m"]),
            [("/m".to_string(), true)]
        );
        assert_eq!(
            exempt(&["-e", "/m", "+e", "/m//"]),
            [("/m".to_string(), false)]
        );
        // A link loop is its message, muted by a `-w` before it alone.
        let looped = format!("too many (> 20) symbolic links in readlink() path: {l1}");
        assert_eq!(parse_over(&["-e", &l1], &[], &[]).0.unwrap_err(), looped);
        assert_eq!(parse_over(&["-w", "-e", &l1], &[], &[]).0.unwrap_err(), "");
        assert!(
            parse_over(&["+e", &l1], &[], &[]).0.is_ok(),
            "+e reads no link"
        );
        // `-b` before it: `avoiding readlink(P)` there, and P kept as typed.
        let (got, said) = parse_over(&["-b", "-e", &bad], &[], &[]);
        assert!(got.is_ok());
        assert_eq!(
            said[0],
            format!("lsof: avoiding readlink({bad}): -b was specified.")
        );
        let (_, said) = parse_over(&["-e", "/dev/shm", "-b"], &[], &[]);
        assert!(said.iter().all(|l| l.starts_with("READ")), "{said:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `-e not followed by a file system path` quotes the value escaped,
    /// `+e`'s too, and is muted by a `-w` or `-t` before the option, where
    /// the run still ends (measured: `-w -e dev/` and `-t -e dev/` print only
    /// the usage, `-e dev/ -w` the message).
    #[test]
    fn a_relative_exempt_path_is_refused_and_muted_by_w_before_it() {
        let err = |argv: &[&str]| parse_over(argv, &[], &[]).0.unwrap_err();
        assert_eq!(
            err(&["-e", "dev/"]),
            r#"-e not followed by a file system path: "dev/""#
        );
        assert_eq!(
            err(&["+e", "dev/"]),
            r#"-e not followed by a file system path: "dev/""#
        );
        assert_eq!(
            err(&["-e", "-p", "1"]),
            r#"-e not followed by a file system path: "-p""#
        );
        assert_eq!(
            err(&["-p", "1", "-e"]),
            r#"-e not followed by a file system path: """#
        );
        assert_eq!(
            err(&["-e", "d\x1b[2J"]),
            r#"-e not followed by a file system path: "d^[[2J""#
        );
        assert_eq!(err(&["-w", "-e", "dev/"]), "");
        assert_eq!(err(&["-t", "-e", "dev/"]), "");
        assert_eq!(err(&["-w", "-e", "-p", "1"]), "");
        assert_eq!(
            err(&["-t", "+w", "-e", "dev/"]),
            r#"-e not followed by a file system path: "dev/""#
        );
    }

    /// The `-e` check runs once every option is read, before `-h` and `-v`
    /// are acted on, after the other end-of-parse errors, against a table
    /// read there if no `+d` read it; and only a table that holds something.
    /// Every bad path is reported, the last given first, escaped, and the
    /// errors are one, joined as the C prints them (DIVERGENCES 83, 115).
    #[test]
    fn every_unmounted_exempt_path_is_an_error_after_the_others() {
        let mounted = ["/m", "/n"];
        let err = |argv: &[&str]| parse_over(argv, &mounted, &[]).0.unwrap_err();
        assert_eq!(
            err(&["-e", "/nosuch1", "-e", "/m", "+e", "/nosuch2"]),
            "\"-e /nosuch2\" is not a mounted file system.\n\
             lsof: \"-e /nosuch1\" is not a mounted file system."
        );
        assert_eq!(
            err(&["-e", "/nosuch", "-h"]),
            "\"-e /nosuch\" is not a mounted file system."
        );
        assert_eq!(
            err(&["-v", "-e", "/nosuch"]),
            "\"-e /nosuch\" is not a mounted file system."
        );
        assert_eq!(
            err(&["-e", "/no\x1b[2J"]),
            "\"-e /no^[[2J\" is not a mounted file system."
        );
        // What comes before the `-e` check is printed before the table is
        // read for it, and so before what the table says; one read already
        // leaves them all to the end.
        let warned = ["lsof: WARNING: can't stat() tmpfs file system /gone"];
        let (got, said) = parse_over(&["-e", "/nosuch", "-x", "f"], &mounted, &warned);
        assert_eq!(
            got.unwrap_err(),
            "\"-e /nosuch\" is not a mounted file system."
        );
        assert_eq!(said[0], "lsof: -x must accompany +d or +D");
        assert!(
            said[1].starts_with("READ ") && said[2] == warned[0],
            "{said:?}"
        );
        let (got, said) = parse_over(&["-o", "-s", "-x", "-e", "/m"], &mounted, &[]);
        assert_eq!(got.unwrap_err(), "", "printed already, and still an error");
        assert_eq!(
            said[..2],
            [
                "lsof: -o and -s are mutually exclusive",
                "lsof: -x must accompany +d or +D"
            ]
        );
        let d = a_dir();
        let (got, said) = parse_over(&["+d", &d, "-e", "/nosuch", "-o", "-s"], &mounted, &warned);
        assert_eq!(
            got.unwrap_err(),
            "-o and -s are mutually exclusive\nlsof: \"-e /nosuch\" is not a mounted file system."
        );
        assert_eq!(said.len(), 2, "the read at +d, and its line: {said:?}");
        assert_eq!(
            parse(
                ["-s", "TCP:LISTEN,^LISTEN,ESTABLISHED,^ESTABLISHED", "-x"]
                    .iter()
                    .map(|a| a.to_string())
                    .collect()
            )
            .unwrap_err(),
            // Each conflicting state in the order of the platform's state
            // table: the C's (Linux) has ESTABLISHED before LISTEN, the
            // Windows table (MIB_TCP_STATE) LISTEN first.
            if cfg!(windows) {
                "can't include and exclude TCP state: LISTEN\n\
                 lsof: can't include and exclude TCP state: ESTABLISHED\n\
                 lsof: -x must accompany +d or +D"
            } else {
                "can't include and exclude TCP state: ESTABLISHED\n\
                 lsof: can't include and exclude TCP state: LISTEN\n\
                 lsof: -x must accompany +d or +D"
            }
        );
        // `-hx` is `-x`'s error, not the help.
        assert_eq!(
            parse(vec!["-hx".into()]).unwrap_err(),
            "-x must accompany +d or +D"
        );
        assert!(matches!(
            parse_over(&["-h", "-e", "/m"], &mounted, &[]).0,
            Ok(Action::Report(Reports::HELP))
        ));
        // A mounted path, and `-f` changes nothing about it (DIVERGENCES 113).
        assert!(parse_over(&["-f", "-e", "/m", "-e", "/n/"], &mounted, &[])
            .0
            .is_ok());
        // An empty table checks nothing: `-b -e /nosuch` runs.
        assert!(parse_over(&["-e", "/nosuch"], &[], &[]).0.is_ok());
    }

    /// The table is read once, where the C reads it: at the first `+d`/`+D`,
    /// under the `-w`, `-b` and `-e`/`+e` given before it, its lines there;
    /// else for the `-e` check, under the options as they ended; else not
    /// at all while parsing (DIVERGENCES 82, 87, 110).
    #[test]
    fn the_table_is_read_at_the_first_plus_d_under_the_options_there() {
        let d = a_dir();
        let warned = ["lsof: WARNING: can't stat() tmpfs file system /gone"];
        let said = |argv: &[&str]| parse_over(argv, &["/m"], &warned).1;
        let read = |exempt: &str, warn: bool, avoid: bool| {
            format!("READ exempt={exempt} warn={warn} avoid={avoid}")
        };
        // `+d D -w` warns; `-w +d D` does not; one read for two `+d`.
        assert_eq!(
            said(&["+d", &d, "-w", "+D", &d]),
            [read("[]", true, false), warned[0].into()]
        );
        assert_eq!(said(&["-w", "+d", &d]), [read("[]", false, false)]);
        // `+d D -e M` reads with no `-e`; `-e M +d D` with it.
        assert_eq!(
            said(&["+d", &d, "-e", "/m"]),
            [read("[]", true, false), warned[0].into()]
        );
        assert_eq!(
            said(&["-e", "/m", "+d", &d])[0],
            read("[\"-/m\"]", true, false)
        );
        assert_eq!(
            said(&["+e", "/m", "+d", &d])[0],
            read("[\"+/m\"]", true, false)
        );
        // Before a later option's parse-time line, and after an earlier one's.
        assert_eq!(
            said(&["+d", &d, "-S", "0"]),
            [
                read("[]", true, false),
                warned[0].into(),
                "lsof: WARNING: -S time (0) changed to 2".into()
            ]
        );
        assert_eq!(
            said(&["-S", "0", "+d", &d])[0],
            "lsof: WARNING: -S time (0) changed to 2"
        );
        // No `+d`: read for the `-e` check, under the options as they ended.
        assert_eq!(said(&["-e", "/m", "-w"]), [read("[\"-/m\"]", false, false)]);
        assert_eq!(
            said(&["-e", "/m", "-b", "-w"]),
            [read("[\"-/m\"]", false, true)]
        );
        // Neither: not read while parsing, `-h` or not.
        assert!(said(&["-p", "1"]).is_empty());
        assert!(said(&["-h"]).is_empty());
        // A `+d` whose directory fails reads none.
        assert!(parse_over(&["+d", "/nonexistent-dir"], &["/m"], &warned)
            .1
            .iter()
            .all(|l| !l.starts_with("READ")));
        // The table travels with the run.
        match parse_over(&["+d", &d], &["/m"], &[]).0 {
            Ok(Action::Run {
                mounts: Some(t), ..
            }) => assert_eq!(t.entries.len(), 1),
            other => panic!("{other:?}"),
        }
        match parse_over(&["-p", "1"], &["/m"], &[]).0 {
            Ok(Action::Run { mounts, .. }) => assert!(mounts.is_none()),
            other => panic!("{other:?}"),
        }
    }

    /// Parse over a host whose password file knows `alice` (1000) and
    /// `root` (0), every number being its own UID, and whose SELinux is
    /// `selinux`, as `lsof` parses ([`parse_with_host`]).
    fn parse_on_host(argv: &[&str], selinux: bool) -> Result<Action, String> {
        let lookup = |v: &str| match v {
            "alice" => UserLookup::Uid(1000),
            "root" => UserLookup::Uid(0),
            v if v.bytes().all(|b| b.is_ascii_digit()) => {
                v.parse().map_or(UserLookup::Unknown, UserLookup::Uid)
            }
            _ => UserLookup::Unknown,
        };
        let enabled = || selinux;
        let host = HostChecks {
            lookup_user: &lookup,
            selinux_enabled: &enabled,
        };
        parse_with_host(
            argv.iter().map(|s| s.to_string()).collect(),
            &SafeFs::in_process(),
            &no_mounts,
            &host,
        )
    }

    /// The lines an `Err` prints, after main's first `lsof: `.
    fn error_lines(got: Result<Action, String>) -> Vec<String> {
        match got {
            Err(e) => e.split("\nlsof: ").map(str::to_string).collect(),
            Ok(a) => panic!("expected an error, got {a:?}"),
        }
    }

    /// DIVERGENCES 114 and 73: what the C finds wrong while it parses — an
    /// unknown `-u` login, `-Z` without SELinux — beats `-h`, `-v` and
    /// `-F ?`, in option order; each measured, exit 1 with no help.
    #[test]
    fn host_errors_found_while_parsing_beat_help_and_version() {
        let nosuch = "can't get UID for nosuch";
        let z = "-Z limited to SELinux";
        for argv in [
            &["-h", "-u", "nosuch"][..],
            &["-u", "nosuch", "-h"],
            &["-h", "-u", "^nosuch"],
            &["-h", "-g", "1", "-u", "nosuch"],
            &["-h", "-w", "-u", "nosuch"],
            &["-h", "-t", "-u", "nosuch"],
            &["-v", "-u", "nosuch"],
            &["-F", "?", "-u", "nosuch"],
            &["-u", "nosuch", "-F", "?"],
        ] {
            assert_eq!(
                error_lines(parse_on_host(argv, false)),
                [nosuch],
                "{argv:?}"
            );
        }
        for argv in [
            &["-h", "-Z"][..],
            &["-Z", "-h"],
            &["-v", "-Z"],
            &["-F", "?", "-Z"],
            // `-Z` takes the next word whatever it is, `--` aside.
            &["-Z", "-u", "nosuch"],
            &["-Z", "-x"],
            &["-Z", "-p"],
            &["-Z", "-Z"],
            &["-Z", "--", "-h"],
            &["-Z"],
        ] {
            assert_eq!(error_lines(parse_on_host(argv, false)), [z], "{argv:?}");
        }
        // Both, in the order given, and the errors found after the loop next.
        assert_eq!(
            error_lines(parse_on_host(&["-u", "nosuch", "-Z"], false)),
            [nosuch, z]
        );
        assert_eq!(
            error_lines(parse_on_host(&["-Zctx", "-x"], false)),
            [z, "-x must accompany +d or +D"]
        );
        assert_eq!(
            error_lines(parse_on_host(&["-u", "nosuch", "-hx"], false)),
            [nosuch, "-x must accompany +d or +D"]
        );
        // `usage()` ends the run before the checks made after it.
        assert_eq!(
            error_lines(parse_on_host(&["-u", "nosuch", "-X", "-i"], false)),
            [nosuch]
        );
        assert_eq!(
            error_lines(parse_on_host(&["-u", "nosuch", "-a"], false)),
            [nosuch]
        );
        assert_eq!(
            error_lines(parse_on_host(&["+J", "-a"], false)),
            ["+J is not supported"]
        );
        // Where SELinux is enabled `-Z` gives an option word back, and the
        // help is the help.
        assert!(matches!(
            parse_on_host(&["-Z", "-h"], true),
            Ok(Action::Report(Reports::HELP))
        ));
        assert!(matches!(
            parse_on_host(&["-h", "-Z"], true),
            Ok(Action::Report(Reports::HELP))
        ));
        match parse_on_host(&["-Z", "ctx"], true) {
            Ok(Action::Run { selection, .. }) => {
                assert_eq!(selection.selinux, Some(vec!["ctx".into()]))
            }
            other => panic!("{other:?}"),
        }
        // A known login is no error, and `-h` is acted on.
        assert!(matches!(
            parse_on_host(&["-u", "alice", "-h"], false),
            Ok(Action::Report(Reports::HELP))
        ));
        assert!(matches!(
            parse_on_host(&["-u", "0", "-v"], false),
            Ok(Action::Report(Reports::VERSION))
        ));
    }

    /// `enter_uid()` item by item: a UID entered on both sides ends the parse
    /// at that item (`lsof_select_uid()`'s `Error()`), after the unknown
    /// logins before it and before those after it; each UID is entered once,
    /// its first spelling kept (measured: `-u nosuch,^0,0` prints both
    /// lines, `-u 0,^0,nosuch` and `-u root,^0 -u nosuch` the conflict alone).
    #[test]
    fn users_are_resolved_item_by_item() {
        let both = "UID 0 has been included and excluded.";
        assert_eq!(
            error_lines(parse_on_host(&["-u", "nosuch,^0,0"], false)),
            ["can't get UID for nosuch", both]
        );
        assert_eq!(
            error_lines(parse_on_host(&["-u", "0,^0,nosuch"], false)),
            [both]
        );
        assert_eq!(
            error_lines(parse_on_host(&["-u", "root,^0", "-u", "nosuch"], false)),
            [both]
        );
        assert_eq!(
            error_lines(parse_on_host(&["-u", "^root", "-u", "0", "-h"], false)),
            [both]
        );
        match parse_on_host(&["-u", "alice,1000,^5,^5,0"], false) {
            Ok(Action::Run { selection, .. }) => {
                assert_eq!(
                    selection.uids,
                    [
                        UidSel {
                            uid: 1000,
                            login: Some("alice".into())
                        },
                        UidSel {
                            uid: 0,
                            login: None
                        }
                    ]
                );
                assert_eq!(selection.uid_excludes, [5]);
                assert!(selection.users.is_empty() && selection.user_excludes.is_empty());
            }
            other => panic!("{other:?}"),
        }
        // A login is escaped where the message quotes it.
        assert_eq!(
            error_lines(parse_on_host(&["-u", "a\u{1b}b"], false)),
            ["can't get UID for a^[b"]
        );
        // A platform that selects by name keeps each item as typed.
        match parse(vec!["-u".into(), "alice,^bob".into()]) {
            Ok(Action::Run { selection, .. }) => {
                assert_eq!(selection.users, ["alice"]);
                assert_eq!(selection.user_excludes, ["bob"]);
                assert!(selection.uids.is_empty());
            }
            other => panic!("{other:?}"),
        }
    }

    /// An error the parse reads on after is printed where the C prints it,
    /// where it meets it: before a line the parse prints itself further on
    /// (measured: `+J -S 0` and `-Zx -S 0` say the error first, `-S 0 +J`
    /// the warning first), and the run still ends.
    #[test]
    fn read_on_errors_come_before_what_the_parse_prints_after_them() {
        let warn = "lsof: WARNING: -S time (0) changed to 2";
        let (got, said) = parse_saying(&["+J", "-S", "0"]);
        assert_eq!(said, ["lsof: +J is not supported", warn]);
        assert_eq!(got.unwrap_err(), "");
        let (got, said) = parse_saying(&["-S", "0", "+J"]);
        assert_eq!(said, [warn]);
        assert_eq!(got.unwrap_err(), "+J is not supported");
        let (got, said) = parse_saying(&["--", "x"]);
        assert!(said.is_empty() && got.is_ok());
        let (got, said) = parse_saying(&["+J", "-S", "0", "-h"]);
        assert_eq!(said, ["lsof: +J is not supported", warn]);
        assert!(got.is_err(), "no help: {got:?}");
    }

    /// DIVERGENCES 114: `--help` and `--version` are no long options to the
    /// C. A `-` in a word is `illegal option character: -`, and the word's
    /// other letters are read on: `-h`, then `-e lp` (measured, exit 1).
    #[test]
    fn double_dash_words_are_refused_as_the_c_refuses_them() {
        let dash = "illegal option character: -";
        let cases: &[(&[&str], &[&str])] = &[
            (
                &["--help"],
                &[dash, "-e not followed by a file system path: \"lp\""],
            ),
            (
                &["--version"],
                &[dash, "-e not followed by a file system path: \"rsion\""],
            ),
            (
                &["-h", "--help"],
                &[dash, "-e not followed by a file system path: \"lp\""],
            ),
            (&["--h"], &[dash]),
            (&["+-h"], &[dash]),
            (&["---"], &[dash, dash]),
            (&["--x"], &[dash, "-x must accompany +d or +D"]),
        ];
        for (argv, want) in cases {
            // What the parse printed on the way, then what main prints.
            let (got, said) = parse_saying(argv);
            let mut lines: Vec<String> = said
                .iter()
                .map(|l| l.strip_prefix("lsof: ").unwrap_or(l).to_string())
                .collect();
            lines.extend(error_lines(got).into_iter().filter(|l| !l.is_empty()));
            assert_eq!(lines, *want, "{argv:?}");
        }
        // `--` alone still ends the options.
        match parse(vec!["--".into(), "-h".into()]) {
            Ok(Action::Run { selection, .. }) => assert_eq!(selection.paths, ["-h"]),
            other => panic!("{other:?}"),
        }
    }

    /// DIVERGENCES 149: a letter that is no option is the C's `illegal option
    /// character: X`, without the prefix, and the parse reads on, through the
    /// rest of the word and the words after; `-D` and `-m`, which the C knows
    /// and lsof-rs does not implement, say so, take their value word as the
    /// C's `GetOpt` does, and read on too (all measured).
    #[test]
    fn an_illegal_option_character_is_read_past() {
        let ill = |c: &str| format!("illegal option character: {c}");
        let m = if cfg!(target_os = "freebsd") {
            "unsupported option: -m".to_string()
        } else {
            "-m not supported".to_string()
        };
        let cases: Vec<(&[&str], Vec<String>)> = vec![
            (&["-W"], vec![ill("W")]),
            (&["+W"], vec![ill("W")]),
            (&["-Wz"], vec![ill("W"), ill("z")]),
            (&["-W", "-W"], vec![ill("W"), ill("W")]),
            (
                &["-Wp"],
                vec![ill("W"), "option -p requires a value".into()],
            ),
            (&["-a-W"], vec![ill("-"), ill("W")]),
            (&["-+"], vec![ill("+")]),
            (&["+,"], vec![ill(",")]),
            (&["-1"], vec![ill("1")]),
            (&["-\u{1}"], vec![ill("^A")]),
            (
                &["-:"],
                vec!["colon is an illegal option character.".into()],
            ),
            (
                &["-W:"],
                vec![ill("W"), "colon is an illegal option character.".into()],
            ),
            (
                &["-o", "-s", "-W"],
                vec![ill("W"), "-o and -s are mutually exclusive".into()],
            ),
            (
                &["-W", "-o", "-s"],
                vec![ill("W"), "-o and -s are mutually exclusive".into()],
            ),
            (
                &["-W", "-x"],
                vec![ill("W"), "-x must accompany +d or +D".into()],
            ),
            (&["-W", "+J"], vec![ill("W"), "+J is not supported".into()]),
            // Ends in `usage()` before `-X -i` and `-a` are checked, and
            // before a path is looked at.
            (&["-W", "-X", "-i"], vec![ill("W")]),
            (&["-W", "-a"], vec![ill("W")]),
            (&["-W", "/nonexistent"], vec![ill("W")]),
            (&["-W", "--", "-p"], vec![ill("W")]),
            (&["-D"], vec!["unsupported option: -D".into()]),
            (
                &["-D", "-W", "-Y"],
                vec!["unsupported option: -D".into(), ill("Y")],
            ),
            (
                &["-Dfoo", "-W"],
                vec!["unsupported option: -D".into(), ill("W")],
            ),
            (&["-aD"], vec!["unsupported option: -D".into()]),
            (&["-Da"], vec!["unsupported option: -D".into()]),
            (&["-m"], vec![m.clone()]),
            (&["-m", "-W", "-Y"], vec![m.clone(), ill("Y")]),
            (&["-mfoo", "-W"], vec![m.clone(), ill("W")]),
            (&["-W", "-m"], vec![ill("W"), m.clone()]),
            // `--` is no value to `-D` or `-m`, as to `-Z`: it ends the
            // options, and `-W` after it is a name (measured).
            (&["-D", "--", "-W"], vec!["unsupported option: -D".into()]),
            (&["-m", "--", "-W"], vec![m.clone()]),
            (
                &["-W", "-D", "--", "-Y"],
                vec![ill("W"), "unsupported option: -D".into()],
            ),
            (&["-D", "--"], vec!["unsupported option: -D".into()]),
            // `+m` is refused and ends the parse, never read on through:
            // the C's mount supplement, which lsof-rs does not write.
            (&["+m"], vec!["unsupported option: +m".into()]),
            (&["+mfoo"], vec!["unsupported option: +m".into()]),
            (&["+m", "-h"], vec!["unsupported option: +m".into()]),
            (
                &["-W", "+m", "-Y"],
                vec![ill("W"), "unsupported option: +m".into()],
            ),
            // A backslash is escaped as row 122 escapes it, where the C
            // prints it raw; a NUL letter is shown and does not end the list.
            (
                &["-\\"],
                vec![ill(if cfg!(windows) { "\\" } else { "\\\\" })],
            ),
            (&["-\u{0}W"], vec![ill("^@"), ill("W")]),
        ];
        for (argv, want) in cases {
            assert_eq!(error_lines(parse_on_host(argv, false)), want, "{argv:?}");
        }
        // An unknown login and an illegal letter, in option order.
        assert_eq!(
            error_lines(parse_on_host(&["-u", "nosuch", "-W"], false)),
            ["can't get UID for nosuch".to_string(), ill("W")]
        );
        assert_eq!(
            error_lines(parse_on_host(&["-W", "-u", "nosuch"], false)),
            [ill("W"), "can't get UID for nosuch".to_string()]
        );
        // A refusal printed before what the parse prints after it.
        let (got, said) = parse_saying(&["-W", "-S", "0"]);
        assert_eq!(
            said,
            [
                "lsof: illegal option character: W",
                "lsof: WARNING: -S time (0) changed to 2"
            ]
        );
        assert_eq!(got.unwrap_err(), "");
        // `-k` names a kernel file on FreeBSD; elsewhere it is no option.
        let k = error_lines(parse_on_host(&["-k", "/x"], false));
        if cfg!(target_os = "freebsd") {
            assert_eq!(k, ["unsupported option: -k"]);
        } else {
            assert_eq!(k, [ill("k")]);
        }
        // Nor is `--` a value to FreeBSD's `-k`.
        let k = error_lines(parse_on_host(&["-k", "--", "-W"], false));
        if cfg!(target_os = "freebsd") {
            assert_eq!(k, ["unsupported option: -k"]);
        } else {
            assert_eq!(k, [ill("k")]);
        }
    }

    /// The read-on errors cost what the arguments that made them cost, not a
    /// line of text each (DIVERGENCES 149): 200 000 letters that are no
    /// option are 200 000 bytes of codes and no text, and come back as
    /// 200 000 lines, formatted one at a time. Every other kind of line,
    /// texts holding digits, colons and multibyte characters among them,
    /// comes back as it went in, in order.
    #[test]
    fn read_on_errors_are_kept_compactly() {
        let n = 200_000;
        let word = format!("-{}", "W".repeat(n));
        let mut early = Early::default();
        let mut reports = Reports::default();
        let got = parse_options(
            vec![word],
            &SafeFs::in_process(),
            &no_mounts,
            &HostChecks::DEFERRED,
            &mut early,
            &mut reports,
        );
        assert_eq!(got.unwrap_err(), "");
        assert_eq!(early.codes.len(), n);
        assert!(
            early.codes.capacity() <= 2 * n,
            "{}",
            early.codes.capacity()
        );
        assert!(early.texts.is_empty());
        let mut lines = 0usize;
        early.each_line(&mut |l: &str| {
            assert_eq!(l, "illegal option character: W");
            lines += 1;
        });
        assert_eq!(lines, n);

        let mut early = Early::default();
        early.illegal('\0');
        early.no_uid("12:ab");
        early.line("3:x é:");
        early.colon();
        early.plus_json('j');
        early.line("");
        early.illegal('é');
        early.plus_json('J');
        let mut got = Vec::new();
        early.each_line(&mut |l: &str| got.push(l.to_string()));
        assert_eq!(
            got,
            [
                "illegal option character: ^@",
                "can't get UID for 12:ab",
                "3:x é:",
                "colon is an illegal option character.",
                "+j is not supported",
                "",
                "illegal option character: é",
                "+J is not supported",
            ]
        );
        let err = ParseError {
            early,
            last: "end".into(),
        };
        assert_eq!(err.to_string(), got.join("\nlsof: ") + "\nlsof: end");
        let mut drained = Vec::new();
        let mut err = err;
        err.early.drain(|l| drained.push(l.to_string()));
        assert_eq!(drained, got);
        assert!(err.early.is_empty() && err.early.texts.is_empty());
        assert_eq!(err.to_string(), "end");
    }

    /// What `-h`, `-F ?` and `-v` ask for is kept with an error too, so `lsof`
    /// can print it after the error as the C's `usage()` does; without one,
    /// all three are one [`Action::Report`] (DIVERGENCES 150).
    #[test]
    fn help_field_help_and_version_are_reported_together() {
        let reported = |argv: &[&str]| {
            parse_reporting(
                argv.iter().map(|s| s.to_string()).collect(),
                &SafeFs::in_process(),
                &no_mounts,
                &HostChecks::DEFERRED,
            )
        };
        let all = Reports {
            help: true,
            field_help: true,
            version: true,
        };
        for argv in [
            &["-h", "-v", "-F", "?"][..],
            &["-F?", "-vh"],
            &["-v", "-?", "-F", "?"],
        ] {
            let (got, reports) = reported(argv);
            assert!(matches!(got, Ok(Action::Report(r)) if r == all), "{argv:?}");
            assert_eq!(reports, all, "{argv:?}");
        }
        let (got, reports) = reported(&["-v", "-h"]);
        let help_and_version = Reports {
            help: true,
            field_help: false,
            version: true,
        };
        assert!(matches!(got, Ok(Action::Report(r)) if r == help_and_version));
        assert_eq!(reports, help_and_version);
        // With an error, each is still recorded, and the parse is the error.
        let (got, reports) = reported(&["-W", "-F", "?", "-v"]);
        assert_eq!(got.unwrap_err().to_string(), "illegal option character: W");
        assert_eq!(
            reports,
            Reports {
                help: false,
                field_help: true,
                version: true,
            }
        );
        let (got, reports) = reported(&["-x", "-h"]);
        assert_eq!(got.unwrap_err().to_string(), "-x must accompany +d or +D");
        assert_eq!(reports, Reports::HELP);
        let (got, reports) = reported(&["-p", "1"]);
        assert!(matches!(got, Ok(Action::Run { .. })));
        assert!(!reports.any());
        assert!(Reports::HELP.any() && Reports::FIELD_HELP.any() && Reports::VERSION.any());
    }
}
