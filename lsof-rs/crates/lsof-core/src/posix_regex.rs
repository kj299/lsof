//! `-c /regex/[bix]`: a POSIX regular expression, as glibc's `regcomp(3)`
//! reads one, matched against a command name (DIVERGENCES 38).
//!
//! The C compiles the text between the slashes with `regcomp()` (extended
//! unless `b` asks for basic, `REG_ICASE` for `i`, `REG_NOSUB` always) and
//! asks `regexec()` whether a command matches (`lib/lsof.c`,
//! `lsof_select_process_regex()`; `lib/proc.c`, `is_cmd_excl()`). There is no
//! `regcomp()` in safe Rust, so [`translate`] reads the expression by glibc's
//! own grammar (`posix/regcomp.c`: `peek_token()`, `parse_reg_exp()`,
//! `parse_bracket_exp()` and the rest, under `RE_SYNTAX_POSIX_BASIC` and
//! `RE_SYNTAX_POSIX_EXTENDED`), refuses what it refuses with the `regerror()`
//! text it has for it, and writes what it accepts in the `regex` crate's
//! syntax, which [`CommandRegex`] compiles and runs over bytes.
//!
//! Only whether a command matches is asked, never where: POSIX's
//! leftmost-longest rule and the crate's leftmost-first rule pick different
//! matches but agree on whether there is one.
//!
//! What is read is the C's reading under a UTF-8 locale, the one lsof-rs
//! takes everywhere, and `C.UTF-8`'s where locales differ (a range's ends
//! are ASCII there, and there are no collating symbols but a character
//! itself). The engine is linear in the command and in the compiled
//! program, and the program is bounded ([`SIZE_LIMIT`], [`NEST_LIMIT`]).

use std::fmt::Write as _;

/// Why an expression was refused: glibc's `reg_errcode_t`, by the names
/// `regerror()` has for them, and what only lsof-rs refuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegexError {
    /// `REG_BADPAT`.
    BadPattern,
    /// `REG_ECOLLATE`.
    Collate,
    /// `REG_ECTYPE`.
    CharClass,
    /// `REG_EESCAPE`.
    Escape,
    /// `REG_ESUBREG`.
    SubReg,
    /// `REG_EBRACK`.
    Bracket,
    /// `REG_EPAREN` (and `REG_ERPAREN`, which `regcomp()` reports as it).
    Paren,
    /// `REG_EBRACE`.
    Brace,
    /// `REG_BADBR`.
    BadBrace,
    /// `REG_ERANGE`.
    Range,
    /// `REG_BADRPT`.
    BadRepeat,
    /// `REG_ESIZE`, and an expression past lsof-rs's own bounds.
    Size,
    /// A back-reference glibc accepts (`\(a\)\1`): the engine has none.
    BackReference,
}

impl RegexError {
    /// The text `regerror()` gives; lsof-rs's own words for a
    /// back-reference.
    pub fn text(self) -> &'static str {
        match self {
            Self::BadPattern => "Invalid regular expression",
            Self::Collate => "Invalid collation character",
            Self::CharClass => "Invalid character class name",
            Self::Escape => "Trailing backslash",
            Self::SubReg => "Invalid back reference",
            Self::Bracket => "Unmatched [, [^, [:, [., or [=",
            Self::Paren => "Unmatched ( or \\(",
            Self::Brace => "Unmatched \\{",
            Self::BadBrace => "Invalid content of \\{\\}",
            Self::Range => "Invalid range end",
            Self::BadRepeat => "Invalid preceding regular expression",
            Self::Size => "Regular expression too big",
            Self::BackReference => "back references are not supported",
        }
    }
}

/// What matches no character, in the engine's syntax.
const NOTHING: &str = r"[^\x{0}-\x{10FFFF}]";

/// glibc's `RE_DUP_MAX`: the largest count an interval takes.
const RE_DUP_MAX: i64 = 0x7fff;

/// glibc's `BRACKET_NAME_BUF_SIZE`: a `[:name:]`, `[.name.]` or `[=name=]`
/// of this many bytes is `REG_EBRACK`.
const BRACKET_NAME_MAX: usize = 32;

/// How deep the groups, alternations and repetitions written for the
/// engine may nest: past it the expression is `Regular expression too big`,
/// where glibc reads on. The engine counts a concatenation and a list's
/// own nesting as levels too, at most three of its for one of these
/// (`ENGINE_NEST_LIMIT`), and its compiler recurses once a level.
pub const NEST_LIMIT: u32 = 100;

/// The engine's own nesting limit, set above anything [`NEST_LIMIT`] lets
/// the translator write, so that an expression is refused for its depth by
/// the translator's count alone.
const ENGINE_NEST_LIMIT: u32 = NEST_LIMIT * 3 + 32;

/// The bound on a compiled program, in bytes; past it the expression is
/// `Regular expression too big`. glibc has no such bound: it expands
/// `(a{32767}){32767}` until memory runs out. Under it fit the largest
/// interval of one character (`a{32767}`, glibc's `RE_DUP_MAX`),
/// `.{20000}`, `[[:graph:]]{1,255}` and `[[:alpha:]]{300}`; `.{32767}` and
/// `\w{0,800}` do not.
///
/// It bounds two things. The engine stops compiling where the program
/// passes it, so compiling what [`COST_LIMIT`] let through takes bounded
/// time and memory. And a match is at worst every state of the program
/// looked at for every byte of the command, so the program's size is what
/// bounds a match: the worst there is costs milliseconds a command
/// ([`CommandRegex::is_match`]; THREAT-MODEL.md has the measurements).
pub const SIZE_LIMIT: usize = 1 << 23;

/// The bound on what an expression may ask of the engine before it
/// compiles anything, counted as the expression is read: one for each
/// character, anchor, repetition and list element, two for a `.` or a
/// non-matching list, `CLASS_COST` (1,024) for a
/// class of the locale's that is thousands of ranges of characters
/// (`[:alpha:]`, `\w`), `SMALL_CLASS_COST` (64) for one that is tens
/// (`[:space:]`, `\s`). Past it the expression is `Regular expression too
/// big`, in the time it takes to read it.
///
/// [`SIZE_LIMIT`] alone does not bound the engine: it bounds the compiled
/// program, and the engine first builds each class as a set of ranges,
/// folded for case under `i`, which for 60,000 `\W` took 20 s and 2.5 GB
/// before the program was found too big; and what the engine keeps of an
/// expression as it reads it is some hundreds of bytes a character. Under
/// this limit an expression holds at most 63 such classes, or 65,536
/// characters.
pub const COST_LIMIT: u64 = 1 << 16;

/// What a class of thousands of ranges costs ([`COST_LIMIT`]): `[:alpha:]`,
/// `[:alnum:]`, `[:upper:]`, `[:lower:]`, `[:punct:]`, `[:graph:]`,
/// `[:print:]`, `\w` and `\W`.
const CLASS_COST: u64 = 1 << 10;

/// What a class of tens of ranges costs: `[:space:]`, `[:blank:]`,
/// `[:cntrl:]`, `\s` and `\S`.
const SMALL_CLASS_COST: u64 = 1 << 6;

/// One unit of an expression or of a command, as glibc's `re_string` sees a
/// UTF-8 text: a character, or a byte that is part of none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Item {
    Char(char),
    Byte(u8),
}

impl Item {
    /// The ASCII byte this is, if it is one.
    fn ascii(self) -> Option<u8> {
        match self {
            Item::Char(c) if c.is_ascii() => u8::try_from(c).ok(),
            _ => None,
        }
    }

    /// How many bytes it took.
    fn len(self) -> usize {
        match self {
            Item::Char(c) => c.len_utf8(),
            Item::Byte(_) => 1,
        }
    }
}

fn items(text: &[u8]) -> Vec<Item> {
    let mut out = Vec::with_capacity(text.len());
    for chunk in text.utf8_chunks() {
        out.extend(chunk.valid().chars().map(Item::Char));
        out.extend(chunk.invalid().iter().copied().map(Item::Byte));
    }
    out
}

/// `peek_token()`'s token types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    End,
    Char,
    /// A `\` that ends the expression.
    BackSlash,
    Alt,
    Star,
    Plus,
    Question,
    OpenDup,
    CloseDup,
    OpenSub,
    CloseSub,
    OpenBracket,
    Period,
    /// A character that matches nothing.
    Never,
    Anchor(&'static str, bool),
    BackRef(u8),
    Word,
    NotWord,
    Space,
    NotSpace,
}

#[derive(Clone, Copy, Debug)]
struct Token {
    kind: Kind,
    /// `opr.c`: the character the token is when it is read as one.
    lit: Item,
}

/// `peek_token_bracket()`'s token types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BrKind {
    End,
    Char,
    OpenColl,
    OpenEquiv,
    OpenClass,
    Range,
    Close,
    NonMatch,
}

#[derive(Clone, Copy, Debug)]
struct BrToken {
    kind: BrKind,
    c: Item,
}

/// `bracket_elem_t`.
enum Elem {
    /// A single byte: an ASCII character, or a byte that is no character.
    Sb(Item),
    /// A character past ASCII.
    Mb(char),
    Coll(Vec<Item>),
    Equiv(Vec<Item>),
    Class(Vec<Item>),
}

/// A parsed piece, written in the engine's syntax.
struct Frag {
    s: String,
    /// Whether a repetition operator may follow it as it stands.
    atomic: bool,
    /// How deep it nests.
    depth: u32,
}

/// An expression in the engine's syntax, and how it is to be searched.
#[derive(Debug, PartialEq, Eq)]
pub struct Translated {
    /// The `regex` crate's syntax for it.
    pub pattern: String,
    /// glibc searches by characters, so a match starts at a character's
    /// first byte: `REG_ICASE`, a bracket expression that is more than a
    /// list of ASCII characters, or a word operator. Otherwise it searches
    /// by bytes (its `optimize_utf8()`), and a byte of the expression that
    /// is no character matches that byte wherever it is.
    pub by_chars: bool,
}

struct Parser {
    items: Vec<Item>,
    pos: usize,
    extended: bool,
    icase: bool,
    token: Token,
    nsub: usize,
    completed: u16,
    by_chars: bool,
    back_reference: bool,
    /// What the expression asks of the engine so far ([`COST_LIMIT`]).
    cost: u64,
}

/// Read `expression` as `regcomp()` does, extended or basic, and write it
/// for the `regex` crate (bytes, Unicode on).
pub fn translate(expression: &[u8], extended: bool, icase: bool) -> Result<Translated, RegexError> {
    let mut p = Parser {
        items: items(expression),
        pos: 0,
        extended,
        icase,
        token: Token {
            kind: Kind::End,
            lit: Item::Byte(0),
        },
        nsub: 0,
        completed: 0,
        by_chars: icase,
        back_reference: false,
        cost: 0,
    };
    p.fetch(true);
    let tree = p.parse_reg_exp(0)?;
    if p.back_reference {
        return Err(RegexError::BackReference);
    }
    // After every refusal of glibc's own, which reading on may yet find.
    if p.cost > COST_LIMIT {
        return Err(RegexError::Size);
    }
    // `.` and a non-matching list take a newline (`RE_DOT_NEWLINE`, no
    // `RE_HAT_LISTS_NOT_NEWLINE`), and `^` and `$` are the text's ends (no
    // `REG_NEWLINE`).
    let mut pattern = String::from(if icase { "(?si)" } else { "(?s)" });
    if let Some(tree) = tree {
        pattern.push_str(&tree.s);
    }
    Ok(Translated {
        pattern,
        by_chars: p.by_chars,
    })
}

fn push_char(s: &mut String, c: char) {
    let _ = write!(s, "\\x{{{:X}}}", u32::from(c));
}

/// One literal character, or a byte that is none.
fn literal(item: Item) -> Frag {
    let mut s = String::new();
    match item {
        Item::Char(c) => push_char(&mut s, c),
        Item::Byte(b) => {
            let _ = write!(s, "(?-u:\\x{b:02X})");
        }
    }
    Frag {
        s,
        atomic: true,
        depth: 1,
    }
}

fn atom(s: &str) -> Frag {
    Frag {
        s: s.to_string(),
        atomic: true,
        depth: 1,
    }
}

/// glibc's character classes under a UTF-8 locale, in the engine's Unicode
/// properties: its tables are built from the same Unicode data, by these
/// rules (`localedata/unicode-gen/gen_unicode_ctype.py`), though not from
/// the same Unicode version.
const ALNUM: &str = r"\p{Alphabetic}\p{Nd}";
const GRAPH: &str = r"[^\p{Cn}\p{Cc}\p{Zl}\p{Zp}\p{Zs}]\x{A0}\x{2007}\x{202F}";
const SPACE: &str = r"\t\n\x0B\x0C\r\x20\p{Zl}\p{Zp}[\p{Zs}--[\x{A0}\x{2007}\x{202F}]]";

/// What a class costs the engine ([`COST_LIMIT`]).
fn class_cost(name: &[u8]) -> u64 {
    match name {
        b"digit" | b"xdigit" => 1,
        b"space" | b"blank" | b"cntrl" => SMALL_CLASS_COST,
        _ => CLASS_COST,
    }
}

fn class_set(name: &[u8], icase: bool) -> Option<String> {
    // `build_charclass()`: under `REG_ICASE` a case is every letter.
    let name = match name {
        b"upper" | b"lower" if icase => b"alpha",
        other => other,
    };
    Some(match name {
        b"alpha" => r"\p{Alphabetic}[\p{Nd}--[0-9]]".to_string(),
        b"alnum" => ALNUM.to_string(),
        b"upper" => r"\p{Uppercase}\p{Lt}".to_string(),
        // The four titlecase digraphs are both cases to glibc.
        b"lower" => r"\p{Lowercase}\x{1C5}\x{1C8}\x{1CB}\x{1F2}".to_string(),
        b"digit" => "0-9".to_string(),
        b"xdigit" => "0-9A-Fa-f".to_string(),
        b"space" => SPACE.to_string(),
        b"blank" => r"\t[\p{Zs}--[\x{A0}\x{2007}\x{202F}]]".to_string(),
        b"cntrl" => r"\p{Cc}\p{Zl}\p{Zp}".to_string(),
        b"print" => r"[^\p{Cn}\p{Cc}\p{Zl}\p{Zp}]".to_string(),
        b"graph" => GRAPH.to_string(),
        b"punct" => format!("[[{GRAPH}]--[{ALNUM}]]"),
        _ => return None,
    })
}

impl Parser {
    fn at(&self, i: usize) -> Option<Item> {
        self.items.get(i).copied()
    }

    /// `peek_token()`: the token at `pos` and how many items it takes.
    /// `caret_here` is `RE_CARET_ANCHORS_HERE`.
    fn peek(&self, pos: usize, caret_here: bool) -> (Token, usize) {
        let Some(item) = self.at(pos) else {
            return (
                Token {
                    kind: Kind::End,
                    lit: Item::Byte(0),
                },
                0,
            );
        };
        let x = self.extended;
        let tok = |kind, lit| Token { kind, lit };
        if item.ascii() == Some(b'\\') {
            let Some(next) = self.at(pos.saturating_add(1)) else {
                return (tok(Kind::BackSlash, item), 1);
            };
            let kind = match next.ascii() {
                Some(b'|') if !x => Kind::Alt,
                Some(d @ b'1'..=b'9') => Kind::BackRef(d - b'1'),
                Some(b'<') => Kind::Anchor(r"\b{start}", true),
                Some(b'>') => Kind::Anchor(r"\b{end}", true),
                Some(b'b') => Kind::Anchor(r"\b", true),
                Some(b'B') => Kind::Anchor(r"\B", true),
                Some(b'w') => Kind::Word,
                Some(b'W') => Kind::NotWord,
                Some(b's') => Kind::Space,
                Some(b'S') => Kind::NotSpace,
                Some(b'`') => Kind::Anchor(r"\A", false),
                Some(b'\'') => Kind::Anchor(r"\z", false),
                Some(b'(') if !x => Kind::OpenSub,
                Some(b')') if !x => Kind::CloseSub,
                Some(b'+') if !x => Kind::Plus,
                Some(b'?') if !x => Kind::Question,
                Some(b'{') if !x => Kind::OpenDup,
                Some(b'}') if !x => Kind::CloseDup,
                // glibc compares the letter as typed with a command it has
                // put in upper case, so under `REG_ICASE` an escaped small
                // letter matches nothing (`\z` neither `z` nor `Z`).
                Some(b'a'..=b'z') if self.icase => Kind::Never,
                _ => Kind::Char,
            };
            return (tok(kind, next), 2);
        }
        let kind = match item.ascii() {
            Some(b'|') if x => Kind::Alt,
            Some(b'*') => Kind::Star,
            Some(b'+') if x => Kind::Plus,
            Some(b'?') if x => Kind::Question,
            Some(b'{') if x => Kind::OpenDup,
            Some(b'}') if x => Kind::CloseDup,
            Some(b'(') if x => Kind::OpenSub,
            Some(b')') if x => Kind::CloseSub,
            Some(b'[') => Kind::OpenBracket,
            Some(b'.') => Kind::Period,
            // Basic: an anchor only where the expression, a group or an
            // alternative opens.
            Some(b'^') if x || caret_here || pos == 0 => Kind::Anchor(r"\A", false),
            Some(b'$') => {
                // Basic: an anchor only where one of those ends, which is
                // where the next token is `\|` or `\)`. glibc finds that
                // out by reading the next token with this function, which
                // for a run of `$` calls itself once for each (its
                // `peek_token()`: 70,000 of them end the C with SIGSEGV).
                // The answer only depends on the next two items, so they
                // are looked at here and nothing is called (DIVERGENCES
                // 38).
                let next = |n: usize| self.at(pos.saturating_add(n)).and_then(Item::ascii);
                let ends = x
                    || pos.saturating_add(1) == self.items.len()
                    || (next(1) == Some(b'\\') && matches!(next(2), Some(b'|' | b')')));
                if ends {
                    Kind::Anchor(r"\z", false)
                } else {
                    Kind::Char
                }
            }
            _ => Kind::Char,
        };
        (tok(kind, item), 1)
    }

    /// `fetch_token()`.
    fn fetch(&mut self, caret_here: bool) {
        let (token, len) = self.peek(self.pos, caret_here);
        self.token = token;
        self.pos = self.pos.saturating_add(len);
    }

    /// Whether the token ends a branch at this nesting.
    fn ends_branch(&self, nest: u32) -> bool {
        matches!(self.token.kind, Kind::Alt | Kind::End)
            || (nest > 0 && self.token.kind == Kind::CloseSub)
    }

    /// `parse_reg_exp()`: branches between `|`s. `None` is glibc's null
    /// tree, the empty expression.
    fn parse_reg_exp(&mut self, nest: u32) -> Result<Option<Frag>, RegexError> {
        // A back-reference in an alternative can name only a group closed
        // before the alternation or earlier in that alternative: glibc
        // gives each alternative the groups there were when the first
        // began (`(a)|\1` is `Invalid back reference`, `(a)|(b)\2` is
        // not), and what follows the alternation the groups of them all.
        let initial = self.completed;
        let first = self.parse_branch(nest)?;
        if self.token.kind != Kind::Alt {
            return Ok(first);
        }
        let mut depth = first.as_ref().map_or(0, |f| f.depth);
        let mut s = String::from("(?:");
        s.push_str(first.as_ref().map_or("", |f| &f.s));
        while self.token.kind == Kind::Alt {
            self.fetch(true);
            s.push('|');
            if !self.ends_branch(nest) {
                let accumulated = self.completed;
                self.completed = initial;
                let branch = self.parse_branch(nest)?;
                self.completed |= accumulated;
                if let Some(branch) = branch {
                    depth = depth.max(branch.depth);
                    s.push_str(&branch.s);
                }
            }
        }
        s.push(')');
        nested(s, depth)
    }

    /// `parse_branch()`: expressions side by side.
    fn parse_branch(&mut self, nest: u32) -> Result<Option<Frag>, RegexError> {
        let mut tree = self.parse_expression(nest)?;
        while !self.ends_branch(nest) {
            let expr = self.parse_expression(nest)?;
            tree = match (tree, expr) {
                (Some(mut a), Some(b)) => {
                    a.s.push_str(&b.s);
                    a.atomic = false;
                    a.depth = a.depth.max(b.depth);
                    Some(a)
                }
                (None, e) => e,
                (t, None) => t,
            };
        }
        Ok(tree)
    }

    /// Count `units` against [`COST_LIMIT`].
    fn charge(&mut self, units: u64) {
        self.cost = self.cost.saturating_add(units);
    }

    /// `parse_expression()`: one atom and the repetitions after it.
    fn parse_expression(&mut self, nest: u32) -> Result<Option<Frag>, RegexError> {
        let x = self.extended;
        let lit = self.token.lit;
        self.charge(1);
        let mut tree = match self.token.kind {
            Kind::Char | Kind::CloseDup => Some(literal(lit)),
            Kind::OpenSub => Some(self.parse_sub_exp(nest.saturating_add(1))?),
            Kind::OpenBracket => Some(self.parse_bracket_exp()?),
            Kind::BackRef(n) => {
                if self.completed & (1u16 << n) == 0 {
                    return Err(RegexError::SubReg);
                }
                // glibc reads on, and may yet refuse the expression in its
                // own words; if it does not, lsof-rs refuses it in its own.
                self.back_reference = true;
                Some(atom("(?:)"))
            }
            // Basic: an interval with nothing before it
            // (`RE_CONTEXT_INVALID_DUP`).
            Kind::OpenDup if !x => return Err(RegexError::BadRepeat),
            // Extended: so is any repetition (`RE_CONTEXT_INVALID_OPS`);
            // basic reads the operator as itself.
            Kind::OpenDup | Kind::Star | Kind::Plus | Kind::Question => {
                if x {
                    return Err(RegexError::BadRepeat);
                }
                Some(literal(lit))
            }
            // Extended: a `)` that closes nothing is itself
            // (`RE_UNMATCHED_RIGHT_PAREN_ORD`).
            Kind::CloseSub => {
                if !x {
                    return Err(RegexError::Paren);
                }
                Some(literal(lit))
            }
            Kind::Anchor(text, word) => {
                self.by_chars |= word;
                // No repetition applies to an anchor: what follows opens an
                // expression of its own (and in a basic expression a `^`
                // there is a character: `^^a` matches `^a`).
                self.fetch(false);
                return Ok(Some(atom(text)));
            }
            Kind::Period => {
                // Every character: more of a program than one is.
                self.charge(1);
                Some(atom("."))
            }
            Kind::Never => Some(atom(NOTHING)),
            Kind::Word | Kind::NotWord | Kind::Space | Kind::NotSpace => {
                self.by_chars = true;
                let set = match self.token.kind {
                    Kind::Word | Kind::NotWord => {
                        self.charge(CLASS_COST);
                        format!("{ALNUM}_")
                    }
                    _ => {
                        self.charge(SMALL_CLASS_COST);
                        SPACE.to_string()
                    }
                };
                let not = matches!(self.token.kind, Kind::NotWord | Kind::NotSpace);
                Some(atom(&format!("[{}{set}]", if not { "^" } else { "" })))
            }
            Kind::Alt | Kind::End => return Ok(None),
            Kind::BackSlash => return Err(RegexError::Escape),
        };
        self.fetch(false);
        while matches!(
            self.token.kind,
            Kind::Star | Kind::Plus | Kind::Question | Kind::OpenDup
        ) {
            tree = self.parse_dup_op(tree)?;
            // Basic: no repetition of a repetition.
            if !x && matches!(self.token.kind, Kind::Star | Kind::OpenDup) {
                return Err(RegexError::BadRepeat);
            }
        }
        Ok(tree)
    }

    /// `parse_sub_exp()`: a group, its opening token read.
    fn parse_sub_exp(&mut self, nest: u32) -> Result<Frag, RegexError> {
        if nest > NEST_LIMIT {
            return Err(RegexError::Size);
        }
        let this = self.nsub;
        self.nsub = self.nsub.saturating_add(1);
        self.fetch(true);
        let tree = if self.token.kind == Kind::CloseSub {
            None
        } else {
            let tree = self.parse_reg_exp(nest)?;
            if self.token.kind != Kind::CloseSub {
                return Err(RegexError::Paren);
            }
            tree
        };
        if this < 9 {
            self.completed |= 1u16 << this;
        }
        let depth = tree.as_ref().map_or(0, |f| f.depth);
        let s = format!("(?:{})", tree.as_ref().map_or("", |f| &f.s));
        nested(s, depth).map(|f| f.unwrap_or_else(|| atom("(?:)")))
    }

    /// Whether the token is a `,` read as a character.
    fn is_comma(&self) -> bool {
        self.token.kind == Kind::Char && self.token.lit.ascii() == Some(b',')
    }

    /// `fetch_number()`: -1 for no digit, -2 for anything else.
    fn fetch_number(&mut self) -> i64 {
        let mut num = -1i64;
        loop {
            self.fetch(false);
            let c = self.token.lit.ascii();
            if self.token.kind == Kind::End {
                return -2;
            }
            if self.token.kind == Kind::CloseDup || c == Some(b',') {
                return num;
            }
            num = match c {
                Some(d @ b'0'..=b'9') if self.token.kind == Kind::Char && num != -2 => {
                    let d = i64::from(d - b'0');
                    if num == -1 {
                        d
                    } else {
                        num.saturating_mul(10)
                            .saturating_add(d)
                            .min(RE_DUP_MAX.saturating_add(1))
                    }
                }
                _ => -2,
            };
        }
    }

    /// `parse_dup_op()`: `*`, `+`, `?` or an interval, applied to `elem`.
    fn parse_dup_op(&mut self, elem: Option<Frag>) -> Result<Option<Frag>, RegexError> {
        let (start, end) = if self.token.kind == Kind::OpenDup {
            let mut end = 0;
            let mut start = self.fetch_number();
            if start == -1 {
                if self.is_comma() {
                    // `{,m}` is `{0,m}`.
                    start = 0;
                } else {
                    return Err(RegexError::BadBrace);
                }
            }
            if start != -2 {
                end = if self.token.kind == Kind::CloseDup {
                    start
                } else if self.is_comma() {
                    self.fetch_number()
                } else {
                    -2
                };
            }
            if start == -2 || end == -2 {
                return Err(if self.token.kind == Kind::End {
                    RegexError::Brace
                } else {
                    RegexError::BadBrace
                });
            }
            if (end != -1 && start > end) || self.token.kind != Kind::CloseDup {
                return Err(RegexError::BadBrace);
            }
            if (if end == -1 { start } else { end }) > RE_DUP_MAX {
                return Err(RegexError::Size);
            }
            (start, end)
        } else {
            (
                i64::from(self.token.kind == Kind::Plus),
                if self.token.kind == Kind::Question {
                    1
                } else {
                    -1
                },
            )
        };
        self.fetch(false);
        self.charge(1);
        let Some(elem) = elem else {
            return Ok(None);
        };
        if start == 0 && end == 0 {
            return Ok(None);
        }
        let mut s = if elem.atomic {
            elem.s
        } else {
            format!("(?:{})", elem.s)
        };
        match (start, end) {
            (0, -1) => s.push('*'),
            (1, -1) => s.push('+'),
            (0, 1) => s.push('?'),
            (n, -1) => {
                let _ = write!(s, "{{{n},}}");
            }
            (n, m) if n == m => {
                let _ = write!(s, "{{{n}}}");
            }
            (n, m) => {
                let _ = write!(s, "{{{n},{m}}}");
            }
        }
        nested(s, elem.depth).map(|f| {
            f.map(|mut f| {
                f.atomic = false;
                f
            })
        })
    }

    /// `peek_token_bracket()`.
    fn peek_bracket(&self) -> (BrToken, usize) {
        let Some(item) = self.at(self.pos) else {
            return (
                BrToken {
                    kind: BrKind::End,
                    c: Item::Byte(0),
                },
                0,
            );
        };
        // Under `REG_ICASE` glibc parses the expression in upper case.
        let item = match item {
            Item::Char(c) if self.icase => Item::Char(c.to_ascii_uppercase()),
            other => other,
        };
        let tok = |kind, c| BrToken { kind, c };
        if item.ascii() == Some(b'[') {
            let next = self.at(self.pos.saturating_add(1));
            let kind = match next.and_then(Item::ascii) {
                Some(b'.') => BrKind::OpenColl,
                Some(b'=') => BrKind::OpenEquiv,
                Some(b':') => BrKind::OpenClass,
                _ => return (tok(BrKind::Char, item), 1),
            };
            return (tok(kind, next.unwrap_or(item)), 2);
        }
        let kind = match item.ascii() {
            Some(b'-') => BrKind::Range,
            Some(b']') => BrKind::Close,
            Some(b'^') => BrKind::NonMatch,
            _ => BrKind::Char,
        };
        (tok(kind, item), 1)
    }

    /// `parse_bracket_exp()`: a bracket expression, its `[` read.
    fn parse_bracket_exp(&mut self) -> Result<Frag, RegexError> {
        let mut set = String::new();
        let mut complex = false;
        let (mut token, mut len) = self.peek_bracket();
        if token.kind == BrKind::End {
            return Err(RegexError::BadPattern);
        }
        let non_match = token.kind == BrKind::NonMatch;
        if non_match {
            self.charge(1);
            complex = true;
            self.pos = self.pos.saturating_add(len);
            (token, len) = self.peek_bracket();
            if token.kind == BrKind::End {
                return Err(RegexError::BadPattern);
            }
        }
        // A `]` that opens the list is a character, as is whatever opens it:
        // `parse_bracket_element()` reads the first token as one.
        let mut first_round = true;
        loop {
            self.charge(1);
            let start = self.parse_bracket_element(token, len, first_round)?;
            first_round = false;
            (token, len) = self.peek_bracket();
            let mut end = None;
            if !matches!(start, Elem::Class(_) | Elem::Equiv(_)) {
                if token.kind == BrKind::End {
                    return Err(RegexError::Bracket);
                }
                if token.kind == BrKind::Range {
                    self.pos = self.pos.saturating_add(len);
                    let (token2, len2) = self.peek_bracket();
                    if token2.kind == BrKind::End {
                        return Err(RegexError::Bracket);
                    }
                    if token2.kind == BrKind::Close {
                        // A `-` that ends the list is a character.
                        self.pos = self.pos.saturating_sub(len);
                        token.kind = BrKind::Char;
                    } else {
                        end = Some(self.parse_bracket_element(token2, len2, true)?);
                        (token, len) = self.peek_bracket();
                    }
                }
            }
            complex |= matches!(start, Elem::Equiv(_));
            match (start, end) {
                (start, Some(end)) => {
                    complex = true;
                    self.range(&mut set, &start, &end)?;
                }
                (Elem::Sb(item), None) => {
                    // A byte that is no character is in no list.
                    if let Some(b) = item.ascii() {
                        push_char(&mut set, char::from(b));
                    }
                }
                (Elem::Mb(c), None) => {
                    complex = true;
                    push_char(&mut set, c);
                }
                (Elem::Equiv(name) | Elem::Coll(name), None) => {
                    // `C.UTF-8` has no equivalence classes and no collating
                    // symbols: a single byte names itself, and nothing else
                    // is a name.
                    match single_byte(&name).ok_or(RegexError::Collate)? {
                        Item::Char(c) => push_char(&mut set, c),
                        Item::Byte(_) => {}
                    }
                }
                (Elem::Class(name), None) => {
                    complex = true;
                    let name: Vec<u8> = name.iter().filter_map(|i| i.ascii()).collect();
                    let class = class_set(&name, self.icase).ok_or(RegexError::CharClass)?;
                    self.charge(class_cost(&name));
                    let _ = write!(set, "[{class}]");
                }
            }
            if token.kind == BrKind::End {
                return Err(RegexError::Bracket);
            }
            if token.kind == BrKind::Close {
                break;
            }
        }
        self.pos = self.pos.saturating_add(len);
        self.by_chars |= complex;
        let s = match (non_match, set.is_empty()) {
            (false, false) => format!("[{set}]"),
            (true, false) => format!("[^{set}]"),
            // A list of nothing but bytes that are no characters.
            (false, true) => NOTHING.to_string(),
            (true, true) => r"[\x{0}-\x{10FFFF}]".to_string(),
        };
        Ok(atom(&s))
    }

    /// `parse_bracket_element()`.
    fn parse_bracket_element(
        &mut self,
        token: BrToken,
        len: usize,
        accept_hyphen: bool,
    ) -> Result<Elem, RegexError> {
        if let Some(Item::Char(c)) = self.at(self.pos) {
            if !c.is_ascii() {
                self.pos = self.pos.saturating_add(1);
                return Ok(Elem::Mb(c));
            }
        }
        self.pos = self.pos.saturating_add(len);
        match token.kind {
            BrKind::OpenColl | BrKind::OpenEquiv | BrKind::OpenClass => {
                return self.parse_bracket_symbol(token);
            }
            // A `-` is a character only before the `]`.
            BrKind::Range if !accept_hyphen && self.peek_bracket().0.kind != BrKind::Close => {
                return Err(RegexError::Range);
            }
            _ => {}
        }
        Ok(Elem::Sb(token.c))
    }

    /// `parse_bracket_symbol()`: the name in `[:name:]`, `[.name.]` or
    /// `[=name=]`, its opening read.
    fn parse_bracket_symbol(&mut self, token: BrToken) -> Result<Elem, RegexError> {
        let delim = token.c.ascii();
        let mut name = Vec::new();
        let mut bytes = 0usize;
        if self.pos >= self.items.len() {
            return Err(RegexError::Bracket);
        }
        loop {
            let Some(item) = self.at(self.pos) else {
                return Err(RegexError::Bracket);
            };
            // glibc counts bytes, and checks before each.
            if bytes.saturating_add(item.len()) > BRACKET_NAME_MAX {
                return Err(RegexError::Bracket);
            }
            self.pos = self.pos.saturating_add(1);
            let Some(next) = self.at(self.pos) else {
                return Err(RegexError::Bracket);
            };
            if item.ascii() == delim && next.ascii() == Some(b']') {
                break;
            }
            bytes = bytes.saturating_add(item.len());
            // A class is named in the case it was typed; the rest, under
            // `REG_ICASE`, in upper case.
            name.push(match item {
                Item::Char(c) if self.icase && token.kind != BrKind::OpenClass => {
                    Item::Char(c.to_ascii_uppercase())
                }
                other => other,
            });
        }
        self.pos = self.pos.saturating_add(1);
        Ok(match token.kind {
            BrKind::OpenColl => Elem::Coll(name),
            BrKind::OpenEquiv => Elem::Equiv(name),
            _ => Elem::Class(name),
        })
    }

    /// `build_range_exp()`, by `C.UTF-8`'s collation: a single byte has its
    /// value for its place, a byte that is no character too, and a character
    /// past ASCII has none (measured: `[a-\xa9]` is U+0061 to U+00A9, and
    /// `[a-é]` is `Invalid collation character`).
    fn range(&self, set: &mut String, start: &Elem, end: &Elem) -> Result<(), RegexError> {
        let is_class = |e: &Elem| matches!(e, Elem::Class(_) | Elem::Equiv(_));
        if is_class(start) || is_class(end) {
            return Err(RegexError::Range);
        }
        let seq = |e: &Elem| {
            let item = match e {
                Elem::Sb(item) => Some(*item),
                Elem::Coll(name) => single_byte(name),
                _ => None,
            };
            item.map(|item| match item {
                Item::Char(c) => c,
                Item::Byte(b) => char::from(b),
            })
        };
        let (Some(lo), Some(hi)) = (seq(start), seq(end)) else {
            return Err(RegexError::Collate);
        };
        if lo > hi {
            return Err(RegexError::Range);
        }
        push_char(set, lo);
        set.push('-');
        push_char(set, hi);
        Ok(())
    }
}

/// The one byte a name is, if it is one: an ASCII character, or a byte that
/// is no character.
fn single_byte(name: &[Item]) -> Option<Item> {
    match name {
        [item @ Item::Byte(_)] => Some(*item),
        [item @ Item::Char(c)] if c.is_ascii() => Some(*item),
        _ => None,
    }
}
/// A piece that wraps pieces `depth` deep, or too deep to write.
fn nested(s: String, depth: u32) -> Result<Option<Frag>, RegexError> {
    let depth = depth.saturating_add(1);
    if depth > NEST_LIMIT {
        return Err(RegexError::Size);
    }
    Ok(Some(Frag {
        s,
        atomic: true,
        depth,
    }))
}

/// How many commands' answers a [`CommandRegex`] keeps, and the longest
/// command it keeps one for.
const KEPT_ANSWERS: usize = 1024;
const KEPT_COMMAND: usize = 256;

/// One `-c /regex/[bix]` expression, compiled.
#[derive(Clone, Debug)]
pub struct CommandRegex {
    expression: Vec<u8>,
    extended: bool,
    icase: bool,
    regex: regex::bytes::Regex,
    by_chars: bool,
    /// What it answered for the commands asked so far: a command is
    /// asked about once for each time it is selected or located, and many
    /// processes share one, while the worst expression inside
    /// [`SIZE_LIMIT`] takes milliseconds to answer once. Bounded
    /// ([`KEPT_ANSWERS`]), and shared with its copies.
    answers: std::sync::Arc<std::sync::Mutex<Answers>>,
}

type Answers = std::collections::HashMap<Box<[u8]>, bool>;

/// Two are the same when they were made from the same expression.
impl PartialEq for CommandRegex {
    fn eq(&self, other: &Self) -> bool {
        (&self.expression, self.extended, self.icase)
            == (&other.expression, other.extended, other.icase)
    }
}

impl Eq for CommandRegex {}

impl CommandRegex {
    /// Compile `expression`, the text between the slashes, as `regcomp()`
    /// would: extended or basic, and with `REG_ICASE` or without.
    pub fn new(expression: &[u8], extended: bool, icase: bool) -> Result<Self, RegexError> {
        let translated = translate(expression, extended, icase)?;
        let regex = regex::bytes::RegexBuilder::new(&translated.pattern)
            .size_limit(SIZE_LIMIT)
            .nest_limit(ENGINE_NEST_LIMIT)
            .build()
            .map_err(|e| {
                // The translator writes only what the engine reads, so the
                // one thing it can refuse is a program past the limit; the
                // fuzz target holds it to that.
                debug_assert!(matches!(e, regex::Error::CompiledTooBig(_)), "{e}");
                RegexError::Size
            })?;
        Ok(Self {
            expression: expression.to_vec(),
            extended,
            icase,
            regex,
            by_chars: translated.by_chars,
            answers: std::sync::Arc::default(),
        })
    }

    /// The expression as given, for `-V`.
    pub fn expression(&self) -> &[u8] {
        &self.expression
    }

    /// Whether `command` matches, as `regexec()` would say. The engine's
    /// answer, kept for the next time the command is asked about.
    pub fn is_match(&self, command: &[u8]) -> bool {
        if command.len() > KEPT_COMMAND {
            return self.search(command);
        }
        let mut answers = self
            .answers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(&answer) = answers.get(command) {
            return answer;
        }
        let answer = self.search(command);
        if answers.len() >= KEPT_ANSWERS {
            answers.clear();
        }
        answers.insert(command.into(), answer);
        answer
    }

    /// How many answers are kept.
    #[cfg(test)]
    fn kept(&self) -> usize {
        self.answers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// [`Self::is_match`], asked of the engine: time linear in the
    /// command and in the program.
    fn search(&self, command: &[u8]) -> bool {
        if !self.by_chars {
            return self.regex.is_match(command);
        }
        // glibc starts a match only at a character's first byte, or at a
        // byte that is part of none.
        let mut boundary = vec![false; command.len().saturating_add(1)];
        let mut at = 0usize;
        for item in items(command) {
            if let Some(b) = boundary.get_mut(at) {
                *b = true;
            }
            at = at.saturating_add(item.len());
        }
        if let Some(b) = boundary.get_mut(command.len()) {
            *b = true;
        }
        let mut from = 0usize;
        while from <= command.len() {
            let Some(found) = self.regex.find_at(command, from) else {
                return false;
            };
            if boundary.get(found.start()).copied().unwrap_or(false) {
                return true;
            }
            // The leftmost match from here starts inside a character: any
            // other starts after it.
            from = found.start().saturating_add(1);
            while from < command.len() && !boundary.get(from).copied().unwrap_or(true) {
                from = from.saturating_add(1);
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(expression: &str, extended: bool, icase: bool) -> Result<String, RegexError> {
        translate(expression.as_bytes(), extended, icase).map(|t| t.pattern)
    }

    /// What is written for the engine, construct by construct: a literal by
    /// its code point, so that nothing typed is ever the engine's syntax.
    #[test]
    fn an_expression_is_written_in_the_engines_syntax() {
        for (expression, extended, want) in [
            ("a", true, r"(?s)\x{61}"),
            ("a.c", true, r"(?s)\x{61}.\x{63}"),
            ("a\\.c", true, r"(?s)\x{61}\x{2E}\x{63}"),
            ("^a$", true, r"(?s)\A\x{61}\z"),
            ("a|b", true, r"(?s)(?:\x{61}|\x{62})"),
            ("a\\|b", false, r"(?s)(?:\x{61}|\x{62})"),
            ("a|b", false, r"(?s)\x{61}\x{7C}\x{62}"),
            ("(a)", true, r"(?s)(?:\x{61})"),
            ("\\(a\\)", false, r"(?s)(?:\x{61})"),
            ("(a)", false, r"(?s)\x{28}\x{61}\x{29}"),
            ("ab*", true, r"(?s)\x{61}\x{62}*"),
            ("(ab)+", true, r"(?s)(?:\x{61}\x{62})+"),
            ("a+", false, r"(?s)\x{61}\x{2B}"),
            ("a\\+", false, r"(?s)\x{61}+"),
            ("a\\?", false, r"(?s)\x{61}?"),
            ("a**", true, r"(?s)(?:\x{61}*)*"),
            ("a{2}", true, r"(?s)\x{61}{2}"),
            ("a{2,}", true, r"(?s)\x{61}{2,}"),
            ("a{2,3}", true, r"(?s)\x{61}{2,3}"),
            ("a{,3}", true, r"(?s)\x{61}{0,3}"),
            ("a{,}", true, r"(?s)\x{61}*"),
            ("a\\{2\\}", false, r"(?s)\x{61}{2}"),
            ("a{2}", false, r"(?s)\x{61}\x{7B}\x{32}\x{7D}"),
            // `{0}` and a repetition of nothing are nothing.
            ("a{0}b", true, r"(?s)\x{62}"),
            ("a{0,0}", true, r"(?s)"),
            ("", true, r"(?s)"),
            ("()", true, r"(?s)(?:)"),
            ("a||b", true, r"(?s)(?:\x{61}||\x{62})"),
            ("(|a)", true, r"(?s)(?:(?:|\x{61}))"),
            // Basic: an operator with nothing before it is itself, `^` and
            // `$` are anchors only at the ends of an expression, a group or
            // an alternative.
            ("*a", false, r"(?s)\x{2A}\x{61}"),
            ("^*", false, r"(?s)\A\x{2A}"),
            ("a^b", false, r"(?s)\x{61}\x{5E}\x{62}"),
            ("a$b", false, r"(?s)\x{61}\x{24}\x{62}"),
            ("^^a", false, r"(?s)\A\x{5E}\x{61}"),
            ("a$$", false, r"(?s)\x{61}\x{24}\z"),
            ("\\(^a\\)", false, r"(?s)(?:\A\x{61})"),
            ("x\\(a$\\)", false, r"(?s)\x{78}(?:\x{61}\z)"),
            ("a\\|^b", false, r"(?s)(?:\x{61}|\A\x{62})"),
            ("a$\\|b", false, r"(?s)(?:\x{61}\z|\x{62})"),
            // Extended: they are anchors anywhere, and `)` alone is itself.
            ("a^b", true, r"(?s)\x{61}\A\x{62}"),
            ("a)", true, r"(?s)\x{61}\x{29}"),
            ("a}", true, r"(?s)\x{61}\x{7D}"),
            ("[abc]", true, r"(?s)[\x{61}\x{62}\x{63}]"),
            ("[^a-c]", true, r"(?s)[^\x{61}-\x{63}]"),
            ("[]a]", true, r"(?s)[\x{5D}\x{61}]"),
            ("[^]a]", true, r"(?s)[^\x{5D}\x{61}]"),
            ("[a-]", true, r"(?s)[\x{61}\x{2D}]"),
            ("[--a]", true, r"(?s)[\x{2D}-\x{61}]"),
            ("[[.a.]-[.c.]]", true, r"(?s)[\x{61}-\x{63}]"),
            ("[[=a=]]", true, r"(?s)[\x{61}]"),
            ("[\\n]", true, r"(?s)[\x{5C}\x{6E}]"),
            ("[[:digit:]]", true, r"(?s)[[0-9]]"),
            ("[^[:digit:]x]", true, r"(?s)[^[0-9]\x{78}]"),
            ("\\`a\\'", true, r"(?s)\A\x{61}\z"),
            ("\\<a\\>", true, r"(?s)\b{start}\x{61}\b{end}"),
            ("\\ba\\B", true, r"(?s)\b\x{61}\B"),
            ("\\n", true, r"(?s)\x{6E}"),
            ("é", true, r"(?s)\x{E9}"),
        ] {
            assert_eq!(
                pattern(expression, extended, false).as_deref(),
                Ok(want),
                "{expression:?} extended={extended}"
            );
        }
        // `REG_ICASE`: the engine folds; a class of one case is every
        // letter, a list is read in upper case (so `[Z-a]` is `[Z-A]`,
        // refused), and an escaped small letter matches nothing.
        assert_eq!(pattern("a", true, true).as_deref(), Ok(r"(?si)\x{61}"));
        assert_eq!(
            pattern("[a-c]", true, true).as_deref(),
            Ok(r"(?si)[\x{41}-\x{43}]")
        );
        assert_eq!(
            pattern("[[:upper:]]", true, true),
            pattern("[[:alpha:]]", true, true)
        );
        assert_eq!(
            pattern("[[:lower:]]", true, true),
            pattern("[[:alpha:]]", true, true)
        );
        assert_ne!(
            pattern("[[:upper:]]", true, false),
            pattern("[[:alpha:]]", true, false)
        );
        assert_eq!(pattern("[Z-a]", true, true), Err(RegexError::Range));
        assert!(pattern("[Z-a]", true, false).is_ok());
        assert_eq!(
            pattern("\\z", true, true).as_deref(),
            Ok(r"(?si)[^\x{0}-\x{10FFFF}]")
        );
        assert_eq!(pattern("\\Z", true, true).as_deref(), Ok(r"(?si)\x{5A}"));
    }

    /// A byte of the expression that is no character is that byte, outside
    /// a list; in one it is nothing, but it has its place in a range.
    #[test]
    fn a_byte_that_is_no_character_is_written_as_a_byte() {
        let t = |e: &[u8]| translate(e, true, false).map(|t| t.pattern);
        assert_eq!(t(b"\xff").as_deref(), Ok(r"(?s)(?-u:\xFF)"));
        assert_eq!(t(b"a\xc3*").as_deref(), Ok(r"(?s)\x{61}(?-u:\xC3)*"));
        assert_eq!(t(b"[\xff]").as_deref(), Ok(r"(?s)[^\x{0}-\x{10FFFF}]"));
        assert_eq!(t(b"[^\xff]").as_deref(), Ok(r"(?s)[\x{0}-\x{10FFFF}]"));
        assert_eq!(t(b"[a\xff]").as_deref(), Ok(r"(?s)[\x{61}]"));
        assert_eq!(t(b"[a-\xa9]").as_deref(), Ok(r"(?s)[\x{61}-\x{A9}]"));
        assert_eq!(t(b"[\xa9-a]"), Err(RegexError::Range));
        assert_eq!(t(b"[[.\xa9.]]").as_deref(), Ok(r"(?s)[^\x{0}-\x{10FFFF}]"));
        assert_eq!(t("[a-é]".as_bytes()), Err(RegexError::Collate));
        assert_eq!(t("[[.é.]]".as_bytes()), Err(RegexError::Collate));
        assert_eq!(t("[[=é=]]".as_bytes()), Err(RegexError::Collate));
    }

    /// Each refusal, by the code glibc gives it.
    #[test]
    fn what_regcomp_refuses_is_refused_in_its_words() {
        use RegexError::*;
        for (expression, extended, want) in [
            ("[", true, BadPattern),
            ("[^", true, BadPattern),
            ("[a", true, Bracket),
            ("[]", true, Bracket),
            ("[a-", true, Bracket),
            ("[[:alpha:]", true, Bracket),
            ("[[:alpha]]", true, Bracket),
            ("[[:abcdefghijklmnopqrstuvwxyzabcdefg:]]", true, Bracket),
            ("[[:foo:]]", true, CharClass),
            ("[[:ALPHA:]]", true, CharClass),
            ("[[::]]", true, CharClass),
            ("[[.ab.]]", true, Collate),
            ("[[=ab=]]", true, Collate),
            ("[[..]]", true, Collate),
            ("[b-a]", true, Range),
            ("[a-z-9]", true, Range),
            ("[[:alpha:]-z]", true, Range),
            ("[a-[:alpha:]]", true, Range),
            ("[[=a=]-z]", true, Range),
            ("a\\", true, Escape),
            ("\\", false, Escape),
            ("\\1", true, SubReg),
            ("(a)\\2", true, SubReg),
            ("a(", true, Paren),
            ("a\\(", false, Paren),
            ("a\\)", false, Paren),
            ("(a", true, Paren),
            ("a{1", true, Brace),
            ("a{x", true, Brace),
            ("a{1,2", true, Brace),
            ("a\\{1", false, Brace),
            ("a{}", true, BadBrace),
            ("a{x}", true, BadBrace),
            ("a{1x}", true, BadBrace),
            ("a{2,1}", true, BadBrace),
            ("a{1,2,3}", true, BadBrace),
            ("a{1|2}", true, BadBrace),
            ("*a", true, BadRepeat),
            ("+", true, BadRepeat),
            ("?a", true, BadRepeat),
            ("{1}", true, BadRepeat),
            ("^*", true, BadRepeat),
            ("a|*b", true, BadRepeat),
            ("(*a)", true, BadRepeat),
            ("\\{1\\}", false, BadRepeat),
            ("a**", false, BadRepeat),
            ("a*\\{2\\}", false, BadRepeat),
            ("a\\{1\\}\\{2\\}", false, BadRepeat),
            ("a\\+*", false, BadRepeat),
            ("a{32768}", true, Size),
            ("a{99999}", true, Size),
            ("a\\{32768\\}", false, Size),
        ] {
            assert_eq!(
                pattern(expression, extended, false),
                Err(want),
                "{expression:?} extended={extended}"
            );
        }
        // What the other syntax takes.
        for (expression, extended) in [
            ("*a", false),
            ("a**", true),
            ("a*\\+", false),
            ("a{32767}", true),
            ("a)", true),
            ("{1}", false),
            ("[[.a.]-z]", true),
        ] {
            assert!(
                pattern(expression, extended, false).is_ok(),
                "{expression:?}"
            );
        }
        // Every code has `regerror()`'s text for it.
        assert_eq!(BadPattern.text(), "Invalid regular expression");
        assert_eq!(Collate.text(), "Invalid collation character");
        assert_eq!(CharClass.text(), "Invalid character class name");
        assert_eq!(Escape.text(), "Trailing backslash");
        assert_eq!(SubReg.text(), "Invalid back reference");
        assert_eq!(Bracket.text(), "Unmatched [, [^, [:, [., or [=");
        assert_eq!(Paren.text(), "Unmatched ( or \\(");
        assert_eq!(Brace.text(), "Unmatched \\{");
        assert_eq!(BadBrace.text(), "Invalid content of \\{\\}");
        assert_eq!(Range.text(), "Invalid range end");
        assert_eq!(BadRepeat.text(), "Invalid preceding regular expression");
        assert_eq!(Size.text(), "Regular expression too big");
        assert_eq!(BackReference.text(), "back references are not supported");
    }

    /// A back-reference glibc takes is refused, in lsof-rs's words, unless
    /// glibc refuses the expression for something after it, in its own.
    #[test]
    fn a_back_reference_is_refused_once_the_rest_is_read() {
        assert_eq!(
            pattern("(a)\\1", true, false),
            Err(RegexError::BackReference)
        );
        assert_eq!(
            pattern("\\(a\\)\\1", false, false),
            Err(RegexError::BackReference)
        );
        assert_eq!(pattern("(a)\\1[", true, false), Err(RegexError::BadPattern));
        // The tenth group is no back-reference's.
        assert_eq!(
            pattern("(a)(a)(a)(a)(a)(a)(a)(a)(a)\\9", true, false),
            Err(RegexError::BackReference)
        );
        assert_eq!(
            pattern("(a)(a)(a)(a)(a)(a)(a)(a)\\9", true, false),
            Err(RegexError::SubReg)
        );
        // A group still open is not yet one to refer to.
        assert_eq!(pattern("(a\\1)", true, false), Err(RegexError::SubReg));
        // Nor is one closed in another alternative: each alternative has
        // the groups there were when the first began, and what follows
        // them all has theirs (each line glibc's answer, through
        // `regcomp()`).
        for (expression, valid) in [
            ("(a)|\\1", false),
            ("(a)|b\\1", false),
            ("((a)|\\1)", false),
            ("(a|\\1)", false),
            ("(a)(b|\\1)", true),
            ("(a)|(b)\\1", false),
            ("(a)|(b)\\2", true),
            ("(a)|(b)|\\2", false),
            ("a|(b)|\\1", false),
            ("(a)\\1|\\1", false),
            ("(a)\\1*|c", true),
            ("((a)|b)\\2", true),
            ("((a)|b)\\1", true),
            ("((a)|\\2)", false),
            ("(a)(|\\1)", true),
            ("(a)((b)|\\1)", true),
            ("((a)|(b))\\2|\\3", false),
            ("(a)(b)\\1|\\2", false),
            ("(a)|()\\1", false),
            ("(a|(b))\\2", true),
            ("(a|(b)\\2)", true),
            ("((a)|(b))\\3", true),
            ("(a)|(b)|(c)\\3", true),
        ] {
            let want = if valid {
                RegexError::BackReference
            } else {
                RegexError::SubReg
            };
            assert_eq!(pattern(expression, true, false), Err(want), "{expression}");
            let basic = expression
                .replace('(', "\\(")
                .replace(')', "\\)")
                .replace('|', "\\|");
            assert_eq!(pattern(&basic, false, false), Err(want), "{basic}");
        }
    }

    /// In a basic expression a `$` is an anchor only where the expression,
    /// a group or an alternative ends; found by looking at what follows,
    /// not by reading it as glibc does (once for every `$` of a run: 70,000
    /// end the C with SIGSEGV; DIVERGENCES 38).
    #[test]
    fn a_dollar_is_an_anchor_where_a_basic_expression_ends() {
        for (expression, want) in [
            ("a$", r"(?s)\x{61}\z"),
            ("a$b", r"(?s)\x{61}\x{24}\x{62}"),
            ("$a", r"(?s)\x{24}\x{61}"),
            ("a$$", r"(?s)\x{61}\x{24}\z"),
            ("$$$", r"(?s)\x{24}\x{24}\z"),
            ("a$\\|b", r"(?s)(?:\x{61}\z|\x{62})"),
            ("\\(a$\\)", r"(?s)(?:\x{61}\z)"),
            ("\\(a$\\)b", r"(?s)(?:\x{61}\z)\x{62}"),
            ("a$\\(b\\)", r"(?s)\x{61}\x{24}(?:\x{62})"),
            ("a$|b", r"(?s)\x{61}\x{24}\x{7C}\x{62}"),
            ("a$)", r"(?s)\x{61}\x{24}\x{29}"),
            ("a$\\$", r"(?s)\x{61}\x{24}\x{24}"),
            ("a$\\{2\\}", r"(?s)\x{61}\x{24}{2}"),
        ] {
            assert_eq!(
                pattern(expression, false, false).as_deref(),
                Ok(want),
                "{expression}"
            );
        }
        assert_eq!(pattern("a$\\", false, false), Err(RegexError::Escape));
        // A run of them of any length is read in one pass and no depth:
        // every one a character but the last.
        let run = if cfg!(miri) { 2_000 } else { 60_000 };
        let dollars = "$".repeat(run);
        let translated = pattern(&dollars, false, false).unwrap();
        assert_eq!(translated.matches(r"\x{24}").count(), run - 1);
        assert!(translated.ends_with(r"\z"));
        // Past the cost limit it is too big, still without depth (miri,
        // which interprets every step, is spared the million).
        if !cfg!(miri) {
            let long = 1_000_000;
            assert_eq!(
                pattern(&"$".repeat(long), false, false),
                Err(RegexError::Size)
            );
            assert_eq!(
                pattern(&format!("{}\\|a", "$".repeat(long)), false, false),
                Err(RegexError::Size)
            );
        }
    }

    /// What an expression may ask of the engine is bounded before the
    /// engine sees it ([`COST_LIMIT`]): the classes of thousands of ranges
    /// above all, which the size limit alone let through at 20 s and 2.5 GB
    /// (60,000 `\W` under `i`).
    #[test]
    #[cfg_attr(
        miri,
        ignore = "it reads expressions of 65,536 characters: minutes under miri"
    )]
    fn an_expression_past_the_cost_limit_is_too_big_before_it_is_compiled() {
        assert_eq!(
            (COST_LIMIT, CLASS_COST, SMALL_CLASS_COST),
            (1 << 16, 1 << 10, 1 << 6)
        );
        let size = Err(RegexError::Size);
        let ok = |e: &str, x, i| translate(e.as_bytes(), x, i).is_ok();
        // A character costs one: the limit's worth is taken, one more is
        // not.
        let most = usize::try_from(COST_LIMIT).unwrap();
        assert!(ok(&"a".repeat(most), true, false));
        assert_eq!(pattern(&"a".repeat(most + 1), true, false), size);
        assert!(ok(&"a".repeat(most), false, true));
        assert_eq!(pattern(&"a".repeat(most + 1), false, true), size);
        // A `.` two, a repetition one more, a list one for each element
        // and one more where it is a non-matching one.
        assert!(ok(&".".repeat(most / 2), true, false));
        assert_eq!(pattern(&".".repeat(most / 2 + 1), true, false), size);
        assert!(ok(&"a*".repeat(most / 2), true, false));
        assert_eq!(pattern(&"a*".repeat(most / 2 + 1), true, false), size);
        assert!(ok(&"a{2,3}".repeat(most / 2), true, false));
        assert_eq!(pattern(&"a{2,3}".repeat(most / 2 + 1), true, false), size);
        assert!(ok(&"[abc]".repeat(most / 4), true, false));
        assert_eq!(pattern(&"[abc]".repeat(most / 4 + 1), true, false), size);
        assert!(ok(&"[a-c]".repeat(most / 2), true, false));
        assert_eq!(pattern(&"[a-c]".repeat(most / 2 + 1), true, false), size);
        assert!(ok(&"[^a]".repeat(most / 3), true, false));
        assert_eq!(pattern(&"[^a]".repeat(most / 3 + 1), true, false), size);
        // A class of thousands of ranges 1,024: 63 of them with what
        // carries them, never 64.
        for class in [
            "\\w",
            "\\W",
            "[[:alpha:]]",
            "[[:alnum:]]",
            "[[:upper:]]",
            "[[:lower:]]",
            "[[:punct:]]",
            "[[:graph:]]",
            "[[:print:]]",
            "[^[:alpha:]]",
        ] {
            for icase in [false, true] {
                assert!(ok(&class.repeat(63), true, icase), "{class}");
                assert_eq!(pattern(&class.repeat(64), true, icase), size, "{class}");
            }
        }
        // Two in one list are two.
        assert!(ok(&"[[:alpha:][:punct:]]".repeat(31), true, false));
        assert_eq!(
            pattern(&"[[:alpha:][:punct:]]".repeat(32), true, false),
            size
        );
        assert_eq!(
            pattern(&format!("[{}]", "[:alpha:]".repeat(64)), true, false),
            size
        );
        // A class of tens 64, and of digits one.
        for class in ["\\s", "\\S", "[[:space:]]", "[[:blank:]]", "[[:cntrl:]]"] {
            assert!(ok(&class.repeat(900), true, true), "{class}");
            assert_eq!(pattern(&class.repeat(1024), true, true), size, "{class}");
        }
        assert!(ok(&"\\s".repeat(1008), true, false));
        assert_eq!(pattern(&"\\s".repeat(1009), true, false), size);
        assert!(ok(&"[[:digit:]]".repeat(most / 3), true, false));
        assert!(ok(&"[[:xdigit:]]".repeat(most / 3), true, false));
        assert_eq!(
            pattern(&"[[:digit:]]".repeat(most / 3 + 1), true, false),
            size
        );
        // A repetition does not multiply the cost: the program's size is
        // the size limit's to refuse.
        assert!(ok("[[:alpha:]]{32767}", true, false));
        assert!(ok("(\\w{1,255}){1,255}", true, true));
        // What glibc refuses for itself is said first, wherever it is.
        let long = "\\W".repeat(100);
        assert_eq!(
            pattern(&format!("{long}("), true, true),
            Err(RegexError::Paren)
        );
        assert_eq!(
            pattern(&format!("{long}[z-a]"), true, true),
            Err(RegexError::Range)
        );
        // The reviewers' reproducers, and argv's worst: refused at once.
        if !cfg!(miri) {
            let started = std::time::Instant::now();
            for (unit, count, extended, icase) in [
                ("\\W", 60_000, true, true),
                ("\\w\\W\\s\\S", 15_000, true, true),
                ("[^[:punct:]]", 10_000, true, true),
                ("[[:alpha:]]", 10_000, true, false),
                ("\\W*", 1_365, true, true),
                ("\\W", 2_047, true, true),
                ("$", 100_000, false, false),
            ] {
                assert_eq!(
                    CommandRegex::new(unit.repeat(count).as_bytes(), extended, icase).err(),
                    Some(RegexError::Size),
                    "{unit} x {count}"
                );
            }
            assert!(started.elapsed() < std::time::Duration::from_secs(5));
        }
    }

    /// An answer is kept for the next time the command is asked about,
    /// the same answer, and the answers kept are bounded.
    #[test]
    fn an_answer_is_kept_and_the_answers_kept_are_bounded() {
        let regex = CommandRegex::new(b"^a.*[0-4]$", true, false).unwrap();
        assert_eq!(regex.kept(), 0);
        for _ in 0..3 {
            assert!(regex.is_match(b"abc3"));
            assert!(!regex.is_match(b"abc7"));
            assert!(!regex.is_match(b""));
        }
        assert_eq!(regex.kept(), 3);
        // A copy shares them, and answers alike.
        let copy = regex.clone();
        assert!(copy.is_match(b"abc3") && !copy.is_match(b"abc8"));
        assert_eq!((regex.kept(), copy.kept()), (4, 4));
        // A command past the length kept is answered and not kept: at the
        // length it is.
        let long = |n: usize, last: u8| {
            let mut command = vec![b'a'; n - 1];
            command.push(last);
            command
        };
        assert!(regex.is_match(&long(KEPT_COMMAND, b'1')));
        assert_eq!(regex.kept(), 5);
        assert!(regex.is_match(&long(KEPT_COMMAND + 1, b'1')));
        assert!(!regex.is_match(&long(KEPT_COMMAND + 1, b'9')));
        assert_eq!(regex.kept(), 5);
        // However many commands are asked about, a bounded number of
        // answers is kept, and each is still the engine's.
        assert_eq!((KEPT_ANSWERS, KEPT_COMMAND), (1024, 256));
        let commands = if cfg!(miri) { 40 } else { 5000 };
        for round in 0..2 {
            for i in 0..commands {
                let command = format!("a{i}");
                assert_eq!(
                    regex.is_match(command.as_bytes()),
                    i % 10 < 5,
                    "{round} {command}"
                );
                assert!(regex.kept() <= KEPT_ANSWERS);
            }
        }
    }

    /// A `[:name:]`, `[.name.]` or `[=name=]` of 32 bytes or more is no
    /// name (`BRACKET_NAME_BUF_SIZE`): 31 are read, and are then no class
    /// and no collating symbol (glibc's answers, through `regcomp()`).
    #[test]
    fn a_bracket_name_is_at_most_thirty_one_bytes() {
        for (open, close, short) in [
            ("[:", ":]", RegexError::CharClass),
            ("[.", ".]", RegexError::Collate),
            ("[=", "=]", RegexError::Collate),
        ] {
            let named = |n: usize| format!("[{open}{}{close}]", "a".repeat(n));
            for icase in [false, true] {
                assert_eq!(pattern(&named(30), true, icase), Err(short));
                assert_eq!(pattern(&named(31), true, icase), Err(short));
                assert_eq!(pattern(&named(32), true, icase), Err(RegexError::Bracket));
                assert_eq!(pattern(&named(33), true, icase), Err(RegexError::Bracket));
            }
        }
        // Bytes are counted, not characters.
        assert_eq!(
            pattern(&format!("[[:{}:]]", "é".repeat(15)), true, false),
            Err(RegexError::CharClass)
        );
        assert_eq!(
            pattern(&format!("[[:{}:]]", "é".repeat(16)), true, false),
            Err(RegexError::Bracket)
        );
    }

    /// Which expressions glibc searches by characters.
    #[test]
    fn by_chars_is_glibcs_wide_search() {
        let by = |e: &str, icase| translate(e.as_bytes(), true, icase).unwrap().by_chars;
        for e in [
            "abc", "a.c", "[abc]", "a|b", "(a)*", "^a$", "[[.a.]]", "\\`a",
        ] {
            assert!(!by(e, false), "{e}");
            assert!(by(e, true), "{e}");
        }
        for e in [
            "[^a]",
            "[a-c]",
            "[[:alpha:]]",
            "[é]",
            "[[=a=]]",
            "\\w",
            "\\S",
            "\\b",
            "\\<a",
            "a\\>",
            "\\B",
        ] {
            assert!(by(e, false), "{e}");
        }
    }

    /// Nesting and size are bounded where glibc's are not.
    #[test]
    fn an_expression_past_the_bounds_is_too_big() {
        let deep = |n: usize| format!("{}a{}", "(".repeat(n), ")".repeat(n));
        assert!(pattern(&deep(99), true, false).is_ok());
        assert_eq!(pattern(&deep(100), true, false), Err(RegexError::Size));
        assert_eq!(pattern(&deep(250), true, false), Err(RegexError::Size));
        // Under miri, which interprets what takes microseconds, fewer.
        let many = if cfg!(miri) { 2_000 } else { 100_000 };
        assert_eq!(pattern(&deep(many), true, false), Err(RegexError::Size));
        // A repetition is a level, as a group is.
        let stars = |n: usize| format!("a{}", "*".repeat(n));
        assert!(pattern(&stars(99), true, false).is_ok());
        assert_eq!(pattern(&stars(100), true, false), Err(RegexError::Size));
        assert_eq!(pattern(&stars(many), true, false), Err(RegexError::Size));
        // A program past the size limit, each interval one glibc takes.
        if !cfg!(miri) {
            assert_eq!(SIZE_LIMIT, 1 << 23);
            for refused in [
                "(a{1000}){1000}",
                "[[:alpha:]]{1000}",
                "(.{200}){150}",
                ".{32767}",
                "\\w{0,800}z",
                ".{0,20000}z",
                "(.*){1,32767}z",
            ] {
                assert_eq!(
                    CommandRegex::new(refused.as_bytes(), true, false).err(),
                    Some(RegexError::Size),
                    "{refused}"
                );
            }
            // Inside it, what an expression for a command name asks.
            for taken in [
                "a{32767}",
                ".{20000}",
                "[[:graph:]]{1,255}",
                "[[:alpha:]]{300}",
                "(.{200}){75}",
                "\\w{0,400}z",
                ".{0,10000}z",
            ] {
                assert!(
                    CommandRegex::new(taken.as_bytes(), true, false).is_ok(),
                    "{taken}"
                );
            }
        }
    }

    /// Whatever the translator writes inside its own nesting limit, the
    /// engine takes: its limit counts concatenations and lists as levels
    /// too, and is set above the deepest the translator can write. Each
    /// shape is nested as deep as the translator allows.
    #[test]
    #[cfg_attr(miri, ignore = "miri interprets the engine's compiler: minutes")]
    fn the_engine_takes_the_deepest_expression_the_translator_writes() {
        type Shape = fn(usize) -> String;
        let shapes: [(&str, Shape); 6] = [
            ("groups", |n| format!("{}a{}", "(".repeat(n), ")".repeat(n))),
            ("a concatenation in each", |n| {
                format!("{}a{}", "(ab".repeat(n), "c)".repeat(n))
            }),
            ("an alternation in each", |n| {
                format!("{}a{}", "(a|b".repeat(n), "c|d)".repeat(n))
            }),
            ("a repetition of each", |n| {
                format!("{}a{}", "(ab".repeat(n), "c)*".repeat(n))
            }),
            ("a list in the deepest", |n| {
                format!(
                    "{}[^[:punct:][:alpha:]x-z]{}",
                    "(a|".repeat(n),
                    "b)+".repeat(n)
                )
            }),
            ("a byte and a word operator in the deepest", |n| {
                format!("{}\\b\\w{}", "(a|b".repeat(n), "c|d)?".repeat(n))
            }),
        ];
        for (name, shape) in shapes {
            let deepest = (1..=NEST_LIMIT as usize)
                .rev()
                .find(|&n| pattern(&shape(n), true, false).is_ok())
                .unwrap_or_else(|| panic!("{name}: no depth is taken"));
            assert!(deepest >= 24, "{name}: only {deepest} deep");
            assert_eq!(
                pattern(&shape(deepest + 1), true, false),
                Err(RegexError::Size),
                "{name}"
            );
            for icase in [false, true] {
                let regex = CommandRegex::new(shape(deepest).as_bytes(), true, icase);
                assert!(regex.is_ok(), "{name} at {deepest}: {:?}", regex.err());
            }
        }
    }

    /// A match starts at a character's first byte when glibc searches by
    /// characters, and anywhere when it searches by bytes.
    #[test]
    #[cfg_attr(miri, ignore = "miri interprets the engine's compiler: minutes")]
    fn a_match_starts_at_a_character_when_searched_by_characters() {
        let m = |e: &[u8], icase: bool, command: &[u8]| {
            CommandRegex::new(e, true, icase).unwrap().is_match(command)
        };
        // By bytes: the byte is found inside `é` (C3 A9).
        assert!(m(b"\xa9", false, "é".as_bytes()));
        assert!(m(b"\xc3", false, "é".as_bytes()));
        // By characters: not inside it, but as a byte of its own.
        assert!(!m(b"\xa9", true, "é".as_bytes()));
        assert!(m(b"\xa9", true, b"\xa9"));
        assert!(m(b"\xa9", true, b"a\xa9"));
        assert!(m(b"\xa9", true, b"\xc3\xa9\xa9"));
        assert!(m(b"a\xc3", true, "aé".as_bytes()));
        assert!(m("é".as_bytes(), true, b"\xc3\xc3\xa9"));
        // Neither `.` nor a list takes a byte that is no character.
        assert!(!m(b"^.$", false, b"\xff"));
        assert!(!m(b"^[^a]$", false, b"\xff"));
        assert!(m(b"^.$", false, "é".as_bytes()));
        assert!(m(b"^[^a]$", false, "é".as_bytes()));
        assert!(m(b"^bad.byte$", false, b"bad-byte"));
        assert!(!m(b"^bad.byte$", false, b"bad\xffbyte"));
        assert!(m(b"bad\xffbyte", false, b"bad\xffbyte"));
        // The empty expression matches every command, the empty one too.
        assert!(m(b"", false, b""));
        assert!(m(b"", true, b"\xff"));
    }

    #[test]
    fn two_are_the_same_when_made_from_the_same_expression() {
        let r = |e: &[u8], x, i| CommandRegex::new(e, x, i).unwrap();
        assert_eq!(r(b"a", true, false), r(b"a", true, false));
        assert_ne!(r(b"a", true, false), r(b"b", true, false));
        assert_ne!(r(b"a", true, false), r(b"a", false, false));
        assert_ne!(r(b"a", true, false), r(b"a", true, true));
        assert_eq!(r(b"a.c", true, false).expression(), b"a.c");
    }
}
