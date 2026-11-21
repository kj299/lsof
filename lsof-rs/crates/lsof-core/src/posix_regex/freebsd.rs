//! FreeBSD libc's `regcomp()`: Henry Spencer's grammar, as FreeBSD 14
//! builds it into libc (`lib/libc/regex/regcomp.c`, without `LIBREGEX`, so
//! with no GNU operator), read into the same pieces as glibc's
//! (`posix_regex.rs`), which the same engines match (DIVERGENCES 183).
//!
//! What differs from glibc's grammar, each by the function of `regcomp.c`
//! that decides it:
//!
//! * `may_escape()`: a backslash before a letter (`iswalpha()`: general
//!   category L, not the letter numbers, marks or circled letters
//!   Unicode also calls alphabetic), `'` or `` ` `` is
//!   `REG_EESCAPE`, "trailing backslash (\)"; before anything else (`\|`,
//!   `\+`, `\?`, `\1` in an extended expression, `\.`) it is that
//!   character. `\<` and `\>` are the word's ends; there is no `\w`, `\s`,
//!   `\b`, `\B`, `` \` `` or `\'`.
//! * `p_re()`: an empty expression or alternative is `REG_EMPTY`, "empty
//!   (sub)expression" (`a|`, `a||b`, `(|a)`, `` ``), and so is one whose every
//!   piece is `{0}`; a basic expression has no alternation at all.
//! * `p_ere_exp()`: `)` that opens nothing is a character, as `p_re()`
//!   stops only at the `)` of a group it reads; `{` is a
//!   repetition only before a digit or a `,`, and `REG_BADRPT` otherwise;
//!   a repetition of a repetition (`a**`, `a+?`) is `REG_BADRPT`, as is
//!   one of `^`.
//! * `p_simp_re()`: in a basic expression a `*` that does not open it is
//!   a repetition of what is before it, so a second one is `REG_BADRPT`.
//! * `p_count()`: a count is at most `RE_DUP_MAX`, 255.
//! * `p_bracket()`, `p_b_term()`: a `-` that is no range's end and does
//!   not open or close the list is `REG_ERANGE`; `[[:<:]]` and `[[:>:]]`
//!   are the word's ends; a class is one of `wctype()`'s names; a
//!   collating element or an equivalence class is one character or one of
//!   `cname.h`'s names.
//! * `seterr()`: the first refusal is the one reported, and reading stops
//!   there.
//! * `wgetnext()`: a byte that is no character of the locale (UTF-8, as
//!   everywhere in lsof-rs) is `REG_ILLSEQ`, "illegal byte sequence".
//! * `CHaddrange()`: the characters of a range below `NC` (128 in a UTF-8
//!   locale) are added one by one, and the rest is a range only where it
//!   is more than one character, so a range that ends at U+0080 leaves it
//!   out.
//! * `REG_ICASE` (`ordinary()`, `bothcases()`, `CHadd()`, `CHIN()`): no case
//!   is folded while matching. A letter with another case is read as the
//!   list of itself, and a list holds each character added to it, the
//!   `towlower()` and `towupper()` of each that are ASCII, and past ASCII
//!   takes a character whose own `towlower()` or `towupper()` it holds, by
//!   FreeBSD's tables (`freebsd_case.rs`), not Unicode's folding: `İ` is
//!   `[İi]`, the Kelvin sign is `[\u{212A}k]` and not `K`, `ß` has no other
//!   case. A back-reference is the bytes its group matched, in their case
//!   (`memcmp()`).
//!
//! The answers here were measured against FreeBSD 14.5's libc
//! (`tests/posix_regex_freebsd.txt`), but those beside a word operator and
//! a character past ASCII (DIVERGENCES 183).

use std::collections::HashMap;
use std::sync::OnceLock;

use super::engine::{Look, Node, UnitSpec};
use super::freebsd_case::{ALPHA, FB_CASE, LOWER, UPPER};
use super::{class_cost, nested, push_char, Frag, Item, Parser, RegexError, NEST_LIMIT};

/// `NC` in a UTF-8 locale: the characters a list keeps in its bitmap.
const NC: u32 = 128;

/// How much work the case lists of one expression may take: a list
/// written out under `REG_ICASE` reads every character of [`FB_CASE`] once,
/// and each character it writes costs [`CASE_TEXT_COST`]. Past it the
/// expression is too big ([`RegexError::Size`]), as past lsof-rs's other
/// bounds; an expression of a command's length takes a few thousand.
pub(super) const CASE_WORK_LIMIT: u64 = 1 << 24;

/// What one byte of a written case list costs against [`CASE_WORK_LIMIT`].
const CASE_TEXT_COST: u64 = 1;

/// How far a run of a case list goes on over characters the list takes
/// anyway ([`Parser::fb_case_list`]).
const RUN_GAP: u32 = 64;

/// FreeBSD's grammar's state beyond glibc's.
#[derive(Default)]
pub(super) struct State {
    /// `REG_ICASE`, which this grammar applies itself.
    icase: bool,
    /// The case lists written so far, by what they hold.
    lists: HashMap<CaseKey, String>,
    /// The work they took ([`CASE_WORK_LIMIT`]).
    work: u64,
}

/// What a case list holds, as a key: whether it is negated, its bitmap,
/// its characters past ASCII, its ranges and its classes.
type CaseKey = (bool, u128, Vec<char>, Vec<(char, char)>, Vec<&'static str>);

/// FreeBSD's `DUPMAX`, `_POSIX2_RE_DUP_MAX`.
const DUPMAX: i64 = 255;

/// No end to a repetition, as [`Parser::repeat_frag`] takes it.
const NO_END: i64 = -1;

/// What ends a (sub)expression: `p_re()`'s `end1`/`end2`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum End {
    /// The whole expression (`OUT`).
    Out,
    /// An extended group's `)`.
    Paren,
    /// A basic group's `\)`.
    BackslashParen,
}

/// `cname.h`: the names a collating element or an equivalence class may
/// have besides a character of its own.
const CNAMES: &[(&str, char)] = &[
    ("NUL", '\0'),
    ("SOH", '\u{1}'),
    ("STX", '\u{2}'),
    ("ETX", '\u{3}'),
    ("EOT", '\u{4}'),
    ("ENQ", '\u{5}'),
    ("ACK", '\u{6}'),
    ("BEL", '\u{7}'),
    ("alert", '\u{7}'),
    ("BS", '\u{8}'),
    ("backspace", '\u{8}'),
    ("HT", '\t'),
    ("tab", '\t'),
    ("LF", '\n'),
    ("newline", '\n'),
    ("VT", '\u{b}'),
    ("vertical-tab", '\u{b}'),
    ("FF", '\u{c}'),
    ("form-feed", '\u{c}'),
    ("CR", '\r'),
    ("carriage-return", '\r'),
    ("SO", '\u{e}'),
    ("SI", '\u{f}'),
    ("DLE", '\u{10}'),
    ("DC1", '\u{11}'),
    ("DC2", '\u{12}'),
    ("DC3", '\u{13}'),
    ("DC4", '\u{14}'),
    ("NAK", '\u{15}'),
    ("SYN", '\u{16}'),
    ("ETB", '\u{17}'),
    ("CAN", '\u{18}'),
    ("EM", '\u{19}'),
    ("SUB", '\u{1a}'),
    ("ESC", '\u{1b}'),
    ("IS4", '\u{1c}'),
    ("FS", '\u{1c}'),
    ("IS3", '\u{1d}'),
    ("GS", '\u{1d}'),
    ("IS2", '\u{1e}'),
    ("RS", '\u{1e}'),
    ("IS1", '\u{1f}'),
    ("US", '\u{1f}'),
    ("space", ' '),
    ("exclamation-mark", '!'),
    ("quotation-mark", '"'),
    ("number-sign", '#'),
    ("dollar-sign", '$'),
    ("percent-sign", '%'),
    ("ampersand", '&'),
    ("apostrophe", '\''),
    ("left-parenthesis", '('),
    ("right-parenthesis", ')'),
    ("asterisk", '*'),
    ("plus-sign", '+'),
    ("comma", ','),
    ("hyphen", '-'),
    ("hyphen-minus", '-'),
    ("period", '.'),
    ("full-stop", '.'),
    ("slash", '/'),
    ("solidus", '/'),
    ("zero", '0'),
    ("one", '1'),
    ("two", '2'),
    ("three", '3'),
    ("four", '4'),
    ("five", '5'),
    ("six", '6'),
    ("seven", '7'),
    ("eight", '8'),
    ("nine", '9'),
    ("colon", ':'),
    ("semicolon", ';'),
    ("less-than-sign", '<'),
    ("equals-sign", '='),
    ("greater-than-sign", '>'),
    ("question-mark", '?'),
    ("commercial-at", '@'),
    ("left-square-bracket", '['),
    ("backslash", '\\'),
    ("reverse-solidus", '\\'),
    ("right-square-bracket", ']'),
    ("circumflex", '^'),
    ("circumflex-accent", '^'),
    ("underscore", '_'),
    ("low-line", '_'),
    ("grave-accent", '`'),
    ("left-brace", '{'),
    ("left-curly-bracket", '{'),
    ("vertical-line", '|'),
    ("right-brace", '}'),
    ("right-curly-bracket", '}'),
    ("tilde", '~'),
    ("DEL", '\u{7f}'),
];

/// One piece of a (sub)expression as `p_ere_exp()` or `p_simp_re()` read
/// it: what it matches, and whether it left anything in the program (a
/// `{0}` drops what it repeats, `repeat()`'s `DROP`), which `p_re()` asks
/// to tell an empty expression.
struct Piece {
    frag: Option<Frag>,
    emitted: bool,
}

impl Parser {
    /// `regcomp()` by FreeBSD's grammar: the whole expression.
    pub(super) fn freebsd(&mut self) -> Result<Option<Frag>, RegexError> {
        // Spencer's matcher steps a character at a time under a UTF-8
        // locale (`XMBRTOWC`), so a match starts at a character.
        self.by_chars = true;
        // `REG_ICASE` is in the lists this grammar writes; the engines fold
        // nothing (a back-reference is `memcmp()`).
        self.fb.icase = self.icase;
        self.icase = false;
        self.fb_re(End::Out, 0)
    }

    fn fb_more(&self) -> bool {
        self.pos < self.items.len()
    }

    fn fb_more2(&self) -> bool {
        self.pos.saturating_add(1) < self.items.len()
    }

    /// The byte `PEEK()` would see, where it is ASCII.
    fn fb_peek(&self) -> Option<u8> {
        self.at(self.pos).and_then(Item::ascii)
    }

    fn fb_peek2(&self) -> Option<u8> {
        self.at(self.pos.saturating_add(1)).and_then(Item::ascii)
    }

    fn fb_see(&self, c: u8) -> bool {
        self.fb_peek() == Some(c)
    }

    fn fb_seetwo(&self, a: u8, b: u8) -> bool {
        self.fb_peek() == Some(a) && self.fb_peek2() == Some(b)
    }

    fn fb_eat(&mut self, c: u8) -> bool {
        let seen = self.fb_see(c);
        if seen {
            self.pos = self.pos.saturating_add(1);
        }
        seen
    }

    fn fb_eattwo(&mut self, a: u8, b: u8) -> bool {
        let seen = self.fb_seetwo(a, b);
        if seen {
            self.pos = self.pos.saturating_add(2);
        }
        seen
    }

    /// `wgetnext()`: the next character, or `REG_ILLSEQ` for a byte that
    /// is none.
    fn fb_wgetnext(&mut self) -> Result<char, RegexError> {
        match self.at(self.pos) {
            Some(Item::Char(c)) => {
                self.pos = self.pos.saturating_add(1);
                Ok(c)
            }
            // `MORE()` was asked first everywhere this is called.
            _ => Err(RegexError::IllSeq),
        }
    }

    /// Whether `p_re()` is at its end.
    fn fb_seeend(&self, end: End) -> bool {
        match end {
            End::Out => false,
            End::Paren => self.fb_see(b')'),
            End::BackslashParen => self.fb_seetwo(b'\\', b')'),
        }
    }

    /// `p_re()`: branches (extended only), each of pieces side by side.
    fn fb_re(&mut self, end: End, nest: u32) -> Result<Option<Frag>, RegexError> {
        if nest > NEST_LIMIT {
            return Err(RegexError::Size);
        }
        let outer = end == End::Out;
        let mut branches: Vec<Option<Frag>> = Vec::new();
        loop {
            let mut pieces: Vec<Option<Frag>> = Vec::new();
            let mut emitted = false;
            let mut terminate = false;
            // `p_bre_pre_parse()`: a basic expression's `^` where it opens.
            if !self.extended && self.fb_eat(b'^') {
                pieces.push(Some(self.fb_look(r"\A", Look::Start)));
                emitted = true;
            }
            let mut nchain = 0u32;
            while self.fb_more() && !(self.extended && self.fb_see(b'|')) && !self.fb_seeend(end) {
                let piece = if self.extended {
                    self.fb_ere_exp(nest)?
                } else {
                    let (piece, dollar) = self.fb_simp_re(nchain, nest)?;
                    terminate = dollar;
                    piece
                };
                emitted |= piece.emitted;
                pieces.push(piece.frag);
                nchain = nchain.saturating_add(1);
            }
            // `p_bre_post_parse()`: a `$` that ends a basic (sub)expression
            // is its end, not a character.
            if terminate {
                pieces.pop();
                pieces.push(Some(self.fb_look(r"\z", Look::End)));
            }
            if !emitted {
                return Err(RegexError::Empty);
            }
            branches.push(self.fb_concat(pieces));
            if !self.extended {
                break;
            }
            // `p_branch_do()`.
            let mut ate = 0u32;
            while self.fb_eat(b'|') {
                ate = ate.saturating_add(1);
            }
            if ate == 0 {
                break;
            }
            if ate > 1 || (outer && !self.fb_more()) {
                return Err(RegexError::Empty);
            }
        }
        if branches.len() == 1 {
            return Ok(branches.pop().flatten());
        }
        let mut depth = 0;
        let mut s = String::from("(?:");
        let mut nodes = Vec::with_capacity(branches.len());
        for (i, branch) in branches.iter().enumerate() {
            if i > 0 {
                s.push('|');
            }
            if let Some(branch) = branch {
                depth = depth.max(branch.depth);
                s.push_str(&branch.s);
            }
            nodes.push(self.node_of(branch.as_ref()));
        }
        s.push(')');
        let node = self.tree.push(Node::Alt(nodes));
        nested(s, depth, node)
    }

    /// Pieces side by side, as `parse_branch()` joins glibc's.
    fn fb_concat(&mut self, pieces: Vec<Option<Frag>>) -> Option<Frag> {
        let mut tree: Option<Frag> = None;
        for expr in pieces {
            tree = match (tree, expr) {
                (Some(mut a), Some(b)) => {
                    a.s.push_str(&b.s);
                    a.node = self.tree.concat(a.node, b.node);
                    a.atomic = false;
                    a.depth = a.depth.max(b.depth);
                    Some(a)
                }
                (None, e) => e,
                (t, None) => t,
            };
        }
        tree
    }

    /// An anchor or a word's end.
    fn fb_look(&mut self, text: &'static str, look: Look) -> Frag {
        self.charge(1);
        self.atom(text.to_string(), Node::Look(look))
    }

    /// One character, as `ordinary()` emits it: under `REG_ICASE` a letter
    /// with another case is the list of it (`bothcases()`).
    fn fb_ordinary(&mut self, c: char) -> Result<Frag, RegexError> {
        if self.fb.icase {
            if let Some((_, _, _, flags)) = case_of(c) {
                if flags & ALPHA != 0 && othercase(c) != c {
                    let mut list = List::default();
                    list.add(c);
                    return self.fb_case_list(&list, false);
                }
            }
        }
        self.charge(1);
        Ok(self.literal(Item::Char(c)))
    }

    /// `may_escape()`: whether a backslash may stand before `c` (not
    /// before a letter, `'` or `` ` ``). A letter is `iswalpha()`'s, general
    /// category L, as `[[:alpha:]]` is ([`fb_class_set`]).
    fn fb_may_escape(c: char) -> bool {
        !(c == '\'' || c == '`' || is_letter(c))
    }

    /// `p_ere_exp()`: one atom of an extended expression and the
    /// repetition after it.
    fn fb_ere_exp(&mut self, nest: u32) -> Result<Piece, RegexError> {
        let item = self.at(self.pos).ok_or(RegexError::Empty)?;
        self.pos = self.pos.saturating_add(1);
        let mut wascaret = false;
        let frag = match item.ascii() {
            Some(b'(') => {
                if !self.fb_more() {
                    return Err(RegexError::Paren);
                }
                let index = self.nsub;
                self.nsub = self.nsub.saturating_add(1);
                let inner = if self.fb_see(b')') {
                    None
                } else {
                    self.fb_re(End::Paren, nest.saturating_add(1))?
                };
                if !self.fb_eat(b')') {
                    return Err(RegexError::Paren);
                }
                self.fb_group(index, inner)?
            }
            Some(b'^') => {
                wascaret = true;
                self.fb_look(r"\A", Look::Start)
            }
            Some(b'$') => self.fb_look(r"\z", Look::End),
            Some(b'|') => return Err(RegexError::Empty),
            Some(b'*' | b'+' | b'?' | b'{') => return Err(RegexError::BadRepeat),
            Some(b'.') => {
                self.charge(2);
                self.unit(".".to_string())
            }
            Some(b'[') => self.fb_bracket()?,
            Some(b'\\') => {
                if !self.fb_more() {
                    return Err(RegexError::Escape);
                }
                match self.fb_wgetnext()? {
                    '<' => self.fb_look(r"\b{start}", Look::Word(r"\b{start}")),
                    '>' => self.fb_look(r"\b{end}", Look::Word(r"\b{end}")),
                    c if Self::fb_may_escape(c) => self.fb_ordinary(c)?,
                    _ => return Err(RegexError::Escape),
                }
            }
            _ => {
                self.pos = self.pos.saturating_sub(1);
                let c = self.fb_wgetnext()?;
                self.fb_ordinary(c)?
            }
        };
        let mut piece = Piece {
            frag: Some(frag),
            emitted: true,
        };
        let Some(c) = self.fb_peek() else {
            return Ok(piece);
        };
        if !matches!(c, b'*' | b'+' | b'?' | b'{') {
            return Ok(piece);
        }
        if c == b'{'
            && !(self.fb_more2()
                && self
                    .fb_peek2()
                    .is_some_and(|d| d.is_ascii_digit() || d == b','))
        {
            return Err(RegexError::BadRepeat);
        }
        self.pos = self.pos.saturating_add(1);
        if wascaret {
            return Err(RegexError::BadRepeat);
        }
        let (from, to) = match c {
            b'*' => (0, NO_END),
            b'+' => (1, NO_END),
            b'?' => (0, 1),
            _ => {
                let count = self.fb_count()?;
                let count2 = if self.fb_eat(b',') {
                    if self.fb_peek().is_some_and(|d| d.is_ascii_digit()) {
                        let count2 = self.fb_count()?;
                        if count > count2 {
                            return Err(RegexError::BadBrace);
                        }
                        count2
                    } else {
                        NO_END
                    }
                } else {
                    count
                };
                if !self.fb_eat(b'}') {
                    while self.fb_more() && !self.fb_see(b'}') {
                        self.pos = self.pos.saturating_add(1);
                    }
                    return Err(if self.fb_more() {
                        RegexError::BadBrace
                    } else {
                        RegexError::Brace
                    });
                }
                (count, count2)
            }
        };
        piece = self.fb_repeat(piece, from, to)?;
        // No repetition of a repetition.
        if let Some(c) = self.fb_peek() {
            if matches!(c, b'*' | b'+' | b'?')
                || (c == b'{'
                    && self.fb_more2()
                    && self.fb_peek2().is_some_and(|d| d.is_ascii_digit()))
            {
                return Err(RegexError::BadRepeat);
            }
        }
        Ok(piece)
    }

    /// `p_simp_re()`: one atom of a basic expression and the repetition
    /// after it, and whether it was a `$` with none, which ends the
    /// expression where it is the last.
    fn fb_simp_re(&mut self, nchain: u32, nest: u32) -> Result<(Piece, bool), RegexError> {
        let item = self.at(self.pos).ok_or(RegexError::Empty)?;
        self.pos = self.pos.saturating_add(1);
        let mut escaped = false;
        let mut c = item.ascii();
        if c == Some(b'\\') {
            if !self.fb_more() {
                return Err(RegexError::Escape);
            }
            escaped = true;
            c = self.at(self.pos).and_then(Item::ascii);
            self.pos = self.pos.saturating_add(1);
        }
        let frag = match (escaped, c) {
            (false, Some(b'.')) => {
                self.charge(2);
                Some(self.unit(".".to_string()))
            }
            (false, Some(b'[')) => Some(self.fb_bracket()?),
            (true, Some(b'<')) => Some(self.fb_look(r"\b{start}", Look::Word(r"\b{start}"))),
            (true, Some(b'>')) => Some(self.fb_look(r"\b{end}", Look::Word(r"\b{end}"))),
            (true, Some(b'{')) => return Err(RegexError::BadRepeat),
            (true, Some(b'(')) => {
                let index = self.nsub;
                self.nsub = self.nsub.saturating_add(1);
                let inner = if self.fb_more() && !self.fb_seetwo(b'\\', b')') {
                    self.fb_re(End::BackslashParen, nest.saturating_add(1))?
                } else {
                    None
                };
                if !self.fb_eattwo(b'\\', b')') {
                    return Err(RegexError::Paren);
                }
                Some(self.fb_group(index, inner)?)
            }
            (true, Some(b')')) => return Err(RegexError::Paren),
            (true, Some(d @ b'1'..=b'9')) => {
                let n = d - b'1';
                if self.completed & (1u16 << n) == 0 {
                    return Err(RegexError::SubReg);
                }
                Some(self.atom("(?:)".to_string(), Node::BackRef(n)))
            }
            (false, Some(b'*')) if nchain != 0 => return Err(RegexError::BadRepeat),
            _ => {
                self.pos = self.pos.saturating_sub(1);
                let ch = self.fb_wgetnext()?;
                if escaped && !Self::fb_may_escape(ch) {
                    return Err(RegexError::Escape);
                }
                Some(self.fb_ordinary(ch)?)
            }
        };
        let piece = Piece {
            frag,
            emitted: true,
        };
        if self.fb_eat(b'*') {
            return Ok((self.fb_repeat(piece, 0, NO_END)?, false));
        }
        if self.fb_eattwo(b'\\', b'{') {
            let count = self.fb_count()?;
            let count2 = if self.fb_eat(b',') {
                if self.fb_peek().is_some_and(|d| d.is_ascii_digit()) {
                    let count2 = self.fb_count()?;
                    if count > count2 {
                        return Err(RegexError::BadBrace);
                    }
                    count2
                } else {
                    NO_END
                }
            } else {
                count
            };
            if !self.fb_eattwo(b'\\', b'}') {
                while self.fb_more() && !self.fb_seetwo(b'\\', b'}') {
                    self.pos = self.pos.saturating_add(1);
                }
                return Err(if self.fb_more() {
                    RegexError::BadBrace
                } else {
                    RegexError::Brace
                });
            }
            return Ok((self.fb_repeat(piece, count, count2)?, false));
        }
        Ok((piece, !escaped && c == Some(b'$')))
    }

    /// `p_count()`: a repetition's count, at most [`DUPMAX`].
    fn fb_count(&mut self) -> Result<i64, RegexError> {
        let mut count = 0i64;
        let mut digits = 0u32;
        while let Some(d) = self.fb_peek().filter(u8::is_ascii_digit) {
            if count > DUPMAX {
                break;
            }
            count = count * 10 + i64::from(d - b'0');
            digits = digits.saturating_add(1);
            self.pos = self.pos.saturating_add(1);
        }
        if digits == 0 || count > DUPMAX {
            return Err(RegexError::BadBrace);
        }
        Ok(count)
    }

    /// `repeat()` and its like: `piece` `from` to `to` times. `{0}` drops
    /// it from the program. An anchor or a word's end matches no
    /// character, so repeated it is itself, or nothing where it may be
    /// left out.
    fn fb_repeat(&mut self, piece: Piece, from: i64, to: i64) -> Result<Piece, RegexError> {
        if from == 0 && to == 0 {
            self.charge(1);
            return Ok(Piece {
                frag: None,
                emitted: false,
            });
        }
        let zero_width = piece
            .frag
            .as_ref()
            .is_some_and(|f| matches!(self.tree.nodes.get(f.node as usize), Some(Node::Look(_))));
        if zero_width {
            self.charge(1);
            return Ok(Piece {
                frag: if from == 0 { None } else { piece.frag },
                emitted: true,
            });
        }
        Ok(Piece {
            frag: self.repeat_frag(piece.frag, from, to)?,
            emitted: true,
        })
    }

    /// A group, number `index` from 0, around `inner`; it is closed, and a
    /// back-reference may name it from here on (`p->pend[]`).
    fn fb_group(&mut self, index: usize, inner: Option<Frag>) -> Result<Frag, RegexError> {
        if index < 9 {
            self.completed |= 1u16 << index;
        }
        let depth = inner.as_ref().map_or(0, |f| f.depth);
        let s = format!("(?:{})", inner.as_ref().map_or("", |f| &f.s));
        let child = self.node_of(inner.as_ref());
        let node = self.tree.push(Node::Group { index, child });
        Ok(nested(s, depth, node)?.unwrap_or(Frag {
            s: String::new(),
            node,
            atomic: true,
            depth: 1,
        }))
    }

    /// `p_bracket()`: a list, its `[` read.
    fn fb_bracket(&mut self) -> Result<Frag, RegexError> {
        // "Dept of Truly Sickening Special-Case Kludges": the word's ends.
        if self.items.len().saturating_sub(self.pos) > 5 {
            let ahead: Vec<Option<u8>> = (0..6)
                .map(|i| self.at(self.pos.saturating_add(i)).and_then(Item::ascii))
                .collect();
            for (text, look) in [(b"[:<:]]", r"\b{start}"), (b"[:>:]]", r"\b{end}")] {
                if ahead.iter().zip(text.iter()).all(|(a, b)| *a == Some(*b)) {
                    self.pos = self.pos.saturating_add(6);
                    return Ok(self.fb_look(look, Look::Word(look)));
                }
            }
        }
        let mut list = List::default();
        let negated = self.fb_eat(b'^');
        if negated {
            self.charge(1);
        }
        if self.fb_eat(b']') {
            list.add(']');
        } else if self.fb_eat(b'-') {
            list.add('-');
        }
        while self.fb_more() && !self.fb_see(b']') && !self.fb_seetwo(b'-', b']') {
            self.charge(1);
            self.fb_b_term(&mut list)?;
        }
        if self.fb_eat(b'-') {
            list.add('-');
        }
        if !self.fb_eat(b']') {
            return Err(RegexError::Bracket);
        }
        if self.fb.icase {
            return self.fb_case_list(&list, negated);
        }
        Ok(self.fb_list(list, negated))
    }

    /// `p_b_term()`: one element of a list.
    fn fb_b_term(&mut self, list: &mut List) -> Result<(), RegexError> {
        let c = match self.fb_peek() {
            Some(b'[') => self.fb_peek2(),
            Some(b'-') => return Err(RegexError::Range),
            _ => None,
        };
        match c {
            Some(b':') => {
                self.pos = self.pos.saturating_add(2);
                if !self.fb_more() {
                    return Err(RegexError::Bracket);
                }
                if matches!(self.fb_peek(), Some(b'-' | b']')) {
                    return Err(RegexError::CharClass);
                }
                // `p_b_cclass()`: the letters of the name.
                let start = self.pos;
                while self
                    .at(self.pos)
                    .is_some_and(|i| matches!(i, Item::Char(c) if c.is_alphabetic()))
                {
                    self.pos = self.pos.saturating_add(1);
                }
                let name: String = self.items[start..self.pos]
                    .iter()
                    .filter_map(|i| match i {
                        Item::Char(c) => Some(*c),
                        Item::Byte(_) => None,
                    })
                    .collect();
                if name.len() >= 15 {
                    return Err(RegexError::CharClass);
                }
                let set = fb_class_set(name.as_bytes()).ok_or(RegexError::CharClass)?;
                self.charge(class_cost(name.as_bytes()));
                if !list.classes.contains(&set) {
                    list.classes.push(set);
                }
                if !self.fb_more() {
                    return Err(RegexError::Bracket);
                }
                if !self.fb_eattwo(b':', b']') {
                    return Err(RegexError::CharClass);
                }
            }
            Some(b'=') => {
                self.pos = self.pos.saturating_add(2);
                if !self.fb_more() {
                    return Err(RegexError::Bracket);
                }
                if matches!(self.fb_peek(), Some(b'-' | b']')) {
                    return Err(RegexError::Collate);
                }
                let c = self.fb_coll_elem(b'=')?;
                list.add(c);
                if !self.fb_more() {
                    return Err(RegexError::Bracket);
                }
                if !self.fb_eattwo(b'=', b']') {
                    return Err(RegexError::Collate);
                }
            }
            _ => {
                let start = self.fb_b_symbol()?;
                let finish =
                    if self.fb_see(b'-') && self.fb_more2() && self.fb_peek2() != Some(b']') {
                        self.pos = self.pos.saturating_add(1);
                        if self.fb_eat(b'-') {
                            '-'
                        } else {
                            self.fb_b_symbol()?
                        }
                    } else {
                        start
                    };
                if start == finish {
                    list.add(start);
                } else {
                    // A UTF-8 locale: code points, not collation.
                    if start > finish {
                        return Err(RegexError::Range);
                    }
                    // `CHaddrange()` adds what is below `NC` one by one, and
                    // the rest only where it is more than one character.
                    let finish = if u32::from(start) < NC && u32::from(finish) == NC {
                        '\u{7f}'
                    } else {
                        finish
                    };
                    if start == finish {
                        list.add(start);
                    } else {
                        list.ranges.push((start, finish));
                    }
                }
            }
        }
        Ok(())
    }

    /// `p_b_symbol()`: a character, or a `[.name.]`.
    fn fb_b_symbol(&mut self) -> Result<char, RegexError> {
        if !self.fb_more() {
            return Err(RegexError::Bracket);
        }
        if !self.fb_eattwo(b'[', b'.') {
            return self.fb_wgetnext();
        }
        let value = self.fb_coll_elem(b'.')?;
        if !self.fb_eattwo(b'.', b']') {
            return Err(RegexError::Collate);
        }
        Ok(value)
    }

    /// `p_b_coll_elem()`: the name up to `endc` and `]`, which must be a
    /// name of `cname.h` or one character.
    fn fb_coll_elem(&mut self, endc: u8) -> Result<char, RegexError> {
        let start = self.pos;
        while self.fb_more() && !self.fb_seetwo(endc, b']') {
            self.pos = self.pos.saturating_add(1);
        }
        if !self.fb_more() {
            return Err(RegexError::Bracket);
        }
        let name = &self.items[start..self.pos];
        let text: Option<String> = name
            .iter()
            .map(|i| match i {
                Item::Char(c) => Some(*c),
                Item::Byte(_) => None,
            })
            .collect();
        if let Some(text) = &text {
            if let Some(&(_, c)) = CNAMES.iter().find(|(n, _)| n == text) {
                return Ok(c);
            }
        }
        // `mbrtowc()` of the name: one character is that character; none
        // (an empty name) or a byte that starts none is `REG_ILLSEQ`.
        match name.first() {
            Some(Item::Char(c)) if name.len() == 1 => Ok(*c),
            Some(Item::Char(_)) => Err(RegexError::Collate),
            _ => Err(RegexError::IllSeq),
        }
    }

    /// A list under `REG_ICASE`, in the engines' syntax: what FreeBSD's
    /// `CHIN()` takes of the set `CHadd()`, `CHaddrange()` and `CHaddtype()`
    /// made of it.
    ///
    /// Below `NC` (ASCII) a character is in the set where its bit is: each
    /// character added, and the `towlower()` and `towupper()` of each that
    /// are below `NC`. Past it a character is in the set where it, its
    /// `towlower()` or its `towupper()` is (`CHIN1()`): below `NC` by the
    /// bitmap, past it where it is the `towlower()` or `towupper()` of a
    /// character added, in a range or in a class; a negated list's `CHIN1()`
    /// is the opposite of each, and still any of the three will do. A
    /// character neither table changes is thus in the set where `CHIN1()`
    /// puts it, and the list is written as that (its `base`) for every
    /// character past ASCII, the ASCII characters it takes one by one, and
    /// each character of [`FB_CASE`] the three take that `base` does not.
    fn fb_case_list(&mut self, list: &List, negated: bool) -> Result<Frag, RegexError> {
        // `CHadd()`, each character and each of a range below `NC`;
        // `CHaddrange()` keeps the rest; `CHaddtype()` the class.
        let mut bitmap = 0u128;
        let mut wides: Vec<char> = Vec::new();
        let mut ranges: Vec<(char, char)> = Vec::new();
        for &(lo, hi) in &list.ranges {
            if lo == hi {
                chadd(lo, &mut bitmap, &mut wides);
                continue;
            }
            let mut c = u32::from(lo);
            while c < NC && c <= u32::from(hi) {
                if let Some(ch) = char::from_u32(c) {
                    chadd(ch, &mut bitmap, &mut wides);
                }
                c = c.saturating_add(1);
            }
            if c < u32::from(hi) {
                ranges.push((char::from_u32(c).unwrap_or(lo), hi));
            }
        }
        let mut classes = list.classes.clone();
        classes.sort_unstable();
        classes.dedup();
        for class in &classes {
            let table = class_ranges(class);
            for c in 0..NC {
                if let Some(ch) = char::from_u32(c) {
                    if in_ranges(table, ch) {
                        chadd(ch, &mut bitmap, &mut wides);
                    }
                }
            }
        }
        wides.sort_unstable();
        wides.dedup();
        ranges.sort_unstable();
        ranges.dedup();
        let key: CaseKey = (negated, bitmap, wides, ranges, classes);
        let text = match self.fb.lists.get(&key) {
            Some(text) => text.clone(),
            None => {
                let text = self.fb_case_text(&key)?;
                self.fb.lists.insert(key, text.clone());
                text
            }
        };
        self.fb.work = self.fb.work.saturating_add(
            CASE_TEXT_COST.saturating_mul(u64::try_from(text.len()).unwrap_or(u64::MAX)),
        );
        if self.fb.work > CASE_WORK_LIMIT {
            return Err(RegexError::Size);
        }
        // What the engine is asked: a unit for every eight bytes written (a
        // range is about sixteen), and the classes, charged as they were
        // read.
        self.charge(u64::try_from(text.len() / 8).unwrap_or(u64::MAX));
        Ok(self.atom(
            text.clone(),
            Node::Unit(UnitSpec {
                negated: false,
                sets: vec![text],
            }),
        ))
    }

    /// The text of a case list ([`Self::fb_case_list`]).
    fn fb_case_text(&mut self, key: &CaseKey) -> Result<String, RegexError> {
        let (negated, bitmap, wides, ranges, classes) = key;
        self.fb.work = self
            .fb
            .work
            .saturating_add(u64::try_from(FB_CASE.len()).unwrap_or(u64::MAX));
        if self.fb.work > CASE_WORK_LIMIT {
            return Err(RegexError::Size);
        }
        // What `CHIN1()` finds past `NC` before it is negated: the other
        // cases of the characters added, a range, a class.
        let mut hit: Vec<(char, char)> = wides
            .iter()
            .flat_map(|&w| [lower(w), upper(w)])
            .map(|c| (c, c))
            .chain(ranges.iter().copied())
            .collect();
        for class in classes {
            hit.extend_from_slice(class_ranges(class));
        }
        let hit = merge(hit);
        let in_bitmap = |x: char| u32::from(x) < NC && bitmap & (1u128 << u32::from(x)) != 0;
        let chin1 = |x: char| {
            let found = if u32::from(x) < NC {
                in_bitmap(x)
            } else {
                in_ranges(&hit, x)
            };
            found != *negated
        };
        let chin = |c: char| {
            if u32::from(c) < NC {
                in_bitmap(c) != *negated
            } else {
                chin1(c) || chin1(lower(c)) || chin1(upper(c))
            }
        };
        // The ASCII characters it takes, and the characters of `FB_CASE` it
        // takes that `base` does not, as runs; a run goes on over what the
        // list takes anyway (`base`), where that is near, so that a case
        // list of thousands is written in a few hundred.
        let mut runs: Vec<(char, char)> = Vec::new();
        let push = |c: char, runs: &mut Vec<(char, char)>, work: &mut u64| {
            if let Some(last) = runs.last_mut() {
                let gap = u32::from(c).saturating_sub(u32::from(last.1));
                if gap <= RUN_GAP {
                    let between = (u32::from(last.1).saturating_add(1)..u32::from(c))
                        .all(|x| char::from_u32(x).is_some_and(&chin));
                    *work = work.saturating_add(u64::from(gap));
                    if between {
                        last.1 = c;
                        return;
                    }
                }
            }
            runs.push((c, c));
        };
        let mut work = 0u64;
        for c in (0..NC).filter_map(char::from_u32).filter(|&c| chin(c)) {
            push(c, &mut runs, &mut work);
        }
        for &(c, _, _, _) in FB_CASE {
            if u32::from(c) >= NC && chin(c) && !chin1(c) {
                push(c, &mut runs, &mut work);
            }
        }
        self.fb.work = self.fb.work.saturating_add(work);
        let mut text = String::from("[");
        for (lo, hi) in runs {
            push_char(&mut text, lo);
            if lo != hi {
                text.push('-');
                push_char(&mut text, hi);
            }
        }
        // `base`: what `CHIN1()` takes past ASCII, as it was read.
        let mut base = String::new();
        let others = wides.iter().flat_map(|&w| [lower(w), upper(w)]);
        for (lo, hi) in merge(
            others
                .map(|c| (c, c))
                .chain(ranges.iter().copied())
                .collect(),
        ) {
            push_char(&mut base, lo);
            if lo != hi {
                base.push('-');
                push_char(&mut base, hi);
            }
        }
        for class in classes {
            base.push('[');
            base.push_str(class);
            base.push(']');
        }
        if *negated || !base.is_empty() {
            let base = if base.is_empty() {
                r"\x{0}-\x{10FFFF}".to_string()
            } else if *negated {
                format!("^{base}")
            } else {
                base
            };
            text.push_str("[[");
            text.push_str(&base);
            text.push_str(r"]--[\x{0}-\x{7F}]]");
        }
        if text.len() == 1 {
            return Ok(super::NOTHING.to_string());
        }
        text.push(']');
        Ok(text)
    }

    /// The list read, in the engines' syntax.
    fn fb_list(&mut self, list: List, negated: bool) -> Frag {
        let mut own = String::new();
        for &(lo, hi) in &list.ranges {
            push_char(&mut own, lo);
            if lo != hi {
                own.push('-');
                push_char(&mut own, hi);
            }
        }
        let mut set = own.clone();
        for class in &list.classes {
            set.push('[');
            set.push_str(class);
            set.push(']');
        }
        let s = if negated {
            format!("[^{set}]")
        } else {
            format!("[{set}]")
        };
        let mut sets = Vec::with_capacity(list.classes.len().saturating_add(1));
        if !own.is_empty() {
            sets.push(format!("[{own}]"));
        }
        sets.extend(list.classes.iter().map(|c| format!("[{c}]")));
        self.atom(s, Node::Unit(UnitSpec { negated, sets }))
    }
}

/// What a list holds: characters and ranges of them, in the order read,
/// and classes.
#[derive(Default)]
struct List {
    ranges: Vec<(char, char)>,
    classes: Vec<&'static str>,
}

impl List {
    fn add(&mut self, c: char) {
        self.ranges.push((c, c));
    }
}

/// `wctype()`'s classes under FreeBSD's UTF-8 locale, in the engine's
/// Unicode properties: POSIX's twelve and FreeBSD's own five. FreeBSD's
/// tables are built from Unicode's general categories, by these rules, as
/// a dump of `iswctype()` over every code point on FreeBSD 14.5 shows
/// (every class, every code point that both Unicode versions assign):
/// `alpha` is the letters alone (not glibc's digits of other scripts or
/// letter numbers), `cntrl` takes the format characters but U+FEFF,
/// `punct` is the punctuation and ASCII's symbols, `graph` the private
/// use too, `blank` only the tab and the space; `number` is `digit`,
/// `rune` every character, and `ideogram`, `phonogram` and `special` take
/// none.
fn fb_class_set(name: &[u8]) -> Option<&'static str> {
    Some(match name {
        b"alpha" => r"\p{L}",
        b"alnum" => r"\p{L}\p{Nd}",
        b"upper" => r"\p{Lu}",
        b"lower" => r"\p{Ll}",
        b"digit" | b"number" => r"\p{Nd}",
        b"xdigit" => r"\p{Nd}A-Fa-f",
        b"space" => r"\t\n\x0B\x0C\r\p{Zs}\p{Zl}\p{Zp}",
        b"blank" => r"\t\x20",
        b"cntrl" => r"\p{Cc}[\p{Cf}--\x{FEFF}]",
        b"punct" => r"\p{P}$+<=>^`|~",
        b"graph" => r"\p{L}\p{M}\p{N}\p{P}\p{S}\p{Co}",
        b"print" => r"\p{L}\p{M}\p{N}\p{P}\p{S}\p{Co}\p{Zs}\p{Zl}\p{Zp}",
        b"rune" => r"[^\p{Cn}\x{FEFF}]",
        b"ideogram" | b"phonogram" | b"special" => r"[^\x{0}-\x{10FFFF}]",
        _ => return None,
    })
}

/// The entry of [`FB_CASE`] for `c`, if either table changes it.
fn case_of(c: char) -> Option<(char, char, char, u8)> {
    FB_CASE
        .binary_search_by_key(&c, |&(from, _, _, _)| from)
        .ok()
        .and_then(|i| FB_CASE.get(i))
        .copied()
}

/// FreeBSD's `towlower()`.
fn lower(c: char) -> char {
    case_of(c).map_or(c, |(_, l, _, _)| l)
}

/// FreeBSD's `towupper()`.
fn upper(c: char) -> char {
    case_of(c).map_or(c, |(_, _, u, _)| u)
}

/// `othercase()`: an upper case letter's `towlower()`, a lower case one's
/// `towupper()`, any other character itself.
fn othercase(c: char) -> char {
    match case_of(c) {
        Some((_, l, _, flags)) if flags & UPPER != 0 => l,
        Some((_, _, u, flags)) if flags & LOWER != 0 => u,
        _ => c,
    }
}

/// Whether `c` is a letter, `iswalpha()`'s (general category L).
fn is_letter(c: char) -> bool {
    if c.is_ascii() {
        return c.is_ascii_alphabetic();
    }
    fb_class_set(b"alpha").is_some_and(|set| in_ranges(class_ranges(set), c))
}

/// The characters of one of [`fb_class_set`]'s sets, as `regex-syntax`
/// reads them, which is how the engines take them; read once.
fn class_ranges(set: &str) -> &'static [(char, char)] {
    const NAMES: [&[u8]; 15] = [
        b"alpha",
        b"alnum",
        b"upper",
        b"lower",
        b"digit",
        b"xdigit",
        b"space",
        b"blank",
        b"cntrl",
        b"punct",
        b"graph",
        b"print",
        b"rune",
        b"ideogram",
        b"number",
    ];
    type Tables = Vec<(&'static str, Vec<(char, char)>)>;
    static TABLES: OnceLock<Tables> = OnceLock::new();
    let tables = TABLES.get_or_init(|| {
        let mut tables: Tables = Vec::new();
        for set in NAMES.iter().filter_map(|name| fb_class_set(name)) {
            if tables.iter().any(|(s, _)| *s == set) {
                continue;
            }
            let parsed = regex_syntax::ParserBuilder::new()
                .utf8(false)
                .unicode(true)
                .build()
                .parse(&format!("[{set}]"));
            let ranges = match parsed.map(regex_syntax::hir::Hir::into_kind) {
                Ok(regex_syntax::hir::HirKind::Class(regex_syntax::hir::Class::Unicode(class))) => {
                    class
                        .ranges()
                        .iter()
                        .map(|r| (r.start(), r.end()))
                        .collect()
                }
                // An empty class is no class to `regex-syntax`.
                _ => Vec::new(),
            };
            tables.push((set, ranges));
        }
        tables
    });
    tables
        .iter()
        .find(|(s, _)| *s == set)
        .map_or(&[][..], |(_, r)| r.as_slice())
}

/// Ranges sorted, and those that touch or overlap made one.
fn merge(mut ranges: Vec<(char, char)>) -> Vec<(char, char)> {
    ranges.sort_unstable();
    let mut merged: Vec<(char, char)> = Vec::with_capacity(ranges.len());
    for (lo, hi) in ranges {
        if let Some(last) = merged.last_mut() {
            if u32::from(lo) <= u32::from(last.1).saturating_add(1) {
                last.1 = last.1.max(hi);
                continue;
            }
        }
        merged.push((lo, hi));
    }
    merged
}

/// Whether `c` is in `ranges`, sorted and apart.
fn in_ranges(ranges: &[(char, char)], c: char) -> bool {
    let i = ranges.partition_point(|&(_, hi)| hi < c);
    ranges.get(i).is_some_and(|&(lo, _)| lo <= c)
}

/// `CHadd()` under `REG_ICASE`: `c` in the bitmap below `NC` and among the
/// characters past it, and its `towlower()` and `towupper()` in the bitmap
/// where they are below `NC`.
fn chadd(c: char, bitmap: &mut u128, wides: &mut Vec<char>) {
    for x in [c, lower(c), upper(c)] {
        if u32::from(x) < NC {
            *bitmap |= 1u128 << u32::from(x);
        }
    }
    if u32::from(c) >= NC {
        wides.push(c);
    }
}

#[cfg(test)]
mod tests {
    use super::super::{translate_in, CommandRegex, Dialect, COST_LIMIT, NEST_LIMIT, TREE_LIMIT};
    use super::*;

    fn read(expression: &str, extended: bool, icase: bool) -> Result<(), RegexError> {
        translate_in(Dialect::FreeBsd, expression.as_bytes(), extended, icase).map(|_| ())
    }

    fn regex(expression: &str, extended: bool, icase: bool) -> CommandRegex {
        CommandRegex::new_in(Dialect::FreeBsd, expression.as_bytes(), extended, icase)
            .unwrap_or_else(|e| panic!("{expression:?}: {e:?}"))
    }

    /// The bounds glibc's grammar has (`posix_regex.rs`) hold FreeBSD's
    /// too: nesting, the crate's cost, the tree, and its own case lists'
    /// work. The guard at the head of `fb_re()` is what holds the
    /// recursion: 200,000 groups are refused before they are read, not
    /// after the stack is gone.
    #[test]
    #[cfg_attr(miri, ignore = "it reads expressions of 200,000 groups")]
    fn the_freebsd_grammar_is_bounded() {
        assert_eq!(NEST_LIMIT, 100);
        let ere = |n: usize| format!("{}a{}", "(".repeat(n), ")".repeat(n));
        let bre = |n: usize| format!("{}a{}", "\\(".repeat(n), "\\)".repeat(n));
        for icase in [false, true] {
            assert_eq!(read(&ere(99), true, icase), Ok(()));
            assert_eq!(read(&ere(100), true, icase), Err(RegexError::Size));
            assert_eq!(read(&ere(101), true, icase), Err(RegexError::Size));
            assert_eq!(read(&bre(99), false, icase), Ok(()));
            assert_eq!(read(&bre(100), false, icase), Err(RegexError::Size));
            assert_eq!(read(&bre(101), false, icase), Err(RegexError::Size));
            for n in [101, 200_000] {
                assert_eq!(read(&ere(n), true, icase), Err(RegexError::Size));
                assert_eq!(read(&bre(n), false, icase), Err(RegexError::Size));
                // Unclosed, they are refused for their depth all the same
                // (and 101 `(` for the 101st, which closes nothing).
                let open = if n == 101 {
                    RegexError::Paren
                } else {
                    RegexError::Size
                };
                assert_eq!(read(&"(".repeat(n), true, icase), Err(open));
                assert_eq!(read(&"\\(".repeat(n), false, icase), Err(open));
                let alternatives = format!("{}a{}", "(a|".repeat(n), ")".repeat(n));
                assert_eq!(read(&alternatives, true, icase), Err(RegexError::Size));
            }
        }
        // The crate's cost: past it, lsof-rs's own engine, the same answer.
        let most = usize::try_from(COST_LIMIT).unwrap();
        let within = regex(&"a".repeat(most), true, false);
        let past = regex(&"a".repeat(most + 1), true, false);
        assert!(!within.is_own() && past.is_own());
        assert!(!past.is_match(b"aaa"));
        let past = regex(&"[[:alpha:]]".repeat(64), true, false);
        assert!(past.is_own());
        assert!(past.is_match("é".repeat(64).as_bytes()));
        assert!(!past.is_match("é".repeat(63).as_bytes()));
        // A letter with another case under `i` is a list, which costs what
        // it is written in: past the limit sooner than without `i`.
        let cost = |e: &str, icase| {
            translate_in(Dialect::FreeBsd, e.as_bytes(), true, icase)
                .unwrap()
                .cost
        };
        assert!(cost("[[:upper:]]", true) > cost("[[:upper:]]", false) + 100);
        let n = (1..64)
            .find(|&n| regex(&"[[:upper:]]".repeat(n), true, true).is_own())
            .unwrap();
        assert!(!regex(&"[[:upper:]]".repeat(n), true, false).is_own());
        // The tree.
        assert_eq!(read(&"a".repeat(TREE_LIMIT - 1), true, false), Ok(()));
        assert_eq!(
            read(&"a".repeat(TREE_LIMIT), true, false),
            Err(RegexError::Size)
        );
        // The case lists: a list read once for its text, and its text for
        // each time it is written.
        assert_eq!(CASE_WORK_LIMIT, 1 << 24);
        assert_eq!(read(&"[[:upper:]]".repeat(10_000), true, true), Ok(()));
        assert_eq!(
            read(&"[[:upper:]]".repeat(20_000), true, true),
            Err(RegexError::Size)
        );
        let distinct = |n: u32, class: &str| -> String {
            (0..n)
                .filter_map(|k| char::from_u32(0x10000 + k))
                .map(|c| format!("[{c}{class}]"))
                .collect()
        };
        assert_eq!(read(&distinct(4_000, ""), true, true), Ok(()));
        assert_eq!(read(&distinct(4_000, ""), true, false), Ok(()));
        assert_eq!(
            read(&distinct(8_000, ""), true, true),
            Err(RegexError::Size)
        );
        assert_eq!(read(&distinct(8_000, ""), true, false), Ok(()));
        assert_eq!(read(&distinct(1_000, "[:upper:]"), true, true), Ok(()));
        assert_eq!(
            read(&distinct(8_000, "[:upper:]"), true, true),
            Err(RegexError::Size)
        );
        // Without `i` no list is written out, and none is bounded so.
        assert_eq!(read(&"[[:upper:]]".repeat(20_000), true, false), Ok(()));
        // A letter repeated is one list, however many times.
        assert_eq!(read(&"İ".repeat(100_000), false, true), Ok(()));
    }

    /// `may_escape()`: a backslash before a letter is refused, and before
    /// anything else taken, a letter being `iswalpha()`'s, general category
    /// L, as FreeBSD 14.5 measured: not a letter number (`Ⅻ`), a circled
    /// letter (`ⓐ`), or a mark Unicode calls alphabetic.
    #[test]
    fn a_backslash_before_a_letter_alone_is_refused() {
        for extended in [true, false] {
            for c in [
                "Ⅻ", "Ⅰ", "ⓐ", "Ⓐ", "\u{345}", "\u{670}", "\u{903}", "\u{1885}", "\u{e31}", "٠",
                "½", "⁰", "|", "1",
            ] {
                if c == "1" && !extended {
                    continue;
                }
                let e = format!("x\\{c}");
                assert_eq!(read(&e, extended, false), Ok(()), "{e}");
                assert!(regex(&e, extended, false).is_match(format!("x{c}").as_bytes()));
            }
            for c in ["ª", "ǅ", "〆", "ʰ", "µ", "א", "中", "a", "Z", "w", "`", "'"] {
                let e = format!("x\\{c}");
                assert_eq!(read(&e, extended, false), Err(RegexError::Escape), "{e}");
            }
        }
    }

    /// `REG_ICASE` as FreeBSD 14.5 has it (each answer measured there).
    #[test]
    fn a_case_is_freebsds_under_icase() {
        let m = |e: &str, extended: bool, command: &str| {
            regex(e, extended, true).is_match(command.as_bytes())
        };
        // `İ` is `[İi]`: `towlower(İ)` is `i`, and `I` is no case of it.
        assert!(m("^İ$", true, "i") && m("^İ$", true, "İ") && !m("^İ$", true, "I"));
        assert!(m("^i$", true, "İ") && m("^i$", true, "ı") && m("^I$", true, "İ"));
        assert!(m("abcdefghijklmnopqrs", true, "abcdefghijklmnopqrs"));
        assert!(m("İ", true, "abcdefghijklmnopqrs"));
        // The Kelvin sign is `[\u{212A}k]`, not `K`.
        for e in ["^x\u{212a}$", "^x[\u{212a}]$"] {
            assert!(m(e, true, "xk") && m(e, true, "x\u{212a}") && !m(e, true, "xK"));
        }
        assert!(m("^K$", true, "\u{212a}") && m("^k$", true, "\u{212a}"));
        // `ſ` is an `S`'s, `ß` has no other case, `ǅ` has none of its own.
        assert!(m("^s$", true, "ſ") && m("^ſ$", true, "S") && !m("^ſ$", true, "s"));
        assert!(m("^ß$", true, "ß") && !m("^ß$", true, "ẞ") && m("^ẞ$", true, "ß"));
        assert!(m("^ǅ$", true, "ǅ") && !m("^ǅ$", true, "ǆ") && !m("^ǅ$", true, "Ǆ"));
        assert!(m("^[ǅ]$", true, "ǆ") && m("^[ǅ]$", true, "Ǆ") && !m("^[^ǅ]$", true, "ǅ"));
        // A class: the characters whose `towlower()` or `towupper()` it has.
        assert!(m("^[[:upper:]]$", true, "ÿ") && m("^[[:upper:]]$", true, "µ"));
        assert!(!m("^[[:upper:]]$", true, "ß") && m("^[[:lower:]]$", true, "ß"));
        assert!(m("^[^[:upper:]]$", true, "ı") && !m("^[^[:upper:]]$", true, "a"));
        assert!(m("^[À-Þ]$", true, "×") && m("^[À-Þ]$", true, "à") && !m("^[À-Þ]$", true, "÷"));
        // A back-reference is the bytes its group matched, in their case.
        assert!(m("^\\(a\\)\\1$", false, "aa") && !m("^\\(a\\)\\1$", false, "aA"));
        assert!(m("^\\(.\\)\\1$", false, "éé") && !m("^\\(.\\)\\1$", false, "éÉ"));
        // Without `i` nothing is folded.
        assert!(!regex("^İ$", true, false).is_match(b"i"));
    }

    /// Each list under `i` takes what FreeBSD's `CHIN()` takes, read here
    /// line by line from `regcomp.c` and `regex2.h` (`CHadd()`,
    /// `CHaddrange()`, `CHaddtype()`, `CHIN1()`, `CHIN()`, `NC` 128), for
    /// every character below U+3000, every character of [`FB_CASE`] and
    /// those beside them, and some past them: the runs a list is written in
    /// go over no character it does not take.
    #[test]
    #[cfg_attr(miri, ignore = "tens of thousands of searches")]
    fn a_list_under_icase_takes_what_chin_takes() {
        struct Cset {
            bmp: [bool; 128],
            wides: Vec<char>,
            ranges: Vec<(char, char)>,
            types: Vec<&'static [(char, char)]>,
            invert: bool,
        }
        impl Cset {
            fn chadd(&mut self, ch: char) {
                if (ch as u32) < 128 {
                    self.bmp[ch as usize] = true;
                } else {
                    self.wides.push(ch);
                }
                for nch in [lower(ch), upper(ch)] {
                    if (nch as u32) < 128 {
                        self.bmp[nch as usize] = true;
                    }
                }
            }
            fn chaddrange(&mut self, min: char, max: char) {
                let mut min = min as u32;
                while min < 128 && min <= max as u32 {
                    self.chadd(char::from_u32(min).unwrap());
                    min += 1;
                }
                if min >= max as u32 {
                    return;
                }
                self.ranges.push((char::from_u32(min).unwrap(), max));
            }
            fn chaddtype(&mut self, t: &'static [(char, char)]) {
                for i in 0..128u8 {
                    if in_ranges(t, char::from(i)) {
                        self.chadd(char::from(i));
                    }
                }
                self.types.push(t);
            }
            fn chin1(&self, ch: char) -> bool {
                if (ch as u32) < 128 {
                    return self.bmp[ch as usize] ^ self.invert;
                }
                for &w in &self.wides {
                    if ch == lower(w) || ch == upper(w) {
                        return !self.invert;
                    }
                }
                for &(min, max) in &self.ranges {
                    if min <= ch && ch <= max {
                        return !self.invert;
                    }
                }
                for t in &self.types {
                    if in_ranges(t, ch) {
                        return !self.invert;
                    }
                }
                self.invert
            }
            fn chin(&self, ch: char) -> bool {
                if (ch as u32) < 128 {
                    return self.bmp[ch as usize] ^ self.invert;
                }
                self.chin1(ch) || self.chin1(lower(ch)) || self.chin1(upper(ch))
            }
        }
        // Negated, its characters, its ranges, its classes.
        type Spec = (
            bool,
            &'static str,
            &'static [(char, char)],
            &'static [&'static str],
        );
        let lists: [Spec; 16] = [
            (false, "", &[], &["upper"]),
            (true, "", &[], &["upper"]),
            (false, "", &[], &["lower"]),
            (true, "x", &[], &["lower"]),
            (false, "", &[], &["alpha", "punct"]),
            (true, "\u{3a9}", &[], &["space"]),
            (false, "", &[('\u{100}', '\u{17f}')], &[]),
            (true, "", &[('\u{100}', '\u{17f}')], &[]),
            (false, "", &[('a', '\u{80}')], &[]),
            (true, "", &[('a', '\u{80}')], &[]),
            (false, "\u{1c5}\u{130}\u{212a}\u{b5}", &[], &[]),
            (true, "\u{1c5}\u{130}\u{212a}\u{b5}", &[], &[]),
            (
                false,
                "",
                &[('\u{c0}', '\u{de}'), ('\u{391}', '\u{3a9}')],
                &[],
            ),
            (false, "k", &[('A', '\u{212a}')], &["digit"]),
            (true, "", &[('\u{2160}', '\u{2188}')], &["cntrl"]),
            (false, "\u{345}\u{24b6}", &[], &["graph"]),
        ];
        let mut chars: Vec<char> = (0..0x3000).filter_map(char::from_u32).collect();
        for &(c, l, u, _) in FB_CASE {
            for x in [c, l, u] {
                for d in [-1i64, 0, 1] {
                    chars.extend(char::from_u32((x as i64 + d) as u32));
                }
            }
        }
        chars.extend([
            '\u{ff21}',
            '\u{ff41}',
            '\u{10400}',
            '\u{10428}',
            '\u{1e900}',
            '\u{10ffff}',
        ]);
        chars.sort_unstable();
        chars.dedup();
        for (invert, own, ranges, classes) in lists {
            let mut cs = Cset {
                bmp: [false; 128],
                wides: Vec::new(),
                ranges: Vec::new(),
                types: Vec::new(),
                invert,
            };
            let mut e = String::from(if invert { "^[^" } else { "^[" });
            for c in own.chars() {
                cs.chadd(c);
                e.push(c);
            }
            for &(lo, hi) in ranges {
                cs.chaddrange(lo, hi);
                e.push(lo);
                e.push('-');
                e.push(hi);
            }
            for class in classes {
                cs.chaddtype(class_ranges(fb_class_set(class.as_bytes()).unwrap()));
                e.push_str(&format!("[:{class}:]"));
            }
            e.push_str("]$");
            let crate_ = regex(&e, true, true);
            let engine =
                CommandRegex::new_own_in(Dialect::FreeBsd, e.as_bytes(), true, true).unwrap();
            for &c in &chars {
                let command = c.to_string();
                let want = cs.chin(c);
                assert_eq!(crate_.is_match(command.as_bytes()), want, "{e:?} {c:?}");
                if c as u32 % 7 == 0 || case_of(c).is_some() {
                    assert_eq!(engine.is_match(command.as_bytes()), want, "own {e:?} {c:?}");
                }
            }
        }
    }

    /// `CHaddrange()`: a range that ends at U+0080 leaves it out.
    #[test]
    fn a_range_that_ends_at_u0080_leaves_it_out() {
        for icase in [false, true] {
            let r = regex("^[a-\u{80}]$", true, icase);
            assert!(r.is_match(b"a") && r.is_match(b"\x7f") && !r.is_match("\u{80}".as_bytes()));
            let r = regex("^[^a-\u{80}]$", true, icase);
            assert!(r.is_match("\u{80}".as_bytes()) && !r.is_match(b"\x7f"));
            assert!(regex("^[a-\u{81}]$", true, icase).is_match("\u{80}".as_bytes()));
            assert!(regex("^[\u{80}-\u{81}]$", true, icase).is_match("\u{80}".as_bytes()));
        }
    }

    /// The table is FreeBSD's: sorted, and every mapping one of a
    /// character for one, as `casedump.c` read them.
    #[test]
    fn the_case_table_is_sorted_and_freebsds() {
        assert_eq!(FB_CASE.len(), 2880);
        assert!(FB_CASE.windows(2).all(|w| w[0].0 < w[1].0));
        assert_eq!(
            case_of('\u{130}'),
            Some(('\u{130}', 'i', '\u{130}', UPPER | ALPHA))
        );
        assert_eq!(
            case_of('\u{212a}'),
            Some(('\u{212a}', 'k', '\u{212a}', UPPER | ALPHA))
        );
        assert_eq!(
            case_of('\u{1c5}'),
            Some(('\u{1c5}', '\u{1c5}', '\u{1c4}', ALPHA))
        );
        assert_eq!(
            case_of('\u{345}'),
            Some(('\u{345}', '\u{345}', '\u{399}', 0))
        );
        assert_eq!(case_of('ß'), None);
        assert_eq!(
            (othercase('İ'), othercase('ı'), othercase('ǅ')),
            ('i', 'I', 'ǅ')
        );
    }
}
