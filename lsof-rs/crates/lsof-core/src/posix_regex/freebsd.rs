//! FreeBSD libc's `regcomp()`: Henry Spencer's grammar, as FreeBSD 14
//! builds it into libc (`lib/libc/regex/regcomp.c`, without `LIBREGEX`, so
//! with no GNU operator), read into the same pieces as glibc's
//! (`posix_regex.rs`), which the same engines match (DIVERGENCES 183).
//!
//! What differs from glibc's grammar, each by the function of `regcomp.c`
//! that decides it:
//!
//! * `may_escape()`: a backslash before a letter, `'` or `` ` `` is
//!   `REG_EESCAPE`, "trailing backslash (\)"; before anything else (`\|`,
//!   `\+`, `\?`, `\1` in an extended expression, `\.`) it is that
//!   character. `\<` and `\>` are the word's ends; there is no `\w`, `\s`,
//!   `\b`, `\B`, `` \` `` or `\'`.
//! * `p_re()`: an empty expression or alternative is `REG_EMPTY`, "empty
//!   (sub)expression" (`a|`, `a||b`, `(|a)`, `` ``), and so is one whose every
//!   piece is `{0}`; a basic expression has no alternation at all.
//! * `p_ere_exp()`: `)` that opens nothing is `REG_EPAREN`; `{` is a
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
//!
//! Every answer here was measured against FreeBSD 14.5's libc
//! (`tests/posix_regex_freebsd.txt`).

use super::engine::{Look, Node, UnitSpec};
use super::{class_cost, nested, push_char, Frag, Item, Parser, RegexError, NEST_LIMIT};

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

    /// One character, as `ordinary()` emits it.
    fn fb_ordinary(&mut self, c: char) -> Frag {
        self.charge(1);
        self.literal(Item::Char(c))
    }

    /// `may_escape()`: whether a backslash may stand before `c` (not
    /// before a letter, `'` or `` ` ``).
    fn fb_may_escape(c: char) -> bool {
        !(c.is_alphabetic() || c == '\'' || c == '`')
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
                    c if Self::fb_may_escape(c) => self.fb_ordinary(c),
                    _ => return Err(RegexError::Escape),
                }
            }
            _ => {
                self.pos = self.pos.saturating_sub(1);
                let c = self.fb_wgetnext()?;
                self.fb_ordinary(c)
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
                Some(self.fb_ordinary(ch))
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
                list.classes.push(set);
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
                    list.ranges.push((start, finish));
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
    classes: Vec<String>,
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
fn fb_class_set(name: &[u8]) -> Option<String> {
    Some(
        match name {
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
        }
        .to_string(),
    )
}
