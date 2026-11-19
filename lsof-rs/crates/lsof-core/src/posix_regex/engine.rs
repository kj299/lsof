//! lsof-rs's own engine for `-c /regex/`: what the `regex` crate cannot
//! run, a back-reference, or will not, an expression past its bounds
//! (`posix_regex::COST_LIMIT`, `posix_regex::SIZE_LIMIT`; DIVERGENCES 38).
//!
//! The translator builds a [`Tree`] beside the pattern it writes. Its
//! leaves are the pattern's own atoms, each one character or byte
//! ([`UnitSpec`]) or one assertion ([`Look`]), read by `regex-syntax` as
//! the `regex` crate reads them, so that a leaf takes here what it takes
//! there. What joins them is matched here, over a command name, which is
//! short (15 bytes on Linux, 63 for a kernel thread): the cost of a match
//! is polynomial in the command and linear in the tree, and no interval is
//! written out as copies of what it repeats.
//!
//! An expression without a back-reference is a regular one, and is
//! answered by reachability ([`Mat`]): for each node, from which offset of
//! the command to which it can match. An interval of more passes than the
//! command has bytes, plus one, is that many: past `n + 1` passes over a
//! command of `n` bytes, every further pass matches nothing, and one that
//! matches nothing can be made again or left out.
//!
//! With a back-reference, a match is asked of every way the groups can be
//! bound, as POSIX has it: a back-reference matches what its group matched
//! last, and nothing when the group has matched nothing (glibc's answer:
//! `^(a)?\1$` does not match the empty command). Only the groups some
//! back-reference names are kept, and only while one may still be read;
//! what a node answers for an offset and the groups it reads is kept and
//! not asked again. glibc's search is not this: it misses some matches
//! that exist (`(a){0,2}\1` and `aa`), and finds some that do not
//! (`^(.*)(.*)\2\1$` matches every command; DIVERGENCES 38, measured).
//! The search is bounded
//! ([`SEARCH_BUDGET`]): past it a command is taken as not matching, where
//! glibc's own search is exponential and runs on.

use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use super::RegexError;

/// An assertion: where the expression or the command starts or ends, or a
/// word operator, which the `regex` crate decides ([`Engine::looks`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Look {
    Start,
    End,
    /// `\b`, `\B`, `\b{start}` or `\b{end}`, in the engine's syntax.
    Word(&'static str),
}

/// One character or byte: what matches it, in the `regex` crate's syntax,
/// and whether it is a non-matching list. A list's classes of the locale
/// are kept apart from its characters, so that a class is built once for
/// an expression, however many lists name it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct UnitSpec {
    /// A non-matching list: a character none of the sets takes.
    pub(super) negated: bool,
    /// What it takes, each set one character or byte.
    pub(super) sets: Vec<String>,
}

/// A node of the tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Node {
    Empty,
    Unit(UnitSpec),
    Look(Look),
    Concat(Vec<u32>),
    Alt(Vec<u32>),
    Repeat {
        child: u32,
        min: u32,
        /// `None` is no end.
        max: Option<u32>,
    },
    /// A group, numbered from 0; only the first nine can be named.
    Group {
        index: usize,
        child: u32,
    },
    /// `\1` to `\9`, numbered from 0.
    BackRef(u8),
}

/// What the translator built: its nodes, by number. A concatenation is
/// made before what it is given after its first two, so a child's number
/// need not be below its parent's ([`post_order`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Tree {
    pub(super) nodes: Vec<Node>,
}

impl Tree {
    /// Add a node, and say where it is.
    pub(super) fn push(&mut self, node: Node) -> u32 {
        self.nodes.push(node);
        u32::try_from(self.nodes.len().saturating_sub(1)).unwrap_or(u32::MAX)
    }

    /// A concatenation of `a` and `b`: `a`'s own, when it is one.
    pub(super) fn concat(&mut self, a: u32, b: u32) -> u32 {
        if let Some(Node::Concat(children)) = self.nodes.get_mut(a as usize) {
            children.push(b);
            return a;
        }
        self.push(Node::Concat(vec![a, b]))
    }
}

/// What one set takes, as `regex-syntax` read it.
#[derive(Debug)]
enum Set {
    /// One character, of these.
    Chars(Vec<(char, char)>),
    /// One byte, of these.
    Bytes(Vec<(u8, u8)>),
    /// These bytes.
    Literal(Box<[u8]>),
}

impl Set {
    /// Read a set the translator wrote, with the flags of the whole pattern.
    fn new(spec: &str, icase: bool) -> Result<Self, RegexError> {
        let hir = regex_syntax::ParserBuilder::new()
            .utf8(false)
            .unicode(true)
            .case_insensitive(icase)
            .dot_matches_new_line(true)
            .build()
            .parse(spec)
            // The translator writes only what the engine reads; the fuzz
            // target holds it to that.
            .map_err(|_| RegexError::Size)?;
        Ok(match hir.into_kind() {
            regex_syntax::hir::HirKind::Literal(literal) => Set::Literal(literal.0),
            regex_syntax::hir::HirKind::Class(regex_syntax::hir::Class::Unicode(class)) => {
                Set::Chars(
                    class
                        .ranges()
                        .iter()
                        .map(|r| (r.start(), r.end()))
                        .collect(),
                )
            }
            regex_syntax::hir::HirKind::Class(regex_syntax::hir::Class::Bytes(class)) => {
                Set::Bytes(
                    class
                        .ranges()
                        .iter()
                        .map(|r| (r.start(), r.end()))
                        .collect(),
                )
            }
            _ => return Err(RegexError::Size),
        })
    }

    /// How many bytes it takes at `at`, if any.
    fn take(&self, command: &Command<'_>, at: usize) -> Option<usize> {
        match self {
            Set::Chars(ranges) => {
                let (c, len) = command.char_at(at)?;
                in_ranges(ranges, c).then_some(len)
            }
            Set::Bytes(ranges) => {
                let b = *command.bytes.get(at)?;
                in_ranges(ranges, b).then_some(1)
            }
            Set::Literal(bytes) => command
                .bytes
                .get(at..)?
                .starts_with(bytes)
                .then_some(bytes.len()),
        }
    }
}

fn in_ranges<T: Ord + Copy>(ranges: &[(T, T)], x: T) -> bool {
    let i = ranges.partition_point(|&(_, end)| end < x);
    ranges.get(i).is_some_and(|&(start, _)| start <= x)
}

/// A unit, compiled.
#[derive(Clone, Debug)]
struct Unit {
    negated: bool,
    sets: Vec<Arc<Set>>,
}

impl Unit {
    /// The lengths it can take at `at`, as a mask: bit `l` for `l` bytes.
    fn lengths(&self, command: &Command<'_>, at: usize) -> u8 {
        if self.negated {
            // A character, and none of the sets takes it.
            let Some((_, len)) = command.char_at(at) else {
                return 0;
            };
            if self.sets.iter().any(|s| s.take(command, at) == Some(len)) {
                return 0;
            }
            return 1 << len;
        }
        self.sets
            .iter()
            .filter_map(|s| s.take(command, at))
            .fold(0, |mask, len| mask | (1u8 << len.min(7)))
    }
}

/// A command, read once for every unit that asks about it.
struct Command<'a> {
    bytes: &'a [u8],
    /// The character that starts at each offset, if one does, and its
    /// length.
    chars: Vec<Option<(char, usize)>>,
    /// Where each word operator holds.
    looks: Vec<Vec<bool>>,
}

impl<'a> Command<'a> {
    fn new(bytes: &'a [u8], looks: &[(&'static str, regex::bytes::Regex)]) -> Self {
        let chars = (0..bytes.len())
            .map(|at| {
                let rest = bytes.get(at..at.saturating_add(4).min(bytes.len()))?;
                let c = rest.utf8_chunks().next()?.valid().chars().next()?;
                Some((c, c.len_utf8()))
            })
            .collect();
        let looks = looks
            .iter()
            .map(|(_, regex)| {
                let mut holds = vec![false; bytes.len().saturating_add(1)];
                let mut from = 0usize;
                while from <= bytes.len() {
                    let Some(found) = regex.find_at(bytes, from) else {
                        break;
                    };
                    if let Some(h) = holds.get_mut(found.start()) {
                        *h = true;
                    }
                    from = found.start().saturating_add(1);
                }
                holds
            })
            .collect();
        Self {
            bytes,
            chars,
            looks,
        }
    }

    fn char_at(&self, at: usize) -> Option<(char, usize)> {
        self.chars.get(at).copied().flatten()
    }

    fn len(&self) -> usize {
        self.bytes.len()
    }
}

/// The longest command lsof-rs's own engine searches: one longer is taken
/// as not matching. No system names a process so long (Linux 63 bytes,
/// FreeBSD 19, Windows 259 UTF-16 units); it bounds what lsof-core is given
/// some other way, as what the engine keeps of a command is its square.
pub const OWN_COMMAND_MAX: usize = 1024;

/// How much a search for one command may do, with a back-reference: each
/// node asked at an offset with the groups it reads, and each way it
/// matches there, is one. Past it the command is taken as not matching.
/// Each takes a few hundred bytes at most, so the search stays under a few
/// hundred megabytes and a second or so; the expressions there are, on
/// commands of the lengths there are, take thousands (THREAT-MODEL.md).
pub const SEARCH_BUDGET: u64 = 1 << 20;

/// The groups a back-reference can name.
const GROUPS: usize = 9;

/// A group's match, as offsets `(start << 16) | end` (a command is at most
/// [`OWN_COMMAND_MAX`] bytes), or none, or (in what a node changes)
/// unchanged.
type Span = u32;
const UNSET: Span = u32::MAX;
const UNCHANGED: Span = u32::MAX - 1;

/// The groups' matches, by group.
type Groups = [Span; GROUPS];

/// What a node does to the groups: [`UNCHANGED`] where it leaves a group as
/// it found it.
const KEEP: Groups = [UNCHANGED; GROUPS];

/// A set of groups, a bit each.
type Mask = u16;

/// The compiled expression.
#[derive(Clone, Debug)]
pub(super) struct Engine {
    nodes: Vec<Node>,
    root: Option<u32>,
    /// The units, by node; `None` for a node that is no unit.
    units: Vec<Option<Unit>>,
    /// The word operators the expression has, and where each is in
    /// [`Command::looks`].
    looks: Vec<(&'static str, regex::bytes::Regex)>,
    /// Whether a match starts only at a character's first byte.
    by_chars: bool,
    icase: bool,
    /// The groups each node's back-references read.
    reads: Vec<Mask>,
    /// The groups some back-reference names that each node sets.
    writes: Vec<Mask>,
    /// The groups that may be read after each node, before they are set
    /// again: what a node's answer keeps of what it set.
    live: Vec<Mask>,
    back_references: bool,
    /// [`SEARCH_BUDGET`], but in the tests.
    budget: u64,
}

impl Engine {
    /// Compile the tree.
    pub(super) fn new(
        tree: &Tree,
        root: Option<u32>,
        by_chars: bool,
        icase: bool,
    ) -> Result<Self, RegexError> {
        let nodes = tree.nodes.clone();
        let mut sets: HashMap<&str, Arc<Set>> = HashMap::new();
        let mut units = Vec::with_capacity(nodes.len());
        let mut looks: Vec<(&'static str, regex::bytes::Regex)> = Vec::new();
        for node in &nodes {
            units.push(match node {
                Node::Unit(spec) => {
                    let mut compiled = Vec::with_capacity(spec.sets.len());
                    for text in &spec.sets {
                        let set = match sets.get(text.as_str()) {
                            Some(set) => Arc::clone(set),
                            None => {
                                let set = Arc::new(Set::new(text, icase)?);
                                sets.insert(text, Arc::clone(&set));
                                set
                            }
                        };
                        compiled.push(set);
                    }
                    Some(Unit {
                        negated: spec.negated,
                        sets: compiled,
                    })
                }
                Node::Look(Look::Word(text)) => {
                    if !looks.iter().any(|(t, _)| t == text) {
                        let regex = regex::bytes::Regex::new(text).map_err(|_| RegexError::Size)?;
                        looks.push((text, regex));
                    }
                    None
                }
                _ => None,
            });
        }
        // Children before their parents: what a node reads and sets is
        // known when it is reached.
        let order = post_order(&nodes, root);
        let mut reads = vec![0 as Mask; nodes.len()];
        let mut writes = vec![0 as Mask; nodes.len()];
        let mut back_references = false;
        for &id in &order {
            let id = id as usize;
            let Some(node) = nodes.get(id) else {
                continue;
            };
            let of = |m: &[Mask], ids: &[u32]| {
                ids.iter()
                    .fold(0, |acc, &c| acc | m.get(c as usize).copied().unwrap_or(0))
            };
            let (r, w) = match node {
                Node::Concat(children) | Node::Alt(children) => {
                    (of(&reads, children), of(&writes, children))
                }
                Node::Repeat { child, .. } => (of(&reads, &[*child]), of(&writes, &[*child])),
                Node::Group { index, child } => (
                    of(&reads, &[*child]),
                    of(&writes, &[*child]) | group_bit(*index),
                ),
                Node::BackRef(n) => {
                    back_references = true;
                    (group_bit(usize::from(*n)), 0)
                }
                Node::Empty | Node::Unit(_) | Node::Look(_) => (0, 0),
            };
            if let (Some(rr), Some(ww)) = (reads.get_mut(id), writes.get_mut(id)) {
                *rr = r;
                *ww = w;
            }
        }
        // Only a group a back-reference names is kept.
        let named = reads.iter().fold(0, |acc, &r| acc | r);
        for w in &mut writes {
            *w &= named;
        }
        // What may be read after a node: from the root down, so parents
        // before children.
        let mut live = vec![0 as Mask; nodes.len()];
        for &id in order.iter().rev() {
            let id = id as usize;
            let here = live.get(id).copied().unwrap_or(0);
            let Some(node) = nodes.get(id) else {
                continue;
            };
            let mut set = |c: u32, m: Mask| {
                if let Some(l) = live.get_mut(c as usize) {
                    *l |= m;
                }
            };
            match node {
                Node::Concat(children) => {
                    let mut after = here;
                    for &c in children.iter().rev() {
                        set(c, after);
                        after |= reads.get(c as usize).copied().unwrap_or(0);
                    }
                }
                Node::Alt(children) => {
                    for &c in children {
                        set(c, here);
                    }
                }
                Node::Repeat { child, .. } => {
                    set(
                        *child,
                        here | reads.get(*child as usize).copied().unwrap_or(0),
                    );
                }
                Node::Group { child, .. } => set(*child, here),
                Node::Empty | Node::Unit(_) | Node::Look(_) | Node::BackRef(_) => {}
            }
        }
        Ok(Self {
            nodes,
            root,
            units,
            looks,
            by_chars,
            icase,
            reads,
            writes,
            live,
            back_references,
            budget: SEARCH_BUDGET,
        })
    }

    /// The same, with a search budget of `budget`.
    #[cfg(test)]
    pub(super) fn with_budget(&self, budget: u64) -> Self {
        Self {
            budget,
            ..self.clone()
        }
    }

    /// Whether `command` matches: `None` when the search went past
    /// [`SEARCH_BUDGET`].
    pub(super) fn is_match(&self, command: &[u8]) -> Option<bool> {
        let Some(root) = self.root else {
            // The empty expression matches every command.
            return Some(true);
        };
        if command.len() > OWN_COMMAND_MAX {
            return None;
        }
        let command = Command::new(command, &self.looks);
        // glibc searching by characters starts a match only at a
        // character's first byte, or at a byte that is part of none.
        let mut starts = vec![!self.by_chars; command.len().saturating_add(1)];
        let mut at = 0usize;
        for item in super::items(command.bytes) {
            if let Some(s) = starts.get_mut(at) {
                *s = true;
            }
            at = at.saturating_add(item.len());
        }
        if let Some(s) = starts.get_mut(command.len()) {
            *s = true;
        }
        let starts = starts
            .iter()
            .enumerate()
            .filter_map(|(at, &s)| s.then_some(at));
        if !self.back_references {
            let mat = self.matrix(root, &command);
            return Some(starts.into_iter().any(|at| mat.row_any(at)));
        }
        let mut search = Search {
            engine: self,
            command: &command,
            memo: HashMap::new(),
            spent: 0,
        };
        for at in starts {
            match search.any(root, at, &[UNSET; GROUPS]) {
                Ok(true) => return Some(true),
                Ok(false) => {}
                Err(Exhausted) => return None,
            }
        }
        Some(false)
    }

    fn node(&self, id: u32) -> &Node {
        self.nodes.get(id as usize).unwrap_or(&Node::Empty)
    }

    fn unit(&self, id: u32) -> Option<&Unit> {
        self.units.get(id as usize).and_then(Option::as_ref)
    }

    /// Whether the assertion holds at `at`.
    fn look(&self, look: &Look, command: &Command<'_>, at: usize) -> bool {
        match look {
            Look::Start => at == 0,
            Look::End => at == command.len(),
            Look::Word(text) => self
                .looks
                .iter()
                .position(|(t, _)| t == text)
                .and_then(|i| command.looks.get(i))
                .and_then(|holds| holds.get(at))
                .copied()
                .unwrap_or(false),
        }
    }

    /// From which offset of `command` to which `id` matches.
    fn matrix(&self, id: u32, command: &Command<'_>) -> Mat {
        let n = command.len();
        match self.node(id) {
            Node::Empty | Node::BackRef(_) => Mat::identity(n),
            Node::Unit(_) => {
                let mut m = Mat::empty(n);
                if let Some(unit) = self.unit(id) {
                    for at in 0..n {
                        let lengths = unit.lengths(command, at);
                        for len in 1..8usize {
                            if lengths & (1 << len) != 0 {
                                m.set(at, at.saturating_add(len));
                            }
                        }
                    }
                }
                m
            }
            Node::Look(look) => {
                let mut m = Mat::empty(n);
                for at in 0..=n {
                    if self.look(look, command, at) {
                        m.set(at, at);
                    }
                }
                m
            }
            Node::Concat(children) => {
                let mut acc = Mat::identity(n);
                for &c in children {
                    acc = match self.unit(c) {
                        // A character or byte moves each row along by its
                        // length: no product needed.
                        Some(unit) => acc.then_unit(unit, command),
                        None => acc.then(&self.matrix(c, command)),
                    };
                }
                acc
            }
            Node::Alt(children) => {
                let mut acc = Mat::empty(n);
                for &c in children {
                    acc.or(&self.matrix(c, command));
                }
                acc
            }
            Node::Group { child, .. } => self.matrix(*child, command),
            Node::Repeat { child, min, max } => {
                let once = self.matrix(*child, command);
                // Past n + 1 passes, a pass more or less changes nothing.
                let cap = u32::try_from(n.saturating_add(1)).unwrap_or(u32::MAX);
                let min = (*min).min(cap);
                let max = max.unwrap_or(cap).min(cap);
                let first = once.power(min);
                if max == cap {
                    // As many passes as there may be: the closure.
                    return first.then(&once.closure());
                }
                let mut some = once.clone();
                some.or(&Mat::identity(n));
                first.then(&some.power(max.saturating_sub(min)))
            }
        }
    }
}

/// The nodes under `root`, each after its children. A concatenation is
/// made before what is added to it, so the order the nodes were made in is
/// not this.
fn post_order(nodes: &[Node], root: Option<u32>) -> Vec<u32> {
    let mut order = Vec::with_capacity(nodes.len());
    let mut stack: Vec<(u32, bool)> = root.map(|r| (r, false)).into_iter().collect();
    while let Some((id, expanded)) = stack.pop() {
        if expanded {
            order.push(id);
            continue;
        }
        stack.push((id, true));
        match nodes.get(id as usize) {
            Some(Node::Concat(children) | Node::Alt(children)) => {
                stack.extend(children.iter().map(|&c| (c, false)));
            }
            Some(Node::Repeat { child, .. } | Node::Group { child, .. }) => {
                stack.push((*child, false));
            }
            _ => {}
        }
    }
    order
}

fn group_bit(index: usize) -> Mask {
    if index < GROUPS {
        1 << index
    } else {
        0
    }
}

/// From which offset to which: a row of `n + 1` bits for each offset.
#[derive(Clone, Debug)]
struct Mat {
    words: usize,
    bits: Vec<u64>,
}

impl Mat {
    fn empty(n: usize) -> Self {
        let words = n.saturating_add(1).div_ceil(64);
        Self {
            words,
            bits: vec![0; words.saturating_mul(n.saturating_add(1))],
        }
    }

    fn identity(n: usize) -> Self {
        let mut m = Self::empty(n);
        for at in 0..=n {
            m.set(at, at);
        }
        m
    }

    fn rows(&self) -> usize {
        self.bits.len().checked_div(self.words).unwrap_or(0)
    }

    fn row(&self, at: usize) -> &[u64] {
        let start = at.saturating_mul(self.words);
        self.bits
            .get(start..start.saturating_add(self.words))
            .unwrap_or(&[])
    }

    fn row_any(&self, at: usize) -> bool {
        self.row(at).iter().any(|&w| w != 0)
    }

    fn set(&mut self, from: usize, to: usize) {
        let i = from.saturating_mul(self.words).saturating_add(to / 64);
        if to < self.rows() {
            if let Some(w) = self.bits.get_mut(i) {
                *w |= 1 << (to % 64);
            }
        }
    }

    fn or(&mut self, other: &Mat) {
        for (a, b) in self.bits.iter_mut().zip(&other.bits) {
            *a |= b;
        }
    }

    /// `self` and then `other`.
    fn then(&self, other: &Mat) -> Mat {
        let mut out = Mat {
            words: self.words,
            bits: vec![0; self.bits.len()],
        };
        for from in 0..self.rows() {
            let start = from.saturating_mul(self.words);
            for (w, &word) in self.row(from).iter().enumerate() {
                let mut word = word;
                while word != 0 {
                    let bit = word.trailing_zeros() as usize;
                    word &= word.wrapping_sub(1);
                    let mid = w.saturating_mul(64).saturating_add(bit);
                    let row = other.row(mid);
                    if let Some(dst) = out.bits.get_mut(start..start.saturating_add(self.words)) {
                        for (d, s) in dst.iter_mut().zip(row) {
                            *d |= s;
                        }
                    }
                }
            }
        }
        out
    }

    /// `self` and then `unit`, a character or byte: each offset a row
    /// reaches moves on by what the unit takes there.
    fn then_unit(&self, unit: &Unit, command: &Command<'_>) -> Mat {
        let mut out = Mat {
            words: self.words,
            bits: vec![0; self.bits.len()],
        };
        let n = command.len();
        // Where the unit takes each length.
        let mut takes: Vec<(usize, Vec<u64>)> = Vec::new();
        for at in 0..n {
            let lengths = unit.lengths(command, at);
            for len in 1..8usize {
                if lengths & (1 << len) == 0 {
                    continue;
                }
                let i = match takes.iter().position(|(l, _)| *l == len) {
                    Some(i) => i,
                    None => {
                        takes.push((len, vec![0; self.words]));
                        takes.len().saturating_sub(1)
                    }
                };
                if let Some(w) = takes.get_mut(i).and_then(|(_, m)| m.get_mut(at / 64)) {
                    *w |= 1 << (at % 64);
                }
            }
        }
        for from in 0..self.rows() {
            let start = from.saturating_mul(self.words);
            let row = self.row(from);
            let Some(dst) = out.bits.get_mut(start..start.saturating_add(self.words)) else {
                continue;
            };
            for (len, mask) in &takes {
                // dst |= (row & mask) << len, across the words.
                let (whole, part) = (len / 64, len % 64);
                for i in (0..dst.len()).rev() {
                    let word =
                        |j: usize| -> u64 { row.get(j).zip(mask.get(j)).map_or(0, |(r, m)| r & m) };
                    let Some(src) = i.checked_sub(whole) else {
                        continue;
                    };
                    let mut v = word(src) << part;
                    if part > 0 {
                        if let Some(lower) = src.checked_sub(1) {
                            v |= word(lower) >> (64 - part);
                        }
                    }
                    if let Some(d) = dst.get_mut(i) {
                        *d |= v;
                    }
                }
            }
        }
        out
    }

    /// Every offset `self` reaches from each, any number of times over
    /// (none included). A match never moves back, so a row is done once
    /// those after it are.
    fn closure(&self) -> Mat {
        let mut out = self.clone();
        for from in (0..self.rows()).rev() {
            out.set(from, from);
            let start = from.saturating_mul(self.words);
            let row: Vec<u64> = self.row(from).to_vec();
            for (w, &word) in row.iter().enumerate() {
                let mut word = word;
                while word != 0 {
                    let bit = word.trailing_zeros() as usize;
                    word &= word.wrapping_sub(1);
                    let mid = w.saturating_mul(64).saturating_add(bit);
                    if mid <= from {
                        continue;
                    }
                    let reached: Vec<u64> = out.row(mid).to_vec();
                    if let Some(dst) = out.bits.get_mut(start..start.saturating_add(self.words)) {
                        for (d, s) in dst.iter_mut().zip(&reached) {
                            *d |= s;
                        }
                    }
                }
            }
        }
        out
    }

    /// `self`, `times` times over.
    fn power(&self, times: u32) -> Mat {
        let mut result = Mat::identity(self.rows().saturating_sub(1));
        let mut base = self.clone();
        let mut times = times;
        while times > 0 {
            if times & 1 == 1 {
                result = result.then(&base);
            }
            times >>= 1;
            if times > 0 {
                base = base.then(&base);
            }
        }
        result
    }
}

/// The search went past [`SEARCH_BUDGET`].
#[derive(Debug)]
struct Exhausted;

/// Where a node can end, from an offset, and what it set on the way.
type Ends = Rc<[(u16, Groups)]>;

struct Search<'e, 'c> {
    engine: &'e Engine,
    command: &'c Command<'c>,
    /// What each node answered, for an offset and the groups it reads.
    memo: HashMap<(u32, u16, Groups), Ends>,
    spent: u64,
}

impl Search<'_, '_> {
    fn charge(&mut self, units: usize) -> Result<(), Exhausted> {
        self.spent = self
            .spent
            .saturating_add(u64::try_from(units).unwrap_or(u64::MAX));
        if self.spent > self.engine.budget {
            return Err(Exhausted);
        }
        Ok(())
    }

    /// Where `id` can end from `at`, with the groups as `groups` has them,
    /// and what it sets of those that may be read after it.
    fn eval(&mut self, id: u32, at: usize, groups: &Groups) -> Result<Ends, Exhausted> {
        let e = self.engine;
        self.charge(1)?;
        // What one character, byte, assertion or back-reference does is
        // asked again rather than kept: it is quick to answer, and they
        // would be most of what is kept.
        let end = |len: usize| -> Ends { Rc::from([(offset(at.saturating_add(len)), KEEP)]) };
        match e.node(id) {
            Node::Empty => return Ok(end(0)),
            Node::Unit(_) => {
                let lengths = e.unit(id).map_or(0, |u| u.lengths(self.command, at));
                let ends: Vec<_> = (1..8usize)
                    .filter(|len| lengths & (1 << len) != 0)
                    .map(|len| (offset(at.saturating_add(len)), KEEP))
                    .collect();
                return Ok(ends.into());
            }
            Node::Look(look) => {
                let holds = e.look(look, self.command, at);
                return Ok(if holds { end(0) } else { Rc::from([]) });
            }
            Node::BackRef(n) => {
                let len = self.back_reference(usize::from(*n), at, groups);
                return Ok(len.map_or_else(|| Rc::from([]), end));
            }
            _ => {}
        }
        let reads = e.reads.get(id as usize).copied().unwrap_or(0);
        let key = (id, offset(at), only(groups, reads));
        if let Some(found) = self.memo.get(&key) {
            return Ok(Rc::clone(found));
        }
        let keep = e.live.get(id as usize).copied().unwrap_or(0)
            & e.writes.get(id as usize).copied().unwrap_or(0);
        // Each way a node matches is paid for before it is kept, so what
        // the search holds is bounded by its budget.
        let mut out: Vec<(u16, Groups)> = Vec::new();
        match e.node(id) {
            Node::Empty | Node::Unit(_) | Node::Look(_) | Node::BackRef(_) => {}
            Node::Group { index, child } => {
                let index = *index;
                let found = self.eval(*child, at, groups)?;
                for &(end, changed) in found.iter() {
                    let mut changed = changed;
                    if group_bit(index) & keep != 0 {
                        if let Some(g) = changed.get_mut(index) {
                            *g = span(at, usize::from(end));
                        }
                    }
                    self.charge(1)?;
                    out.push((end, only_changed(&changed, keep)));
                }
            }
            Node::Alt(children) => {
                for &c in children {
                    let found = self.eval(c, at, groups)?;
                    self.charge(found.len())?;
                    out.extend(
                        found
                            .iter()
                            .map(|&(end, ch)| (end, only_changed(&ch, keep))),
                    );
                }
            }
            Node::Concat(children) => {
                let mut states = vec![(offset(at), KEEP)];
                for &c in children {
                    states = self.step(c, &states, groups)?;
                    if states.is_empty() {
                        break;
                    }
                }
                out.extend(
                    states
                        .iter()
                        .map(|&(end, ch)| (end, only_changed(&ch, keep))),
                );
            }
            Node::Repeat { child, min, max } => {
                // Past `cap` passes a pass more or less changes nothing.
                let cap = self.cap(*child);
                let (min, max) = ((*min).min(cap), max.unwrap_or(cap).min(cap));
                let mut states = vec![(offset(at), KEEP)];
                let mut pass = 0u32;
                loop {
                    if pass >= min {
                        self.charge(states.len())?;
                        out.extend(
                            states
                                .iter()
                                .map(|&(end, ch)| (end, only_changed(&ch, keep))),
                        );
                    }
                    if pass >= max || states.is_empty() {
                        break;
                    }
                    let next = self.step(*child, &states, groups)?;
                    pass = pass.saturating_add(1);
                    if next == states {
                        // Every pass after this one is the same.
                        self.charge(next.len())?;
                        out.extend(next.iter().map(|&(end, ch)| (end, only_changed(&ch, keep))));
                        break;
                    }
                    states = next;
                }
            }
        }
        out.sort_unstable();
        out.dedup();
        let found: Ends = out.into();
        self.memo.insert(key, Rc::clone(&found));
        Ok(found)
    }

    /// Whether `id` matches from `at` at all, where nothing after it reads
    /// what it sets: the first way found is enough, so a concatenation is
    /// walked one way at a time, and a repetition stops at the first pass
    /// that gets anywhere.
    fn any(&mut self, id: u32, at: usize, groups: &Groups) -> Result<bool, Exhausted> {
        let e = self.engine;
        match e.node(id) {
            Node::Group { child, .. } => self.any(*child, at, groups),
            Node::Alt(children) => {
                for &c in children {
                    if self.any(c, at, groups)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Node::Concat(children) => {
                let Some((&last, init)) = children.split_last() else {
                    return Ok(true);
                };
                // Depth first, each place in the concatenation, offset and
                // groups set walked once.
                let mut seen = std::collections::HashSet::new();
                let mut stack = vec![(0usize, offset(at), KEEP)];
                while let Some((i, at, changed)) = stack.pop() {
                    let now = apply(groups, &changed);
                    let Some(&c) = init.get(i) else {
                        if self.any(last, usize::from(at), &now)? {
                            return Ok(true);
                        }
                        continue;
                    };
                    let after = e.live.get(c as usize).copied().unwrap_or(0);
                    let found = self.eval(c, usize::from(at), &now)?;
                    for &(end, more) in found.iter().rev() {
                        let next = (
                            i.saturating_add(1),
                            end,
                            only_changed(&apply_changes(&changed, &more), after),
                        );
                        if seen.insert(next) {
                            self.charge(1)?;
                            stack.push(next);
                        }
                    }
                }
                Ok(false)
            }
            Node::Repeat { child, min, .. } => {
                // The passes it must make: any more are not needed.
                let mut states = vec![(offset(at), KEEP)];
                for _ in 0..(*min).min(self.cap(*child)) {
                    states = self.step(*child, &states, groups)?;
                    if states.is_empty() {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            Node::Empty => Ok(true),
            Node::Unit(_) | Node::Look(_) | Node::BackRef(_) => {
                Ok(!self.eval(id, at, groups)?.is_empty())
            }
        }
    }

    /// How many passes of `child` a repetition makes at most: past
    /// `(n + 1)(g + 1)` over a command of `n` bytes, where `child` sets `g`
    /// groups, a pass more or less changes nothing. Past `n` passes some
    /// match nothing; one that matches nothing sets each group it sets to
    /// nothing where it is, can be made again, and changes nothing more
    /// once every group it can set is so.
    fn cap(&self, child: u32) -> u32 {
        let sets = self
            .engine
            .writes
            .get(child as usize)
            .copied()
            .unwrap_or(0)
            .count_ones();
        let cap = self
            .command
            .len()
            .saturating_add(1)
            .saturating_mul(usize::try_from(sets).unwrap_or(GROUPS).saturating_add(1))
            .saturating_add(1);
        u32::try_from(cap).unwrap_or(u32::MAX)
    }

    /// Each of `states` (an offset, and what was set to get there) followed
    /// by `id`: where it ends, and what is set of what may be read after it.
    fn step(
        &mut self,
        id: u32,
        states: &[(u16, Groups)],
        groups: &Groups,
    ) -> Result<Vec<(u16, Groups)>, Exhausted> {
        let after = self.engine.live.get(id as usize).copied().unwrap_or(0);
        let mut next = Vec::new();
        for &(at, changed) in states {
            let now = apply(groups, &changed);
            let found = self.eval(id, usize::from(at), &now)?;
            self.charge(found.len().saturating_add(1))?;
            for &(end, more) in found.iter() {
                next.push((end, only_changed(&apply_changes(&changed, &more), after)));
            }
        }
        next.sort_unstable();
        next.dedup();
        Ok(next)
    }

    /// How many bytes `\n` takes at `at`: what group `n` matched, again;
    /// under `REG_ICASE` each character in the case `towupper()` gives it.
    /// Nothing, where the group has matched nothing.
    fn back_reference(&self, n: usize, at: usize, groups: &Groups) -> Option<usize> {
        let g = *groups.get(n)?;
        if g == UNSET || g == UNCHANGED {
            return None;
        }
        let (start, end) = (
            usize::from(u16::try_from(g >> 16).ok()?),
            usize::from(u16::try_from(g & 0xffff).ok()?),
        );
        let bytes = self.command.bytes;
        let matched = bytes.get(start..end)?;
        if !self.engine.icase {
            return bytes
                .get(at..)?
                .starts_with(matched)
                .then_some(matched.len());
        }
        // Character by character, a byte that is no character as itself.
        let (mut i, mut j) = (start, at);
        while i < end {
            let a = self.command.char_at(i);
            let b = self.command.char_at(j);
            match (a, b) {
                (Some((x, lx)), Some((y, ly))) => {
                    if upper(x) != upper(y) || i.saturating_add(lx) > end {
                        return None;
                    }
                    i = i.saturating_add(lx);
                    j = j.saturating_add(ly);
                }
                (None, None) => {
                    if bytes.get(i) != bytes.get(j) || bytes.get(j).is_none() {
                        return None;
                    }
                    i = i.saturating_add(1);
                    j = j.saturating_add(1);
                }
                _ => return None,
            }
        }
        Some(j.saturating_sub(at))
    }
}

/// `towupper()`: the one character a character's upper case is, or the
/// character itself where that is more than one (`ß`).
fn upper(c: char) -> char {
    let mut u = c.to_uppercase();
    match (u.next(), u.next()) {
        (Some(one), None) => one,
        _ => c,
    }
}

/// An offset in a command, which is at most [`OWN_COMMAND_MAX`] bytes.
fn offset(at: usize) -> u16 {
    u16::try_from(at).unwrap_or(u16::MAX)
}

fn span(start: usize, end: usize) -> Span {
    let start = u32::from(u16::try_from(start).unwrap_or(u16::MAX));
    let end = u32::from(u16::try_from(end).unwrap_or(u16::MAX));
    (start << 16) | end
}

/// The groups in `mask`, the rest unset: the part of the groups a node
/// reads, which is all its answer depends on.
fn only(groups: &Groups, mask: Mask) -> Groups {
    let mut out = [UNSET; GROUPS];
    for (i, (o, g)) in out.iter_mut().zip(groups).enumerate() {
        if mask & group_bit(i) != 0 {
            *o = *g;
        }
    }
    out
}

/// What was set of the groups in `mask`; the rest unchanged.
fn only_changed(changed: &Groups, mask: Mask) -> Groups {
    let mut out = KEEP;
    for (i, (o, g)) in out.iter_mut().zip(changed).enumerate() {
        if mask & group_bit(i) != 0 {
            *o = *g;
        }
    }
    out
}

/// What `first` changed and then `then`.
fn apply_changes(first: &Groups, then: &Groups) -> Groups {
    let mut out = *first;
    for (o, t) in out.iter_mut().zip(then) {
        if *t != UNCHANGED {
            *o = *t;
        }
    }
    out
}

/// The groups as `groups` has them, with `changed` set.
fn apply(groups: &Groups, changed: &Groups) -> Groups {
    let mut out = *groups;
    for (o, c) in out.iter_mut().zip(changed) {
        if *c != UNCHANGED {
            *o = *c;
        }
    }
    out
}
