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
//! bound: a back-reference matches what its group matched last, and nothing
//! when the group has matched nothing (glibc's answer: `^(a)?\1$` does not
//! match the empty command). Where POSIX is unclear, glibc's reading is
//! taken: a group inside a repetition keeps what it matched in an earlier
//! pass through a later pass that does not reach it (`^(a|(b))*\2$`
//! matches `bab`, as glibc says; a strict reading of POSIX's rule for
//! nested groups would not). glibc's own search is not this: it misses
//! some matches that exist (`(a){0,2}\1` and `aa`), and finds some that do
//! not (`^(.*)(.*)\2\1$` matches every command; DIVERGENCES 38, measured).
//!
//! The search ([`Search`]) walks what is left to match, depth first, so
//! that the first way found is enough: groups, alternatives and
//! concatenations one item at a time; a repetition that sets no group a
//! back-reference names by every way it can end (offsets, kept for an
//! offset and the groups it reads), and one that does a pass at a time,
//! each pass that matches nothing made at once and each other one listed
//! whole where it sets at most two groups or else walked item by item, a
//! group that no back-reference after can read taken as unset so that the
//! states that differ only there are one. Before it, the expression
//! is matched as a regular one whose back-references match anything, which
//! says where nothing can match. Each start is searched in turns of the
//! same length, doubled each round, so that a match easy to find from one
//! start is found however long the others would take; a state from which
//! nothing matches is walked once, for every start; a group just set is
//! checked against where it is named next; and only the groups a
//! back-reference may still read are kept. The search is bounded, in
//! steps ([`SEARCH_BUDGET`]) and in what it holds ([`SEARCH_MEMORY`]):
//! past either a command is taken as not matching (THREAT-MODEL.md has how
//! often, measured), where glibc's own search is exponential and runs on.

use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use super::towupper::TOWUPPER;
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
    /// Under `REG_ICASE`, the command as glibc compares a back-reference
    /// in it: read from its start, each character in the case [`upper`]
    /// gives it where that is as long, and each byte that is no character
    /// as itself.
    folded: Vec<u8>,
}

impl<'a> Command<'a> {
    fn new(bytes: &'a [u8], looks: &[(&'static str, regex::bytes::Regex)], icase: bool) -> Self {
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
        let mut folded = Vec::new();
        if icase {
            folded.reserve(bytes.len());
            for item in super::items(bytes) {
                match item {
                    super::Item::Char(c) => {
                        let u = upper(c);
                        let mut buf = [0u8; 4];
                        let same = if u.len_utf8() == c.len_utf8() { u } else { c };
                        folded.extend_from_slice(same.encode_utf8(&mut buf).as_bytes());
                    }
                    super::Item::Byte(b) => folded.push(b),
                }
            }
        }
        Self {
            bytes,
            chars,
            looks,
            folded,
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
/// state walked, each way a repetition matches, each item checked, each
/// thing kept is one. Past it the command is taken as not matching.
/// Measured at about 0.1 s a million on this host (THREAT-MODEL.md): every
/// case the reviews found takes under 50,000; of 9,000 random expressions
/// of up to nine groups against a 63-byte name, 3 go past it (or past
/// [`SEARCH_MEMORY`]), none of which has a match, and the 3,942 that match
/// are found within it; of 6,000 random repetitions and runs of groups
/// against names of 14 to 63 bytes, 60 go past, 2 of which have a match
/// (found past 4.2 million steps; glibc finds them in 0.09 and 0.53 s).
pub const SEARCH_BUDGET: u64 = 1 << 22;

/// How many bytes a search for one command may hold, its tables counted by
/// the room they have, every 1,024 steps and before the two largest grow:
/// past it, as past [`SEARCH_BUDGET`], the command is taken as not
/// matching. What it holds is at most this and what 1,024 steps add (each
/// kept thing is a step; THREAT-MODEL.md has what was measured).
pub const SEARCH_MEMORY: usize = 32 << 20;

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
    /// Of those, the ones it sets however it matches.
    must: Vec<Mask>,
    /// The most of those one way of matching it sets: a pass of a
    /// repetition setting few is listed whole ([`Search::pass`]).
    path_sets: Vec<u32>,
    /// The groups that may be read after each node, before they are set
    /// again: what a node's answer keeps of what it set.
    live: Vec<Mask>,
    back_references: bool,
    /// [`SEARCH_BUDGET`], but in the tests.
    budget: u64,
    /// [`SEARCH_MEMORY`], but in the tests.
    memory: usize,
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
        // The groups each node sets however it matches.
        let mut must = vec![0 as Mask; nodes.len()];
        for &id in &order {
            let get = |c: &u32| must.get(*c as usize).copied().unwrap_or(0);
            let m = match nodes.get(id as usize) {
                Some(Node::Concat(children)) => children.iter().fold(0, |acc, c| acc | get(c)),
                Some(Node::Alt(children)) => children.iter().fold(Mask::MAX, |acc, c| acc & get(c)),
                Some(Node::Repeat { child, min, .. }) if *min > 0 => get(child),
                Some(Node::Group { index, child }) => get(child) | group_bit(*index),
                _ => 0,
            };
            if let Some(slot) = must.get_mut(id as usize) {
                *slot = m & named;
            }
        }
        // The most groups a way of matching each node sets.
        let mut path_sets = vec![0u32; nodes.len()];
        for &id in &order {
            let get = |c: &u32| path_sets.get(*c as usize).copied().unwrap_or(0);
            let m = match nodes.get(id as usize) {
                Some(Node::Concat(children)) => children
                    .iter()
                    .fold(0u32, |acc, c| acc.saturating_add(get(c))),
                Some(Node::Alt(children)) => children.iter().map(get).max().unwrap_or(0),
                // Its passes, together, may set every group under it.
                Some(Node::Repeat { .. }) => {
                    writes.get(id as usize).copied().unwrap_or(0).count_ones()
                }
                Some(Node::Group { child, .. }) => get(child).saturating_add(u32::from(
                    writes.get(id as usize).copied().unwrap_or(0)
                        != writes.get(*child as usize).copied().unwrap_or(0),
                )),
                _ => 0,
            };
            if let Some(slot) = path_sets.get_mut(id as usize) {
                *slot = m;
            }
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
            must,
            path_sets,
            live,
            back_references,
            budget: SEARCH_BUDGET,
            memory: SEARCH_MEMORY,
        })
    }

    /// The same, with a search budget of `budget`.
    pub(super) fn with_budget(&self, budget: u64) -> Self {
        Self {
            budget,
            ..self.clone()
        }
    }

    /// The same, with a search held to `memory` bytes.
    pub(super) fn with_memory(&self, memory: usize) -> Self {
        Self {
            memory,
            ..self.clone()
        }
    }

    /// Whether `command` matches: `None` when the search went past
    /// [`SEARCH_BUDGET`].
    pub(super) fn is_match(&self, command: &[u8]) -> Option<bool> {
        self.search(command).0
    }

    /// [`Engine::is_match`], and how many steps of [`SEARCH_BUDGET`] the
    /// search took (none without a back-reference).
    pub(super) fn search(&self, command: &[u8]) -> (Option<bool>, u64) {
        let Some(root) = self.root else {
            // The empty expression matches every command.
            return (Some(true), 0);
        };
        if command.len() > OWN_COMMAND_MAX {
            return (None, 0);
        }
        let command = Command::new(command, &self.looks, self.icase);
        let starts = self.starts(&command).into_iter();
        if !self.back_references {
            let mat = self.matrix(root, &command);
            return (Some(starts.into_iter().any(|at| mat.row_any(at))), 0);
        }
        // What the expression would match if each back-reference matched
        // anything at all: where that matches nothing, nothing does, and a
        // start it cannot match from is not searched.
        let over = self.matrix(root, &command);
        let starts: Vec<usize> = starts.filter(|&at| over.row_any(at)).collect();
        let mut search = Search {
            engine: self,
            command: &command,
            memo: HashMap::new(),
            conts: Conts::default(),
            dead: std::collections::HashSet::new(),
            canon: HashMap::new(),
            over: HashMap::new(),
            star: HashMap::new(),
            read: HashMap::new(),
            empties: HashMap::new(),
            spent: 0,
            kept: 0,
            round: 0,
            slice: FIRST_SLICE,
        };
        let answer = search.run(root, &starts);
        (answer, search.spent)
    }

    /// Where a match may start: glibc searching by characters starts one
    /// only at a character's first byte, or at a byte that is part of none.
    fn starts(&self, command: &Command<'_>) -> Vec<usize> {
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
        starts
            .iter()
            .enumerate()
            .filter_map(|(at, &s)| s.then_some(at))
            .collect()
    }

    /// Whether `command` matches, by trying every way of matching each
    /// node in turn, as plainly as can be: for the tests and the fuzz
    /// target, which hold the engine to it on short commands. `None` past
    /// `limit` steps, or for a command longer than [`ORACLE_COMMAND_MAX`].
    /// A repetition is held to more passes than [`Search::cap`] allows, so
    /// that the cap is checked too.
    pub(super) fn oracle(&self, command: &[u8], limit: u64) -> Option<bool> {
        let Some(root) = self.root else {
            return Some(true);
        };
        if command.len() > ORACLE_COMMAND_MAX {
            return None;
        }
        let command = Command::new(command, &self.looks, self.icase);
        let mut oracle = Oracle {
            engine: self,
            command: &command,
            steps: 0,
            limit,
            depth: 0,
        };
        for at in self.starts(&command) {
            if oracle.matches(root, at, [UNSET; GROUPS], &mut |_, _, _| true) {
                return (oracle.steps <= limit).then_some(true);
            }
        }
        (oracle.steps <= limit).then_some(false)
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
        self.matrix_with(id, command, &mut |c| self.matrix(c, command))
    }

    /// [`Engine::matrix`], with each child's from `child`.
    fn matrix_with(
        &self,
        id: u32,
        command: &Command<'_>,
        child: &mut dyn FnMut(u32) -> Mat,
    ) -> Mat {
        let n = command.len();
        match self.node(id) {
            Node::Empty => Mat::identity(n),
            // Only in [`Engine::is_match`]'s first look, where a
            // back-reference may match anything from where it is.
            Node::BackRef(_) => Mat::onwards(n),
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
                        None => acc.then(&child(c)),
                    };
                }
                acc
            }
            Node::Alt(children) => {
                let mut acc = Mat::empty(n);
                for &c in children {
                    acc.or(&child(c));
                }
                acc
            }
            Node::Group { child: c, .. } => child(*c),
            Node::Repeat { child: c, min, max } => {
                let once = child(*c);
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

/// The offsets a row of bits holds.
fn ones(row: &[u64]) -> Vec<usize> {
    let mut out = Vec::new();
    for (w, &word) in row.iter().enumerate() {
        let mut word = word;
        while word != 0 {
            out.push(
                w.saturating_mul(64)
                    .saturating_add(word.trailing_zeros() as usize),
            );
            word &= word.wrapping_sub(1);
        }
    }
    out
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

    /// Every offset to every offset at or after it.
    fn onwards(n: usize) -> Self {
        let mut m = Self::empty(n);
        for from in 0..=n {
            for to in from..=n {
                m.set(from, to);
            }
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

/// Why a search stopped before it had an answer.
#[derive(Debug, PartialEq, Eq)]
enum Stop {
    /// It went past [`SEARCH_BUDGET`].
    Exhausted,
    /// The start it searches from has had its turn ([`Search::run`]).
    Turn,
}

/// Where a node can end, from an offset, and what it set on the way.
type Ends = Rc<[(u16, Groups)]>;

/// What is still to be matched: a node, or the end of a group that started
/// at `start` (the group's node). Each is followed by the rest, another
/// [`Conts`] entry; entry 0 is nothing, which is a match.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Item {
    Node(u32),
    Close {
        group: u32,
        start: u16,
    },
    /// A repetition (its node) that has made `passes` passes: it may end
    /// here, once it has made its least, or make one more. Past its least,
    /// with no most, the passes are not counted.
    Rep {
        node: u32,
        passes: u32,
    },
    /// The end of a pass of repetition `node` that started at `start`, one
    /// that matched something: a pass that matches nothing is made at once
    /// ([`Search::empty`]).
    PassEnd {
        node: u32,
        start: u16,
    },
}

/// The continuations made so far, each once.
#[derive(Default)]
struct Conts {
    /// Each one's first item, and the rest; entry 0 is the empty one,
    /// which is not kept here (`items[i - 1]` is entry `i`).
    items: Vec<(Item, u32)>,
    /// The groups each may read: those its states keep.
    needs: Vec<Mask>,
    index: HashMap<(Item, u32), u32>,
}

/// A place in the search: what is still to be matched, where, and the
/// groups that may still be read.
type State = (u32, u16, Groups);

/// The search from one start, depth first, so that the first way found is
/// enough: the states it is in, each with what it leads to and how many of
/// those it has walked. Every state leads only to states further on (an
/// offset further; or what is left to match smaller; or, at a repetition,
/// a pass more counted, or more of the groups matching nothing, as a pass
/// that matches nothing sets each group it sets to nothing and one that
/// changes no group is not made, [`Search::pass`]), so a state none of
/// whose next states matches does not match, and no start walks it again
/// ([`Search::dead`]).
#[derive(Default)]
struct Walk {
    path: Vec<(State, Vec<State>, usize)>,
    /// The state it starts from, while it has not been walked.
    first: Option<State>,
}

/// The most groups a pass of a repetition may set for its passes to be
/// listed whole, each at once, rather than walked ([`Search::pass`]).
const EAGER_PASS: u32 = 2;

/// The bytes of a table of `T` with room for `capacity`: a byte of its own
/// for each entry, and an eighth more entries than it says it has room for.
fn room<T>(capacity: usize) -> usize {
    capacity
        .saturating_add(capacity / 7)
        .saturating_mul(std::mem::size_of::<T>().saturating_add(1))
}

fn table<K, V>(m: &HashMap<K, V>) -> usize {
    room::<(K, V)>(m.capacity())
}

/// How often, in steps, [`Search::held`] is counted.
const HELD_EVERY: u64 = 1 << 10;

/// The bytes of one state on a walk's path, with what it leads to.
fn path_bytes(next: &Vec<State>) -> usize {
    next.capacity()
        .saturating_mul(std::mem::size_of::<State>())
        .saturating_add(std::mem::size_of::<(State, Vec<State>, usize)>())
}

/// How much of a continuation [`Search::may_finish`] reads.
const CHECKED: usize = 64;

/// The first turn each start is given, in steps; each round doubles it.
const FIRST_SLICE: u64 = 32;

struct Search<'e, 'c> {
    engine: &'e Engine,
    command: &'c Command<'c>,
    /// What each repetition, and what is under one, answered, for an
    /// offset and the groups it reads.
    memo: HashMap<(u32, u16, Groups), Ends>,
    conts: Conts,
    /// The states from which nothing matches.
    dead: std::collections::HashSet<State>,
    /// What [`Search::canon`] has said, for each span it was asked.
    canon: HashMap<(u16, u16), Span>,
    /// Each node's [`Engine::matrix`], as [`Search::may_finish`] asks.
    over: HashMap<u32, Rc<Mat>>,
    /// Each repetition's child's [`Engine::matrix`], any number of times.
    star: HashMap<u32, Rc<Mat>>,
    /// What [`Search::may_read`] has said.
    read: HashMap<(u32, u16, u16, Span), bool>,
    /// What [`Search::empty`] has said.
    empties: HashMap<(u32, u16, Groups), Rc<[Mask]>>,
    /// Steps taken, by every start.
    spent: u64,
    /// Bytes held outside the tables: what they point to, and the walks'
    /// paths ([`Search::held`]).
    kept: usize,
    /// Steps taken in this turn.
    round: u64,
    /// How many a turn may take.
    slice: u64,
}

/// What one state leads to.
enum Next {
    Match,
    States(Vec<State>),
}

impl Search<'_, '_> {
    fn charge(&mut self, units: usize) -> Result<(), Stop> {
        let units = u64::try_from(units).unwrap_or(u64::MAX);
        let before = self.spent;
        self.spent = self.spent.saturating_add(units);
        self.round = self.round.saturating_add(units);
        if self.spent > self.engine.budget {
            return Err(Stop::Exhausted);
        }
        // What it holds, counted every so many steps.
        if before / HELD_EVERY != self.spent / HELD_EVERY && self.held() > self.engine.memory {
            return Err(Stop::Exhausted);
        }
        if self.round > self.slice {
            return Err(Stop::Turn);
        }
        Ok(())
    }

    /// About how many bytes the search holds: each table as the room it
    /// has, and what it keeps outside them.
    fn held(&self) -> usize {
        [
            room::<State>(self.dead.capacity()),
            table(&self.memo),
            table(&self.canon),
            table(&self.over),
            table(&self.star),
            table(&self.read),
            table(&self.empties),
            table(&self.conts.index),
            self.conts
                .items
                .capacity()
                .saturating_mul(std::mem::size_of::<(Item, u32)>()),
            self.conts.needs.capacity().saturating_mul(2),
            self.kept,
        ]
        .iter()
        .fold(0usize, |acc, &b| acc.saturating_add(b))
    }

    /// Before an entry is added to a table of `T` holding `len` with room
    /// for `capacity`: whether the room it then takes, with what the search
    /// holds, is within [`SEARCH_MEMORY`]. The two largest tables are asked
    /// this, so that the room a table grows to is held to it before it is
    /// taken.
    fn grows<T>(&self, len: usize, capacity: usize) -> Result<(), Stop> {
        if len < capacity {
            return Ok(());
        }
        let grown = room::<T>(capacity.saturating_mul(2).max(4));
        if self.held().saturating_add(grown) > self.engine.memory {
            return Err(Stop::Exhausted);
        }
        Ok(())
    }

    /// Whether the expression matches from any of `starts`: `None` past
    /// the budget. Each start is searched in turns, every start in a round
    /// one turn of the same length, each round's twice the last's; a turn
    /// that ends inside a repetition asks it again next time, from what it
    /// kept. So a match the search from one start finds in `t` steps is
    /// found within `4 (n + 2) t` steps of all of them, `n` the command's
    /// length, however long the others would search.
    fn run(&mut self, root: u32, starts: &[usize]) -> Option<bool> {
        let mut walks = Vec::with_capacity(starts.len());
        for &at in starts {
            let first = self.cont(Item::Node(root), 0).ok()?;
            let state = (first, offset(at), self.keep(first, &[UNSET; GROUPS]));
            walks.push(Walk {
                path: Vec::new(),
                first: Some(state),
            });
        }
        loop {
            let mut left = false;
            for walk in &mut walks {
                if walk.path.is_empty() && walk.first.is_none() {
                    continue;
                }
                self.round = 0;
                match self.walk(walk) {
                    Ok(true) => return Some(true),
                    Ok(false) => *walk = Walk::default(),
                    Err(Stop::Turn) => left = true,
                    Err(Stop::Exhausted) => return None,
                }
            }
            if !left {
                return Some(false);
            }
            self.slice = self.slice.saturating_mul(2);
        }
    }

    /// One turn of `walk`: whether it found a match, or walked every state
    /// it leads to.
    fn walk(&mut self, walk: &mut Walk) -> Result<bool, Stop> {
        loop {
            // The next state to walk: the first, or the next one the
            // deepest state on the path leads to.
            let state = if let Some(first) = walk.first {
                first
            } else {
                let Some((state, next, done)) = walk.path.last_mut() else {
                    return Ok(false);
                };
                let Some(&to) = next.get(*done) else {
                    // None of what it leads to matches.
                    let state = *state;
                    if let Some((_, next, _)) = walk.path.pop() {
                        self.kept = self.kept.saturating_sub(path_bytes(&next));
                    }
                    let room = self.dead.capacity();
                    self.grows::<State>(self.dead.len(), room)?;
                    self.dead.insert(state);
                    self.charge(1)?;
                    continue;
                };
                *done = done.saturating_add(1);
                if self.dead.contains(&to) {
                    continue;
                }
                to
            };
            match self.next(state) {
                Ok(Next::Match) => return Ok(true),
                Ok(Next::States(states)) => {
                    walk.first = None;
                    self.kept = self.kept.saturating_add(path_bytes(&states));
                    walk.path.push((state, states, 0));
                }
                Err(stop) => {
                    // Walked again on its next turn.
                    if walk.first.is_none() {
                        if let Some((_, _, done)) = walk.path.last_mut() {
                            *done = done.saturating_sub(1);
                        }
                    }
                    return Err(stop);
                }
            }
        }
    }

    /// The continuation `item`, then `rest`.
    fn cont(&mut self, item: Item, rest: u32) -> Result<u32, Stop> {
        if let Some(&id) = self.conts.index.get(&(item, rest)) {
            return Ok(id);
        }
        self.charge(1)?;
        let e = self.engine;
        let needs = match item {
            Item::Node(id) => {
                e.reads.get(id as usize).copied().unwrap_or(0)
                    | e.live.get(id as usize).copied().unwrap_or(0)
            }
            Item::Close { group, .. } => e.live.get(group as usize).copied().unwrap_or(0),
            Item::Rep { node, .. } | Item::PassEnd { node, .. } => {
                e.reads.get(node as usize).copied().unwrap_or(0)
                    | e.live.get(node as usize).copied().unwrap_or(0)
            }
        };
        self.conts.items.push((item, rest));
        self.conts.needs.push(needs);
        let id = u32::try_from(self.conts.items.len()).unwrap_or(u32::MAX);
        self.conts.index.insert((item, rest), id);
        Ok(id)
    }

    /// Of `groups`, what continuation `cont` may read.
    fn keep(&self, cont: u32, groups: &Groups) -> Groups {
        let needs = cont
            .checked_sub(1)
            .and_then(|i| self.conts.needs.get(i as usize))
            .copied()
            .unwrap_or(0);
        only(groups, needs)
    }

    /// What `state` leads to: the states after its first item, the first
    /// of them the one to walk first (a repetition's fewest passes, an
    /// alternation's first), or a match.
    fn next(&mut self, (cont, at, groups): State) -> Result<Next, Stop> {
        self.charge(1)?;
        let Some(&(item, rest)) = cont
            .checked_sub(1)
            .and_then(|i| self.conts.items.get(i as usize))
        else {
            return Ok(Next::Match);
        };
        let e = self.engine;
        let pos = usize::from(at);
        let mut out = Vec::new();
        let id = match item {
            Item::Close { group, start } => {
                let mut groups = groups;
                if let Node::Group { index, .. } = e.node(group) {
                    if let Some(g) = groups.get_mut(*index) {
                        *g = self.canon(usize::from(start), pos)?;
                    }
                }
                if !self.may_finish(rest, at, &groups)? {
                    return Ok(Next::States(Vec::new()));
                }
                out.push((rest, at, groups));
                return self.states(out);
            }
            Item::Rep { node, passes } => return self.pass(node, passes, rest, at, groups),
            Item::PassEnd { start, .. } => {
                if at <= start {
                    // A pass that matches nothing is made at once.
                    return Ok(Next::States(Vec::new()));
                }
                let groups = match rest
                    .checked_sub(1)
                    .and_then(|i| self.conts.items.get(i as usize))
                {
                    Some(&(Item::Rep { node, .. }, after)) => {
                        let kept = self.keep(rest, &groups);
                        self.unread(node, rest, after, at, kept)?
                    }
                    _ => groups,
                };
                out.push((rest, at, groups));
                return self.states(out);
            }
            Item::Node(id) => id,
        };
        match e.node(id) {
            Node::Empty => out.push((rest, at, groups)),
            Node::Unit(_) => {
                let lengths = e.unit(id).map_or(0, |u| u.lengths(self.command, pos));
                for len in 1..8usize {
                    if lengths & (1 << len) != 0 {
                        out.push((rest, offset(pos.saturating_add(len)), groups));
                    }
                }
            }
            Node::Look(look) => {
                if e.look(look, self.command, pos) {
                    out.push((rest, at, groups));
                }
            }
            Node::BackRef(n) => {
                if let Some(len) = self.back_reference(usize::from(*n), pos, &groups) {
                    out.push((rest, offset(pos.saturating_add(len)), groups));
                }
            }
            Node::Concat(children) => {
                let mut c = rest;
                for &child in children.iter().rev() {
                    c = self.cont(Item::Node(child), c)?;
                }
                out.push((c, at, groups));
            }
            Node::Alt(children) => {
                for &child in children {
                    let c = self.cont(Item::Node(child), rest)?;
                    out.push((c, at, groups));
                }
            }
            Node::Group { index, child } => {
                let mut c = rest;
                if e.writes.get(id as usize).copied().unwrap_or(0) & group_bit(*index) != 0 {
                    c = self.cont(
                        Item::Close {
                            group: id,
                            start: at,
                        },
                        c,
                    )?;
                }
                let c = self.cont(Item::Node(*child), c)?;
                out.push((c, at, groups));
            }
            Node::Repeat { child, min, .. } => {
                if rest == 0 {
                    // Nothing after it: the passes it must make are enough.
                    return Ok(if self.passes(*child, *min, pos, &groups)? {
                        Next::Match
                    } else {
                        Next::States(Vec::new())
                    });
                }
                if e.writes.get(*child as usize).copied().unwrap_or(0) == 0 {
                    // It sets no group that is read: every way it can end
                    // is an offset, and few.
                    let found = self.eval(id, pos, &groups)?;
                    self.charge(found.len())?;
                    out.extend(found.iter().map(|&(end, _)| (rest, end, groups)));
                } else {
                    // One pass at a time, as what is left to match: the
                    // ways it can end, with every group each way sets, are
                    // too many to list where it sets two or more that are
                    // read after it.
                    let c = self.cont(
                        Item::Rep {
                            node: id,
                            passes: 0,
                        },
                        rest,
                    )?;
                    out.push((c, at, groups));
                }
            }
        }
        self.states(out)
    }

    /// What a state at repetition `node`, after `passes` passes, leads to:
    /// its end, once it has made its least, first (the fewest passes), and
    /// then each way one more pass can end. A pass that matches nothing and
    /// changes no group that may be read leads back to the same state, and
    /// is left out: a pass that matches nothing sets each group it sets to
    /// nothing, so a state leads only to states further on, or with more of
    /// its groups matching nothing.
    fn pass(
        &mut self,
        node: u32,
        passes: u32,
        rest: u32,
        at: u16,
        groups: Groups,
    ) -> Result<Next, Stop> {
        let e = self.engine;
        let Node::Repeat { child, min, max } = e.node(node) else {
            return Ok(Next::States(Vec::new()));
        };
        let child = *child;
        // Past `cap` passes a pass more or less changes nothing.
        let cap = self.cap(child);
        let min = (*min).min(cap);
        let max = max.filter(|&m| m < cap);
        let mut out = Vec::new();
        if passes >= min {
            if rest == 0 {
                return Ok(Next::Match);
            }
            // What it set is checked as it was set, and a group nothing
            // after can read is unset ([`Search::unread`]).
            out.push((rest, at, groups));
        }
        if max.is_none_or(|m| passes < m) {
            let more = match max {
                Some(_) => passes.saturating_add(1),
                None => passes.saturating_add(1).min(min),
            };
            let c = self.cont(Item::Rep { node, passes: more }, rest)?;
            // The passes that match nothing, each a set of groups it sets
            // to nothing, made at once.
            let empty = self.empty(child, usize::from(at), &groups)?;
            let before = self.unread(node, c, rest, at, self.keep(c, &groups))?;
            for &set in empty.iter() {
                let mut now = groups;
                for (k, g) in now.iter_mut().enumerate() {
                    if set & group_bit(k) != 0 {
                        *g = span(0, 0);
                    }
                }
                let now = self.unread(node, c, rest, at, self.keep(c, &now))?;
                if more == passes && now == before {
                    continue;
                }
                out.push((c, at, now));
            }
            if e.path_sets.get(child as usize).copied().unwrap_or(u32::MAX) <= EAGER_PASS {
                // A pass that sets few groups: every way it can end, and
                // what it sets, are few, and listed at once.
                let found = self.eval(child, usize::from(at), &groups)?;
                self.charge(found.len())?;
                for &(end, changed) in found.iter() {
                    if end == at {
                        continue;
                    }
                    let now = self.keep(c, &apply(&groups, &changed));
                    let now = self.unread(node, c, rest, end, now)?;
                    out.push((c, end, now));
                }
            } else {
                // One that matches something, walked as the rest is.
                let end = self.cont(Item::PassEnd { node, start: at }, c)?;
                let walk = self.cont(Item::Node(child), end)?;
                out.push((walk, at, groups));
            }
        }
        self.states(out)
    }

    /// The ways `id` can match nothing at `at`, with the groups as `groups`
    /// has them: each the set of groups (that a back-reference names) it
    /// sets on the way, each to nothing. A group set to nothing is one a
    /// back-reference to it then matches nothing with, so where a set of
    /// them is set no way of matching nothing is lost: the passes of a
    /// repetition that match nothing make, past enough of them, every set
    /// they can. Kept, for `id`, `at` and the groups it reads.
    fn empty(&mut self, id: u32, at: usize, groups: &Groups) -> Result<Rc<[Mask]>, Stop> {
        let e = self.engine;
        self.charge(1)?;
        let none: Rc<[Mask]> = Rc::from([]);
        let nothing: Rc<[Mask]> = Rc::from([0]);
        match e.node(id) {
            Node::Empty => return Ok(nothing),
            Node::Unit(_) => return Ok(none),
            Node::Look(look) => {
                return Ok(if e.look(look, self.command, at) {
                    nothing
                } else {
                    none
                });
            }
            Node::BackRef(n) => {
                let len = self.back_reference(usize::from(*n), at, groups);
                return Ok(if len == Some(0) { nothing } else { none });
            }
            _ => {}
        }
        let reads = e.reads.get(id as usize).copied().unwrap_or(0);
        let key = (id, offset(at), only(groups, reads));
        if let Some(found) = self.empties.get(&key) {
            return Ok(Rc::clone(found));
        }
        let with = |set: Mask| {
            let mut g = *groups;
            for (k, slot) in g.iter_mut().enumerate() {
                if set & group_bit(k) != 0 {
                    *slot = span(0, 0);
                }
            }
            g
        };
        let mut out: Vec<Mask> = Vec::new();
        match e.node(id) {
            Node::Empty | Node::Unit(_) | Node::Look(_) | Node::BackRef(_) => {}
            Node::Alt(children) => {
                for &c in children {
                    let found = self.empty(c, at, groups)?;
                    self.charge(found.len())?;
                    out.extend(found.iter());
                }
            }
            Node::Group { index, child } => {
                let bit = group_bit(*index) & e.writes.get(id as usize).copied().unwrap_or(0);
                let found = self.empty(*child, at, groups)?;
                self.charge(found.len())?;
                out.extend(found.iter().map(|&m| m | bit));
            }
            Node::Concat(children) => {
                let mut sets: Vec<Mask> = vec![0];
                for &c in children {
                    let mut next = Vec::new();
                    for &set in &sets {
                        let found = self.empty(c, at, &with(set))?;
                        self.charge(found.len())?;
                        next.extend(found.iter().map(|&m| m | set));
                    }
                    next.sort_unstable();
                    next.dedup();
                    sets = next;
                    if sets.is_empty() {
                        break;
                    }
                }
                out = sets;
            }
            Node::Repeat { child, min, max } => {
                if *min == 0 {
                    out.push(0);
                }
                if max.is_none_or(|m| m > 0) {
                    // What a number of passes can set, each of them
                    // matching nothing: every set one fewer can (make the
                    // last again), and more, so that they stop changing
                    // within a pass for each set there can be.
                    let most = max.unwrap_or(u32::MAX);
                    let mut sets: Vec<Mask> = vec![0];
                    let mut all: Vec<Mask> = Vec::new();
                    let mut pass = 0u32;
                    while pass < most {
                        let mut next = Vec::new();
                        for &set in &sets {
                            let found = self.empty(*child, at, &with(set))?;
                            self.charge(found.len())?;
                            next.extend(found.iter().map(|&m| m | set));
                        }
                        next.sort_unstable();
                        next.dedup();
                        pass = pass.saturating_add(1);
                        if next.is_empty() {
                            break;
                        }
                        let same = next == sets;
                        sets = next;
                        // Once a pass more adds none, none ever does: what
                        // these passes make, any more make.
                        if pass >= *min || same {
                            all.extend(sets.iter());
                        }
                        if same {
                            break;
                        }
                    }
                    out.extend(all);
                }
            }
        }
        out.sort_unstable();
        out.dedup();
        self.charge(out.len())?;
        let found: Rc<[Mask]> = out.into();
        self.kept = self.kept.saturating_add(found.len().saturating_mul(2));
        self.empties.insert(key, Rc::clone(&found));
        Ok(found)
    }

    /// `groups`, at repetition `node` (continuation `c`, `rest` after the
    /// repetition) at `at`, each group whose match nothing after can read
    /// taken as unset: so the states that differ only in such a group are
    /// one. Only the groups the passes set are asked about, as those are
    /// what makes the states of a repetition many; one the passes read is
    /// kept. A back-reference reads a group's match only while the group
    /// is as `groups` has it; where none can match its text before the
    /// group is surely set again ([`Search::may_read`]), what matches from
    /// the state matches as well with the group unset (a back-reference to
    /// it matching nothing either way), and what does not, does not.
    fn unread(
        &mut self,
        node: u32,
        c: u32,
        rest: u32,
        at: u16,
        groups: Groups,
    ) -> Result<Groups, Stop> {
        let e = self.engine;
        let Node::Repeat { child, .. } = e.node(node) else {
            return Ok(groups);
        };
        let child_reads = e.reads.get(*child as usize).copied().unwrap_or(0);
        let child_writes = e.writes.get(*child as usize).copied().unwrap_or(0);
        let mut out = groups;
        for (k, g) in out.iter_mut().enumerate() {
            let bit = group_bit(k);
            if *g == UNSET || child_reads & bit != 0 || child_writes & bit == 0 {
                continue;
            }
            if !self.may_read(c, node, rest, at, k, *g)? {
                *g = UNSET;
            }
        }
        Ok(out)
    }

    /// Whether some back-reference to group `k` may read its match `g`:
    /// from `at`, after more passes of repetition `node` (which do not read
    /// the group, and may set it again) and then `rest`, as far as
    /// [`CHECKED`] items tell, every node taken as its [`Engine::matrix`].
    /// False where none is reached, or none that is reached can match
    /// `g`'s text from anywhere it may be reached (where it cannot, the
    /// group has been set again by then, or nothing matches). Kept for `c`
    /// (the repetition, then `rest`), `at`, `k` and `g`.
    fn may_read(
        &mut self,
        c: u32,
        node: u32,
        rest: u32,
        at: u16,
        k: usize,
        g: Span,
    ) -> Result<bool, Stop> {
        let key = (c, at, offset(k), g);
        if let Some(&answer) = self.read.get(&key) {
            return Ok(answer);
        }
        let answer = self.may_read_from(node, rest, at, k, g)?;
        self.charge(1)?;
        self.read.insert(key, answer);
        Ok(answer)
    }

    /// [`Search::may_read`], not kept.
    fn may_read_from(
        &mut self,
        node: u32,
        rest: u32,
        at: u16,
        k: usize,
        g: Span,
    ) -> Result<bool, Stop> {
        let e = self.engine;
        let bit = group_bit(k);
        let n = self.command.len();
        let words = n.saturating_add(1).div_ceil(64);
        let Node::Repeat { child, .. } = e.node(node) else {
            return Ok(true);
        };
        // Where any number of passes may end.
        let star = self.star(*child)?;
        let mut reach: Vec<u64> = star.row(usize::from(at)).to_vec();
        let mut cont = rest;
        let row = |m: &Mat, reach: &[u64]| {
            let mut next = vec![0u64; words];
            for from in ones(reach) {
                for (d, s) in next.iter_mut().zip(m.row(from)) {
                    *d |= s;
                }
            }
            next
        };
        for _ in 0..CHECKED {
            if reach.iter().all(|&w| w == 0) {
                return Ok(false);
            }
            let Some(&(item, next)) = cont
                .checked_sub(1)
                .and_then(|i| self.conts.items.get(i as usize))
            else {
                // The end, and the group never read.
                return Ok(false);
            };
            self.charge(1)?;
            match item {
                // A group the passes set is under the repetition, and
                // nothing after it holds that group, so nothing after sets
                // it again but a repetition the walk is inside of, which
                // is taken as any number of its passes.
                Item::PassEnd { .. } | Item::Close { .. } => {}
                Item::Rep { node: r, .. } => {
                    if e.reads.get(r as usize).copied().unwrap_or(0) & bit != 0 {
                        return Ok(true);
                    }
                    let Node::Repeat { child: rc, .. } = e.node(r) else {
                        return Ok(true);
                    };
                    let m = self.star(*rc)?;
                    reach = row(&m, &reach);
                }
                Item::Node(id) => match e.node(id) {
                    Node::BackRef(j) if usize::from(*j) == k => {
                        let mut hit = false;
                        for from in ones(&reach) {
                            if self
                                .back_reference(k, from, &only(&[g; GROUPS], bit))
                                .is_some()
                            {
                                hit = true;
                                break;
                            }
                        }
                        if hit {
                            return Ok(true);
                        }
                        // Where it fails, the group may have been set
                        // again by then.
                        let m = self.over(id)?;
                        reach = row(&m, &reach);
                    }
                    _ => {
                        if e.reads.get(id as usize).copied().unwrap_or(0) & bit != 0 {
                            return Ok(true);
                        }
                        let m = self.over(id)?;
                        reach = row(&m, &reach);
                    }
                },
            }
            cont = next;
        }
        Ok(true)
    }

    /// Any number of passes of `child`, none included, each as its
    /// [`Engine::matrix`]: kept.
    fn star(&mut self, child: u32) -> Result<Rc<Mat>, Stop> {
        if let Some(m) = self.star.get(&child) {
            return Ok(Rc::clone(m));
        }
        let once = self.over(child)?;
        self.charge(self.command.len().saturating_add(1))?;
        let m = Rc::new(once.closure());
        self.kept = self.kept.saturating_add(m.bits.len().saturating_mul(8));
        self.star.insert(child, Rc::clone(&m));
        Ok(m)
    }

    /// Whether `cont` may match from `at`, as far as [`CHECKED`] items of
    /// it tell: each back-reference whose group is as `groups` has it
    /// matched as what the group matched, and every other node as if its
    /// back-references matched anything ([`Engine::matrix`]). Where this
    /// says no, nothing matches; it is asked where a group has just been
    /// set, so that a search does not go on past a group that cannot be
    /// matched again where it is named.
    fn may_finish(&mut self, cont: u32, at: u16, groups: &Groups) -> Result<bool, Stop> {
        let e = self.engine;
        let n = self.command.len();
        let words = n.saturating_add(1).div_ceil(64);
        let mut reach = vec![0u64; words];
        let at = usize::from(at);
        if let Some(w) = reach.get_mut(at / 64) {
            *w |= 1 << (at % 64);
        }
        // The groups whose match is still the one `groups` has.
        let mut known: Mask = Mask::MAX;
        let mut cont = cont;
        for _ in 0..CHECKED {
            let Some(&(item, rest)) = cont
                .checked_sub(1)
                .and_then(|i| self.conts.items.get(i as usize))
            else {
                return Ok(true);
            };
            self.charge(1)?;
            match item {
                Item::Close { group, .. } => {
                    if let Some(Node::Group { index, .. }) = e.nodes.get(group as usize) {
                        known &= !group_bit(*index);
                    }
                }
                Item::PassEnd { .. } => {}
                Item::Rep { node, .. } => {
                    // The rest of a repetition: any number of passes more,
                    // as many as there are or none, a superset of what it
                    // may still make, whatever it has made.
                    let Node::Repeat { child, .. } = e.node(node) else {
                        return Ok(true);
                    };
                    let m = self.star(*child)?;
                    known &= !e.writes.get(node as usize).copied().unwrap_or(0);
                    let mut next = vec![0u64; words];
                    for from in ones(&reach) {
                        for (d, s) in next.iter_mut().zip(m.row(from)) {
                            *d |= s;
                        }
                    }
                    reach = next;
                }
                Item::Node(id) => {
                    let next = match e.node(id) {
                        Node::BackRef(k) if known & group_bit(usize::from(*k)) != 0 => {
                            let mut next = vec![0u64; words];
                            for from in ones(&reach) {
                                let len = self.back_reference(usize::from(*k), from, groups);
                                if let Some(to) = len.map(|l| from.saturating_add(l)) {
                                    if let Some(w) = next.get_mut(to / 64) {
                                        *w |= 1 << (to % 64);
                                    }
                                }
                            }
                            next
                        }
                        _ => {
                            let m = self.over(id)?;
                            known &= !e.writes.get(id as usize).copied().unwrap_or(0);
                            let mut next = vec![0u64; words];
                            for from in ones(&reach) {
                                for (d, s) in next.iter_mut().zip(m.row(from)) {
                                    *d |= s;
                                }
                            }
                            next
                        }
                    };
                    if next.iter().all(|&w| w == 0) {
                        return Ok(false);
                    }
                    reach = next;
                }
            }
            cont = rest;
        }
        Ok(true)
    }

    /// What a group that matched from `start` to `end` is kept as: the
    /// first place in the command that holds the same bytes (and, under
    /// `REG_ICASE`, the same folded bytes), for a back-reference reads only
    /// those. So the states of two starts whose groups hold the same text
    /// are one, and what nothing matches from is known for both.
    fn canon(&mut self, start: usize, end: usize) -> Result<Span, Stop> {
        if start >= end {
            return Ok(span(0, 0));
        }
        if let Some(&g) = self.canon.get(&(offset(start), offset(end))) {
            return Ok(g);
        }
        self.charge(1)?;
        let c = self.command;
        let len = end.saturating_sub(start);
        let same = |p: usize| {
            let end_p = p.saturating_add(len);
            c.bytes.get(p..end_p) == c.bytes.get(start..end)
                && (!self.engine.icase || c.folded.get(p..end_p) == c.folded.get(start..end))
        };
        let first = (0..start).find(|&p| same(p)).unwrap_or(start);
        let g = span(first, first.saturating_add(len));
        self.canon.insert((offset(start), offset(end)), g);
        Ok(g)
    }

    /// [`Engine::matrix`] for `id`, kept.
    fn over(&mut self, id: u32) -> Result<Rc<Mat>, Stop> {
        if let Some(m) = self.over.get(&id) {
            return Ok(Rc::clone(m));
        }
        // A matrix is a row for each offset.
        self.charge(self.command.len().saturating_add(1))?;
        let e = self.engine;
        let command = self.command;
        let mut failed = None;
        let m = e.matrix_with(id, command, &mut |c| match self.over(c) {
            Ok(m) => (*m).clone(),
            Err(stop) => {
                failed = Some(stop);
                Mat::empty(command.len())
            }
        });
        if let Some(stop) = failed {
            return Err(stop);
        }
        let m = Rc::new(m);
        self.kept = self.kept.saturating_add(m.bits.len().saturating_mul(8));
        self.over.insert(id, Rc::clone(&m));
        Ok(m)
    }

    /// `states`, each with only the groups its continuation may read.
    fn states(&mut self, mut states: Vec<State>) -> Result<Next, Stop> {
        // What a walk keeps of them is paid for before it is kept.
        self.charge(states.len())?;
        for (cont, _, groups) in &mut states {
            if *cont == 0 {
                return Ok(Next::Match);
            }
            *groups = self.keep(*cont, groups);
        }
        Ok(Next::States(states))
    }

    /// Whether `child` can make `min` passes from `at`.
    fn passes(&mut self, child: u32, min: u32, at: usize, groups: &Groups) -> Result<bool, Stop> {
        let mut states = vec![(offset(at), KEEP)];
        for _ in 0..min.min(self.cap(child)) {
            states = self.step(child, &states, groups)?;
            if states.is_empty() {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Where `id` can end from `at`, with the groups as `groups` has them,
    /// and what it sets of those that may be read after it.
    fn eval(&mut self, id: u32, at: usize, groups: &Groups) -> Result<Ends, Stop> {
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
                            *g = self.canon(at, usize::from(end))?;
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
        self.kept = self.kept.saturating_add(
            found
                .len()
                .saturating_mul(std::mem::size_of::<(u16, Groups)>()),
        );
        self.grows::<((u32, u16, Groups), Ends)>(self.memo.len(), self.memo.capacity())?;
        self.memo.insert(key, Rc::clone(&found));
        Ok(found)
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
    ) -> Result<Vec<(u16, Groups)>, Stop> {
        let e = self.engine;
        let after = e.live.get(id as usize).copied().unwrap_or(0);
        // What `id` sets however it matches it sets again: what a state had
        // there makes no difference. (A pass reads a group of its own only
        // after it has set it: glibc refuses a back-reference before its
        // group closes, as the translator does.)
        let again = e.must.get(id as usize).copied().unwrap_or(0);
        let mut states = states.to_vec();
        if again != 0 {
            for (_, changed) in &mut states {
                *changed = only_changed(changed, !again);
            }
            states.sort_unstable();
            states.dedup();
        }
        let mut next = Vec::new();
        for &(at, changed) in &states {
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
        back_reference(self.command, self.engine.icase, *groups.get(n)?, at)
    }
}

/// How many bytes a back-reference to a group that matched `g` takes at
/// `at` of `command`: what the group matched, again; under `REG_ICASE` each
/// character in the case `towupper()` gives it. Nothing, where the group
/// has matched nothing.
fn back_reference(command: &Command<'_>, icase: bool, g: Span, at: usize) -> Option<usize> {
    if g == UNSET || g == UNCHANGED {
        return None;
    }
    let (start, end) = (
        usize::from(u16::try_from(g >> 16).ok()?),
        usize::from(u16::try_from(g & 0xffff).ok()?),
    );
    let bytes = command.bytes;
    let matched = bytes.get(start..end)?;
    if !icase {
        return bytes
            .get(at..)?
            .starts_with(matched)
            .then_some(matched.len());
    }
    // Character by character, as `towupper()` has them; where either side
    // is no character (or the group ends inside one), byte by byte, as
    // glibc compares its folded copy of the command.
    let (mut i, mut j) = (start, at);
    while i < end {
        match (command.char_at(i), command.char_at(j)) {
            (Some((x, lx)), Some((y, ly))) if i.saturating_add(lx) <= end => {
                if upper(x) != upper(y) {
                    return None;
                }
                i = i.saturating_add(lx);
                j = j.saturating_add(ly);
            }
            _ => {
                if command.folded.get(i)? != command.folded.get(j)? {
                    return None;
                }
                i = i.saturating_add(1);
                j = j.saturating_add(1);
            }
        }
    }
    Some(j.saturating_sub(at))
}

/// The longest command [`super::CommandRegex::oracle`] searches.
pub const ORACLE_COMMAND_MAX: usize = 8;

/// [`Engine::oracle`]'s search.
struct Oracle<'e, 'c> {
    engine: &'e Engine,
    command: &'c Command<'c>,
    steps: u64,
    limit: u64,
    depth: u32,
}

/// What is matched after a node, and whether it matches: from where the
/// node ended, with the groups as they are there.
type Then<'a> = dyn FnMut(&mut Oracle<'_, '_>, usize, Groups) -> bool + 'a;

impl Oracle<'_, '_> {
    /// Whether `id` matches from `at` and `then` after it. How deep the
    /// search is, in calls of this, is held to [`ORACLE_DEPTH`]: past it,
    /// as past its steps, there is no answer.
    fn matches(&mut self, id: u32, at: usize, groups: Groups, then: &mut Then<'_>) -> bool {
        self.steps = self.steps.saturating_add(1);
        if self.steps > self.limit || self.depth >= ORACLE_DEPTH {
            self.steps = self.limit.saturating_add(1);
            return false;
        }
        self.depth = self.depth.saturating_add(1);
        let found = self.node_matches(id, at, groups, then);
        self.depth = self.depth.saturating_sub(1);
        found
    }

    fn node_matches(&mut self, id: u32, at: usize, groups: Groups, then: &mut Then<'_>) -> bool {
        let e = self.engine;
        match e.node(id) {
            Node::Empty => then(self, at, groups),
            Node::Unit(_) => {
                let lengths = e.unit(id).map_or(0, |u| u.lengths(self.command, at));
                (1..8usize).any(|len| {
                    lengths & (1 << len) != 0 && then(self, at.saturating_add(len), groups)
                })
            }
            Node::Look(look) => e.look(look, self.command, at) && then(self, at, groups),
            Node::BackRef(n) => {
                let Some(&g) = groups.get(usize::from(*n)) else {
                    return false;
                };
                let len = if e.icase {
                    back_reference(self.command, true, g, at)
                } else if g == UNSET {
                    None
                } else {
                    let (start, end) = (
                        usize::from(offset((g >> 16) as usize)),
                        usize::from(offset((g & 0xffff) as usize)),
                    );
                    let bytes = self.command.bytes;
                    let matched = bytes.get(start..end).unwrap_or_default();
                    (bytes.get(at..).unwrap_or_default().starts_with(matched))
                        .then_some(matched.len())
                };
                len.is_some_and(|len| then(self, at.saturating_add(len), groups))
            }
            Node::Concat(children) => self.sequence(children, 0, at, groups, then),
            Node::Alt(children) => children.iter().any(|&c| self.matches(c, at, groups, then)),
            Node::Group { index, child } => {
                let index = *index;
                self.matches(*child, at, groups, &mut |o, end, mut g| {
                    if let Some(slot) = g.get_mut(index) {
                        *slot = span(at, end);
                    }
                    then(o, end, g)
                })
            }
            Node::Repeat { child, min, max } => {
                let most = u32::try_from(
                    self.command
                        .len()
                        .saturating_add(2)
                        .saturating_mul(GROUPS + 2),
                )
                .unwrap_or(u32::MAX);
                let max = max.unwrap_or(most).min(most);
                self.passes(*child, (*min).min(most), max, 0, at, groups, then)
            }
        }
    }

    fn sequence(
        &mut self,
        children: &[u32],
        i: usize,
        at: usize,
        groups: Groups,
        then: &mut Then<'_>,
    ) -> bool {
        let Some(&c) = children.get(i) else {
            return then(self, at, groups);
        };
        self.matches(c, at, groups, &mut |o, end, g| {
            o.sequence(children, i.saturating_add(1), end, g, then)
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn passes(
        &mut self,
        child: u32,
        min: u32,
        max: u32,
        done: u32,
        at: usize,
        groups: Groups,
        then: &mut Then<'_>,
    ) -> bool {
        if done >= min && then(self, at, groups) {
            return true;
        }
        if done >= max {
            return false;
        }
        self.matches(child, at, groups, &mut |o, end, g| {
            o.passes(child, min, max, done.saturating_add(1), end, g, then)
        })
    }
}

/// How deep [`Engine::oracle`] goes: past it, it has no answer.
const ORACLE_DEPTH: u32 = 300;

/// `towupper()` in glibc 2.39's C.UTF-8: the simple upper case of a
/// character, one character for one (`ᾳ` is `ᾼ`, `ß` is itself), from a
/// table measured from glibc, not from Rust's case tables, which follow the
/// toolchain's Unicode and give the full mapping; a test holds the table to
/// glibc's.
pub(super) fn upper(c: char) -> char {
    TOWUPPER
        .binary_search_by_key(&c, |&(from, _)| from)
        .ok()
        .and_then(|i| TOWUPPER.get(i))
        .map_or(c, |&(_, to)| to)
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
