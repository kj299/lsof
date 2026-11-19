//! `-r`'s marker format, `m<fmt>`: glibc's `strftime(3)` and `localtime(3)`
//! in safe Rust, as the C's `util_strftime()` calls them (`src/util.c`).
//!
//! `std` has neither, so this module is the three things the C library does
//! for that call, each measured against glibc 2.39 (a helper that calls
//! `localtime()` and `strftime()` under a `TZ`, over every conversion, flag
//! and width, the zones of `/usr/share/zoneinfo`, and files made to be
//! wrong):
//!
//! * [`strftime`]: `time/strftime_l.c` in the C locale, into a buffer of a
//!   fixed size, giving 0 where the result does not fit;
//! * [`LocalTime`]: `localtime()`, `mktime()` and `tzset()` with the state
//!   glibc keeps between them (`time/tzset.c`, `time/tzfile.c`,
//!   `time/mktime.c`), a compiled zone file read as `__tzfile_read()` reads
//!   one through a [`ZoneFs`] the platform gives;
//! * [`PosixTz`]: a `TZ` rule string (`time/tzset.c`).
//!
//! Everything here is a parser or arithmetic over bytes the user chose (the
//! format, `TZ`, the file `TZ` names): nothing panics, memory stays within
//! [`DATA_IN_MEMORY`] and [`NAME_KEEP`] whatever a file's size, and no loop
//! runs longer than its input.

use std::cell::RefCell;
use std::rc::Rc;

/// A broken-down time, the members of `struct tm` that `strftime` reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tm {
    pub sec: i32,
    pub min: i32,
    pub hour: i32,
    pub mday: i32,
    /// Months since January.
    pub mon: i32,
    /// Years since 1900.
    pub year: i32,
    /// Days since Sunday.
    pub wday: i32,
    /// Days since January 1.
    pub yday: i32,
    pub isdst: bool,
    /// Seconds east of UTC.
    pub gmtoff: i64,
    /// The zone's abbreviation, `tm_zone`.
    pub zone: Vec<u8>,
}

const SECS_PER_DAY: i64 = 86_400;

fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

/// Days before each month, in a common year and in a leap year
/// (`__mon_yday`).
const MON_YDAY: [[i64; 13]; 2] = [
    [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365],
    [0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366],
];

fn mon_yday(leap: bool, month: usize) -> i64 {
    MON_YDAY
        .get(usize::from(leap))
        .and_then(|row| row.get(month))
        .copied()
        .unwrap_or(0)
}

/// `__offtime()`: second `t` of the epoch, `offset` seconds east, broken
/// down. `None` where the year does not fit an `int` (the C library's
/// `EOVERFLOW`, on which the C calls `strftime` with no time at all).
pub fn offtime(t: i64, offset: i64) -> Option<Tm> {
    let mut days = t.div_euclid(SECS_PER_DAY);
    let mut rem = t.rem_euclid(SECS_PER_DAY).checked_add(offset)?;
    days = days.checked_add(rem.div_euclid(SECS_PER_DAY))?;
    rem = rem.rem_euclid(SECS_PER_DAY);
    let wday = days.checked_add(4)?.rem_euclid(7);
    // Days since 0000-03-01, in 400-year eras of 146,097 days.
    let z = days.checked_add(719_468)?;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let mday = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = era
        .checked_mul(400)?
        .checked_add(yoe)?
        .checked_add(i64::from(month <= 2))?;
    let leap = is_leap(year);
    let yday = mon_yday(leap, usize::try_from(month - 1).ok()?) + mday - 1;
    Some(Tm {
        sec: i32::try_from(rem % 60).ok()?,
        min: i32::try_from(rem / 60 % 60).ok()?,
        hour: i32::try_from(rem / 3600).ok()?,
        mday: i32::try_from(mday).ok()?,
        mon: i32::try_from(month - 1).ok()?,
        year: i32::try_from(year.checked_sub(1900)?).ok()?,
        wday: i32::try_from(wday).ok()?,
        yday: i32::try_from(yday).ok()?,
        isdst: false,
        gmtoff: offset,
        zone: Vec::new(),
    })
}

// ---------------------------------------------------------------- TZ rules

/// How a `TZ` rule names the day of a change (`tz_rule.type`): `n`, day of
/// the year from 0, counting February 29; `Jn`, from 1, not counting it;
/// `Mm.n.d`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum RuleDay {
    #[default]
    J0,
    J1,
    M,
}

/// One half of a `TZ` rule string: `tz_rule`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Rule {
    name: Vec<u8>,
    kind: RuleDay,
    m: u16,
    n: u16,
    d: u16,
    /// Seconds after midnight the change comes.
    secs: i64,
    /// Seconds east of UTC.
    offset: i64,
}

/// A POSIX `TZ` string as glibc's `__tzset_parse_tz()` reads it: standard
/// time and, where it names one, the alternative, with the days they
/// change. A string it reads nothing of is UTC with no name, and one it
/// reads part of keeps that part, as glibc does (`TZ=Foo/Bar` is UTC named
/// `Foo`, `TZ=ABC5,M3.2.0,M11.1.0` has a summer with no name at UTC:
/// measured).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PosixTz {
    rules: [Rule; 2],
}

fn peek(s: &[u8], at: usize) -> u8 {
    s.get(at).copied().unwrap_or(0)
}

/// What a rule string is read from, as a C string: its byte at `i`, and 0
/// at its end and past it. A `TZ` value is a slice; a zone file's footer,
/// which may be as long as the file, is read where it lies
/// ([`FooterText`]), so that no more of it than its names is held.
trait Src {
    fn at(&self, i: usize) -> u8;
}

impl Src for [u8] {
    fn at(&self, i: usize) -> u8 {
        peek(self, i)
    }
}

/// How many bytes from `i` on `keep` takes (each read once; a C string's
/// end takes none).
fn run(s: &(impl Src + ?Sized), i: usize, keep: impl Fn(u8) -> bool) -> usize {
    let mut n = 0usize;
    while keep(s.at(i.saturating_add(n))) {
        n = n.saturating_add(1);
        if i.checked_add(n).is_none() {
            break;
        }
    }
    n
}

/// `sscanf("%hu")`: a run of digits as an `unsigned short`, and how many
/// bytes it took; `None` with no digit. Blanks before it are skipped and a
/// sign is read, as `strtoul()` reads them; a value past the type wraps,
/// as glibc stores it.
fn scan_hu(s: &(impl Src + ?Sized), from: usize) -> Option<(u16, usize)> {
    let mut i = from.saturating_add(run(s, from, |b| {
        matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
    }));
    let negative = match s.at(i) {
        b'-' => {
            i = i.saturating_add(1);
            true
        }
        b'+' => {
            i = i.saturating_add(1);
            false
        }
        _ => false,
    };
    let digits = run(s, i, |b| b.is_ascii_digit());
    if digits == 0 {
        return None;
    }
    let mut value = 0u64;
    for k in 0..digits {
        let b = s.at(i.saturating_add(k));
        value = value
            .saturating_mul(10)
            .saturating_add(u64::from(b.wrapping_sub(b'0')));
    }
    if negative {
        value = value.wrapping_neg();
    }
    // The low 16 bits, as `%hu` stores them.
    Some((
        (value & 0xffff) as u16,
        i.saturating_add(digits).saturating_sub(from),
    ))
}

/// `sscanf("%hu%n:%hu%n:%hu%n")`: up to three numbers between colons, as
/// many as were read, and how many bytes the last one read ended at.
fn scan_hms(s: &(impl Src + ?Sized), from: usize) -> (Vec<u16>, usize) {
    let mut found = Vec::with_capacity(3);
    let mut used = 0usize;
    while found.len() < 3 {
        let mut at = from.saturating_add(used);
        if !found.is_empty() {
            if s.at(at) != b':' {
                break;
            }
            at = at.saturating_add(1);
        }
        let Some((value, took)) = scan_hu(s, at) else {
            break;
        };
        used = used
            .saturating_add(usize::from(!found.is_empty()))
            .saturating_add(took);
        found.push(value);
    }
    (found, used)
}

/// What a rule string that names an alternative and no rule asks of
/// `__tzfile_default()`: the two names and their offsets, east of UTC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DefaultRules {
    pub(crate) std: Vec<u8>,
    pub(crate) dst: Vec<u8>,
    pub(crate) stdoff: i64,
    pub(crate) dstoff: i64,
    /// `tz_rules` as `__tzset_parse_tz()` leaves them where
    /// `__tzfile_default()` finds `posixrules`: cleared by its `memset()`
    /// (the day `J0` 0, the change at second 0), the names and offsets
    /// read. What `__tz_compute()` then works from.
    pub(crate) as_read: PosixTz,
}

impl PosixTz {
    /// UTC, named `name`.
    pub fn utc(name: &[u8]) -> PosixTz {
        let mut tz = PosixTz::default();
        for rule in &mut tz.rules {
            rule.name = name.to_vec();
        }
        tz
    }

    /// The names, standard time's then the alternative's (`tz_rules[].name`).
    pub(crate) fn names(&self) -> [Vec<u8>; 2] {
        [
            self.rules
                .first()
                .map(|r| r.name.clone())
                .unwrap_or_default(),
            self.rules
                .get(1)
                .map(|r| r.name.clone())
                .unwrap_or_default(),
        ]
    }

    /// `rules[which].offset`, seconds east of UTC.
    pub(crate) fn offset_of(&self, which: usize) -> i64 {
        self.rules.get(which).map_or(0, |r| r.offset)
    }

    /// `parse_tzname()`: three letters or more, or `<...>` around three or
    /// more letters, digits and signs. Kept whole, as glibc keeps it, to
    /// [`NAME_KEEP`] bytes, which is more than any marker can show.
    fn name(s: &(impl Src + ?Sized), at: &mut usize) -> Option<Vec<u8>> {
        let letters = run(s, *at, |b| b.is_ascii_alphabetic());
        let (start, len, end) = if letters >= 3 {
            (*at, letters, letters)
        } else {
            if s.at(*at) != b'<' {
                return None;
            }
            let inner = at.saturating_add(1);
            let quoted = run(s, inner, |b| {
                b.is_ascii_alphanumeric() || b == b'+' || b == b'-'
            });
            if s.at(inner.saturating_add(quoted)) != b'>' || quoted < 3 {
                return None;
            }
            (inner, quoted, quoted.saturating_add(2))
        };
        let kept = len.min(NAME_KEEP);
        let name = (0..kept).map(|k| s.at(start.saturating_add(k))).collect();
        *at = at.saturating_add(end);
        Some(name)
    }

    /// `parse_offset()`: `[+-]hh[:mm[:ss]]`, west of UTC unless `-`.
    fn offset(&mut self, s: &(impl Src + ?Sized), at: &mut usize, which: usize) -> bool {
        let first = s.at(*at);
        if which == 0 && !(first == b'+' || first == b'-' || first.is_ascii_digit()) {
            return false;
        }
        let sign: i64 = if first == b'-' || first == b'+' {
            *at = at.saturating_add(1);
            if first == b'-' {
                1
            } else {
                -1
            }
        } else {
            -1
        };
        let (found, used) = scan_hms(s, *at);
        let part = |i: usize, most: u16| i64::from(found.get(i).copied().unwrap_or(0).min(most));
        let standard = self.rules.first().map_or(0, |r| r.offset);
        let Some(rule) = self.rules.get_mut(which) else {
            return false;
        };
        if found.is_empty() {
            if which == 0 {
                rule.offset = 0;
                return false;
            }
            // The alternative is an hour ahead where it does not say.
            rule.offset = standard.saturating_add(3600);
        } else {
            rule.offset = sign * (part(2, 59) + part(1, 59) * 60 + part(0, 24) * 3600);
        }
        *at = at.saturating_add(used);
        true
    }

    /// `parse_rule()`: when a change comes.
    fn rule(&mut self, s: &(impl Src + ?Sized), at: &mut usize, which: usize) -> bool {
        let Some(rule) = self.rules.get_mut(which) else {
            return false;
        };
        let mut i = *at;
        if s.at(i) == b',' {
            i = i.saturating_add(1);
        }
        let c = s.at(i);
        if c == b'J' || c.is_ascii_digit() {
            rule.kind = if c == b'J' { RuleDay::J1 } else { RuleDay::J0 };
            if rule.kind == RuleDay::J1 {
                i = i.saturating_add(1);
                if !s.at(i).is_ascii_digit() {
                    return false;
                }
            }
            let digits = run(s, i, |b| b.is_ascii_digit());
            let mut d = 0u64;
            for k in 0..digits {
                let b = s.at(i.saturating_add(k));
                d = d
                    .saturating_mul(10)
                    .saturating_add(u64::from(b.wrapping_sub(b'0')));
            }
            if d > 365 || (rule.kind == RuleDay::J1 && d == 0) {
                return false;
            }
            rule.d = u16::try_from(d).unwrap_or(0);
            i = i.saturating_add(digits);
        } else if c == b'M' {
            rule.kind = RuleDay::M;
            let mut j = i.saturating_add(1);
            // `sscanf()` stores each number as it reads it, so a rule
            // glibc then refuses keeps what was read (`M11.1.` is the
            // first Sunday of November, at midnight).
            for k in 0..3 {
                if k > 0 {
                    if s.at(j) != b'.' {
                        return false;
                    }
                    j = j.saturating_add(1);
                }
                let Some((value, took)) = scan_hu(s, j) else {
                    return false;
                };
                match k {
                    0 => rule.m = value,
                    1 => rule.n = value,
                    _ => rule.d = value,
                }
                j = j.saturating_add(took);
            }
            if !(1..=12).contains(&rule.m) || !(1..=5).contains(&rule.n) || rule.d > 6 {
                return false;
            }
            i = j;
        } else if c == 0 {
            // No rule: the United States' since 2007.
            rule.kind = RuleDay::M;
            (rule.m, rule.n, rule.d) = if which == 0 { (3, 2, 0) } else { (11, 1, 0) };
        } else {
            return false;
        }
        match s.at(i) {
            0 | b',' => rule.secs = 7200,
            b'/' => {
                i = i.saturating_add(1);
                if s.at(i) == 0 {
                    return false;
                }
                let negative = s.at(i) == b'-';
                i = i.saturating_add(usize::from(negative));
                let (found, used) = scan_hms(s, i);
                let hh = i64::from(found.first().copied().unwrap_or(2));
                let mm = i64::from(found.get(1).copied().unwrap_or(0));
                let ss = i64::from(found.get(2).copied().unwrap_or(0));
                i = i.saturating_add(used);
                rule.secs = if negative { -1 } else { 1 } * (hh * 3600 + mm * 60 + ss);
            }
            _ => return false,
        }
        *at = i;
        true
    }

    /// `__tzset_parse_tz()`. `s` ends at its first NUL, as a C string does.
    /// Where the string names an alternative and no rule (`EST5EDT`), glibc
    /// asks `posixrules` for the changes ([`LocalTime`] does): this is what
    /// it settles on where that file gives none, the United States' rule.
    pub fn parse(s: &[u8]) -> PosixTz {
        let s = s.split(|&b| b == 0).next().unwrap_or_default();
        Self::parse_with_default(s).0
    }

    /// [`PosixTz::parse`] of any source, and what `__tzfile_default()` is
    /// asked, if anything: the names and offsets as read where the string
    /// ended after the alternative's offset, or with a lone `,`.
    fn parse_with_default(s: &(impl Src + ?Sized)) -> (PosixTz, Option<DefaultRules>) {
        let mut tz = PosixTz::default();
        let mut at = 0usize;
        let Some(name) = Self::name(s, &mut at) else {
            return (tz, None);
        };
        if let Some(rule) = tz.rules.first_mut() {
            rule.name = name;
        }
        if !tz.offset(s, &mut at, 0) {
            return (tz, None);
        }
        if s.at(at) == 0 {
            // No alternative.
            let standard = tz.rules.first().cloned().unwrap_or_default();
            if let Some(rule) = tz.rules.get_mut(1) {
                rule.name = standard.name;
                rule.offset = standard.offset;
            }
            return (tz, None);
        }
        let mut wants = None;
        if let Some(name) = Self::name(s, &mut at) {
            if let Some(rule) = tz.rules.get_mut(1) {
                rule.name = name;
            }
            tz.offset(s, &mut at, 1);
            if s.at(at) == 0 || (s.at(at) == b',' && s.at(at.saturating_add(1)) == 0) {
                let [std, dst] = tz.names();
                wants = Some(DefaultRules {
                    std,
                    dst,
                    stdoff: tz.offset_of(0),
                    dstoff: tz.offset_of(1),
                    as_read: tz.clone(),
                });
            }
        }
        if tz.rule(s, &mut at, 0) {
            tz.rule(s, &mut at, 1);
        }
        (tz, wants)
    }

    /// `compute_change()`: when `which`'s change comes in `year`.
    fn change(&self, which: usize, year: i64) -> i64 {
        let Some(rule) = self.rules.get(which) else {
            return 0;
        };
        let mut t = if year > 1970 {
            let y = year - 1;
            ((year - 1970) * 365 + (y / 4 - 1970 / 4) - (y / 100 - 1970 / 100)
                + (y / 400 - 1970 / 400))
                .saturating_mul(SECS_PER_DAY)
        } else {
            0
        };
        let leap = is_leap(year);
        match rule.kind {
            RuleDay::J1 => {
                t = t.saturating_add((i64::from(rule.d) - 1) * SECS_PER_DAY);
                if rule.d >= 60 && leap {
                    t = t.saturating_add(SECS_PER_DAY);
                }
            }
            RuleDay::J0 => t = t.saturating_add(i64::from(rule.d) * SECS_PER_DAY),
            RuleDay::M => {
                // A month glibc refused is kept as it read it (`M13.1.0`),
                // and its table, `__mon_yday[leap][m]`, read past the row:
                // in a common year M13 is the year's end, a month of no
                // days, and M14 to M25 the leap year's row that follows it
                // (M14 is January; measured). Past that (M26 on, or M13 on
                // in a leap year) glibc reads past the table, which is
                // undefined; here the change then falls after the year
                // (DIVERGENCES 152, C-DEFECT not reproduced).
                let m = usize::from(rule.m);
                let (before, length) = if (1..=12).contains(&m) {
                    let before = mon_yday(leap, m - 1);
                    (before, mon_yday(leap, m) - before)
                } else if !leap && (14..=25).contains(&m) {
                    let before = mon_yday(true, m - 14);
                    (before, mon_yday(true, m - 13) - before)
                } else {
                    (mon_yday(leap, 12), 0)
                };
                t = t.saturating_add(before * SECS_PER_DAY);
                // Zeller's congruence: the weekday of the month's first day.
                let m1 = (i64::from(rule.m) + 9) % 12 + 1;
                let yy0 = if rule.m <= 2 { year - 1 } else { year };
                let (yy1, yy2) = (yy0 / 100, yy0 % 100);
                let dow =
                    ((26 * m1 - 2) / 10 + 1 + yy2 + yy2 / 4 + yy1 / 4 - 2 * yy1).rem_euclid(7);
                let mut d = i64::from(rule.d) - dow;
                if d < 0 {
                    d += 7;
                }
                for _ in 1..rule.n {
                    if d + 7 >= length {
                        break;
                    }
                    d += 7;
                }
                t = t.saturating_add(d * SECS_PER_DAY);
            }
        }
        t.saturating_sub(rule.offset).saturating_add(rule.secs)
    }

    /// `__tz_compute()`'s choice: the offset and whether it is the
    /// alternative at second `t`, whose year in UTC is `year`.
    fn at(&self, t: i64, year: i64) -> (i64, bool) {
        let (c0, c1) = (self.change(0, year), self.change(1, year));
        let isdst = if c0 > c1 {
            // South of the equator the alternative ends in the next year.
            t < c1 || t >= c0
        } else {
            t >= c0 && t < c1
        };
        (self.offset_of(usize::from(isdst)), isdst)
    }
}

// ------------------------------------------------------------------- TZif

/// How much of a zone name is kept: more than any marker's buffer can hold
/// (`(len + 1) * 8 + 1` bytes for a format of `len` bytes, an argument
/// Linux bounds at 128 KiB), so a longer name does what glibc's whole one
/// does, not fit. glibc keeps every byte (measured: a 3 MiB name in a
/// footer is `tzname[0]`).
pub const NAME_KEEP: usize = 16 << 20;

/// The most of a zone file's data that is read into memory: a file whose
/// data is longer is read where it is needed, through the descriptor kept
/// open, so that memory stays this size whatever the file's (glibc reads
/// any length into memory). Only a file rewritten in place while it is in
/// use could tell the two apart.
pub const DATA_IN_MEMORY: u64 = 64 << 20;

/// What `stat()` gives that `__tzfile_read()` keeps to know a file again:
/// `st_dev`, `st_ino` and `st_mtime`, whole seconds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileKey {
    pub dev: u64,
    pub ino: u64,
    pub mtime: i64,
}

/// A file read at an offset, as `pread(2)` reads it.
pub trait ReadAt {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<usize>;
}

impl ReadAt for Vec<u8> {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
        let from = usize::try_from(offset).unwrap_or(usize::MAX);
        let have = self.get(from..).unwrap_or_default();
        let n = have.len().min(buf.len());
        if let (Some(to), Some(from)) = (buf.get_mut(..n), have.get(..n)) {
            to.copy_from_slice(from);
        }
        Ok(n)
    }
}

#[cfg(unix)]
impl ReadAt for std::fs::File {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
        std::os::unix::fs::FileExt::read_at(self, buf, offset)
    }
}

/// What tells a regular file from any other that has since taken its path
/// or been written: device, inode, size, and modification and change times
/// to the nanosecond.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileId {
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub mtime: (i64, i64),
    pub ctime: (i64, i64),
}

/// A regular file read at an offset by opening its path again for each
/// read (`O_RDONLY|O_CLOEXEC|O_NONBLOCK`), and reading nothing from what is
/// not the file it was ([`FileId`]): no descriptor is kept between reads.
/// Where it was replaced or written since, glibc has its copy; that is
/// read as failing (DIVERGENCES 152).
#[cfg(unix)]
pub struct Reopened {
    path: std::path::PathBuf,
    id: FileId,
}

#[cfg(unix)]
impl Reopened {
    /// The file at `path`, known by `id`.
    pub fn new(path: &[u8], id: FileId) -> Reopened {
        use std::os::unix::ffi::OsStrExt;
        Reopened {
            path: std::path::PathBuf::from(std::ffi::OsStr::from_bytes(path)),
            id,
        }
    }

    /// `m` as a [`FileId`].
    pub fn id_of(m: &std::fs::Metadata) -> FileId {
        use std::os::unix::fs::MetadataExt;
        FileId {
            dev: m.dev(),
            ino: m.ino(),
            size: m.size(),
            mtime: (m.mtime(), m.mtime_nsec()),
            ctime: (m.ctime(), m.ctime_nsec()),
        }
    }
}

#[cfg(unix)]
impl ReadAt for Reopened {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(crate::safefs::NONBLOCK)
            .open(&self.path)?;
        let m = file.metadata()?;
        if !m.is_file() || Self::id_of(&m) != self.id {
            return Err(std::io::ErrorKind::NotFound.into());
        }
        std::os::unix::fs::FileExt::read_at(&file, buf, offset)
    }
}

/// A zone file as it was opened, `fopen()` and `fstat()`.
pub enum ZoneSource {
    /// A regular file of `size` bytes (`st_size`), read where it is asked
    /// through `data`, the descriptor opened, while it is read as glibc's
    /// `__tzfile_read()` reads it; which `fclose()`s it at the end. Where
    /// its data is more than [`DATA_IN_MEMORY`] and is read where it lies
    /// after that, it is read through `later`, which holds no descriptor
    /// (it opens the file again for each read, and reads nothing from one
    /// that is not the file it was), so that lsof-rs keeps none open where
    /// the C keeps none (measured: the C lists no zone file of its own).
    Regular {
        key: FileKey,
        size: u64,
        data: Rc<dyn ReadAt>,
        later: Rc<dyn ReadAt>,
    },
    /// Anything else, a FIFO, a device, a directory: what it gave before it
    /// ended, failed or ran out of time. glibc reads such a file with stdio
    /// and can use only a version 1 file from it ([`stream_data_len`]).
    Stream { key: FileKey, bytes: Vec<u8> },
}

impl std::fmt::Debug for ZoneSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZoneSource::Regular { key, size, .. } => {
                write!(f, "Regular({key:?}, {size} bytes)")
            }
            ZoneSource::Stream { key, bytes } => {
                write!(f, "Stream({key:?}, {} bytes)", bytes.len())
            }
        }
    }
}

/// The two calls glibc's zone code makes on a path: `stat()` (following
/// links), to know whether the file it has is still the one named, and the
/// open with its `fstat()`. `None` where either fails.
pub trait ZoneFs {
    fn stat(&mut self, path: &[u8]) -> Option<FileKey>;
    fn open(&mut self, path: &[u8]) -> Option<ZoneSource>;
}

/// No zone file at all: Windows, where only a `TZ` rule string is read,
/// and the parse's own check of a marker format.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoZoneFiles;

impl ZoneFs for NoZoneFiles {
    fn stat(&mut self, _: &[u8]) -> Option<FileKey> {
        None
    }
    fn open(&mut self, _: &[u8]) -> Option<ZoneSource> {
        None
    }
}

/// One file of [`MemZoneFiles`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemFile {
    pub key: FileKey,
    pub bytes: Vec<u8>,
    /// Read as a FIFO or a device is ([`ZoneSource::Stream`]).
    pub stream: bool,
}

/// Zone files held in memory, by path, and a count of the calls made on
/// them: the tests' and the fuzzer's file system.
#[derive(Clone, Debug, Default)]
pub struct MemZoneFiles {
    pub files: Vec<(Vec<u8>, MemFile)>,
    /// Every `stat()` and open asked, in order, `S path` and `O path`.
    pub calls: Rc<RefCell<Vec<String>>>,
}

impl MemZoneFiles {
    /// Put `bytes` at `path`, a regular file known by `key`.
    pub fn put(&mut self, path: &[u8], key: FileKey, bytes: &[u8]) {
        self.files.retain(|(p, _)| p != path);
        self.files.push((
            path.to_vec(),
            MemFile {
                key,
                bytes: bytes.to_vec(),
                stream: false,
            },
        ));
    }

    fn find(&self, path: &[u8]) -> Option<&MemFile> {
        self.files.iter().find(|(p, _)| p == path).map(|(_, f)| f)
    }
}

impl ZoneFs for MemZoneFiles {
    fn stat(&mut self, path: &[u8]) -> Option<FileKey> {
        self.calls
            .borrow_mut()
            .push(format!("S {}", String::from_utf8_lossy(path)));
        self.find(path).map(|f| f.key)
    }
    fn open(&mut self, path: &[u8]) -> Option<ZoneSource> {
        self.calls
            .borrow_mut()
            .push(format!("O {}", String::from_utf8_lossy(path)));
        let f = self.find(path)?;
        let bytes: Rc<dyn ReadAt> = Rc::new(f.bytes.clone());
        Some(if f.stream {
            ZoneSource::Stream {
                key: f.key,
                bytes: f.bytes.clone(),
            }
        } else {
            ZoneSource::Regular {
                key: f.key,
                size: f.bytes.len() as u64,
                data: Rc::clone(&bytes),
                later: bytes,
            }
        })
    }
}

/// A count of the header, `decode()`d as glibc decodes it: a signed `int`
/// cast to `size_t`, so 2^31 and up are about 2^64.
fn decode_count(b: &[u8]) -> u64 {
    let mut four = [0u8; 4];
    for (to, from) in four.iter_mut().zip(b) {
        *to = *from;
    }
    i64::from(i32::from_be_bytes(four)) as u64
}

/// The six counts of a 44-byte header: `isutcnt`, `isstdcnt`, `leapcnt`,
/// `timecnt`, `typecnt`, `charcnt`.
fn header_counts(head: &[u8]) -> [u64; 6] {
    let mut counts = [0u64; 6];
    for (k, c) in counts.iter_mut().enumerate() {
        let at = 20usize.saturating_add(k.saturating_mul(4));
        *c = decode_count(head.get(at..at.saturating_add(4)).unwrap_or_default());
    }
    counts
}

/// How many bytes a stream (a FIFO, a device) must give after its 44-byte
/// `header` for glibc to read a zone from it: a version 1 file's data,
/// whose length its counts give. `None` where glibc gives up at the header
/// read from a stream: another magic, a version 2 file or later (it seeks
/// to the second header, which a pipe refuses and a device's `st_size` of
/// 0 cannot hold), a count past `int` (whose array it cannot allocate), or
/// more `isstd` or `isut` entries than types.
pub fn stream_data_len(header: &[u8]) -> Option<u64> {
    if header.len() < 44 || header.get(..4) != Some(b"TZif") || peek(header, 4) != 0 {
        return None;
    }
    let [isgmt, isstd, leaps, times, types, chars] = header_counts(header);
    if [isgmt, isstd, leaps, times, types, chars]
        .iter()
        .any(|&c| c > u64::from(i32::MAX as u32))
        || isstd > types
        || isgmt > types
    {
        return None;
    }
    times
        .checked_mul(5)?
        .checked_add(types.checked_mul(6)?)?
        .checked_add(chars)?
        .checked_add(leaps.checked_mul(8)?)?
        .checked_add(isstd)?
        .checked_add(isgmt)
}

/// Bytes of a zone file between two offsets, read where they lie: from a
/// copy in memory, or through the open descriptor, a 64 KiB piece at a
/// time kept, so that walking an array is one read a piece.
struct Region {
    data: Rc<dyn ReadAt>,
    /// The bytes themselves where they are held in memory.
    held: Option<Rc<Vec<u8>>>,
    start: u64,
    len: u64,
    piece: RefCell<(u64, Vec<u8>)>,
}

const PIECE: u64 = 64 << 10;

impl Region {
    fn new(data: Rc<dyn ReadAt>, start: u64, len: u64) -> Region {
        Region {
            data,
            held: None,
            start,
            len,
            piece: RefCell::new((0, Vec::new())),
        }
    }

    /// The byte at `off`, 0 past the end or where the read fails.
    fn byte(&self, off: u64) -> u8 {
        if off >= self.len {
            return 0;
        }
        let Some(abs) = self.start.checked_add(off) else {
            return 0;
        };
        if let Some(held) = &self.held {
            return usize::try_from(abs)
                .ok()
                .and_then(|i| held.get(i))
                .copied()
                .unwrap_or(0);
        }
        let base = abs - abs % PIECE;
        let mut piece = self.piece.borrow_mut();
        if piece.1.is_empty() || piece.0 != base {
            // No more than the region holds from there.
            let want = PIECE.min(self.start.saturating_add(self.len).saturating_sub(base));
            let mut buf = vec![0u8; usize::try_from(want).unwrap_or(0)];
            let mut have = 0usize;
            while have < buf.len() {
                let at = base.saturating_add(have as u64);
                match self
                    .data
                    .read_at(buf.get_mut(have..).unwrap_or_default(), at)
                {
                    Ok(0) | Err(_) => break,
                    Ok(n) => have = have.saturating_add(n),
                }
            }
            buf.truncate(have);
            *piece = (base, buf);
        }
        piece
            .1
            .get(usize::try_from(abs - base).unwrap_or(usize::MAX))
            .copied()
            .unwrap_or(0)
    }

    fn bytes<const N: usize>(&self, off: u64) -> [u8; N] {
        let mut out = [0u8; N];
        for (k, b) in out.iter_mut().enumerate() {
            *b = self.byte(off.saturating_add(k as u64));
        }
        out
    }
}

/// A zone file's footer, its rule string, read as a C string where it lies:
/// 0 at its first NUL and past it.
struct FooterText<'a> {
    region: &'a Region,
    /// How far it is known to hold no NUL, and where its first is.
    clear: std::cell::Cell<u64>,
    nul: std::cell::Cell<Option<u64>>,
}

impl Src for FooterText<'_> {
    fn at(&self, i: usize) -> u8 {
        let i = i as u64;
        if self.nul.get().is_some_and(|n| i >= n) || i >= self.region.len {
            return 0;
        }
        while self.clear.get() <= i {
            let k = self.clear.get();
            if self.region.byte(k) == 0 {
                self.nul.set(Some(k));
                return 0;
            }
            self.clear.set(k.saturating_add(1));
        }
        self.region.byte(i)
    }
}

/// A type of a zone file (`struct ttinfo`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct TtInfo {
    offset: i32,
    isdst: bool,
    idx: u8,
    isstd: bool,
    isgmt: bool,
}

/// What `__tzfile_default()` did to `posixrules`' transitions: each moved
/// by the offsets asked less the file's (`rule_stdoff`, `rule_dstoff` as
/// they stood, which for the second the read itself never sets).
#[derive(Clone, Copy, Debug)]
struct Moved {
    stdoff: i64,
    dstoff: i64,
    rule_stdoff: i64,
    rule_dstoff: i64,
}

/// A zone file as `__tzfile_read()` keeps it.
struct TzData {
    wide: bool,
    timecnt: u64,
    trans: Region,
    idxs: Region,
    typecnt: u64,
    /// The first 256 types, all a transition can name; then, as
    /// `__tzfile_default()` leaves them, its two.
    head: Vec<TtInfo>,
    /// The file's own first types, which [`Moved`] is worked out from.
    raw_head: Vec<TtInfo>,
    /// The first standard time type and its number, and the first daylight
    /// time type, of all of them.
    first_std: Option<(u64, TtInfo)>,
    first_dst: Option<TtInfo>,
    /// `zone_names` and, after it in glibc's one allocation, the footer's
    /// text: what a name at an index up to 255 is read from.
    names: Vec<u8>,
    leapcnt: u64,
    leaps: Region,
    spec: Option<(PosixTz, Option<DefaultRules>)>,
    moved: Option<Moved>,
}

impl TzData {
    fn raw_idx(&self, i: u64) -> u8 {
        self.idxs.byte(i)
    }

    fn raw_transition(&self, i: u64) -> i64 {
        if self.wide {
            i64::from_be_bytes(self.trans.bytes::<8>(i.saturating_mul(8)))
        } else {
            i64::from(i32::from_be_bytes(
                self.trans.bytes::<4>(i.saturating_mul(4)),
            ))
        }
    }

    fn raw_type(&self, idx: u8) -> TtInfo {
        self.raw_head
            .get(usize::from(idx))
            .copied()
            .unwrap_or_default()
    }

    /// `type_idxs[i]`.
    fn type_idx(&self, i: u64) -> u8 {
        let raw = self.raw_idx(i);
        if self.moved.is_some() {
            u8::from(self.raw_type(raw).isdst)
        } else {
            raw
        }
    }

    /// `types[idx]`.
    fn ty(&self, idx: u8) -> TtInfo {
        self.head.get(usize::from(idx)).copied().unwrap_or_default()
    }

    /// `transitions[i]`.
    fn transition(&self, i: u64) -> i64 {
        let raw = self.raw_transition(i);
        let Some(m) = self.moved else {
            return raw;
        };
        let this = self.raw_type(self.raw_idx(i));
        let was_dst = i > 0 && self.raw_type(self.raw_idx(i - 1)).isdst;
        let by = if this.isgmt {
            0
        } else if was_dst && !this.isstd {
            m.dstoff.wrapping_sub(m.rule_dstoff)
        } else {
            m.stdoff.wrapping_sub(m.rule_stdoff)
        };
        raw.wrapping_add(by)
    }

    /// `&zone_names[idx]` as a C string.
    fn name(&self, idx: u8) -> Vec<u8> {
        let from = self.names.get(usize::from(idx)..).unwrap_or_default();
        from.split(|&b| b == 0).next().unwrap_or_default().to_vec()
    }

    /// `leaps[i]`: when, and the correction from then on (`long`).
    fn leap(&self, i: u64) -> (i64, i64) {
        let width = if self.wide { 12u64 } else { 8 };
        let at = i.saturating_mul(width);
        let when = if self.wide {
            i64::from_be_bytes(self.leaps.bytes::<8>(at))
        } else {
            i64::from(i32::from_be_bytes(self.leaps.bytes::<4>(at)))
        };
        let change = i32::from_be_bytes(self.leaps.bytes::<4>(at.saturating_add(width - 4)));
        (when, i64::from(change))
    }

    /// `__tzfile_read()` from `fopen()` to `fclose()`: `None` for its `goto
    /// lose`. Every check of glibc 2.39's is made, in its unchecked
    /// `size_t` arithmetic where that decides; what is undefined there (a
    /// file with no type, which glibc reads one past) is refused.
    fn load(src: &ZoneSource) -> Option<TzData> {
        let (data, size, stream, later): (Rc<dyn ReadAt>, u64, bool, Rc<dyn ReadAt>) = match src {
            ZoneSource::Regular {
                data, size, later, ..
            } => match v1_read_to_eof(data.as_ref(), *size) {
                // A version 1 file is read as a stream is, to its end,
                // whatever `st_size` says (glibc never looks at it there).
                Some(bytes) => {
                    let len = bytes.len() as u64;
                    let bytes: Rc<dyn ReadAt> = Rc::new(bytes);
                    (Rc::clone(&bytes), len, false, bytes)
                }
                None => (Rc::clone(data), *size, false, Rc::clone(later)),
            },
            ZoneSource::Stream { bytes, .. } => {
                let bytes: Rc<dyn ReadAt> = Rc::new(bytes.clone());
                (Rc::clone(&bytes), bytes_len(src), true, bytes)
            }
        };
        let file = Region::new(Rc::clone(&data), 0, size);
        let mut pos: u64 = 0;
        let mut wide = false;
        let counts = loop {
            if pos.checked_add(44).is_none_or(|end| end > size) {
                return None;
            }
            let head: [u8; 44] = file.bytes::<44>(pos);
            if head.get(..4) != Some(b"TZif") {
                return None;
            }
            let counts = header_counts(&head);
            let [isgmt, isstd, leaps, times, types, chars] = counts;
            if isstd > types || isgmt > types {
                return None;
            }
            if !wide && head.get(4).copied().unwrap_or(0) != 0 {
                // `fseek(f, to_skip, SEEK_CUR)`: a pipe refuses it, and a
                // device's `st_size` of 0 leaves no room for the data.
                if stream {
                    return None;
                }
                let skip = times
                    .wrapping_mul(5)
                    .wrapping_add(types.wrapping_mul(6))
                    .wrapping_add(chars)
                    .wrapping_add(leaps.wrapping_mul(8))
                    .wrapping_add(isstd)
                    .wrapping_add(isgmt);
                // `long` arithmetic: a skip past 2^63 is a step back.
                let to = 44i64.checked_add(pos as i64)?.checked_add(skip as i64)?;
                pos = u64::try_from(to).ok()?;
                wide = true;
                continue;
            }
            pos = pos.checked_add(44)?;
            break counts;
        };
        let [isgmt, isstd, leapcnt, timecnt, typecnt, chars] = counts;
        let width: u64 = if wide { 8 } else { 4 };
        // The footer's length, from `st_size`, as glibc works it out.
        let mut spec_len: u64 = 0;
        if wide {
            let rem = (size as i64).checked_sub(pos as i64)?;
            let data_len = timecnt
                .wrapping_mul(9)
                .wrapping_add(typecnt.wrapping_mul(6))
                .wrapping_add(chars);
            if rem < 0 || (rem as u64) < data_len {
                return None;
            }
            spec_len = (rem as u64).wrapping_sub(data_len);
            if leapcnt > u64::MAX / 12 || spec_len < leapcnt.wrapping_mul(12) {
                return None;
            }
            spec_len -= leapcnt * 12;
            if spec_len < isstd {
                return None;
            }
            spec_len -= isstd;
            if spec_len == 0 || spec_len - 1 < isgmt {
                return None;
            }
            spec_len -= isgmt + 1;
            if spec_len == 0 {
                return None;
            }
        }
        // The one allocation: each array's size must not overflow, as
        // `alloc_buffer` checks.
        let alloc = timecnt
            .checked_mul(8)?
            .checked_add(leapcnt.checked_mul(16)?)?
            .checked_add(typecnt.checked_mul(8)?)?
            .checked_add(timecnt)?
            .checked_add(chars)?
            .checked_add(spec_len)?;
        let _ = alloc;
        // A file with no type is no zone: glibc reads one that is not there.
        if typecnt == 0 {
            return None;
        }
        let trans_len = timecnt.checked_mul(width)?;
        let types_len = typecnt.checked_mul(6)?;
        let leaps_len = leapcnt.checked_mul(width.checked_add(4)?)?;
        let block = trans_len
            .checked_add(timecnt)?
            .checked_add(types_len)?
            .checked_add(chars)?
            .checked_add(leaps_len)?
            .checked_add(isstd)?
            .checked_add(isgmt)?;
        // Every `fread()` and `getc()` must be met.
        if pos.checked_add(block).is_none_or(|end| end > size) {
            return None;
        }
        // Held in memory where it fits, else read where it lies, through
        // `later`: nothing kept holds the descriptor the file was read
        // through, which the caller closes, as glibc's `fclose()`.
        let (data, base): (Option<Rc<Vec<u8>>>, u64) = if block <= DATA_IN_MEMORY {
            let mut copy = vec![0u8; usize::try_from(block).ok()?];
            let mut have = 0usize;
            while have < copy.len() {
                match data.read_at(
                    copy.get_mut(have..).unwrap_or_default(),
                    pos.saturating_add(have as u64),
                ) {
                    Ok(0) | Err(_) => return None,
                    Ok(n) => have = have.saturating_add(n),
                }
            }
            (Some(Rc::new(copy)), 0)
        } else {
            (None, pos)
        };
        let at = |off: u64| base.saturating_add(off);
        let kept: Rc<dyn ReadAt> = match &data {
            Some(held) => Rc::clone(held) as Rc<dyn ReadAt>,
            None => later,
        };
        let region = |start: u64, len: u64| Region {
            held: data.clone(),
            ..Region::new(Rc::clone(&kept), at(start), len)
        };
        let trans = region(0, trans_len);
        let idxs = region(trans_len, timecnt);
        let types_at = trans_len + timecnt;
        let types_raw = region(types_at, types_len);
        let names_at = types_at + types_len;
        let names_raw = region(names_at, chars);
        let leaps_at = names_at + chars;
        let leaps = region(leaps_at, leaps_len);
        let flags_at = leaps_at + leaps_len;
        let flags = region(flags_at, isstd + isgmt);
        for i in 0..timecnt {
            if u64::from(idxs.byte(i)) >= typecnt {
                return None;
            }
        }
        let mut head = Vec::with_capacity(usize::try_from(typecnt.min(256)).unwrap_or(256));
        let mut first_std = None;
        let mut first_dst = None;
        for i in 0..typecnt {
            let raw = types_raw.bytes::<6>(i * 6);
            let [a, b, c, d, isdst, idx] = raw;
            if isdst > 1 || u64::from(idx) > chars {
                return None;
            }
            let info = TtInfo {
                offset: i32::from_be_bytes([a, b, c, d]),
                isdst: isdst == 1,
                idx,
                isstd: i < isstd && flags.byte(i) != 0,
                isgmt: i < isgmt && flags.byte(isstd + i) != 0,
            };
            if i < 256 {
                head.push(info);
            }
            if info.isdst {
                first_dst.get_or_insert(info);
            } else {
                first_std.get_or_insert((i, info));
            }
        }
        // The footer: a newline, then all but its last byte, cut at its
        // first NUL; one that opens otherwise, or is empty, is no rule.
        let mut names = Vec::new();
        let keep = NAME_KEEP.saturating_add(256);
        for i in 0..chars.min(keep as u64) {
            names.push(names_raw.byte(i));
        }
        let mut spec = None;
        if wide {
            let footer_at = pos + block;
            let text = Region::new(Rc::clone(&src_data(src)), footer_at + 1, spec_len - 1);
            if file.byte(footer_at) == b'\n' {
                let footer = FooterText {
                    region: &text,
                    clear: std::cell::Cell::new(0),
                    nul: std::cell::Cell::new(None),
                };
                if footer.at(0) != 0 {
                    spec = Some(PosixTz::parse_with_default(&footer));
                }
                // A name that runs past `zone_names` runs into it.
                if names.len() as u64 == chars {
                    let mut i = 0usize;
                    while names.len() < keep {
                        let b = footer.at(i);
                        names.push(b);
                        if b == 0 {
                            break;
                        }
                        i = i.saturating_add(1);
                    }
                }
            }
        }
        let raw_head = head.clone();
        Some(TzData {
            wide,
            timecnt,
            trans,
            idxs,
            typecnt,
            head,
            raw_head,
            first_std,
            first_dst,
            names,
            leapcnt,
            leaps,
            spec,
            moved: None,
        })
    }
}

/// A stream's length.
fn bytes_len(src: &ZoneSource) -> u64 {
    match src {
        ZoneSource::Stream { bytes, .. } => bytes.len() as u64,
        ZoneSource::Regular { size, .. } => *size,
    }
}

/// A regular file whose header is a version 1 file's and whose `st_size`
/// is short of what that header says follows it, read from its start to
/// its end or that length, as glibc's `fread()`s read it: they never ask
/// `st_size`, so a file that says it is empty and is not (`/proc/self/
/// environ`, measured: the C reads a zone from it) is a zone. `None` for
/// any other file, which is read where it lies. What it reads is at most
/// what the file holds, and never more than [`DATA_IN_MEMORY`] of data (a
/// stream's bound).
fn v1_read_to_eof(data: &dyn ReadAt, size: u64) -> Option<Vec<u8>> {
    let head = read_from(data, 0, 44);
    let len = stream_data_len(&head)?;
    let need = 44u64.checked_add(len)?;
    if size >= need || len > DATA_IN_MEMORY {
        return None;
    }
    Some(read_from(data, 0, need))
}

/// Up to `len` bytes of `data` from `at`, read in turn until it ends or a
/// read fails: as much memory as the file gave.
fn read_from(data: &dyn ReadAt, at: u64, len: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; usize::try_from(len.min(PIECE)).unwrap_or(0)];
    while (out.len() as u64) < len {
        let want = usize::try_from((len - out.len() as u64).min(PIECE)).unwrap_or(0);
        let Some(chunk) = buf.get_mut(..want) else {
            break;
        };
        match data.read_at(chunk, at.saturating_add(out.len() as u64)) {
            Ok(0) | Err(_) => break,
            Ok(n) => out.extend_from_slice(chunk.get(..n).unwrap_or_default()),
        }
    }
    out
}

/// Zone files through `std` alone: a regular file is read as glibc reads
/// it; anything else is opened without blocking and read as nothing, the
/// file glibc would fail on when it gives no version 1 data. FreeBSD's
/// platform (whose FIFO and device reads are unmeasured, no FreeBSD C
/// here); Linux reads them as glibc does (the backend's own [`ZoneFs`]).
#[cfg(unix)]
#[derive(Clone, Copy, Debug, Default)]
pub struct StdZoneFs;

#[cfg(unix)]
impl ZoneFs for StdZoneFs {
    fn stat(&mut self, path: &[u8]) -> Option<FileKey> {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::metadata(std::ffi::OsStr::from_bytes(path)).ok()?;
        Some(FileKey {
            dev: m.dev(),
            ino: m.ino(),
            mtime: m.mtime(),
        })
    }
    fn open(&mut self, path: &[u8]) -> Option<ZoneSource> {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let mut open = std::fs::OpenOptions::new();
        open.read(true).custom_flags(crate::safefs::NONBLOCK);
        let file = open.open(std::ffi::OsStr::from_bytes(path)).ok()?;
        let m = file.metadata().ok()?;
        let key = FileKey {
            dev: m.dev(),
            ino: m.ino(),
            mtime: m.mtime(),
        };
        Some(if m.is_file() {
            ZoneSource::Regular {
                key,
                size: m.len(),
                data: Rc::new(file),
                later: Rc::new(Reopened::new(path, Reopened::id_of(&m))),
            }
        } else {
            ZoneSource::Stream {
                key,
                bytes: Vec::new(),
            }
        })
    }
}

/// `__tzfile_compute()` at `found:`: the type of the transition before
/// `i`, its name in `tzname`, the other name from the first later
/// transition of the other kind.
fn found_at(data: &TzData, names: &mut [Option<Vec<u8>>; 2], i: u64, n: u64) -> TtInfo {
    let ty = data.ty(data.type_idx(i.saturating_sub(1)));
    if let Some(slot) = names.get_mut(usize::from(ty.isdst)) {
        *slot = Some(data.name(ty.idx));
    }
    let mut j = i;
    while j < n {
        let tj = data.ty(data.type_idx(j));
        let dst = usize::from(tj.isdst);
        if names.get(dst).is_some_and(Option::is_none) {
            if let Some(slot) = names.get_mut(dst) {
                *slot = Some(data.name(tj.idx));
            }
            if names.get(1 - dst).is_some_and(Option::is_some) {
                break;
            }
        }
        j += 1;
    }
    if names[0].is_none() {
        names[0] = names[1].clone();
    }
    ty
}

/// The source's bytes, however it was opened.
fn src_data(src: &ZoneSource) -> Rc<dyn ReadAt> {
    match src {
        ZoneSource::Regular { data, .. } => Rc::clone(data),
        ZoneSource::Stream { bytes, .. } => Rc::new(bytes.clone()),
    }
}

/// Where glibc finds zone files, its default, and the file a rule string
/// with no rule takes its changes from (`TZDIR`, `TZDEFAULT`, `TZDEFRULES`).
pub const TZDIR: &[u8] = b"/usr/share/zoneinfo";
pub const TZDEFAULT: &[u8] = b"/etc/localtime";
pub const TZDEFRULES: &[u8] = b"posixrules";

/// The environment, as `getenv()` reads it.
pub type Getenv = Box<dyn Fn(&str) -> Option<Vec<u8>>>;

/// glibc 2.39's local time: `tzset()`, `localtime()`, `localtime_r()` and
/// `mktime()` (`time/tzset.c`, `time/tzfile.c`, `time/mktime.c`), with the
/// state glibc keeps between calls, in one value a process makes once:
///
/// * `TZ` as it was last read (`old_tz`); with it set and unchanged,
///   nothing is read again, whatever it names;
/// * with `TZ` unset, `/etc/localtime` `stat`ed at each `localtime()`,
///   `mktime()` and `tzset()`, and read again where its device, inode or
///   whole-second modification time changed, or it was not in use (a file
///   that has gone is UTC named `UTC`, and is opened again at the next
///   call);
/// * a rule string with an alternative and no rule (`EST5EDT` where no
///   such file is) reading `posixrules` and moving its changes to the
///   offsets given, at every such call, `old_tz` forgotten;
/// * the zone file as `__tzfile_read()` keeps it, `rule_stdoff` and
///   `rule_dstoff`, `tzname`;
/// * `mktime()`'s guess at the offset, which starts at 0 and decides which
///   of two times an hour a zone repeats with one `tm_isdst` is taken.
///
/// [`LocalTime::reset`] makes it a new process's again.
pub struct LocalTime {
    getenv: Getenv,
    secure: bool,
    fs: Box<dyn ZoneFs>,
    initialized: bool,
    old_tz: Option<Vec<u8>>,
    use_tzfile: bool,
    key: FileKey,
    data: Option<TzData>,
    rule_stdoff: i64,
    rule_dstoff: i64,
    rules: PosixTz,
    tzname: [Vec<u8>; 2],
    offset_guess: i64,
}

impl std::fmt::Debug for LocalTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalTime")
            .field("old_tz", &self.old_tz)
            .field("use_tzfile", &self.use_tzfile)
            .field("offset_guess", &self.offset_guess)
            .finish_non_exhaustive()
    }
}

/// A request to `mktime()`: the members of `struct tm` it reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MkTm {
    pub sec: i32,
    pub min: i32,
    pub hour: i32,
    pub mday: i32,
    pub mon: i32,
    pub year: i32,
    /// Negative: not known.
    pub isdst: i32,
}

impl MkTm {
    /// A broken-down time as `mktime()` is asked it, `tm_isdst` included.
    pub fn of(tm: &Tm) -> MkTm {
        MkTm {
            sec: tm.sec,
            min: tm.min,
            hour: tm.hour,
            mday: tm.mday,
            mon: tm.mon,
            year: tm.year,
            isdst: i32::from(tm.isdst),
        }
    }
}

/// `shr()`: an arithmetic shift.
fn shr(a: i64, b: u32) -> i64 {
    a >> b
}

/// `leapyear()` of a year counted from 1900.
fn leapyear(year: i64) -> bool {
    (year & 3) == 0 && (year % 100 != 0 || ((year / 100) & 3) == ((-(1900i64 / 100)) & 3))
}

/// `ydhms_diff()`: seconds from (year0, yday0, hour0:min0:sec0) to
/// (year1, yday1, hour1:min1:sec1), the leap days between counted as glibc
/// counts them, in its `int`s where they are `int`s.
#[allow(clippy::too_many_arguments)]
fn ydhms_diff(
    year1: i64,
    yday1: i64,
    hour1: i32,
    min1: i32,
    sec1: i32,
    year0: i32,
    yday0: i32,
    hour0: i32,
    min0: i32,
    sec0: i32,
) -> i64 {
    let year0l = i64::from(year0);
    let a4 = (shr(year1, 2) + shr(1900, 2) - i64::from((year1 & 3) == 0)) as i32;
    let b4 = (shr(year0l, 2) + shr(1900, 2) - i64::from((year0l & 3) == 0)) as i32;
    let a100 = (a4.wrapping_add(i32::from(a4 < 0))) / 25 - i32::from(a4 < 0);
    let b100 = (b4.wrapping_add(i32::from(b4 < 0))) / 25 - i32::from(b4 < 0);
    let a400 = a100 >> 2;
    let b400 = b100 >> 2;
    let intervening = (a4.wrapping_sub(b4))
        .wrapping_sub(a100.wrapping_sub(b100))
        .wrapping_add(a400.wrapping_sub(b400));
    let years = year1.wrapping_sub(year0l);
    let days = years
        .wrapping_mul(365)
        .wrapping_add(yday1)
        .wrapping_sub(i64::from(yday0))
        .wrapping_add(i64::from(intervening));
    let hours = days
        .wrapping_mul(24)
        .wrapping_add(i64::from(hour1))
        .wrapping_sub(i64::from(hour0));
    let minutes = hours
        .wrapping_mul(60)
        .wrapping_add(i64::from(min1))
        .wrapping_sub(i64::from(min0));
    minutes
        .wrapping_mul(60)
        .wrapping_add(i64::from(sec1))
        .wrapping_sub(i64::from(sec0))
}

/// `long_int_avg()`: the mean, rounded up, without overflow.
fn long_int_avg(a: i64, b: i64) -> i64 {
    shr(a, 1).wrapping_add(shr(b, 1)).wrapping_add((a | b) & 1)
}

/// `isdst_differ()`.
fn isdst_differ(a: i32, b: i32) -> bool {
    ((a == 0) != (b == 0)) && a >= 0 && b >= 0
}

impl LocalTime {
    /// A process's local time: the environment read through `getenv`, in
    /// secure-execution mode or not, zone files through `fs`.
    pub fn new(getenv: Getenv, secure: bool, fs: Box<dyn ZoneFs>) -> LocalTime {
        LocalTime {
            getenv,
            secure,
            fs,
            initialized: false,
            old_tz: None,
            use_tzfile: false,
            key: FileKey::default(),
            data: None,
            rule_stdoff: 0,
            rule_dstoff: 0,
            rules: PosixTz::default(),
            tzname: [b"GMT".to_vec(), b"GMT".to_vec()],
            offset_guess: 0,
        }
    }

    /// UTC: no `TZ` and no zone file, as on a host without
    /// `/etc/localtime`. What the parse checks a marker format in when it
    /// must not read the host's zone.
    pub fn utc() -> LocalTime {
        LocalTime::new(Box::new(|_| None), false, Box::new(NoZoneFiles))
    }

    /// Back to a new process's state, the environment and files kept: for
    /// tests, which must not depend on the order they run in.
    pub fn reset(&mut self) {
        let getenv = std::mem::replace(&mut self.getenv, Box::new(|_| None));
        let fs = std::mem::replace(&mut self.fs, Box::new(NoZoneFiles));
        *self = LocalTime::new(getenv, self.secure, fs);
    }

    /// `mktime()`'s offset guess, as the last call left it.
    pub fn offset_guess(&self) -> i64 {
        self.offset_guess
    }

    /// `tzname`, as the last call left it.
    pub fn tzname(&self, isdst: bool) -> &[u8] {
        self.tzname
            .get(usize::from(isdst))
            .map_or(&[][..], Vec::as_slice)
    }

    /// `update_vars()`: `tzname` from the rules.
    fn update_vars(&mut self) {
        self.tzname = self.rules.names();
    }

    /// `tzset_internal(always)`.
    fn tzset_internal(&mut self, always: bool) {
        if self.initialized && !always {
            return;
        }
        self.initialized = true;
        let tz =
            (self.getenv)("TZ").map(|v| v.split(|&b| b == 0).next().unwrap_or_default().to_vec());
        let tz = match tz {
            Some(v) if v.is_empty() => Some(b"Universal".to_vec()),
            Some(v) if v.first() == Some(&b':') => Some(v.get(1..).unwrap_or_default().to_vec()),
            other => other,
        };
        if let (Some(old), Some(tz)) = (&self.old_tz, &tz) {
            if old == tz {
                return;
            }
        }
        let tz = tz.unwrap_or_else(|| TZDEFAULT.to_vec());
        self.old_tz = Some(tz.clone());
        self.tzfile_read(&tz);
        if self.use_tzfile {
            return;
        }
        if tz.is_empty() || tz == TZDEFAULT {
            self.rules = PosixTz::utc(b"UTC");
            self.update_vars();
            return;
        }
        self.parse_tz(&tz);
    }

    /// `__tzset_parse_tz()`.
    fn parse_tz(&mut self, tz: &[u8]) {
        self.parsed_tz(PosixTz::parse_with_default(tz));
    }

    /// `__tzset_parse_tz()` once the string is read: where it names an
    /// alternative and no rule, `__tzfile_default()` (`posixrules`), and
    /// where that loads, `tz_rules` left as the string was read to there,
    /// `old_tz` forgotten and nothing more; else the rules, and `tzname`
    /// from them.
    fn parsed_tz(&mut self, (rules, wants): (PosixTz, Option<DefaultRules>)) {
        if let Some(d) = wants {
            self.rules = d.as_read.clone();
            self.tzfile_default(d);
            if self.use_tzfile {
                self.old_tz = None;
                return;
            }
        }
        self.rules = rules;
        self.update_vars();
    }

    /// `__tzfile_read(file, 0, NULL)`.
    fn tzfile_read(&mut self, file: &[u8]) {
        let was_using = self.use_tzfile;
        self.use_tzfile = false;
        if file.is_empty() {
            self.data = None;
            return;
        }
        if self.secure
            && ((file.first() == Some(&b'/') && file != TZDEFAULT && !file.starts_with(TZDIR))
                || file.windows(3).any(|w| w == b"../"))
        {
            self.data = None;
            return;
        }
        let path = if file.first() == Some(&b'/') {
            file.to_vec()
        } else {
            let dir = (self.getenv)("TZDIR")
                .filter(|d| !d.is_empty() && !self.secure)
                .unwrap_or_else(|| TZDIR.to_vec());
            [&dir[..], b"/", file].concat()
        };
        if was_using && self.fs.stat(&path) == Some(self.key) {
            self.use_tzfile = true;
            return;
        }
        let Some(src) = self.fs.open(&path) else {
            self.data = None;
            return;
        };
        self.key = match &src {
            ZoneSource::Regular { key, .. } | ZoneSource::Stream { key, .. } => *key,
        };
        self.data = None;
        let Some(data) = TzData::load(&src) else {
            return;
        };
        // `tzname`: the names of the last standard and daylight time types
        // a transition goes to, else the first name.
        let mut names: [Option<Vec<u8>>; 2] = [None, None];
        let mut i = data.timecnt;
        while i > 0 {
            i -= 1;
            let ty = data.ty(data.type_idx(i));
            let dst = usize::from(ty.isdst);
            if names.get(dst).is_some_and(Option::is_none) {
                if let Some(slot) = names.get_mut(dst) {
                    *slot = Some(data.name(ty.idx));
                }
                if names.get(1 - dst).is_some_and(Option::is_some) {
                    break;
                }
            }
        }
        let [n0, n1] = names;
        let n0 = n0.unwrap_or_else(|| {
            data.names
                .split(|&b| b == 0)
                .next()
                .unwrap_or_default()
                .to_vec()
        });
        let n1 = n1.unwrap_or_else(|| n0.clone());
        self.tzname = [n0, n1];
        if data.timecnt == 0 {
            let first = i64::from(data.ty(0).offset);
            self.rule_stdoff = first;
            self.rule_dstoff = first;
        } else {
            // The last transition to standard time sets it, else 0.
            self.rule_stdoff = 0;
            let mut i = data.timecnt;
            while i > 0 {
                i -= 1;
                let ty = data.ty(data.type_idx(i));
                if !ty.isdst {
                    self.rule_stdoff = i64::from(ty.offset);
                    break;
                }
            }
        }
        self.data = Some(data);
        self.use_tzfile = true;
    }

    /// `__tzfile_default()`: `posixrules`, its changes moved to the offsets
    /// and given the names the rule string asked for.
    fn tzfile_default(&mut self, d: DefaultRules) {
        self.tzfile_read(TZDEFRULES);
        if !self.use_tzfile {
            return;
        }
        let Some(data) = self.data.as_mut() else {
            self.use_tzfile = false;
            return;
        };
        if data.typecnt < 2 {
            self.use_tzfile = false;
            return;
        }
        data.moved = Some(Moved {
            stdoff: i64::from(d.stdoff as i32),
            dstoff: i64::from(d.dstoff as i32),
            rule_stdoff: self.rule_stdoff,
            rule_dstoff: self.rule_dstoff,
        });
        self.rule_stdoff = i64::from(d.stdoff as i32);
        self.rule_dstoff = i64::from(d.dstoff as i32);
        let std_len = d.std.len().saturating_add(1);
        let (t0, t1) = (data.raw_type(0), data.raw_type(1));
        data.head = vec![
            TtInfo {
                offset: d.stdoff as i32,
                isdst: false,
                idx: 0,
                ..t0
            },
            TtInfo {
                offset: d.dstoff as i32,
                isdst: true,
                // An `unsigned char`, as glibc's is.
                idx: (std_len & 0xff) as u8,
                ..t1
            },
        ];
        data.typecnt = 2;
        data.first_std = data.head.first().map(|t| (0, *t));
        data.first_dst = data.head.get(1).copied();
        let mut names = d.std.clone();
        names.push(0);
        names.extend_from_slice(&d.dst);
        names.push(0);
        data.names = names;
        self.tzname = [d.std, d.dst];
        // Read again the next time it is wanted.
        self.key = FileKey::default();
    }

    /// `tzset()`.
    pub fn tzset(&mut self) {
        self.tzset_internal(true);
        if !self.use_tzfile {
            self.update_vars();
        }
    }

    /// `localtime()`: `TZ` looked at again (and with it unset,
    /// `/etc/localtime`), then second `t` broken down. `None` where the
    /// year does not fit an `int`.
    pub fn localtime(&mut self, t: i64) -> Option<Tm> {
        self.convert(t, true)
    }

    /// `localtime_r()`: the zone read once a process, then left.
    pub fn localtime_r(&mut self, t: i64) -> Option<Tm> {
        self.convert(t, false)
    }

    /// `__tz_convert(t, 1, tp)`.
    fn convert(&mut self, t: i64, always: bool) -> Option<Tm> {
        self.tzset_internal(always);
        let (offset, isdst, zone, correction, hit) = if self.use_tzfile {
            self.tzfile_compute(t)?
        } else {
            let year = i64::from(offtime(t, 0)?.year) + 1900;
            let (offset, isdst) = self.rules.at(t, year);
            let zone = self.tzname(isdst).to_vec();
            (offset, isdst, zone, 0, 0)
        };
        let mut tm = offtime(t, offset.checked_sub(correction)?)?;
        tm.sec = tm.sec.checked_add(hit)?;
        tm.isdst = isdst;
        tm.gmtoff = offset;
        tm.zone = zone;
        Some(tm)
    }

    /// `__tzfile_compute(t, 1, …)`: the offset, whether it is daylight
    /// time, the name, the leap seconds' correction and how many of them
    /// `t` is, `tzname` set as it goes.
    fn tzfile_compute(&mut self, t: i64) -> Option<(i64, bool, Vec<u8>, i64, i32)> {
        enum Branch {
            Before,
            Past,
            Between(u64),
        }
        let (branch, n) = {
            let data = self.data.as_ref()?;
            let n = data.timecnt;
            let branch = if n == 0 || t < data.transition(0) {
                Branch::Before
            } else if t >= data.transition(n - 1) {
                Branch::Past
            } else {
                Branch::Between(Self::search(data, t, n)?)
            };
            (branch, n)
        };
        let mut names: [Option<Vec<u8>>; 2] = [None, None];
        let info = match branch {
            Branch::Before => {
                // Before every transition: the first standard time type, or
                // the first; `tzname[1]` the first daylight time type.
                let data = self.data.as_ref()?;
                let info = match data.first_std {
                    Some((_, ty)) => ty,
                    None => data.ty(0),
                };
                if let Some(dst) = data.first_dst {
                    names[1] = Some(data.name(dst.idx));
                }
                names[0] = Some(data.name(info.idx));
                info
            }
            Branch::Past => match self.data.as_ref()?.spec.clone() {
                None => found_at(self.data.as_ref()?, &mut names, n, n),
                Some(spec) => {
                    // `__tzset_parse_tz(tzspec)`. A rule string that names
                    // daylight time and no rule (`EST5EDT`) loads
                    // `posixrules` in place of the zone being computed
                    // from, as glibc does in the middle of this function
                    // (its zone is freed under it): the rules then are the
                    // string's names and offsets with `tz_rules` cleared,
                    // the leap seconds `posixrules`', and the zone is read
                    // again at the next `localtime()`; where `posixrules`
                    // is missing, the zone is gone, the United States'
                    // rule is the string's and no leap second is left,
                    // and with `TZ` unchanged that is all there is from
                    // then on (measured, DIVERGENCES 152).
                    // Where nothing is loaded after it, glibc's `leap:`
                    // reads the zone it freed, whose leap seconds are still
                    // there to read (measured, a 3797-byte zone: its 27).
                    let freed_leaps = self.leap_at(t);
                    self.parsed_tz(spec);
                    match offtime(t, 0) {
                        Some(ut) => {
                            // `__tz_compute(timer, tp, 1)`: `tm_zone` is
                            // `tzname[isdst]`.
                            let (offset, isdst) = self.rules.at(t, i64::from(ut.year) + 1900);
                            let zone = self.tzname(isdst).to_vec();
                            let (correction, hit) = if self.data.is_some() {
                                self.leap_at(t)
                            } else {
                                freed_leaps
                            };
                            return Some((offset, isdst, zone, correction, hit));
                        }
                        None => {
                            // The rules read and not used: the last type of
                            // what is loaded now.
                            let [r0, r1] = self.tzname.clone();
                            names = [Some(r0), Some(r1)];
                            let data = self.data.as_ref()?;
                            let n = data.timecnt;
                            found_at(data, &mut names, n, n)
                        }
                    }
                }
            },
            Branch::Between(i) => found_at(self.data.as_ref()?, &mut names, i, n),
        };
        let data = self.data.as_ref()?;
        let [n0, n1] = names;
        let n0 = n0.unwrap_or_else(|| {
            data.names
                .split(|&b| b == 0)
                .next()
                .unwrap_or_default()
                .to_vec()
        });
        let n1 = n1.unwrap_or_else(|| n0.clone());
        self.tzname = [n0, n1];
        let zone = self.tzname(info.isdst).to_vec();
        let (correction, hit) = self.leap_at(t);
        Some((i64::from(info.offset), info.isdst, zone, correction, hit))
    }

    /// The transition after `t` that `__tzfile_compute()` finds, where `t`
    /// lies between the first and the last: a guess from the last at two
    /// changes a year, ten steps either way from it, else a binary search.
    fn search(data: &TzData, t: i64, n: u64) -> Option<u64> {
        let last = data.transition(n - 1);
        let mut lo = 0u64;
        let mut hi = n - 1;
        let guess = last.wrapping_sub(t) / 15_778_476;
        if let Ok(g) = u64::try_from(guess) {
            if g < n {
                let mut i = n - 1 - g;
                if t < data.transition(i) {
                    if i < 10 || t >= data.transition(i - 10) {
                        while i > 1 && t < data.transition(i - 1) {
                            i -= 1;
                        }
                        return Some(i.max(1));
                    }
                    hi = i - 10;
                } else {
                    if i + 10 >= n || t < data.transition(i + 10) {
                        while i < n - 1 && t >= data.transition(i) {
                            i += 1;
                        }
                        return Some(i.max(1));
                    }
                    lo = i + 10;
                }
            }
        }
        while lo + 1 < hi {
            let i = (lo + hi) / 2;
            if t < data.transition(i) {
                hi = i;
            } else {
                lo = i;
            }
        }
        Some(hi.max(1))
    }

    /// The leap seconds at `t`: the correction, and how many `t` is.
    fn leap_at(&self, t: i64) -> (i64, i32) {
        let Some(data) = self.data.as_ref() else {
            return (0, 0);
        };
        let mut i = data.leapcnt;
        let (when, change) = loop {
            if i == 0 {
                return (0, 0);
            }
            i -= 1;
            let (when, change) = data.leap(i);
            if t >= when {
                break (when, change);
            }
        };
        let mut hit = 0i32;
        let before = if i == 0 { 0 } else { data.leap(i - 1).1 };
        if t == when && change > before {
            hit = 1;
            while i > 0 {
                let (w, c) = data.leap(i);
                let (pw, pc) = data.leap(i - 1);
                if w != pw.wrapping_add(1) || c != pc.wrapping_add(1) {
                    break;
                }
                hit = hit.saturating_add(1);
                i -= 1;
            }
        }
        (change, hit)
    }

    /// `ranged_convert()`: `localtime_r(t)`, or where its year does not fit,
    /// the nearest second between `t` and 0 whose year does, found by halves.
    fn ranged_convert(&mut self, t: &mut i64) -> Option<Tm> {
        if let Some(tm) = self.localtime_r(*t) {
            return Some(tm);
        }
        let mut bad = *t;
        let mut ok = 0i64;
        let mut oktm = None;
        loop {
            let mid = long_int_avg(ok, bad);
            if mid == ok || mid == bad {
                break;
            }
            match self.localtime_r(mid) {
                Some(tm) => {
                    ok = mid;
                    oktm = Some(tm);
                }
                None => bad = mid,
            }
        }
        let tm = oktm?;
        *t = ok;
        Some(tm)
    }

    /// `mktime()` of `tm`, as strftime's `%s` calls it on a copy: `tzset()`
    /// first, then the search; -1 where it fails.
    pub fn mktime(&mut self, tm: &MkTm) -> i64 {
        self.tzset();
        self.mktime_internal(tm).unwrap_or(-1)
    }

    /// `__mktime_internal(tp, __localtime64_r, &localtime_offset)`.
    fn mktime_internal(&mut self, tp: &MkTm) -> Option<i64> {
        let mut remaining_probes = 6;
        let (min, hour, mday, mon) = (tp.min, tp.hour, tp.mday, tp.mon);
        let isdst = tp.isdst;
        let mut dst2 = 0i32;
        let mon_remainder = mon % 12;
        let negative_mon_remainder = i32::from(mon_remainder < 0);
        let mon_years = mon / 12 - negative_mon_remainder;
        let year = i64::from(tp.year) + i64::from(mon_years);
        let row = usize::try_from(mon_remainder + 12 * negative_mon_remainder).unwrap_or(0);
        let mon_yday = mon_yday(leapyear(year), row) - 1;
        let yday = mon_yday + i64::from(mday);
        let off = self.offset_guess;
        let sec_requested = tp.sec;
        let sec = tp.sec.clamp(0, 59);
        let negative_offset_guess = off.wrapping_neg() as i32;
        let t0 = ydhms_diff(
            year,
            yday,
            hour,
            min,
            sec,
            70,
            0,
            0,
            0,
            negative_offset_guess,
        );
        let (mut t, mut t1, mut t2) = (t0, t0, t0);
        let diff = |tm: &Tm| {
            ydhms_diff(
                year, yday, hour, min, sec, tm.year, tm.yday, tm.hour, tm.min, tm.sec,
            )
        };
        let mut tm;
        let mut matched = true;
        loop {
            tm = self.ranged_convert(&mut t)?;
            let dt = diff(&tm);
            if dt == 0 {
                break;
            }
            let tm_isdst = i32::from(tm.isdst);
            let oscillating = t == t1
                && t != t2
                && (tm_isdst < 0
                    || if isdst < 0 {
                        dst2 <= i32::from(tm_isdst != 0)
                    } else {
                        (isdst != 0) != (tm_isdst != 0)
                    });
            if oscillating {
                // In a spring-forward gap: the time `dt` away.
                matched = false;
                break;
            }
            remaining_probes -= 1;
            if remaining_probes == 0 {
                return None;
            }
            t1 = t2;
            t2 = t;
            t = t.wrapping_add(dt);
            dst2 = i32::from(tm_isdst != 0);
        }
        if matched && isdst_differ(isdst, i32::from(tm.isdst)) {
            // The wrong `tm_isdst`: a time near with the right one, and its
            // offset; else an hour's difference.
            let dst_difference = i32::from(isdst == 0) - i32::from(!tm.isdst);
            let stride: i32 = 601_200;
            let duration_max: i32 = 457_243_209;
            let delta_bound = duration_max / 2 + stride;
            let mut found = None;
            let mut delta = stride;
            'search: while delta < delta_bound {
                for direction in [-1i32, 1] {
                    let Some(mut ot) = t.checked_add(i64::from(delta * direction)) else {
                        continue;
                    };
                    let otm = self.ranged_convert(&mut ot)?;
                    if !isdst_differ(isdst, i32::from(otm.isdst)) {
                        let gt = ot.wrapping_add(diff(&otm));
                        if let Some(gtm) = self.localtime_r(gt) {
                            found = Some((gt, gtm));
                            break 'search;
                        }
                    }
                }
                delta += stride;
            }
            match found {
                Some((gt, gtm)) => {
                    t = gt;
                    tm = gtm;
                }
                None => {
                    t = t.wrapping_add(3600 * i64::from(dst_difference));
                    tm = self.localtime_r(t)?;
                }
            }
        }
        self.offset_guess = t
            .wrapping_sub(t0)
            .wrapping_sub(i64::from(negative_offset_guess));
        if sec_requested != tm.sec {
            let mut adjustment = i64::from(sec == 0 && tm.sec == 60);
            adjustment -= i64::from(sec);
            adjustment += i64::from(sec_requested);
            t = t.checked_add(adjustment)?;
            self.localtime_r(t)?;
        }
        Some(t)
    }
}

impl TimeHooks for LocalTime {
    fn mktime(&mut self, tm: &Tm) -> i64 {
        LocalTime::mktime(self, &MkTm::of(tm))
    }
    fn tzset(&mut self) {
        LocalTime::tzset(self);
    }
    fn tzname(&self, isdst: bool) -> Vec<u8> {
        LocalTime::tzname(self, isdst).to_vec()
    }
}

/// What `strftime()` asks the C library for besides the time it is given:
/// `%s`'s `mktime()`, and `%Z`'s `tzset()` and `tzname` where the time
/// names no zone.
pub trait TimeHooks {
    /// `mktime()` of a copy of `tm`; -1 where it fails.
    fn mktime(&mut self, tm: &Tm) -> i64;
    fn tzset(&mut self);
    fn tzname(&self, isdst: bool) -> Vec<u8>;
}

// --------------------------------------------------------------- strftime

const WEEKDAYS: [&str; 7] = [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
];
const MONTHS: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

/// How a conversion's text is cased: `^` (and `#` on a name), or `#` on
/// `%p` and `%Z` and `%P` itself.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Case {
    Keep,
    Upper,
    Lower,
}

/// The buffer `strftime` fills: `maxsize` is its length, and what does not
/// fit with a byte to spare ends the call with 0 (`add()`'s `return 0`).
struct Out<'a> {
    buf: &'a mut [u8],
    at: usize,
}

impl Out<'_> {
    /// `add(n, …)` under a field width: `n` bytes, with what the width
    /// asks for before them, zeros under the `0` flag and spaces
    /// otherwise. `false` where they do not fit; nothing is written then.
    fn add(&mut self, text: &[u8], width: i64, pad: u8, case: Case) -> bool {
        let n = text.len();
        let delta = usize::try_from(width).unwrap_or(0).saturating_sub(n);
        let incr = n.saturating_add(delta);
        if incr >= self.buf.len().saturating_sub(self.at) {
            return false;
        }
        let fill = if pad == b'0' { b'0' } else { b' ' };
        for _ in 0..delta {
            self.put(fill);
        }
        for &b in text {
            self.put(match case {
                Case::Keep => b,
                Case::Upper => b.to_ascii_uppercase(),
                Case::Lower => b.to_ascii_lowercase(),
            });
        }
        true
    }

    fn put(&mut self, b: u8) {
        if let Some(slot) = self.buf.get_mut(self.at) {
            *slot = b;
            self.at = self.at.saturating_add(1);
        }
    }
}

/// How deep a conversion that is itself a format (`%c`, `%D`, …) goes:
/// each is made of plain conversions, so one level.
const SUBFORMAT_DEPTH: u8 = 2;

/// glibc 2.39's `strftime(buf, buf.len(), format, tm)` in the C locale:
/// how many bytes it wrote, a NUL after them; 0 where the result and its
/// NUL do not fit (or it is empty), and then the buffer holds what was
/// written before the conversion that did not fit, as glibc leaves it.
/// `hooks` is the C library's state, which `%s` asks `mktime()` of (a copy
/// of `tm`, printing -1 where it fails), and `%Z` `tzset()` and `tzname`
/// of where `tm` names no zone, as glibc asks them.
///
/// The format is bytes and ends at its first NUL. Its conversions are
/// glibc's, with the `_`, `-`, `0`, `^` and `#` flags, a field width, and
/// the `E` and `O` modifiers where glibc takes them; anything else is
/// copied as written, from its `%`. Every one was measured, among them:
/// a width pads text with spaces even under `-`; `%z` pads its sign and
/// its digits apart (`%8z` is seven spaces, `-`, `00000400`); `%+…`, a
/// flag of newer C libraries, is none here; `%^q` is `%^Q`.
pub fn strftime(buf: &mut [u8], format: &[u8], tm: &Tm, hooks: &mut dyn TimeHooks) -> usize {
    let format = format.split(|&b| b == 0).next().unwrap_or_default();
    let mut out = Out { buf, at: 0 };
    let mut c = Call {
        hooks,
        tzset_called: false,
    };
    if !format_into(&mut out, format, tm, &mut c, SUBFORMAT_DEPTH) {
        return 0;
    }
    let written = out.at;
    match out.buf.get_mut(written) {
        Some(end) => {
            *end = 0;
            written
        }
        None => 0,
    }
}

/// The ISO 8601 week's days so far (`iso_week_days()`).
fn iso_week_days(yday: i64, wday: i64) -> i64 {
    let big_enough_multiple_of_7 = (366 / 7 + 2) * 7;
    yday - (yday - wday + 4 + big_enough_multiple_of_7) % 7 + 4 - 1
}

/// One `strftime()` call's link to the C library: `tzset()` is called at
/// most once a call (`tzset_called`).
struct Call<'h> {
    hooks: &'h mut dyn TimeHooks,
    tzset_called: bool,
}

fn format_into(out: &mut Out<'_>, format: &[u8], tm: &Tm, call: &mut Call<'_>, depth: u8) -> bool {
    let mut f = 0usize;
    while f < format.len() {
        let c = peek(format, f);
        if c != b'%' {
            if !out.add(&[c], -1, 0, Case::Keep) {
                return false;
            }
            f = f.saturating_add(1);
            continue;
        }
        let start = f;
        let mut pad = 0u8;
        let mut upper = false;
        let mut change_case = false;
        loop {
            f = f.saturating_add(1);
            match peek(format, f) {
                b @ (b'_' | b'-' | b'0') => pad = b,
                b'^' => upper = true,
                b'#' => change_case = true,
                _ => break,
            }
        }
        let mut width: i64 = -1;
        if peek(format, f).is_ascii_digit() {
            width = 0;
            while peek(format, f).is_ascii_digit() {
                let digit = i64::from(peek(format, f).wrapping_sub(b'0'));
                width = width
                    .saturating_mul(10)
                    .saturating_add(digit)
                    .min(i64::from(i32::MAX));
                f = f.saturating_add(1);
            }
        }
        let modifier = match peek(format, f) {
            m @ (b'E' | b'O') => {
                f = f.saturating_add(1);
                m
            }
            _ => 0,
        };
        let conversion = peek(format, f);
        let mut case = if upper { Case::Upper } else { Case::Keep };
        let name_case = if upper || change_case {
            Case::Upper
        } else {
            Case::Keep
        };
        // What the conversion is: text, a number, or another format.
        enum Is<'t> {
            Text(&'t [u8], Case),
            Owned(Vec<u8>, Case),
            /// The least digits, the value, and whether it is padded with
            /// spaces unless a flag says otherwise.
            Number(i64, i64, bool),
            Sub(&'static [u8]),
            Bad,
        }
        let hour12 = if tm.hour % 12 == 0 { 12 } else { tm.hour % 12 };
        // `int year = tp->tm_year + TM_YEAR_BASE`: an `int`, which wraps
        // past 2^31 - 1 (measured: a time in the year 2^31 prints `%Y`
        // `-2147483648`).
        let year32 = tm.year.wrapping_add(1900);
        let year = i64::from(year32);
        let e = modifier == b'E';
        let o = modifier == b'O';
        let number = |digits: i64, value: i64| Is::Number(digits, value, false);
        let unless_e = |is: Is<'static>| if e { Is::Bad } else { is };
        let weekday = WEEKDAYS
            .get(usize::try_from(tm.wday).unwrap_or(7))
            .map_or(&b"?"[..], |s| s.as_bytes());
        let month = MONTHS
            .get(usize::try_from(tm.mon).unwrap_or(12))
            .map_or(&b"?"[..], |s| s.as_bytes());
        let is = match conversion {
            b'%' if modifier != 0 => Is::Bad,
            b'%' => Is::Text(b"%", case),
            b'a' | b'A' if modifier != 0 => Is::Bad,
            b'a' => Is::Text(weekday.get(..3).unwrap_or(weekday), name_case),
            b'A' => Is::Text(weekday, name_case),
            // `#` is acted on before `E` is refused, so `%#Eh` is `%#EH`.
            b'b' | b'h' if e => {
                if change_case {
                    case = Case::Upper;
                }
                Is::Bad
            }
            b'B' if e => Is::Bad,
            b'b' | b'h' => Is::Text(month.get(..3).unwrap_or(month), name_case),
            b'B' => Is::Text(month, name_case),
            b'c' if o => Is::Bad,
            b'c' => Is::Sub(b"%a %b %e %H:%M:%S %Y"),
            b'C' => number(1, year.div_euclid(100)),
            b'x' if o => Is::Bad,
            b'x' => Is::Sub(b"%m/%d/%y"),
            b'D' if modifier != 0 => Is::Bad,
            b'D' => Is::Sub(b"%m/%d/%y"),
            b'd' => unless_e(number(2, i64::from(tm.mday))),
            b'e' => unless_e(Is::Number(2, i64::from(tm.mday), true)),
            b'F' if modifier != 0 => Is::Bad,
            b'F' => Is::Sub(b"%Y-%m-%d"),
            b'H' => unless_e(number(2, i64::from(tm.hour))),
            b'I' => unless_e(number(2, i64::from(hour12))),
            b'k' => unless_e(Is::Number(2, i64::from(tm.hour), true)),
            b'l' => unless_e(Is::Number(2, i64::from(hour12), true)),
            b'j' => unless_e(number(3, i64::from(tm.yday) + 1)),
            b'M' => unless_e(number(2, i64::from(tm.min))),
            b'm' => unless_e(number(2, i64::from(tm.mon) + 1)),
            b'n' => Is::Text(b"\n", case),
            b't' => Is::Text(b"\t", case),
            b'P' => Is::Text(if tm.hour > 11 { b"pm" } else { b"am" }, Case::Lower),
            b'p' => Is::Text(
                if tm.hour > 11 { b"PM" } else { b"AM" },
                if change_case { Case::Lower } else { case },
            ),
            b'R' => Is::Sub(b"%H:%M"),
            b'r' => Is::Sub(b"%I:%M:%S %p"),
            b'S' => unless_e(number(2, i64::from(tm.sec))),
            // `mktime()` of a copy of the time, -1 where it fails, unchecked.
            b's' => Is::Owned(call.hooks.mktime(tm).to_string().into_bytes(), Case::Keep),
            b'X' if o => Is::Bad,
            b'X' | b'T' => Is::Sub(b"%H:%M:%S"),
            b'u' => number(1, i64::from((tm.wday - 1 + 7) % 7 + 1)),
            b'U' => unless_e(number(2, i64::from((tm.yday - tm.wday + 7) / 7))),
            b'V' | b'g' | b'G' if e => Is::Bad,
            b'V' | b'g' | b'G' => {
                let (yday, wday) = (i64::from(tm.yday), i64::from(tm.wday));
                let mut iso_year = year32;
                let mut days = iso_week_days(yday, wday);
                if days < 0 {
                    // The week belongs to the year before.
                    iso_year = iso_year.wrapping_sub(1);
                    let leap = is_leap(i64::from(iso_year));
                    days = iso_week_days(yday + 365 + i64::from(leap), wday);
                } else {
                    let leap = is_leap(i64::from(iso_year));
                    let d = iso_week_days(yday - (365 + i64::from(leap)), wday);
                    if d >= 0 {
                        iso_year = iso_year.wrapping_add(1);
                        days = d;
                    }
                }
                let iso_year = i64::from(iso_year);
                match conversion {
                    b'g' => number(2, iso_year.rem_euclid(100)),
                    b'G' => number(1, iso_year),
                    _ => number(2, days / 7 + 1),
                }
            }
            b'W' => unless_e(number(
                2,
                i64::from((tm.yday - (tm.wday - 1 + 7) % 7 + 7) / 7),
            )),
            b'w' => unless_e(number(1, i64::from(tm.wday))),
            b'Y' if o => Is::Bad,
            b'Y' => number(1, year),
            // `(tp->tm_year % 100 + 100) % 100`: of `tm_year` itself.
            b'y' => number(2, i64::from(tm.year).rem_euclid(100)),
            b'Z' => {
                let case = if change_case { Case::Lower } else { case };
                if tm.zone.is_empty() {
                    // No zone in the time: `tzset()`, once a call, and
                    // `tzname[tm_isdst]`.
                    if !call.tzset_called {
                        call.hooks.tzset();
                        call.tzset_called = true;
                    }
                    Is::Owned(call.hooks.tzname(tm.isdst), case)
                } else {
                    Is::Text(&tm.zone, case)
                }
            }
            b'z' => {
                // The sign is a field of its own, and so is padded to the
                // width; then the digits, to four or the width.
                let sign: &[u8] = if tm.gmtoff < 0 { b"-" } else { b"+" };
                if !out.add(sign, width, pad, case) {
                    return false;
                }
                let minutes = tm.gmtoff.unsigned_abs() / 60;
                let value = i64::try_from((minutes / 60) * 100 + minutes % 60).unwrap_or(i64::MAX);
                number(4, value)
            }
            _ => Is::Bad,
        };
        match is {
            Is::Text(text, case) => {
                if !out.add(text, width, pad, case) {
                    return false;
                }
            }
            Is::Owned(text, case) => {
                if !out.add(&text, width, pad, case) {
                    return false;
                }
            }
            Is::Number(least, value, spaces) => {
                let digits = least.max(width);
                let mut pad = pad;
                if spaces && pad != b'0' && pad != b'-' {
                    pad = b'_';
                }
                let mut width = width;
                let mut text = value.unsigned_abs().to_string().into_bytes();
                if value < 0 {
                    text.insert(0, b'-');
                }
                let shown = i64::try_from(text.len()).unwrap_or(i64::MAX);
                let padding = digits.saturating_sub(shown);
                if pad != b'-' && padding > 0 {
                    let room = out.buf.len().saturating_sub(out.at);
                    if pad == b'_' {
                        let Ok(padding_len) = usize::try_from(padding) else {
                            return false;
                        };
                        if padding_len >= room {
                            return false;
                        }
                        for _ in 0..padding_len {
                            out.put(b' ');
                        }
                        width = if width > padding { width - padding } else { 0 };
                    } else {
                        if usize::try_from(digits).map_or(true, |d| d >= room) {
                            return false;
                        }
                        let zeros = usize::try_from(padding).unwrap_or(0);
                        if value < 0 {
                            text.remove(0);
                            out.put(b'-');
                        }
                        for _ in 0..zeros {
                            out.put(b'0');
                        }
                        width = 0;
                    }
                }
                if !out.add(&text, width, pad, case) {
                    return false;
                }
            }
            Is::Sub(sub) => {
                // Measured without a buffer first, as glibc does, so the
                // whole is padded to the width.
                let Some(depth) = depth.checked_sub(1) else {
                    return false;
                };
                let mut scratch = [0u8; 64];
                let mut inner = Out {
                    buf: &mut scratch,
                    at: 0,
                };
                if !format_into(&mut inner, sub, tm, call, depth) {
                    return false;
                }
                let len = inner.at;
                let text = scratch.get(..len).unwrap_or_default();
                if !out.add(text, width, pad, case) {
                    return false;
                }
                // The call glibc makes for it ends what it wrote with a
                // NUL, which stays where the next conversion does not fit.
                if let Some(end) = out.buf.get_mut(out.at) {
                    *end = 0;
                }
            }
            Is::Bad => {
                // As written, from its `%`: through this byte, or to the
                // format's end where it ends inside one.
                let end = if conversion == 0 {
                    f
                } else {
                    f.saturating_add(1)
                };
                let mut from = start;
                // glibc looks back for the nearest `%`, which is this
                // byte itself where the conversion is one (`%E%`).
                if conversion == b'%' {
                    from = f;
                }
                let text = format.get(from..end.min(format.len())).unwrap_or_default();
                if !out.add(text, width, pad, case) {
                    return false;
                }
                if conversion == 0 {
                    break;
                }
            }
        }
        f = f.saturating_add(1);
    }
    true
}

/// `-r m<fmt>`'s marker, as `main.c` makes it: a buffer of
/// `(len + 1) * 8 + 1` bytes the format is written into at the option and
/// again at each cycle, and printed up to its first NUL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Marker {
    format: Vec<u8>,
    buf: Vec<u8>,
}

impl Marker {
    /// The marker for `format`, tried at second `now` in `zone` as the C
    /// tries it where it reads the option: `None` where `strftime` gives 0
    /// (`illegal <fmt>`), which is a result that is empty or longer than
    /// eight bytes for each of the format's, and one.
    pub fn new(format: &[u8], lt: &mut LocalTime, now: i64) -> Option<Marker> {
        let format = format.split(|&b| b == 0).next().unwrap_or_default();
        let size = format
            .len()
            .checked_add(1)?
            .checked_mul(8)?
            .checked_add(1)?;
        let mut marker = Marker {
            format: format.to_vec(),
            buf: vec![0; size],
        };
        (marker.fill(lt, now) > 0).then_some(marker)
    }

    /// `util_strftime(fmtr, fmtl - 1, fmt)`: `localtime(time(NULL))`, then
    /// `strftime()`.
    fn fill(&mut self, lt: &mut LocalTime, now: i64) -> usize {
        let Some(tm) = lt.localtime(now) else {
            return 0;
        };
        let most = self.buf.len().saturating_sub(1);
        match self.buf.get_mut(..most) {
            Some(buf) => strftime(buf, &self.format, &tm, lt),
            None => 0,
        }
    }

    /// The marker at second `now`: the buffer filled again and read up to
    /// its first NUL. Where the result no longer fits (a zone whose name
    /// grew), that is what was written before it stopped fitting and what
    /// the buffer held after it, as in the C; the buffer starts as zeros
    /// here, where the C's is whatever `malloc()` gave it.
    pub fn at(&mut self, lt: &mut LocalTime, now: i64) -> &[u8] {
        self.fill(lt, now);
        if let Some(last) = self.buf.last_mut() {
            *last = 0;
        }
        self.buf.split(|&b| b == 0).next().unwrap_or_default()
    }

    /// The format, as given.
    pub fn format(&self) -> &[u8] {
        &self.format
    }
}

/// Whether `-F` refuses the format (`%n illegal in -r m<fmt> when -F has
/// been specified`): a `%` followed by `n`, where a `%` after a `%` is not
/// looked at (`main.c:1107-1117`).
pub fn has_newline_conversion(format: &[u8]) -> bool {
    let mut i = 0usize;
    while let Some(at) = format
        .get(i..)
        .and_then(|rest| rest.iter().position(|&b| b == b'%'))
    {
        i = i.saturating_add(at).saturating_add(1);
        match peek(format, i) {
            b'n' => return true,
            b'%' => i = i.saturating_add(1),
            _ => {}
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .filter_map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
            .collect()
    }

    /// The zone files the tests read, at the paths glibc reads them from.
    fn zone_files() -> MemZoneFiles {
        let mut fs = MemZoneFiles::default();
        let key = |ino| FileKey {
            dev: 1,
            ino,
            mtime: 1,
        };
        let files: [(&[u8], &[u8]); 23] = [
            (b"/craft/v1only", include_bytes!("../tests/tzif/v1only")),
            (b"/craft/v1as2", include_bytes!("../tests/tzif/v1as2")),
            (b"/craft/onetype", include_bytes!("../tests/tzif/onetype")),
            (
                b"/craft/onetype_dst",
                include_bytes!("../tests/tzif/onetype_dst"),
            ),
            (
                b"/craft/onetype_foot",
                include_bytes!("../tests/tzif/onetype_foot"),
            ),
            (b"/craft/leap", include_bytes!("../tests/tzif/leap")),
            (b"/craft/nonul", include_bytes!("../tests/tzif/nonul")),
            (
                b"/craft/hugecount",
                include_bytes!("../tests/tzif/hugecount"),
            ),
            (b"/craft/isstdbig", include_bytes!("../tests/tzif/isstdbig")),
            (b"/craft/trunc", include_bytes!("../tests/tzif/trunc")),
            (b"/craft/trunc2", include_bytes!("../tests/tzif/trunc2")),
            (b"/craft/empty", include_bytes!("../tests/tzif/empty")),
            (b"/craft/hdr", include_bytes!("../tests/tzif/hdr")),
            (b"/craft/badmagic", include_bytes!("../tests/tzif/badmagic")),
            (b"/craft/ver4", include_bytes!("../tests/tzif/ver4")),
            (b"/craft/footer_x", include_bytes!("../tests/tzif/footer_x")),
            (b"/craft/stride", include_bytes!("../tests/tzif/stride")),
            (b"/craft/runon", include_bytes!("../tests/tzif/runon")),
            (
                b"/usr/share/zoneinfo/Asia/Almaty",
                include_bytes!("../tests/tzif/almaty"),
            ),
            (
                b"/usr/share/zoneinfo/America/New_York",
                include_bytes!("../tests/tzif/new_york"),
            ),
            (
                b"/usr/share/zoneinfo/UTC",
                include_bytes!("../tests/tzif/utc"),
            ),
            (
                b"/usr/share/zoneinfo/Asia/Kolkata",
                include_bytes!("../tests/tzif/kolkata"),
            ),
            (
                b"/usr/share/zoneinfo/Europe/Lisbon",
                include_bytes!("../tests/tzif/lisbon"),
            ),
        ];
        for (i, (path, bytes)) in files.iter().enumerate() {
            fs.put(path, key(i as u64 + 10), bytes);
        }
        fs.put(
            b"/usr/share/zoneinfo/posixrules",
            key(99),
            include_bytes!("../tests/tzif/new_york"),
        );
        fs
    }

    /// A process's local time under `TZ` (`None`: unset) and `TZDIR`.
    fn local(tz: Option<&[u8]>, tzdir: Option<&[u8]>, fs: MemZoneFiles) -> LocalTime {
        let (tz, tzdir) = (tz.map(<[u8]>::to_vec), tzdir.map(<[u8]>::to_vec));
        LocalTime::new(
            Box::new(move |name| match name {
                "TZ" => tz.clone(),
                "TZDIR" => tzdir.clone(),
                _ => None,
            }),
            false,
            Box::new(fs),
        )
    }

    /// One line a call glibc 2.39 answered, made by the helper this module
    /// was measured with: `TZ`, `TZDIR` (or `-`), the second, the buffer's
    /// size, the format in hex, then what `strftime` returned, the buffer up
    /// to its NUL in hex, `tm_gmtoff`, `tm_isdst` and `tm_zone` in hex.
    /// Each is asked again here, of a [`LocalTime`] for its `TZ`; what
    /// differs is returned, with how many lines were asked.
    fn check_vectors(text: &str, fs: &dyn Fn() -> Box<dyn ZoneFs>) -> (usize, Vec<String>) {
        let mut zones: std::collections::HashMap<(String, String), LocalTime> = Default::default();
        let mut bad = Vec::new();
        let mut count = 0usize;
        for line in text.lines() {
            let f: Vec<&str> = line.split('\t').collect();
            let [tz, tzdir, epoch, size, format, ret, out, gmtoff, isdst, zone_name] = f[..] else {
                panic!("a line of ten fields: {line:?}");
            };
            let lt = zones
                .entry((tz.to_string(), tzdir.to_string()))
                .or_insert_with(|| {
                    let tz = (tz != "-").then(|| hex(tz));
                    let tzdir = (tzdir != "-").then(|| hex(tzdir));
                    LocalTime::new(
                        Box::new(move |name| match name {
                            "TZ" => tz.clone(),
                            "TZDIR" => tzdir.clone(),
                            _ => None,
                        }),
                        false,
                        fs(),
                    )
                });
            let epoch: i64 = epoch.parse().unwrap();
            let size: usize = size.parse().unwrap();
            let show = |h: &str| String::from_utf8_lossy(&hex(h)).into_owned();
            let asked = format!(
                "TZ={} TZDIR={} t={epoch} size={size} {:?} want {ret} {:?} off={gmtoff} dst={isdst} zone={:?}",
                if tz == "-" { "-".into() } else { show(tz) },
                if tzdir == "-" { "-".into() } else { show(tzdir) },
                show(format),
                show(out),
                show(zone_name),
            );
            count += 1;
            let Some(tm) = lt.localtime(epoch) else {
                bad.push(format!("{asked}\n   got no time"));
                continue;
            };
            let mut buf = vec![b'#'; size];
            let got = strftime(&mut buf, &hex(format), &tm, lt);
            let text = buf.split(|&b| b == 0).next().unwrap_or_default();
            let want_ret: usize = ret.parse().unwrap();
            let same_time = tm.gmtoff == gmtoff.parse::<i64>().unwrap()
                && i32::from(tm.isdst) == isdst.parse::<i32>().unwrap()
                && tm.zone == hex(zone_name);
            // Where glibc gives 0 the buffer is compared too: it holds
            // what was written before the conversion that did not fit.
            if got != want_ret || text != hex(out) || !same_time {
                bad.push(format!(
                    "{asked}\n   got {got} {:?} off={} dst={} zone={:?}",
                    String::from_utf8_lossy(text),
                    tm.gmtoff,
                    tm.isdst,
                    String::from_utf8_lossy(&tm.zone)
                ));
            }
        }
        (count, bad)
    }

    fn assert_none_differ(count: usize, bad: &[String]) {
        assert!(
            bad.is_empty(),
            "{} of {count} differ:\n{}",
            bad.len(),
            bad.iter()
                .take(4000)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    /// 801 calls glibc answered, kept with this module
    /// (`tests/timefmt_glibc.txt`): 694 of the 118,516 it was measured
    /// with (every conversion with no flag in UTC and formats at random, six
    /// seconds each of 64 `TZ` rule strings that name no zone file, six each
    /// of 16 crafted zone files, `tests/tzif/`, named `/craft/NAME`:
    /// versions 1 to 4, a footer of each shape, leap seconds, counts past the
    /// file, no file at all), 60 around February 29 under four `Jn` and `n`
    /// rules, and 47 more. No file of the host is read, so it runs anywhere,
    /// miri too.
    #[test]
    fn glibc_vectors_kept_with_the_code() {
        // Under miri a line in eight, 101: each call costs about 0.4 s there
        // through `LocalTime` (measured: 161 lines took 62 s), and the 101
        // keep the test within the 41 s it took before `%s` was `mktime()`.
        let text: String = include_str!("../tests/timefmt_glibc.txt")
            .lines()
            .step_by(if cfg!(miri) { 8 } else { 1 })
            .map(|line| format!("{line}\n"))
            .collect();
        let (count, bad) = check_vectors(&text, &|| Box::new(zone_files()));
        assert_eq!(count, if cfg!(miri) { 101 } else { 801 });
        assert_none_differ(count, &bad);
    }

    /// Every line of the file `LSOF_TZ_VECTORS` names ([`check_vectors`]'s
    /// lines), read with the host's zone files: the whole measurement, where
    /// the helper's output is at hand.
    #[test]
    #[cfg(unix)]
    #[cfg_attr(miri, ignore = "reads the host's zone files")]
    fn glibc_vectors_from_a_file() {
        let Some(path) = std::env::var_os("LSOF_TZ_VECTORS") else {
            return;
        };
        let text = std::fs::read_to_string(path).expect("the vectors file");
        let (count, bad) = check_vectors(&text, &|| Box::new(StdZoneFs));
        assert_none_differ(count, &bad);
    }

    /// `mktime()` and `%s` as glibc 2.39 answers them, each line a fresh
    /// process (`tests/mktime_glibc.txt`, made by the measurement's helper:
    /// `L:t` is `strftime("%s", localtime(t))`, `M:year:mon:mday:hour:min:sec:isdst`
    /// `mktime()` of that, in order). Among them the hour Asia/Almaty
    /// repeats on 2024-02-29 with one `tm_isdst`, which a fresh process
    /// takes as the later and one whose last guess was +06 as the earlier;
    /// New York's fall and spring with each `tm_isdst`; a `tm_isdst` no time
    /// near has (one hour off); years at `int`'s ends; seconds past 59.
    #[test]
    fn mktime_as_glibc_answers_it_in_a_fresh_process() {
        let mut bad = Vec::new();
        // Under miri the first six lines alone (Asia/Almaty's repeated
        // hour, in each order): a `tm_isdst` no time near has costs 380
        // probes, each a `localtime_r()`, and the 21 lines took 72 s there
        // (measured).
        for line in include_str!("../tests/mktime_glibc.txt")
            .lines()
            .take(if cfg!(miri) { 6 } else { usize::MAX })
        {
            let [tz, ops, want] = line.split('\t').collect::<Vec<_>>()[..] else {
                panic!("three fields: {line:?}");
            };
            let mut lt = local(Some(tz.as_bytes()), None, zone_files());
            let mut got = Vec::new();
            for op in ops.split(' ') {
                let f: Vec<i64> = op
                    .get(2..)
                    .unwrap()
                    .split(':')
                    .map(|n| n.parse().unwrap())
                    .collect();
                if op.starts_with('L') {
                    let tm = lt.localtime(f[0]).unwrap();
                    let mut buf = [0u8; 64];
                    let n = strftime(&mut buf, b"%s", &tm, &mut lt);
                    got.push(String::from_utf8_lossy(&buf[..n]).into_owned());
                } else {
                    let i = |k: usize| i32::try_from(f[k]).unwrap();
                    let req = MkTm {
                        year: i(0),
                        mon: i(1),
                        mday: i(2),
                        hour: i(3),
                        min: i(4),
                        sec: i(5),
                        isdst: i(6),
                    };
                    got.push(lt.mktime(&req).to_string());
                }
            }
            let got = got.join(" ");
            if got != want {
                bad.push(format!("TZ={tz} {ops}\n  want {want}\n  got  {got}"));
            }
        }
        assert!(bad.is_empty(), "{}", bad.join("\n"));
    }

    /// The guess `mktime()` carries is a process's: [`LocalTime::reset`]
    /// makes it a new one's again, so the fold is the later time again.
    #[test]
    fn reset_is_a_new_process() {
        let mut lt = local(Some(b"Asia/Almaty"), None, zone_files());
        let percent_s = |lt: &mut LocalTime, t: i64| {
            let tm = lt.localtime(t).unwrap();
            let mut buf = [0u8; 32];
            let n = strftime(&mut buf, b"%s", &tm, lt);
            String::from_utf8_lossy(&buf[..n]).into_owned()
        };
        assert_eq!(percent_s(&mut lt, 1_709_224_200), "1709224200");
        assert_eq!(percent_s(&mut lt, 1_709_227_800), "1709227800");
        lt.reset();
        assert_eq!(lt.offset_guess(), 0);
        assert_eq!(percent_s(&mut lt, 1_709_227_800), "1709231400");
    }

    /// glibc's `tzset()` in secure-execution mode (a set-user-ID run): `TZ`
    /// is read as a file only where it is the default or lies under the
    /// system's directory and holds no `../`, and `TZDIR` is not read.
    #[test]
    fn secure_mode_reads_only_the_system_zone_files() {
        let asked = |tz: &[u8], tzdir: Option<&[u8]>, secure: bool| {
            let fs = MemZoneFiles::default();
            let calls = Rc::clone(&fs.calls);
            let (tz, tzdir) = (tz.to_vec(), tzdir.map(<[u8]>::to_vec));
            let mut lt = LocalTime::new(
                Box::new(move |name| match name {
                    "TZ" => Some(tz.clone()),
                    "TZDIR" => tzdir.clone(),
                    _ => None,
                }),
                secure,
                Box::new(fs),
            );
            lt.tzset();
            let calls = calls.borrow().clone();
            calls
        };
        let zi: &[u8] = b"/tmp/zi";
        assert!(asked(b"/tmp/x", None, true).is_empty());
        assert!(asked(b"a/../b", None, true).is_empty());
        assert_eq!(
            asked(b"Europe/Paris", Some(zi), true),
            ["O /usr/share/zoneinfo/Europe/Paris"]
        );
        assert_eq!(
            asked(b"/usr/share/zoneinfo/Asia/Tokyo", None, true),
            ["O /usr/share/zoneinfo/Asia/Tokyo"]
        );
        assert_eq!(asked(b"/tmp/x", None, false), ["O /tmp/x"]);
        assert_eq!(
            asked(b"a/../b", None, false),
            ["O /usr/share/zoneinfo/a/../b"]
        );
        assert_eq!(
            asked(b"Europe/Paris", Some(zi), false),
            ["O /tmp/zi/Europe/Paris"]
        );
    }

    /// With no `TZ` and no zone file (Windows, which reads none), the
    /// marker's zone is UTC; a `TZ` rule string needs no file.
    #[test]
    fn with_no_zone_file_the_zone_is_utc_or_tzs_rule() {
        let utc = LocalTime::utc().localtime(0).unwrap();
        assert_eq!(
            (utc.gmtoff, utc.isdst, utc.zone.as_slice()),
            (0, false, &b"UTC"[..])
        );
        let mut cet = local(
            Some(b"CET-1CEST,M3.5.0,M10.5.0/3"),
            None,
            MemZoneFiles::default(),
        );
        let tm = cet.localtime(0).unwrap();
        assert_eq!((tm.gmtoff, tm.zone.as_slice()), (3600, &b"CET"[..]));
    }

    fn key(ino: u64, mtime: i64) -> FileKey {
        FileKey { dev: 7, ino, mtime }
    }

    /// `TZ` unset: every `localtime()` (and `mktime()`, `tzset()`) `stat`s
    /// `/etc/localtime` and reads it again where its device, inode or
    /// whole-second time changed; `localtime_r()` alone never looks again;
    /// a file that has gone is UTC named `UTC`, and the next call opens it
    /// without the `stat` (each measured with glibc 2.39 in a mount
    /// namespace: a rename over it, a link moved, an in-place rewrite with
    /// the time put back, `rm`).
    #[test]
    fn with_tz_unset_etc_localtime_is_looked_at_each_call() {
        let mut fs = zone_files();
        let utc = include_bytes!("../tests/tzif/utc");
        let almaty = include_bytes!("../tests/tzif/almaty");
        fs.put(TZDEFAULT, key(1, 100), utc);
        let calls = Rc::clone(&fs.calls);
        let files = Rc::new(RefCell::new(fs));
        struct Shared(Rc<RefCell<MemZoneFiles>>);
        impl ZoneFs for Shared {
            fn stat(&mut self, p: &[u8]) -> Option<FileKey> {
                self.0.borrow_mut().stat(p)
            }
            fn open(&mut self, p: &[u8]) -> Option<ZoneSource> {
                self.0.borrow_mut().open(p)
            }
        }
        let mut lt = LocalTime::new(
            Box::new(|_| None),
            false,
            Box::new(Shared(Rc::clone(&files))),
        );
        let t = 1_700_000_000;
        let zone = |lt: &mut LocalTime| {
            let tm = lt.localtime(t).unwrap();
            (String::from_utf8_lossy(&tm.zone).into_owned(), tm.gmtoff)
        };
        let taken = |calls: &Rc<RefCell<Vec<String>>>| std::mem::take(&mut *calls.borrow_mut());
        assert_eq!(zone(&mut lt), ("UTC".into(), 0));
        assert_eq!(taken(&calls), ["O /etc/localtime"]);
        // The same key: a stat, no read.
        assert_eq!(zone(&mut lt), ("UTC".into(), 0));
        assert_eq!(taken(&calls), ["S /etc/localtime"]);
        // Rewritten in place, the time put back: not seen.
        files.borrow_mut().put(TZDEFAULT, key(1, 100), almaty);
        assert_eq!(zone(&mut lt), ("UTC".into(), 0));
        // A new inode (a rename over it): read again.
        files.borrow_mut().put(TZDEFAULT, key(2, 100), almaty);
        assert_eq!(zone(&mut lt), ("+06".into(), 21_600));
        assert_eq!(
            taken(&calls),
            ["S /etc/localtime", "S /etc/localtime", "O /etc/localtime"]
        );
        // A second later: read again.
        files.borrow_mut().put(TZDEFAULT, key(2, 101), utc);
        assert_eq!(zone(&mut lt), ("UTC".into(), 0));
        // `localtime_r()` alone does not look; `mktime()`'s `tzset()` does,
        // and the zone it finds is the one `localtime_r()` then uses.
        files.borrow_mut().put(TZDEFAULT, key(3, 101), almaty);
        taken(&calls);
        assert_eq!(lt.localtime_r(t).unwrap().gmtoff, 0);
        assert!(taken(&calls).is_empty());
        let tm = lt.localtime_r(t).unwrap();
        lt.mktime(&MkTm::of(&tm));
        assert_eq!(taken(&calls), ["S /etc/localtime", "O /etc/localtime"]);
        assert_eq!(lt.localtime_r(t).unwrap().gmtoff, 21_600);
        files.borrow_mut().put(TZDEFAULT, key(5, 101), utc);
        assert_eq!(zone(&mut lt), ("UTC".into(), 0));
        taken(&calls);
        // Gone: UTC named UTC; back: opened with no stat first.
        files.borrow_mut().files.clear();
        assert_eq!(zone(&mut lt), ("UTC".into(), 0));
        assert_eq!(taken(&calls), ["S /etc/localtime", "O /etc/localtime"]);
        files.borrow_mut().put(TZDEFAULT, key(4, 1), almaty);
        assert_eq!(zone(&mut lt), ("+06".into(), 21_600));
        assert_eq!(taken(&calls), ["O /etc/localtime"]);
    }

    /// `TZ` set and unchanged: nothing is looked at again, whatever it
    /// names, `/etc/localtime` itself included (measured).
    #[test]
    fn with_tz_set_nothing_is_read_again() {
        for tz in [
            &b"Asia/Almaty"[..],
            b"/etc/localtime",
            b":/etc/localtime",
            b"UTC0",
        ] {
            let mut fs = zone_files();
            fs.put(TZDEFAULT, key(1, 1), include_bytes!("../tests/tzif/utc"));
            let calls = Rc::clone(&fs.calls);
            let mut lt = local(Some(tz), None, fs);
            lt.localtime(0);
            calls.borrow_mut().clear();
            lt.localtime(0);
            lt.tzset();
            let tm = lt.localtime(0).unwrap();
            lt.mktime(&MkTm::of(&tm));
            assert!(calls.borrow().is_empty(), "{tz:?}: {:?}", calls.borrow());
        }
    }

    /// A rule string with daylight time and no rule, and no file of its
    /// name: glibc reads `posixrules`, moves its changes to the offsets
    /// given and names them as asked; past the file's last change its
    /// footer decides, names and offsets both (measured: `TZ=FOO3BAR` with
    /// `posixrules` New York's: 2001-09-08 23:46:40 BAR -0200, but 2040-06-22
    /// 13:46:40 EDT -0400). `old_tz` is forgotten, so each call looks for
    /// the file of that name again (a `stat` once one is in use) and reads
    /// `posixrules` again (strace: `newfstatat FOO3BAR`, `openat FOO3BAR`,
    /// `openat posixrules`, each call).
    #[test]
    fn a_rule_string_with_no_rule_reads_posixrules_each_call() {
        let fs = zone_files();
        let calls = Rc::clone(&fs.calls);
        let mut lt = local(Some(b"FOO3BAR"), None, fs);
        let show = |lt: &mut LocalTime, t: i64| {
            let tm = lt.localtime(t).unwrap();
            let mut buf = [0u8; 64];
            let n = strftime(&mut buf, b"%F %T %Z %z", &tm, lt);
            String::from_utf8_lossy(&buf[..n]).into_owned()
        };
        assert_eq!(
            show(&mut lt, 1_000_000_000),
            "2001-09-08 23:46:40 BAR -0200"
        );
        assert_eq!(
            std::mem::take(&mut *calls.borrow_mut()),
            [
                "O /usr/share/zoneinfo/FOO3BAR",
                "O /usr/share/zoneinfo/posixrules"
            ]
        );
        assert_eq!(
            show(&mut lt, 2_224_000_000),
            "2040-06-22 13:46:40 EDT -0400"
        );
        assert_eq!(
            std::mem::take(&mut *calls.borrow_mut()),
            [
                "S /usr/share/zoneinfo/FOO3BAR",
                "O /usr/share/zoneinfo/FOO3BAR",
                "O /usr/share/zoneinfo/posixrules"
            ]
        );
        assert_eq!(show(&mut lt, 972_799_199), "2000-10-29 03:59:59 BAR -0200");
        assert_eq!(show(&mut lt, 972_799_200), "2000-10-29 03:00:00 FOO -0300");
        // No `posixrules`: the United States' rule, built in.
        let mut fs = zone_files();
        fs.files.retain(|(p, _)| !p.ends_with(b"posixrules"));
        let mut lt = local(Some(b"FOO3BAR"), None, fs);
        assert_eq!(
            show(&mut lt, 2_224_000_000),
            "2040-06-22 15:46:40 BAR -0200"
        );
    }

    /// A zone file whose footer names daylight time and no rule
    /// (`FOO3BAR`), past its last change: glibc's `__tzset_parse_tz()` of
    /// it reads `posixrules` in place of the zone (`__tzfile_default()`),
    /// and works the time out from `tz_rules` as the parse left them,
    /// cleared (the day `J0` 0, at second 0), so that for most of a year
    /// it is daylight time; the zone is read again at the next call. With
    /// no `posixrules`, the zone is gone for good and the United States'
    /// rule is the string's, at every time after. Measured with glibc 2.39
    /// (`localtime()` and `strftime("%F %T %Z %z %s")`, a call a line, in
    /// one process): lsof-rs had taken the United States' rule each time
    /// and kept the zone.
    #[test]
    fn a_footer_with_daylight_time_and_no_rule_reads_posixrules_in_its_place() {
        let show = |lt: &mut LocalTime, t: i64| {
            let tm = lt.localtime(t).unwrap();
            let mut buf = [0u8; 64];
            let n = strftime(&mut buf, b"%F %T %Z %z %s", &tm, lt);
            String::from_utf8_lossy(&buf[..n]).into_owned()
        };
        let times = [-100, 0, 1_000_000_000, 2_224_000_000, 972_799_200, -100];
        let mut fs = MemZoneFiles::default();
        fs.put(b"/z", key(1, 1), include_bytes!("../tests/tzif/nofoot"));
        fs.put(
            b"/tzd/posixrules",
            key(2, 1),
            include_bytes!("../tests/tzif/new_york"),
        );
        let mut without = fs.clone();
        without.files.retain(|(p, _)| !p.ends_with(b"posixrules"));
        let mut lt = local(Some(b"/z"), Some(b"/tzd"), fs);
        let got: Vec<String> = times.iter().map(|&t| show(&mut lt, t)).collect();
        assert_eq!(
            got,
            [
                "1970-01-01 00:58:20 AAA +0100 14300",
                "1969-12-31 22:00:00 BAR -0200 0",
                "2001-09-08 23:46:40 BAR -0200 1000000000",
                "2040-06-22 15:46:40 BAR -0200 2224000000",
                "2000-10-29 04:00:00 BAR -0200 972799200",
                "1970-01-01 00:58:20 AAA +0100 14300",
            ]
        );
        let mut lt = local(Some(b"/z"), Some(b"/tzd"), without);
        let got: Vec<String> = times.iter().map(|&t| show(&mut lt, t)).collect();
        assert_eq!(
            got,
            [
                "1970-01-01 00:58:20 AAA +0100 14300",
                "1969-12-31 21:00:00 FOO -0300 0",
                "2001-09-08 23:46:40 BAR -0200 1000000000",
                "2040-06-22 15:46:40 BAR -0200 2224000000",
                "2000-10-29 04:00:00 BAR -0200 972799200",
                "1969-12-31 20:58:20 FOO -0300 -100",
            ]
        );
    }

    /// Past the last change of a zone with leap seconds whose footer names
    /// daylight time and no rule, with no `posixrules`: glibc frees the
    /// zone in `__tzfile_default()` and its `leap:` then reads the freed
    /// zone's leap seconds, here still there (measured, 6 runs of 6: the
    /// 27 of a `right/` New York at 2000000000), and none at the next call,
    /// the zone gone.
    #[test]
    fn the_call_that_loses_the_zone_reads_its_leap_seconds() {
        let show = |lt: &mut LocalTime, t: i64| {
            let tm = lt.localtime(t).unwrap();
            let mut buf = [0u8; 64];
            let n = strftime(&mut buf, b"%F %T %Z %z %s", &tm, lt);
            String::from_utf8_lossy(&buf[..n]).into_owned()
        };
        let mut fs = MemZoneFiles::default();
        fs.put(
            b"/z",
            key(1, 1),
            include_bytes!("../tests/tzif/rightnorule"),
        );
        let mut lt = local(Some(b"/z"), Some(b"/tzd"), fs);
        let got: Vec<String> = [0, 2_000_000_000, 2_000_000_000]
            .iter()
            .map(|&t| show(&mut lt, t))
            .collect();
        assert_eq!(
            got,
            [
                "1969-12-31 19:00:00 EST -0500 0",
                "2033-05-17 23:32:53 EDT -0400 1999999973",
                "2033-05-17 23:33:20 EDT -0400 2000000000",
            ]
        );
    }

    /// A regular file whose `st_size` says less than its version 1 header
    /// says follows, read to its end as glibc's `fread()`s read it: a file
    /// that says it is empty and is a zone (`/proc/self/environ` holding
    /// one, measured: the C prints `ABC+0100`, lsof-rs had `+0000`). A
    /// version 2 file is read by `st_size`, as glibc reads its footer, and
    /// is no zone there.
    #[test]
    fn a_version_1_file_is_read_to_its_end_whatever_its_size_says() {
        struct Sized0(Vec<u8>);
        impl ZoneFs for Sized0 {
            fn stat(&mut self, _: &[u8]) -> Option<FileKey> {
                None
            }
            fn open(&mut self, _: &[u8]) -> Option<ZoneSource> {
                let data: Rc<dyn ReadAt> = Rc::new(self.0.clone());
                Some(ZoneSource::Regular {
                    key: FileKey::default(),
                    size: 0,
                    data: Rc::clone(&data),
                    later: data,
                })
            }
        }
        let zone = |bytes: &[u8]| {
            let mut lt = LocalTime::new(
                Box::new(|n| (n == "TZ").then(|| b"/z".to_vec())),
                false,
                Box::new(Sized0(bytes.to_vec())),
            );
            let tm = lt.localtime(0).unwrap();
            (String::from_utf8_lossy(&tm.zone).into_owned(), tm.gmtoff)
        };
        let v1 = include_bytes!("../tests/tzif/v1only");
        let mut fs = MemZoneFiles::default();
        fs.put(b"/z", key(1, 1), v1);
        let sized = local(Some(b"/z"), None, fs).localtime(0).unwrap();
        assert!(!sized.zone.is_empty());
        assert_eq!(
            zone(v1),
            (
                String::from_utf8_lossy(&sized.zone).into_owned(),
                sized.gmtoff
            )
        );
        // Short of its data: no zone, as glibc's short `fread()`.
        assert_eq!(zone(&v1[..v1.len() - 1]).0, "");
        assert_eq!(zone(include_bytes!("../tests/tzif/new_york")).0, "");
    }

    /// `%Y`, `%C` and `%G` of a year past an `int`: glibc's `int year =
    /// tp->tm_year + 1900` wraps (measured, `TZ=UTC`, the second
    /// 67767976233532800: `-2147483648 -21474837 -2147483648 52 01 48` for
    /// `%Y %C %G %g %V %y`); `%y` is of `tm_year` itself.
    #[test]
    fn the_year_is_the_cs_int() {
        let mut lt = LocalTime::utc();
        let tm = lt.localtime(67_767_976_233_532_800).unwrap();
        let mut buf = [0u8; 128];
        let n = strftime(&mut buf, b"%Y %C %G %g %V %y", &tm, &mut lt);
        assert_eq!(&buf[..n], b"-2147483648 -21474837 -2147483648 52 01 48");
    }

    /// A zone file glibc reads from a pipe or a device: a version 1 file
    /// alone (measured: one sent through a FIFO is `ABC +0100`; the same as
    /// version 2 is no zone, so `TZ`'s own reading of the path, UTC with no
    /// name).
    #[test]
    fn a_stream_is_read_as_glibc_reads_one() {
        let v1 = include_bytes!("../tests/tzif/v1only");
        let v2 = include_bytes!("../tests/tzif/new_york");
        assert_eq!(stream_data_len(&v1[..44]), Some(v1.len() as u64 - 44));
        assert_eq!(stream_data_len(&v2[..44]), None);
        assert_eq!(stream_data_len(&[0u8; 44]), None);
        assert_eq!(stream_data_len(&v1[..43]), None);
        for (bytes, stream, want) in [
            (&v1[..], true, true),
            (&v2[..], true, false),
            (&v2[..], false, true),
            (&v1[..40], true, false),
        ] {
            let mut fs = MemZoneFiles::default();
            fs.files.push((
                b"/z".to_vec(),
                MemFile {
                    key: key(1, 1),
                    bytes: bytes.to_vec(),
                    stream,
                },
            ));
            let tm = local(Some(b"/z"), None, fs).localtime(0).unwrap();
            assert_eq!(!tm.zone.is_empty(), want, "{stream} {}", bytes.len());
        }
    }

    /// A zone file whose data passes [`DATA_IN_MEMORY`] is read where it
    /// lies, the same as one held: a version 2 file of 8 million
    /// transitions (72 MiB), every one to the same type but the last.
    #[test]
    #[cfg_attr(miri, ignore = "72 MiB through the interpreter")]
    fn a_long_file_is_read_where_it_lies() {
        let n: u32 = 8 << 20;
        let mut f = Vec::new();
        let header = |f: &mut Vec<u8>, version: u8, times: u32, types: u32, chars: u32| {
            f.extend_from_slice(b"TZif");
            f.push(version);
            f.extend_from_slice(&[0; 15]);
            for c in [0, 0, 0, times, types, chars] {
                f.extend_from_slice(&c.to_be_bytes());
            }
        };
        header(&mut f, b'2', 0, 1, 4);
        f.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        f.extend_from_slice(b"UTC\0");
        header(&mut f, b'2', n, 2, 8);
        for i in 0..n {
            f.extend_from_slice(&(i64::from(i) * 60).to_be_bytes());
        }
        for i in 0..n {
            f.push(u8::from(i == n - 1));
        }
        f.extend_from_slice(&3600i32.to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(&7200i32.to_be_bytes());
        f.extend_from_slice(&[0, 4]);
        f.extend_from_slice(b"AAA\0BBB\0");
        f.extend_from_slice(b"\nCCC-3\n");
        assert!(f.len() as u64 > DATA_IN_MEMORY);
        let mut fs = MemZoneFiles::default();
        fs.put(b"/z", key(1, 1), &f);
        let mut lt = local(Some(b"/z"), None, fs);
        let at = |lt: &mut LocalTime, t: i64| {
            let tm = lt.localtime(t).unwrap();
            (String::from_utf8_lossy(&tm.zone).into_owned(), tm.gmtoff)
        };
        assert_eq!(at(&mut lt, 6_000), ("AAA".into(), 3600));
        assert_eq!(
            at(&mut lt, (i64::from(n) - 1) * 60 - 1),
            ("AAA".into(), 3600)
        );
        assert_eq!(at(&mut lt, i64::from(n) * 60), ("CCC".into(), 10_800));
        assert_eq!(lt.tzname(true), b"CCC");
    }

    /// Nothing the zone keeps holds what the file was read through, which
    /// its opener closes once it is read, as glibc `fclose()`s it: lsof-rs
    /// listed its own `/usr/share/zoneinfo/America/New_York` (fd 3) where
    /// the C lists none (measured). A file read where it lies later is
    /// read through `later`, which holds no descriptor.
    #[test]
    fn the_file_read_through_is_not_kept() {
        struct Watched {
            bytes: Vec<u8>,
            data: Rc<RefCell<Vec<std::rc::Weak<dyn ReadAt>>>>,
        }
        impl ZoneFs for Watched {
            fn stat(&mut self, _: &[u8]) -> Option<FileKey> {
                None
            }
            fn open(&mut self, _: &[u8]) -> Option<ZoneSource> {
                let data: Rc<dyn ReadAt> = Rc::new(self.bytes.clone());
                self.data.borrow_mut().push(Rc::downgrade(&data));
                Some(ZoneSource::Regular {
                    key: FileKey::default(),
                    size: self.bytes.len() as u64,
                    data,
                    later: Rc::new(Vec::new()),
                })
            }
        }
        let opened = Rc::new(RefCell::new(Vec::new()));
        let mut lt = LocalTime::new(
            Box::new(|n| (n == "TZ").then(|| b"/z".to_vec())),
            false,
            Box::new(Watched {
                bytes: include_bytes!("../tests/tzif/new_york").to_vec(),
                data: Rc::clone(&opened),
            }),
        );
        assert_eq!(lt.localtime(0).unwrap().zone, b"EST");
        assert_eq!(opened.borrow().len(), 1);
        assert!(opened.borrow().iter().all(|w| w.upgrade().is_none()));
        assert_eq!(lt.localtime(1_000_000_000).unwrap().zone, b"EDT");
    }

    /// A file's data up to [`DATA_IN_MEMORY`] is copied at the read, as
    /// glibc copies it, and the file is not read again; a longer one is
    /// read where it lies, at each conversion.
    #[test]
    fn short_data_is_held_and_long_data_read_where_it_lies() {
        struct Counted(Vec<u8>, Rc<std::cell::Cell<u32>>);
        impl ReadAt for Counted {
            fn read_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
                self.1.set(self.1.get() + 1);
                self.0.read_at(buf, offset)
            }
        }
        struct One(Vec<u8>, Rc<std::cell::Cell<u32>>);
        impl ZoneFs for One {
            fn stat(&mut self, _: &[u8]) -> Option<FileKey> {
                None
            }
            fn open(&mut self, _: &[u8]) -> Option<ZoneSource> {
                let data: Rc<dyn ReadAt> = Rc::new(Counted(self.0.clone(), Rc::clone(&self.1)));
                Some(ZoneSource::Regular {
                    key: FileKey::default(),
                    size: self.0.len() as u64,
                    data: Rc::clone(&data),
                    later: data,
                })
            }
        }
        let reads = Rc::new(std::cell::Cell::new(0));
        let ny = include_bytes!("../tests/tzif/new_york").to_vec();
        let mut lt = LocalTime::new(
            Box::new(|n| (n == "TZ").then(|| b"/z".to_vec())),
            false,
            Box::new(One(ny, Rc::clone(&reads))),
        );
        lt.localtime(0).unwrap();
        let after_load = reads.get();
        assert!(after_load > 0);
        lt.localtime(1_000_000_000).unwrap();
        assert_eq!(reads.get(), after_load, "held: no read after the load");
        if cfg!(miri) {
            // 64 MiB through the interpreter.
            return;
        }
        // A version 1 file whose data passes the bound: 5 bytes a
        // transition.
        let n = u32::try_from(DATA_IN_MEMORY / 5 + 1).unwrap();
        let mut f = b"TZif\0".to_vec();
        f.extend_from_slice(&[0; 15]);
        for c in [0u32, 0, 0, n, 1, 4] {
            f.extend_from_slice(&c.to_be_bytes());
        }
        f.extend(std::iter::repeat_n(0u8, n as usize * 4));
        f.extend(std::iter::repeat_n(0u8, n as usize));
        f.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        f.extend_from_slice(b"ABC\0");
        let reads = Rc::new(std::cell::Cell::new(0));
        let mut lt = LocalTime::new(
            Box::new(|n| (n == "TZ").then(|| b"/z".to_vec())),
            false,
            Box::new(One(f, Rc::clone(&reads))),
        );
        assert_eq!(lt.localtime(5).unwrap().zone, b"ABC");
        let after_load = reads.get();
        lt.localtime(-5).unwrap();
        assert!(reads.get() > after_load, "read where it lies");
    }

    /// A name with no NUL in `zone_names` runs on into the footer's text,
    /// which follows it in glibc's one allocation (measured: `charcnt` 3,
    /// `ABC`, footer `XYZ5`: before the first change the zone is
    /// `ABCXYZ5`, after it the footer's `XYZ`).
    #[test]
    fn a_name_with_no_nul_runs_into_the_footer() {
        let mut lt = local(Some(b"/craft/runon"), None, zone_files());
        let tm = lt.localtime(-5).unwrap();
        assert_eq!((tm.zone.as_slice(), tm.gmtoff), (&b"ABCXYZ5"[..], -18_000));
        assert_eq!(lt.localtime(5).unwrap().zone, b"XYZ");
    }

    /// `%s` is `mktime()` of the broken-down time, so in an hour a zone
    /// repeats with one `tm_isdst` a new process prints the later time
    /// (measured: Asia/Almaty, 2024-02-29 23:30 +06, t=1709227800, prints
    /// 1709231400).
    #[test]
    fn percent_s_is_mktimes() {
        let mut lt = local(Some(b"Asia/Almaty"), None, zone_files());
        let t = 1_709_227_800;
        let tm = lt.localtime(t).unwrap();
        assert_eq!(tm.gmtoff, 21_600);
        let mut buf = [0u8; 32];
        let n = strftime(&mut buf, b"%s", &tm, &mut lt);
        assert_eq!(&buf[..n], b"1709231400");
    }

    /// `%Z` of a time that names no zone asks `tzset()`, once a call, and
    /// prints `tzname`.
    #[test]
    fn percent_z_of_no_zone_is_tzname() {
        struct Hooks(u32);
        impl TimeHooks for Hooks {
            fn mktime(&mut self, _: &Tm) -> i64 {
                0
            }
            fn tzset(&mut self) {
                self.0 += 1;
            }
            fn tzname(&self, isdst: bool) -> Vec<u8> {
                if isdst {
                    b"D".to_vec()
                } else {
                    b"S".to_vec()
                }
            }
        }
        let mut tm = offtime(0, 0).unwrap();
        let mut h = Hooks(0);
        let mut buf = [0u8; 16];
        let n = strftime(&mut buf, b"%Z%Z", &tm, &mut h);
        assert_eq!((&buf[..n], h.0), (&b"SS"[..], 1));
        tm.zone = b"X".to_vec();
        let n = strftime(&mut buf, b"%Z", &tm, &mut h);
        assert_eq!((&buf[..n], h.0), (&b"X"[..], 1));
    }

    /// Through `std` alone a regular file is read and anything else is no
    /// zone, at once: a FIFO with no writer, a directory, `/dev/zero`.
    #[test]
    #[cfg(unix)]
    #[cfg_attr(miri, ignore = "it makes files and a FIFO")]
    fn std_zone_files_read_regular_files_alone() {
        let dir = std::env::temp_dir().join(format!("lsof-rs-tzif-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ny = include_bytes!("../tests/tzif/new_york");
        std::fs::write(dir.join("ny"), ny).unwrap();
        use std::os::unix::ffi::OsStrExt;
        let path = |p: &std::path::Path| p.as_os_str().as_bytes().to_vec();
        let mut fs = StdZoneFs;
        match fs.open(&path(&dir.join("ny"))) {
            Some(ZoneSource::Regular { size, .. }) => assert_eq!(size, ny.len() as u64),
            other => panic!("{other:?}"),
        }
        assert!(fs.stat(&path(&dir.join("ny"))).is_some());
        assert!(fs.open(&path(&dir.join("nosuch"))).is_none());
        assert!(matches!(
            fs.open(&path(&dir)),
            Some(ZoneSource::Stream { .. })
        ));
        let fifo = dir.join("fifo");
        if std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .is_ok_and(|s| s.success())
        {
            assert!(
                matches!(fs.open(&path(&fifo)), Some(ZoneSource::Stream { ref bytes, .. }) if bytes.is_empty())
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
