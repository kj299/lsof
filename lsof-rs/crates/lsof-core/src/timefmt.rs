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
//! * [`TzFile`]: a compiled time zone (`TZif`, `time/tzfile.c`);
//! * [`PosixTz`]: a `TZ` rule string (`time/tzset.c`).
//!
//! Everything here is a parser or arithmetic over bytes the user chose (the
//! format, `TZ`, the file `TZ` names): nothing panics, nothing allocates
//! past its input's size, and no loop runs longer than its input.

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

/// The longest zone abbreviation kept: glibc keeps any length; a longer one
/// is cut here, which no zone file and no `TZ` a person writes has.
pub const ZONE_NAME_MAX: usize = 256;

fn peek(s: &[u8], at: usize) -> u8 {
    s.get(at).copied().unwrap_or(0)
}

/// `sscanf("%hu")`: a run of digits as an `unsigned short`, and how many
/// bytes it took; `None` with no digit. Blanks before it are skipped and a
/// sign is read, as `strtoul()` reads them; a value past the type wraps,
/// as glibc stores it.
fn scan_hu(s: &[u8]) -> Option<(u16, usize)> {
    let mut i = s
        .iter()
        .take_while(|&&b| matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r'))
        .count();
    let negative = match peek(s, i) {
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
    let digits = s
        .get(i..)?
        .iter()
        .take_while(|b| b.is_ascii_digit())
        .count();
    if digits == 0 {
        return None;
    }
    let mut value = 0u64;
    for &b in s.get(i..i.saturating_add(digits))? {
        value = value
            .saturating_mul(10)
            .saturating_add(u64::from(b.wrapping_sub(b'0')));
    }
    if negative {
        value = value.wrapping_neg();
    }
    // The low 16 bits, as `%hu` stores them.
    Some(((value & 0xffff) as u16, i.saturating_add(digits)))
}

/// `sscanf("%hu%n:%hu%n:%hu%n")`: up to three numbers between colons, as
/// many as were read, and how many bytes the last one read ended at.
fn scan_hms(s: &[u8]) -> (Vec<u16>, usize) {
    let mut found = Vec::with_capacity(3);
    let mut used = 0usize;
    while found.len() < 3 {
        let rest = s.get(used..).unwrap_or_default();
        let rest = if found.is_empty() {
            rest
        } else if rest.first() == Some(&b':') {
            rest.get(1..).unwrap_or_default()
        } else {
            break;
        };
        let Some((value, took)) = scan_hu(rest) else {
            break;
        };
        used = used
            .saturating_add(usize::from(!found.is_empty()))
            .saturating_add(took);
        found.push(value);
    }
    (found, used)
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

    /// `parse_tzname()`: three letters or more, or `<...>` around three or
    /// more letters, digits and signs.
    fn name(s: &[u8], at: &mut usize) -> Option<Vec<u8>> {
        let rest = s.get(*at..)?;
        let letters = rest.iter().take_while(|b| b.is_ascii_alphabetic()).count();
        let (start, len, end) = if letters >= 3 {
            (0usize, letters, letters)
        } else {
            if rest.first() != Some(&b'<') {
                return None;
            }
            let quoted = rest
                .get(1..)?
                .iter()
                .take_while(|&&b| b.is_ascii_alphanumeric() || b == b'+' || b == b'-')
                .count();
            if peek(rest, quoted.saturating_add(1)) != b'>' || quoted < 3 {
                return None;
            }
            (1, quoted, quoted.saturating_add(2))
        };
        let name = rest.get(start..start.saturating_add(len))?;
        *at = at.saturating_add(end);
        Some(name.get(..name.len().min(ZONE_NAME_MAX))?.to_vec())
    }

    /// `parse_offset()`: `[+-]hh[:mm[:ss]]`, west of UTC unless `-`.
    fn offset(&mut self, s: &[u8], at: &mut usize, which: usize) -> bool {
        let first = peek(s, *at);
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
        let (found, used) = scan_hms(s.get(*at..).unwrap_or_default());
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
    fn rule(&mut self, s: &[u8], at: &mut usize, which: usize) -> bool {
        let Some(rule) = self.rules.get_mut(which) else {
            return false;
        };
        let mut i = *at;
        if peek(s, i) == b',' {
            i = i.saturating_add(1);
        }
        let c = peek(s, i);
        if c == b'J' || c.is_ascii_digit() {
            rule.kind = if c == b'J' { RuleDay::J1 } else { RuleDay::J0 };
            if rule.kind == RuleDay::J1 {
                i = i.saturating_add(1);
                if !peek(s, i).is_ascii_digit() {
                    return false;
                }
            }
            let digits = s
                .get(i..)
                .unwrap_or_default()
                .iter()
                .take_while(|b| b.is_ascii_digit())
                .count();
            let mut d = 0u64;
            for &b in s.get(i..i.saturating_add(digits)).unwrap_or_default() {
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
                    if peek(s, j) != b'.' {
                        return false;
                    }
                    j = j.saturating_add(1);
                }
                let Some((value, took)) = scan_hu(s.get(j..).unwrap_or_default()) else {
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
        match peek(s, i) {
            0 | b',' => rule.secs = 7200,
            b'/' => {
                i = i.saturating_add(1);
                if peek(s, i) == 0 {
                    return false;
                }
                let negative = peek(s, i) == b'-';
                i = i.saturating_add(usize::from(negative));
                let (found, used) = scan_hms(s.get(i..).unwrap_or_default());
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
    pub fn parse(s: &[u8]) -> PosixTz {
        let s = s.split(|&b| b == 0).next().unwrap_or_default();
        let mut tz = PosixTz::default();
        let mut at = 0usize;
        let Some(name) = Self::name(s, &mut at) else {
            return tz;
        };
        if let Some(rule) = tz.rules.first_mut() {
            rule.name = name;
        }
        if !tz.offset(s, &mut at, 0) {
            return tz;
        }
        if peek(s, at) == 0 {
            // No alternative.
            let standard = tz.rules.first().cloned().unwrap_or_default();
            if let Some(rule) = tz.rules.get_mut(1) {
                rule.name = standard.name;
                rule.offset = standard.offset;
            }
            return tz;
        }
        if let Some(name) = Self::name(s, &mut at) {
            if let Some(rule) = tz.rules.get_mut(1) {
                rule.name = name;
            }
            tz.offset(s, &mut at, 1);
        }
        if tz.rule(s, &mut at, 0) {
            tz.rule(s, &mut at, 1);
        }
        tz
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
                // and its table is read past the year's end: the change
                // then falls after the year, in a month of no days.
                let (before, length) = if (1..=12).contains(&rule.m) {
                    let m = usize::from(rule.m);
                    let before = mon_yday(leap, m - 1);
                    (before, mon_yday(leap, m) - before)
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

    /// `__tz_compute()`: the offset, whether it is the alternative, and
    /// the name at second `t`, whose year in UTC is `year`.
    fn at(&self, t: i64, year: i64) -> (i64, bool, &[u8]) {
        let (c0, c1) = (self.change(0, year), self.change(1, year));
        let isdst = if c0 > c1 {
            // South of the equator the alternative ends in the next year.
            t < c1 || t >= c0
        } else {
            t >= c0 && t < c1
        };
        let rule = self.rules.get(usize::from(isdst));
        (
            rule.map_or(0, |r| r.offset),
            isdst,
            rule.map_or(&[][..], |r| r.name.as_slice()),
        )
    }
}

// ------------------------------------------------------------------- TZif

/// The most of a compiled time zone file that is read: thirty times the
/// largest `zic` writes (`right/` zones with every transition to 2037 are
/// under 4 KiB; a file made for a hundred thousand years of rules is no
/// zone). A longer file is no zone file here, where glibc reads any length
/// into memory (DIVERGENCES).
pub const TZIF_MAX_BYTES: u64 = 1 << 20;

/// A zone file's bytes, for [`Zone::from_env`]: the file at `path` read
/// whole if it is a regular file of at most [`TZIF_MAX_BYTES`] (looked at
/// before it is opened and once it is, so a FIFO or a device in its place
/// is never read), and nothing otherwise.
pub fn read_zone_file(path: &std::path::Path) -> Option<Vec<u8>> {
    use std::io::Read;
    if !std::fs::metadata(path).ok()?.is_file() {
        return None;
    }
    let file = std::fs::File::open(path).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(TZIF_MAX_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() as u64 <= TZIF_MAX_BYTES).then_some(bytes)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TtInfo {
    offset: i32,
    isdst: bool,
    idx: u8,
}

/// A compiled time zone, `TZif` (`tzfile(5)`), as glibc's `__tzfile_read()`
/// keeps it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TzFile {
    transitions: Vec<i64>,
    type_idxs: Vec<u8>,
    types: Vec<TtInfo>,
    names: Vec<u8>,
    /// Each leap second's time and the correction from then on.
    leaps: Vec<(i64, i32)>,
    /// The footer: the rules past the last transition.
    spec: Option<PosixTz>,
}

/// Big-endian fields read off the front of a slice, each `None` past its end.
struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(n)?;
        self.0 = rest;
        Some(head)
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }

    fn i64(&mut self) -> Option<i64> {
        Some(i64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }
}

impl TzFile {
    /// The file's bytes as `__tzfile_read()` reads them on a 64-bit
    /// `time_t`: the 64-bit block of a version 2 or 3 file and its footer,
    /// the 32-bit block of a version 1 file. `None` for what glibc refuses
    /// (`goto lose`): another magic or version, counts the file is too
    /// short for, a type past the types, a name past the names.
    pub fn parse(file: &[u8]) -> Option<TzFile> {
        let mut c = Cursor(file);
        let mut wide = false;
        loop {
            let head = c.take(44)?;
            if head.get(..4)? != b"TZif" {
                return None;
            }
            // Any version: glibc 2.39 reads one it does not know (`4`,
            // and `1`, which is none) as it reads version 2.
            let version = *head.get(4)?;
            let mut counts = Cursor(head.get(20..)?);
            let isgmt = usize::try_from(counts.u32()?).ok()?;
            let isstd = usize::try_from(counts.u32()?).ok()?;
            let leaps = usize::try_from(counts.u32()?).ok()?;
            let times = usize::try_from(counts.u32()?).ok()?;
            let types = usize::try_from(counts.u32()?).ok()?;
            let chars = usize::try_from(counts.u32()?).ok()?;
            // No type at all is no zone: glibc reads such a file and then
            // a type that is not there.
            if isstd > types || isgmt > types || (types == 0 && (version == 0 || wide)) {
                return None;
            }
            if version != 0 && !wide {
                // The 32-bit block is passed over for the 64-bit one.
                let skip = times
                    .checked_mul(5)?
                    .checked_add(types.checked_mul(6)?)?
                    .checked_add(chars)?
                    .checked_add(leaps.checked_mul(8)?)?
                    .checked_add(isstd)?
                    .checked_add(isgmt)?;
                c.take(skip)?;
                wide = true;
                continue;
            }
            let width = if wide { 8 } else { 4 };
            // Each count is checked against what is left before anything is
            // kept, so nothing is allocated for a count the file lacks.
            let mut times_raw = Cursor(c.take(times.checked_mul(width)?)?);
            let type_idxs = c.take(times)?.to_vec();
            let mut types_raw = Cursor(c.take(types.checked_mul(6)?)?);
            let names = c.take(chars)?.to_vec();
            let mut leaps_raw = Cursor(c.take(leaps.checked_mul(width.checked_add(4)?)?)?);
            c.take(isstd)?;
            c.take(isgmt)?;
            let mut transitions = Vec::with_capacity(times);
            for _ in 0..times {
                transitions.push(if wide {
                    times_raw.i64()?
                } else {
                    i64::from(times_raw.u32()? as i32)
                });
            }
            if type_idxs.iter().any(|&i| usize::from(i) >= types) {
                return None;
            }
            let mut infos = Vec::with_capacity(types);
            for _ in 0..types {
                let offset = types_raw.u32()? as i32;
                let isdst = *types_raw.take(1)?.first()?;
                let idx = *types_raw.take(1)?.first()?;
                if isdst > 1 || usize::from(idx) > chars {
                    return None;
                }
                infos.push(TtInfo {
                    offset,
                    isdst: isdst == 1,
                    idx,
                });
            }
            let mut leap_list = Vec::with_capacity(leaps);
            for _ in 0..leaps {
                let when = if wide {
                    leaps_raw.i64()?
                } else {
                    i64::from(leaps_raw.u32()? as i32)
                };
                leap_list.push((when, leaps_raw.u32()? as i32));
            }
            // The footer: a newline, the rules, and the file's last byte,
            // whatever that is. A file with less than two bytes there is
            // refused; one whose footer does not open with a newline has
            // no rules (measured).
            let spec = if wide {
                let rest = c.0;
                let text = rest.get(1..rest.len().checked_sub(1).filter(|&n| n >= 1)?)?;
                let text = text.split(|&b| b == 0).next().unwrap_or_default();
                (rest.first() == Some(&b'\n') && !text.is_empty()).then(|| PosixTz::parse(text))
            } else {
                None
            };
            return Some(TzFile {
                transitions,
                type_idxs,
                types: infos,
                names,
                leaps: leap_list,
                spec,
            });
        }
    }

    fn name(&self, idx: u8) -> &[u8] {
        let from = self.names.get(usize::from(idx)..).unwrap_or_default();
        let name = from.split(|&b| b == 0).next().unwrap_or_default();
        name.get(..name.len().min(ZONE_NAME_MAX))
            .unwrap_or_default()
    }

    /// `__tzfile_compute()`: the offset, whether it is the alternative and
    /// the name at second `t`, then the leap seconds' correction and how
    /// many of them `t` is.
    fn at(&self, t: i64) -> Option<(i64, bool, Vec<u8>, i64, i32)> {
        let first = self.transitions.first().copied();
        let last = self.transitions.last().copied();
        let (offset, isdst, name) = if first.is_none_or(|first| t < first) {
            // Before every transition: the first type that is standard
            // time, or the first.
            let i = self.types.iter().position(|ty| !ty.isdst).unwrap_or(0);
            let info = self.types.get(i)?;
            (
                i64::from(info.offset),
                info.isdst,
                self.name(info.idx).to_vec(),
            )
        } else if let (Some(spec), true) = (&self.spec, last.is_some_and(|last| t >= last)) {
            let year = i64::from(offtime(t, 0)?.year) + 1900;
            let (offset, isdst, name) = spec.at(t, year);
            (offset, isdst, name.to_vec())
        } else {
            // The type of the last transition at or before `t`.
            let after = self.transitions.partition_point(|&when| when <= t);
            let idx = *self.type_idxs.get(after.checked_sub(1)?)?;
            let info = self.types.get(usize::from(idx))?;
            (
                i64::from(info.offset),
                info.isdst,
                self.name(info.idx).to_vec(),
            )
        };
        let mut correction = 0i64;
        let mut hit = 0i32;
        if let Some(mut i) = self.leaps.iter().rposition(|&(when, _)| t >= when) {
            let (when, change) = *self.leaps.get(i)?;
            correction = i64::from(change);
            let before = |i: usize| i.checked_sub(1).and_then(|j| self.leaps.get(j)).copied();
            if t == when && change > before(i).map_or(0, |(_, c)| c) {
                hit = 1;
                while let (Some(&(when, change)), Some((earlier, less))) =
                    (self.leaps.get(i), before(i))
                {
                    if earlier.checked_add(1) != Some(when) || less.checked_add(1) != Some(change) {
                        break;
                    }
                    hit = hit.saturating_add(1);
                    i -= 1;
                }
            }
        }
        Some((offset, isdst, name, correction, hit))
    }
}

/// The time zone a run prints its marker in: what `tzset()` settles on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Zone {
    File(Box<TzFile>),
    Rules(PosixTz),
}

/// Where glibc finds zone files, and its default (`TZDIR`, `TZDEFAULT`).
pub const TZDIR: &[u8] = b"/usr/share/zoneinfo";
pub const TZDEFAULT: &[u8] = b"/etc/localtime";

impl Zone {
    /// `tzset_internal()`: the zone `TZ` (`tz`, `None` when it is not set)
    /// names. `read` gives the bytes of the file at a path, `None` where
    /// there is none that is a zone file's size; `tzdir` is `TZDIR` from
    /// the environment; in secure-execution mode (`secure`) only the
    /// default and files under the system's directory are read.
    ///
    /// 1. No `TZ` is `/etc/localtime`; an empty one is `Universal`; a
    ///    leading `:` is dropped.
    /// 2. That is a file, under the zone directory unless it starts with
    ///    `/`: a file glibc accepts is the zone.
    /// 3. Otherwise no `TZ`, an empty one and `/etc/localtime` are UTC, and
    ///    anything else is read as a rule string ([`PosixTz::parse`]).
    ///
    /// One thing glibc does is not done: where the string names an
    /// alternative and no rule (`EST5EDT` with no file of that name) it
    /// reads the changes from the zone directory's `posixrules` file,
    /// moved to the offsets given. The rule it has built in is used
    /// instead, `M3.2.0,M11.1.0`, which is what that file holds where it is
    /// the distribution's link to `America/New_York`, up to the file's last
    /// transition (2037), and what glibc itself uses where there is no such
    /// file (DIVERGENCES).
    pub fn from_env(
        tz: Option<&[u8]>,
        tzdir: Option<&[u8]>,
        secure: bool,
        read: &mut dyn FnMut(&[u8]) -> Option<Vec<u8>>,
    ) -> Zone {
        let tz = tz.map(|tz| tz.split(|&b| b == 0).next().unwrap_or_default());
        let tz: Option<&[u8]> = match tz {
            Some([]) => Some(b"Universal"),
            Some([b':', rest @ ..]) => Some(rest),
            other => other,
        };
        let file = tz.unwrap_or(TZDEFAULT);
        let refused = file.is_empty()
            || (secure
                && tz.is_some()
                && ((file.first() == Some(&b'/')
                    && file != TZDEFAULT
                    && !file.starts_with(TZDIR))
                    || file.windows(3).any(|w| w == b"../")));
        if !refused {
            let path = if file.first() == Some(&b'/') {
                file.to_vec()
            } else {
                let dir = tzdir
                    .filter(|dir| !dir.is_empty() && !secure)
                    .unwrap_or(TZDIR);
                [dir, b"/", file].concat()
            };
            if let Some(zone) = read(&path).and_then(|bytes| TzFile::parse(&bytes)) {
                return Zone::File(Box::new(zone));
            }
        }
        match tz {
            None | Some([]) => Zone::Rules(PosixTz::utc(b"UTC")),
            Some(tz) if tz == TZDEFAULT => Zone::Rules(PosixTz::utc(b"UTC")),
            Some(tz) => Zone::Rules(PosixTz::parse(tz)),
        }
    }

    /// `localtime()`: second `t` in this zone. `None` where the year does
    /// not fit ([`offtime`]).
    pub fn localtime(&self, t: i64) -> Option<Tm> {
        let (offset, isdst, name, correction, hit) = match self {
            Zone::File(file) => file.at(t)?,
            Zone::Rules(rules) => {
                let year = i64::from(offtime(t, 0)?.year) + 1900;
                let (offset, isdst, name) = rules.at(t, year);
                (offset, isdst, name.to_vec(), 0, 0)
            }
        };
        let mut tm = offtime(t, offset.checked_sub(correction)?)?;
        tm.sec = tm.sec.checked_add(hit)?;
        tm.isdst = isdst;
        tm.gmtoff = offset;
        tm.zone = name;
        Some(tm)
    }
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
/// `epoch` is the time `tm` is of, which `%s` prints.
///
/// The format is bytes and ends at its first NUL. Its conversions are
/// glibc's, with the `_`, `-`, `0`, `^` and `#` flags, a field width, and
/// the `E` and `O` modifiers where glibc takes them; anything else is
/// copied as written, from its `%`. Every one was measured, among them:
/// a width pads text with spaces even under `-`; `%z` pads its sign and
/// its digits apart (`%8z` is seven spaces, `-`, `00000400`); `%+…`, a
/// flag of newer C libraries, is none here; `%^q` is `%^Q`.
pub fn strftime(buf: &mut [u8], format: &[u8], tm: &Tm, epoch: i64) -> usize {
    let format = format.split(|&b| b == 0).next().unwrap_or_default();
    let mut out = Out { buf, at: 0 };
    if !format_into(&mut out, format, tm, epoch, SUBFORMAT_DEPTH) {
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

fn format_into(out: &mut Out<'_>, format: &[u8], tm: &Tm, epoch: i64, depth: u8) -> bool {
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
        let year = i64::from(tm.year) + 1900;
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
            // `mktime()` of the time it was broken down from.
            b's' => Is::Owned(epoch.to_string().into_bytes(), Case::Keep),
            b'X' if o => Is::Bad,
            b'X' | b'T' => Is::Sub(b"%H:%M:%S"),
            b'u' => number(1, i64::from((tm.wday - 1 + 7) % 7 + 1)),
            b'U' => unless_e(number(2, i64::from((tm.yday - tm.wday + 7) / 7))),
            b'V' | b'g' | b'G' if e => Is::Bad,
            b'V' | b'g' | b'G' => {
                let (yday, wday) = (i64::from(tm.yday), i64::from(tm.wday));
                let mut iso_year = year;
                let mut days = iso_week_days(yday, wday);
                if days < 0 {
                    // The week belongs to the year before.
                    iso_year -= 1;
                    days = iso_week_days(yday + 365 + i64::from(is_leap(iso_year)), wday);
                } else {
                    let d = iso_week_days(yday - (365 + i64::from(is_leap(iso_year))), wday);
                    if d >= 0 {
                        iso_year += 1;
                        days = d;
                    }
                }
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
            b'y' => number(2, year.rem_euclid(100)),
            b'Z' => Is::Text(&tm.zone, if change_case { Case::Lower } else { case }),
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
                if !format_into(&mut inner, sub, tm, epoch, depth) {
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

/// `-r m<fmt>`'s marker, as `main.c` makes it: a buffer of `(len + 1) * 8
/// + 1` bytes the format is written into at the option and again at each
/// cycle, and printed up to its first NUL.
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
    pub fn new(format: &[u8], zone: &Zone, now: i64) -> Option<Marker> {
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
        (marker.fill(zone, now) > 0).then_some(marker)
    }

    /// `util_strftime(fmtr, fmtl - 1, fmt)`.
    fn fill(&mut self, zone: &Zone, now: i64) -> usize {
        let Some(tm) = zone.localtime(now) else {
            return 0;
        };
        let most = self.buf.len().saturating_sub(1);
        match self.buf.get_mut(..most) {
            Some(buf) => strftime(buf, &self.format, &tm, now),
            None => 0,
        }
    }

    /// The marker at second `now`: the buffer filled again and read up to
    /// its first NUL. Where the result no longer fits (a zone whose name
    /// grew), that is what was written before it stopped fitting and what
    /// the buffer held after it, as in the C; the buffer starts as zeros
    /// here, where the C's is whatever `malloc()` gave it.
    pub fn at(&mut self, zone: &Zone, now: i64) -> &[u8] {
        self.fill(zone, now);
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

    /// Every line of the file `LSOF_TZ_VECTORS` names is one call glibc
    /// answered, made by the helper this module was measured with:
    /// `TZ`, `TZDIR` (or `-`), the second, the buffer's size, the format
    /// in hex, then what `strftime` returned, the buffer up to its NUL in
    /// hex, `tm_gmtoff`, `tm_isdst` and `tm_zone` in hex. With no such
    /// variable there is nothing to compare, and the fixed vectors below
    /// are the test.
    #[test]
    #[cfg_attr(miri, ignore = "reads the host's zone files")]
    fn glibc_vectors_from_a_file() {
        let Some(path) = std::env::var_os("LSOF_TZ_VECTORS") else {
            return;
        };
        let text = std::fs::read_to_string(path).expect("the vectors file");
        let mut read = |path: &[u8]| {
            let path = String::from_utf8_lossy(path).into_owned();
            let meta = std::fs::metadata(&path).ok()?;
            (meta.is_file() && meta.len() <= TZIF_MAX_BYTES)
                .then(|| std::fs::read(&path).ok())
                .flatten()
        };
        let mut zones: std::collections::HashMap<(String, String), Zone> = Default::default();
        let mut bad = Vec::new();
        let mut count = 0usize;
        for line in text.lines() {
            let f: Vec<&str> = line.split('\t').collect();
            let [tz, tzdir, epoch, size, format, ret, out, gmtoff, isdst, zone_name] = f[..] else {
                panic!("a line of ten fields: {line:?}");
            };
            let zone = zones
                .entry((tz.to_string(), tzdir.to_string()))
                .or_insert_with(|| {
                    let tz = (tz != "-").then(|| hex(tz));
                    let tzdir = (tzdir != "-").then(|| hex(tzdir));
                    Zone::from_env(tz.as_deref(), tzdir.as_deref(), false, &mut read)
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
            let Some(tm) = zone.localtime(epoch) else {
                bad.push(format!("{asked}\n   got no time"));
                continue;
            };
            let mut buf = vec![b'#'; size];
            let got = strftime(&mut buf, &hex(format), &tm, epoch);
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
}
