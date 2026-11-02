//! uid → account name, without `libc`.
//!
//! `getpwuid` would need a C dependency, so this reads `/etc/passwd` itself,
//! by the rules glibc's `files` service reads it with (`nss_files`, its
//! `LINE_PARSER` for `struct passwd`; [`parse_line`]), which is what
//! `getpwuid(3)` returns where `/etc/nsswitch.conf` says `passwd: files`
//! (DIVERGENCES 70). That misses accounts served only by another NSS source
//! (LDAP, SSSD, systemd-homed: item 39), which is why an unknown uid falls
//! back to its number rather than to an error: lsof's USER column showing
//! `1000` is honest, showing the wrong name would not be.
//!
//! The C keeps each name it found, cut to `LOGINML` (32) bytes, and nothing
//! it did not: a uid with no name is looked up again each time, and under
//! `-r` the names it keeps are dropped when `/etc/passwd`'s mtime or ctime
//! changes (`printuid()`, `print.c:1706-1815`). [`name_for`] and
//! [`new_cycle`] do the same.

use std::collections::HashMap;
use std::io::BufRead;
use std::sync::{Mutex, MutexGuard, OnceLock};

/// The password file, as the C names it.
const PASSWD: &str = "/etc/passwd";

/// The C's `LOGINML`, `sizeof(((struct utmpx *)0)->ut_user)`: a login name
/// is kept to this many bytes (`strncpy(upn->nm, pw->pw_name, LOGINML)`).
pub const LOGINML: usize = 32;

/// What [`name_for`] keeps between calls.
#[derive(Default)]
struct Cache {
    /// The names found, cut to [`LOGINML`]: the C's UID cache.
    found: HashMap<u32, Box<[u8]>>,
    /// The file as read for this cycle, uid → first name, read at the first
    /// uid not in `found`. The C's `getpwuid()` reads the file at every such
    /// call; here once per cycle ([`new_cycle`] forgets it), which is the
    /// same file unless it is written in the instant between two calls.
    snapshot: Option<HashMap<u32, Box<[u8]>>>,
    /// `/etc/passwd`'s mtime and ctime, in seconds (`time_t`), when the
    /// first `-r` cycle `stat`ed it.
    stamp: Option<(i64, i64)>,
}

fn cache() -> MutexGuard<'static, Cache> {
    static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
    CACHE
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Every line of the file at `path`, fed to `each`, as glibc's
/// `__nss_readline()` reads them: up to each `\n`, any length, as bytes.
/// Nothing when it cannot be opened: then no account has a name.
fn each_line(path: &str, mut each: impl FnMut(&[u8])) {
    let Ok(file) = std::fs::File::open(path) else {
        return;
    };
    let mut reader = std::io::BufReader::new(file);
    let mut line = Vec::new();
    loop {
        line.clear();
        match reader.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => each(&line),
        }
    }
}

/// uid → name, the file read now.
fn read_passwd() -> HashMap<u32, Box<[u8]>> {
    let mut m = HashMap::new();
    each_line(PASSWD, |line| add_uid(&mut m, line));
    m
}

fn add_uid(m: &mut HashMap<u32, Box<[u8]>>, line: &[u8]) {
    if let Some((name, uid)) = parse_line(line) {
        m.entry(uid).or_insert_with(|| login_name(name));
    }
}

/// A name as the C keeps it: its first [`LOGINML`] bytes, as bytes, so a
/// cut inside a character keeps the bytes it kept, and USER prints them as
/// `\xNN` ([`lsof_core::RawNames`]). What is a control character is escaped
/// when it is printed, where the C prints it raw (a C-DEFECT: an account's
/// name can drive the terminal of whoever runs lsof; DIVERGENCES 70).
fn login_name(name: &[u8]) -> Box<[u8]> {
    name.get(..LOGINML).unwrap_or(name).into()
}

/// The parsing half of `read_passwd`: uid → first name, from the bytes of
/// a password file. Pure, so the fuzz target can drive it with arbitrary
/// bytes; must never panic. A line [`parse_line`] refuses is skipped.
#[cfg(any(test, feature = "fuzzing"))]
pub fn parse_passwd(text: &[u8]) -> HashMap<u32, Box<[u8]>> {
    let mut m = HashMap::new();
    for line in text.split(|&b| b == b'\n') {
        add_uid(&mut m, line);
    }
    m
}

/// `isspace()` in the C locale.
fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// One line of a password file as glibc's `files` service reads it for
/// `getpwuid()` and `getpwnam()`: its name and uid, or `None` for a line
/// either skips. Measured against the C (its `getpwuid()`, `passwd: files`):
///
/// * the line ends at its `\n`, or at a NUL, as a C string does; blanks before it are
///   skipped, and then an empty line or one opening with `#` is a comment
///   (` #x:x:1:1` too);
/// * the name runs to the first `:`; one opening with `+` or `-` is a NIS
///   `compat` entry, which the `files` lookups skip;
/// * the password is the next field, and then the uid and the gid are each
///   read by `strtoul()` — blanks and a sign before the digits allowed, a
///   minus negating — that must read a digit, end at a `:` or the line's
///   end, and not exceed `UINT32_MAX` (so `-0` is 0, and `-1`, `4294967296`,
///   `4206 ` and `4207x` refuse the line), the gid required (`n:x:1` and
///   `n:x:1:` are refused, `n:x:1:1` is not);
/// * the rest is not looked at.
pub fn parse_line(line: &[u8]) -> Option<(&[u8], u32)> {
    // `LINE_PARSER` ends the line at its `\n`, and the C string at a NUL.
    let line = line
        .split(|&b| b == b'\n' || b == 0)
        .next()
        .unwrap_or_default();
    let start = line.iter().position(|&b| !is_space(b))?;
    let line = &line[start..];
    if line.first() == Some(&b'#') {
        return None;
    }
    // Each field from `at`, as `STRING_FIELD` and `INT_FIELD` take them
    // (`nss_files/files-parse.c`): `at` is left past the `:` that ends it.
    let mut at = 0usize;
    let string_field = |at: &mut usize| {
        let rest = line.get(*at..).unwrap_or_default();
        let len = rest.iter().position(|&b| b == b':').unwrap_or(rest.len());
        let field = &rest[..len];
        *at = at.saturating_add(len);
        if *at < line.len() {
            *at += 1;
        }
        field
    };
    let name = string_field(&mut at);
    if matches!(name.first(), Some(b'+' | b'-')) {
        return None;
    }
    let _password = string_field(&mut at);
    let int_field = |at: &mut usize| -> Option<u32> {
        let rest = line.get(*at..).unwrap_or_default();
        let (value, used) = strtoul(rest);
        if used == 0 {
            return None;
        }
        match rest.get(used) {
            None => {}
            Some(b':') => *at += 1,
            Some(_) => return None,
        }
        *at += used;
        u32::try_from(value).ok()
    };
    let uid = int_field(&mut at)?;
    let _gid = int_field(&mut at)?;
    Some((name, uid))
}

/// `strtoul(s, &end, 10)` on a 64-bit `long`: the value and how many bytes
/// it read, `0` when it read no digit (`end == s`). Blanks first, then a
/// sign, then digits; past `ULONG_MAX` it is `ULONG_MAX`, and a minus
/// negates modulo 2^64.
fn strtoul(s: &[u8]) -> (u64, usize) {
    let mut i = s.iter().take_while(|&&b| is_space(b)).count();
    let negative = match s.get(i) {
        Some(b'-') => {
            i += 1;
            true
        }
        Some(b'+') => {
            i += 1;
            false
        }
        _ => false,
    };
    let digits = s
        .get(i..)
        .unwrap_or_default()
        .iter()
        .take_while(|b| b.is_ascii_digit())
        .count();
    if digits == 0 {
        return (0, 0);
    }
    let mut value = Some(0u64);
    for &d in &s[i..i + digits] {
        value = value
            .and_then(|v| v.checked_mul(10))
            .and_then(|v| v.checked_add(u64::from(d - b'0')));
    }
    let value = match value {
        None => u64::MAX,
        Some(v) if negative => v.wrapping_neg(),
        Some(v) => v,
    };
    (value, i + digits)
}

/// A `-u` value as the C's `enter_uid()` reads it: all digits is a UID as it
/// stands, anything else is a login name looked up in the password file —
/// the first entry with that name, as `getpwnam(3)` returns it, compared as
/// bytes (a login need not be UTF-8; DIVERGENCES 92).
///
/// Two departures, both deliberate:
///
/// * **No wrap-around.** The C accumulates the digits in a `uid_t` and never
///   checks for overflow, so `-u 4294967296` is UID 0 and lists root's
///   processes — measured. Here a number that does not fit is not a UID, is
///   then looked up as a name, and is almost certainly `Unknown` (fatal).
/// * **`/etc/passwd` only.** Without libc there is no `getpwnam`, so an account
///   served only by another NSS source (LDAP, SSSD, systemd-homed) cannot be
///   named here and is reported as unknown; its numeric UID still works. The
///   USER column has the same limit, and shows the number for such an account.
pub fn lookup(value: &[u8]) -> lsof_core::UserLookup {
    use lsof_core::UserLookup;
    if !value.is_empty() && value.iter().all(u8::is_ascii_digit) {
        if let Some(uid) = std::str::from_utf8(value)
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
        {
            return UserLookup::Uid(uid);
        }
    }
    match names_map().get(value) {
        Some(&uid) => UserLookup::Uid(uid),
        None => UserLookup::Unknown,
    }
}

/// name → uid, read once: the `-u` values are all looked up while the
/// options are read. Its own map rather than a search of the uid → name one,
/// which keeps only the first name for each UID and so could not find a
/// second account sharing one.
static NAMES: OnceLock<HashMap<Vec<u8>, u32>> = OnceLock::new();

fn names_map() -> &'static HashMap<Vec<u8>, u32> {
    NAMES.get_or_init(|| {
        let mut m = HashMap::new();
        each_line(PASSWD, |line| add_name(&mut m, line));
        m
    })
}

fn add_name(m: &mut HashMap<Vec<u8>, u32>, line: &[u8]) {
    if let Some((name, uid)) = parse_line(line) {
        m.entry(name.to_vec()).or_insert(uid);
    }
}

/// name → uid, the first line for each name winning, as `getpwnam()` scans.
/// Pure; the same line rules as [`parse_line`], and the whole name.
#[cfg(test)]
pub fn parse_passwd_names(text: &[u8]) -> HashMap<Vec<u8>, u32> {
    let mut m = HashMap::new();
    for line in text.split(|&b| b == b'\n') {
        add_name(&mut m, line);
    }
    m
}

/// The login name for `uid`, or `None` where the C shows the number instead:
/// under `-l` (`numeric`, which skips the lookup), and for a UID no account
/// has. The difference is not cosmetic — the C prints a number right-aligned
/// in eight columns (`printuid()`'s `"%*lu"`) and writes no `-F L` field for
/// it, where it writes one for a name (DIVERGENCES 36).
pub fn name_for(uid: u32, numeric: bool) -> Option<Box<[u8]>> {
    if numeric {
        return None;
    }
    let mut c = cache();
    if let Some(name) = c.found.get(&uid) {
        return Some(name.clone());
    }
    let name = c
        .snapshot
        .get_or_insert_with(read_passwd)
        .get(&uid)?
        .clone();
    c.found.insert(uid, name.clone());
    Some(name)
}

/// What the C does at the first login it prints in each `-r` cycle
/// (`CkPasswd`): `stat` `/etc/passwd`, and drop the names it keeps when its
/// mtime or ctime is not what the first cycle saw. A uid it never found is
/// looked up again anyway. The `stat`'s error is the C's `can't
/// stat(/etc/passwd)`, which ends its run where a login is then looked up
/// (the caller decides that; DIVERGENCES 70).
pub fn new_cycle() -> std::io::Result<()> {
    new_cycle_of(&mut cache(), PASSWD)
}

/// [`new_cycle`] on `c`, for the file at `path`.
fn new_cycle_of(c: &mut Cache, path: &str) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    c.snapshot = None;
    let md = std::fs::metadata(path)?;
    let stamp = (md.mtime(), md.ctime());
    match c.stamp {
        None => c.stamp = Some(stamp),
        Some(seen) if seen != stamp => {
            c.found.clear();
            c.stamp = Some(stamp);
        }
        Some(_) => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_number_is_shown_where_there_is_no_name() {
        // `-l`, and a UID no account has, both leave USER to the number —
        // which the table then prints eight wide and `-F` writes no `L` for.
        assert_eq!(name_for(0, true), None, "-l never looks the name up");
        assert_eq!(name_for(u32::MAX - 1, false), None, "no account has it");
        if let Some(root) = read_passwd().get(&0) {
            assert_eq!(name_for(0, false).as_deref(), Some(&**root));
        }
    }

    #[test]
    fn a_new_cycle_forgets_the_snapshot_and_keeps_found_names() {
        // Without the file changing, a found name is kept; the per-cycle
        // read is dropped either way. Under miri the file is not there.
        let _ = name_for(0, false);
        if new_cycle().is_ok() {
            assert!(cache().snapshot.is_none());
            let before = cache().found.get(&0).cloned();
            assert!(new_cycle().is_ok());
            assert_eq!(cache().found.get(&0).cloned(), before);
        }
        // A changed stamp drops them.
        let mut c = cache();
        c.found.insert(7_777_777, b"x"[..].into());
        c.stamp = Some((-1, -1));
        drop(c);
        if new_cycle().is_ok() {
            assert!(!cache().found.contains_key(&7_777_777));
        }
    }

    #[test]
    fn names_resolve_to_the_first_matching_line_like_getpwnam() {
        let m = parse_passwd_names(b"root:x:0:0:::\ntoor:x:0:0:::\nalice:x:1000:1000:::\nalice:x:1001:1001:::\nbad:x:nope:1:::\n+nis:x:5:5\n");
        assert_eq!(m.get(&b"root"[..]), Some(&0));
        // A second account on the same UID is still found by its name.
        assert_eq!(m.get(&b"toor"[..]), Some(&0));
        // A repeated name keeps its FIRST line, as getpwnam scans.
        assert_eq!(m.get(&b"alice"[..]), Some(&1000));
        assert_eq!(m.get(&b"bad"[..]), None);
        assert_eq!(m.get(&b"+nis"[..]), None);
        assert_eq!(m.len(), 3);
    }

    #[test]
    fn a_numeric_value_is_a_uid_and_never_wraps() {
        use lsof_core::UserLookup;
        assert_eq!(lookup(b"0"), UserLookup::Uid(0));
        assert_eq!(lookup(b"12345"), UserLookup::Uid(12345));
        // The C wraps this to 0 and lists root's processes. It is not a UID,
        // so it is looked up as a name instead — and no account is called that.
        assert_eq!(lookup(b"4294967296"), UserLookup::Unknown);
        assert_eq!(lookup(b""), UserLookup::Unknown);
    }

    #[test]
    fn well_formed_lines_map_uid_to_name() {
        let m = parse_passwd(b"root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534::/nonexistent:/usr/sbin/nologin\n");
        assert_eq!(m.get(&0).map(|n| &**n), Some(&b"root"[..]));
        assert_eq!(m.get(&65534).map(|n| &**n), Some(&b"nobody"[..]));
        assert_eq!(m.len(), 2);
    }

    /// Every line of the measurement (2026-11-02: the C's `getpwuid()` and
    /// `getpwnam()` over a password file bound on `/etc/passwd` in a private
    /// mount namespace, `passwd: files`), and what the C made of it.
    #[test]
    fn lines_are_read_by_glibcs_files_rules() {
        type Case<'a> = (&'a [u8], Option<(&'a [u8], u32)>);
        let cases: &[Case] = &[
            (b"  lead:x:4101:4101::/:/bin/sh", Some((b"lead", 4101))),
            (b"\ttab:x:4113:1::/:/bin/sh", Some((b"tab", 4113))),
            (b"#com:x:4102:4102::/:/bin/sh", None),
            (b" #notcomment:x:4118:1::/:/bin/sh", None),
            (b"+plus:x:4103:4103::/:/bin/sh", None),
            (b"-minus:x:4104:4104::/:/bin/sh", None),
            (b"+", None),
            (b"sp:x: 4105:4105::/:/bin/sh", Some((b"sp", 4105))),
            (b"a5:x:\t4205:1", Some((b"a5", 4205))),
            (b"pl:x:+4106:4106::/:/bin/sh", Some((b"pl", 4106))),
            (b"trail:x:4107x:4107::/:/bin/sh", None),
            (b"a6:x:4206 :1", None),
            (b"nogid:x:4108:", None),
            (b"b3:x:4213", None),
            (b"gidonly:x:4109:4109", Some((b"gidonly", 4109))),
            (b"b4:x:4214:1:", Some((b"b4", 4214))),
            (b"wrap:x:4294971407:1::/:/bin/sh", None),
            (b"neg:x:-4294963185:1::/:/bin/sh", None),
            (b"a1:x:-1:1::/:/bin/sh", None),
            (b"a2:x:4294967295:1::/:/bin/sh", Some((b"a2", u32::MAX))),
            (b"a3:x:4294967296:1::/:/bin/sh", None),
            (b"b5:x:18446744073709551617:1", None),
            (b"b7:x:-0:1", Some((b"b7", 0))),
            (b"a7:x:4207:-1", None),
            (b"a8:x:4208:99999999999", None),
            (b"a9:x:4209:x", None),
            (b"b6:x:4216:+1:g", Some((b"b6", 4216))),
            (b"b8:x:4218: 1", Some((b"b8", 4218))),
            (b"b9:x:4219:1x", None),
            (b"b0:x:00004210:1", Some((b"b0", 4210))),
            (b"b1:x::1", None),
            (b"b2", None),
            (b"hex:x:0x1014:1::/:/bin/sh", None),
            (b"emp::4117:1", Some((b"emp", 4117))),
            (b"crlf:x:4119:1::/:/bin/sh\r", Some((b"crlf", 4119))),
            (b"   ", None),
            (b"", None),
            (b":x:5:5:::", Some((b"", 5))),
            (b"nul:x:7\0:1", None),
            (b"nul:x:7:1\0junk", Some((b"nul", 7))),
            (b"nl:x:9:1\n", Some((b"nl", 9))),
            // strtoul's negation, modulo 2^64.
            (b"m:x:-18446744073709551615:1", Some((b"m", 1))),
        ];
        for (line, want) in cases {
            assert_eq!(
                parse_line(line),
                *want,
                "{:?}",
                String::from_utf8_lossy(line)
            );
        }
    }

    /// The stamp is the file's mtime and ctime: a `chmod` alone, which
    /// changes no byte and no mtime, drops the names kept, as the C's
    /// `CkPasswd` compares both.
    #[test]
    #[cfg_attr(miri, ignore = "sleeps past a ctime second")]
    fn a_new_cycle_forgets_names_when_only_the_ctime_changed() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("lsof-rs-pw-{}", std::process::id()));
        std::fs::write(&path, b"a:x:1:1\n").unwrap();
        let p = path.to_str().unwrap().to_string();
        let mut c = Cache::default();
        new_cycle_of(&mut c, &p).unwrap();
        c.found.insert(1, b"a"[..].into());
        new_cycle_of(&mut c, &p).unwrap();
        assert!(c.found.contains_key(&1), "nothing changed");
        std::thread::sleep(std::time::Duration::from_millis(1100));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        new_cycle_of(&mut c, &p).unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(c.found.is_empty(), "the ctime changed");
        assert!(new_cycle_of(&mut c, "/nonexistent/passwd").is_err());
    }

    /// `strtoul()` skips every `isspace()` byte before the digits, a
    /// carriage return and a form feed among them.
    #[test]
    fn a_uid_after_any_blank_is_read() {
        assert_eq!(parse_line(b"n:x:\r5:1"), Some((&b"n"[..], 5)));
        assert_eq!(parse_line(b"n:x:\x0c\x0b6:\r1"), Some((&b"n"[..], 6)));
        assert_eq!(parse_line(b"n:x:\x085:1"), None, "a backspace is no blank");
    }

    #[test]
    fn a_name_is_kept_to_loginml_bytes() {
        let long = format!("{}:x:4110:4110::/:/bin/sh", "n".repeat(40));
        let m = parse_passwd(long.as_bytes());
        assert_eq!(m.get(&4110).map(|n| &**n), Some("n".repeat(32).as_bytes()));
        // `-u` compares the whole name (a longer one the parse refuses).
        let n = parse_passwd_names(long.as_bytes());
        assert_eq!(n.get("n".repeat(40).as_bytes()), Some(&4110));
    }

    /// The cut is bytes, so one inside a character keeps the bytes it kept
    /// (`L`×31 then the first byte of `é`), which USER prints as `\xc3`;
    /// a lossy decode had made a U+FFFD and widened the column.
    #[test]
    fn a_cut_inside_a_character_keeps_its_bytes() {
        let line = format!("{}é:x:7031:7031::/:/bin/sh", "L".repeat(31));
        let m = parse_passwd(line.as_bytes());
        let mut want = b"L".repeat(31);
        want.push(0xc3);
        assert_eq!(m.get(&7031).map(|n| &**n), Some(&want[..]));
        let line = format!("{}€:x:7032:7032::/:/bin/sh", "L".repeat(30));
        let m = parse_passwd(line.as_bytes());
        let mut want = b"L".repeat(30);
        want.extend_from_slice(&[0xe2, 0x82]);
        assert_eq!(m.get(&7032).map(|n| &**n), Some(&want[..]));
        // Bytes that are not UTF-8 are kept as they are.
        let m = parse_passwd(b"ab\xffcd:x:7033:7033::/:/bin/sh\n");
        assert_eq!(m.get(&7033).map(|n| &**n), Some(&b"ab\xffcd"[..]));
    }

    #[test]
    fn duplicate_uid_keeps_the_first_name_like_getpwuid() {
        let m = parse_passwd(b"first:x:7:7:::\nsecond:x:7:7:::\n");
        assert_eq!(m.get(&7).map(|n| &**n), Some(&b"first"[..]));
        // A line refused does not take the uid from a later one.
        let m = parse_passwd(b"bad:x:8:\ngood:x:8:8\n");
        assert_eq!(m.get(&8).map(|n| &**n), Some(&b"good"[..]));
    }

    #[test]
    fn arbitrary_bytes_do_not_panic() {
        for s in [
            &b""[..],
            b":",
            b"::::::::",
            b"\xff:\xfe:\xfd",
            b"a:b:c:d\r\ne:f:1:",
            b":::0",
            b"-",
            b"x:x:-",
            b"x:x:+",
            b"x:x:   ",
        ] {
            let _ = parse_passwd(s);
        }
        assert_eq!(parse_passwd(b":::0").len(), 0, "uid is the THIRD field");
    }
}
