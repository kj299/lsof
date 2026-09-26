//! uid → account name, without `libc`.
//!
//! `getpwuid` would need a C dependency, so this parses `/etc/passwd` directly
//! and caches the map for the process lifetime. That misses accounts served
//! only by NSS (LDAP, SSSD, systemd-homed), which is why an unknown uid falls
//! back to its number rather than to an error: lsof's USER column showing `1000`
//! is honest, showing the wrong name would not be.

use std::collections::HashMap;
use std::sync::OnceLock;

static PASSWD: OnceLock<HashMap<u32, String>> = OnceLock::new();

fn passwd_map() -> &'static HashMap<u32, String> {
    PASSWD.get_or_init(|| match crate::text::read_lossy("/etc/passwd") {
        Some(text) => parse_passwd(&text),
        None => HashMap::new(),
    })
}

/// The parsing half of [`passwd_map`]: uid → first name seen, from the text of
/// `/etc/passwd`. Pure, so the fuzz target can drive it with arbitrary bytes;
/// must never panic. A line without three `:`-separated fields, or whose third
/// field is not a number, is skipped — the file is only as well-formed as its
/// last editor left it.
pub fn parse_passwd(text: &str) -> HashMap<u32, String> {
    let mut m = HashMap::new();
    for line in text.lines() {
        // name:passwd:uid:gid:gecos:home:shell — we want fields 0 and 2.
        let mut f = line.split(':');
        let (Some(name), Some(_), Some(uid)) = (f.next(), f.next(), f.next()) else {
            continue;
        };
        if let Ok(uid) = uid.parse::<u32>() {
            m.entry(uid).or_insert_with(|| name.to_string());
        }
    }
    m
}

/// A `-u` value as the C's `enter_uid()` reads it: all digits is a UID as it
/// stands, anything else is a login name looked up in the password file —
/// the first entry with that name, as `getpwnam(3)` returns it.
///
/// Two departures, both deliberate:
///
/// * **No wrap-around.** The C accumulates the digits in a `uid_t` and never
///   checks for overflow, so `-u 4294967296` is UID 0 and lists root's
///   processes — measured. Here a number that does not fit is not a UID, is
///   then looked up as a name, and is almost certainly `Unknown` (fatal).
/// * **`/etc/passwd` only.** Without libc there is no `getpwnam`, so an account
///   served only by NSS (LDAP, SSSD, systemd-homed) cannot be named here and
///   is reported as unknown; its numeric UID still works. The USER column has
///   the same limit, and shows the number for such an account.
pub fn lookup(value: &str) -> lsof_core::UserLookup {
    use lsof_core::UserLookup;
    if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) {
        if let Ok(uid) = value.parse::<u32>() {
            return UserLookup::Uid(uid);
        }
    }
    match names_map().get(value) {
        Some(&uid) => UserLookup::Uid(uid),
        None => UserLookup::Unknown,
    }
}

/// name → uid, read once. Its own map rather than a search of [`PASSWD`]
/// (uid → name), which keeps only the first name for each UID and so could
/// not find a second account sharing one.
static NAMES: OnceLock<HashMap<String, u32>> = OnceLock::new();

fn names_map() -> &'static HashMap<String, u32> {
    NAMES.get_or_init(|| match crate::text::read_lossy("/etc/passwd") {
        Some(text) => parse_passwd_names(&text),
        None => HashMap::new(),
    })
}

/// name → uid, the first line for each name winning, as `getpwnam()` scans.
/// Pure; the same malformed-line rules as [`parse_passwd`].
pub fn parse_passwd_names(text: &str) -> HashMap<String, u32> {
    let mut m = HashMap::new();
    for line in text.lines() {
        let mut f = line.split(':');
        let (Some(name), Some(_), Some(uid)) = (f.next(), f.next(), f.next()) else {
            continue;
        };
        if let Ok(uid) = uid.parse::<u32>() {
            m.entry(name.to_string()).or_insert(uid);
        }
    }
    m
}

/// The login name for `uid`, or `None` where the C shows the number instead:
/// under `-l` (`numeric`, which skips the lookup), and for a UID no account
/// has. The difference is not cosmetic — the C prints a number right-aligned
/// in eight columns (`printuid()`'s `"%*lu"`) and writes no `-F L` field for
/// it, where it writes one for a name (DIVERGENCES 36).
pub fn name_for(uid: u32, numeric: bool) -> Option<String> {
    if numeric {
        return None;
    }
    passwd_map().get(&uid).cloned()
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
        if let Some(root) = passwd_map().get(&0) {
            assert_eq!(name_for(0, false).as_deref(), Some(root.as_str()));
        }
    }

    #[test]
    fn names_resolve_to_the_first_matching_line_like_getpwnam() {
        let m = parse_passwd_names("root:x:0:0:::\ntoor:x:0:0:::\nalice:x:1000:1000:::\nalice:x:1001:1001:::\nbad:x:nope:1:::\n");
        assert_eq!(m.get("root"), Some(&0));
        // A second account on the same UID is still found by its name.
        assert_eq!(m.get("toor"), Some(&0));
        // A repeated name keeps its FIRST line, as getpwnam scans.
        assert_eq!(m.get("alice"), Some(&1000));
        assert_eq!(m.get("bad"), None);
        assert_eq!(m.len(), 3);
    }

    #[test]
    fn a_numeric_value_is_a_uid_and_never_wraps() {
        use lsof_core::UserLookup;
        assert_eq!(lookup("0"), UserLookup::Uid(0));
        assert_eq!(lookup("12345"), UserLookup::Uid(12345));
        // The C wraps this to 0 and lists root's processes. It is not a UID,
        // so it is looked up as a name instead — and no account is called that.
        assert_eq!(lookup("4294967296"), UserLookup::Unknown);
        assert_eq!(lookup(""), UserLookup::Unknown);
    }

    #[test]
    fn well_formed_lines_map_uid_to_name() {
        let m = parse_passwd("root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534::/nonexistent:/usr/sbin/nologin\n");
        assert_eq!(m.get(&0).map(String::as_str), Some("root"));
        assert_eq!(m.get(&65534).map(String::as_str), Some("nobody"));
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn malformed_lines_are_skipped_never_guessed() {
        // A truncated line, a non-numeric uid, a uid that overflows u32, a
        // blank line, a comment — /etc/passwd is only as well-formed as its
        // last editor left it, and none of these may panic or invent an entry.
        let m = parse_passwd("truncated:x\nalice:x:notanumber:1:::\nbob:x:99999999999:1:::\n\n# comment\ncarol:x:1001:1001:::\n");
        assert_eq!(m.len(), 1);
        assert_eq!(m.get(&1001).map(String::as_str), Some("carol"));
    }

    #[test]
    fn duplicate_uid_keeps_the_first_name_like_getpwuid() {
        let m = parse_passwd("first:x:7:7:::\nsecond:x:7:7:::\n");
        assert_eq!(m.get(&7).map(String::as_str), Some("first"));
    }

    #[test]
    fn empty_name_is_legal_and_kept() {
        // `:x:5:` has an empty first field; the map records it rather than
        // dropping the uid, so the USER column shows "" and not the number —
        // the file said so.
        let m = parse_passwd(":x:5:5:::\n");
        assert_eq!(m.get(&5).map(String::as_str), Some(""));
    }

    #[test]
    fn arbitrary_text_does_not_panic() {
        for s in [
            "",
            ":",
            "::::::::",
            "\u{FFFD}:\u{FFFD}:\u{FFFD}",
            "a:b:c:d\r\ne:f:1:",
            ":::0",
        ] {
            let _ = parse_passwd(s);
        }
        assert_eq!(parse_passwd(":::0").len(), 0, "uid is the THIRD field");
    }
}
