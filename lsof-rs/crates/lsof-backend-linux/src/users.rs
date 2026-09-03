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
    PASSWD.get_or_init(|| match std::fs::read_to_string("/etc/passwd") {
        Ok(text) => parse_passwd(&text),
        Err(_) => HashMap::new(),
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

/// Resolve `uid` to an account name, or its decimal form when unknown.
/// `numeric` (`-l`) skips the lookup entirely, matching lsof.
pub fn name_for(uid: u32, numeric: bool) -> String {
    if numeric {
        return uid.to_string();
    }
    passwd_map()
        .get(&uid)
        .cloned()
        .unwrap_or_else(|| uid.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

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
