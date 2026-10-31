//! uid ↔ login name, from `/etc/passwd`.
//!
//! The same rule as the Linux backend's, for the same reason: `getpwuid(3)`
//! is libc, and the password file is a file. FreeBSD's `/etc/passwd` is the
//! seven-field file `pwd_mkdb(8)` writes from `master.passwd`; an account
//! served only by NIS or LDAP is not in it, and shows as its number.

use std::collections::HashMap;
use std::sync::OnceLock;

fn passwd_text() -> String {
    std::fs::read("/etc/passwd")
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default()
}

/// uid → the first name with it, and name → the first uid with it.
pub fn parse_passwd(text: &str) -> (HashMap<u32, String>, HashMap<String, u32>) {
    let (mut by_uid, mut by_name) = (HashMap::new(), HashMap::new());
    for line in text.lines() {
        if line.starts_with('#') {
            continue;
        }
        let mut f = line.split(':');
        let (Some(name), Some(_), Some(uid)) = (f.next(), f.next(), f.next()) else {
            continue;
        };
        if let Ok(uid) = uid.parse::<u32>() {
            by_uid.entry(uid).or_insert_with(|| name.to_string());
            by_name.entry(name.to_string()).or_insert(uid);
        }
    }
    (by_uid, by_name)
}

type Maps = (HashMap<u32, String>, HashMap<String, u32>);

fn maps() -> &'static Maps {
    static MAPS: OnceLock<Maps> = OnceLock::new();
    MAPS.get_or_init(|| parse_passwd(&passwd_text()))
}

/// The login for `uid`, or `None` where the C shows the number: under `-l`,
/// and for a uid no account has.
pub fn name_for(uid: u32, numeric: bool) -> Option<String> {
    if numeric {
        return None;
    }
    maps().0.get(&uid).cloned()
}

/// A `-u` value as the C's `enter_uid()` reads it: digits are a uid, a name
/// is looked up, and a name nothing has is fatal.
pub fn lookup(value: &str) -> lsof_core::UserLookup {
    use lsof_core::UserLookup;
    if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) {
        if let Ok(uid) = value.parse::<u32>() {
            return UserLookup::Uid(uid);
        }
    }
    match maps().1.get(value) {
        Some(&uid) => UserLookup::Uid(uid),
        None => UserLookup::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_entry_wins_and_a_bad_line_is_skipped() {
        let (u, n) = parse_passwd(
            "# comment\nroot:*:0:0:Charlie &:/root:/bin/sh\ntoor:*:0:0::/root:\nbad\nx:*:y:0::/:\n",
        );
        assert_eq!(u.get(&0).map(String::as_str), Some("root"));
        assert_eq!((n.get("toor"), n.get("x"), u.len()), (Some(&0), None, 1));
    }
}
