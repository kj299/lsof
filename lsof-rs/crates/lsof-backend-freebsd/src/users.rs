//! uid ↔ login name, as FreeBSD's libc gives them: `getpwnam_r(3)` and
//! `getpwuid_r(3)`, through `lsof-getpw`, which follow `nsswitch.conf(5)`
//! through `nsdispatch(3)` (files, NIS, LDAP...) as the C's `getpwnam()` and
//! `getpwuid()` do (DIVERGENCES 39). Not measured against the C on FreeBSD,
//! and not guarded as the Linux backend guards glibc: FreeBSD's
//! `nsdispatch()` is another parser, with no crash measured.
//!
//! Where libc cannot be asked (this module's tests, which build on Linux
//! too, and miri) `/etc/passwd` is read: the seven-field file `pwd_mkdb(8)`
//! writes from `master.passwd`.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

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
/// The C keeps each name it found and nothing it did not, so a uid with no
/// name is asked again each time (`printuid()`).
pub fn name_for(uid: u32, numeric: bool) -> Option<String> {
    if numeric {
        return None;
    }
    static FOUND: OnceLock<Mutex<HashMap<u32, String>>> = OnceLock::new();
    let mut found = FOUND
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(name) = found.get(&uid) {
        return Some(name.clone());
    }
    let name = match asked_by_uid(uid) {
        Some(name) => name?,
        None => maps().0.get(&uid).cloned()?,
    };
    found.insert(uid, name.clone());
    Some(name)
}

/// libc's name for `uid`: `None` where it cannot be asked, `Some(None)`
/// where it has none.
fn asked_by_uid(uid: u32) -> Option<Option<String>> {
    if !cfg!(target_os = "freebsd") {
        return None;
    }
    let answer = lsof_getpw::by_uid(uid)?;
    Some(
        answer
            .found()
            .map(|a| String::from_utf8_lossy(&a.name).into_owned()),
    )
}

/// libc's uid for the login `name`, asked twice as the C asks it
/// (`arg.c:2030`, `lsof.c:1220`): `None` where it cannot be asked,
/// `Some(None)` where it has no such account.
fn asked_by_name(name: &str) -> Option<Option<u32>> {
    if !cfg!(target_os = "freebsd") {
        return None;
    }
    let uid = |answer: lsof_getpw::Answer| answer.found().map(|a| a.uid);
    if uid(lsof_getpw::by_name(name.as_bytes())?).is_none() {
        return Some(None);
    }
    Some(lsof_getpw::by_name(name.as_bytes()).and_then(uid))
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
    let uid = match asked_by_name(value) {
        Some(uid) => uid,
        None => maps().1.get(value).copied(),
    };
    match uid {
        Some(uid) => UserLookup::Uid(uid),
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
