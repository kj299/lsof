//! uid ↔ login name, as FreeBSD's libc gives them: `getpwnam_r(3)` and
//! `getpwuid_r(3)`, through `lsof-getpw`, which follow `nsswitch.conf(5)`
//! through `nsdispatch(3)` (files, NIS, LDAP...) as the C's `getpwnam()` and
//! `getpwuid()` do (DIVERGENCES 39), with the Linux backend's rules around
//! them: a login kept to the C's `LOGINML` bytes, as bytes; an answer that
//! does not fit in `lsof_getpw::CAP` left to the file's reader; a `-u` login
//! asked twice, a second lookup that fails being the C's `Error()`. Not
//! measured against the C on FreeBSD, and not guarded as the Linux backend
//! guards glibc: FreeBSD's `nsdispatch()` is another parser, with no crash
//! measured.
//!
//! Where libc cannot be asked (this module's tests, which build on Linux
//! too, and miri) `/etc/passwd` is read: the seven-field file `pwd_mkdb(8)`
//! writes from `master.passwd`.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// The C's `LOGINML`, `sizeof(((struct utmpx *)0)->ut_user)`, 32 on FreeBSD
/// as on Linux: a login name is kept to this many bytes.
const LOGINML: usize = 32;

/// uid → the first name with it, and name → the first uid with it, from
/// the bytes of a password file.
#[cfg(test)]
fn parse_passwd(text: &[u8]) -> Maps {
    let mut maps = Maps::default();
    for line in text.split(|&b| b == b'\n') {
        add_line(&mut maps, line);
    }
    maps
}

/// One line of the password file into `maps`; a comment or a line with no
/// numeric uid is skipped.
fn add_line((by_uid, by_name): &mut Maps, line: &[u8]) {
    if line.first() == Some(&b'#') {
        return;
    }
    let mut f = line.split(|&b| b == b':');
    let (Some(name), Some(_), Some(uid)) = (f.next(), f.next(), f.next()) else {
        return;
    };
    let Some(uid) = std::str::from_utf8(uid)
        .ok()
        .and_then(|u| u.parse::<u32>().ok())
    else {
        return;
    };
    by_uid.entry(uid).or_insert_with(|| login_name(name));
    by_name.entry(name.to_vec()).or_insert(uid);
}

/// uid → name, and name → uid.
pub type Maps = (HashMap<u32, Box<[u8]>>, HashMap<Vec<u8>, u32>);

/// The password file, read once, within lsof-core's bounds on a line and
/// on a file (`lsof_core::netnames::file_lines`).
fn maps() -> &'static Maps {
    static MAPS: OnceLock<Maps> = OnceLock::new();
    MAPS.get_or_init(|| {
        let mut maps = Maps::default();
        lsof_core::netnames::file_lines(std::path::Path::new("/etc/passwd"), |line| {
            add_line(&mut maps, line);
            false
        });
        maps
    })
}

/// A name as the C keeps it: its first [`LOGINML`] bytes.
fn login_name(name: &[u8]) -> Box<[u8]> {
    name.get(..LOGINML).unwrap_or(name).into()
}

/// What libc answered, as lsof-rs takes it: the account, or none; `None`
/// where the answer would not fit in `lsof_getpw::CAP`, and the file is
/// read instead.
fn libc_answer(answer: lsof_getpw::Answer) -> Option<Option<lsof_getpw::Account>> {
    (!answer.too_large()).then(|| answer.found())
}

/// The login for `uid`, or `None` where the C shows the number: under `-l`,
/// and for a uid no account has.
/// The C keeps each name it found and nothing it did not, so a uid with no
/// name is asked again each time (`printuid()`).
pub fn name_for(uid: u32, numeric: bool) -> Option<Box<[u8]>> {
    if numeric {
        return None;
    }
    static FOUND: OnceLock<Mutex<HashMap<u32, Box<[u8]>>>> = OnceLock::new();
    let mut found = FOUND
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(name) = found.get(&uid) {
        return Some(name.clone());
    }
    let asked = if cfg!(target_os = "freebsd") {
        lsof_getpw::by_uid(uid).and_then(libc_answer)
    } else {
        None
    };
    let name = match asked {
        Some(account) => login_name(&account?.name),
        None => maps().0.get(&uid).cloned()?,
    };
    found.insert(uid, name.clone());
    Some(name)
}

/// libc's uid for the login `name`, asked twice as the C asks it
/// (`arg.c:2030`, `lsof.c:1220`): `None` where it cannot be asked or an
/// answer does not fit in `lsof_getpw::CAP`; `Some(None)` where the first
/// lookup found nothing; [`lsof_core::UserLookup::Lost`] where the second
/// did not find what the first did.
fn asked_by_name(name: &[u8]) -> Option<lsof_core::UserLookup> {
    use lsof_core::UserLookup;
    if !cfg!(target_os = "freebsd") {
        return None;
    }
    let once = || libc_answer(lsof_getpw::by_name(name)?).map(|a| a.map(|a| a.uid));
    if once()?.is_none() {
        return Some(UserLookup::Unknown);
    }
    Some(once()?.map_or(UserLookup::Lost, UserLookup::Uid))
}

/// A `-u` value as the C's `enter_uid()` reads it: digits are a uid, a name
/// is looked up, as bytes, and a name nothing has is fatal.
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
    if let Some(answer) = asked_by_name(value) {
        return answer;
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
            b"# comment\nroot:*:0:0:Charlie &:/root:/bin/sh\ntoor:*:0:0::/root:\nbad\nx:*:y:0::/:\n",
        );
        assert_eq!(u.get(&0).map(|n| &n[..]), Some(&b"root"[..]));
        assert_eq!(
            (n.get(&b"toor"[..]), n.get(&b"x"[..]), u.len()),
            (Some(&0), None, 1)
        );
    }

    /// A login is kept as bytes, to `LOGINML` of them, as the Linux
    /// backend keeps it; an answer past the cap leaves the file to be read.
    #[test]
    fn a_login_is_kept_as_bytes_and_cut_as_the_c_cuts_it() {
        let long = [b'a'; 40];
        let mut text = long.to_vec();
        text.extend_from_slice(b":*:7:7::/:\n\xff\xfe:*:8:8::/:\n");
        let (u, n) = parse_passwd(&text);
        assert_eq!(u.get(&7).map(|n| n.len()), Some(LOGINML));
        assert_eq!(u.get(&8).map(|n| &n[..]), Some(&b"\xff\xfe"[..]));
        assert_eq!(n.get(&b"\xff\xfe"[..]), Some(&8));
        assert_eq!(libc_answer(lsof_getpw::Answer::Failed(34)), None);
        assert_eq!(libc_answer(lsof_getpw::Answer::NotFound), Some(None));
        assert_eq!(lookup(b"0"), lsof_core::UserLookup::Uid(0));
    }
}
