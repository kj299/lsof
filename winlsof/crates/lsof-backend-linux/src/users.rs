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
    PASSWD.get_or_init(|| {
        let mut m = HashMap::new();
        let Ok(text) = std::fs::read_to_string("/etc/passwd") else {
            return m;
        };
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
    })
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
