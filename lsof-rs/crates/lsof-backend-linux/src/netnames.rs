//! `-i`'s host and service names, from the files glibc reads them from.
//!
//! The rules are `lsof_core::netnames`'s; this module names the files and
//! keeps what the system's resolver answered, so that a name is asked of it
//! once however many times the C asks (it looks a name up once for IPv6,
//! and again for IPv4).

use std::net::IpAddr;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use lsof_core::netnames::{glibc_host, service_in_file, system_addresses, GlibcFiles};

const HOSTS: &str = "/etc/hosts";
const HOST_CONF: &str = "/etc/host.conf";
const NSSWITCH: &str = "/etc/nsswitch.conf";
const SERVICES: &str = "/etc/services";

/// How many names' answers are kept: a run with more `-i @name` words than
/// this asks again for the earliest.
const KEPT: usize = 64;

/// What the system's resolver said of each name asked.
type Asked = Vec<(String, Vec<IpAddr>)>;

fn asked() -> &'static Mutex<Asked> {
    static ASKED: OnceLock<Mutex<Asked>> = OnceLock::new();
    ASKED.get_or_init(Mutex::default)
}

/// `name` through `getaddrinfo(3)`, once.
fn system(name: &str) -> Vec<IpAddr> {
    let mut kept = asked()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some((_, found)) = kept.iter().find(|(n, _)| n == name) {
        return found.clone();
    }
    let found = system_addresses(name);
    if kept.len() >= KEPT {
        kept.remove(0);
    }
    kept.push((name.to_string(), found.clone()));
    found
}

/// A host name's addresses of one family (`lsof_core::Backend::lookup_host`).
pub fn lookup_host(name: &[u8], v6: bool) -> Vec<IpAddr> {
    use std::os::unix::ffi::OsStrExt;
    let multi = std::env::var_os("RESOLV_MULTI");
    let files = GlibcFiles {
        hosts: Path::new(HOSTS),
        host_conf: Path::new(HOST_CONF),
        nsswitch: Path::new(NSSWITCH),
    };
    glibc_host(
        name,
        v6,
        &files,
        multi.as_deref().map(OsStrExt::as_bytes),
        &mut system,
    )
}

/// A service name's port for a protocol, from `/etc/services`
/// (`lsof_core::Backend::lookup_service`).
pub fn lookup_service(name: &[u8], protocol: &str) -> Option<u16> {
    service_in_file(Path::new(SERVICES), name, protocol.as_bytes())
}
