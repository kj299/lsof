//! `-i`'s host and service names, from the files glibc reads them from.
//!
//! The rules are `lsof_core::netnames`'s; this module names the files and
//! keeps what the system's resolver answered, so that a name is asked of it
//! once however many times the C asks (it looks a name up once for IPv6,
//! and again for IPv4).

use std::ffi::OsString;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use lsof_core::netnames::{glibc_host, glibc_service, system_addresses, GlibcFiles};

const HOSTS: &str = "/etc/hosts";
const HOST_CONF: &str = "/etc/host.conf";
const NSSWITCH: &str = "/etc/nsswitch.conf";
const SERVICES: &str = "/etc/services";

/// The process's auxiliary vector, which says whether it runs in
/// secure-execution mode.
const AUXV: &str = "/proc/self/auxv";

/// `AT_SECURE` (`<elf.h>`).
const AT_SECURE: usize = 23;

/// How many names' answers are kept: a run with more `-i @name` words than
/// this asks again for the earliest.
const KEPT: usize = 64;

/// What the system's resolver said of each name asked, at most [`KEPT`] of
/// them.
#[derive(Default)]
struct Asked {
    kept: Vec<(String, Vec<IpAddr>)>,
}

impl Asked {
    /// `name`'s addresses: what `resolver` said of it the first time it
    /// was asked, and it is asked now if that is not kept.
    fn ask(&mut self, name: &str, resolver: &mut dyn FnMut(&str) -> Vec<IpAddr>) -> Vec<IpAddr> {
        if let Some((_, found)) = self.kept.iter().find(|(n, _)| n == name) {
            return found.clone();
        }
        let found = resolver(name);
        if self.kept.len() >= KEPT {
            self.kept.remove(0);
        }
        self.kept.push((name.to_string(), found.clone()));
        found
    }
}

fn asked() -> &'static Mutex<Asked> {
    static ASKED: OnceLock<Mutex<Asked>> = OnceLock::new();
    ASKED.get_or_init(Mutex::default)
}

/// The files glibc's `getaddrinfo(3)` reads before it answers, whatever
/// the name: its sources, the hosts file, the resolver's two, and the
/// order of the addresses.
const GETADDRINFO_READS: [&str; 5] = [
    NSSWITCH,
    HOSTS,
    HOST_CONF,
    "/etc/resolv.conf",
    "/etc/gai.conf",
];

/// `name` through `getaddrinfo(3)`, once; unless one of the files glibc
/// reads for it (`reads`) would hold it there, a FIFO or a device in its
/// place: then the name is not asked, and has no address. The C is held
/// (measured: `/etc/hosts`, `/etc/host.conf` or `/etc/nsswitch.conf` as a
/// FIFO, and it never returns), which lsof-rs can avoid for its own reading
/// and, by looking first, for the C library's.
fn system_unless_held(name: &str, reads: &[&Path]) -> Vec<IpAddr> {
    if reads
        .iter()
        .any(|path| lsof_core::netnames::would_hold_a_reader(path))
    {
        return Vec::new();
    }
    asked()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .ask(name, &mut system_addresses)
}

/// Whether the auxiliary vector `auxv` (the bytes of `/proc/self/auxv`:
/// pairs of native words, a type and its value) says the process runs in
/// secure-execution mode, `AT_SECURE` not zero: set-user-ID, set-group-ID
/// or with file capabilities. A vector that does not say (none could be
/// read, or it has no such entry) is taken as saying it does.
fn at_secure(auxv: &[u8]) -> bool {
    const WORD: usize = std::mem::size_of::<usize>();
    let word = |bytes: &[u8]| <[u8; WORD]>::try_from(bytes).map(usize::from_ne_bytes).ok();
    for entry in auxv.chunks_exact(WORD.saturating_mul(2)) {
        let (kind, value) = entry.split_at(WORD);
        if word(kind) == Some(AT_SECURE) {
            return word(value) != Some(0);
        }
    }
    true
}

/// The file `multi` is read from, as glibc's `_res_hconf_init()` names it:
/// `RESOLV_HOST_CONF` from the environment (`env`) if it is set, whatever
/// it holds, and `/etc/host.conf` if not. In secure-execution mode
/// (`secure`) the variable is not looked at: there glibc's loader takes it
/// out of the environment before the program starts (measured with a
/// set-user-ID copy of the C; `RESOLV_MULTI` it leaves, and so does
/// lsof-rs).
fn host_conf_path(env: Option<OsString>, secure: bool) -> PathBuf {
    match env {
        Some(path) if !secure => PathBuf::from(path),
        _ => PathBuf::from(HOST_CONF),
    }
}

/// A host name's addresses of one family (`lsof_core::Backend::lookup_host`).
pub fn lookup_host(name: &[u8], v6: bool) -> Vec<IpAddr> {
    use std::os::unix::ffi::OsStrExt;
    let multi = std::env::var_os("RESOLV_MULTI");
    let host_conf = match std::env::var_os("RESOLV_HOST_CONF") {
        None => PathBuf::from(HOST_CONF),
        env => {
            let auxv = lsof_core::netnames::small_file(Path::new(AUXV), 1 << 16);
            host_conf_path(env, at_secure(&auxv))
        }
    };
    let files = GlibcFiles {
        hosts: Path::new(HOSTS),
        host_conf: &host_conf,
        nsswitch: Path::new(NSSWITCH),
    };
    let mut reads: Vec<&Path> = GETADDRINFO_READS.iter().map(Path::new).collect();
    reads.push(&host_conf);
    glibc_host(
        name,
        v6,
        &files,
        multi.as_deref().map(OsStrExt::as_bytes),
        &mut |name| system_unless_held(name, &reads),
    )
}

/// A service name's port for a protocol, from `/etc/services` where
/// `/etc/nsswitch.conf` has glibc read it
/// (`lsof_core::Backend::lookup_service`).
pub fn lookup_service(name: &[u8], protocol: &str) -> Option<u16> {
    glibc_service(
        name,
        protocol.as_bytes(),
        Path::new(SERVICES),
        Path::new(NSSWITCH),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u32) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::from(n))
    }

    /// The resolver is asked once a name, however often the name is looked
    /// up (the C asks twice, once a family), and the answers kept are
    /// bounded.
    #[test]
    fn the_resolver_is_asked_once_for_each_name() {
        let mut asked = Asked::default();
        let mut calls: Vec<String> = Vec::new();
        let mut resolver = |name: &str| {
            calls.push(name.to_string());
            vec![ip(u32::try_from(name.len()).unwrap())]
        };
        assert_eq!(asked.ask("one", &mut resolver), [ip(3)]);
        assert_eq!(asked.ask("one", &mut resolver), [ip(3)]);
        assert_eq!(asked.ask("three", &mut resolver), [ip(5)]);
        assert_eq!(asked.ask("one", &mut resolver), [ip(3)]);
        assert_eq!(asked.ask("three", &mut resolver), [ip(5)]);
        // A name with no address is kept as that.
        let mut nothing = |_: &str| Vec::new();
        assert_eq!(asked.ask("", &mut nothing), Vec::<IpAddr>::new());
        assert_eq!(asked.ask("", &mut resolver), Vec::<IpAddr>::new());
        assert_eq!(calls, ["one", "three"]);
        // Past the bound the earliest is forgotten, and asked again.
        assert_eq!(KEPT, 64);
        let mut asked = Asked::default();
        let mut count = 0u32;
        let mut resolver = |_: &str| {
            count += 1;
            vec![ip(count)]
        };
        for i in 0..KEPT {
            asked.ask(&format!("n{i}"), &mut resolver);
        }
        assert_eq!(asked.kept.len(), KEPT);
        assert_eq!(asked.ask("n0", &mut resolver), [ip(1)]);
        assert_eq!(asked.ask("more", &mut resolver), [ip(65)]);
        assert_eq!(asked.kept.len(), KEPT);
        assert_eq!(asked.ask("n1", &mut resolver), [ip(2)]);
        assert_eq!(asked.ask("n0", &mut resolver), [ip(66)]);
        assert_eq!(asked.kept.len(), KEPT);
        for i in 0..if cfg!(miri) { 80 } else { 1000 } {
            asked.ask(&format!("m{i}"), &mut resolver);
        }
        assert_eq!(asked.kept.len(), KEPT);
    }

    /// `AT_SECURE` in an auxiliary vector, and what stands for one that
    /// does not say.
    #[test]
    fn secure_execution_is_read_from_the_auxiliary_vector() {
        let vector = |entries: &[(usize, usize)]| {
            let mut bytes = Vec::new();
            for (kind, value) in entries {
                bytes.extend_from_slice(&kind.to_ne_bytes());
                bytes.extend_from_slice(&value.to_ne_bytes());
            }
            bytes
        };
        assert!(!at_secure(&vector(&[(6, 4096), (23, 0), (0, 0)])));
        assert!(at_secure(&vector(&[(6, 4096), (23, 1), (0, 0)])));
        assert!(at_secure(&vector(&[(23, 1 << 20)])));
        // The first entry of the type decides, and a value of 23 is no
        // type.
        assert!(!at_secure(&vector(&[(23, 0), (23, 1)])));
        assert!(at_secure(&vector(&[(6, 23), (0, 0)])));
        // No such entry, no vector, or a cut one: secure.
        assert!(at_secure(&vector(&[(6, 4096), (0, 0)])));
        assert!(at_secure(b""));
        let cut = vector(&[(23, 0)]);
        assert!(at_secure(&cut[..cut.len() - 1]));
        // A vector read at an offset is not one.
        let mut shifted = vec![0u8];
        shifted.extend(vector(&[(23, 0)]));
        assert!(at_secure(&shifted));
    }

    /// `RESOLV_HOST_CONF` names the file `multi` is read from, but in
    /// secure-execution mode (measured with a set-user-ID copy of the C).
    #[test]
    fn host_conf_is_named_as_glibc_names_it() {
        let env = |path: &str| Some(OsString::from(path));
        assert_eq!(host_conf_path(None, false), Path::new("/etc/host.conf"));
        assert_eq!(host_conf_path(None, true), Path::new("/etc/host.conf"));
        assert_eq!(host_conf_path(env("/x/hc"), false), Path::new("/x/hc"));
        assert_eq!(
            host_conf_path(env("/x/hc"), true),
            Path::new("/etc/host.conf")
        );
        // Set and empty is a file that is not there.
        assert_eq!(host_conf_path(env(""), false), Path::new(""));
    }

    /// This process's own vector is there to read and says it is not
    /// secure (tests do not run set-user-ID); miri has no `/proc`.
    #[test]
    #[cfg_attr(miri, ignore = "it reads /proc/self/auxv")]
    fn this_process_is_not_in_secure_execution_mode() {
        let auxv = lsof_core::netnames::small_file(Path::new(AUXV), 1 << 16);
        assert!(!auxv.is_empty());
        assert!(!at_secure(&auxv));
    }

    /// A FIFO or a device where glibc reads a file would hold it, so the
    /// name is not handed to it: nothing is asked, at once. (The resolver
    /// here would be asked for a name that is none, which `std` refuses
    /// without a query.)
    #[test]
    #[cfg_attr(miri, ignore = "it makes a FIFO and reads /dev")]
    fn the_resolver_is_not_asked_past_a_file_that_would_hold_it() {
        use lsof_core::netnames::would_hold_a_reader;
        let dir = std::env::temp_dir().join(format!("lsof-rs-held-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (fifo, file) = (dir.join("fifo"), dir.join("file"));
        rustix::fs::mknodat(
            rustix::fs::CWD,
            fifo.to_str().unwrap(),
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        std::fs::write(&file, "x").unwrap();
        assert!(would_hold_a_reader(&fifo));
        assert!(would_hold_a_reader(Path::new("/dev/zero")));
        assert!(!would_hold_a_reader(&file));
        assert!(!would_hold_a_reader(&dir));
        assert!(!would_hold_a_reader(&dir.join("nosuch")));
        // lsof-rs's own readers do not open it either: were one to, it
        // would wait for the writer that comes in a second, and no longer.
        let writer = {
            let fifo = fifo.clone();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(1));
                let _ = rustix::fs::open(
                    fifo.to_str().unwrap(),
                    rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::NONBLOCK,
                    rustix::fs::Mode::empty(),
                );
            })
        };
        let started = std::time::Instant::now();
        assert!(!lsof_core::netnames::file_lines(&fifo, |_| false));
        assert_eq!(
            lsof_core::netnames::nsswitch_conf(&fifo),
            lsof_core::netnames::Conf::Unreadable
        );
        assert_eq!(lsof_core::netnames::small_file(&fifo, 100), b"");
        assert!(started.elapsed() < std::time::Duration::from_millis(700));
        writer.join().unwrap();
        // Held: no answer, and none kept as one.
        let name = "\0 lsof-rs: no name";
        let started = std::time::Instant::now();
        assert_eq!(
            system_unless_held(name, &[&file, &fifo]),
            Vec::<IpAddr>::new()
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        let kept = |name: &str| asked().lock().unwrap().kept.iter().any(|(n, _)| n == name);
        assert!(!kept(name));
        // Not held: asked, and the answer kept.
        assert_eq!(
            system_unless_held(name, &[&file, &dir]),
            Vec::<IpAddr>::new()
        );
        assert!(kept(name));
        // The files looked at are glibc's, all of them.
        assert_eq!(
            GETADDRINFO_READS,
            [
                "/etc/nsswitch.conf",
                "/etc/hosts",
                "/etc/host.conf",
                "/etc/resolv.conf",
                "/etc/gai.conf"
            ]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
