//! The C's `Readlink()` (`lib/misc.c`): how lsof spells a path before it
//! looks at it — a path argument, a `+d`/`+D` directory, a mount's source.
//!
//! It is not `realpath(3)`. Each prefix of the path is read as a symbolic
//! link, in turn, and a link is replaced by its target: an absolute target
//! replaces everything assembled so far, a relative one is appended where the
//! link was. Nothing else changes, and the result is read again until it no
//! longer does. So a relative path stays relative, `.`, `..` and doubled
//! slashes stay where they are, and the text of a link is taken as it reads.
//! lsof-rs had resolved these with `canonicalize()`, and three things users see
//! came out differently (DIVERGENCES 63, 65):
//!
//! * a path names a FILE SYSTEM only when it is spelt as the mount table spells
//!   the mount point: `lsof /dev/shm` does; `lsof shm` from `/dev`, `lsof
//!   /dev/shm/.` and `lsof .` from inside it name the directory alone;
//! * a `/proc/PID/fd/N` link is text: `pipe:[N]` is appended to
//!   `/proc/PID/fd`, which names nothing, so the C reports a status error where
//!   lsof-rs had followed the link to the pipe (and, for an eventfd, to every
//!   `anon_inode` on the host);
//! * `+d`/`+D` name their entries from it: `+D rel` reports `rel/y`, not
//!   `$PWD/rel/y`.
//!
//! The algorithm is [`resolve_with`], over bytes, with the link reader passed
//! in, so it is tested without a file system; [`resolve`] reads real links.

/// `MAXSYMLINKS` as the C is built on Linux: glibc's `<sys/param.h>` defines
/// it as 20, ahead of `lib/misc.c`'s fallback of 32. Measured:
/// `too many (> 20) symbolic links in readlink() path: loop1`.
pub const MAXSYMLINKS: usize = 20;

/// `MAXPATHLEN`. The C assembles into buffers of `MAXPATHLEN + 1` bytes and
/// gives up on a path that would not fit with its terminating NUL.
pub const MAXPATHLEN: usize = 4096;

/// Why [`resolve`] gave up. The C says why and drops the path: a path argument
/// is then no search item, and a `+d`/`+D` ends the run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadlinkError {
    /// A prefix, or the assembled path, does not fit in `MAXPATHLEN` bytes.
    TooLong,
    /// More than [`MAXSYMLINKS`] rereadings changed the path: a loop, or a
    /// chain too long to follow.
    TooManyLinks,
}

impl ReadlinkError {
    /// The C's message, naming `arg` as it was given (`Readlink_op`), which
    /// the caller has escaped. Like every warning, it is muted by `-w`.
    pub fn message(self, arg: &str) -> String {
        match self {
            ReadlinkError::TooLong => format!("readlink() path too long: {arg}"),
            ReadlinkError::TooManyLinks => {
                format!("too many (> {MAXSYMLINKS}) symbolic links in readlink() path: {arg}")
            }
        }
    }
}

/// [`resolve`], with `read_link(prefix)` supplying the target of the symbolic
/// link at `prefix`, or `None` where there is none.
pub fn resolve_with(
    arg: &[u8],
    mut read_link: impl FnMut(&[u8]) -> Option<Vec<u8>>,
) -> Result<Vec<u8>, ReadlinkError> {
    let mut path = arg.to_vec();
    // The C recurses, pushing each new spelling onto a stack it counts
    // (`Readlink_sx`); it refuses the next change once it holds MAXSYMLINKS.
    let mut changes = 0;
    loop {
        let next = one_pass(&path, &mut read_link)?;
        if next == path {
            return Ok(path);
        }
        if changes >= MAXSYMLINKS {
            return Err(ReadlinkError::TooManyLinks);
        }
        changes += 1;
        path = next;
    }
}

/// One reading of `arg`, component by component: the body of the C's loop.
fn one_pass(
    arg: &[u8],
    read_link: &mut impl FnMut(&[u8]) -> Option<Vec<u8>>,
) -> Result<Vec<u8>, ReadlinkError> {
    let mut out: Vec<u8> = Vec::with_capacity(arg.len());
    // A component runs from `start` (its leading `/`, if any) to the next `/`
    // after its first byte, so `//x` is the components `/`, `/x`.
    let mut start = 0;
    while start < arg.len() {
        let end = arg[start + 1..]
            .iter()
            .position(|&b| b == b'/')
            .map_or(arg.len(), |i| start + 1 + i);
        if end > MAXPATHLEN {
            return Err(ReadlinkError::TooLong);
        }
        // The prefix as typed, not as assembled: the kernel resolves the links
        // before it, so this reads the same link.
        let prefix = &arg[..end];
        // The C reads at most `MAXPATHLEN` bytes of a link. Linux never gives
        // more than `PATH_MAX - 1`, so that cut never happens, and a target
        // longer than it could not be read again anyway.
        let target = read_link(prefix);
        let (piece, linked): (&[u8], bool) = match &target {
            // An absolute target replaces everything assembled so far.
            Some(t) if t.first() == Some(&b'/') => {
                out.clone_from(t);
                start = end;
                continue;
            }
            Some(t) => (t, true),
            None => (&arg[start..end], false),
        };
        // A `/` between the assembly and the piece, unless one is there: the
        // piece brings its own, or the assembly ends in one. The first
        // component gets one only when it was a link whose own path started
        // at the root (`/link` -> `rel` is `/rel`).
        let sep = if piece.first() == Some(&b'/') {
            false
        } else if let Some(&last) = out.last() {
            last != b'/'
        } else {
            linked && prefix.first() == Some(&b'/')
        };
        if out.len() + usize::from(sep) + piece.len() >= MAXPATHLEN {
            return Err(ReadlinkError::TooLong);
        }
        if sep {
            out.push(b'/');
        }
        out.extend_from_slice(piece);
        start = end;
    }
    Ok(out)
}

/// `arg` as the C's `Readlink()` spells it, reading the host's links.
#[cfg(unix)]
pub fn resolve(arg: &std::ffi::OsStr) -> Result<std::ffi::OsString, ReadlinkError> {
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    resolve_with(arg.as_bytes(), |prefix| {
        std::fs::read_link(std::ffi::OsStr::from_bytes(prefix))
            .ok()
            .map(|t| t.into_os_string().into_vec())
    })
    .map(std::ffi::OsString::from_vec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Resolve `arg` against a table of links: prefix -> target.
    fn with(links: &[(&str, &[u8])], arg: &[u8]) -> Result<Vec<u8>, ReadlinkError> {
        let table: HashMap<Vec<u8>, Vec<u8>> = links
            .iter()
            .map(|(k, v)| (k.as_bytes().to_vec(), v.to_vec()))
            .collect();
        resolve_with(arg, |p| table.get(p).cloned())
    }

    fn ok(links: &[(&str, &[u8])], arg: &str) -> String {
        String::from_utf8(with(links, arg.as_bytes()).unwrap()).unwrap()
    }

    #[test]
    fn a_path_with_no_link_is_left_exactly_as_typed() {
        for p in [
            "shm",
            "./shm",
            "shm/.",
            "shm/",
            "rel//",
            ".",
            "/",
            "//",
            "/dev//shm",
            "//dev/shm",
            "/dev/./shm",
            "/dev/shm/.",
            "a/../b",
            "",
        ] {
            assert_eq!(ok(&[], p), p, "{p:?}");
        }
    }

    #[test]
    fn a_relative_link_is_replaced_where_it_stands() {
        // Measured against the C: `+d rel-link` reports `rel/y`, `+d
        // deep/a/b/up` reports `deep/a/b/../../../rel/y`.
        assert_eq!(ok(&[("rel-link", b"rel")], "rel-link"), "rel");
        assert_eq!(ok(&[("rel-link", b"rel")], "rel-link/x"), "rel/x");
        assert_eq!(
            ok(&[("deep/a/b/up", b"../../../rel")], "deep/a/b/up"),
            "deep/a/b/../../../rel"
        );
        // A trailing slash survives: the prefix `rel-link/` is no link (the
        // kernel says EINVAL), so its `/` is appended to the target.
        assert_eq!(ok(&[("rel-link", b"rel")], "rel-link/"), "rel/");
    }

    #[test]
    fn an_absolute_link_replaces_the_assembly() {
        assert_eq!(ok(&[("/x/link", b"/real")], "/x/link/y"), "/real/y");
        assert_eq!(ok(&[("/b/shmlink", b"/dev/shm")], "/b/shmlink"), "/dev/shm");
        // A link to `/` followed by a component keeps its doubled slash, and
        // is stable when read again.
        assert_eq!(ok(&[("/x/root", b"/")], "/x/root/y"), "//y");
        assert_eq!(ok(&[], "//y"), "//y");
    }

    #[test]
    fn a_relative_link_after_an_assembly_ending_in_a_slash_gets_none() {
        // `/x/root` -> `/` leaves the assembly `/`; the link after it, `l` ->
        // `rel`, is appended without a second `/`.
        let links: &[(&str, &[u8])] = &[("/x/root", b"/"), ("/x/root/l", b"rel")];
        assert_eq!(ok(links, "/x/root/l"), "/rel");
    }

    #[test]
    fn a_relative_link_at_the_root_gets_its_slash() {
        // `/link` -> `rel` is `/rel`: the first component was a link whose
        // path began at `/`.
        assert_eq!(ok(&[("/link", b"rel")], "/link"), "/rel");
        // ...and a relative path's first link stays relative.
        assert_eq!(ok(&[("link", b"rel")], "link"), "rel");
    }

    #[test]
    fn a_magic_link_is_read_as_text() {
        // `/proc/913/fd/5 -> pipe:[3518]`: the C stats
        // `/proc/913/fd/pipe:[3518]`, which does not exist.
        assert_eq!(
            ok(&[("/proc/913/fd/5", b"pipe:[3518]")], "/proc/913/fd/5"),
            "/proc/913/fd/pipe:[3518]"
        );
        assert_eq!(
            ok(
                &[("/proc/913/fd/8", b"/b/gone (deleted)")],
                "/proc/913/fd/8"
            ),
            "/b/gone (deleted)"
        );
    }

    #[test]
    fn links_are_followed_until_nothing_changes() {
        // a -> b -> c, each in the assembled path.
        let links: &[(&str, &[u8])] = &[("a", b"b"), ("b", b"c")];
        assert_eq!(ok(links, "a/f"), "c/f");
    }

    #[test]
    fn twenty_changes_are_allowed_and_the_twenty_first_is_refused() {
        // l0 -> l1 -> ... -> lN: N changes, then a reading that changes
        // nothing.
        let chain = |n: usize| -> Vec<(String, Vec<u8>)> {
            (0..n)
                .map(|i| (format!("l{i}"), format!("l{}", i + 1).into_bytes()))
                .collect()
        };
        let run = |n: usize| {
            let table: HashMap<Vec<u8>, Vec<u8>> = chain(n)
                .into_iter()
                .map(|(k, v)| (k.into_bytes(), v))
                .collect();
            resolve_with(b"l0", |p| table.get(p).cloned())
        };
        assert_eq!(run(20), Ok(b"l20".to_vec()));
        assert_eq!(run(21), Err(ReadlinkError::TooManyLinks));
        // A loop never settles.
        let loop_: &[(&str, &[u8])] = &[("loop1", b"loop2"), ("loop2", b"loop1")];
        assert_eq!(with(loop_, b"loop1"), Err(ReadlinkError::TooManyLinks));
        // A link to itself reads back unchanged: no error here; the `stat`
        // that follows reports the loop.
        assert_eq!(ok(&[("self", b"self")], "self"), "self");
    }

    #[test]
    fn a_path_that_cannot_fit_is_refused() {
        // `alen + llen + slen >= sizeof(abuf)`: an assembly of MAXPATHLEN - 1
        // bytes fits, one of MAXPATHLEN does not.
        let fits = "a/".repeat(MAXPATHLEN / 2 - 1) + "f";
        assert_eq!(fits.len(), MAXPATHLEN - 1);
        assert_eq!(with(&[], fits.as_bytes()).unwrap(), fits.as_bytes());
        let full = fits + "f";
        assert_eq!(with(&[], full.as_bytes()), Err(ReadlinkError::TooLong));
        // A component that ends past MAXPATHLEN is refused before its link is
        // read (`len >= sizeof(tbuf)`).
        let long = "a".repeat(MAXPATHLEN + 1);
        let mut asked = false;
        let r = resolve_with(long.as_bytes(), |_| {
            asked = true;
            None
        });
        assert_eq!(r, Err(ReadlinkError::TooLong));
        assert!(!asked);
    }

    #[test]
    fn the_limit_holds_for_what_a_link_assembles() {
        // `/l` -> a relative target of n bytes assembles `/` + target.
        let at = |n: usize, arg: &[u8]| {
            let table: HashMap<Vec<u8>, Vec<u8>> = HashMap::from([(b"/l".to_vec(), vec![b't'; n])]);
            resolve_with(arg, |p| table.get(p).cloned())
        };
        assert_eq!(at(MAXPATHLEN - 2, b"/l").unwrap().len(), MAXPATHLEN - 1);
        assert_eq!(at(MAXPATHLEN - 1, b"/l"), Err(ReadlinkError::TooLong));
        // A component after it can push it over.
        assert_eq!(at(MAXPATHLEN - 3, b"/l/x"), Err(ReadlinkError::TooLong));
        assert!(at(MAXPATHLEN - 4, b"/l/x").is_ok());
    }

    #[test]
    fn bytes_that_are_not_utf8_pass_through() {
        assert_eq!(
            with(&[("nulink", b"nu/\xff")], b"nulink").unwrap(),
            b"nu/\xff"
        );
        assert_eq!(with(&[], b"nu/\xfe").unwrap(), b"nu/\xfe");
    }

    #[test]
    fn a_target_too_long_to_read_again_is_refused() {
        // Never seen from a real link, which Linux keeps under PATH_MAX: an
        // absolute target that long cannot be read again.
        let mut target = vec![b't'; MAXPATHLEN + 10];
        target[0] = b'/';
        let mut longest = 0;
        let r = resolve_with(b"/l", |p| {
            longest = longest.max(p.len());
            (p == b"/l").then(|| target.clone())
        });
        assert_eq!(r, Err(ReadlinkError::TooLong));
        assert!(longest <= MAXPATHLEN, "read a {longest}-byte prefix");
    }

    #[test]
    fn the_messages_are_the_cs() {
        assert_eq!(
            ReadlinkError::TooManyLinks.message("loop1"),
            "too many (> 20) symbolic links in readlink() path: loop1"
        );
        assert_eq!(
            ReadlinkError::TooLong.message("a/b"),
            "readlink() path too long: a/b"
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolve_reads_the_hosts_links() {
        use std::os::unix::ffi::OsStrExt;
        let dir = std::env::temp_dir().join(format!("lsof-rs-readlink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("rel")).unwrap();
        std::os::unix::fs::symlink("rel", dir.join("rel-link")).unwrap();
        std::os::unix::fs::symlink("l2", dir.join("l1")).unwrap();
        std::os::unix::fs::symlink("l1", dir.join("l2")).unwrap();
        let base = dir.as_os_str().as_bytes().to_vec();
        let p = |s: &str| {
            let mut v = base.clone();
            v.extend_from_slice(s.as_bytes());
            std::ffi::OsString::from(std::str::from_utf8(&v).unwrap())
        };
        let got = resolve(&p("/rel-link/x")).unwrap();
        assert_eq!(got, p("/rel/x"));
        assert_eq!(resolve(&p("/l1")), Err(ReadlinkError::TooManyLinks));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
