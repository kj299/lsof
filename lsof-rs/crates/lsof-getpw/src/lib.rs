//! An account by name or by uid, from the C library: `getpwnam_r(3)` and
//! `getpwuid_r(3)`.
//!
//! The C lsof asks `getpwnam()` for each `-u` login (`src/arg.c:2030`, and
//! again in `lsof_select_login()`, `lib/lsof.c:1220`) and `getpwuid()` for
//! each owner it prints by name (`printuid()`, `src/print.c:1788`). glibc
//! answers both by walking `/etc/nsswitch.conf`'s `passwd:` sources, which
//! it loads as shared objects (`libnss_files`, `libnss_sss`, `libnss_ldap`,
//! `libnss_systemd`, `libnss_hesiod`...); FreeBSD's libc by `nsdispatch(3)`.
//! An account only such a source serves has no name for a program that
//! reads `/etc/passwd` itself, which is what lsof-rs did until 2026-11-20
//! (DIVERGENCES 39). This crate is the one boundary through which it asks
//! the C library instead, kept out of `lsof-core`, `lsof-cli` and
//! `lsof-backend-linux`, which stay `#![forbid(unsafe_code)]`.
//!
//! The reentrant forms, not the C's: lsof-rs has threads (its `-S` and name
//! helpers), and `getpwnam()`'s static result is shared by all of them. The
//! answer is the same: glibc's `getpwnam()` is `getpwnam_r()` into a buffer
//! it grows on `ERANGE` until the entry fits (`nss/getXXbyYY.c`), and so is
//! [`by_name`], to [`CAP`] bytes.
//!
//! # What a caller must check first
//!
//! glibc 2.39 reads past the end of a heap block when a database it walks
//! for the lookup has an empty list of sources: nsswitch.conf's `passwd:`
//! line listing none, or opening with an action (`passwd: [NOTFOUND=return]
//! files`), and, under `passwd: compat` with a `+@group` or `-@group` line
//! in the password file, such a `netgroup:` line (`compat` asks
//! `innetgr()`). Valgrind reports the invalid reads in `__nss_lookup()`
//! (`nss/nsswitch.c:73,82`), and the C's survival is the heap's luck. Under
//! `passwd: compat` with `passwd_compat: compat`, and a `+` line in the
//! password file, glibc's `compat` source asks itself until the stack is
//! gone (SIGSEGV, the C's exit 139, measured). None of it is anything this
//! crate can see, so its caller reads nsswitch.conf first and does not ask
//! where it could hold any of them (`lsof-backend-linux`'s `users.rs`).
//!
//! # Safety
//!
//! Three `unsafe` sites, each with a `SAFETY` comment: the zeroed `struct
//! passwd` the call fills, and the two calls. Each call is given a buffer
//! this crate owns and the length it has (a byte buffer, which a `passwd`'s
//! strings need no alignment of), a `passwd` it owns, and a result pointer
//! it owns, and nothing of what the C library wrote is read through
//! a pointer: the uid is a field of the `passwd`, read only where the result
//! pointer points at it, and the name is found in the buffer by its offset
//! and read as a slice of it (`name_at`), so a source that points
//! anywhere else gives no name rather than a read of memory this crate does
//! not own. Everything but the calls is safe code, and is tested under miri
//! too (`read_call`, `ask_growing`).
#![deny(unsafe_op_in_unsafe_fn)]

/// The buffer the first call is given: glibc's `NSS_BUFLEN_PASSWD`, what
/// its `sysconf(_SC_GETPW_R_SIZE_MAX)` returns (1024, measured), and what
/// its own `getpwnam()` starts with.
pub const START: usize = 1024;

/// The largest buffer asked with, 16 MiB: past it the answer is `ERANGE`
/// ([`Answer::too_large`]). glibc's `getpwnam()` has no bound and grows its
/// buffer until `malloc()` fails, for an entry from any source, a remote one
/// included; here a source cannot make lsof-rs hold more than this. Sixteen
/// times the longest password-file line lsof-rs's own reader takes
/// (`lsof_core::netnames::LINE_LIMIT`, 1 MiB), so every line that reader
/// takes, glibc takes here too.
pub const CAP: usize = 1 << 24;

/// One account, as far as lsof reads one: its name, as bytes, and its uid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    /// `pw_name`, without its NUL. Empty for a lookup by name, which reads
    /// the uid alone, as the C does.
    pub name: Vec<u8>,
    /// `pw_uid`.
    pub uid: u32,
}

/// What the C library answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    /// The account.
    Found(Account),
    /// No account: the call returned 0 and no entry.
    NotFound,
    /// The call failed with this error number: `ERANGE` at [`CAP`], or what
    /// a source reported (`EINVAL` where glibc refuses nsswitch.conf,
    /// `EIO`, `ENOMEM`, ...). The C's `getpwnam()` returns NULL for each,
    /// which is how lsof takes it; it is kept apart for the tests.
    Failed(i32),
}

impl Answer {
    /// The account, where there is one.
    pub fn found(self) -> Option<Account> {
        match self {
            Answer::Found(account) => Some(account),
            Answer::NotFound | Answer::Failed(_) => None,
        }
    }

    /// Whether the entry did not fit in [`CAP`] bytes: `ERANGE` from the
    /// last call. glibc's `files` source fails every lookup so, not only
    /// that entry's, once a line of the file is longer than the buffer
    /// (measured: a 20 MB line first, and root is not found).
    pub fn too_large(&self) -> bool {
        *self == Answer::Failed(ERANGE)
    }
}

/// What one call into the C library gave, for [`ask_growing`].
#[cfg_attr(
    not(all(any(target_os = "linux", target_os = "freebsd"), not(miri))),
    allow(dead_code)
)]
#[derive(Debug, PartialEq, Eq)]
enum Step {
    /// Done: this is the answer.
    Done(Answer),
    /// `ERANGE`: the buffer was too small for the entry.
    TooSmall,
}

/// The loop glibc's `getpwnam()` runs around `getpwnam_r()`: `call` with a
/// zeroed buffer of [`START`] bytes, then twice that while it says the
/// buffer is too small, up to [`CAP`]; past that, `ERANGE`. Each buffer is
/// dropped before the next is made, so at most one is held.
#[cfg_attr(
    not(all(any(target_os = "linux", target_os = "freebsd"), not(miri))),
    allow(dead_code)
)]
fn ask_growing(start: usize, cap: usize, mut call: impl FnMut(&mut [u8]) -> Step) -> Answer {
    let mut size = start.clamp(1, cap.max(1));
    loop {
        let mut buf = vec![0u8; size];
        match call(&mut buf) {
            Step::Done(answer) => return answer,
            Step::TooSmall if size < cap => size = size.saturating_mul(2).min(cap),
            Step::TooSmall => return Answer::Failed(ERANGE),
        }
    }
}

/// `ERANGE`, which is 34 on Linux and FreeBSD alike (and is only a number
/// in [`Answer::Failed`] elsewhere).
#[cfg_attr(
    not(all(any(target_os = "linux", target_os = "freebsd"), not(miri))),
    allow(dead_code)
)]
const ERANGE: i32 = 34;

/// The bytes of the C string at address `at`, read from `buf`, where the C
/// library wrote it: from `at` to the first NUL. `None` where `at` is not
/// inside `buf` (a null pointer, or a source that put the string elsewhere)
/// or no NUL ends it there.
#[cfg_attr(
    not(all(any(target_os = "linux", target_os = "freebsd"), not(miri))),
    allow(dead_code)
)]
fn name_at(buf: &[u8], at: usize) -> Option<&[u8]> {
    let offset = at.checked_sub(buf.as_ptr() as usize)?;
    let rest = buf.get(offset..)?;
    let len = rest.iter().position(|&b| b == 0)?;
    rest.get(..len)
}

/// The name as the C library is given it: a C string ends at its first NUL,
/// so the bytes after one are not asked (an argv word, which `-u` values
/// are, cannot hold one).
fn c_name(name: &[u8]) -> std::ffi::CString {
    let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    let cut = name.get(..end).unwrap_or_default();
    // No NUL is left in `cut`, so this cannot fail; an empty name is what
    // it would be if it did.
    std::ffi::CString::new(cut).unwrap_or_default()
}

/// What one call left, read ([`read_call`]).
#[cfg_attr(
    not(all(any(target_os = "linux", target_os = "freebsd"), not(miri))),
    allow(dead_code)
)]
#[derive(Debug, PartialEq, Eq)]
enum Got {
    /// An entry: its uid, and its name where it is in the buffer.
    Entry { uid: u32, name: Option<Vec<u8>> },
    /// No entry.
    None,
    /// An error other than `ERANGE`.
    Error(i32),
}

/// One call's return code `rc` and, where the result pointer pointed at
/// the `passwd` given, that entry's `pw_uid` and `pw_name` address, read
/// against `buf`: [`Step::TooSmall`] for `ERANGE`. A result pointer that is
/// null, or points anywhere else, is no entry (nothing is read through it).
#[cfg_attr(
    not(all(any(target_os = "linux", target_os = "freebsd"), not(miri))),
    allow(dead_code)
)]
fn read_call(rc: i32, entry: Option<(u32, usize)>, buf: &[u8]) -> Result<Got, Step> {
    match (rc, entry) {
        (ERANGE, _) => Err(Step::TooSmall),
        (0, Some((uid, name))) => Ok(Got::Entry {
            uid,
            name: name_at(buf, name).map(<[u8]>::to_vec),
        }),
        (0, None) => Ok(Got::None),
        (e, _) => Ok(Got::Error(e)),
    }
}

/// [`by_name`]'s answer from one call: the uid alone, as the C reads it.
#[cfg_attr(
    not(all(any(target_os = "linux", target_os = "freebsd"), not(miri))),
    allow(dead_code)
)]
fn uid_answer(got: Result<Got, Step>) -> Step {
    match got {
        Ok(Got::Entry { uid, .. }) => Step::Done(Answer::Found(Account {
            name: Vec::new(),
            uid,
        })),
        Ok(Got::None) => Step::Done(Answer::NotFound),
        Ok(Got::Error(e)) => Step::Done(Answer::Failed(e)),
        Err(step) => step,
    }
}

/// [`by_uid`]'s answer from one call: the name too, and no entry where it
/// is not in the buffer.
#[cfg_attr(
    not(all(any(target_os = "linux", target_os = "freebsd"), not(miri))),
    allow(dead_code)
)]
fn name_answer(got: Result<Got, Step>) -> Step {
    match got {
        Ok(Got::Entry {
            uid,
            name: Some(name),
        }) => Step::Done(Answer::Found(Account { name, uid })),
        Ok(Got::Entry { name: None, .. } | Got::None) => Step::Done(Answer::NotFound),
        Ok(Got::Error(e)) => Step::Done(Answer::Failed(e)),
        Err(step) => step,
    }
}

/// The account named `name` (its uid), as `getpwnam(3)` finds it; `None`
/// where nothing can be asked: off Linux and FreeBSD, and under miri.
pub fn by_name(name: &[u8]) -> Option<Answer> {
    #[cfg(all(any(target_os = "linux", target_os = "freebsd"), not(miri)))]
    {
        let name = c_name(name);
        Some(ask_growing(START, CAP, |buf| {
            uid_answer(sys::getpwnam_into(&name, buf))
        }))
    }
    #[cfg(not(all(any(target_os = "linux", target_os = "freebsd"), not(miri))))]
    {
        let _ = c_name(name);
        None
    }
}

/// The account whose uid is `uid` (its name), as `getpwuid(3)` finds it;
/// `None` where nothing can be asked: off Linux and FreeBSD, and under
/// miri. An entry whose name is not in the buffer given (see `name_at`)
/// is not found.
pub fn by_uid(uid: u32) -> Option<Answer> {
    #[cfg(all(any(target_os = "linux", target_os = "freebsd"), not(miri)))]
    {
        Some(ask_growing(START, CAP, |buf| {
            name_answer(sys::getpwuid_into(uid, buf))
        }))
    }
    #[cfg(not(all(any(target_os = "linux", target_os = "freebsd"), not(miri))))]
    {
        let _ = uid;
        None
    }
}

#[cfg(all(any(target_os = "linux", target_os = "freebsd"), not(miri)))]
mod sys {
    /// One `getpwnam_r()` of `name` into `buf`, read ([`call`]).
    pub(crate) fn getpwnam_into(
        name: &std::ffi::CStr,
        buf: &mut [u8],
    ) -> Result<super::Got, super::Step> {
        call(buf, |pwd, buf, result| {
            // getpwnam_r() is MT-Safe (glibc's manual: `MT-Safe locale`;
            // FreeBSD's getpwent(3)) and writes nowhere of ours but the three
            // it is given. A `struct passwd` holds strings alone, no array of
            // pointers (as `struct group`'s `gr_mem` is), so the C library
            // writes only bytes into `buf` and needs no alignment of it.
            // SAFETY: `name` is NUL-terminated and outlives the call; `pwd`
            // and `result` are `call`'s own, valid for a write of a `passwd`
            // and of a pointer; `buf` is valid for writes of `buf.len()`
            // bytes, the length given, at any alignment (above).
            unsafe {
                libc::getpwnam_r(
                    name.as_ptr(),
                    pwd,
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    result,
                )
            }
        })
    }

    /// One `getpwuid_r()` of `uid` into `buf`, read ([`call`]).
    pub(crate) fn getpwuid_into(uid: u32, buf: &mut [u8]) -> Result<super::Got, super::Step> {
        call(buf, |pwd, buf, result| {
            // SAFETY: as in `getpwnam_into`: `pwd`, `result` and `buf` are
            // `call`'s own and valid for the writes the call makes, `buf` for
            // the `buf.len()` bytes it is told of, with no alignment needed
            // (a `passwd` holds no array of pointers); `uid` is a value.
            unsafe { libc::getpwuid_r(uid, pwd, buf.as_mut_ptr().cast(), buf.len(), result) }
        })
    }

    /// One call, `call(pwd, buf, result)`, with a `passwd` and a result
    /// pointer of its own, read by [`super::read_call`]: the entry's two
    /// fields are read from the `passwd` itself, where the result pointer
    /// points at it, and nothing is read through a pointer.
    fn call(
        buf: &mut [u8],
        call: impl FnOnce(*mut libc::passwd, &mut [u8], *mut *mut libc::passwd) -> libc::c_int,
    ) -> Result<super::Got, super::Step> {
        // SAFETY: `libc::passwd` is a C struct of pointers and integers
        // (and, on FreeBSD, a `time_t` and an int), for which all-zero bytes
        // are a valid value: null pointers and zeros. It is an
        // out-parameter only.
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let rc = call(&mut pwd, buf, &mut result);
        let entry =
            (result == std::ptr::addr_of_mut!(pwd)).then_some((pwd.pw_uid, pwd.pw_name as usize));
        super::read_call(rc, entry, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_buffer_doubles_from_start_while_it_is_too_small() {
        let mut sizes = Vec::new();
        let answer = ask_growing(START, CAP, |buf| {
            sizes.push(buf.len());
            assert!(buf.iter().all(|&b| b == 0), "each buffer starts zeroed");
            if buf.len() < 5000 {
                Step::TooSmall
            } else {
                Step::Done(Answer::NotFound)
            }
        });
        assert_eq!(answer, Answer::NotFound);
        assert_eq!(sizes, [1024, 2048, 4096, 8192]);
    }

    #[test]
    fn the_buffer_stops_at_the_cap_with_erange() {
        let mut sizes = Vec::new();
        let answer = ask_growing(START, CAP, |buf| {
            sizes.push(buf.len());
            Step::TooSmall
        });
        assert_eq!(answer, Answer::Failed(ERANGE));
        // 1 KiB to 16 MiB: fifteen calls, the last at the cap itself.
        assert_eq!(sizes.len(), 15);
        assert_eq!(sizes.first(), Some(&1024));
        assert_eq!(sizes.last(), Some(&(16 << 20)));
        assert_eq!((START, CAP), (1024, 16 << 20));
        #[cfg(any(target_os = "linux", target_os = "freebsd"))]
        assert_eq!(ERANGE, libc::ERANGE);
    }

    #[test]
    fn a_cap_that_is_no_power_of_two_is_asked_with_itself() {
        let mut sizes = Vec::new();
        let answer = ask_growing(3, 10, |buf| {
            sizes.push(buf.len());
            Step::TooSmall
        });
        assert_eq!(answer, Answer::Failed(34));
        assert_eq!(sizes, [3, 6, 10]);
        // A start past the cap is the cap; a zero start is one byte.
        let mut first = 0;
        ask_growing(99, 10, |buf| {
            first = buf.len();
            Step::Done(Answer::NotFound)
        });
        assert_eq!(first, 10);
        ask_growing(0, 10, |buf| {
            first = buf.len();
            Step::Done(Answer::NotFound)
        });
        assert_eq!(first, 1);
    }

    #[test]
    fn a_failure_or_an_answer_ends_the_loop_at_once() {
        let mut calls = 0;
        let answer = ask_growing(START, CAP, |_| {
            calls += 1;
            Step::Done(Answer::Failed(5))
        });
        assert_eq!((answer, calls), (Answer::Failed(5), 1));
        assert_eq!(Answer::Failed(5).found(), None);
        assert!(Answer::Failed(ERANGE).too_large());
        assert!(!Answer::Failed(5).too_large() && !Answer::NotFound.too_large());
        assert_eq!(Answer::NotFound.found(), None);
        let a = Account {
            name: b"x".to_vec(),
            uid: 7,
        };
        assert_eq!(Answer::Found(a.clone()).found(), Some(a));
    }

    #[test]
    fn a_name_is_read_from_the_buffer_alone() {
        let buf = *b"xx\0root\0tail";
        let base = buf.as_ptr() as usize;
        assert_eq!(name_at(&buf, base + 3), Some(&b"root"[..]));
        assert_eq!(name_at(&buf, base), Some(&b"xx"[..]));
        assert_eq!(name_at(&buf, base + 2), Some(&b""[..]));
        // No NUL after it in the buffer: no name.
        assert_eq!(name_at(&buf, base + 8), None);
        // Outside the buffer, before or after it, or null: no name.
        assert_eq!(name_at(&buf, base - 1), None);
        assert_eq!(name_at(&buf, base + buf.len()), None);
        assert_eq!(name_at(&buf, 0), None);
    }

    #[test]
    fn a_call_is_read_by_its_code_and_its_entry_alone() {
        let buf = *b"root\0x";
        let at = buf.as_ptr() as usize;
        assert_eq!(read_call(ERANGE, None, &buf), Err(Step::TooSmall));
        assert_eq!(read_call(ERANGE, Some((0, at)), &buf), Err(Step::TooSmall));
        assert_eq!(read_call(0, None, &buf), Ok(Got::None));
        assert_eq!(read_call(5, None, &buf), Ok(Got::Error(5)));
        assert_eq!(read_call(22, Some((0, at)), &buf), Ok(Got::Error(22)));
        assert_eq!(
            read_call(0, Some((7, at)), &buf),
            Ok(Got::Entry {
                uid: 7,
                name: Some(b"root".to_vec())
            })
        );
        assert_eq!(
            read_call(0, Some((7, 0)), &buf),
            Ok(Got::Entry { uid: 7, name: None })
        );
    }

    #[test]
    fn by_name_takes_the_uid_and_by_uid_the_name_too() {
        let entry = |name: Option<&[u8]>| {
            Ok(Got::Entry {
                uid: 7,
                name: name.map(<[u8]>::to_vec),
            })
        };
        let found = |name: &[u8]| {
            Step::Done(Answer::Found(Account {
                name: name.to_vec(),
                uid: 7,
            }))
        };
        assert_eq!(uid_answer(entry(Some(b"x"))), found(b""));
        assert_eq!(uid_answer(entry(None)), found(b""));
        assert_eq!(name_answer(entry(Some(b"x"))), found(b"x"));
        assert_eq!(name_answer(entry(None)), Step::Done(Answer::NotFound));
        for read in [uid_answer, name_answer] {
            assert_eq!(read(Ok(Got::None)), Step::Done(Answer::NotFound));
            assert_eq!(read(Ok(Got::Error(5))), Step::Done(Answer::Failed(5)));
            assert_eq!(read(Err(Step::TooSmall)), Step::TooSmall);
        }
    }

    #[test]
    fn a_name_is_asked_up_to_its_first_nul() {
        assert_eq!(c_name(b"root").as_bytes(), b"root");
        assert_eq!(c_name(b"root\0junk").as_bytes(), b"root");
        assert_eq!(c_name(b"\0root").as_bytes(), b"");
        assert_eq!(c_name(b"").as_bytes(), b"");
        assert_eq!(
            c_name("j\u{f6}hn".as_bytes()).as_bytes(),
            "j\u{f6}hn".as_bytes()
        );
    }

    /// Whatever the host's password database holds, root is uid 0 in it
    /// (every CI runner's and this host's `files`), and nothing is named
    /// by a name no system has. Under miri nothing is asked.
    #[test]
    fn the_c_library_is_asked_where_it_can_be() {
        let asks = cfg!(all(
            any(target_os = "linux", target_os = "freebsd"),
            not(miri)
        ));
        let root = by_name(b"root");
        let zero = by_uid(0);
        let none = by_name(b"lsof-rs-no-such-account-\x01");
        if !asks {
            assert_eq!((root, zero, none), (None, None, None));
            return;
        }
        assert_eq!(root.and_then(Answer::found).map(|a| a.uid), Some(0));
        assert_eq!(
            by_name(b"root\0junk")
                .and_then(Answer::found)
                .map(|a| a.uid),
            Some(0)
        );
        assert_eq!(
            zero.and_then(Answer::found).map(|a| a.name),
            Some(b"root".to_vec())
        );
        assert_eq!(none, Some(Answer::NotFound));
        assert_eq!(by_uid(u32::MAX - 7), Some(Answer::NotFound));
    }

    /// The C library is told the true length of the buffer it is given:
    /// a 4-byte slice of a 64-byte one is too small for root's entry, which
    /// the 64 bytes would hold, and the C library says `ERANGE` and leaves
    /// every byte past the 4 as it was. A length told too long would have it
    /// write root's entry into them.
    #[test]
    #[cfg(all(any(target_os = "linux", target_os = "freebsd"), not(miri)))]
    fn the_c_library_writes_only_inside_the_length_it_is_told() {
        let mut big = [0xa5u8; 64];
        let got = sys::getpwuid_into(0, &mut big[..4]);
        assert_eq!(got, Err(Step::TooSmall));
        assert!(big[4..].iter().all(|&b| b == 0xa5), "{big:?}");
        let mut big = [0xa5u8; 64];
        let root = std::ffi::CString::new("root").unwrap_or_default();
        let got = sys::getpwnam_into(&root, &mut big[..4]);
        assert_eq!(got, Err(Step::TooSmall));
        assert!(big[4..].iter().all(|&b| b == 0xa5), "{big:?}");
        // The whole 64 bytes hold it.
        let got = sys::getpwuid_into(0, &mut big);
        assert!(
            matches!(&got, Ok(Got::Entry { uid: 0, name: Some(n) }) if n == b"root"),
            "{got:?}"
        );
    }

    /// From a buffer of one byte, glibc's `ERANGE` grows it until root's
    /// entry fits, through the real calls: each `ERANGE` is read as too
    /// small, and the growth reaches an answer well before the cap.
    #[test]
    #[cfg(all(any(target_os = "linux", target_os = "freebsd"), not(miri)))]
    fn a_buffer_too_small_for_the_c_library_grows_until_it_answers() {
        let mut sizes = Vec::new();
        let answer = ask_growing(1, CAP, |buf| {
            sizes.push(buf.len());
            name_answer(sys::getpwuid_into(0, buf))
        });
        assert_eq!(answer.found().map(|a| a.name), Some(b"root".to_vec()));
        assert!(sizes.len() > 1 && sizes.starts_with(&[1, 2]), "{sizes:?}");
        let root = std::ffi::CString::new("root").unwrap_or_default();
        let answer = ask_growing(1, CAP, |buf| uid_answer(sys::getpwnam_into(&root, buf)));
        assert_eq!(answer.found().map(|a| a.uid), Some(0));
    }
}
