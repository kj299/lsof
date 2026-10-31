//! FreeBSD data-acquisition backend for lsof-rs.
//!
//! Implements [`lsof_core::backend::Backend`] from the records the C's own
//! FreeBSD dialect reads (`lib/dialects/freebsd/`), through `sysctl(3)`:
//!
//! | What | Where | The C |
//! |---|---|---|
//! | processes | `kern.proc.proc` (`kinfo_proc`) | `gather_proc_info()` |
//! | open files | `kern.proc.filedesc.<pid>` (`kinfo_file`) | `kinfo_getfile()` |
//! | locks | `kern.lockf` (`kinfo_lockf`) | `read_lockf()` |
//! | TCP state, AF_UNIX peers | `net.inet.{tcp,udp}.pcblist`, `net.local.*.pcblist` | `read_pcb_lists()` |
//! | an unnamed kind's `struct file` | `kern.file` (`xfile`) | `read_xfiles()` |
//! | file systems | `statfs(2)`, `getfsstat(2)` | `readvfs()`, `readmnt()` |
//! | device names | a walk of `/dev` | `readdev()` |
//!
//! What the C reads from kernel memory through `kvm(3)` — which needs the
//! kernel's symbol table and `/dev/kmem` — this backend does not read at all:
//! since FreeBSD 14 the dialect reads none of it for the rows it prints (a
//! pipe's buffer and a kqueue's count are in `kinfo_file` from 1400062 on),
//! and what is left is only `+f`'s file-structure columns.
//!
//! # Safety
//!
//! `std` has no `sysctl`. The four libc calls are declared in `sys`, the
//! one module where `unsafe` is allowed (`#![deny(unsafe_code)]` everywhere
//! else), and each is wrapped in a function that owns its buffer and returns
//! bytes. The bytes are parsed by `kinfo`, safe code that bounds-checks
//! every read against the record's stated and actual length. The layouts it
//! reads by (`layout`) were measured from the FreeBSD 14.5 and 15.1
//! headers, on amd64 and i386, by compiling `offsetof()` with clang; a
//! `kinfo_proc` whose `ki_structsize` is not the measured one is refused
//! rather than misread.
//!
//! # Platforms
//!
//! FreeBSD 14 and 15, on x86_64 and i686 (`x86`). Elsewhere this crate is an
//! empty shell, as the Linux and Windows backends are off their platforms;
//! its pure modules also build on any Unix under `cfg(test)` so the parsers
//! and the row rules are tested on the Linux CI runners too.
//!
//! # Privilege
//!
//! Unprivileged, `kern.proc.filedesc` answers only for processes this user
//! may debug; another's process then has no rows and so, as in the C, no
//! line at all.

#![deny(unsafe_code)]
#![cfg_attr(not(target_os = "freebsd"), allow(dead_code))]

#[cfg(any(target_os = "freebsd", all(unix, any(test, feature = "fuzzing"))))]
mod devnames;
#[cfg(any(target_os = "freebsd", test, feature = "fuzzing"))]
mod kinfo;
#[cfg(any(target_os = "freebsd", test, feature = "fuzzing"))]
mod layout;
#[cfg(any(target_os = "freebsd", all(unix, any(test, feature = "fuzzing"))))]
mod mounts;
#[cfg(any(target_os = "freebsd", test, feature = "fuzzing"))]
mod names;
#[cfg(any(target_os = "freebsd", test, feature = "fuzzing"))]
mod rows;
#[cfg(any(target_os = "freebsd", all(unix, any(test, feature = "fuzzing"))))]
mod users;

#[cfg(target_os = "freebsd")]
mod backend;
#[cfg(target_os = "freebsd")]
#[allow(unsafe_code)]
mod sys;

#[cfg(target_os = "freebsd")]
pub use backend::FreeBsdBackend;

/// The pure parsers, for the cargo-fuzz target in `../../fuzz`. Not API.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzz_api {
    pub use crate::kinfo::{
        files, inet_addr, locks, pcblist, procs, statfs_list, unix_path, xfiles, KFile, Pcb,
    };
    pub use crate::layout::{PROC_AMD64, PROC_I386, XINPCB, XTCPCB, XUNPCB};
    pub use crate::rows::{numbered, special, Env, Opts, Vfs};
}
