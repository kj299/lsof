//! Linux data-acquisition backend for lsof-rs — **Phase L1**.
//!
//! Implements [`lsof_core::backend::Backend`] over `/proc`, which is the whole
//! data source: process identity from `/proc/<pid>/status`, open files from
//! `/proc/<pid>/fd` (plus the `cwd`/`root`/`exe` magic links), file attributes
//! from `stat`, and sockets from `/proc/net/*`.
//! `std::os::unix::fs::MetadataExt` exposes every field needed, so this crate
//! has **no dependencies** — the same posture as `lsof-core`, and it keeps the
//! supply-chain gate's surface unchanged.
//!
//! `#![forbid(unsafe_code)]`: unlike the Windows backend, nothing here needs
//! FFI. Reading a filesystem is safe Rust all the way down.
//!
//! # What is covered
//!
//! * **L0** — processes, owners, and open files. Regular files, directories,
//!   character and **block** devices, and FIFOs are typed from `st_mode`;
//!   DEVICE, SIZE, NODE and NLINK come from the same `stat`. Enough for `-p`,
//!   `-c`, `-u`, `-t`, `-d`, `-a`, `-R`, bare paths and `+D`/`+d`.
//! * **L1** — sockets. `/proc/net/{tcp,tcp6,udp,udp6,raw,raw6,unix}` is read
//!   once per gather and indexed by inode; an fd whose link target is
//!   `socket:[N]` is resolved by that key into a real TYPE (`IPv4`/`IPv6`/
//!   `unix`), protocol, addresses and TCP state. **`-i` and `-U` work**, in
//!   every form the core supports (`-iTCP:443`, `-i@host`, `-i4`/`-i6`,
//!   `-iUDP`, `-iICMP`, `-iRAW`), as does `-T q`.
//!
//! # What it does not cover yet
//!
//! Deferred to L2: `mem` rows from `/proc/<pid>/maps`, the lock column from
//! `/proc/locks`, named `anon_inode` kinds, deleted-file marking, and the
//! mount-table options (`-e`, `-m`, `+|-x`). See
//! `lsof-rs/docs/linux-backend-scope.md`, and the `DEBT (L2)` entries in
//! `lsof-rs/coverage/feature-inventory-lsof-rs.toml`, which the coverage gate
//! prints on every run.
//!
//! **Network namespaces.** `/proc/net` is the *caller's* namespace, so a socket
//! held by a process in a container will not be found. That degrades to the L0
//! row — `SOCK` with the `socket:[inode]` name — rather than to a wrong answer.
//! Reading per-namespace is L2.
//!
//! **Inaccessible files are omitted, not reported.** Diffed against the C
//! `lsof` 4.95.0, this is the one behavioural difference in rows L0 claims to
//! cover: where a link cannot be read, the C still emits a row carrying the
//! reason — a kernel thread shows
//! `txt unknown /proc/2/exe (readlink: Permission denied)` — whereas this
//! backend emits nothing. Nothing we *do* report disagrees with the C; the
//! difference is only in these error rows. Matching them means reproducing
//! libc's errno strings, so it is deliberately left to a later phase rather
//! than approximated.
//!
//! # Differential
//!
//! Unlike the Windows backend — which has no same-host oracle, hence
//! `lsof-rs/differential/`'s oracle-substitution workaround — the real C `lsof`
//! runs here, so this backend can be diffed against it directly:
//!
//! ```text
//! lsof -p <pid>   (C)   vs   lsof -p <pid>   (this backend)
//! ```
//!
//! That comparison is what found the error-row difference above on the first
//! run, and in L1 it caught four more before any of it shipped: the DEVICE and
//! NODE cells are filled differently per socket family (inet shows inode and
//! protocol, AF_UNIX shows the kernel socket pointer and inode — getting them
//! backwards is invisible without the diff), `-U` was never enforced in the
//! core at all, and three renderer divergences that had been latent on Windows
//! since v0.2.0 (see `docs/known-limitations.md`).
//!
//! # Privilege
//!
//! Unprivileged, `/proc/<pid>/fd` is readable only for your own processes;
//! others appear with identity but no files. As root, everything is readable.
//! That is the direct analog of the Windows backend's elevation split, and it
//! needs no privilege to be *requested* — Linux grants it by uid, so there is
//! nothing here matching `SeDebugPrivilege`'s enable/disable dance.

//! # Building elsewhere
//!
//! Everything is gated on `#[cfg(target_os = "linux")]`; on any other host this
//! crate compiles to an empty shell, exactly as `lsof-backend-windows` does off
//! Windows. That is what keeps `cargo check --target x86_64-pc-windows-gnu
//! --all-targets` — the cross-check CI runs from Linux — green with both
//! backends in one workspace.

#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
mod backend;
#[cfg(target_os = "linux")]
mod files;
#[cfg(target_os = "linux")]
mod locks;
#[cfg(target_os = "linux")]
mod maps;
#[cfg(target_os = "linux")]
mod net;
#[cfg(target_os = "linux")]
mod process;
#[cfg(target_os = "linux")]
mod users;

#[cfg(target_os = "linux")]
pub use backend::LinuxBackend;

/// The pure text parsers, exposed for the cargo-fuzz targets in `../../fuzz`.
///
/// Every function here takes `&str` and touches no file: each is the parsing
/// half of a `read → parse` split, so that the exact code path the backend runs
/// on kernel-supplied text can be driven with arbitrary bytes. This module exists
/// only under the `fuzzing` feature, which the CLI never enables; it is not API.
///
/// Why these are worth fuzzing at all in a `forbid(unsafe_code)` crate: the
/// contract is *no panic on hostile input* (PLAYBOOK Phase 4 gate 3), and
/// `/proc/<pid>/status`'s `Name:` is attacker-settable, an AF_UNIX path can hold
/// arbitrary bytes, and `/etc/passwd` is only as well-formed as its last editor.
/// A panic while listing files is a denial of service against the tool that is
/// supposed to be diagnosing one (LESSONS #021).
#[cfg(all(target_os = "linux", feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzz_api {
    pub use crate::files::{name_for_target, parse_fdinfo, FdInfo};
    pub use crate::locks::parse_locks;
    pub use crate::maps::{parse_maps, Mapping};
    pub use crate::net::{
        fields_with_rest, parse_addr, parse_queues, socket_inode, tcp_state, unix_state,
        unix_suffix, SocketTable,
    };
    pub use crate::process::parse_status;
    pub use crate::users::parse_passwd;
    pub use lsof_core::model::Protocol;
}
