//! Linux data-acquisition backend for lsof-rs — phases L0 to L3 are done.
//!
//! Implements [`lsof_core::backend::Backend`] over `/proc`, with `/etc/passwd`
//! for login names: process identity from `/proc/<pid>/status`, open files from
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
//!   every form the core supports (`-iTCP:443`, `-i@addr`, `-i4`/`-i6`,
//!   `-iUDP`, `-iICMP`, `-iRAW`), as does `-T q`.
//! * **Bounded calls** (`safefs`): every `stat`, `lstat`, `readlink` and
//!   directory listing lsof makes on a path it was given — an argument, a
//!   `+d`/`+D` tree, a mount point — runs in a helper process that gives it
//!   `-S` seconds, so a file system that never answers costs a run that limit
//!   per call that meets it, and not the run (DIVERGENCES 94, 110, 118).
//! * **L2** — everything the scope document deferred has landed but naming
//!   netlink sockets (below):
//!   `mem` rows and the `DEL` marking from `/proc/<pid>/maps`, the lock column
//!   from `/proc/locks`, named `anon_inode` kinds (`[eventfd:6]`, `[pidfd:N]`,
//!   `[eventpoll]`, …), the mount table behind `-f`/`+f` and the mount-point
//!   rule, per-namespace socket reads so a container's socket is named rather
//!   than left as a bare `socket:[inode]`, and the `pack` row from
//!   `/proc/net/packet`.
//!
//! # What it does not cover yet
//!
//! Sockets the C names and this backend does not. A socket no `/proc/net`
//! table lists — AF_VSOCK, an unbound **netlink** socket, a ping socket — the
//! C names from the `system.sockprotoname` extended attribute, which has no
//! `std` API; that waits on the decision recorded as DIVERGENCES item 22, not
//! on effort. Two families do have tables this backend does not read as the C
//! does: a *bound* netlink socket is listed in `/proc/net/netlink`, which the
//! C types `netlink` (item 109), and a raw socket, which the C types `raw`
//! from `/proc/net/raw` where this backend types it IPv4 or IPv6 (item 108).
//! Packet sockets are done.
//!
//! Also open: the `-Z` CONTEXT column and the rows of
//! `lsof-rs/DIVERGENCES.md` still OPEN for this backend. `lsof-rs/docs/linux-l2-plan.md` measures each;
//! the `DEBT` entries in `lsof-rs/coverage/feature-inventory-lsof-rs.toml` are
//! what the coverage gate prints on every run.
//!
//! **A file that cannot be read is a row saying why**, as it is in the C: a
//! link that will not read is TYPE `unknown` with NAME `/proc/1/cwd (readlink:
//! Permission denied)`, an fd table that will not open is one `NOFD` row, and
//! under `-w` or `-t` there is none of either (see `files::for_proc_dir`).
//! This backend left all of it out until 2026-09-25, in the belief that
//! matching it meant reproducing libc's error strings — which Rust's
//! `io::Error` already prints.
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
//! That comparison found the error-row difference on its first run (closed
//! 2026-09-25, once a fixture the gate could not read existed), and in L1 it caught four more before any of it shipped: the DEVICE and
//! NODE cells are filled differently per socket family (inet shows inode and
//! protocol, AF_UNIX shows the kernel socket pointer and inode — getting them
//! backwards is invisible without the diff), `-U` was never enforced in the
//! core at all, and three renderer divergences that had been latent on Windows
//! since v0.2.0 (see `docs/known-limitations.md`).
//!
//! # Privilege
//!
//! Unprivileged, `/proc/<pid>/fd` is readable only for your own processes;
//! others appear with rows saying why (above). As root, everything is readable.
//! That is the direct analog of the Windows backend's elevation split, and it
//! needs no privilege to be *requested* — Linux grants it by uid, so there is
//! nothing here matching `SeDebugPrivilege`'s enable/disable dance.

//! # Building elsewhere
//!
//! Everything is gated on `#[cfg(target_os = "linux")]`; on any other host this
//! crate compiles to an empty shell, exactly as `lsof-backend-windows` does off
//! Windows. That is what keeps `cargo check --target x86_64-pc-windows-gnu
//! --all-targets` green from Linux with both backends in one workspace. CI
//! does not run that check; its windows job builds the Windows backend
//! natively.

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
mod mounts;
#[cfg(target_os = "linux")]
mod net;
#[cfg(target_os = "linux")]
mod process;
#[cfg(target_os = "linux")]
pub mod safefs;
#[cfg(target_os = "linux")]
mod text;
#[cfg(target_os = "linux")]
mod users;

#[cfg(target_os = "linux")]
pub use backend::LinuxBackend;

/// The pure text parsers, exposed for the cargo-fuzz targets in `../../fuzz`.
///
/// Every function here takes text or bytes and touches no file: each is the parsing
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
    pub use crate::maps::{parse_maps, parse_maps_bytes, Mapping};
    pub use crate::mounts::{parse_mounts, MountLine};
    pub use crate::net::{
        fields_with_rest, packet_node, parse_addr, parse_queues, socket_inode, socket_type_suffix,
        tcp_state, unix_state, unix_suffix, SocketTable,
    };
    pub use crate::process::parse_status;
    pub use crate::users::parse_passwd;
    pub use lsof_core::model::Protocol;
}
