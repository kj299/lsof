//! Linux data-acquisition backend for winlsof — **Phase L0**.
//!
//! Implements [`lsof_core::backend::Backend`] over `/proc`, which is the whole
//! data source: process identity from `/proc/<pid>/status`, open files from
//! `/proc/<pid>/fd` (plus the `cwd`/`root`/`exe` magic links), and file
//! attributes from `stat`. `std::os::unix::fs::MetadataExt` exposes every field
//! needed, so this crate has **no dependencies** — the same posture as
//! `lsof-core`, and it keeps the supply-chain gate's surface unchanged.
//!
//! `#![forbid(unsafe_code)]`: unlike the Windows backend, nothing here needs
//! FFI. Reading a filesystem is safe Rust all the way down.
//!
//! # What Phase L0 covers
//!
//! Enough for `-p`, `-c`, `-u`, `-t`, `-d`, `-a`, `-R`, bare paths and `+D`/`+d`
//! to work, since the portable selection engine and all three renderers are
//! reused unchanged. Regular files, directories, character and **block**
//! devices, and FIFOs are typed from `st_mode`; DEVICE, SIZE, NODE and NLINK
//! come from the same `stat`.
//!
//! # What it does not cover yet
//!
//! **Sockets are not classified.** Doing so means parsing `/proc/net/{tcp,udp,
//! unix,…}` and joining on the `socket:[inode]` an fd link reports — Phase L1.
//! Until then a socket fd is reported with the type code `SOCK` and its
//! `socket:[inode]` name rather than being guessed at or hidden: the row is
//! real, and the inode is exactly the key L1 will join on. A consequence worth
//! stating plainly is that **`-i` matches nothing on this backend today**, which
//! is the honest result of having no socket data — not a filter bug.
//!
//! Also deferred: `mem` rows from `/proc/<pid>/maps`, the lock column from
//! `/proc/locks`, and named `anon_inode` kinds (Phase L2). See
//! `winlsof/docs/linux-backend-scope.md`.
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
//! `winlsof/differential/`'s oracle-substitution workaround — the real C `lsof`
//! runs here, so this backend can be diffed against it directly:
//!
//! ```text
//! lsof -p <pid>   (C)   vs   lsof -p <pid>   (this backend)
//! ```
//!
//! That comparison is what found the error-row difference above, on the first
//! run.
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
mod process;
#[cfg(target_os = "linux")]
mod users;

#[cfg(target_os = "linux")]
pub use backend::LinuxBackend;
