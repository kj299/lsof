//! The system calls `std` has no API for, and the only `unsafe` in this
//! crate.
//!
//! Four libc functions, each declared with the prototype FreeBSD's headers
//! give it (`sys/sysctl.h`, `sys/mount.h`, `unistd.h`), each wrapped in one
//! safe function that owns its buffer and hands back bytes. What the bytes
//! mean is [`crate::kinfo`]'s business, in safe code; nothing here interprets
//! them, casts them to a struct, or keeps a pointer past the call.
//!
//! `statfs` and `getfsstat` are versioned symbols in FreeBSD's libc: the
//! unversioned name binds the default version, `FBSD_1.5` since FreeBSD 12,
//! whose `struct statfs` is the 2344-byte one `layout::sf` describes. The
//! older layout is reachable only through `FBSD_1.0` explicitly, which
//! nothing here names.

use std::ffi::{c_char, c_int, c_long, c_uint, c_void, CString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::layout;

extern "C" {
    fn sysctl(
        name: *const c_int,
        namelen: c_uint,
        oldp: *mut c_void,
        oldlenp: *mut usize,
        newp: *const c_void,
        newlen: usize,
    ) -> c_int;
    fn sysctlbyname(
        name: *const c_char,
        oldp: *mut c_void,
        oldlenp: *mut usize,
        newp: *const c_void,
        newlen: usize,
    ) -> c_int;
    fn getfsstat(buf: *mut c_void, bufsize: c_long, mode: c_int) -> c_int;
    fn statfs(path: *const c_char, buf: *mut c_void) -> c_int;
    fn geteuid() -> u32;
}

/// How many times a read that raced a growing table is tried again.
const TRIES: usize = 8;

/// A sysctl read, by MIB or by name: the size asked, a buffer of that size
/// and a quarter more (the table can grow between the two calls; the C
/// doubles for `kern.file`, whose size FreeBSD 9 under-reported), and the
/// read; `ENOMEM`, the table grew past even that, tries again from the size.
fn read_with(call: impl Fn(*mut c_void, &mut usize) -> c_int) -> io::Result<Vec<u8>> {
    let mut last = io::Error::from_raw_os_error(12);
    for _ in 0..TRIES {
        let mut len = 0usize;
        if call(std::ptr::null_mut(), &mut len) != 0 {
            return Err(io::Error::last_os_error());
        }
        let cap = len.saturating_add(len / 4).saturating_add(4096);
        let mut buf = vec![0u8; cap];
        let mut got = cap;
        if call(buf.as_mut_ptr().cast(), &mut got) == 0 {
            buf.truncate(got.min(cap));
            return Ok(buf);
        }
        last = io::Error::last_os_error();
        if last.raw_os_error() != Some(12) {
            return Err(last);
        }
    }
    Err(last)
}

/// `sysctl(3)` of a MIB.
pub fn sysctl_mib(mib: &[c_int]) -> io::Result<Vec<u8>> {
    let n = c_uint::try_from(mib.len()).map_err(|_| io::Error::from_raw_os_error(22))?;
    read_with(|old, len| {
        // SAFETY: `mib` is a live slice of `n` ints; `old` is null (the size
        // probe) or points to a buffer `read_with` owns of exactly `*len`
        // bytes, which is what the kernel writes at most; `len` is a valid
        // `&mut usize`; no new value is set (null, 0).
        unsafe { sysctl(mib.as_ptr(), n, old, len, std::ptr::null(), 0) }
    })
}

/// `sysctlbyname(3)`.
pub fn sysctl_name(name: &str) -> io::Result<Vec<u8>> {
    let name = CString::new(name).map_err(|_| io::Error::from_raw_os_error(22))?;
    read_with(|old, len| {
        // SAFETY: `name` is a NUL-terminated string that outlives the call;
        // `old` and `len` as in `sysctl_mib`.
        unsafe { sysctlbyname(name.as_ptr(), old, len, std::ptr::null(), 0) }
    })
}

/// `getfsstat(2)` under `MNT_NOWAIT`: every mounted file system's `struct
/// statfs`, from the kernel's cache, waiting on none of them.
pub fn getfsstat_all() -> io::Result<Vec<u8>> {
    let rec = layout::sf::SIZE;
    for _ in 0..TRIES {
        // SAFETY: a null buffer asks only for the count; nothing is written.
        let n = unsafe { getfsstat(std::ptr::null_mut(), 0, layout::MNT_NOWAIT) };
        let Ok(n) = usize::try_from(n) else {
            return Err(io::Error::last_os_error());
        };
        // Room for a few more, mounted between the calls.
        let cap = (n + 8).saturating_mul(rec);
        let mut buf = vec![0u8; cap];
        let size = c_long::try_from(cap).map_err(|_| io::Error::from_raw_os_error(12))?;
        // SAFETY: `buf` is `cap` bytes, and `size` tells the kernel so; it
        // writes whole records within that and returns how many.
        let got = unsafe { getfsstat(buf.as_mut_ptr().cast(), size, layout::MNT_NOWAIT) };
        let Ok(got) = usize::try_from(got) else {
            return Err(io::Error::last_os_error());
        };
        // As many as fitted: if that is all the room there was, more may
        // have been mounted, and the count is asked again.
        if got < n + 8 {
            buf.truncate(got.saturating_mul(rec).min(cap));
            return Ok(buf);
        }
    }
    Err(io::Error::from_raw_os_error(12))
}

/// `statfs(2)` of `path`: the `struct statfs` of the file system it is on.
pub fn statfs_path(path: &Path) -> io::Result<Vec<u8>> {
    let c =
        CString::new(path.as_os_str().as_bytes()).map_err(|_| io::Error::from_raw_os_error(22))?;
    let mut buf = vec![0u8; layout::sf::SIZE];
    // SAFETY: `c` is NUL-terminated and outlives the call; `buf` is exactly
    // one `struct statfs` of the version the unversioned symbol binds.
    if unsafe { statfs(c.as_ptr(), buf.as_mut_ptr().cast()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(buf)
}

/// The effective user ID.
pub fn euid() -> u32 {
    // SAFETY: `geteuid` takes nothing, cannot fail and touches no memory of
    // ours.
    unsafe { geteuid() }
}
