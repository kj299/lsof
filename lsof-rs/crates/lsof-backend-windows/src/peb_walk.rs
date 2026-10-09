//! The PEB → `ProcessParameters` → `CurrentDirectory.DosPath` walk behind
//! `peb::cwd`, over a reader of the target's memory, in portable safe Rust.
//!
//! Every pointer followed here was read out of the target process, which can
//! write its own PEB: `ProcessParameters` and `DosPath.Buffer` are values it
//! chose, and so is `DosPath.Length`. Each address is therefore computed with
//! `checked_add` after `usize::try_from`, and one that does not fit is
//! unreadable, which is no `cwd` row, exactly as a failed `ReadProcessMemory`
//! is. Before this module, `peb.rs` added the field offsets with a plain `+`: a
//! `ProcessParameters` above `0xFFFF_FFFF_FFFF_FFC7` wrapped `params + 0x38` in
//! the release build, so the walk read the `DosPath` from an address in
//! `0x0..0x37`. (From `0x…FFC0` to `0x…FFC7` only the later `+ 0x40` wraps, and
//! the read before it, in the top 8 bytes of the address space, fails first.)
//! Measured with a stand-in reader on Linux: `0xffff_ffff_ffff_ffd0` read the
//! `UNICODE_STRING` at `0x8`, and the row named the string planted there;
//! whether a Windows process can map those first bytes was not measured. With
//! `overflow-checks` on, the same pointer panicked the pid's worker thread,
//! which cost that pid its `cwd`, module and mapped rows.
//!
//! # Why this module is not `#[cfg(windows)]`
//!
//! For the reason `names` is not: so its unit tests and the `windows_peb`
//! fuzz target run on the Linux runner, which is where `cargo fuzz` runs. The
//! one Win32 call, `ReadProcessMemory`, stays in `peb.rs` and comes in as the
//! `read` closure.

// Denied, not warned: a `+` on a pointer the target chose is the defect this
// module exists to prevent, so none may be written here, test code included
// (CI runs `clippy --all-targets -D warnings` on both platforms).
#![deny(clippy::arithmetic_side_effects)]

// 64-bit offsets: PEB.ProcessParameters, then CurrentDirectory.DosPath
// (UNICODE_STRING: Length @ +0, 8-byte Buffer pointer @ +8).
const PEB64_PARAMS: usize = 0x20;
const RTLUPP64_CURDIR: usize = 0x38;
const US64_BUFFER: usize = 0x08;

// 32-bit (WOW64) offsets: PEB32.ProcessParameters, then CurrentDirectory.DosPath
// (UNICODE_STRING32: Length @ +0, 4-byte Buffer pointer @ +4).
const PEB32_PARAMS: usize = 0x10;
const RTLUPP32_CURDIR: usize = 0x24;
const US32_BUFFER: usize = 0x04;

/// `base + off` in the target's address space, or `None` when it does not fit
/// a `usize`: `base` is a pointer the target chose.
fn field(base: u64, off: usize) -> Option<usize> {
    usize::try_from(base).ok()?.checked_add(off)
}

/// `N` bytes at `addr`, or `None` when the reader cannot supply all of them.
fn read_n<const N: usize>(
    read: &mut impl FnMut(usize, usize) -> Option<Vec<u8>>,
    addr: usize,
) -> Option<[u8; N]> {
    read(addr, N)?.get(..N)?.try_into().ok()
}

/// 64-bit target: the working directory of the process whose PEB is at `peb`
/// (from `ProcessBasicInformation`, the kernel's), read through `read(addr,
/// len)`. `None` is no `cwd` row.
pub fn cwd64(peb: usize, read: &mut impl FnMut(usize, usize) -> Option<Vec<u8>>) -> Option<String> {
    let params = u64::from_le_bytes(read_n(read, peb.checked_add(PEB64_PARAMS)?)?);
    if params == 0 {
        return None;
    }
    let length = u16::from_le_bytes(read_n(read, field(params, RTLUPP64_CURDIR)?)?);
    let buffer = u64::from_le_bytes(read_n(read, field(params, RTLUPP64_CURDIR + US64_BUFFER)?)?);
    wide(read, usize::try_from(buffer).ok()?, length)
}

/// 32-bit (WOW64) target: as [`cwd64`], from the PEB32 at `peb32` (from
/// `ProcessWow64Information`) with 32-bit pointers. A `u32` plus these offsets
/// cannot overflow a 64-bit `usize`; it is checked anyway, so this module has
/// no unchecked arithmetic at all.
pub fn cwd32(
    peb32: usize,
    read: &mut impl FnMut(usize, usize) -> Option<Vec<u8>>,
) -> Option<String> {
    let params = u32::from_le_bytes(read_n(read, peb32.checked_add(PEB32_PARAMS)?)?);
    if params == 0 {
        return None;
    }
    let params = u64::from(params);
    let length = u16::from_le_bytes(read_n(read, field(params, RTLUPP32_CURDIR)?)?);
    let buffer = u32::from_le_bytes(read_n(read, field(params, RTLUPP32_CURDIR + US32_BUFFER)?)?);
    wide(read, usize::try_from(buffer).ok()?, length)
}

/// Read `length` bytes of UTF-16 at `addr` and decode to a `String`. A `u16`
/// length bounds the read at 64 KiB, and an odd final byte is dropped.
fn wide(
    read: &mut impl FnMut(usize, usize) -> Option<Vec<u8>>,
    addr: usize,
    length: u16,
) -> Option<String> {
    if length == 0 || addr == 0 {
        return None;
    }
    let bytes = read(addr, usize::from(length))?;
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    Some(String::from_utf16_lossy(&units))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// A target's address space: runs of bytes at addresses. A read is served
    /// only when it falls inside one run, as `ReadProcessMemory` fails on a
    /// range that is not wholly readable.
    fn reader(mem: &BTreeMap<usize, Vec<u8>>) -> impl FnMut(usize, usize) -> Option<Vec<u8>> + '_ {
        move |addr, len| {
            let (&base, bytes) = mem.range(..=addr).next_back()?;
            let from = addr.checked_sub(base)?;
            bytes.get(from..from.checked_add(len)?).map(<[u8]>::to_vec)
        }
    }

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    /// A 64-bit PEB at 0x1000 whose `ProcessParameters` is `params`, and, where
    /// `params + RTLUPP64_CURDIR` fits, a `DosPath` of `length` and `buffer`.
    /// (Not computed with `field`, the code under test.)
    fn image64(params: u64, length: u16, buffer: u64) -> BTreeMap<usize, Vec<u8>> {
        let mut m = BTreeMap::new();
        m.insert(0x1020, params.to_le_bytes().to_vec());
        let at = usize::try_from(params)
            .ok()
            .and_then(|p| p.checked_add(RTLUPP64_CURDIR));
        if let Some(at) = at {
            let mut us = length.to_le_bytes().to_vec();
            us.extend([0u8; 6]);
            us.extend(buffer.to_le_bytes());
            m.insert(at, us);
        }
        m
    }

    #[test]
    fn a_benign_peb_gives_the_cwd() {
        let mut m = image64(0x2000, 10, 0x3000);
        m.insert(0x3000, utf16("C:\\x\\"));
        assert_eq!(cwd64(0x1000, &mut reader(&m)).as_deref(), Some("C:\\x\\"));
    }

    #[test]
    fn a_benign_wow64_peb_gives_the_cwd() {
        let mut m = BTreeMap::new();
        m.insert(0x1010, 0x2000u32.to_le_bytes().to_vec());
        let mut us = 8u16.to_le_bytes().to_vec();
        us.extend([0u8; 2]);
        us.extend(0x3000u32.to_le_bytes());
        m.insert(0x2024, us);
        m.insert(0x3000, utf16("D:\\y"));
        assert_eq!(cwd32(0x1000, &mut reader(&m)).as_deref(), Some("D:\\y"));
    }

    /// The target stores a `ProcessParameters` pointer at the top of the
    /// address space, so `params + 0x38` (or `+ 0x40`) overflows. Written with
    /// a plain `+` this panicked under overflow checks (measured: "attempt to
    /// add with overflow"); it must be an unreadable PEB.
    #[test]
    fn a_parameters_pointer_that_wraps_is_unreadable_not_a_panic() {
        for params in [
            u64::MAX,
            u64::MAX - 0x37,
            u64::MAX - 0x3f,
            0xffff_ffff_ffff_ffd0,
        ] {
            let m = image64(params, 8, 0x3000);
            assert_eq!(cwd64(0x1000, &mut reader(&m)), None, "params={params:#x}");
        }
    }

    /// The same pointer with the addresses the wrap lands on mapped (this
    /// reader serves them; whether Windows lets a process map them was not
    /// measured): without overflow checks a plain `+` read the `DosPath` at 0x8
    /// and its buffer at 0x10, and the row named the string planted there
    /// (measured: `Some("EVIL\\")`).
    #[test]
    fn a_wrapped_parameters_pointer_never_reads_where_the_wrap_lands() {
        let mut m = BTreeMap::new();
        m.insert(0x1020, 0xffff_ffff_ffff_ffd0u64.to_le_bytes().to_vec());
        let mut us = 10u16.to_le_bytes().to_vec();
        us.extend([0u8; 6]);
        us.extend(0x3000u64.to_le_bytes());
        m.insert(0x8, us);
        m.insert(0x3000, utf16("EVIL\\"));
        assert_eq!(cwd64(0x1000, &mut reader(&m)), None);
    }

    /// A WOW64 `ProcessParameters` at `u32::MAX`: `+ 0x24` fits a 64-bit
    /// `usize` and reads nothing there; on a 32-bit `usize` it would wrap.
    #[test]
    fn a_wow64_parameters_pointer_at_u32_max_is_unreadable_not_a_panic() {
        let mut m = BTreeMap::new();
        m.insert(0x1010, u32::MAX.to_le_bytes().to_vec());
        assert_eq!(cwd32(0x1000, &mut reader(&m)), None);
    }

    #[test]
    fn a_zero_length_or_null_buffer_is_no_cwd() {
        assert_eq!(
            cwd64(0x1000, &mut reader(&image64(0x2000, 0, 0x3000))),
            None
        );
        assert_eq!(cwd64(0x1000, &mut reader(&image64(0x2000, 8, 0))), None);
        assert_eq!(cwd64(0x1000, &mut reader(&image64(0, 8, 0x3000))), None);
    }

    /// A PEB base at the top of the address space, which the kernel never
    /// reports: `+ 0x20` (`+ 0x10` on WOW64) overflows. The addresses those
    /// sums would wrap to, 0xf and 0x7, start complete walks, so a wrapped read
    /// would return their cwd.
    #[test]
    fn a_peb_base_at_the_top_is_unreadable() {
        let mut m = image64(0x2000, 10, 0x3000);
        m.insert(0x3000, utf16("EVIL\\"));
        m.insert(0xf, 0x2000u64.to_le_bytes().to_vec());
        assert_eq!(cwd64(usize::MAX - 0x10, &mut reader(&m)), None);
        m.insert(0x7, 0x5000u32.to_le_bytes().to_vec());
        let mut us = 10u16.to_le_bytes().to_vec();
        us.extend([0u8; 2]);
        us.extend(0x3000u32.to_le_bytes());
        m.insert(0x5024, us);
        assert_eq!(cwd32(usize::MAX - 0x8, &mut reader(&m)), None);
    }
}
