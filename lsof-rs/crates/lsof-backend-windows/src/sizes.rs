//! Buffer sizes and bounds computed from counts the kernel reports, checked.
//!
//! `handles.rs` grows a query buffer to the size `NtQuerySystemInformation` or
//! `NtQueryObject` says it needs, and `etw.rs` bounds TDH's property array by
//! the count in the buffer's own header before `slice::from_raw_parts`. Those
//! counts are `u32`s, and with a 64-bit `usize` no input can overflow the
//! arithmetic; with a 32-bit one it can, and a wrapped bound would pass the
//! check that guards a raw slice. So it is checked, and a size that does not fit
//! is the query failing, never a panic and never a wrap. Portable (not
//! `#[cfg(windows)]`) so these tests run on Linux.

#![deny(clippy::arithmetic_side_effects)]

/// The next query-buffer size after a "buffer too small" status: double
/// `cap`, or the `ret` bytes the call reported needing plus `slack`, whichever
/// is larger. `None` when either does not fit a `usize`, or the result does not
/// fit the `u32` (`ULONG`) length both calls take: a buffer the call cannot be
/// told the size of can never succeed, and each further round would only
/// allocate twice as much (4 GiB to 256 GiB over `query_all_handles`'s rounds,
/// simulated). Every caller already handles `None` as the query failing.
pub(crate) fn next_cap(cap: usize, ret: u32, slack: usize) -> Option<usize> {
    let needed = usize::try_from(ret).ok()?.checked_add(slack)?;
    let next = cap.checked_mul(2)?.max(needed);
    u32::try_from(next).is_ok().then_some(next)
}

/// Whether `count` elements of `elem` bytes, starting at byte `start`, lie
/// inside a buffer of `len` bytes. An end that overflows does not.
pub(crate) fn props_fit(start: usize, count: usize, elem: usize, len: usize) -> bool {
    count
        .checked_mul(elem)
        .and_then(|n| n.checked_add(start))
        .is_some_and(|end| end <= len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_cap_doubles_or_takes_what_the_call_asked_for() {
        assert_eq!(next_cap(1 << 20, 0, 4096), Some(1 << 21));
        assert_eq!(next_cap(0x1000, 0x5000, 256), Some(0x5100));
        // The largest size a `u32` length can tell the call.
        assert_eq!(
            next_cap(0x1000, u32::MAX - 256, 256),
            Some(u32::MAX as usize)
        );
    }

    /// `cap * 2` with a plain `*` panicked here under overflow checks; with
    /// checks off, the top bit doubled to 0 and the next round asked for a
    /// 4 KiB buffer.
    #[test]
    fn next_cap_that_overflows_is_none_not_a_panic() {
        assert_eq!(next_cap(usize::MAX, 0, 4096), None);
        assert_eq!(next_cap(usize::MAX / 2 + 1, 0, 4096), None);
        assert_eq!(next_cap(1 << 20, 1, usize::MAX), None);
    }

    /// The largest count the kernel can report, plus the slack, fits a 64-bit
    /// `usize` (0x1_0000_0fff) but not the `u32` length the call takes: passed
    /// `as u32` it told the call 4088 bytes, so no round could succeed and each
    /// allocated twice the last. So it is the query failing, and so is
    /// doubling past it.
    #[test]
    fn next_cap_past_what_the_call_can_be_told_is_none() {
        assert_eq!(next_cap(1 << 20, u32::MAX, 4096), None);
        assert_eq!(next_cap(1 << 20, 0xffff_f001, 4096), None);
        assert_eq!(next_cap(1 << 31, 0, 4096), None);
    }

    #[test]
    fn props_fit_is_the_bounds_check_and_cannot_wrap() {
        assert!(props_fit(16, 2, 24, 4096));
        assert!(
            props_fit(16, 2, 24, 64),
            "the array may end at the buffer's end"
        );
        assert!(!props_fit(16, 2, 24, 63));
        // `count * elem` and `start + …` with a plain `*`/`+` panicked (or, with
        // checks off, wrapped to a small end that passed).
        assert!(!props_fit(16, usize::MAX, 24, 4096));
        assert!(!props_fit(usize::MAX, 1, 1, usize::MAX));
    }
}
