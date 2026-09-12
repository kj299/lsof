//! The canary that proves the AddressSanitizer job is actually sanitizing.
//!
//! A sanitizer gate that never sees a bug is indistinguishable from one that
//! is silently not instrumenting anything — a wrong `RUSTFLAGS`, a missing
//! `--target`, a runtime DLL that failed to load, and the job still goes
//! green. That failure mode is exactly how this project's *other* sanitizer
//! gate came to be "declared but never run" (porting-kit LESSONS #019), so
//! this one carries its own proof.
//!
//! The CI job builds this test with `--features asan-canary` and asserts the
//! run **fails** with an `AddressSanitizer` diagnostic. If it passes, ASan is
//! not working and the job stops before reporting anything about the real
//! code.
//!
//! It is behind a feature so it never builds in an ordinary `cargo test`, and
//! behind `cfg(windows)` because that is the only place the gate runs.

#![cfg(all(windows, feature = "asan-canary"))]

/// A deliberate heap-buffer-overflow read, one byte past a four-byte
/// allocation.
///
/// `black_box` on both the pointer and the result keeps the optimiser from
/// proving the read dead and deleting it — a canary that is optimised away is
/// the same false green it exists to catch.
#[test]
fn asan_reports_a_heap_overflow() {
    let v: Vec<u8> = vec![1, 2, 3, 4];
    let p = std::hint::black_box(v.as_ptr());
    // SAFETY: none. This read is out of bounds ON PURPOSE and is the entire
    // point of the test: ASan must abort the process here. Compiled only
    // under the `asan-canary` feature, which nothing but the CI job sets.
    let past_the_end = unsafe { *p.add(64) };
    std::hint::black_box(past_the_end);
    // Unreachable when ASan is working. Reaching it is the failure this test
    // reports, in the words the job's log check looks for.
    panic!("CANARY SURVIVED: the out-of-bounds read was not caught — ASan is not instrumenting this build");
}
