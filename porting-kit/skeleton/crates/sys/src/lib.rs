//! `sys` — the unsafe/FFI quarantine. Every `unsafe` in the whole project lives
//! here, and every block carries a `// SAFETY:` the audit harness enforces.
//!
//! Two patterns carry almost all the weight (both proven in the retrospective):
//!   1. RAII wrappers for every OS resource — acquire in `new`, release in
//!      `Drop`. This kills the use-after-free / leak / released-too-late classes
//!      by construction (the C `close()`/`free()`/`drop-privilege` bug family).
//!   2. Small audited safe fns over raw FFI — the `unsafe` is a few lines behind
//!      a safe signature, with its invariants written down.
//!
//! The example below is self-contained (no external -sys crate) so the skeleton
//! builds offline; replace the raw-pointer round-trip with your real FFI.

/// RAII owner of a heap resource obtained through a raw pointer — the shape of an
/// `OwnedHandle` / `OwnedFd` / `PrivilegeGuard`. The invariant: `ptr` is always
/// either null or a pointer this type uniquely owns and will free exactly once.
pub struct OwnedResource {
    ptr: *mut u64,
}

impl OwnedResource {
    /// Acquire the resource. (Stand-in for `CreateFileW`, `socket()`, etc.)
    pub fn acquire(value: u64) -> Self {
        // Box::into_raw hands us a uniquely-owned, non-null, aligned pointer.
        OwnedResource { ptr: Box::into_raw(Box::new(value)) }
    }

    /// Read the resource's value through the raw pointer — the "safe wrapper over
    /// FFI" pattern: the `unsafe` is contained and its precondition is proven.
    pub fn get(&self) -> u64 {
        // SAFETY: `ptr` is non-null and aligned — it came from `Box::into_raw`
        // in `acquire` and is only nulled by `Drop`, which consumes `self`, so
        // it is valid for reads for the whole borrow.
        unsafe { *self.ptr }
    }
}

impl Drop for OwnedResource {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: `ptr` was produced by `Box::into_raw` in `acquire` and has
            // not been freed (this is the sole `Drop`, and no other method frees
            // it), so reconstituting the Box to free it exactly once is sound.
            unsafe { drop(Box::from_raw(self.ptr)); }
            self.ptr = std::ptr::null_mut();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_get_and_drop_are_sound() {
        let r = OwnedResource::acquire(42);
        assert_eq!(r.get(), 42);
        // Drop runs here without leak or double-free (verify under Miri:
        // `cargo +nightly miri test`).
    }
}
