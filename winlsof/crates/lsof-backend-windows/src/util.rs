//! Small safe wrappers over the raw Win32 surface. Every `unsafe` call in the
//! backend is funneled through helpers like these so the rest of the code reads
//! as ordinary safe Rust.

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};

/// RAII wrapper that owns a Windows `HANDLE` and closes it exactly once on drop.
/// This eliminates the handle-leak / double-close bugs that plague the C code.
pub struct OwnedHandle(HANDLE);

impl OwnedHandle {
    /// Adopt a handle, rejecting the null and `INVALID_HANDLE_VALUE` sentinels.
    pub fn new(h: HANDLE) -> Option<Self> {
        if h.is_null() || h == INVALID_HANDLE_VALUE {
            None
        } else {
            Some(Self(h))
        }
    }

    /// Borrow the raw handle for passing to an API. The handle stays owned by
    /// `self`, so the borrow must not outlive it.
    pub fn raw(&self) -> HANDLE {
        self.0
    }

    /// Relinquish ownership, returning the raw handle without closing it. The
    /// caller becomes responsible for closing it exactly once.
    pub fn into_raw(self) -> HANDLE {
        let h = self.0;
        std::mem::forget(self);
        h
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: `self.0` was validated as a real, owned handle at construction
        // and is closed exactly once, here.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// Convert a (possibly NUL-terminated) UTF-16 buffer to a `String`, stopping at
/// the first NUL.
pub fn wide_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}
