//! The least-privilege model.
//!
//! Two pieces: [`is_elevated`] reports whether we hold an elevated token, and
//! [`PrivilegeGuard`] enables a named privilege (e.g. `SeDebugPrivilege`) for
//! *only* the lifetime of the guard, removing it again on drop. The backend
//! enables a privilege solely around the specific call that needs it, and only
//! when the switches in use require system-wide data — never globally, and
//! never at all for queries (like `-i`) that work in the plain user context.

use std::ffi::c_void;
use std::mem::{size_of, zeroed};

use windows_sys::Win32::Foundation::{HANDLE, LUID};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, GetTokenInformation, LookupPrivilegeValueW, TokenElevation,
    LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION,
    TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::util::OwnedHandle;

/// Returns true if the current process is running with an elevated token (i.e.
/// "Run as administrator"). Used only to tailor the user-facing hint; it never
/// causes a privilege to be enabled.
pub fn is_elevated() -> bool {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a pseudo-handle that must not be closed;
    // OpenProcessToken writes a real token handle we adopt below.
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if ok == 0 {
        return false;
    }
    let Some(token) = OwnedHandle::new(token) else {
        return false;
    };
    let mut elevation: TOKEN_ELEVATION = unsafe { zeroed() };
    let mut ret_len = 0u32;
    // SAFETY: token is valid; the buffer matches TOKEN_ELEVATION's size.
    let ok = unsafe {
        GetTokenInformation(
            token.raw(),
            TokenElevation,
            &mut elevation as *mut _ as *mut c_void,
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        )
    };
    ok != 0 && elevation.TokenIsElevated != 0
}

/// Enables a privilege on the current process token for the guard's lifetime.
///
/// Currently exercised by the Phase 3 handle-enumeration path; retained as the
/// single, audited home for privilege elevation so the rest of the backend can
/// stay privilege-free.
#[allow(dead_code)]
pub struct PrivilegeGuard {
    token: OwnedHandle,
    luid: LUID,
    enabled: bool,
}

#[allow(dead_code)]
impl PrivilegeGuard {
    /// Enable `name` (e.g. `"SeDebugPrivilege"`) just for this guard. Returns
    /// `None` if the privilege isn't held or can't be adjusted (e.g. unelevated).
    pub fn enable(name: &str) -> Option<Self> {
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: pseudo-handle in, real token out (adopted below).
        let ok = unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut token,
            )
        };
        if ok == 0 {
            return None;
        }
        let token = OwnedHandle::new(token)?;

        let mut luid: LUID = unsafe { zeroed() };
        // SAFETY: looking up a well-known privilege name into `luid`.
        let ok = unsafe { LookupPrivilegeValueW(std::ptr::null(), wide.as_ptr(), &mut luid) };
        if ok == 0 {
            return None;
        }

        let mut guard = Self {
            token,
            luid,
            enabled: false,
        };
        if guard.set(true) {
            guard.enabled = true;
            Some(guard)
        } else {
            None
        }
    }

    /// Enable or disable the privilege on the token.
    fn set(&mut self, on: bool) -> bool {
        let privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: self.luid,
                Attributes: if on { SE_PRIVILEGE_ENABLED } else { 0 },
            }],
        };
        // SAFETY: token is valid; `privileges` describes exactly one LUID.
        let ok = unsafe {
            AdjustTokenPrivileges(
                self.token.raw(),
                0,
                &privileges,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        ok != 0
    }
}

impl Drop for PrivilegeGuard {
    fn drop(&mut self) {
        if self.enabled {
            // Best-effort: drop the privilege as soon as the work is done.
            let _ = self.set(false);
        }
    }
}
