//! The platform "dialect" boundary.
//!
//! A [`Backend`] is the Rust analog of an lsof dialect's `gather_proc_info()`
//! hook: it knows how to enumerate the system's processes and their open files
//! on one platform. The portable code in this crate drives a `&dyn Backend`,
//! so the Windows implementation (and any future Linux one) is fully decoupled
//! from selection and rendering.

use crate::model::Process;
use crate::selection::Selection;

/// An OS privilege that a particular query may require. Used to implement the
/// least-privilege model: the CLI/back end only ever requests a privilege when
/// the switches in use actually need it, and never holds it longer than the
/// single call that needs it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Privilege {
    /// No elevation required — visible in the plain user context.
    None,
    /// Requires `SeDebugPrivilege` (Administrator) to reach data owned by other
    /// users' / protected processes (e.g. duplicating their handles).
    SeDebug,
}

/// Errors a backend can report. Selection that simply yields no rows is *not*
/// an error — it returns an empty `Vec`.
#[derive(Debug)]
pub enum BackendError {
    /// The backend isn't available on this build/platform.
    Unsupported(String),
    /// An underlying OS call failed.
    Os(String),
}

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendError::Unsupported(m) => write!(f, "unsupported: {m}"),
            BackendError::Os(m) => write!(f, "OS error: {m}"),
        }
    }
}

impl std::error::Error for BackendError {}

/// A platform data source for winlsof.
pub trait Backend {
    /// A short human-readable name (e.g. `"windows"`, `"mock"`).
    fn name(&self) -> &str;

    /// Gather processes and their open files, already narrowed by `sel` where
    /// the backend can do so cheaply. The portable [`selection`](crate::selection)
    /// engine applies the authoritative filtering afterwards, so a backend may
    /// also return a superset.
    fn gather(&self, sel: &Selection) -> Result<Vec<Process>, BackendError>;
}
