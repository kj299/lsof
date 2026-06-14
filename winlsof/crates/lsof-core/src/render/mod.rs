//! Output renderers — the portable equivalent of lsof's `src/print.c`.
//!
//! Three formats are supported, matching lsof so existing scripts keep working:
//! the default human-readable [`table`], the `-F` machine-readable [`fields`]
//! output, and [`json`] (`-J` / `-j`).

pub mod fields;
pub mod json;
pub mod table;

/// Selected output format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Format {
    /// Default human-readable columnar table.
    #[default]
    Table,
    /// `-F` field output. The `nul` flag selects NUL (`\0`) line termination
    /// (`-F0`) instead of newline.
    Fields { nul: bool },
    /// `-J` aggregated JSON object.
    Json,
    /// `-j` JSON Lines (one object per file).
    JsonLines,
}
