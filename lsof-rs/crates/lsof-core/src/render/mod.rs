//! Output renderers — the portable equivalent of lsof's `src/print.c`.
//!
//! Three formats are supported, matching lsof so existing scripts keep working:
//! the default human-readable [`table`], the `-F` machine-readable [`fields`]
//! output, and [`json`] (`-J` / `-j`).
//!
//! Text a local user chooses — COMMAND, NAME, and USER — never reaches the
//! terminal raw: the table and `-F` renderers pass it through [`escape`]
//! (lsof's `safestrprt()`), and the JSON renderers escape per the JSON grammar.

pub mod escape;
pub mod fields;
pub mod json;
pub mod table;

pub use escape::Escaper;
pub use table::TableOpts;

/// How many decimal digits an offset may have before it is printed in hex —
/// the C's `OFFDECDIG` (`lib/common.h`), which `-o <digits>` overrides.
pub const DEFAULT_OFFSET_DIGITS: usize = 8;

/// An offset as lsof writes it: `0t<decimal>`, or `0x<hex>` once the decimal
/// form has more than `digits` digits (`print.c`: `if (OffDecDig && len >
/// (OffDecDig + 2))`, the 2 being the `0t`). `digits == 0` is `-o 0`, which
/// the C reads as "no limit" because the test is `OffDecDig &&`.
///
/// Measured on an fd seeked to 123456789: `0x75bcd15` by default, `0t123456789`
/// under `-o 9` or `-o 0`. Zero never reaches the hex branch (`0t0` is three
/// characters, and a limit of 0 is no limit), so the C's `%#x` printing a bare
/// `0` for zero needs no mirror here.
pub fn offset_text(offset: u64, digits: usize) -> String {
    let dec = format!("0t{offset}");
    if digits != 0 && dec.len() > digits.saturating_add(2) {
        format!("{offset:#x}")
    } else {
        dec
    }
}

/// Selected output format.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum Format {
    /// Default human-readable columnar table.
    #[default]
    Table,
    /// `-F` field output. `nul` selects NUL (`\0`) line termination (`-F0`);
    /// `only`, when `Some`, restricts output to the requested field letters
    /// (the structural `p`/`f` markers are always emitted).
    Fields { nul: bool, only: Option<Vec<char>> },
    /// `-J` aggregated JSON object.
    Json,
    /// `-j` JSON Lines (one object per file).
    JsonLines,
}

impl Format {
    /// The between-cycle separator lsof prints in repeat (`-r`) mode, chosen by
    /// format to match `src/main.c`: `=======` for the table, the `m` marker
    /// field for `-F` (NL-terminated, or `\0\n` under `-F0` so a NUL-splitting
    /// parser still finds the record boundary), and nothing for JSON, whose
    /// objects already self-delimit ("JSON modes handle their own cycle
    /// separation"). Each non-empty value carries its own trailing NL.
    pub fn repeat_marker(&self) -> &'static str {
        match self {
            Format::Table => "=======\n",
            Format::Fields { nul: true, .. } => "m\0\n",
            Format::Fields { nul: false, .. } => "m\n",
            Format::Json | Format::JsonLines => "",
        }
    }
}
