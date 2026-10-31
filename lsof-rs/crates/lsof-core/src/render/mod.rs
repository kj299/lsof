//! Output renderers — the portable equivalent of lsof's `src/print.c`.
//!
//! Three formats are supported, matching lsof so existing scripts keep working:
//! the default human-readable [`table`], the `-F` machine-readable [`fields`]
//! output, and [`json`] (`-J` / `-j`), the C's JSON schema since lsof-rs
//! 2.0.0.
//!
//! Text a local user chooses — COMMAND, NAME, and USER — never reaches the
//! terminal raw: the table and `-F` renderers pass it through [`escape`]
//! (lsof's `safestrprt()`), and the JSON renderers escape per the JSON grammar
//! and every other control character besides.

pub mod escape;
pub mod fflags;
pub mod fields;
pub mod json;
pub mod table;

use crate::model::{AccessMode, FileType, OpenFile, Protocol, SocketInfo};
use crate::selection::TcpInfoFlags;

pub use escape::Escaper;
pub use fflags::FileFlags;
pub use table::TableOpts;

/// How many decimal digits an offset may have before it is printed in hex —
/// the C's `OFFDECDIG` (`lib/common.h`), which `-o <digits>` overrides. An
/// `i32` because the C's `OffDecDig` is an `int`, and how it wraps is what
/// [`offset_text`] reproduces.
pub const DEFAULT_OFFSET_DIGITS: i32 = 8;

/// An offset as lsof writes it: `0t<decimal>`, or `0x<hex>` once the decimal
/// form has more than `digits` digits (`print.c`: `if (OffDecDig && len >
/// (OffDecDig + 2))`, the 2 being the `0t`). `digits == 0` is `-o 0`, which
/// the C reads as "no limit" because the test is `OffDecDig &&`.
///
/// Measured on an fd seeked to 123456789: `0x75bcd15` by default, `0t123456789`
/// under `-o 9` or `-o 0`.
///
/// `digits` is the C's `int`, and so is the sum: `OffDecDig + 2` wraps past
/// `INT_MAX`, so a limit of 2147483646 or 2147483647 (or one the parser
/// wrapped negative, see `-o` in `args.rs`) prints EVERY offset in hex, zero
/// included — and the C's `%#llx` writes zero as a bare `0`, with no `0x`
/// (DIVERGENCES 117, measured: `-o 2147483646 -o` prints `0`, `0xc`, `0x63`
/// for offsets 0, 12 and 99, where `-o 2147483645 -o` prints `0t0`, `0t12`,
/// `0t99`). Below that, zero never reaches the hex branch: `0t0` is three
/// characters, and a limit of 0 is no limit.
pub fn offset_text(offset: u64, digits: i32) -> String {
    let dec = format!("0t{offset}");
    // At most 22 bytes (`0t` and twenty digits), so the conversion holds.
    let len = i32::try_from(dec.len()).unwrap_or(i32::MAX);
    if digits != 0 && len > digits.wrapping_add(2) {
        if offset == 0 {
            "0".to_string()
        } else {
            format!("{offset:#x}")
        }
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
    /// `-J` (one document) or `-j` (JSON Lines), with what `-F`, `-T` and
    /// `-f` chose for it ([`json::JsonOpts`]).
    Json(JsonFormat),
}

/// What a JSON run prints, owned: [`json::JsonOpts`] borrows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsonFormat {
    /// `-j`: one object per file.
    pub lines: bool,
    /// The `-F` letters, `None` for the C's default set.
    pub only: Option<Vec<char>>,
    /// How the `flags` key prints, or whether at all.
    pub file_flags: FileFlags,
    /// Which `tcp_info` members print.
    pub tcp_show: TcpInfoFlags,
}

impl Format {
    /// The between-cycle separator lsof prints in repeat (`-r`) mode, chosen by
    /// format to match `src/main.c`: `=======` for the table, the `m` marker
    /// field for `-F` (NL-terminated, or `\0\n` under `-F0` so a NUL-splitting
    /// parser still finds the record boundary), nothing after a `-J` document,
    /// which ends in its own newline, and a blank line after each `-j` cycle,
    /// as the C prints one (`main.c:1527-1531`; measured, an empty `-j` cycle
    /// is that line alone). Each non-empty value carries its own trailing NL.
    pub fn repeat_marker(&self) -> &'static str {
        match self {
            Format::Table => "=======\n",
            Format::Fields { nul: true, .. } => "m\0\n",
            Format::Fields { nul: false, .. } => "m\n",
            Format::Json(j) if j.lines => "\n",
            Format::Json(_) => "",
        }
    }
}

// What one row shows, decided once for every renderer that shows it, so `-F`,
// JSON and the table cannot drift apart.

/// Whether the row's NODE is its protocol (`-F P`, JSON `protocol`) rather
/// than its inode (`-F i`, JSON `inode`): the C's `Lf->inp_ty`, 2 for every
/// socket but an AF_UNIX one, whose inode is reported like a file's
/// (`print_tcptpi()` splits on `Lf->type == LSOF_FILE_UNIX`). A raw or `sock`
/// row has no [`SocketInfo`] and so prints its inode, as the C's does
/// (`inp_ty` 1, `dsock.c:3536-3580`); [`OpenFile::is_socket`] would not say so.
pub(crate) fn node_is_protocol(f: &OpenFile) -> bool {
    f.socket.is_some() && f.file_type != FileType::Unix
}

/// The device character text (`-F d`, JSON `device`): only a row with no
/// file-system device has one. On Linux the two are exclusive — the dialect
/// sets a device string (`Lf->dev_ch`) only for a row with no `st_dev`, such
/// as a socket — and `-F D`/`device_number` print the number otherwise.
pub(crate) fn device_text(f: &OpenFile) -> Option<&str> {
    match f.fs_device {
        None => f.device.as_deref(),
        Some(_) => None,
    }
}

/// The access letter, `None` where it is blank: `-F a` prints a blank as a
/// space, JSON leaves `access` out.
pub(crate) fn access_code(f: &OpenFile) -> Option<char> {
    match f.access {
        AccessMode::Unknown => None,
        mode => Some(mode.code()),
    }
}

/// The lock letter, `None` where it is blank, as [`access_code`].
pub(crate) fn lock_code(f: &OpenFile) -> Option<char> {
    f.lock.map(|k| k.code())
}

/// The socket of a row the C keeps a TCP/TPI record for (`Lf->lts.type >=
/// 0`), which the Linux dialect sets for TCP, UDP, UDP-Lite and AF_UNIX
/// sockets and for nothing else: the table's state/queue suffix and JSON's
/// `tcp_info` object are printed for these rows alone. A packet, raw or ICMP
/// row has none (DIVERGENCES 35).
pub(crate) fn tcp_info_socket(f: &OpenFile) -> Option<&SocketInfo> {
    let sock = f.socket.as_deref()?;
    let annotated = matches!(
        sock.protocol,
        Protocol::Tcp | Protocol::Udp | Protocol::UdpLite
    ) || f.file_type == FileType::Unix;
    annotated.then_some(sock)
}
