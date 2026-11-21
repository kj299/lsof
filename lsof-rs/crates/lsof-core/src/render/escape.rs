//! Terminal-safe rendering of text an unprivileged user chooses — the portable
//! equivalent of lsof's `safestrprt()`, `safestrprtn()` and `safepup()` in
//! `lib/misc.c`.
//!
//! A process names itself (`prctl(PR_SET_NAME)`, the image's basename), and
//! anyone who can create a file or a socket names it. COMMAND and NAME are
//! therefore the two cells whose bytes a local user controls outright. Printed
//! raw, an ESC sequence in either drives the terminal of whoever runs lsof —
//! clears the screen, rewrites earlier rows, retitles the window — and a bare
//! `\r` lets a row overwrite its own beginning. The C closes this by printing
//! every byte `isprint()` rejects in a visible form; this module reproduces its
//! exact output so the Linux differential can check it against the real thing.
//!
//! | input | output | rule |
//! |---|---|---|
//! | `\b` `\f` `\n` `\r` `\t` | `\b` `\f` `\n` `\r` `\t` | C-style escape |
//! | other `U+0000..=U+001F` | `^@` `^A` … `^[` … `^_` | caret + (c + 0x40) |
//! | `U+007F` (DEL) | `\x7f` | hex |
//! | space | `\x20` | COMMAND ([`Escaper::command`]) and [`Escaper::text_spaced`] |
//! | `\` | `\\` | Unix style only — see below |
//! | C1 controls `U+0080..=U+009F`, `U+2028`, `U+2029` | `\xc2\x9b` … | each UTF-8 byte in hex |
//! | any other non-ASCII | raw in NAME/`-F`; `\xNN` per byte in COMMAND | see below |
//!
//! Two printers because the C has two. The COMMAND column goes through
//! `safestrprtn(…, flags = 2)`: a space counts as unprintable (so
//! `awk '{print $1}'` still gets the whole command) and there is no
//! wide-character path, so the column is always pure ASCII and its width is its
//! byte count. NAME, USER and every `-F` value go through `safestrprt(…, 0)`:
//! spaces are text, and in a UTF-8 locale a printable multibyte character is
//! passed through — only what `iswprint()` rejects is escaped, byte by byte.
//! glibc's `iswprint()` rejects the C1 controls and the two Unicode line
//! separators, so that is the set escaped here, independent of any locale.
//!
//! The backslash is escaped so the output is unambiguous: a name that literally
//! contains the two characters `\` `n` must not read like one that contained a
//! newline. That is right where `\` is a rare character and wrong where it is
//! the path separator — on Windows every NAME is `C:\…`, and doubling each
//! separator would make the common case unreadable to close an ambiguity the
//! JSON formats (`-J`/`-j`, the C's `json_puts_escaped()` rules) already close. So the
//! backslash is the one platform-dependent rule; the CLI passes
//! [`Escaper::for_host`].
//!
//! Nothing is allocated when nothing needs escaping — the overwhelmingly
//! common case — because the borrowing functions return [`Cow::Borrowed`].

use std::borrow::Cow;

/// The one platform-dependent rule (whether `\` is escaped) plus the methods
/// that apply the table above.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Escaper {
    /// Escape `\` as `\\`. The C always does; on Windows `\` is the path
    /// separator and stays raw.
    pub backslash: bool,
}

impl Escaper {
    /// The C's behavior on every platform it runs on.
    pub const UNIX: Escaper = Escaper { backslash: true };
    /// Backslash is the path separator, so it is text.
    pub const WINDOWS: Escaper = Escaper { backslash: false };

    /// The style for the platform this binary was built for.
    pub const fn for_host() -> Escaper {
        if cfg!(windows) {
            Escaper::WINDOWS
        } else {
            Escaper::UNIX
        }
    }

    /// NAME, USER and `-F` values: `safestrprt(s, fs, 0)`. Spaces and printable
    /// Unicode pass through.
    pub fn text<'a>(&self, s: &'a str) -> Cow<'a, str> {
        escape(s, Mode::Text, self.backslash)
    }

    /// `safestrprt(s, fs, 2)`: [`Escaper::text`] with a space escaped too,
    /// `\x20`, and printable Unicode still passed through. The C quotes the
    /// `-c` name it refuses as too long this way (`lib/lsof.c:178-182`);
    /// measured, `-c 'é a\\<DEL><U+009B>b…'` prints `é\x20a\\\x7f\xc2\x9bb…`.
    pub fn text_spaced<'a>(&self, s: &'a str) -> Cow<'a, str> {
        escape(s, Mode::TextSpaced, self.backslash)
    }

    /// [`Escaper::text`] for a name that need not be UTF-8 — a file name, a
    /// link's target — as `safestrprt()` prints one in a UTF-8 locale: where
    /// `mblen()` finds no character, the byte is printed as `\xNN`, and the
    /// rest as text. `nu/\xfe`, measured.
    pub fn bytes<'a>(&self, b: &'a [u8]) -> Cow<'a, str> {
        if let Ok(s) = std::str::from_utf8(b) {
            return self.text(s);
        }
        let mut out = String::with_capacity(b.len() + 8);
        for chunk in b.utf8_chunks() {
            out.push_str(&self.text(chunk.valid()));
            for &byte in chunk.invalid() {
                push_hex(&mut out, byte);
            }
        }
        Cow::Owned(out)
    }

    /// The COMMAND column: `safestrprtn(s, width, fs, 2)` without the width.
    /// Whitespace-free and pure ASCII, so the column splits and measures as
    /// bytes.
    pub fn command<'a>(&self, s: &'a str) -> Cow<'a, str> {
        escape(s, Mode::Command, self.backslash)
    }

    /// [`Escaper::command`] cut to at most `width` printed bytes — lsof's
    /// `+c`. Like `safestrprtn()`, an escape that does not fit whole is not
    /// started: the cell never ends in half an escape that a reader would take
    /// for a different character. An escape is one **byte's**, as the C's
    /// printer walks bytes (`Escaper::command_cut`): of a character of
    /// several bytes, the bytes that fit are printed (`\xe6\x97` of `日`
    /// in a cell of nine, measured).
    pub fn command_truncated(&self, s: &str, width: usize) -> String {
        self.command_bytes_truncated(s.as_bytes(), width)
    }

    /// `safestrprtn(b, width, fs, 2)`'s walk (`lib/misc.c:1486-1499`), which
    /// COMMAND and TASKCMD are printed by (`src/print.c:831, 871`): a byte
    /// at a time, each either one printed byte or one escape, and the walk
    /// ends at the first that does not fit in what is left of `width`
    /// (`if ((i + cl) > len) break;`), never skipping it for a later,
    /// shorter one. It has no multibyte path, so every byte that is not
    /// ASCII is an escape of its own, `\xNN`, four wide, whether or not it
    /// is part of a character: `é` in a cell with four left is `\xc3`.
    /// lsof-rs had taken a character for one unit, eight wide for `é`, and
    /// printed none of it (a process named `日本語` had an empty COMMAND
    /// cell).
    ///
    /// `put` is handed each byte that fits, in order; the bytes' printed
    /// width is returned.
    fn command_cut(&self, b: &[u8], width: usize, mut put: impl FnMut(u8)) -> usize {
        let mut used = 0usize;
        for &byte in b {
            let w = if byte.is_ascii() {
                escaped_width(char::from(byte), Mode::Command, self.backslash)
            } else {
                4
            };
            if used + w > width {
                break;
            }
            used += w;
            put(byte);
        }
        used
    }
}

impl Escaper {
    /// [`Escaper::command`] for a command that need not be UTF-8: each byte
    /// that is no character is `\xNN`, as `safestrprtn()` prints it.
    pub fn command_bytes<'a>(&self, b: &'a [u8]) -> Cow<'a, str> {
        if let Ok(s) = std::str::from_utf8(b) {
            return self.command(s);
        }
        let mut out = String::with_capacity(b.len() + 8);
        for chunk in b.utf8_chunks() {
            out.push_str(&self.command(chunk.valid()));
            for &byte in chunk.invalid() {
                push_hex(&mut out, byte);
            }
        }
        Cow::Owned(out)
    }

    /// [`Escaper::command_truncated`] for a command that need not be UTF-8:
    /// every byte that is not ASCII is a four-byte escape, cut whole or not
    /// at all, whether or not it is part of a character
    /// (`Escaper::command_cut`).
    pub fn command_bytes_truncated(&self, b: &[u8], width: usize) -> String {
        let mut out = String::with_capacity(width.min(b.len().saturating_mul(4)));
        self.command_cut(b, width, |byte| {
            if byte.is_ascii() {
                push(&mut out, char::from(byte), Mode::Command, self.backslash);
            } else {
                push_hex(&mut out, byte);
            }
        });
        out
    }
}

impl Escaper {
    /// [`Escaper::text`] into `out` as `safestrprt()` prints it, a call at a
    /// time: a `putc()` for each byte of a character it prints, a `fputs()`
    /// for each escape.
    pub fn text_calls(&self, s: &str, out: &mut crate::render::Calls) {
        for c in s.chars() {
            unit_calls(c, Mode::Text, self.backslash, out);
        }
    }

    /// [`Escaper::bytes`] into `out`, a call at a time.
    pub fn bytes_calls(&self, b: &[u8], out: &mut crate::render::Calls) {
        for chunk in b.utf8_chunks() {
            self.text_calls(chunk.valid(), out);
            for &byte in chunk.invalid() {
                let mut e = String::with_capacity(4);
                push_hex(&mut e, byte);
                out.call(e);
            }
        }
    }

    /// [`Escaper::command_bytes_truncated`] into `out`, a call at a time
    /// (`safestrprtn()`'s `putc()`s and `fputs()`s); how many bytes it
    /// printed.
    pub fn command_bytes_truncated_calls(
        &self,
        b: &[u8],
        width: usize,
        out: &mut crate::render::Calls,
    ) -> usize {
        self.command_cut(b, width, |byte| {
            if byte.is_ascii() {
                unit_calls(char::from(byte), Mode::Command, self.backslash, out);
            } else {
                let mut e = String::with_capacity(4);
                push_hex(&mut e, byte);
                out.call(e);
            }
        })
    }

    /// [`Escaper::command`] of a string cut to `width`, a call at a time.
    pub fn command_truncated_calls(
        &self,
        s: &str,
        width: usize,
        out: &mut crate::render::Calls,
    ) -> usize {
        self.command_bytes_truncated_calls(s.as_bytes(), width, out)
    }
}

/// `c` printed as the C's printer prints it, into `out`: a `putc()` for
/// each of its bytes where it passes, one `fputs()` for an ASCII escape,
/// one for each byte's `\xNN` where a multibyte character is escaped.
fn unit_calls(c: char, mode: Mode, backslash: bool, out: &mut crate::render::Calls) {
    let mut buf = [0u8; 4];
    let bytes = c.encode_utf8(&mut buf).as_bytes();
    if escaped_width(c, mode, backslash) == 1 {
        out.each_byte(bytes);
        return;
    }
    if c.is_ascii() && c != ' ' && c != '\x7f' {
        let mut e = String::with_capacity(2);
        push(&mut e, c, mode, backslash);
        out.call(e);
        return;
    }
    for &b in bytes {
        let mut e = String::with_capacity(4);
        push_hex(&mut e, b);
        out.call(e);
    }
}

/// Which of the C's two printers is being mirrored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// `safestrprt(…, 0)`: space is text, printable Unicode passes.
    Text,
    /// `safestrprt(…, 2)`: space is unprintable, printable Unicode passes.
    TextSpaced,
    /// `safestrprtn(…, 2)`: space is unprintable, only ASCII passes.
    Command,
}

/// Printed width of `c` in this mode: 1 when it passes through, else the
/// length of its escape.
fn escaped_width(c: char, mode: Mode, backslash: bool) -> usize {
    match c {
        '\\' if backslash => 2,
        ' ' if mode != Mode::Text => 4,
        c if (c as u32) < 0x20 => 2,
        c if c.is_ascii() && c != '\x7f' => 1,
        // DEL, or a non-ASCII character that is escaped byte by byte.
        c if c == '\x7f' || mode == Mode::Command || is_unprintable_unicode(c) => 4 * c.len_utf8(),
        _ => 1,
    }
}

/// What glibc's `iswprint()` rejects among the characters a `&str` can hold:
/// the C0 and C1 control blocks (`char::is_control`, category Cc) and the two
/// Unicode line separators (categories Zl and Zp). Everything else that is
/// non-ASCII is text in a UTF-8 locale. JSON escapes the same set
/// (`render/json.rs`), so a name or command a terminal cannot show raw in the
/// table is never raw in `-J`/`-j` either.
pub(crate) fn is_unprintable_unicode(c: char) -> bool {
    c.is_control() || c == '\u{2028}' || c == '\u{2029}'
}

fn escape(s: &str, mode: Mode, backslash: bool) -> Cow<'_, str> {
    // Borrow when nothing needs escaping; that is almost every cell.
    let Some(first) = s
        .char_indices()
        .find(|&(_, c)| escaped_width(c, mode, backslash) != 1)
        .map(|(i, _)| i)
    else {
        return Cow::Borrowed(s);
    };
    let mut out = String::with_capacity(s.len() + 8);
    out.push_str(&s[..first]);
    for c in s[first..].chars() {
        push(&mut out, c, mode, backslash);
    }
    Cow::Owned(out)
}

/// Append `c` to `out` in printed form — `safepup()`, with the pass-through
/// case folded in.
fn push(out: &mut String, c: char, mode: Mode, backslash: bool) {
    if escaped_width(c, mode, backslash) == 1 {
        out.push(c);
        return;
    }
    match c {
        '\x08' => out.push_str("\\b"),
        '\x0c' => out.push_str("\\f"),
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' => out.push_str("\\t"),
        '\\' => out.push_str("\\\\"),
        c if (c as u32) < 0x20 => {
            out.push('^');
            out.push((c as u8 + 0x40) as char);
        }
        c => {
            // Space (COMMAND, `text_spaced`), DEL, and every escaped
            // non-ASCII character: the C prints `\x%02x` for each byte it
            // could not print.
            let mut buf = [0u8; 4];
            for b in c.encode_utf8(&mut buf).bytes() {
                push_hex(out, b);
            }
        }
    }
}

/// `\x%02x`, `safepup()`'s form for a byte it cannot print.
fn push_hex(out: &mut String, b: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push_str("\\x");
    out.push(HEX[usize::from(b >> 4)] as char);
    out.push(HEX[usize::from(b & 0x0f)] as char);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pieces(f: impl FnOnce(&mut crate::render::Calls)) -> Vec<String> {
        struct Log(Vec<String>);
        impl std::io::Write for Log {
            fn write(&mut self, d: &[u8]) -> std::io::Result<usize> {
                self.0.push(String::from_utf8_lossy(d).into_owned());
                Ok(d.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut calls = crate::render::Calls::new();
        f(&mut calls);
        let mut log = Log(Vec::new());
        calls.write_to(&mut log).unwrap();
        log.0
    }

    /// `safestrprt()` a call at a time: a `putc()` for each byte of a
    /// character it prints (each of `é`'s two), one `fputs()` for an
    /// escape, one for each byte's `\xNN` of an escaped multibyte one; and
    /// `safestrprtn()`'s cut. Text already printed is cut the same way, a
    /// `^` before `@` to `_` taken for an escape.
    #[test]
    fn escaped_text_is_cut_where_the_cs_calls_cut_it() {
        assert_eq!(
            pieces(|c| U.text_calls("a\u{1b}\\é\u{9b} ", c)),
            ["a", "^[", "\\\\", "\u{fffd}", "\u{fffd}", "\\xc2", "\\x9b", " "]
        );
        assert_eq!(
            pieces(|c| {
                U.bytes_calls(b"x\xffy", c);
            }),
            ["x", "\\xff", "y"]
        );
        assert_eq!(
            pieces(|c| {
                let used = U.command_bytes_truncated_calls(b"a b\x01c", 5, c);
                assert_eq!(used, 5);
            }),
            ["a", "\\x20"]
        );
        assert_eq!(
            pieces(|c| c.printed("x\\n^Ay\\x7f^a")),
            ["x", "\\n", "^A", "y", "\\x7f", "^", "a"]
        );
    }

    const U: Escaper = Escaper::UNIX;
    const W: Escaper = Escaper::WINDOWS;

    #[test]
    fn plain_text_is_borrowed_not_copied() {
        for s in [
            "",
            "sleep",
            "/usr/lib/x86_64-linux-gnu/libc.so.6",
            "café",
            "C:",
        ] {
            assert!(matches!(U.text(s), Cow::Borrowed(_)), "{s:?}");
            assert!(
                matches!(U.command(s), Cow::Borrowed(_)) || !s.is_ascii(),
                "{s:?}"
            );
        }
        // A space is text in NAME and unprintable in COMMAND.
        assert!(matches!(U.text("a b"), Cow::Borrowed(_)));
        assert_eq!(U.command("a b"), "a\\x20b");
        // On Windows a path is plain text.
        assert!(matches!(W.text("C:\\Windows\\System32"), Cow::Borrowed(_)));
    }

    #[test]
    fn safepup_table_named_escapes_and_carets() {
        assert_eq!(U.text("\x08\x0c\n\r\t"), "\\b\\f\\n\\r\\t");
        assert_eq!(U.text("\x00\x01\x1b\x1f"), "^@^A^[^_");
        assert_eq!(U.text("\x7f"), "\\x7f");
        // The ANSI clear-screen the fuzz target's finding pointed at.
        assert_eq!(U.text("h\x1b[2Jz"), "h^[[2Jz");
    }

    #[test]
    fn a_command_of_bytes_escapes_each_byte_that_is_no_character() {
        assert_eq!(U.command_bytes(b"abc"), "abc");
        assert_eq!(U.command_bytes(b"a\xffb c"), "a\\xffb\\x20c");
        assert_eq!(U.command_bytes("é".as_bytes()), "\\xc3\\xa9");
        assert_eq!(U.command_bytes(b"\xc3\xa9\xff"), "\\xc3\\xa9\\xff");
        // Cut whole: `\xff` needs four.
        assert_eq!(U.command_bytes_truncated(b"ab\xffcd", 5), "ab");
        assert_eq!(U.command_bytes_truncated(b"ab\xffcd", 6), "ab\\xff");
        assert_eq!(U.command_bytes_truncated(b"ab\xffcd", 9), "ab\\xffcd");
        assert_eq!(U.command_bytes_truncated(b"a b\xff", 9), "a\\x20b");
        assert_eq!(U.command_bytes_truncated(b"sleep", 3), "sle");
    }

    #[test]
    fn bytes_escape_what_is_not_utf8_byte_by_byte() {
        // Measured: `+d nu` reports `nu/\xfe` for a file named 0xfe.
        assert_eq!(U.bytes(b"nu/\xfe"), "nu/\\xfe");
        // Valid UTF-8 is `text`, borrowed when nothing needs escaping.
        assert!(matches!(U.bytes("café".as_bytes()), Cow::Borrowed("café")));
        assert_eq!(U.bytes(b"a\x1bb"), "a^[b");
        // A cut sequence is each of its bytes; what follows it is text again,
        // escaped by the same rules.
        assert_eq!(U.bytes(b"\xe2\x82(\\\xa1\xc3\xa9"), "\\xe2\\x82(\\\\\\xa1é");
        assert_eq!(W.bytes(b"C:\\\xff"), "C:\\\\xff");
    }

    #[test]
    fn backslash_is_the_platform_rule() {
        assert_eq!(U.text("a\\n"), "a\\\\n"); // literal `\` `n` stays distinguishable
        assert_eq!(W.text("a\\n"), "a\\n");
        assert_eq!(U.command("C:\\x"), "C:\\\\x");
        assert_eq!(W.command("C:\\x"), "C:\\x");
    }

    #[test]
    fn command_is_pure_ascii_text_keeps_printable_unicode() {
        // COMMAND: safestrprtn has no wide-character path — every non-ASCII
        // byte is hex. NAME/-F: a UTF-8 locale prints é; iswprint() rejects
        // the C1 controls (here U+009B, the 8-bit CSI) and U+2028/U+2029.
        assert_eq!(U.command("é"), "\\xc3\\xa9");
        assert_eq!(U.text("é"), "é");
        assert_eq!(U.text("a\u{9b}b"), "a\\xc2\\x9bb");
        assert_eq!(U.command("a\u{9b}b"), "a\\xc2\\x9bb");
        assert_eq!(
            U.text("a\u{2028}b\u{2029}"),
            "a\\xe2\\x80\\xa8b\\xe2\\x80\\xa9"
        );
        assert_eq!(U.text("\u{200b}\u{202e}"), "\u{200b}\u{202e}"); // Cf: glibc says printable
        assert_eq!(U.text("日本"), "日本");
        assert_eq!(U.command("日"), "\\xe6\\x97\\xa5");
    }

    #[test]
    fn the_differential_fixture_comm_byte_for_byte() {
        // linux_diff.py's fixture C: 15 bytes, one of each class, exactly what
        // the C prints for it in COMMAND (table) and in `-Fc` (text).
        let comm = "h\x1b[2J\r \\\x7f\t\u{e9}\u{9b}z";
        assert_eq!(comm.len(), 15, "TASK_COMM_LEN - 1");
        assert_eq!(
            U.command(comm),
            "h^[[2J\\r\\x20\\\\\\x7f\\t\\xc3\\xa9\\xc2\\x9bz"
        );
        assert_eq!(U.text(comm), "h^[[2J\\r \\\\\\x7f\\t\u{e9}\\xc2\\x9bz");
    }

    #[test]
    fn truncation_counts_printed_bytes_and_never_splits_an_escape() {
        // "a^[b": width 3 keeps the whole escape; width 2 cannot start it.
        assert_eq!(U.command_truncated("a\x1bb", 4), "a^[b");
        assert_eq!(U.command_truncated("a\x1bb", 3), "a^[");
        assert_eq!(U.command_truncated("a\x1bb", 2), "a");
        assert_eq!(U.command_truncated("a\x1bb", 0), "");
        // A 4-byte escape at the boundary is dropped whole (the C breaks, it
        // does not skip to a later, shorter unit).
        assert_eq!(U.command_truncated("a bc", 4), "a");
        assert_eq!(U.command_truncated("a bc", 5), "a\\x20");
        assert_eq!(U.command_truncated("verylongcommandname.exe", 4), "very");
        assert_eq!(U.command_truncated("ab", 99), "ab");
        // Every result is a prefix of the untruncated form and within width.
        let s = "x\u{e9}\t \\y";
        let full = U.command(s);
        for w in 0..=full.len() + 1 {
            let t = U.command_truncated(s, w);
            assert!(t.len() <= w && full.starts_with(&t), "w={w} {t:?}");
        }
    }

    /// `safestrprtn()` walks bytes (`lib/misc.c:1486-1499`): each byte of a
    /// character of several is an escape of its own, four wide, and the
    /// walk ends at the first that does not fit. Measured against the C,
    /// each in COMMAND: `日本語` in the default nine columns is `\xe6\x97`,
    /// `naïve-app` is `na\xc3`, `é` under `+c 1` (a cell of seven, the
    /// title's width) is `\xc3`, `aé` under `+c 4` is `a\xc3`. lsof-rs took
    /// a character for one escape and printed none of it.
    #[test]
    fn a_command_is_cut_between_the_bytes_of_a_character() {
        assert_eq!(U.command_truncated("日本語", 9), "\\xe6\\x97");
        assert_eq!(U.command_truncated("naïve-app", 9), "na\\xc3");
        assert_eq!(U.command_truncated("é", 7), "\\xc3");
        assert_eq!(U.command_truncated("aé", 7), "a\\xc3");
        // Width by width: an escape is started only where all four of its
        // bytes fit.
        for (width, want) in [
            (0, ""),
            (3, ""),
            (4, "\\xc3"),
            (7, "\\xc3"),
            (8, "\\xc3\\xa9"),
            (9, "\\xc3\\xa9z"),
        ] {
            assert_eq!(U.command_truncated("éz", width), want, "width {width}");
        }
        assert_eq!(U.command_truncated("aé", 4), "a");
        assert_eq!(U.command_truncated("aé", 5), "a\\xc3");
        // The walk ends there: a later, shorter unit is not printed in the
        // room the escape left.
        assert_eq!(U.command_truncated("éb", 5), "\\xc3");
        assert_eq!(U.command_truncated("aéb", 4), "a");
        // A command that is not UTF-8 is walked the same way, byte by
        // byte, whether or not its bytes make a character.
        assert_eq!(
            U.command_bytes_truncated("日本語".as_bytes(), 9),
            "\\xe6\\x97"
        );
        assert_eq!(U.command_bytes_truncated(b"\xe6\x97\xff", 9), "\\xe6\\x97");
        assert_eq!(
            U.command_bytes_truncated(b"\xff\xe6\x97\xa5", 9),
            "\\xff\\xe6"
        );
        // Backslash or no backslash, the bytes are cut alike.
        assert_eq!(W.command_truncated("日本語", 9), "\\xe6\\x97");
        // A call at a time, as the C's `fputs()`s make it, and the width
        // used, which the cell is padded from.
        assert_eq!(
            pieces(|c| {
                let used = U.command_truncated_calls("日本語", 9, c);
                assert_eq!(used, 8);
            }),
            ["\\xe6", "\\x97"]
        );
        assert_eq!(
            pieces(|c| {
                let used = U.command_bytes_truncated_calls("naïve-app".as_bytes(), 9, c);
                assert_eq!(used, 6);
            }),
            ["n", "a", "\\xc3"]
        );
        // Every cut is a prefix of the whole, within its width, and the
        // longest one that ends between two of the C's units.
        for s in ["日本語", "naïve-app", "x\u{e9}\t \\y\u{9b}z", "\u{1f600}!"] {
            let full = U.command(s);
            for w in 0..=full.len() + 1 {
                let t = U.command_truncated(s, w);
                assert!(t.len() <= w && full.starts_with(&t), "{s:?} w={w} {t:?}");
                assert_eq!(t, U.command_bytes_truncated(s.as_bytes(), w));
                // Nothing more would have fitted: what follows the cut is
                // an escape too wide for what is left, or nothing.
                let rest = &full[t.len()..];
                let next = if rest.starts_with("\\x") {
                    4
                } else if rest.starts_with('\\') || rest.starts_with('^') {
                    2
                } else {
                    usize::from(!rest.is_empty())
                };
                assert!(
                    next == 0 || t.len() + next > w,
                    "{s:?} w={w} {t:?} {rest:?}"
                );
            }
        }
    }

    /// `safestrprt(…, 2)`, measured on the C's `-c` length message: a space
    /// is `\x20`, é stays raw, the backslash, DEL and U+009B as in `text`.
    #[test]
    fn text_spaced_is_safestrprt_flags_2() {
        assert_eq!(
            U.text_spaced("\u{e9} a\\\x7f\u{9b}b"),
            "\u{e9}\\x20a\\\\\\x7f\\xc2\\x9bb"
        );
        assert_eq!(U.text_spaced("a ba b"), "a\\x20ba\\x20b");
        assert_eq!(U.text_spaced("aa\x1b[2J"), "aa^[[2J");
        assert!(matches!(U.text_spaced("sleep"), Cow::Borrowed(_)));
        assert!(matches!(U.text_spaced("café"), Cow::Borrowed(_)));
    }

    #[test]
    fn output_never_holds_a_control_character() {
        let hostile: String = (0u8..=0x9f)
            .map(char::from)
            .chain("\u{2028}\u{2029}\\ é".chars())
            .collect();
        for e in [U, W] {
            for out in [
                e.text(&hostile),
                e.command(&hostile),
                e.text_spaced(&hostile),
            ] {
                assert!(
                    !out.chars()
                        .any(|c| c.is_control() || c == '\u{2028}' || c == '\u{2029}'),
                    "{out:?}"
                );
            }
            let cmd = e.command(&hostile);
            assert!(cmd.is_ascii() && !cmd.contains(' '), "{cmd:?}");
            assert!(!e.text_spaced(&hostile).contains(' '));
        }
    }
}
