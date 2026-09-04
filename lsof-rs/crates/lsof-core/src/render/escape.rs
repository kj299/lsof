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
//! | space | `\x20` | COMMAND only ([`Escaper::command`]) |
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
//! JSON formats (`-J`/`-j`, escaped per the JSON grammar) already close. So the
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

    /// The COMMAND column: `safestrprtn(s, width, fs, 2)` without the width.
    /// Whitespace-free and pure ASCII, so the column splits and measures as
    /// bytes.
    pub fn command<'a>(&self, s: &'a str) -> Cow<'a, str> {
        escape(s, Mode::Command, self.backslash)
    }

    /// [`Escaper::command`] cut to at most `width` printed bytes — lsof's
    /// `+c`. Like `safestrprtn()`, an escape that does not fit whole is not
    /// started: the cell never ends in half an escape that a reader would take
    /// for a different character.
    pub fn command_truncated(&self, s: &str, width: usize) -> String {
        let mut out = String::with_capacity(width.min(s.len() + 8));
        let mut used = 0;
        for c in s.chars() {
            let w = escaped_width(c, Mode::Command, self.backslash);
            if used + w > width {
                break;
            }
            used += w;
            push(&mut out, c, Mode::Command, self.backslash);
        }
        out
    }
}

/// Which of the C's two printers is being mirrored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// `safestrprt(…, 0)`: space is text, printable Unicode passes.
    Text,
    /// `safestrprtn(…, 2)`: space is unprintable, only ASCII passes.
    Command,
}

/// Printed width of `c` in this mode: 1 when it passes through, else the
/// length of its escape.
fn escaped_width(c: char, mode: Mode, backslash: bool) -> usize {
    match c {
        '\\' if backslash => 2,
        ' ' if mode == Mode::Command => 4,
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
/// non-ASCII is text in a UTF-8 locale.
fn is_unprintable_unicode(c: char) -> bool {
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
            // Space (COMMAND), DEL, and every escaped non-ASCII character: the
            // C prints `\x%02x` for each byte it could not print.
            const HEX: &[u8; 16] = b"0123456789abcdef";
            let mut buf = [0u8; 4];
            for b in c.encode_utf8(&mut buf).bytes() {
                out.push_str("\\x");
                out.push(HEX[usize::from(b >> 4)] as char);
                out.push(HEX[usize::from(b & 0x0f)] as char);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn output_never_holds_a_control_character() {
        let hostile: String = (0u8..=0x9f)
            .map(char::from)
            .chain("\u{2028}\u{2029}\\ é".chars())
            .collect();
        for e in [U, W] {
            for out in [e.text(&hostile), e.command(&hostile)] {
                assert!(
                    !out.chars()
                        .any(|c| c.is_control() || c == '\u{2028}' || c == '\u{2029}'),
                    "{out:?}"
                );
            }
            let cmd = e.command(&hostile);
            assert!(cmd.is_ascii() && !cmd.contains(' '), "{cmd:?}");
        }
    }
}
