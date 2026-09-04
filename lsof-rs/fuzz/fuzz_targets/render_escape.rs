#![no_main]

// Fuzz lsof-core's renderer escaping (`render::escape`, the port of lsof's
// safestrprt()/safestrprtn()/safepup()).
//
// This is the security boundary the other targets point at: COMMAND is set by
// the process itself and NAME by whoever created the file or socket, and the
// `proc_status` target showed a `\r` reaching the model verbatim, as it must.
// The parsers' contract is fidelity; this module's contract is that what they
// pass through can no longer drive a terminal or forge a record. Checked here
// on arbitrary input, under both platform styles:
//
//   - no output holds a control character (C0, DEL, C1) or U+2028/U+2029;
//   - COMMAND-mode output is pure ASCII and whitespace-free, so a table row
//     still splits on whitespace into its columns;
//   - the `+c` truncation stays within its width, is the escaped form of some
//     prefix of the input (so it never ends in part of an escape), and is the
//     longest such prefix that fits — the C's safestrprtn() break semantics;
//   - a result that had to be allocated differs from its input — the
//     borrowing fast path is not silently copying every cell;
//   - nothing panics.
//
// The first draft checked "no partial escape" by looking at the tail for `^`
// or `\`; the fuzzer disproved that in seconds with the input `\n\x1e`, whose
// escape `\n^^` legitimately ends in `^` (0x1e + 0x40 is `^`). A raw `^` — or
// on Windows a raw `\` — at the end of a name is legal too. Tail inspection
// cannot express the property; the prefix construction below can.

use std::borrow::Cow;

use libfuzzer_sys::fuzz_target;
use lsof_core::render::Escaper;

fn holds_control(s: &str) -> bool {
    s.chars()
        .any(|c| c.is_control() || c == '\u{2028}' || c == '\u{2029}')
}

fuzz_target!(|data: &[u8]| {
    let (width, text) = match data.split_first() {
        Some((w, rest)) => (usize::from(*w), String::from_utf8_lossy(rest)),
        None => return,
    };
    for esc in [Escaper::UNIX, Escaper::WINDOWS] {
        let t = esc.text(&text);
        assert!(!holds_control(&t), "text leaked a control: {t:?}");
        if let Cow::Owned(o) = &t {
            assert_ne!(o.as_str(), text.as_ref(), "allocated a copy for nothing");
        }

        let c = esc.command(&text);
        assert!(!holds_control(&c), "command leaked a control: {c:?}");
        assert!(c.is_ascii() && !c.contains(' '), "command not ASCII/space-free: {c:?}");
        if let Cow::Owned(o) = &c {
            assert_ne!(o.as_str(), text.as_ref(), "allocated a copy for nothing");
        }

        let cut = esc.command_truncated(&text, width);
        assert!(cut.len() <= width, "over width {width}: {cut:?}");
        assert!(c.starts_with(cut.as_str()), "not a prefix: {cut:?} of {c:?}");
        // The escaped lengths of every prefix of the input, one character at a
        // time. A cut that split an escape would have a length that is none of
        // them; a cut that stopped early would be followed by a unit that fit.
        let mut ends = vec![0usize];
        let mut buf = [0u8; 4];
        for ch in text.chars() {
            let unit = esc.command(ch.encode_utf8(&mut buf)).len();
            ends.push(ends.last().unwrap() + unit);
        }
        let at = ends
            .iter()
            .position(|&l| l == cut.len())
            .unwrap_or_else(|| panic!("cut is not a whole-unit prefix: {cut:?} of {c:?}"));
        if let Some(&next) = ends.get(at + 1) {
            assert!(next > width, "stopped early: {cut:?} (width {width}) could hold up to {next}");
        }
    }
});
