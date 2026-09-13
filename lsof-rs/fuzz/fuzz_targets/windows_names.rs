#![no_main]

// Fuzz the Windows backend's text-parsing surface (lsof-backend-windows,
// `names`) — the crate's share of the kit's per-backend fuzz gate.
//
// That gate had never reached this crate. All nine other targets cover the
// Linux backend, the CLI and the core, while `check_ledgers.py` counted nine
// and reported the fuzz ledger `present` — counting artifacts rather than
// covering the crates they are artifacts of (porting-kit LESSONS #021 and its
// 2026-09-13 follow-up).
//
// The inputs here are chosen by the OPERATING SYSTEM, not the user: an NT
// device path, a `\\?\` final path, a kernel object type name, a UTF-16
// buffer from a `…W` call. A panic on any of them is a denial of service
// against the tool that is supposed to be diagnosing one — and a row that
// smuggles whitespace into a whitespace-split table is a correctness bug the
// unit tests cannot reach, because they only try the shapes we thought of.
//
// This target runs on LINUX, like every other. `names` is deliberately not
// `cfg(windows)` so it can.

use libfuzzer_sys::fuzz_target;
use lsof_backend_windows::fuzz_api::{
    device_to_dos, drive_of, normalize_final, pipe_display, short_type_code, wide_to_string,
    win_type_to_filetype,
};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);

    // A DOS-map entry built from the input itself, so the prefix match is
    // exercised against strings that really can collide with it — a fixed map
    // would only ever test the "no match" arm.
    // A CHAR boundary, not a byte index: `from_utf8_lossy` yields real UTF-8,
    // and slicing a `&str` mid-code-point panics. The fuzzer found that in this
    // harness on its first run — a target that panics on its own input reports
    // a false positive forever, so the harness has to be as careful as the
    // code it drives.
    let split = (0..=text.len() / 2)
        .rev()
        .find(|i| text.is_char_boundary(*i))
        .unwrap_or(0);
    let map = vec![
        ("C:".to_string(), text[..split].to_string()),
        ("D:".to_string(), "\\Device\\HarddiskVolume1".to_string()),
    ];
    let dos = device_to_dos(&text, &map);
    // The real invariant: either nothing matched and the input comes back
    // unchanged, or a `X:` drive replaced a mapped prefix and everything after
    // that prefix survives VERBATIM — so the output past the two drive bytes
    // is a suffix of the input.
    //
    // The first version of this assertion compared against the tail of the
    // FIRST map entry, and the fuzzer refuted it in seconds with a string the
    // second entry matched instead. Sixth time an over-strong invariant has
    // been written on this project (LESSONS #26), and the first time the
    // machine caught it before a human did.
    assert!(
        dos == text || dos.get(2..).is_some_and(|tail| text.ends_with(tail)),
        "device_to_dos did not preserve the tail: {dos:?} from {text:?}"
    );

    // `drive_of` returns two bytes of the input or nothing — never invents.
    if let Some(d) = drive_of(&text) {
        assert_eq!(d.len(), 2, "drive letter is two bytes: {d:?}");
        assert!(text.starts_with(&d), "drive not a prefix of {text:?}");
    }

    // Stripping a prefix only ever shortens: `\\?\UNC\` (8 bytes) becomes
    // `\\` (2), `\\?\` (4) becomes nothing, anything else is untouched.
    let n = normalize_final(&text);
    assert!(
        n.len() <= text.len(),
        "normalize_final grew: {n:?} from {text:?}"
    );

    // The pipe rewrite swaps one fixed prefix for another.
    let _ = pipe_display(&text);

    // THE CONTRACT THE TABLE DEPENDS ON. A TYPE code is never empty, never
    // longer than eight, and ASCII-alphanumeric throughout — so it cannot
    // widen the column without bound, and cannot put a space in a cell that
    // the differential's normalizer splits on.
    let code = short_type_code(&text);
    assert!(!code.is_empty(), "empty TYPE code from {text:?}");
    assert!(code.len() <= 8, "TYPE code too long: {code:?}");
    assert!(
        code.bytes().all(|b| b.is_ascii_alphanumeric()),
        "TYPE code is not alphanumeric: {code:?}"
    );

    // The same contract through the classifier, which is what the scan calls.
    let ty = win_type_to_filetype(&text);
    let rendered = ty.code();
    assert!(!rendered.is_empty(), "empty TYPE from {text:?}");
    assert!(
        !rendered.contains(char::is_whitespace),
        "TYPE code contains whitespace: {rendered:?}"
    );

    // A UTF-16 buffer from a `…W` call, built from the raw bytes so unpaired
    // surrogates and a missing NUL both occur.
    let wide: Vec<u16> = data
        .chunks(2)
        .map(|c| u16::from_le_bytes([c[0], *c.get(1).unwrap_or(&0)]))
        .collect();
    let s = wide_to_string(&wide);
    // Everything before the first NUL, and nothing after it.
    let units = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    assert!(
        s.chars().count() <= units,
        "wide_to_string invented code points: {s:?}"
    );
});
