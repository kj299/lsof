#![no_main]

// Fuzz `-r` and `+r`'s value (lsof-cli, `args`; DIVERGENCES 152): its delay,
// `c<N>` and `m<fmt>` read as the C reads them, with what follows the delay's
// digits read again as options, attached and as the next word, beside `-F`
// (the `%n` test) and JSON. Contract: the parse never panics, an error quotes
// no control character, and a marker format is the rest of its word.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    let value = OsString::from_vec(data.to_vec());
    let mut attached = b"-r".to_vec();
    attached.extend_from_slice(data);
    let mut plus = b"+r".to_vec();
    plus.extend_from_slice(data);
    let lines: [Vec<OsString>; 5] = [
        vec!["-r".into(), value.clone()],
        vec![OsString::from_vec(attached.clone())],
        vec![OsString::from_vec(plus), "-F".into(), "p".into()],
        vec!["+r".into(), value.clone(), "-J".into()],
        vec![OsString::from_vec(attached), "-t".into(), value],
    ];
    for argv in lines {
        if let Err(e) = lsof_cli::args::parse(argv) {
            for piece in e.split("\nlsof: ") {
                assert!(
                    !piece.chars().any(|c| c.is_control() || c == '\u{2028}' || c == '\u{2029}'),
                    "an error holds a control character: {e:?}"
                );
            }
        }
    }
});
