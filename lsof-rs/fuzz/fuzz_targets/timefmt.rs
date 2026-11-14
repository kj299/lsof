#![no_main]

// Fuzz `-r m<fmt>`'s time formatting (lsof-core, `timefmt`; DIVERGENCES
// 152): a compiled time zone file (`TZ` may name any file), a POSIX `TZ`
// rule string, and a `strftime(3)` format, each the user's bytes. Contract:
// no panic; `strftime` never writes past its buffer and gives 0 or the
// length it wrote; a marker is at most its buffer.

use libfuzzer_sys::fuzz_target;
use lsof_core::timefmt::{has_newline_conversion, strftime, Marker, PosixTz, TzFile, Zone};

fuzz_target!(|data: &[u8]| {
    // The first line is a format and a time, the rest a zone.
    let mut parts = data.splitn(2, |&b| b == b'\n');
    let head = parts.next().unwrap_or_default();
    let rest = parts.next().unwrap_or_default();
    let t = i64::from_le_bytes(
        head.iter().copied().chain(std::iter::repeat(0)).take(8).collect::<Vec<u8>>()[..8]
            .try_into()
            .unwrap_or([0; 8]),
    ) >> 16;
    let format = head.get(8..).unwrap_or_default();
    let zones = [
        TzFile::parse(rest).map(|f| Zone::File(Box::new(f))),
        Some(Zone::Rules(PosixTz::parse(rest))),
        Some(Zone::Rules(PosixTz::parse(head))),
        Some(Zone::from_env(Some(rest), Some(head), false, &mut |_| Some(rest.to_vec()))),
    ];
    for zone in zones.into_iter().flatten() {
        let Some(tm) = zone.localtime(t) else { continue };
        for size in [0usize, 1, 7, 64, 1024] {
            let mut buf = vec![0xa5u8; size];
            let n = strftime(&mut buf, format, &tm, t);
            assert!(n == 0 || (n < size && buf[n] == 0), "{n} of {size}");
        }
        if let Some(mut marker) = Marker::new(format, &zone, t) {
            let at = marker.at(&zone, t.saturating_add(86_400 * 183)).len();
            assert!(at <= (format.len() + 1) * 8);
        }
    }
    let _ = has_newline_conversion(data);
});
