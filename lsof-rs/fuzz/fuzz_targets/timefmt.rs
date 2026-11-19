#![no_main]

// Fuzz `-r m<fmt>`'s time formatting (lsof-core, `timefmt`; DIVERGENCES
// 152): a compiled time zone file (`TZ` may name any file, read as a
// regular file and as a stream), a POSIX `TZ` rule string, and a
// `strftime(3)` format, each the user's bytes, through glibc's local time
// ([`LocalTime`]: `localtime()`, `mktime()` for `%s`, `posixrules` for a
// rule string with no rule). Contract: no panic; `strftime` never writes
// past its buffer and gives 0 or the length it wrote; a marker is at most
// its buffer.

use libfuzzer_sys::fuzz_target;
use lsof_core::timefmt::{
    has_newline_conversion, stream_data_len, strftime, FileKey, LocalTime, Marker, MemFile,
    MemZoneFiles,
};

fuzz_target!(|data: &[u8]| {
    // The first line is a format and a time, the rest a zone.
    let mut parts = data.splitn(2, |&b| b == b'\n');
    let head = parts.next().unwrap_or_default();
    let rest = parts.next().unwrap_or_default();
    let t = i64::from_le_bytes(
        head.iter()
            .copied()
            .chain(std::iter::repeat(0))
            .take(8)
            .collect::<Vec<u8>>()[..8]
            .try_into()
            .unwrap_or([0; 8]),
    ) >> 16;
    let format = head.get(8..).unwrap_or_default().to_vec();
    let _ = stream_data_len(rest);
    for (tz, stream) in [
        (Some(b"/z".to_vec()), false),
        (Some(b"/z".to_vec()), true),
        (Some(rest.to_vec()), false),
        (Some(head.to_vec()), false),
        (None, false),
    ] {
        let mut fs = MemZoneFiles::default();
        for path in [&b"/z"[..], b"/etc/localtime", b"/usr/share/zoneinfo/posixrules"] {
            fs.files.push((
                path.to_vec(),
                MemFile {
                    key: FileKey::default(),
                    bytes: rest.to_vec(),
                    stream,
                },
            ));
        }
        let mut lt = LocalTime::new(
            Box::new(move |name| (name == "TZ").then(|| tz.clone()).flatten()),
            false,
            Box::new(fs),
        );
        let Some(tm) = lt.localtime(t) else {
            continue;
        };
        for size in [0usize, 1, 7, 64, 1024] {
            let mut buf = vec![0xa5u8; size];
            let n = strftime(&mut buf, &format, &tm, &mut lt);
            assert!(n == 0 || (n < size && buf[n] == 0), "{n} of {size}");
        }
        if let Some(mut marker) = Marker::new(&format, &mut lt, t) {
            let at = marker.at(&mut lt, t.saturating_add(86_400 * 183)).len();
            assert!(at <= (format.len() + 1) * 8);
        }
    }
    let _ = has_newline_conversion(data);
});
