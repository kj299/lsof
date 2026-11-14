#![no_main]

// Fuzz the mount supplement reader (lsof-backend-linux, `mounts::
// parse_supplement`; `+m m`, DIVERGENCES 153): the file is any the user
// names. Contract: no panic; every complaint is one line with no control
// character (the file's bytes are escaped where the C prints them raw);
// a directory kept is one that starts with `/` and holds no NUL.

use libfuzzer_sys::fuzz_target;
use lsof_backend_linux::fuzz_api::parse_supplement;

fuzz_target!(|data: &[u8]| {
    let first = data.first().map_or(0, |&b| usize::from(b));
    for warn in [true, false] {
        let mut said = Vec::new();
        let got = parse_supplement(data, b"F\x1b", first, warn, &mut |l: &str| {
            said.push(l.to_string())
        });
        for line in &said {
            assert!(!line.chars().any(char::is_control), "{line:?}");
        }
        if let Some(map) = got {
            for dir in map.keys() {
                assert!(dir.first() == Some(&b'/') && !dir.contains(&0), "{dir:?}");
            }
        }
    }
});
