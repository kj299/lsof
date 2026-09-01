#![no_main]

use libfuzzer_sys::fuzz_target;

// The hand-rolled lsof-rs option parser takes untrusted argv and must NEVER
// panic: it may only return `Ok(Action)` or `Err(String)`. Split the fuzz bytes
// into arguments on NUL boundaries (so multi-argument command lines are
// explored, including empty args and non-UTF-8 turned lossy) and parse.
fuzz_target!(|data: &[u8]| {
    let argv: Vec<String> = data
        .split(|&b| b == 0)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect();
    let _ = lsof_cli::args::parse(argv);
});
