//! `cli` — thin entry point: parse args, read input, call `core`, render. Keep
//! logic OUT of here (it belongs in `core`, where it is testable and unsafe-free).
//! This binary is deliberately shaped to answer the example differential matrix
//! (`--help`, `--version`, `--format`, stdin), so `diff_run.py` can run against
//! it out of the box.
//!
//! Output goes through [`exit_on_write_error`], not `println!`: see there
//! (LESSONS #063).

use std::io::{self, BufWriter, Read, Write};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    let code = run(&args, &mut out);
    exit_on_write_error(out.flush());
    match code {
        Ok(0) => {}
        Ok(code) => std::process::exit(code),
        Err(e) => exit_on_write_error(Err(e)),
    }
}

/// Everything the tool prints goes to `out`; the exit status comes back.
fn run(args: &[String], out: &mut impl Write) -> io::Result<i32> {
    if args.iter().any(|a| a == "--help") {
        writeln!(
            out,
            "usage: port [--format text|json] [--version]  (reads key=value lines on stdin)"
        )?;
        return Ok(0);
    }
    if args.iter().any(|a| a == "--version") {
        writeln!(out, "port {}", env!("CARGO_PKG_VERSION"))?;
        return Ok(0);
    }
    // `saturating_add` rather than `+`, here and below: this workspace denies
    // `clippy::arithmetic_side_effects`, and the skeleton has to pass the gates
    // it configures — see crates/core/src/parser.rs.
    let json = matches!(args.iter().position(|a| a == "--format"),
        Some(i) if args.get(i.saturating_add(1)).map(String::as_str) == Some("json"));

    let mut input = String::new();
    let _ = io::stdin().read_to_string(&mut input);

    match core::parse(&input) {
        Ok(records) if json => {
            writeln!(out, "[")?;
            for (i, r) in records.iter().enumerate() {
                let comma = if i.saturating_add(1) < records.len() {
                    ","
                } else {
                    ""
                };
                writeln!(
                    out,
                    "  {{\"key\": {:?}, \"value\": {:?}}}{}",
                    r.key, r.value, comma
                )?;
            }
            writeln!(out, "]")?;
        }
        Ok(records) => {
            for r in &records {
                writeln!(out, "{}\t{}", r.key, r.value)?;
            }
        }
        Err(e) => {
            eprintln!("parse error: {e:?}");
            return Ok(1);
        }
    }
    Ok(0)
}

/// What a failed write to stdout means (LESSONS #063).
///
/// **The C dies of SIGPIPE; Rust ignores it.** A C program's default
/// disposition for SIGPIPE is to terminate, silently, so `tool | head -1` ends
/// quietly and the shell reports 141. The Rust runtime sets SIGPIPE to ignored
/// at startup, so the same write returns `EPIPE` instead — and `println!`
/// turns that into a panic: `failed printing to stdout: Broken pipe`, exit 101.
/// Every port that prints with `println!` inherits that difference, and no
/// test sees it, because a test reads all of the output.
///
/// So a closed pipe exits 141 and says nothing — the same `$?` and the same
/// `set -o pipefail` verdict as the C. (Re-raising the signal would be exact,
/// and needs `unsafe`.) Any other write failure is a real error, reported in
/// one line with exit 1. If the C you are porting ignores SIGPIPE itself,
/// mirror that instead.
fn exit_on_write_error(r: io::Result<()>) {
    if let Err(e) = r {
        if e.kind() == io::ErrorKind::BrokenPipe {
            std::process::exit(141);
        }
        eprintln!("write error: {e}");
        std::process::exit(1);
    }
}
