//! `cli` — thin entry point: parse args, read input, call `core`, render. Keep
//! logic OUT of here (it belongs in `core`, where it is testable and unsafe-free).
//! This binary is deliberately shaped to answer the example differential matrix
//! (`--help`, `--version`, `--format`, stdin), so `diff_run.py` can run against
//! it out of the box.

use std::io::Read;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help") {
        println!("usage: port [--format text|json] [--version]  (reads key=value lines on stdin)");
        return;
    }
    if args.iter().any(|a| a == "--version") {
        println!("port {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    // `saturating_add` rather than `+`, here and below: this workspace denies
    // `clippy::arithmetic_side_effects`, and the skeleton has to pass the gates
    // it configures — see crates/core/src/parser.rs.
    let json = matches!(args.iter().position(|a| a == "--format"),
        Some(i) if args.get(i.saturating_add(1)).map(String::as_str) == Some("json"));

    let mut input = String::new();
    let _ = std::io::stdin().read_to_string(&mut input);

    match core::parse(&input) {
        Ok(records) if json => {
            println!("[");
            for (i, r) in records.iter().enumerate() {
                let comma = if i.saturating_add(1) < records.len() {
                    ","
                } else {
                    ""
                };
                println!(
                    "  {{\"key\": {:?}, \"value\": {:?}}}{}",
                    r.key, r.value, comma
                );
            }
            println!("]");
        }
        Ok(records) => {
            for r in &records {
                println!("{}\t{}", r.key, r.value);
            }
        }
        Err(e) => {
            eprintln!("parse error: {e:?}");
            std::process::exit(1);
        }
    }
}
