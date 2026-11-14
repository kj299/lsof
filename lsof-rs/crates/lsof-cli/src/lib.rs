//! Library surface of the lsof-rs CLI.
//!
//! Exposes the lsof-compatible option parser so it can be unit-tested and
//! fuzzed (see `../../fuzz/`) independently of the `lsof` binary in `main.rs`,
//! which remains the primary artifact.
//!
//! It has no third-party dependency of its own (`lsof-core` brings `regex`,
//! for `-c /regex/`, and on Linux the backend it links brings `rustix`) and
//! is `#![forbid(unsafe_code)]`. The
//! attribute is per crate root, and this package builds two crates, so the
//! binary in `main.rs` carries its own copy.
#![forbid(unsafe_code)]

pub mod args;
pub mod repeat;
