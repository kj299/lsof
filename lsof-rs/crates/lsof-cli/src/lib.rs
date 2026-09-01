//! Library surface of the lsof-rs CLI.
//!
//! Exposes the lsof-compatible option parser so it can be unit-tested and
//! fuzzed (see `../../fuzz/`) independently of the `lsof` binary in `main.rs`,
//! which remains the primary artifact.

pub mod args;
