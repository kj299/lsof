//! Library surface of the lsof-rs CLI.
//!
//! Exposes the lsof-compatible option parser so it can be unit-tested and
//! fuzzed (see `../../fuzz/`) independently of the `lsof` binary in `main.rs`,
//! which remains the primary artifact.
//!
//! Like `lsof-core` it is dependency-free and `#![forbid(unsafe_code)]`. The
//! attribute is per crate root, and this package builds two crates, so the
//! binary in `main.rs` carries its own copy.
#![forbid(unsafe_code)]

pub mod args;
