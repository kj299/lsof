//! `core` — the platform-agnostic heart of the port. This is where MOST of the
//! translated C logic lives: data model, parsing, algorithm, rendering.
//!
//! `#![forbid(unsafe_code)]` is the single highest-leverage line in the project
//! (the retrospective's finding). It makes "is the unsafe contained?" a
//! compile-time fact: nothing in this crate can reach for `unsafe`, so all the
//! memory-safety risk is pushed into `sys`, where the audit harness enforces a
//! `// SAFETY:` on every block. Keep this crate dependency-free where you can.
#![forbid(unsafe_code)]

pub mod model;
pub mod parser;

pub use model::Record;
pub use parser::{parse, ParseError};
