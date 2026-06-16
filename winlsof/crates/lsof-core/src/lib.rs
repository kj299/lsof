//! `lsof-core` — the platform-agnostic heart of winlsof.
//!
//! This crate mirrors the clean split the original C lsof uses between its
//! machine-independent code (`src/`, `lib/`) and its per-OS "dialect" backends
//! (`lib/dialects/<os>/`). Here, the dialect boundary is the [`Backend`] trait:
//! a platform implementation gathers the running processes and the files/handles
//! they have open, and this crate handles everything portable — the data model
//! ([`model`]), the selection/filter engine ([`selection`]), and the output
//! renderers ([`render`]).
//!
//! It is deliberately dependency-free and `#![forbid(unsafe_code)]`, so it
//! builds and is fully unit-tested on any host (including this project's Linux
//! CI), independent of the Windows backend.
#![forbid(unsafe_code)]

pub mod backend;
pub mod mock;
pub mod model;
pub mod render;
pub mod selection;
pub mod service;

pub use backend::{Backend, BackendError, Privilege};
pub use model::{AccessMode, FdType, FileType, OpenFile, Process, Protocol, SocketInfo, TcpState};
pub use selection::{FdFilter, FdKind, FdSpec, InetFilter, Selection};
