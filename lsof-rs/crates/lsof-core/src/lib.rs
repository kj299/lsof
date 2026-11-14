//! `lsof-core` — the platform-agnostic heart of lsof-rs.
//!
//! This crate mirrors the clean split the original C lsof uses between its
//! machine-independent code (`src/`, `lib/`) and its per-OS "dialect" backends
//! (`lib/dialects/<os>/`). Here, the dialect boundary is the [`Backend`] trait:
//! a platform implementation gathers the running processes and the files/handles
//! they have open, and this crate handles everything portable — the data model
//! ([`model`]), the selection/filter engine ([`selection`]), and the output
//! renderers ([`render`]).
//!
//! It is `#![forbid(unsafe_code)]` and has one dependency, the `regex` crate,
//! for `-c /regex/` ([`posix_regex`]; DIVERGENCES 38), so it builds and is
//! fully unit-tested on any host (including this project's Linux CI),
//! independent of the Windows backend.
#![forbid(unsafe_code)]

pub mod backend;
pub mod dns;
mod endpoints;
pub use endpoints::{EndpointTables, UnixEnds};
pub mod mock;
pub mod model;
pub mod netnames;
pub mod posix_regex;
pub mod readlink;
pub mod render;
pub mod safefs;
pub mod selection;
pub mod service;
pub mod sockname;
pub mod timefmt;

pub use backend::{
    errno_text, Backend, BackendError, MountEntry, MountKind, MountRequest, MountSupplement,
    MountTable, Privilege, UserLookup,
};
pub use model::{
    AccessMode, BoundPath, FdType, FileId, FileType, NameAddition, OpenFile, Process, Protocol,
    RawNames, SockState, SocketInfo, TcpState, UnixState,
};
pub use render::Escaper;
pub use safefs::{Blocking, FileStat, FsCalls, InProcess, SafeFs};
pub use selection::{
    CommandMatch, CommandWidth, DirArg, EndpointMode, ExemptFs, FdFilter, FdKind, FdSpec,
    FilesystemArgs, InetFilter, InetSpec, Located, PathItem, Selection, StateFilter, TaskMode,
    TcpInfoFlags, UidSel, WalkedEntry, DEFAULT_COMMAND_WIDTH,
};
