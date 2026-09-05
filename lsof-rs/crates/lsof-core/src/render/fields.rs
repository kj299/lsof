//! `-F` machine-readable field output (lsof's scripting format).
//!
//! Output is a flat stream of `<letter><value><terminator>` tokens. A `p` token
//! starts a process set; an `f` token starts a file within it. The terminator
//! is newline by default, or NUL with `-F0`.
//!
//! The letters and, just as importantly, their **order** come from the C's
//! `print.c`, which walks a fixed sequence and prints each selected field that
//! has a value:
//!
//! * process set — `p` pid, `g` pgid, `R` ppid, `c` command, `u` uid,
//!   `L` login/user;
//! * file set — `f` fd, `a` access, `l` lock, `t` type, `G` file flags,
//!   `d` device character code, `D` device number, `s` size, `o` offset,
//!   `i` node, `k` link count, `P` protocol, `n` name, then the `T` TCP/TPI
//!   tokens, which the C emits *after* the name.
//!
//! A consumer that reads `-F` as a stream keyed on the letter does not care,
//! but one that pipes both binaries through `diff` does, and so does anything
//! that treats the first `T` after `n` as the end of a record.
//!
//! Bare `-F` selects **all standard fields** — Lsof.8: "When the field
//! selection character list is empty, all standard fields are selected (except
//! the raw device field, security context and zone field for compatibility
//! reasons)". When `only` is `Some`, only those letters are emitted; `p` is
//! the one field that is "always selected", and `f` is emitted only when it is
//! asked for, so `-Fcn` yields `p`, `c`, `n` and no `f`.
//!
//! Two fields are emitted **empty rather than omitted**, because the C does:
//! `a` is a space when the access mode is unknown, and `l` is a space when the
//! file holds no lock. A consumer keying on field presence would otherwise see
//! a different record shape for those rows.
//!
//! The `c` (command), `L` (user) and `n` (name) values are escaped through
//! [`Escaper`] exactly as lsof's `print.c` passes them through
//! `safestrprt(…, 0)`: a control character in a name can neither drive the
//! terminal nor forge a field or record boundary — the terminators (`\n`, or
//! `\0` under `-F0`) cannot appear inside a value.

use crate::model::{AccessMode, FdType, FileType, Process};
use crate::render::Escaper;

/// Render `procs` in `-F` format. `nul` selects NUL line termination (`-F0`);
/// `only` restricts the emitted fields (besides the `p`/`f` markers); `esc`
/// chooses the platform's backslash rule.
pub fn render(procs: &[Process], nul: bool, only: Option<&[char]>, esc: Escaper) -> String {
    let term = if nul { '\0' } else { '\n' };
    let want = |c: char| only.is_none_or(|s| s.contains(&c));
    let mut out = String::new();
    // Field emitter (macro, not a closure, so `end_set!` can also touch `out`).
    macro_rules! push {
        ($c:expr, $v:expr) => {{
            out.push($c);
            out.push_str($v);
            out.push(term);
        }};
    }
    // Close a process/file set. In `-F0` the set's last field keeps its NUL and
    // gets a NL *appended* — `print.c` does `putchar('\0')` for the field, then
    // `putchar('\n')` for the set — so the bytes are `…\0\n`. Appending rather
    // than replacing matters: a consumer that splits the stream on NUL, which is
    // the whole point of `-F0`, otherwise finds the last field of one set glued
    // to the first field of the next. In default `-F` every field is already
    // NL-terminated and this is a no-op.
    macro_rules! end_set {
        () => {{
            if nul && out.ends_with('\0') {
                out.push('\n');
            }
        }};
    }

    for p in procs {
        // `p` is the one field Lsof.8 calls "always selected".
        push!('p', &p.pid.to_string());
        if want('g') {
            if let Some(pgid) = p.pgid {
                push!('g', &pgid.to_string());
            }
        }
        if want('R') {
            if let Some(ppid) = p.ppid {
                push!('R', &ppid.to_string());
            }
        }
        if want('c') {
            push!('c', &esc.text(&p.command));
        }
        if want('u') {
            if let Some(uid) = p.uid {
                push!('u', &uid.to_string());
            }
        }
        if want('L') {
            if let Some(user) = &p.user {
                push!('L', &esc.text(user));
            }
        }
        end_set!();
        for f in &p.files {
            let fd = match f.fd {
                FdType::Handle(n) => n.to_string(),
                _ => f.fd.code(),
            };
            if want('f') {
                push!('f', &fd);
            }
            // Empty, not absent: the C prints `a ` and `l ` so every file set
            // has the same shape.
            if want('a') {
                let a = match f.access {
                    AccessMode::Unknown => ' ',
                    mode => mode.code(),
                };
                push!('a', &a.to_string());
            }
            if want('l') {
                let l = f.lock.map_or(' ', |k| k.code());
                push!('l', &l.to_string());
            }
            if want('t') {
                push!('t', &f.file_type.code());
            }
            if want('G') {
                if let Some(g) = f.file_flags {
                    // `0x<file flags>;0x<per-open flags>`. The second is the C's
                    // `pof`, which its Linux dialect never sets.
                    push!('G', &format!("0x{g:x};0x0"));
                }
            }
            // `d` is the file's device CHARACTER code, `D` its device NUMBER
            // in hex — two different fields, emitted in that order (`print.c`
            // does DEVCH then DEVN), and the C emits whichever it has. `D` is
            // the FILESYSTEM device: for /dev/null the C prints the devtmpfs it
            // lives on, not the 1,3 the DEVICE column shows. On Linux the two
            // are mutually exclusive — the dialect sets a device *string* only
            // for rows with no filesystem device, such as sockets.
            if want('d') && f.fs_device.is_none() {
                if let Some(d) = &f.device {
                    push!('d', d);
                }
            }
            if want('D') {
                if let Some(dev) = f.fs_device {
                    push!('D', &format!("0x{dev:x}"));
                }
            }
            if want('s') {
                if let Some(s) = f.size {
                    push!('s', &s.to_string());
                }
            }
            if want('o') {
                if let Some(o) = f.offset {
                    push!('o', &format!("0t{o}"));
                }
            }
            // `i` and `P` are the same cell under two names, and the C picks
            // between them with one discriminant (`Lf->inp_ty`): a row's NODE
            // either *is* an inode or *is* a protocol, never both and never
            // neither. Only an internet socket takes the protocol branch — an
            // AF_UNIX row reports its inode like a regular file does, which is
            // the split `print_tcptpi()` makes on `Lf->type == LSOF_FILE_UNIX`.
            let node_is_protocol = f.socket.is_some() && f.file_type != FileType::Unix;
            if want('i') && !node_is_protocol {
                if let Some(n) = &f.node {
                    push!('i', n);
                }
            }
            if want('k') {
                if let Some(n) = f.links {
                    push!('k', &n.to_string());
                }
            }
            if want('P') && node_is_protocol {
                if let Some(sock) = &f.socket {
                    push!('P', sock.protocol.as_str());
                }
            }
            // Emit NAME only when there is one. Some rows (e.g. `-K` thread
            // `task` rows) have no name; a bare `n` field code with an empty
            // value is just noise.
            if want('n') && !f.name.is_empty() {
                push!('n', &esc.text(&f.name));
            }
            // The TCP/TPI tokens come last, *after* the name: `print.c` calls
            // `print_tcptpi()` once `printname()` has run.
            if want('T') {
                if let Some(sock) = &f.socket {
                    if let Some(st) = sock.state {
                        push!('T', &format!("ST={}", st.as_str()));
                    }
                    // Extended info as repeated `T` fields with lsof's own
                    // prefixes: QR (read queue), QS (send queue), WR (window
                    // read size = our advertised receive window).
                    if let Some(tcp) = &sock.tcp {
                        if let Some(q) = tcp.recv_queue {
                            push!('T', &format!("QR={q}"));
                        }
                        if let Some(q) = tcp.send_queue {
                            push!('T', &format!("QS={q}"));
                        }
                        if let Some(w) = tcp.recv_window {
                            push!('T', &format!("WR={w}"));
                        }
                    }
                }
            }
            end_set!();
        }
    }
    out
}
