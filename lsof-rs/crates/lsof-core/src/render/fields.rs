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
//! * process set — `p` pid, `K` task id and `M` task command (a `-K` task
//!   entry only), `g` pgid, `R` ppid, `c` command, `u` uid, `L` login/user;
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
use crate::render::{offset_text, Escaper, DEFAULT_OFFSET_DIGITS};
use crate::selection::TcpInfoFlags;

/// One letter of the C's field table (`store.c`'s `FieldSel[]`).
#[derive(Clone, Copy, Debug)]
pub struct Field {
    /// The letter.
    pub id: char,
    /// What `-F ?` calls it.
    pub what: &'static str,
    /// Whether `-F ?` lists it.
    pub listed: bool,
    /// Whether a bare `-F` selects it (`select_default_fields()`).
    pub default: bool,
}

/// The C's field table, in its order: every letter `-F` accepts, and
/// how `-F ?` and a bare `-F` treat it.
///
/// The C accepts every letter here, and refuses any other with `lsof: unknown
/// field: x`. Its list leaves out what its Linux build compiles away — the
/// file structure's share count, address and node ID, and zones — and the
/// security context unless SELinux is on. lsof-rs lists the same letters on
/// every platform. The default set is every letter but the raw device number
/// (left out "for compatibility"), the security context and the zone. A
/// letter the C accepts need not print anything: `C`, `F`, `N`, `z` and `Z`
/// never do here, as none does on a Linux host without SELinux.
pub const FIELD_TABLE: &[Field] = &[
    Field {
        id: 'a',
        what: "access: r = read; w = write; u = read/write",
        listed: true,
        default: true,
    },
    Field {
        id: 'c',
        what: "command name",
        listed: true,
        default: true,
    },
    Field {
        id: 'C',
        what: "file struct share count",
        listed: false,
        default: true,
    },
    Field {
        id: 'd',
        what: "device character code",
        listed: true,
        default: true,
    },
    Field {
        id: 'D',
        what: "major/minor device number as 0x<hex>",
        listed: true,
        default: true,
    },
    Field {
        id: 'f',
        what: "file descriptor",
        listed: true,
        default: true,
    },
    Field {
        id: 'F',
        what: "file struct address as 0x<hex>",
        listed: false,
        default: true,
    },
    Field {
        id: 'G',
        what: "file flaGs",
        listed: true,
        default: true,
    },
    Field {
        id: 'i',
        what: "inode number",
        listed: true,
        default: true,
    },
    Field {
        id: 'k',
        what: "link count",
        listed: true,
        default: true,
    },
    Field {
        id: 'K',
        what: "task ID (TID)",
        listed: true,
        default: true,
    },
    Field {
        id: 'l',
        what: "lock: r/R = read; w/W = write; u = read/write",
        listed: true,
        default: true,
    },
    Field {
        id: 'L',
        what: "login name",
        listed: true,
        default: true,
    },
    Field {
        id: 'm',
        what: "marker between repeated output",
        listed: true,
        default: true,
    },
    Field {
        id: 'M',
        what: "task comMand name",
        listed: true,
        default: true,
    },
    Field {
        id: 'n',
        what: "comment, name, Internet addresses",
        listed: true,
        default: true,
    },
    Field {
        id: 'N',
        what: "file struct node ID as 0x<hex>",
        listed: false,
        default: true,
    },
    Field {
        id: 'o',
        what: "file offset as 0t<dec> or 0x<hex>",
        listed: true,
        default: true,
    },
    Field {
        id: 'p',
        what: "process ID (PID)",
        listed: true,
        default: true,
    },
    Field {
        id: 'g',
        what: "process group ID (PGID)",
        listed: true,
        default: true,
    },
    Field {
        id: 'P',
        what: "protocol name",
        listed: true,
        default: true,
    },
    Field {
        id: 'r',
        what: "raw device number as 0x<hex>",
        listed: true,
        default: false,
    },
    Field {
        id: 'R',
        what: "paRent PID",
        listed: true,
        default: true,
    },
    Field {
        id: 's',
        what: "file size",
        listed: true,
        default: true,
    },
    Field {
        id: 'S',
        what: "stream module and device names",
        listed: true,
        default: true,
    },
    Field {
        id: 't',
        what: "file type",
        listed: true,
        default: true,
    },
    Field {
        id: 'T',
        what: "TCP/TPI info",
        listed: true,
        default: true,
    },
    Field {
        id: 'u',
        what: "user ID (UID)",
        listed: true,
        default: true,
    },
    Field {
        id: 'z',
        what: "zone name",
        listed: false,
        default: false,
    },
    Field {
        id: 'Z',
        what: "security context",
        listed: false,
        default: false,
    },
    Field {
        id: '0',
        what: "(zero) use NUL field terminator instead of NL",
        listed: true,
        default: true,
    },
];

/// Whether `-F` accepts `c` as a field letter.
pub fn field_known(c: char) -> bool {
    FIELD_TABLE.iter().any(|f| f.id == c)
}

/// Whether a bare `-F` selects `c`. Of the letters lsof-rs prints, only `r`
/// is left out, so `-F` alone prints no raw device number and `-F -Fr` does.
pub fn field_is_default(c: char) -> bool {
    FIELD_TABLE.iter().any(|f| f.id == c && f.default)
}

/// What `-F ?` writes, which the C writes to stderr (`usage.c`): a heading,
/// then one line per listed letter.
pub fn field_help() -> String {
    let mut out = String::from("lsof:\tID    field description\n");
    for f in FIELD_TABLE.iter().filter(|f| f.listed) {
        out.push_str(&format!("\t {}    {}\n", f.id, f.what));
    }
    out
}

/// Render `procs` in `-F` format. `nul` selects NUL line termination (`-F0`);
/// `only` restricts the emitted fields; `tcp_show` is `-T`'s selection, which
/// gates the `T` tokens the same way it gates the table's suffix; `esc` chooses
/// the platform's backslash rule.
pub fn render(
    procs: &[Process],
    nul: bool,
    only: Option<&[char]>,
    tcp_show: TcpInfoFlags,
    esc: Escaper,
) -> String {
    render_with_offset_digits(procs, nul, only, tcp_show, esc, DEFAULT_OFFSET_DIGITS)
}

/// [`render`] with `-o <digits>`'s limit, which the `o` field obeys exactly as
/// the table does: `0t<dec>` up to that many digits, `0x<hex>` past it
/// (`print.c` applies `OffDecDig` in both printers).
pub fn render_with_offset_digits(
    procs: &[Process],
    nul: bool,
    only: Option<&[char]>,
    tcp_show: TcpInfoFlags,
    esc: Escaper,
    offset_digits: usize,
) -> String {
    let term = if nul { '\0' } else { '\n' };
    // No list is the C's default set, which is every letter but a few; a
    // list is exactly those letters (the parser spells out the default set
    // when a letter outside it is added to it, `-F -Fr`).
    let want = |c: char| only.map_or_else(|| field_is_default(c), |s| s.contains(&c));
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
        // `-K`: the task id and the task's own command, emitted right after
        // `p` and only for a task entry (`print.c`'s HASTASKS block).
        if want('K') {
            if let Some(tid) = p.tid {
                push!('K', &tid.to_string());
            }
        }
        if want('M') {
            if let Some(tc) = &p.task_command {
                push!('M', &esc.text(tc));
            }
        }
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
            if want('t') && f.file_type.has_code() {
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
            // The device a character or block special names, in hex, after `D`
            // where `print.c` puts it (DIVERGENCES 47).
            if want('r') {
                if let Some(rdev) = f.rdev {
                    push!('r', &format!("0x{:x}", rdev.get()));
                }
            }
            if want('s') {
                if let Some(s) = f.size {
                    push!('s', &s.to_string());
                }
            }
            if want('o') {
                if let Some(o) = f.offset {
                    push!('o', &offset_text(o, offset_digits));
                }
            }
            // `i` and `P` are the same cell under two names, and the C picks
            // between them with one discriminant (`Lf->inp_ty`): a row's NODE
            // either *is* an inode or *is* a protocol, never both and never
            // neither. An AF_UNIX row reports its inode like a regular file
            // does, which is the split `print_tcptpi()` makes on
            // `Lf->type == LSOF_FILE_UNIX`; every other socket takes the
            // protocol branch, including AF_PACKET, whose NODE is an ethernet
            // protocol rather than an IP one (`dsock.c` sets `inp_ty = 2`).
            //
            // So `P` is emitted from NODE, not from `socket.protocol`. For an
            // internet row the two are the same string — the backends fill
            // NODE from the protocol — but a packet row's protocol names its
            // *family* and its NODE names the ethernet protocol, and it is the
            // latter the C prints here.
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
                if let Some(n) = &f.node {
                    push!('P', n);
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
            // Selecting the `T` field says these tokens may appear; `-T`
            // says which of them do. `print_tcptpi()` consults `Ftcptpi` in
            // both output modes, so the two gates are independent and both
            // apply. (Bare `-F` sets `Ftcptpi` itself — see the CLI.)
            if want('T') {
                if let Some(sock) = &f.socket {
                    if tcp_show.state {
                        if let Some(st) = sock.shown_state() {
                            push!('T', &format!("ST={}", st.as_str()));
                        }
                    }
                    // Extended info as repeated `T` fields with lsof's own
                    // prefixes: QR (read queue), QS (send queue), WR (window
                    // read size = our advertised receive window).
                    if let Some(tcp) = &sock.tcp {
                        if tcp_show.queue {
                            if let Some(q) = tcp.recv_queue {
                                push!('T', &format!("QR={q}"));
                            }
                            if let Some(q) = tcp.send_queue {
                                push!('T', &format!("QS={q}"));
                            }
                        }
                        if tcp_show.window {
                            if let Some(w) = tcp.recv_window {
                                push!('T', &format!("WR={w}"));
                            }
                        }
                    }
                }
            }
            end_set!();
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `-F ?` is the C's text to the byte, as `lsof -F ?` wrote it to stderr
    /// on the Linux test host (no SELinux): the table's letters less the five
    /// its build does not list.
    #[test]
    fn field_help_is_the_cs_text() {
        let measured = concat!(
            "lsof:\tID    field description\n",
            "\t a    access: r = read; w = write; u = read/write\n",
            "\t c    command name\n",
            "\t d    device character code\n",
            "\t D    major/minor device number as 0x<hex>\n",
            "\t f    file descriptor\n",
            "\t G    file flaGs\n",
            "\t i    inode number\n",
            "\t k    link count\n",
            "\t K    task ID (TID)\n",
            "\t l    lock: r/R = read; w/W = write; u = read/write\n",
            "\t L    login name\n",
            "\t m    marker between repeated output\n",
            "\t M    task comMand name\n",
            "\t n    comment, name, Internet addresses\n",
            "\t o    file offset as 0t<dec> or 0x<hex>\n",
            "\t p    process ID (PID)\n",
            "\t g    process group ID (PGID)\n",
            "\t P    protocol name\n",
            "\t r    raw device number as 0x<hex>\n",
            "\t R    paRent PID\n",
            "\t s    file size\n",
            "\t S    stream module and device names\n",
            "\t t    file type\n",
            "\t T    TCP/TPI info\n",
            "\t u    user ID (UID)\n",
            "\t 0    (zero) use NUL field terminator instead of NL\n",
        );
        assert_eq!(field_help(), measured);
    }

    /// The C accepts every letter of its table and nothing else.
    #[test]
    fn a_field_letter_is_one_the_cs_table_has() {
        for c in "0CDFGKLMNPRSTZacdfgiklmnoprstuz".chars() {
            assert!(field_known(c), "{c}");
        }
        assert_eq!(FIELD_TABLE.len(), 31);
        for c in "xyqQ?/1-+ ".chars() {
            assert!(!field_known(c), "{c:?}");
        }
    }
}
