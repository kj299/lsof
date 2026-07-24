//! `-F` machine-readable field output (lsof's scripting format).
//!
//! Output is a flat stream of `<letter><value><terminator>` tokens. A `p` token
//! starts a process set; an `f` token starts a file within it. The terminator
//! is newline by default, or NUL with `-F0`. Field letters match lsof: `p` pid,
//! `R` ppid, `c` command, `L` login/user, `f` fd, `a` access, `t` type,
//! `d` device, `s` size, `i` node, `P` protocol, `T` TCP state (`ST=`).
//!
//! When `only` is `Some`, only the requested field letters are emitted. The
//! structural record markers `p` (process) and `f` (file) are always emitted so
//! the stream stays parseable, matching lsof.

use crate::model::{AccessMode, FdType, Process};

/// Render `procs` in `-F` format. `nul` selects NUL line termination (`-F0`);
/// `only` restricts the emitted fields (besides the `p`/`f` markers).
pub fn render(procs: &[Process], nul: bool, only: Option<&[char]>) -> String {
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
    // Close a process/file set. In `-F0` fields are NUL-terminated but each set
    // still ends with a NL so a consumer can split process/file sets on it —
    // lsof's documented `-F0` format (the last field of a set is NL-terminated,
    // not NUL). In default `-F` every field is already NL-terminated, so this is
    // a no-op. Without it, `-F0` output is one giant NUL-blob with no record
    // boundaries, which breaks `lsof -F0` parsers.
    macro_rules! end_set {
        () => {{
            if nul && out.ends_with('\0') {
                out.pop();
                out.push('\n');
            }
        }};
    }

    for p in procs {
        // `p` and `f` are structural set markers — always emitted.
        push!('p', &p.pid.to_string());
        if want('R') {
            if let Some(ppid) = p.ppid {
                push!('R', &ppid.to_string());
            }
        }
        if want('c') {
            push!('c', &p.command);
        }
        if want('L') {
            if let Some(user) = &p.user {
                push!('L', user);
            }
        }
        end_set!();
        for f in &p.files {
            let fd = match f.fd {
                FdType::Handle(n) => n.to_string(),
                _ => f.fd.code(),
            };
            push!('f', &fd);
            if want('a') && f.access != AccessMode::Unknown {
                push!('a', &f.access.code().to_string());
            }
            if want('t') {
                push!('t', &f.file_type.code());
            }
            if want('d') {
                if let Some(d) = &f.device {
                    push!('d', d);
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
            // lsof leaves the `i` (inode) field empty for sockets — the protocol
            // is reported via `P` (and shown in the table's NODE column), never
            // as an inode. Emit `i` only for non-socket rows.
            if want('i') && f.socket.is_none() {
                if let Some(n) = &f.node {
                    push!('i', n);
                }
            }
            if let Some(sock) = &f.socket {
                if want('P') {
                    push!('P', sock.protocol.as_str());
                }
                if want('T') {
                    if let Some(st) = sock.state {
                        push!('T', &format!("ST={}", st.as_str()));
                    }
                }
            }
            if want('k') {
                if let Some(n) = f.links {
                    push!('k', &n.to_string());
                }
            }
            // Emit NAME only when there is one. Some rows (e.g. `-K` thread
            // `task` rows) have no name; a bare `n` field code with an empty
            // value is just noise.
            if want('n') && !f.name.is_empty() {
                push!('n', &f.name);
            }
            end_set!();
        }
    }
    out
}
