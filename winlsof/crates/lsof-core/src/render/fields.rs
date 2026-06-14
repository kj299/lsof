//! `-F` machine-readable field output (lsof's scripting format).
//!
//! Output is a flat stream of `<letter><value><terminator>` tokens. A `p` token
//! starts a process set; an `f` token starts a file within it. The terminator
//! is newline by default, or NUL with `-F0`. Field letters match lsof: `p` pid,
//! `R` ppid, `c` command, `L` login/user, `f` fd, `a` access, `t` type,
//! `d` device, `s` size, `i` node, `P` protocol, `T` TCP state (`ST=`).

use crate::model::{AccessMode, FdType, Process};

/// Render `procs` in `-F` format. `nul` selects NUL line termination (`-F0`).
pub fn render(procs: &[Process], nul: bool) -> String {
    let term = if nul { '\0' } else { '\n' };
    let mut out = String::new();
    let mut push = |c: char, v: &str| {
        out.push(c);
        out.push_str(v);
        out.push(term);
    };

    for p in procs {
        push('p', &p.pid.to_string());
        if let Some(ppid) = p.ppid {
            push('R', &ppid.to_string());
        }
        push('c', &p.command);
        if let Some(user) = &p.user {
            push('L', user);
        }
        for f in &p.files {
            let fd = match f.fd {
                FdType::Handle(n) => n.to_string(),
                _ => f.fd.code(),
            };
            push('f', &fd);
            if f.access != AccessMode::Unknown {
                push('a', &f.access.code().to_string());
            }
            push('t', f.file_type.code());
            if let Some(d) = &f.device {
                push('d', d);
            }
            if let Some(s) = f.size {
                push('s', &s.to_string());
            }
            if let Some(n) = &f.node {
                push('i', n);
            }
            if let Some(sock) = &f.socket {
                push('P', sock.protocol.as_str());
                if let Some(st) = sock.state {
                    push('T', &format!("ST={}", st.as_str()));
                }
            }
            push('n', &f.name);
        }
    }
    out
}
