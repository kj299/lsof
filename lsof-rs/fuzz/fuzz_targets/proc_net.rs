#![no_main]

// Fuzz the Linux backend's `/proc/net/*` parsers (lsof-backend-linux, `net`).
//
// These read kernel-written tables — tcp, tcp6, udp, udp6, raw, raw6, unix —
// and join them to fds by inode. The kernel is trusted to write well-formed
// text, but the port must not *depend* on that: the AF_UNIX `Path` column is
// whatever bytes a local process bound, a future kernel may add or reorder
// columns, and a panic here takes down the tool that is diagnosing the machine.
// Contract: no panic on arbitrary bytes (PLAYBOOK Phase 4 gate 3, LESSONS #021).
//
// One input drives every table parser, because the interesting bugs are in the
// shared line/field/address decoders, not in which file a table came from.

use libfuzzer_sys::fuzz_target;
use lsof_backend_linux::fuzz_api::{
    fields_with_rest, parse_addr, parse_queues, socket_inode, tcp_state, unix_state, unix_suffix,
    Protocol, SocketTable,
};

fuzz_target!(|data: &[u8]| {
    // The real code path only ever sees valid UTF-8 (read_to_string fails
    // otherwise), but lossy conversion is the stronger test and costs nothing.
    let text = String::from_utf8_lossy(data);

    // Whole-table parsers, each on a fresh table so entries never interact.
    for (proto, v6, queues) in [
        (Protocol::Tcp, false, false),
        (Protocol::Tcp, true, true),
        (Protocol::Udp, false, false),
        (Protocol::Udp, true, true),
    ] {
        let mut t = SocketTable::default();
        t.parse_inet(&text, proto, v6, queues);
    }
    for v6 in [false, true] {
        let mut t = SocketTable::default();
        t.parse_raw(&text, v6);
    }
    let mut t = SocketTable::default();
    t.parse_unix(&text);

    // Line- and field-level decoders, fed the input directly and line by line.
    let _ = socket_inode(&text);
    let _ = tcp_state(&text);
    let _ = parse_queues(&text);
    let _ = parse_addr(&text, false);
    let _ = parse_addr(&text, true);
    for line in text.lines() {
        let _ = parse_addr(line, false);
        let _ = parse_addr(line, true);
        let _ = tcp_state(line);
        for n in [1usize, 3, 8, 64] {
            let f = fields_with_rest(line, n);
            // The one structural invariant worth asserting: never more fields
            // than asked for (the last one is the untouched remainder).
            assert!(f.len() <= n, "fields_with_rest returned {} > {}", f.len(), n);
        }
        let f = fields_with_rest(line, 8);
        if f.len() >= 6 {
            // /proc/net/unix column order: Num RefCount Protocol Flags Type St.
            let _ = unix_suffix(f[4]);
            // Every AF_UNIX row has a state — an unparsable or out-of-range
            // pair is UNKNOWN, never "no state", which is what the C prints
            // once its own strtoul failure has left the value at 0.
            let st = unix_state(f[3], f[5]);
            assert!(
                !st.as_str().is_empty(),
                "unix_state({:?}, {:?}) produced an empty name",
                f[3],
                f[5]
            );
        }
    }
});
