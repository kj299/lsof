#![no_main]

// Fuzz the Linux backend's reader of the kernel's NETLINK_SOCK_DIAG dump of
// AF_UNIX sockets (lsof-backend-linux, `diag`), which `-E`/`+E` name a UNIX
// socket's peer and a listener's pending connection from (DIVERGENCES 56).
// Every length in a reply is the kernel's word; each is checked before it
// is used. Contract: no panic on arbitrary bytes, and nothing kept of a
// socket the run's own table does not list.

use libfuzzer_sys::fuzz_target;
use lsof_backend_linux::fuzz_api::{parse_reply, Ends};

fuzz_target!(|data: &[u8]| {
    // The table: inodes below 1000, or every inode.
    let some = |i: u64| i < 1000;
    let mut ends = Ends::new(&some);
    let _ = parse_reply(data, &mut ends);
    for (inode, e) in ends.into_map() {
        assert!(inode < 1000, "a socket the table does not list was kept");
        assert!(e.peer.is_none_or(|p| p < 1000), "a peer the table does not list");
        assert!(e.incoming.is_none_or(|p| p < 1000), "a pending connection the table does not list");
    }
    let all = |_: u64| true;
    let mut ends = Ends::new(&all);
    // The dump read as it arrives: in pieces, each its own buffer.
    for piece in data.chunks(97) {
        let _ = parse_reply(piece, &mut ends);
    }
});
