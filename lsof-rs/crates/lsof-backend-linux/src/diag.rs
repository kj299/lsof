//! A UNIX socket's peer and a listener's pending connection, for `-E`/`+E`,
//! from the kernel's `NETLINK_SOCK_DIAG` dump of AF_UNIX sockets, as the C's
//! `get_uxpeeri()` reads them (`dsock.c:937-1076`; DIVERGENCES 56).
//!
//! One request, `SOCK_DIAG_BY_FAMILY` for AF_UNIX in every state with
//! `UDIAG_SHOW_PEER | UDIAG_SHOW_ICONS`, then replies until `NLMSG_DONE`.
//! Each reply record is read as bytes, every length checked against what is
//! left before it is used: a record or attribute that claims more than there
//! is ends the reading of that buffer, as `NLMSG_OK()` and `RTA_OK()` end the
//! C's. What is kept is bounded by the run's own `/proc/net/unix`, already in
//! memory: only a socket that table lists is given an end, and only one that
//! table lists is named (`check_unix()`), so a dump of any size keeps at most
//! one [`UnixEnds`] per socket the table read. The bytes received are bounded
//! too ([`MAX_DUMP_BYTES`]), and so is the wait, for the whole dump
//! ([`DUMP_DEADLINE`]): past either, the dump is read no further, as when the
//! C's `recv()` fails.
//!
//! Only the kernel's answer to this request is read, which the C does not
//! check and which changes nothing the kernel says: the socket is connected
//! to the kernel (port 0), so the kernel delivers it nothing from another
//! port, a datagram from any other sender is dropped all the same, and a
//! record that does not carry the request's own sequence number, which is
//! never 0, is skipped (THREAT-MODEL §2).
//!
//! What fails is what fails in the C, in its words: a request that cannot be
//! sent (`netlink peer request error: …`), an `NLMSG_ERROR` reply (`netlink
//! UNIX socket msg peer info error`), and a `recv()` that fails or ends,
//! silently; each leaves the sockets not yet read with no peer. A netlink
//! socket that cannot be made is `netlink socket error: …`, and the C's
//! `Error()`: exit 1, nothing listed (measured with an injected
//! `EAFNOSUPPORT`), which [`unix_ends`] reports as `None`.

use std::collections::HashMap;

use lsof_core::UnixEnds;

/// `struct nlmsghdr`'s size, and `NLMSG_HDRLEN`.
const NLMSG_HDRLEN: usize = 16;
/// `NLMSG_ERROR` and `NLMSG_DONE`.
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
/// `SOCK_DIAG_BY_FAMILY`.
const SOCK_DIAG_BY_FAMILY: u16 = 20;
/// `NLM_F_REQUEST | NLM_F_DUMP`.
const NLM_F_REQUEST_DUMP: u16 = 0x0001 | 0x0300;
/// `AF_UNIX`.
const AF_UNIX: u8 = 1;
/// `UDIAG_SHOW_PEER | UDIAG_SHOW_ICONS`.
const UDIAG_SHOW: u32 = 0x4 | 0x8;
/// `UNIX_DIAG_PEER` and `UNIX_DIAG_ICONS`.
const UNIX_DIAG_PEER: u16 = 2;
const UNIX_DIAG_ICONS: u16 = 3;
/// `struct unix_diag_msg`'s size.
const UNIX_DIAG_MSG_LEN: usize = 16;
/// `struct rtattr`'s size, `RTA_LENGTH(0)`.
const RTA_HDRLEN: usize = 4;

/// One `recv()`'s buffer. The C's is `SOCKET_BUFFER_SIZE`,
/// `min(getpagesize(), 8192)` (`dsock.c:47`): 4,096 bytes with 4 KiB pages,
/// 8,192 with larger ones. The kernel sizes a dump's message by the reader's
/// largest buffer, up to 32 KiB, so a larger one only takes fewer calls.
pub const RECV_BUFFER: usize = 32 * 1024;

/// The most a dump is read for: 64 MiB, some 1.4 million sockets of 48 bytes,
/// past which it is read no further.
pub const MAX_DUMP_BYTES: usize = 64 << 20;

/// The longest the whole dump is waited for, every `recv()` together. The
/// kernel answers a dump at once; a reply that never comes, or one that
/// trickles in, ends the reading at this deadline, as a failed `recv()` does.
pub const DUMP_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

/// The request: an `nlmsghdr` and a `unix_diag_req`, 40 bytes, as the C's
/// `get_diagmsg()` builds it (measured with strace), but for `seq`, its
/// `nlmsg_seq`, which the C leaves 0 and the kernel copies into each record
/// of its answer.
pub fn request(seq: u32) -> [u8; 40] {
    let mut r = [0u8; 40];
    r[0..4].copy_from_slice(&40u32.to_ne_bytes());
    r[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    r[6..8].copy_from_slice(&NLM_F_REQUEST_DUMP.to_ne_bytes());
    r[8..12].copy_from_slice(&seq.to_ne_bytes());
    // nlmsg_pid stays 0: the kernel fills it in.
    r[16] = AF_UNIX; // sdiag_family
                     // sdiag_protocol and the pad stay 0.
    r[20..24].copy_from_slice(&u32::MAX.to_ne_bytes()); // udiag_states: all
                                                        // udiag_ino stays 0: every socket.
    r[28..32].copy_from_slice(&UDIAG_SHOW.to_ne_bytes());
    // udiag_cookie stays 0.
    r
}

/// What reading one buffer of the dump came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Every record was read; the dump goes on.
    More,
    /// `NLMSG_DONE`: the dump is over.
    Done,
    /// `NLMSG_ERROR`: the kernel refused it.
    Error,
}

/// The ends found so far, of the sockets `known` names (the run's own
/// `/proc/net/unix`).
pub struct Ends<'a> {
    known: &'a dyn Fn(u64) -> bool,
    /// The request's `nlmsg_seq`: a record that carries another is not the
    /// kernel's answer to it, and is skipped.
    seq: u32,
    found: HashMap<u64, UnixEnds>,
}

impl<'a> Ends<'a> {
    /// The ends of an answer to the request numbered `seq`.
    pub fn new(known: &'a dyn Fn(u64) -> bool, seq: u32) -> Ends<'a> {
        Ends {
            known,
            seq,
            found: HashMap::new(),
        }
    }

    /// What was found, by inode.
    pub fn into_map(self) -> HashMap<u64, UnixEnds> {
        self.found
    }

    /// `fill_uxpino()`: `si`'s peer is `pi`, unless it has one already; both
    /// must be listed.
    fn peer(&mut self, si: u64, pi: u64) {
        if !(self.known)(si) || !(self.known)(pi) {
            return;
        }
        let e = self.found.entry(si).or_default();
        if e.peer.is_none() {
            e.peer = Some(pi);
        }
    }

    /// `fill_uxicino()`: listener `si`'s pending connection is `ic`, unless
    /// it has one already; both must be listed.
    fn incoming(&mut self, si: u64, ic: u64) {
        if !(self.known)(si) {
            return;
        }
        if self.found.get(&si).is_some_and(|e| e.incoming.is_some()) {
            return;
        }
        if (self.known)(ic) {
            self.found.entry(si).or_default().incoming = Some(ic);
        }
    }
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(
        b.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(
        b.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

/// `NLMSG_ALIGN()` / `RTA_ALIGN()`: up to a multiple of 4, or `None` past
/// `usize`.
fn align4(n: usize) -> Option<usize> {
    Some(n.checked_add(3)? & !3)
}

/// Read one buffer of the dump into `ends`, record by record, as the C's
/// `NLMSG_OK()`/`NLMSG_NEXT()` loop does, skipping a record that is not an
/// answer to the request (its `nlmsg_seq`). Pure: the fuzz target drives it
/// with arbitrary bytes, and it must never panic, nor stop moving forward:
/// each record is left by at least a header's length, whatever it claims.
pub fn parse_reply(buf: &[u8], ends: &mut Ends<'_>) -> Step {
    let mut rest = buf;
    while rest.len() >= NLMSG_HDRLEN {
        let Some(len) = u32_at(rest, 0).and_then(|l| usize::try_from(l).ok()) else {
            break;
        };
        if len < NLMSG_HDRLEN || len > rest.len() {
            break;
        }
        if u32_at(rest, 8) == Some(ends.seq) {
            match u16_at(rest, 4) {
                Some(NLMSG_DONE) => return Step::Done,
                Some(NLMSG_ERROR) => return Step::Error,
                _ => {}
            }
            if let Some(body) = rest.get(NLMSG_HDRLEN..len) {
                parse_diag(body, ends);
            }
        }
        let Some(next) = align4(len.max(NLMSG_HDRLEN)) else {
            break;
        };
        let Some(after) = rest.get(next..) else { break };
        rest = after;
    }
    Step::More
}

/// `parse_diag()`: one `unix_diag_msg` and its attributes.
fn parse_diag(body: &[u8], ends: &mut Ends<'_>) {
    if body.len() <= UNIX_DIAG_MSG_LEN || body.first() != Some(&AF_UNIX) {
        return;
    }
    let Some(ino) = u32_at(body, 4).filter(|&i| i != 0) else {
        return;
    };
    let ino = u64::from(ino);
    let mut attrs = body.get(UNIX_DIAG_MSG_LEN..).unwrap_or_default();
    while attrs.len() >= RTA_HDRLEN {
        let Some(len) = u16_at(attrs, 0).map(usize::from) else {
            break;
        };
        if len < RTA_HDRLEN || len > attrs.len() {
            break;
        }
        let payload = attrs.get(RTA_HDRLEN..len).unwrap_or_default();
        match u16_at(attrs, 2) {
            Some(UNIX_DIAG_PEER) => {
                if let Some(peer) = u32_at(payload, 0).filter(|&p| p != 0) {
                    ends.peer(ino, u64::from(peer));
                    ends.peer(u64::from(peer), ino);
                }
            }
            Some(UNIX_DIAG_ICONS) => {
                for ic in payload.chunks_exact(4) {
                    if let Some(ic) = u32_at(ic, 0) {
                        ends.incoming(ino, u64::from(ic));
                    }
                }
            }
            _ => {}
        }
        let Some(next) = align4(len.max(RTA_HDRLEN)) else {
            break;
        };
        let Some(after) = attrs.get(next..) else {
            break;
        };
        attrs = after;
    }
}

/// A number for the request that is not 0 and not easily guessed: the
/// sequence number a record of its answer must carry.
fn request_seq() -> u32 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u32(std::process::id());
    let seq = h.finish();
    // The low half, never 0.
    u32::try_from(seq & 0xffff_ffff).unwrap_or(1).max(1)
}

/// Ask the kernel for every AF_UNIX socket's peer and pending connections,
/// and keep those of the sockets `known` names; what fails is said through
/// `say`, in the C's words (the module's notes). `None` when no netlink
/// socket could be made, after `netlink socket error: …` is said: the C's
/// `Error()`, which ends the run with exit 1 and nothing listed.
pub fn unix_ends(
    known: &dyn Fn(u64) -> bool,
    say: &dyn Fn(&str),
) -> Option<HashMap<u64, UnixEnds>> {
    use rustix::net::{
        connect, netlink, recvfrom, sendto, socket_with, sockopt, AddressFamily, RecvFlags,
        SendFlags, SocketFlags, SocketType,
    };
    let seq = request_seq();
    let mut ends = Ends::new(known, seq);
    let fd = match socket_with(
        AddressFamily::NETLINK,
        SocketType::DGRAM,
        SocketFlags::CLOEXEC,
        Some(netlink::SOCK_DIAG),
    ) {
        Ok(fd) => fd,
        Err(e) => {
            say(&format!(
                "lsof: netlink socket error: {}",
                lsof_core::errno_text(&std::io::Error::from_raw_os_error(e.raw_os_error()))
            ));
            return None;
        }
    };
    let kernel = netlink::SocketAddrNetlink::new(0, 0);
    // Not the C's: only the kernel may send to this socket. A failure leaves
    // it unconnected, as the C's is, and the sender check below holds.
    let _ = connect(&fd, &kernel);
    let deadline = std::time::Instant::now() + DUMP_DEADLINE;
    if let Err(e) = sendto(&fd, &request(seq), SendFlags::empty(), &kernel) {
        say(&format!(
            "lsof: netlink peer request error: {}",
            lsof_core::errno_text(&std::io::Error::from_raw_os_error(e.raw_os_error()))
        ));
        return Some(ends.into_map());
    }
    let mut buf = vec![0u8; RECV_BUFFER];
    let mut total = 0usize;
    loop {
        // What is left of the deadline bounds this `recv()`; none left, or a
        // wait the kernel will not take, ends the reading (a timeout of 0
        // would be no timeout at all).
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero()
            || sockopt::set_socket_timeout(
                &fd,
                sockopt::Timeout::Recv,
                Some(left.max(std::time::Duration::from_millis(1))),
            )
            .is_err()
        {
            break;
        }
        let (n, from) = match recvfrom(&fd, &mut buf[..], RecvFlags::empty()) {
            Ok((n, _, from)) if n > 0 => (n.min(buf.len()), from),
            _ => break,
        };
        total = total.saturating_add(n);
        if total > MAX_DUMP_BYTES {
            break;
        }
        // From the kernel, port 0, or not read at all.
        let kernels = from
            .and_then(|a| netlink::SocketAddrNetlink::try_from(a).ok())
            .is_some_and(|a| a.pid() == 0);
        if !kernels {
            continue;
        }
        match parse_reply(buf.get(..n).unwrap_or_default(), &mut ends) {
            Step::More => {}
            Step::Done => break,
            Step::Error => {
                say("lsof: netlink UNIX socket msg peer info error");
                break;
            }
        }
    }
    Some(ends.into_map())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The request's sequence number in these tests.
    const SEQ: u32 = 0x5eed;

    /// One `SOCK_DIAG_BY_FAMILY` record for socket `ino`, with `attrs`.
    fn record(ino: u32, attrs: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut body = vec![AF_UNIX, 1, 1, 0];
        body.extend_from_slice(&ino.to_ne_bytes());
        body.extend_from_slice(&[0; 8]);
        for (ty, payload) in attrs {
            let len = u16::try_from(RTA_HDRLEN + payload.len()).unwrap();
            body.extend_from_slice(&len.to_ne_bytes());
            body.extend_from_slice(&ty.to_ne_bytes());
            body.extend_from_slice(payload);
            while body.len() % 4 != 0 {
                body.push(0);
            }
        }
        let mut m = Vec::new();
        m.extend_from_slice(
            &u32::try_from(NLMSG_HDRLEN + body.len())
                .unwrap()
                .to_ne_bytes(),
        );
        m.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
        m.extend_from_slice(&2u16.to_ne_bytes());
        m.extend_from_slice(&SEQ.to_ne_bytes());
        m.extend_from_slice(&[0; 4]);
        m.extend_from_slice(&body);
        m
    }

    fn peer(p: u32) -> (u16, Vec<u8>) {
        (UNIX_DIAG_PEER, p.to_ne_bytes().to_vec())
    }

    fn icons(list: &[u32]) -> (u16, Vec<u8>) {
        (
            UNIX_DIAG_ICONS,
            list.iter().flat_map(|i| i.to_ne_bytes()).collect(),
        )
    }

    fn done() -> Vec<u8> {
        let mut m = vec![];
        m.extend_from_slice(&20u32.to_ne_bytes());
        m.extend_from_slice(&NLMSG_DONE.to_ne_bytes());
        m.extend_from_slice(&[0; 2]);
        m.extend_from_slice(&SEQ.to_ne_bytes());
        m.extend_from_slice(&[0; 8]);
        m
    }

    /// Record `m`'s `nlmsg_seq` made `seq`.
    fn with_seq(mut m: Vec<u8>, seq: u32) -> Vec<u8> {
        m[8..12].copy_from_slice(&seq.to_ne_bytes());
        m
    }

    #[test]
    fn the_request_is_the_cs_forty_bytes() {
        let r = request(SEQ);
        assert_eq!(u32_at(&r, 0), Some(40));
        assert_eq!(u32_at(&r, 8), Some(SEQ), "nlmsg_seq, the C's 0 aside");
        assert_eq!(u32_at(&r, 12), Some(0), "nlmsg_pid: the kernel's to fill");
        assert_eq!(u16_at(&r, 4), Some(20), "SOCK_DIAG_BY_FAMILY");
        assert_eq!(u16_at(&r, 6), Some(0x301), "NLM_F_REQUEST|NLM_F_DUMP");
        assert_eq!(r[16], 1, "AF_UNIX");
        assert_eq!(u32_at(&r, 20), Some(u32::MAX), "every state");
        assert_eq!(u32_at(&r, 24), Some(0), "every inode");
        assert_eq!(
            u32_at(&r, 28),
            Some(0xc),
            "UDIAG_SHOW_PEER|UDIAG_SHOW_ICONS"
        );
    }

    #[test]
    fn a_peer_is_filled_both_ways_the_first_one_kept() {
        let known = |i: u64| (1..100).contains(&i);
        let mut ends = Ends::new(&known, SEQ);
        let mut buf = record(10, &[peer(11)]);
        // A connected datagram socket's server end has no peer of its own:
        // the first client's record gives it one, a second client none.
        buf.extend(record(20, &[peer(22)]));
        buf.extend(record(21, &[peer(22)]));
        buf.extend(record(22, &[]));
        buf.extend(done());
        assert_eq!(parse_reply(&buf, &mut ends), Step::Done);
        let m = ends.into_map();
        assert_eq!(m[&10].peer, Some(11));
        assert_eq!(m[&11].peer, Some(10));
        assert_eq!(m[&22].peer, Some(20), "the first record to name it");
        assert_eq!(m[&21].peer, Some(22));
    }

    #[test]
    fn a_socket_or_peer_not_in_the_table_is_given_nothing() {
        let known = |i: u64| i != 99;
        let mut ends = Ends::new(&known, SEQ);
        let mut buf = record(10, &[peer(99)]);
        buf.extend(record(99, &[peer(12)]));
        // A pending connection's peer, the embryo, has inode 0: no peer.
        buf.extend(record(13, &[peer(0)]));
        assert_eq!(parse_reply(&buf, &mut ends), Step::More);
        let m = ends.into_map();
        assert!(m.get(&10).is_none_or(|e| e.peer.is_none()));
        assert!(m.get(&12).is_none_or(|e| e.peer.is_none()));
        assert!(m.get(&13).is_none_or(|e| e.peer.is_none()));
    }

    #[test]
    fn a_listener_keeps_its_first_listed_pending_connection() {
        let known = |i: u64| i != 30;
        let mut ends = Ends::new(&known, SEQ);
        let mut buf = record(5, &[icons(&[30, 31, 32])]);
        buf.extend(record(5, &[icons(&[33])]));
        buf.extend(record(6, &[icons(&[])]));
        parse_reply(&buf, &mut ends);
        let m = ends.into_map();
        assert_eq!(m[&5].incoming, Some(31), "30 is not listed; 31 is first");
        assert!(m.get(&6).is_none_or(|e| e.incoming.is_none()));
    }

    #[test]
    fn an_error_reply_ends_the_dump() {
        let known = |_: u64| true;
        let mut ends = Ends::new(&known, SEQ);
        let mut buf = record(1, &[peer(2)]);
        let mut err = done();
        err[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        buf.extend(err);
        buf.extend(record(3, &[peer(4)]));
        assert_eq!(parse_reply(&buf, &mut ends), Step::Error);
        let m = ends.into_map();
        assert_eq!(m[&1].peer, Some(2), "read before the error");
        assert!(!m.contains_key(&3), "nothing after it");
    }

    #[test]
    fn lengths_that_claim_more_than_there_is_end_the_reading() {
        let known = |_: u64| true;
        // A record longer than the buffer, one shorter than a header, an
        // attribute past its record, a peer of two bytes, every prefix of a
        // good record, and a buffer of every byte: none panics, and none
        // reads past what it was given.
        let good = record(7, &[peer(8), icons(&[9, 10])]);
        for cut in 0..good.len() {
            let mut ends = Ends::new(&known, SEQ);
            parse_reply(&good[..cut], &mut ends);
        }
        let mut long = good.clone();
        long[0..4].copy_from_slice(&u32::MAX.to_ne_bytes());
        let mut ends = Ends::new(&known, SEQ);
        assert_eq!(parse_reply(&long, &mut ends), Step::More);
        assert!(ends.into_map().is_empty());
        let mut short = good.clone();
        short[0..4].copy_from_slice(&3u32.to_ne_bytes());
        let mut ends = Ends::new(&known, SEQ);
        parse_reply(&short, &mut ends);
        assert!(ends.into_map().is_empty());
        let mut attr = good.clone();
        attr[NLMSG_HDRLEN + UNIX_DIAG_MSG_LEN..][..2].copy_from_slice(&0xffffu16.to_ne_bytes());
        let mut ends = Ends::new(&known, SEQ);
        parse_reply(&attr, &mut ends);
        assert!(ends.into_map().is_empty());
        let mut ends = Ends::new(&known, SEQ);
        parse_reply(&record(7, &[(UNIX_DIAG_PEER, vec![8, 0])]), &mut ends);
        assert!(ends.into_map().is_empty());
        let all: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let mut ends = Ends::new(&known, SEQ);
        parse_reply(&all, &mut ends);
    }

    #[test]
    fn records_are_read_at_their_aligned_lengths() {
        let known = |_: u64| true;
        let mut ends = Ends::new(&known, SEQ);
        // An ICONS of one inode and a SHUTDOWN of one byte (padded) before
        // the PEER: each attribute starts at its predecessor's aligned end.
        let buf = record(40, &[(6, vec![0]), icons(&[41]), peer(42)]);
        parse_reply(&buf, &mut ends);
        let m = ends.into_map();
        assert_eq!(m[&40].peer, Some(42));
        assert_eq!(m[&40].incoming, Some(41));
    }

    #[test]
    fn a_record_or_attribute_shorter_than_its_header_ends_the_reading() {
        let known = |_: u64| true;
        // A record of length 0: `NLMSG_OK()` fails, and the buffer is read no
        // further, the good record after it included. Were it taken, its
        // aligned length, 0, would never move the reading on.
        let mut buf = vec![0u8; NLMSG_HDRLEN];
        buf.extend(record(9, &[peer(10)]));
        let mut ends = Ends::new(&known, SEQ);
        assert_eq!(parse_reply(&buf, &mut ends), Step::More);
        assert!(ends.into_map().is_empty(), "nothing after it is read");
        // Lengths 1 to 15 too, each a record shorter than its header.
        for len in 1..NLMSG_HDRLEN as u32 {
            let mut buf = record(9, &[peer(10)]);
            buf[0..4].copy_from_slice(&len.to_ne_bytes());
            buf.extend(record(11, &[peer(12)]));
            let mut ends = Ends::new(&known, SEQ);
            assert_eq!(parse_reply(&buf, &mut ends), Step::More, "{len}");
            assert!(ends.into_map().is_empty(), "{len}");
        }
        // An attribute of length 0 ends its record's attributes, `RTA_OK()`,
        // and the next record is read.
        let mut zero = record(7, &[(UNIX_DIAG_PEER, vec![0, 0]), peer(8)]);
        let at = NLMSG_HDRLEN + UNIX_DIAG_MSG_LEN;
        zero[at..at + 2].copy_from_slice(&0u16.to_ne_bytes());
        zero.extend(record(9, &[peer(10)]));
        let mut ends = Ends::new(&known, SEQ);
        assert_eq!(parse_reply(&zero, &mut ends), Step::More);
        let m = ends.into_map();
        assert!(m.get(&7).is_none_or(|e| e.peer.is_none()), "{m:?}");
        assert_eq!(m[&9].peer, Some(10));
        // And lengths 1 to 3, each shorter than an attribute's header.
        for len in 1..RTA_HDRLEN as u16 {
            let mut short = record(7, &[(UNIX_DIAG_PEER, vec![0, 0]), peer(8)]);
            short[at..at + 2].copy_from_slice(&len.to_ne_bytes());
            let mut ends = Ends::new(&known, SEQ);
            parse_reply(&short, &mut ends);
            assert!(ends.into_map().is_empty(), "{len}");
        }
    }

    #[test]
    fn the_next_record_starts_at_the_aligned_end_of_one_not_padded() {
        let known = |_: u64| true;
        // A record whose length, 45, is not a multiple of 4: its last
        // attribute holds one byte. The next one starts at 48.
        let mut first = record(7, &[peer(8)]);
        first.extend_from_slice(&5u16.to_ne_bytes());
        first.extend_from_slice(&6u16.to_ne_bytes());
        first.push(0);
        let len = u32::try_from(first.len()).unwrap();
        assert_eq!(len, 45);
        first[0..4].copy_from_slice(&len.to_ne_bytes());
        first.extend_from_slice(&[0; 3]);
        first.extend(record(9, &[peer(10)]));
        let mut ends = Ends::new(&known, SEQ);
        assert_eq!(parse_reply(&first, &mut ends), Step::More);
        let m = ends.into_map();
        assert_eq!(m[&7].peer, Some(8));
        assert_eq!(m[&9].peer, Some(10), "read at offset 48: {m:?}");
    }

    #[test]
    fn a_record_of_another_family_or_of_inode_0_names_nothing() {
        let known = |_: u64| true;
        let mut inet = record(7, &[peer(8)]);
        inet[NLMSG_HDRLEN] = 2; // AF_INET
        let mut ends = Ends::new(&known, SEQ);
        parse_reply(&inet, &mut ends);
        assert!(ends.into_map().is_empty());
        // `!(inop = dm->udiag_ino)`: inode 0, though the table lists it (an
        // embryo is listed so), names no peer, either way round.
        let mut ends = Ends::new(&known, SEQ);
        parse_reply(&record(0, &[peer(5), icons(&[6])]), &mut ends);
        assert!(ends.into_map().is_empty());
    }

    #[test]
    fn a_record_that_answers_another_request_is_skipped() {
        let known = |_: u64| true;
        // A DONE, an ERROR and a record numbered otherwise, then this
        // request's own: only the last is read, and the dump goes on.
        let mut err = with_seq(done(), SEQ + 1);
        err[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        let mut buf = with_seq(done(), SEQ + 1);
        buf.extend(err);
        buf.extend(with_seq(record(1, &[peer(2)]), 0));
        buf.extend(record(3, &[peer(4)]));
        let mut ends = Ends::new(&known, SEQ);
        assert_eq!(parse_reply(&buf, &mut ends), Step::More);
        let m = ends.into_map();
        assert!(!m.contains_key(&1), "{m:?}");
        assert_eq!(m[&3].peer, Some(4));
        let mut ends = Ends::new(&known, SEQ);
        assert_eq!(parse_reply(&done(), &mut ends), Step::Done);
    }

    #[test]
    fn the_sequence_number_is_never_0() {
        for _ in 0..64 {
            assert_ne!(request_seq(), 0);
        }
    }

    /// The kernel's own dump of a socketpair this test makes: each end names
    /// the other.
    #[cfg(not(miri))]
    #[test]
    fn the_kernel_names_a_socketpairs_ends() {
        use std::os::unix::fs::MetadataExt;
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        let ino = |s: &std::os::unix::net::UnixStream| {
            use std::os::fd::AsRawFd;
            std::fs::metadata(format!("/proc/self/fd/{}", s.as_raw_fd()))
                .unwrap()
                .ino()
        };
        let (ia, ib) = (ino(&a), ino(&b));
        let known = |i: u64| i == ia || i == ib;
        let said = std::cell::RefCell::new(Vec::new());
        let Some(m) = unix_ends(&known, &|l| said.borrow_mut().push(l.to_string())) else {
            eprintln!("skipped: no NETLINK_SOCK_DIAG here: {said:?}");
            return;
        };
        let said = said.into_inner();
        assert!(said.is_empty(), "{said:?}");
        assert_eq!(m[&ia].peer, Some(ib));
        assert_eq!(m[&ib].peer, Some(ia));
        assert_eq!(m.len(), 2, "only the sockets the table names");
    }
}
