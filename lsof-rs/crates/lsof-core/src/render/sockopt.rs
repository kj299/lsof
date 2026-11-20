//! `-T f` on FreeBSD: a socket's options, its state and its TCP flags, as
//! the C's BSD `print_tcptpi()` prints them (`src/ptti.c`, `HASSOOPT`,
//! `HASSOSTATE`, `HASTCPOPT`), from the [`BsdSocket`] the FreeBSD backend
//! reads out of the pcblists (DIVERGENCES 147).
//!
//! The names and their order are `ptti.c`'s, each entry kept only where the
//! C compiles it: where its `SO_*`, `SS_*`, `SBS_*` or `TF_*` macro is
//! defined by the headers the FreeBSD dialect includes. Those were found by
//! preprocessing the C's own `common.h` against FreeBSD 14.3's and 15.0's
//! headers for amd64 and i386 (`clang -E -dM`); the four agree but for
//! `SS_ISCONFIRMING`, which 15.0 no longer defines (and no 14 kernel sets),
//! and which is kept, as the 14 C has it. The numbers are those headers'.
//!
//! Only the FreeBSD backend records a [`BsdSocket`]; on every other platform
//! nothing here is reached.

use crate::model::BsdSocket;

/// `SO_*` before the queue lengths, in `ptti.c`'s order (`sys/socket.h`).
const SO_BEFORE: &[(u32, &str)] = &[
    (0x2, "ACCEPTCONN"),
    (0x1000, "ACCEPTFILTER"),
    (0x2000, "BINTIME"),
    (0x20, "BROADCAST"),
    (0x1, "DEBUG"),
    (0x10, "DONTROUTE"),
    (0x8, "KEEPALIVE"),
    (0x80, "LINGER"),
    (0x800, "NOSIGPIPE"),
    (0x100, "OOBINLINE"),
];

/// `SO_*` between `RCVBUF` and `SNDBUF`.
const SO_MIDDLE: &[(u32, &str)] = &[(0x4, "REUSEADDR"), (0x200, "REUSEPORT")];

/// `SO_*` after `SNDBUF`.
const SO_AFTER: &[(u32, &str)] = &[(0x400, "TIMESTAMP"), (0x40, "USELOOPBACK")];

const SO_ACCEPTCONN: u32 = 0x2;
const SO_LINGER: u32 = 0x80;

/// Where an `SS=` name's bit is read from: `so_state`, or (`HASSBSTATE`) a
/// socket buffer's `sb_state`, which the kernel reports beside it.
#[derive(Clone, Copy)]
enum From {
    State,
    Rcv,
    Snd,
}

/// `SS_*` and `SBS_*`, in `ptti.c`'s order (`sys/socketvar.h`,
/// `sys/sockbuf.h`).
const SS: &[(From, u32, &str)] = &[
    (From::State, 0x200, "ASYNC"),
    (From::Rcv, 0x20, "CANTRCVMORE"),
    (From::Snd, 0x10, "CANTSENDMORE"),
    (From::State, 0x400, "ISCONFIRMING"),
    (From::State, 0x2, "ISCONNECTED"),
    (From::State, 0x4, "ISCONNECTING"),
    (From::State, 0x8, "ISDISCONNECTING"),
    (From::State, 0x100, "NBIO"),
    (From::Rcv, 0x40, "RCVATMARK"),
];

/// `TF_*` before `MSS`, in `ptti.c`'s order (`netinet/tcp_var.h`).
const TF_BEFORE: &[(u32, &str)] = &[
    (0x1, "ACKNOW"),
    (0x2, "DELACK"),
    (0x10_0000, "FASTRECOVERY"),
    (0x4_0000, "LASTIDLE"),
];

/// `TF_*` after `MSS`.
const TF_AFTER: &[(u32, &str)] = &[
    (0x1_0000, "MORETOCOME"),
    (0x800, "NEEDFIN"),
    (0x400, "NEEDSYN"),
    (0x4, "NODELAY"),
    (0x8, "NOOPT"),
    (0x1000, "NOPUSH"),
    (0x40, "RCVD_SCALE"),
    (0x100, "RCVD_TSTMP"),
    (0x20, "REQ_SCALE"),
    (0x80, "REQ_TSTMP"),
    (0x8_0000, "RXWIN0SENT"),
    (0x200, "SACK_PERMIT"),
    (0x10, "SENTFIN"),
    (0x40_0000, "SIGNATURE"),
    (0x20_0000, "WASFRECOVERY"),
];

/// One `XX=a,b,c` group: the first item after `=`, the rest after `,`.
struct Group(String);

impl Group {
    fn new(title: &str) -> Self {
        Group(title.to_string())
    }
    fn item(&mut self, text: &str) {
        self.0.push(if self.0.contains('=') { ',' } else { '=' });
        self.0.push_str(text);
    }
    /// Each name of `table` whose bits `left` still has, those bits then
    /// cleared.
    fn names(&mut self, table: &[(u32, &str)], left: &mut u32) {
        for &(bit, name) in table {
            if *left & bit != 0 {
                self.item(name);
                *left &= !bit;
            }
        }
    }
    /// `%cUNKNOWN=%#x` of what is left: the C's `%#x` of an `int`, so a
    /// negative one is its 32 bits.
    fn unknown(&mut self, left: u32) {
        if left != 0 {
            self.item(&format!("UNKNOWN={left:#x}"));
        }
    }
}

/// The groups `-T f` adds to a FreeBSD socket's TCP/TPI facts, in order:
/// `SO=…` where the socket's `xsocket` was found, `SS=…` where its
/// `so_state` is not 0, `TF=…` for a TCP socket whose `xtcpcb` was found
/// (it always has `MSS=`). Each is what the table prints between spaces and
/// `-F` as one `T` field.
pub fn parts(b: &BsdSocket) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(x) = &b.xsocket {
        // `(unsigned int)s->so_options`: an `int16_t`, sign-extended.
        let options = i32::from(x.options) as u32;
        let mut left = options;
        let mut g = Group::new("SO");
        g.names(&SO_BEFORE[..7], &mut left);
        // `KEEPALIVE` takes `=%d` of `lts.kai`, which FreeBSD never sets.
        if left & SO_LINGER != 0 {
            // `LINGER=%d` of `lts.ltm`, `(unsigned int)so_linger`, unless 0.
            let mut t = String::from("LINGER");
            if x.linger != 0 {
                t.push_str(&format!("={}", x.linger));
            }
            g.item(&t);
            left &= !SO_LINGER;
        }
        g.names(&SO_BEFORE[8..], &mut left);
        // The queue lengths of a listening socket, and the buffer sizes of
        // any other: each printed, 0 where it was not set
        // (`Lf->lts.pqlens = … = 1` whenever the `xsocket` was found).
        let listening = options & SO_ACCEPTCONN != 0;
        let (pq, q, ql) = if listening {
            (x.incqlen, x.qlen, x.qlimit)
        } else {
            (0, 0, 0)
        };
        let (rb, sb) = if listening {
            (0, 0)
        } else {
            (x.rcv_mbmax, x.snd_mbmax)
        };
        g.item(&format!("PQLEN={pq}"));
        g.item(&format!("QLEN={q}"));
        g.item(&format!("QLIM={ql}"));
        g.item(&format!("RCVBUF={rb}"));
        g.names(SO_MIDDLE, &mut left);
        g.item(&format!("SNDBUF={sb}"));
        g.names(SO_AFTER, &mut left);
        g.unknown(left);
        out.push(g.0);

        // `(unsigned int)s->so_state`, and only where it is not 0; the
        // buffer states are read beside it, never cleared from it.
        let state = i32::from(x.state) as u32;
        if state != 0 {
            let mut left = state;
            let (mut rcv, mut snd) = (u32::from(b.sbs_rcv), u32::from(b.sbs_snd));
            let mut g = Group::new("SS");
            for &(from, bit, name) in SS {
                let word = match from {
                    From::State => &mut left,
                    From::Rcv => &mut rcv,
                    From::Snd => &mut snd,
                };
                if *word & bit != 0 {
                    g.item(name);
                    *word &= !bit;
                }
            }
            g.unknown(left);
            out.push(g.0);
        }
    }
    if let Some((flags, maxseg)) = b.tcp {
        let mut left = flags;
        let mut g = Group::new("TF");
        g.names(TF_BEFORE, &mut left);
        g.item(&format!("MSS={maxseg}"));
        g.names(TF_AFTER, &mut left);
        g.unknown(left);
        out.push(g.0);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::BsdXSocket;

    fn sock(options: i16, state: i16) -> BsdXSocket {
        BsdXSocket {
            options,
            linger: 0,
            state,
            qlen: 3,
            incqlen: 1,
            qlimit: 128,
            rcv_mbmax: 2_097_152,
            snd_mbmax: 2_097_152,
        }
    }

    #[test]
    fn a_listening_tcp_socket_shows_its_queue_lengths_and_no_buffers() {
        let b = BsdSocket {
            record: true,
            xsocket: Some(sock(0x2 | 0x4, 0x100)),
            sbs_rcv: 0,
            sbs_snd: 0,
            tcp: Some((0x4 | 0x40, 16344)),
        };
        assert_eq!(
            parts(&b),
            [
                "SO=ACCEPTCONN,PQLEN=1,QLEN=3,QLIM=128,RCVBUF=0,REUSEADDR,SNDBUF=0",
                "SS=NBIO",
                "TF=MSS=16344,NODELAY,RCVD_SCALE",
            ]
        );
    }

    #[test]
    fn a_connected_socket_shows_its_buffers_and_no_queue_lengths() {
        let mut x = sock(0x8 | 0x80, 0x2);
        x.linger = 5;
        let b = BsdSocket {
            record: true,
            xsocket: Some(x),
            sbs_rcv: 0x20 | 0x40,
            sbs_snd: 0x10,
            tcp: Some((0x1 | 0x10_0000 | 0x200_0000, 1448)),
        };
        assert_eq!(
            parts(&b),
            [
                "SO=KEEPALIVE,LINGER=5,PQLEN=0,QLEN=0,QLIM=0,RCVBUF=2097152,SNDBUF=2097152",
                "SS=CANTRCVMORE,CANTSENDMORE,ISCONNECTED,RCVATMARK",
                "TF=ACKNOW,FASTRECOVERY,MSS=1448,UNKNOWN=0x2000000",
            ]
        );
    }

    #[test]
    fn signed_fields_are_widened_as_the_c_widens_them() {
        // `so_options` and `so_state` are `int16_t`: a top bit set is a
        // 32-bit negative to the C's `%#x`; `so_linger` prints `%d`.
        let mut x = sock(i16::MIN | 0x4000 | 0x1, i16::MIN | 0x1);
        x.linger = -1;
        let b = BsdSocket {
            record: false,
            xsocket: Some(BsdXSocket {
                options: x.options | 0x80,
                ..x
            }),
            sbs_rcv: 0,
            sbs_snd: 0,
            tcp: None,
        };
        assert_eq!(
            parts(&b),
            [
                "SO=DEBUG,LINGER=-1,PQLEN=0,QLEN=0,QLIM=0,RCVBUF=2097152,SNDBUF=2097152,UNKNOWN=0xffffc000",
                "SS=UNKNOWN=0xffff8001",
            ]
        );
    }

    #[test]
    fn a_socket_with_no_xsocket_shows_only_its_tcp_flags_and_zero_state_none() {
        let none = BsdSocket::default();
        assert!(parts(&none).is_empty());
        // A state of 0 prints no `SS=`, whatever the buffer states are.
        let b = BsdSocket {
            xsocket: Some(sock(0, 0)),
            sbs_rcv: 0x20,
            ..BsdSocket::default()
        };
        assert_eq!(
            parts(&b),
            ["SO=PQLEN=0,QLEN=0,QLIM=0,RCVBUF=2097152,SNDBUF=2097152"]
        );
        let t = BsdSocket {
            tcp: Some((0, 0)),
            ..BsdSocket::default()
        };
        assert_eq!(parts(&t), ["TF=MSS=0"]);
    }

    #[test]
    fn every_name_is_printed_in_the_c_order() {
        let all_so = SO_BEFORE
            .iter()
            .chain(SO_MIDDLE)
            .chain(SO_AFTER)
            .fold(0u32, |a, (b, _)| a | b);
        let b = BsdSocket {
            xsocket: Some(BsdXSocket {
                linger: 0,
                ..sock(all_so as i16, 0x200 | 0x400 | 0x2 | 0x4 | 0x8 | 0x100)
            }),
            sbs_rcv: 0x60,
            sbs_snd: 0x10,
            tcp: Some((
                TF_BEFORE.iter().chain(TF_AFTER).fold(0, |a, (b, _)| a | b),
                9,
            )),
            record: true,
        };
        assert_eq!(
            parts(&b),
            [
                "SO=ACCEPTCONN,ACCEPTFILTER,BINTIME,BROADCAST,DEBUG,DONTROUTE,KEEPALIVE,\
                 LINGER,NOSIGPIPE,OOBINLINE,PQLEN=1,QLEN=3,QLIM=128,RCVBUF=0,REUSEADDR,\
                 REUSEPORT,SNDBUF=0,TIMESTAMP,USELOOPBACK",
                "SS=ASYNC,CANTRCVMORE,CANTSENDMORE,ISCONFIRMING,ISCONNECTED,ISCONNECTING,\
                 ISDISCONNECTING,NBIO,RCVATMARK",
                "TF=ACKNOW,DELACK,FASTRECOVERY,LASTIDLE,MSS=9,MORETOCOME,NEEDFIN,NEEDSYN,\
                 NODELAY,NOOPT,NOPUSH,RCVD_SCALE,RCVD_TSTMP,REQ_SCALE,REQ_TSTMP,RXWIN0SENT,\
                 SACK_PERMIT,SENTFIN,SIGNATURE,WASFRECOVERY",
            ]
        );
    }
}
