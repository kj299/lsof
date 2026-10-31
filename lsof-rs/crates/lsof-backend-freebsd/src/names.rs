//! How the C spells what it prints of a FreeBSD record: kernel addresses,
//! device numbers, protocol and address-family names, TCP states.

use lsof_core::model::{Protocol, TcpState};

/// A kernel address as `print_kptr()` prints it: `KA_T_FMT_X`, `"0x%08lx"`,
/// of a `KA_T`, which the FreeBSD dialect makes a `u_long` (`dlsof.h`). On
/// i386 that is 32 bits, so the 64-bit `kvaddr_t` the kernel reports is cut
/// to its low half there, as the C's cast cuts it.
pub fn kptr(addr: u64) -> String {
    #[cfg(target_pointer_width = "32")]
    let addr = addr & 0xffff_ffff;
    format!("0x{addr:08x}")
}

/// `%p` as FreeBSD's libc prints it: `0x` and the hex digits, `0x0` for
/// null. What the C's `"%p file struct"` NAME holds.
pub fn ptr(addr: u64) -> String {
    #[cfg(target_pointer_width = "32")]
    let addr = addr & 0xffff_ffff;
    format!("{addr:#x}")
}

/// `%#x`: `0` for zero, `0x…` otherwise.
pub fn alt_hex(v: u32) -> String {
    if v == 0 {
        "0".to_string()
    } else {
        format!("{v:#x}")
    }
}

/// FreeBSD's `major()` of a 64-bit `dev_t` (`sys/types.h`), as an `int`.
pub fn major(d: u64) -> i32 {
    (((d >> 32) & 0xffff_ff00) | ((d >> 8) & 0xff)) as u32 as i32
}

/// FreeBSD's `minor()`.
pub fn minor(d: u64) -> i32 {
    (((d >> 24) & 0xff00) | (d & 0xffff_00ff)) as u32 as i32
}

/// The DEVICE cell: `"%u,%u"` of `GET_MAJ_DEV()` and `GET_MIN_DEV()`, which
/// are `major()` and `minor()` (`print.c`, `common.h`).
pub fn dev_string(d: u64) -> String {
    format!("{},{}", major(d) as u32, minor(d) as u32)
}

/// The NODE cell of an Internet socket: the protocol, by `printiproto()`'s
/// table as FreeBSD's `netinet/in.h` numbers it. `IPPROTO_IP` is FreeBSD's
/// `IPPROTO_HOPOPTS` (0), and the C's `#if` drops its `IP` case for it; SCTP
/// and UDP-Lite are not in the C's table and print as numbers (`132?`).
pub fn iproto(p: i32) -> Protocol {
    let s = match p {
        6 => return Protocol::Tcp,
        17 => return Protocol::Udp,
        0 => "HOPOPTS",
        1 => "ICMP",
        2 => "IGMP",
        3 => "GGP",
        4 => "IPIP",
        7 => "ST",
        8 => "EGP",
        9 => "PIGP",
        10 => "RCCMON",
        11 => "NVPII",
        12 => "PUP",
        13 => "ARGUS",
        14 => "EMCON",
        15 => "XNET",
        16 => "CHAOS",
        18 => "MUX",
        19 => "MEAS",
        20 => "HMP",
        21 => "PRM",
        22 => "IDP",
        23 => "TRUNK1",
        24 => "TRUNK2",
        25 => "LEAF1",
        26 => "LEAF2",
        27 => "RDP",
        28 => "IRTP",
        29 => "TP",
        30 => "BLT",
        31 => "NSP",
        32 => "INP",
        34 => "3PC",
        35 => "IDPR",
        36 => "XTP",
        37 => "DDP",
        38 => "CMTP",
        39 => "TPXX",
        40 => "IL",
        41 => "IPV6",
        42 => "SDRP",
        43 => "ROUTING",
        44 => "FRAGMNT",
        45 => "IDRP",
        46 => "RSVP",
        47 => "GRE",
        48 => "MHRP",
        49 => "BHA",
        50 => "ESP",
        51 => "AH",
        52 => "INLSP",
        53 => "SWIPE",
        54 => "NHRP",
        58 => "ICMPV6",
        59 => "NONE",
        60 => "DSTOPTS",
        61 => "AHIP",
        62 => "CFTP",
        63 => "HELLO",
        64 => "SATEXPK",
        65 => "KRYPTOL",
        66 => "RVD",
        67 => "IPPC",
        68 => "ADFS",
        69 => "SATMON",
        70 => "VISA",
        71 => "IPCV",
        72 => "CPNX",
        73 => "CPHB",
        74 => "WSN",
        75 => "PVP",
        76 => "BRSATMN",
        77 => "ND",
        78 => "WBMON",
        79 => "WBEXPAK",
        80 => "EON",
        81 => "VMTP",
        82 => "SVMTP",
        83 => "VINES",
        84 => "TTP",
        85 => "IGP",
        86 => "DGP",
        87 => "TCF",
        88 => "IGRP",
        89 => "OSPFIGP",
        90 => "SRPC",
        91 => "LARP",
        92 => "MTP",
        93 => "AX25",
        94 => "IPEIP",
        95 => "MICP",
        96 => "SCCSP",
        97 => "ETHERIP",
        98 => "ENCAP",
        99 => "APES",
        100 => "GMTP",
        255 => "RAW",
        258 => "DIVERT",
        _ => return Protocol::Other(unnamed_proto(p)),
    };
    Protocol::Other(s)
}

/// A protocol the table has no name for, as the C prints it: `%d?` while it
/// fits `IPROTOL - 1` (7) characters, `*%d?` of its last five digits beyond.
/// Interned, so the row can hold it as `&'static str`: there are at most a
/// few hundred protocol numbers a socket can carry, and each is leaked once.
fn unnamed_proto(p: i32) -> &'static str {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static SEEN: OnceLock<Mutex<HashMap<i32, &'static str>>> = OnceLock::new();
    let text = if p < 1_000_000 {
        format!("{p}?")
    } else {
        format!("*{}?", p % 100_000)
    };
    let seen = SEEN.get_or_init(Mutex::default);
    let mut seen = match seen.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    seen.entry(p)
        .or_insert_with(|| Box::leak(text.into_boxed_str()))
}

/// `printunkaf(…, 1)`: the NAME of a socket whose family the dialect does
/// not decode, by the C's table of names as FreeBSD's `sys/socket.h` numbers
/// them.
pub fn unknown_family(fam: i32) -> String {
    let s = match fam {
        0 => "AF_UNSPEC",
        1 => "AF_UNIX",
        2 => "AF_INET",
        3 => "AF_IMPLINK",
        4 => "AF_PUP",
        5 => "AF_CHAOS",
        7 => "AF_ISO",
        8 => "AF_ECMA",
        9 => "AF_DATAKIT",
        10 => "AF_CCITT",
        11 => "AF_SNA",
        12 => "AF_DECnet",
        13 => "AF_DLI",
        14 => "AF_LAT",
        15 => "AF_HYLINK",
        16 => "AF_APPLETALK",
        17 => "AF_ROUTE",
        18 => "AF_LINK",
        19 => "pseudo_AF_XTP",
        20 => "AF_COIP",
        21 => "AF_CNT",
        22 => "pseudo_AF_RTIP",
        23 => "AF_IPX",
        24 => "AF_SIP",
        27 => "pseudo_AF_KEY",
        28 => "AF_INET6",
        _ => {
            let fam = fam as u32;
            return format!("no further information on family {}", alt_hex(fam));
        }
    };
    format!("no further information on {s}")
}

/// A TCP `t_state` by `tcpstates[]` (`netinet/tcp_fsm.h`). The C prints
/// nothing for a number past the table's end; nor does this.
pub fn tcp_state(n: i32) -> Option<TcpState> {
    usize::try_from(n)
        .ok()
        .and_then(|i| lsof_core::model::FREEBSD_TCP_STATES.get(i).copied())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devices_split_as_freebsd_splits_them() {
        // makedev(0x12345678, 0x9abcdef0), as `sys/types.h` packs it.
        let make = |ma: u64, mi: u64| {
            ((ma & 0xffffff00) << 32)
                | ((ma & 0xff) << 8)
                | ((mi & 0xff00) << 24)
                | (mi & 0xffff00ff)
        };
        let d = make(0x1234_5678, 0x9abc_def0);
        assert_eq!(major(d) as u32, 0x1234_5678);
        assert_eq!(minor(d) as u32, 0x9abc_def0);
        assert_eq!(dev_string(make(0, 81)), "0,81");
        // An int that is negative prints as the unsigned the C's %u makes it.
        assert_eq!(dev_string(make(0xffff_ffff, 1)), "4294967295,1");
    }

    #[test]
    fn kernel_addresses_are_padded_to_eight() {
        assert_eq!(kptr(0x1234), "0x00001234");
        #[cfg(target_pointer_width = "64")]
        assert_eq!(kptr(0xfffff800_0a1b2c3d), "0xfffff8000a1b2c3d");
        #[cfg(target_pointer_width = "32")]
        assert_eq!(kptr(0xfffff800_0a1b2c3d), "0x0a1b2c3d");
        assert_eq!(ptr(0), "0x0");
        assert_eq!(alt_hex(0), "0");
        assert_eq!(alt_hex(0x10), "0x10");
    }

    #[test]
    fn protocols_are_named_from_the_c_table() {
        assert_eq!(iproto(6), Protocol::Tcp);
        assert_eq!(iproto(1), Protocol::Other("ICMP"));
        assert_eq!(iproto(0), Protocol::Other("HOPOPTS"));
        assert_eq!(iproto(132), Protocol::Other("132?"));
        assert_eq!(iproto(132).as_str(), iproto(132).as_str());
        assert_eq!(iproto(1_234_567), Protocol::Other("*34567?"));
    }

    #[test]
    fn families_are_named_or_numbered() {
        assert_eq!(unknown_family(18), "no further information on AF_LINK");
        assert_eq!(unknown_family(32), "no further information on family 0x20");
        assert_eq!(unknown_family(0), "no further information on AF_UNSPEC");
    }

    #[test]
    fn tcp_states_are_freebsds() {
        assert_eq!(tcp_state(1), Some(TcpState::Listen));
        assert_eq!(tcp_state(6).map(TcpState::as_str), Some("FIN_WAIT_1"));
        assert_eq!(tcp_state(9).map(TcpState::as_str), Some("FIN_WAIT_2"));
        assert_eq!(tcp_state(11), None);
        assert_eq!(tcp_state(-1), None);
    }
}
