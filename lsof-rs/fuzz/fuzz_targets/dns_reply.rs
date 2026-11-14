#![no_main]

// Fuzz reverse DNS (lsof-core, `dns`; DIVERGENCES 154): a reply to a PTR
// query is bytes from the network, chosen by whoever answers, and lsof-rs
// reads it to name a socket's host. Every reader of one is driven with
// arbitrary bytes: `send_dg()`'s verdict, `getanswer_ptr()`'s name, the name
// unpacker at every offset, `/etc/resolv.conf` and `RES_OPTIONS`, and the
// whole query loop over a transport whose every datagram and TCP message
// is a slice of the input. Contract: no panic; a name is at most 256
// characters of printable ASCII (glibc's escapes); the loop ends within its
// budget of reads.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use lsof_core::dns::{
    answer_name, name_text, ptr_query, query_ptr, udp_verdict, unpack_name, Opened, Received,
    ResolvConf, Rotation, Transport, MAX_NAME_TEXT,
};
use lsof_core::netnames::NssAnswer;

/// Every datagram and message is the next slice of the input.
struct Replies<'a> {
    data: &'a [u8],
    at: usize,
    now: Duration,
    reads: usize,
}

impl Replies<'_> {
    fn next(&mut self, buf: &mut [u8]) -> Option<usize> {
        self.reads += 1;
        if self.at >= self.data.len() {
            return None;
        }
        let len = usize::from(self.data[self.at]).min(self.data.len() - self.at - 1);
        let piece = &self.data[self.at + 1..self.at + 1 + len];
        self.at += 1 + len;
        buf[..piece.len()].copy_from_slice(piece);
        Some(piece.len())
    }
}

impl Transport for Replies<'_> {
    type Udp = ();
    type Tcp = ();
    fn now(&mut self) -> Duration {
        self.now
    }
    fn random(&mut self) -> u16 {
        0x2a2a
    }
    fn udp(&mut self, _: SocketAddr) -> Opened<()> {
        Opened::Socket(())
    }
    fn udp_send(&mut self, _: &mut (), _: &[u8]) -> bool {
        true
    }
    fn udp_recv(&mut self, _: &mut (), buf: &mut [u8], deadline: Duration) -> Received {
        match self.next(buf) {
            Some(n) => Received::Datagram(n),
            None => {
                self.now = deadline;
                Received::TimedOut
            }
        }
    }
    fn tcp(&mut self, _: SocketAddr, _: Duration) -> Option<()> {
        Some(())
    }
    fn tcp_send(&mut self, _: &mut (), _: &[u8], _: Duration) -> bool {
        true
    }
    fn tcp_recv(&mut self, _: &mut (), buf: &mut [u8], _: Duration) -> Option<usize> {
        self.next(buf)
    }
}

fn check(answer: &NssAnswer<String>) {
    if let NssAnswer::Success(name) = answer {
        assert!(name.len() <= MAX_NAME_TEXT, "{name:?}");
        assert!(name.bytes().all(|b| (0x21..0x7f).contains(&b)), "{name:?}");
    }
}

fuzz_target!(|data: &[u8]| {
    let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 7));
    let conf = ResolvConf::default();
    let query = ptr_query(0x2a2a, ip, &conf);
    // The reply as it came, and with the query's id and question at its
    // front, which is what reaches `getanswer_ptr()`.
    let _ = udp_verdict(&query, data);
    check(&answer_name(data));
    let mut framed = query.clone();
    framed.extend_from_slice(data);
    let _ = udp_verdict(&query, &framed);
    check(&answer_name(&framed));
    for at in 0..data.len().min(64) {
        if let Some((name, used)) = unpack_name(data, at) {
            assert!(name.len() <= 255 && used <= data.len() - at);
            let _ = name_text(&name, MAX_NAME_TEXT + 1);
        }
    }
    let _ = ResolvConf::parse(Some(data), Some(data), &|_| Some(7));
    // The whole loop: three servers, two rounds, each read a slice.
    let conf = ResolvConf::parse(
        Some(b"nameserver 127.0.0.53\nnameserver 127.0.0.54\nnameserver 127.0.0.55\noptions timeout:1 attempts:2\n"),
        None,
        &|_| None,
    );
    let mut t = Replies { data: &framed, at: 0, now: Duration::ZERO, reads: 0 };
    check(&query_ptr(&conf, ip, &mut t, &mut Rotation::default()));
    assert!(t.reads <= framed.len() + 8, "{} reads", t.reads);
});
