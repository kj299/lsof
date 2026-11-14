//! The network half of reverse DNS: [`lsof_core::dns::Transport`] over
//! `std::net`, for the PTR queries a socket's NAME needs (DIVERGENCES 154).
//!
//! Each datagram socket is connected to its server, so the kernel drops a
//! datagram from any other address or port, as it drops one for glibc's; its
//! port is the kernel's ephemeral one, and each query's id is 16 bits from
//! `std`'s randomly keyed hasher. Every wait is bounded by the deadline the
//! query loop gives it: a server that never answers costs the time glibc
//! gives it, and a TCP exchange, which glibc waits on without a limit, the
//! time the same server's datagram attempt has.

use std::hash::BuildHasher;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use lsof_core::dns::{Opened, Received, TcpRead, Transport, MAX_MESSAGE};

/// The network, and a monotonic clock started with it.
pub struct Net {
    start: Instant,
    counter: u64,
}

impl Net {
    pub fn new() -> Self {
        Net {
            start: Instant::now(),
            counter: 0,
        }
    }

    /// What is left until `deadline`, `None` once it has come. Never zero:
    /// `std` refuses a zero timeout.
    fn left(&self, deadline: Duration) -> Option<Duration> {
        deadline
            .checked_sub(self.start.elapsed())
            .filter(|d| !d.is_zero())
    }
}

impl Default for Net {
    fn default() -> Self {
        Net::new()
    }
}

/// The address a datagram or stream socket for `server` is bound to: the
/// same family's wildcard, port 0.
fn local_for(server: SocketAddr) -> SocketAddr {
    match server {
        SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        SocketAddr::V6(_) => SocketAddr::from(([0u16; 8], 0)),
    }
}

impl Transport for Net {
    type Udp = UdpSocket;
    type Tcp = TcpStream;

    fn now(&mut self) -> Duration {
        self.start.elapsed()
    }

    fn random(&mut self) -> u16 {
        // `RandomState` is keyed from the operating system's random source,
        // once a thread, and each one made after the first a different key:
        // a value hashed under it cannot be told by anyone who has not read
        // this process's memory.
        self.counter = self.counter.wrapping_add(1);
        let bits = std::collections::hash_map::RandomState::new().hash_one(self.counter);
        (bits ^ (bits >> 16) ^ (bits >> 32) ^ (bits >> 48)) as u16
    }

    fn udp(&mut self, server: SocketAddr) -> Opened<UdpSocket> {
        let Ok(sock) = UdpSocket::bind(local_for(server)) else {
            return Opened::NoSocket;
        };
        match sock.connect(server) {
            Ok(()) => Opened::Socket(sock),
            Err(_) => Opened::NotConnected,
        }
    }

    fn udp_send(&mut self, sock: &mut UdpSocket, message: &[u8]) -> bool {
        sock.send(message).is_ok_and(|n| n == message.len())
    }

    fn udp_recv(&mut self, sock: &mut UdpSocket, buf: &mut [u8], deadline: Duration) -> Received {
        loop {
            let Some(left) = self.left(deadline) else {
                return Received::TimedOut;
            };
            if sock.set_read_timeout(Some(left)).is_err() {
                return Received::Failed;
            }
            let room = buf.len().min(MAX_MESSAGE);
            match sock.recv(buf.get_mut(..room).unwrap_or_default()) {
                Ok(n) => return Received::Datagram(n),
                Err(e) => match e.kind() {
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted => {}
                    ErrorKind::ConnectionRefused => return Received::Refused,
                    _ => return Received::Failed,
                },
            }
        }
    }

    fn tcp(&mut self, server: SocketAddr, deadline: Duration) -> Option<TcpStream> {
        let left = self.left(deadline)?;
        TcpStream::connect_timeout(&server, left).ok()
    }

    fn tcp_send(&mut self, conn: &mut TcpStream, message: &[u8], deadline: Duration) -> bool {
        let Ok(len) = u16::try_from(message.len()) else {
            return false;
        };
        let mut framed = Vec::with_capacity(message.len().saturating_add(2));
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(message);
        let mut sent = 0usize;
        while sent < framed.len() {
            let Some(left) = self.left(deadline) else {
                return false;
            };
            if conn.set_write_timeout(Some(left)).is_err() {
                return false;
            }
            match conn.write(framed.get(sent..).unwrap_or_default()) {
                Ok(0) => return false,
                Ok(n) => sent = sent.saturating_add(n),
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(_) => return false,
            }
        }
        true
    }

    fn tcp_recv(&mut self, conn: &mut TcpStream, buf: &mut [u8], deadline: Duration) -> TcpRead {
        // Its length, big-endian, as `send_vc()` reads it; a reset there is
        // the one glibc connects again for.
        let mut len = [0u8; 2];
        match self.read_full(conn, &mut len, deadline) {
            Ok(()) => {}
            Err(ErrorKind::ConnectionReset) => return TcpRead::Reset,
            Err(_) => return TcpRead::Failed,
        }
        let len = usize::from(u16::from_be_bytes(len));
        let Some(into) = buf.get_mut(..len) else {
            return TcpRead::Failed;
        };
        match self.read_full(conn, into, deadline) {
            Ok(()) => TcpRead::Message(len),
            Err(_) => TcpRead::Failed,
        }
    }
}

impl Net {
    /// `buf` filled from `conn` by `deadline`, or why not: the read's error,
    /// `UnexpectedEof` where the connection ended, `TimedOut` where the
    /// deadline came.
    fn read_full(
        &self,
        conn: &mut TcpStream,
        buf: &mut [u8],
        deadline: Duration,
    ) -> Result<(), ErrorKind> {
        let mut got = 0usize;
        while got < buf.len() {
            let left = self.left(deadline).ok_or(ErrorKind::TimedOut)?;
            conn.set_read_timeout(Some(left)).map_err(|e| e.kind())?;
            match conn.read(buf.get_mut(got..).unwrap_or_default()) {
                Ok(0) => return Err(ErrorKind::UnexpectedEof),
                Ok(n) => got = got.saturating_add(n),
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(e.kind()),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lsof_core::dns::{query_ptr, ResolvConf, Rotation};
    use lsof_core::netnames::NssAnswer;
    use std::net::Ipv4Addr;

    /// A name server on the loopback, made by the test, answers; one that is
    /// silent costs the wait and no more; a closed port moves on at once.
    /// No query leaves the host: every server here is 127.0.0.1, on a port
    /// the test bound.
    #[test]
    #[cfg_attr(miri, ignore = "it opens sockets")]
    fn queries_go_only_where_resolv_conf_says_and_end_at_the_deadline() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        let answering = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (n, peer) = server.recv_from(&mut buf).unwrap();
            let q = &buf[..n];
            let mut r = q[..2].to_vec();
            r.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
            r.extend_from_slice(&q[12..]);
            r.extend_from_slice(&[
                0xc0, 0x0c, 0, 12, 0, 1, 0, 0, 0, 60, 0, 6, 4, b'h', b'o', b's', b't', 0,
            ]);
            server.send_to(&r, peer).unwrap();
        });
        let conf = ResolvConf {
            servers: vec![addr],
            retrans: 2,
            retry: 1,
            ..ResolvConf::default()
        };
        let ip = std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 7));
        let got = query_ptr(&conf, ip, &mut Net::new(), &mut Rotation::default());
        assert_eq!(got, NssAnswer::Success("host".into()));
        answering.join().unwrap();

        // Silent: one second, the least glibc waits.
        let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
        let conf = ResolvConf {
            servers: vec![silent.local_addr().unwrap()],
            retrans: 1,
            retry: 1,
            ..ResolvConf::default()
        };
        let started = Instant::now();
        assert_eq!(
            query_ptr(&conf, ip, &mut Net::new(), &mut Rotation::default()),
            NssAnswer::NotFound
        );
        // The least glibc waits; no upper bound here, where a loaded host
        // could pass it (the waits are lsof-core's tests', on a script).
        let took = started.elapsed();
        assert!(took >= Duration::from_millis(990), "{took:?}");
        drop(silent);

        // Closed: refused (the port of a socket just closed). Another
        // socket may have the port by now, and be silent: the verdict is
        // the same, and the bound only one a hang would pass.
        let closed = UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let conf = ResolvConf {
            servers: vec![closed],
            retrans: 5,
            retry: 2,
            ..ResolvConf::default()
        };
        let started = Instant::now();
        assert_eq!(
            query_ptr(&conf, ip, &mut Net::new(), &mut Rotation::default()),
            NssAnswer::NotFound
        );
        assert!(started.elapsed() < Duration::from_secs(30));
    }

    /// A datagram and a stream socket of the test's on one loopback port:
    /// the first answers `TC`, the second what `serve` makes of each
    /// connection, in turn. `None` where the port could not be had for both.
    fn tc_server(
        serve: Vec<fn(TcpStream)>,
    ) -> Option<(SocketAddr, std::thread::JoinHandle<usize>)> {
        for _ in 0..16 {
            let tcp = std::net::TcpListener::bind("127.0.0.1:0").ok()?;
            let addr = tcp.local_addr().ok()?;
            let Ok(udp) = UdpSocket::bind(addr) else {
                continue;
            };
            let handle = std::thread::spawn(move || {
                let mut buf = [0u8; 512];
                if let Ok((n, peer)) = udp.recv_from(&mut buf) {
                    let mut r = buf[..n].to_vec();
                    r[2] = 0x83;
                    r[3] = 0x80;
                    let _ = udp.send_to(&r, peer);
                }
                let mut served = 0;
                for f in serve {
                    let Ok((conn, _)) = tcp.accept() else {
                        break;
                    };
                    served += 1;
                    f(conn);
                }
                served
            });
            return Some((addr, handle));
        }
        None
    }

    /// The framed query a connection carries.
    fn read_query(conn: &mut TcpStream) -> Vec<u8> {
        let mut len = [0u8; 2];
        conn.read_exact(&mut len).unwrap();
        let mut q = vec![0u8; usize::from(u16::from_be_bytes(len))];
        conn.read_exact(&mut q).unwrap();
        q
    }

    /// `query_ptr` over `Net` in a thread of its own, given 30 s: a hang
    /// fails the test instead of holding it.
    fn ask(conf: ResolvConf) -> (NssAnswer<String>, Duration) {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let started = Instant::now();
            let ip = std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 7));
            let got = query_ptr(&conf, ip, &mut Net::new(), &mut Rotation::default());
            let _ = tx.send((got, started.elapsed()));
        });
        rx.recv_timeout(Duration::from_secs(30))
            .expect("the query did not end")
    }

    /// After `TC` the same server over TCP: the message framed by its
    /// big-endian length both ways and read whole; a server that accepts
    /// and never answers holds it until the datagram attempt's time and no
    /// longer; a reset of the first connection is met by a second, as
    /// glibc's `send_vc()` meets it.
    #[test]
    #[cfg_attr(miri, ignore = "it opens sockets")]
    fn tc_then_tcp_is_framed_bounded_and_tried_again_after_a_reset() {
        fn answer(mut conn: TcpStream) {
            let q = read_query(&mut conn);
            let mut r = q[..2].to_vec();
            r.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
            r.extend_from_slice(&q[12..]);
            r.extend_from_slice(&[
                0xc0, 0x0c, 0, 12, 0, 1, 0, 0, 0, 60, 0, 6, 4, b'h', b'o', b's', b't', 0,
            ]);
            let mut framed = u16::try_from(r.len()).unwrap().to_be_bytes().to_vec();
            framed.extend_from_slice(&r);
            conn.write_all(&framed).unwrap();
        }
        fn silent(mut conn: TcpStream) {
            let _ = read_query(&mut conn);
            let mut rest = [0u8; 1];
            let _ = conn.read(&mut rest);
        }
        // Closed with what it was sent unread: the kernel resets it. The
        // query came in one write, so once a byte of it is here the rest
        // is too.
        fn reset(mut conn: TcpStream) {
            let mut first = [0u8; 3];
            conn.read_exact(&mut first).unwrap();
        }
        let conf = |addr| ResolvConf {
            servers: vec![addr],
            retrans: 1,
            retry: 1,
            ..ResolvConf::default()
        };
        let Some((addr, server)) = tc_server(vec![answer]) else {
            return;
        };
        assert_eq!(ask(conf(addr)).0, NssAnswer::Success("host".into()));
        assert_eq!(server.join().unwrap(), 1);
        let Some((addr, server)) = tc_server(vec![silent]) else {
            return;
        };
        let (got, took) = ask(conf(addr));
        assert_eq!(got, NssAnswer::NotFound);
        assert!(took >= Duration::from_millis(990), "{took:?}");
        assert_eq!(server.join().unwrap(), 1);
        let Some((addr, server)) = tc_server(vec![reset, answer]) else {
            return;
        };
        assert_eq!(ask(conf(addr)).0, NssAnswer::Success("host".into()));
        assert_eq!(server.join().unwrap(), 2);
    }

    #[test]
    fn ids_differ() {
        let mut net = Net::new();
        let ids: std::collections::HashSet<u16> = (0..64).map(|_| net.random()).collect();
        assert!(ids.len() > 32);
    }
}
