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

use lsof_core::dns::{Opened, Received, Transport, MAX_MESSAGE};

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

    fn tcp_recv(
        &mut self,
        conn: &mut TcpStream,
        buf: &mut [u8],
        deadline: Duration,
    ) -> Option<usize> {
        let mut len = [0u8; 2];
        self.read_full(conn, &mut len, deadline)?;
        let len = usize::from(u16::from_be_bytes(len));
        let into = buf.get_mut(..len)?;
        self.read_full(conn, into, deadline)?;
        Some(len)
    }
}

impl Net {
    /// `buf` filled from `conn` by `deadline`.
    fn read_full(&self, conn: &mut TcpStream, buf: &mut [u8], deadline: Duration) -> Option<()> {
        let mut got = 0usize;
        while got < buf.len() {
            let left = self.left(deadline)?;
            conn.set_read_timeout(Some(left)).ok()?;
            match conn.read(buf.get_mut(got..).unwrap_or_default()) {
                Ok(0) => return None,
                Ok(n) => got = got.saturating_add(n),
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(_) => return None,
            }
        }
        Some(())
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
        let took = started.elapsed();
        assert!(
            took >= Duration::from_millis(990) && took < Duration::from_secs(3),
            "{took:?}"
        );
        drop(silent);

        // Closed: refused at once (the port of a socket just closed).
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
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn ids_differ() {
        let mut net = Net::new();
        let ids: std::collections::HashSet<u16> = (0..64).map(|_| net.random()).collect();
        assert!(ids.len() > 32);
    }
}
