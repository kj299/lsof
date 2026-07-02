//! TCP/UDP endpoint enumeration — the Windows replacement for parsing
//! `/proc/net/{tcp,tcp6,udp,udp6}`.
//!
//! `GetExtendedTcpTable` / `GetExtendedUdpTable` return every endpoint *with its
//! owning PID*, for IPv4 and IPv6, and crucially work in the plain user context
//! (just like `netstat -ano`) — so `-i` needs no elevation.

use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use lsof_core::model::{AccessMode, FdType, FileType, OpenFile, Protocol, SocketInfo, TcpState};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

use crate::resolve;

const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

/// Gather every TCP and UDP endpoint as `(owning_pid, OpenFile)` pairs, each with
/// a *numeric* NAME. Name resolution is deferred to [`resolve_name`] so the
/// caller resolves only the endpoints it will actually display — reverse DNS is
/// slow, and a scoped query (`-p`, `-d`, …) must not pay for system-wide PTR
/// lookups on sockets it filters out.
pub fn collect() -> Vec<(u32, OpenFile)> {
    let mut out = Vec::new();
    out.extend(tcp4());
    out.extend(tcp6());
    out.extend(udp4());
    out.extend(udp6());
    out
}

/// Resolve a socket file's NAME in place, honoring `-n` (host) and `-P` (port).
/// Call this only for sockets that survive selection, so reverse DNS runs the
/// minimum number of times.
pub fn resolve_name(file: &mut OpenFile, no_host: bool, no_port: bool) {
    if let Some(sock) = &file.socket {
        file.name = format_socket(sock, no_host, no_port);
    }
}

/// Build the lsof NAME for a socket, honoring host/port resolution flags.
fn format_socket(sock: &SocketInfo, no_host: bool, no_port: bool) -> String {
    let mut s = endpoint(sock.local, sock.protocol, no_host, no_port);
    if let Some(r) = sock.remote {
        if !(r.ip().is_unspecified() && r.port() == 0) {
            s.push_str("->");
            s.push_str(&endpoint(Some(r), sock.protocol, no_host, no_port));
        }
    }
    if let Some(st) = sock.state {
        s.push_str(" (");
        s.push_str(st.as_str());
        s.push(')');
    }
    s
}

/// Format a single `host:port`, resolving each part unless suppressed.
fn endpoint(addr: Option<SocketAddr>, proto: Protocol, no_host: bool, no_port: bool) -> String {
    let Some(addr) = addr else {
        return "*:*".to_string();
    };
    let host = if addr.ip().is_unspecified() {
        "*".to_string()
    } else if no_host {
        host_numeric(addr.ip())
    } else {
        resolve::host_name(addr.ip()).unwrap_or_else(|| host_numeric(addr.ip()))
    };
    let port = if addr.port() == 0 {
        "*".to_string()
    } else {
        lsof_core::service::format_port(addr.port(), proto, no_port)
    };
    format!("{host}:{port}")
}

fn host_numeric(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    }
}

/// Run the two-call (size, then fetch) pattern, retrying if the table grows, and
/// return a 4-byte-aligned buffer (`Vec<u32>`) holding the MIB table.
fn fill<F>(call: F) -> Option<Vec<u32>>
where
    F: Fn(*mut c_void, *mut u32) -> u32,
{
    let mut size = 0u32;
    call(std::ptr::null_mut(), &mut size);
    if size == 0 {
        return None;
    }
    for _ in 0..4 {
        let mut buf = vec![0u32; (size as usize).div_ceil(4)];
        let ret = call(buf.as_mut_ptr() as *mut c_void, &mut size);
        if ret == 0 {
            return Some(buf);
        }
        if ret != ERROR_INSUFFICIENT_BUFFER {
            return None;
        }
        // else: `size` was updated; loop and retry with a bigger buffer.
    }
    None
}

fn ipv4(addr: u32) -> Ipv4Addr {
    // The field stores the four octets in network order; native bytes match.
    Ipv4Addr::from(addr.to_ne_bytes())
}

fn ipv6(addr: [u8; 16]) -> Ipv6Addr {
    Ipv6Addr::from(addr)
}

/// Convert a port stored in network byte order (low 16 bits of a DWORD).
fn port(p: u32) -> u16 {
    u16::from_be((p & 0xFFFF) as u16)
}

fn tcp_state(n: u32) -> TcpState {
    match n {
        1 => TcpState::Closed,
        2 => TcpState::Listen,
        3 => TcpState::SynSent,
        4 => TcpState::SynReceived,
        5 => TcpState::Established,
        6 => TcpState::FinWait1,
        7 => TcpState::FinWait2,
        8 => TcpState::CloseWait,
        9 => TcpState::Closing,
        10 => TcpState::LastAck,
        11 => TcpState::TimeWait,
        12 => TcpState::DeleteTcb,
        _ => TcpState::Unknown,
    }
}

/// Build a socket `OpenFile`. The concrete handle value isn't in the MIB table,
/// so FD is left unknown until Phase 3 correlates handles to endpoints.
fn make_file(
    is_v6: bool,
    proto: Protocol,
    local: SocketAddr,
    remote: Option<SocketAddr>,
    state: Option<TcpState>,
) -> OpenFile {
    let sock = SocketInfo {
        protocol: proto,
        local: Some(local),
        remote,
        state,
    };
    OpenFile {
        fd: FdType::Unknown,
        // Sockets are bidirectional; lsof shows them as `u` (read/write). The
        // concrete handle value (FD) isn't in the MIB table — see the research
        // roadmap on why per-endpoint FD correlation needs undocumented APIs.
        access: AccessMode::ReadWrite,
        file_type: if is_v6 {
            FileType::Ipv6
        } else {
            FileType::Ipv4
        },
        name: sock.display_name(false, false),
        device: None,
        size: None,
        offset: None,
        node: Some(proto.as_str().to_string()),
        links: None,
        socket: Some(sock),
    }
}

/// A non-zero remote endpoint (listening rows have an all-zero remote).
fn remote_opt(addr: IpAddr, p: u16) -> Option<SocketAddr> {
    if p == 0 && addr.is_unspecified() {
        None
    } else {
        Some(SocketAddr::new(addr, p))
    }
}

fn tcp4() -> Vec<(u32, OpenFile)> {
    let Some(buf) = fill(|ptr, sz| unsafe {
        GetExtendedTcpTable(ptr, sz, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0)
    }) else {
        return Vec::new();
    };
    // SAFETY: buf is 4-byte aligned and large enough; the API wrote a valid table.
    let table = unsafe { &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
    let rows: &[MIB_TCPROW_OWNER_PID] =
        unsafe { std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize) };
    rows.iter()
        .map(|r| {
            let local = SocketAddr::new(IpAddr::V4(ipv4(r.dwLocalAddr)), port(r.dwLocalPort));
            let remote = remote_opt(IpAddr::V4(ipv4(r.dwRemoteAddr)), port(r.dwRemotePort));
            let file = make_file(
                false,
                Protocol::Tcp,
                local,
                remote,
                Some(tcp_state(r.dwState)),
            );
            (r.dwOwningPid, file)
        })
        .collect()
}

fn tcp6() -> Vec<(u32, OpenFile)> {
    let Some(buf) = fill(|ptr, sz| unsafe {
        GetExtendedTcpTable(ptr, sz, 0, AF_INET6 as u32, TCP_TABLE_OWNER_PID_ALL, 0)
    }) else {
        return Vec::new();
    };
    // SAFETY: see tcp4.
    let table = unsafe { &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID) };
    let rows: &[MIB_TCP6ROW_OWNER_PID] =
        unsafe { std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize) };
    rows.iter()
        .map(|r| {
            let local = SocketAddr::new(IpAddr::V6(ipv6(r.ucLocalAddr)), port(r.dwLocalPort));
            let remote = remote_opt(IpAddr::V6(ipv6(r.ucRemoteAddr)), port(r.dwRemotePort));
            let file = make_file(
                true,
                Protocol::Tcp,
                local,
                remote,
                Some(tcp_state(r.dwState)),
            );
            (r.dwOwningPid, file)
        })
        .collect()
}

fn udp4() -> Vec<(u32, OpenFile)> {
    let Some(buf) = fill(|ptr, sz| unsafe {
        GetExtendedUdpTable(ptr, sz, 0, AF_INET as u32, UDP_TABLE_OWNER_PID, 0)
    }) else {
        return Vec::new();
    };
    // SAFETY: see tcp4.
    let table = unsafe { &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
    let rows: &[MIB_UDPROW_OWNER_PID] =
        unsafe { std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize) };
    rows.iter()
        .map(|r| {
            let local = SocketAddr::new(IpAddr::V4(ipv4(r.dwLocalAddr)), port(r.dwLocalPort));
            let file = make_file(false, Protocol::Udp, local, None, None);
            (r.dwOwningPid, file)
        })
        .collect()
}

fn udp6() -> Vec<(u32, OpenFile)> {
    let Some(buf) = fill(|ptr, sz| unsafe {
        GetExtendedUdpTable(ptr, sz, 0, AF_INET6 as u32, UDP_TABLE_OWNER_PID, 0)
    }) else {
        return Vec::new();
    };
    // SAFETY: see tcp4.
    let table = unsafe { &*(buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID) };
    let rows: &[MIB_UDP6ROW_OWNER_PID] =
        unsafe { std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize) };
    rows.iter()
        .map(|r| {
            let local = SocketAddr::new(IpAddr::V6(ipv6(r.ucLocalAddr)), port(r.dwLocalPort));
            let file = make_file(true, Protocol::Udp, local, None, None);
            (r.dwOwningPid, file)
        })
        .collect()
}
