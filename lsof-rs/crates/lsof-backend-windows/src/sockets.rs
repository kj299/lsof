//! TCP/UDP endpoint enumeration — the Windows replacement for parsing
//! `/proc/net/{tcp,tcp6,udp,udp6}`.
//!
//! `GetExtendedTcpTable` / `GetExtendedUdpTable` return every endpoint *with its
//! owning PID*, for IPv4 and IPv6, and crucially work in the plain user context
//! (just like `netstat -ano`) — so `-i` needs no elevation.

use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

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

/// Build an IPv6 `SocketAddr` that **preserves the scope id** IP Helper reports
/// (`dw*ScopeId`). `SocketAddr::new` can't set it, so it would otherwise be lost
/// — and a link-local (`fe80::`) connection whose scope is dropped won't match
/// its `GetPerTcp6ConnectionEStats` row key, leaving `-T` window/queue
/// unannotated (`tcpinfo::row_v6`). Scope is 0 for global/loopback, so this is a
/// no-op there; the numeric NAME never shows the scope (the renderer uses the
/// bare address), so display is unchanged.
fn sockaddr_v6(addr: [u8; 16], p: u16, scope: u32) -> SocketAddr {
    SocketAddr::V6(SocketAddrV6::new(ipv6(addr), p, 0, scope))
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
        tcp: None,
    };
    OpenFile {
        lock: None,
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
fn remote_opt(addr: SocketAddr) -> Option<SocketAddr> {
    if addr.port() == 0 && addr.ip().is_unspecified() {
        None
    } else {
        Some(addr)
    }
}

fn tcp4() -> Vec<(u32, OpenFile)> {
    // SAFETY: GetExtendedTcpTable writes the table through `ptr` (up to `*sz`
    // bytes) and updates `*sz`; `fill` passes null (sizing) or a live `*sz`-byte
    // buffer and retains no pointer past the call.
    let Some(buf) = fill(|ptr, sz| unsafe {
        GetExtendedTcpTable(ptr, sz, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0)
    }) else {
        return Vec::new();
    };
    let base = buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
    // SAFETY: buf is a Vec<u32> (align 4) and MIB_TCPROW_OWNER_PID is align-4, so
    // `base` is aligned; dwNumEntries is at offset 0, within the >=4-byte buffer.
    // addr_of! avoids forming a &MIB_TCPTABLE_OWNER_PID (its size_of spans a
    // phantom `[row; 1]`, an OOB read for an empty 4-byte table).
    let count = unsafe { std::ptr::addr_of!((*base).dwNumEntries).read() } as usize;
    // SAFETY: the API wrote exactly `count` contiguous rows at the `table` offset;
    // the slice covers only those (empty, reading nothing, when count is 0).
    let rows: &[MIB_TCPROW_OWNER_PID] = unsafe {
        std::slice::from_raw_parts(
            std::ptr::addr_of!((*base).table) as *const MIB_TCPROW_OWNER_PID,
            count,
        )
    };
    rows.iter()
        .map(|r| {
            let local = SocketAddr::new(IpAddr::V4(ipv4(r.dwLocalAddr)), port(r.dwLocalPort));
            let remote = remote_opt(SocketAddr::new(
                IpAddr::V4(ipv4(r.dwRemoteAddr)),
                port(r.dwRemotePort),
            ));
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
    // SAFETY: as tcp4 — GetExtendedTcpTable writes up to `*sz` bytes through
    // `ptr` and updates `*sz`; `fill` passes null or a live `*sz`-byte buffer.
    let Some(buf) = fill(|ptr, sz| unsafe {
        GetExtendedTcpTable(ptr, sz, 0, AF_INET6 as u32, TCP_TABLE_OWNER_PID_ALL, 0)
    }) else {
        return Vec::new();
    };
    let base = buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID;
    // SAFETY: as tcp4 — aligned Vec<u32>; read dwNumEntries via addr_of! without
    // forming a &MIB_TCP6TABLE_OWNER_PID (OOB for an empty 4-byte table).
    let count = unsafe { std::ptr::addr_of!((*base).dwNumEntries).read() } as usize;
    // SAFETY: as tcp4 — the API wrote exactly `count` contiguous rows at `table`.
    let rows: &[MIB_TCP6ROW_OWNER_PID] = unsafe {
        std::slice::from_raw_parts(
            std::ptr::addr_of!((*base).table) as *const MIB_TCP6ROW_OWNER_PID,
            count,
        )
    };
    rows.iter()
        .map(|r| {
            let local = sockaddr_v6(r.ucLocalAddr, port(r.dwLocalPort), r.dwLocalScopeId);
            let remote = remote_opt(sockaddr_v6(
                r.ucRemoteAddr,
                port(r.dwRemotePort),
                r.dwRemoteScopeId,
            ));
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
    // SAFETY: as tcp4 — GetExtendedUdpTable writes up to `*sz` bytes through
    // `ptr` and updates `*sz`; `fill` passes null or a live `*sz`-byte buffer.
    let Some(buf) = fill(|ptr, sz| unsafe {
        GetExtendedUdpTable(ptr, sz, 0, AF_INET as u32, UDP_TABLE_OWNER_PID, 0)
    }) else {
        return Vec::new();
    };
    let base = buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID;
    // SAFETY: as tcp4 — aligned Vec<u32>; read dwNumEntries via addr_of! without
    // forming a &MIB_UDPTABLE_OWNER_PID (OOB for an empty 4-byte table).
    let count = unsafe { std::ptr::addr_of!((*base).dwNumEntries).read() } as usize;
    // SAFETY: as tcp4 — the API wrote exactly `count` contiguous rows at `table`.
    let rows: &[MIB_UDPROW_OWNER_PID] = unsafe {
        std::slice::from_raw_parts(
            std::ptr::addr_of!((*base).table) as *const MIB_UDPROW_OWNER_PID,
            count,
        )
    };
    rows.iter()
        .map(|r| {
            let local = SocketAddr::new(IpAddr::V4(ipv4(r.dwLocalAddr)), port(r.dwLocalPort));
            let file = make_file(false, Protocol::Udp, local, None, None);
            (r.dwOwningPid, file)
        })
        .collect()
}

fn udp6() -> Vec<(u32, OpenFile)> {
    // SAFETY: as tcp4 — GetExtendedUdpTable writes up to `*sz` bytes through
    // `ptr` and updates `*sz`; `fill` passes null or a live `*sz`-byte buffer.
    let Some(buf) = fill(|ptr, sz| unsafe {
        GetExtendedUdpTable(ptr, sz, 0, AF_INET6 as u32, UDP_TABLE_OWNER_PID, 0)
    }) else {
        return Vec::new();
    };
    let base = buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID;
    // SAFETY: as tcp4 — aligned Vec<u32>; read dwNumEntries via addr_of! without
    // forming a &MIB_UDP6TABLE_OWNER_PID (OOB for an empty 4-byte table).
    let count = unsafe { std::ptr::addr_of!((*base).dwNumEntries).read() } as usize;
    // SAFETY: as tcp4 — the API wrote exactly `count` contiguous rows at `table`.
    let rows: &[MIB_UDP6ROW_OWNER_PID] = unsafe {
        std::slice::from_raw_parts(
            std::ptr::addr_of!((*base).table) as *const MIB_UDP6ROW_OWNER_PID,
            count,
        )
    };
    rows.iter()
        .map(|r| {
            let local = sockaddr_v6(r.ucLocalAddr, port(r.dwLocalPort), r.dwLocalScopeId);
            let file = make_file(true, Protocol::Udp, local, None, None);
            (r.dwOwningPid, file)
        })
        .collect()
}
