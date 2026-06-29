//! `-T [qsw]` — extended TCP info appended to socket rows (Phase 5B).
//!
//! `s` (state) is already shown by the socket NAME formatter, so this module
//! only handles `q` (queue) and `w` (window). Those come from Windows'
//! **per-connection extended TCP statistics** (`GetPerTcpConnectionEStats`):
//!
//! - `w` window  → `TCP_ESTATS_REC_ROD.CurRwinSent` (the receive window we're
//!   currently advertising).
//! - `q` queue   → `TCP_ESTATS_REC_ROD.CurAppRQueue` (bytes queued for the app
//!   to read) and `TCP_ESTATS_SEND_BUFF_ROD.CurAppWQueue` (bytes queued to
//!   send).
//!
//! **Caveat (why this needs Administrator):** EStats read-only-dynamic data is
//! only populated once *collection* is enabled on the connection, which is off
//! by default. So when elevated we enable collection just-in-time, read, then
//! disable again (bounded and reversed, matching the project's least-privilege
//! ethos). Unelevated, the read returns nothing and the row is left unchanged.
//!
//! Iteration 1 covers **IPv4** only; the IPv6 path (`GetPerTcp6ConnectionEStats`
//! over `MIB_TCP6ROW`, with `IN6_ADDR` + scope id) is a follow-up. Everything
//! is best-effort: any non-zero status leaves the row untouched, never errors.

use std::mem::{size_of, zeroed};
use std::net::{SocketAddr, SocketAddrV4};
use std::ptr::null_mut;

use lsof_core::model::{OpenFile, Protocol, TcpState};
use lsof_core::TcpInfoFlags;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetPerTcpConnectionEStats, SetPerTcpConnectionEStats, TCP_ESTATS_REC_ROD_v0,
    TCP_ESTATS_SEND_BUFF_ROD_v0, TcpConnectionEstatsRec, TcpConnectionEstatsSendBuff,
    MIB_TCPROW_LH, MIB_TCPROW_LH_0, TCP_ESTATS_TYPE,
};

use crate::util::trace;

#[derive(Default)]
struct TcpInfo {
    recv_window: Option<u32>,
    recv_queue: Option<u64>,
    send_queue: Option<u64>,
}

/// Append `-T` queue/window annotations to a socket row's NAME, in place.
/// No-op for non-TCP rows, listening sockets (no remote endpoint), and IPv6
/// (iteration 1). `-Ts` needs nothing here — state is already in the name.
pub fn annotate(file: &mut OpenFile, flags: &TcpInfoFlags, elevated: bool) {
    if !(flags.queue || flags.window) {
        return;
    }
    let Some(sock) = &file.socket else { return };
    if sock.protocol != Protocol::Tcp {
        return;
    }
    // EStats are only supported (and only meaningful) for an established
    // connection: TIME_WAIT and other closing states have no live TCB and
    // return ERROR_NOT_SUPPORTED (50). Skipping them avoids ~dozens of
    // doomed enable/read/disable round-trips on a busy host.
    if sock.state != Some(TcpState::Established) {
        return;
    }
    // EStats apply to a connected 4-tuple; listening rows have no remote.
    let (Some(SocketAddr::V4(local)), Some(SocketAddr::V4(remote))) = (sock.local, sock.remote)
    else {
        return;
    };
    let state = sock.state.map(mib_state).unwrap_or(0);
    let Some(info) = query_v4(local, remote, state, elevated, flags.queue, flags.window) else {
        return;
    };

    let mut suffix = String::new();
    if flags.window {
        if let Some(w) = info.recv_window {
            suffix.push_str(&format!(" (Win={w})"));
        }
    }
    if flags.queue {
        if let Some(q) = info.recv_queue {
            suffix.push_str(&format!(" (QR={q})"));
        }
        if let Some(q) = info.send_queue {
            suffix.push_str(&format!(" (QS={q})"));
        }
    }
    file.name.push_str(&suffix);
}

/// Map our [`TcpState`] back to the `MIB_TCP_STATE` number for the row key.
fn mib_state(s: TcpState) -> u32 {
    match s {
        TcpState::Closed => 1,
        TcpState::Listen => 2,
        TcpState::SynSent => 3,
        TcpState::SynReceived => 4,
        TcpState::Established => 5,
        TcpState::FinWait1 => 6,
        TcpState::FinWait2 => 7,
        TcpState::CloseWait => 8,
        TcpState::Closing => 9,
        TcpState::LastAck => 10,
        TcpState::TimeWait => 11,
        TcpState::DeleteTcb => 12,
        TcpState::Unknown => 0,
    }
}

/// Build the `MIB_TCPROW_LH` connection key. Address is stored as the in_addr
/// (network-order octets as a native u32); port is the network-order value in
/// the low 16 bits — the inverse of the decode in `sockets.rs`.
fn row_v4(local: SocketAddrV4, remote: SocketAddrV4, state: u32) -> MIB_TCPROW_LH {
    MIB_TCPROW_LH {
        Anonymous: MIB_TCPROW_LH_0 { dwState: state },
        dwLocalAddr: u32::from_ne_bytes(local.ip().octets()),
        dwLocalPort: local.port().to_be() as u32,
        dwRemoteAddr: u32::from_ne_bytes(remote.ip().octets()),
        dwRemotePort: remote.port().to_be() as u32,
    }
}

/// Enable / disable EStats collection of `estats` for one connection. The RW
/// struct for both REC and SEND_BUFF is a single `BOOLEAN` (`EnableCollection`).
fn set_collection(row: &MIB_TCPROW_LH, estats: TCP_ESTATS_TYPE, on: bool) -> u32 {
    let rw: u8 = on as u8;
    // SAFETY: row is a valid key; rw is a 1-byte buffer matching the RW struct.
    unsafe { SetPerTcpConnectionEStats(row, estats, &rw as *const u8, 0, 1, 0) }
}

fn query_v4(
    local: SocketAddrV4,
    remote: SocketAddrV4,
    state: u32,
    elevated: bool,
    want_q: bool,
    want_w: bool,
) -> Option<TcpInfo> {
    let row = row_v4(local, remote, state);
    let mut info = TcpInfo::default();

    // REC: receive window + receive app queue.
    if want_w || want_q {
        if elevated {
            let s = set_collection(&row, TcpConnectionEstatsRec, true);
            if s != 0 {
                trace(&format!("tcpinfo: enable Rec failed ({s})"));
            }
        }
        let mut rod: TCP_ESTATS_REC_ROD_v0 = unsafe { zeroed() };
        // SAFETY: rod is sized for the Rod buffer; rw/ros are unused (null).
        let st = unsafe {
            GetPerTcpConnectionEStats(
                &row,
                TcpConnectionEstatsRec,
                null_mut(),
                0,
                0,
                null_mut(),
                0,
                0,
                &mut rod as *mut _ as *mut u8,
                0,
                size_of::<TCP_ESTATS_REC_ROD_v0>() as u32,
            )
        };
        trace(&format!("tcpinfo: GetEStats Rec -> status {st}"));
        if st == 0 {
            if want_w {
                info.recv_window = Some(rod.CurRwinSent);
            }
            if want_q {
                info.recv_queue = Some(rod.CurAppRQueue as u64);
            }
        }
        if elevated {
            set_collection(&row, TcpConnectionEstatsRec, false);
        }
    }

    // SEND_BUFF: send app queue.
    if want_q {
        if elevated {
            let s = set_collection(&row, TcpConnectionEstatsSendBuff, true);
            if s != 0 {
                trace(&format!("tcpinfo: enable SendBuff failed ({s})"));
            }
        }
        let mut rod: TCP_ESTATS_SEND_BUFF_ROD_v0 = unsafe { zeroed() };
        // SAFETY: as above for the SendBuff Rod buffer.
        let st = unsafe {
            GetPerTcpConnectionEStats(
                &row,
                TcpConnectionEstatsSendBuff,
                null_mut(),
                0,
                0,
                null_mut(),
                0,
                0,
                &mut rod as *mut _ as *mut u8,
                0,
                size_of::<TCP_ESTATS_SEND_BUFF_ROD_v0>() as u32,
            )
        };
        trace(&format!("tcpinfo: GetEStats SendBuff -> status {st}"));
        if st == 0 {
            info.send_queue = Some(rod.CurAppWQueue as u64);
        }
        if elevated {
            set_collection(&row, TcpConnectionEstatsSendBuff, false);
        }
    }

    if info.recv_window.is_some() || info.recv_queue.is_some() || info.send_queue.is_some() {
        Some(info)
    } else {
        None
    }
}
