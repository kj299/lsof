//! Reverse-DNS host resolution for socket display (the default; `-n` opts out).
//!
//! Uses Winsock `GetNameInfoW`. The numeric IP is turned into a `SOCKADDR` via
//! `WSAStringToAddressW` (which avoids hand-constructing the address unions),
//! and `NI_NAMEREQD` makes a missing PTR record fall back to numeric. Like lsof,
//! resolution is on by default and can be slow, hence the `-n` opt-out.

use std::mem::size_of;
use std::net::IpAddr;
use std::sync::Once;

use windows_sys::Win32::Networking::WinSock::{
    GetNameInfoW, WSAStartup, WSAStringToAddressW, AF_INET, AF_INET6, SOCKADDR, SOCKADDR_STORAGE,
    WSADATA,
};

const NI_NAMEREQD: i32 = 0x0004;

static WSA: Once = Once::new();

fn ensure_wsa() {
    WSA.call_once(|| {
        let mut data: WSADATA = unsafe { std::mem::zeroed() };
        // SAFETY: standard Winsock startup, version 2.2.
        unsafe { WSAStartup(0x0202, &mut data) };
    });
}

/// Resolve an IP address to a host name, or `None` if there is no PTR record.
pub fn host_name(ip: IpAddr) -> Option<String> {
    ensure_wsa();

    let af = if ip.is_ipv6() { AF_INET6 } else { AF_INET };
    let mut wide: Vec<u16> = ip
        .to_string()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut storage: SOCKADDR_STORAGE = unsafe { std::mem::zeroed() };
    let mut len = size_of::<SOCKADDR_STORAGE>() as i32;

    // SAFETY: `wide` is NUL-terminated; storage/len are paired and correctly sized.
    let rc = unsafe {
        WSAStringToAddressW(
            wide.as_mut_ptr(),
            af as i32,
            std::ptr::null(),
            &mut storage as *mut _ as *mut SOCKADDR,
            &mut len,
        )
    };
    if rc != 0 {
        return None;
    }

    let mut host = [0u16; 256];
    // SAFETY: `storage` holds a valid SOCKADDR of `len` bytes; host/len paired.
    let rc = unsafe {
        GetNameInfoW(
            &storage as *const _ as *const SOCKADDR,
            len,
            host.as_mut_ptr(),
            host.len() as u32,
            std::ptr::null_mut(),
            0,
            NI_NAMEREQD,
        )
    };
    if rc != 0 {
        return None;
    }
    let name = crate::util::wide_to_string(&host);
    (!name.is_empty()).then_some(name)
}
