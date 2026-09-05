//! A deterministic in-memory [`Backend`] used for unit/golden tests and as a
//! stand-in when the CLI is built on a non-Windows host (so the full
//! parse → select → render pipeline can be exercised anywhere).

use std::net::SocketAddr;

use crate::backend::{Backend, BackendError};
use crate::model::{
    AccessMode, FdType, FileType, OpenFile, Process, Protocol, SocketInfo, TcpState,
};
use crate::selection::Selection;

/// A small, fixed set of processes covering a regular file, a directory, a
/// listening TCP socket, an established TCP socket, and a UDP socket.
///
/// A socket's `name` holds the endpoints and nothing else: the state is carried
/// in `SocketInfo::state` and each renderer decides where it goes (a table
/// suffix, a `-F` `TST=` token, a JSON key). Baking it into the name here would
/// make the table and `-F n` report it twice, which is the shape a backend has
/// to avoid too.
pub fn sample_processes() -> Vec<Process> {
    let addr = |s: &str| -> SocketAddr { s.parse().expect("valid test addr") };
    vec![
        Process {
            uid: None,
            pgid: None,
            pid: 1000,
            ppid: Some(4),
            command: "explorer.exe".into(),
            user: Some("EXAMPLE\\alice".into()),
            endpoint_peer: false,
            files: vec![
                OpenFile {
                    fs_device: None,
                    file_flags: None,
                    lock: None,
                    fd: FdType::Cwd,
                    access: AccessMode::Read,
                    file_type: FileType::Dir,
                    name: "C:\\Users\\alice".into(),
                    device: Some("C:".into()),
                    size: None,
                    offset: None,
                    node: None,
                    links: None,
                    socket: None,
                },
                OpenFile {
                    fs_device: None,
                    file_flags: None,
                    lock: None,
                    fd: FdType::Handle(220),
                    access: AccessMode::Read,
                    file_type: FileType::Regular,
                    name: "C:\\Windows\\System32\\config.dat".into(),
                    device: Some("C:".into()),
                    size: Some(4096),
                    offset: None,
                    node: Some("123456".into()),
                    links: None,
                    socket: None,
                },
            ],
        },
        Process {
            uid: None,
            pgid: None,
            pid: 1500,
            ppid: Some(1000),
            command: "server.exe".into(),
            user: Some("EXAMPLE\\alice".into()),
            endpoint_peer: false,
            files: vec![
                OpenFile {
                    fs_device: None,
                    file_flags: None,
                    lock: None,
                    fd: FdType::Handle(72),
                    access: AccessMode::ReadWrite,
                    file_type: FileType::Ipv4,
                    name: "*:445".into(),
                    device: None,
                    size: None,
                    offset: None,
                    node: Some("TCP".into()),
                    links: None,
                    socket: Some(SocketInfo {
                        protocol: Protocol::Tcp,
                        local: Some(addr("0.0.0.0:445")),
                        remote: None,
                        state: Some(TcpState::Listen.into()),
                        tcp: None,
                    }),
                },
                OpenFile {
                    fs_device: None,
                    file_flags: None,
                    lock: None,
                    fd: FdType::Handle(88),
                    access: AccessMode::ReadWrite,
                    file_type: FileType::Ipv4,
                    name: "127.0.0.1:445->127.0.0.1:51000".into(),
                    device: None,
                    size: None,
                    offset: None,
                    node: Some("TCP".into()),
                    links: None,
                    socket: Some(SocketInfo {
                        protocol: Protocol::Tcp,
                        local: Some(addr("127.0.0.1:445")),
                        remote: Some(addr("127.0.0.1:51000")),
                        state: Some(TcpState::Established.into()),
                        tcp: None,
                    }),
                },
                OpenFile {
                    fs_device: None,
                    file_flags: None,
                    lock: None,
                    fd: FdType::Handle(96),
                    access: AccessMode::ReadWrite,
                    file_type: FileType::Ipv6,
                    name: "[::]:53".into(),
                    device: None,
                    size: None,
                    offset: None,
                    node: Some("UDP".into()),
                    links: None,
                    socket: Some(SocketInfo {
                        protocol: Protocol::Udp,
                        local: Some(addr("[::]:53")),
                        remote: None,
                        state: None,
                        tcp: None,
                    }),
                },
            ],
        },
    ]
}

/// Backend that always returns [`sample_processes`].
#[derive(Debug, Default)]
pub struct MockBackend;

impl Backend for MockBackend {
    fn name(&self) -> &str {
        "mock"
    }

    fn gather(&self, _sel: &Selection) -> Result<Vec<Process>, BackendError> {
        Ok(sample_processes())
    }
}
