//! `-E` and `+E` where the backend leaves them to the core (Linux;
//! [`Selection::endpoints_in_core`](crate::Selection::endpoints_in_core)): the
//! other ends of a pipe, a UNIX socket, a pseudoterminal, a POSIX message
//! queue, an eventfd and a local TCP or UDP connection, named as the C names
//! them, from the rows every process gave and what the backend found beside
//! them ([`EndpointTables`]; DIVERGENCES 56).
//!
//! The C reads every process under `-E`/`+E` (`process_id()`: `if (!FeptE)
//! return (1)`), enters each end it meets in a table, and once the processes
//! to print are chosen, adds to the NAME of each of their selected rows, as
//! `Lf->nma`, the `PID,cmd,FDmode` of the other rows on the same object
//! (`main.c:1389-1504`):
//!
//! * a pipe, a POSIX message queue (any row on the `mqueue` file system, by
//!   inode) and an eventfd (by its `eventfd-id`): every other row on it, in
//!   the order the C met them (`endpoint_enter()`, `find_pepti()`,
//!   `find_psxmqinfo()`, `find_evtfdinfo()`, `dnode.c`);
//! * a socket whose local and remote addresses another established socket of
//!   the same protocol has the other way round: every row on that one, last
//!   met first (`get_netpeeri()`, `prt_nets_common()`, `dsock.c:1214-1410`);
//! * a UNIX socket: `->INO=N`, its peer's inode, then every row on the peer,
//!   last met first; and for a listener, the same of its first pending
//!   connection (`get_uxpeeri()`, `prt_uxs()`, `process_uxsinfo()`,
//!   `dsock.c:979-1205`), from `NETLINK_SOCK_DIAG`;
//! * a pseudoterminal: on the master (`/dev/ptmx`, by its `tty-index`),
//!   `->/dev/pts/N` and the first slave row, then the other slave rows; on a
//!   slave (by its minor), each master row, in the order met
//!   (`process_ptyinfo()`, `prt_ptyinfo()`, `lib/proc.c:1209-1320`).
//!
//! Under `+E` those other rows are listed too, each with its own ends,
//! whatever else selected or dropped them (`Lf->sf = Selflags`,
//! `lib/proc.c:958-972`).
//!
//! The command is cut to the `+c` width (`%.*s` with `CmdLim`: 9 by default,
//! and `+c 0` prints none of it); the access letter is a blank when unknown
//! (`access_to_char()`). The table prints the addition before a socket's
//! state, `-F n` with the name, and JSON not at all, as the C does.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

use crate::model::{
    AccessMode, FdType, FileType, OpenFile, Process, Protocol, SockState, TcpState,
};
use crate::render::escape::Escaper;
use crate::selection::{CommandWidth, EndpointMode};

/// A UNIX socket's ends, as the C's `get_uxpeeri()` found them in the
/// kernel's `NETLINK_SOCK_DIAG` dump, each one a socket of the run's own
/// `/proc/net/unix` (`check_unix()`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UnixEnds {
    /// The peer's inode: the first `UNIX_DIAG_PEER` that named it, from its
    /// own record or the peer's (`fill_uxpino()`, both ways round).
    pub peer: Option<u64>,
    /// A listener's first pending connection that `/proc/net/unix` lists,
    /// from `UNIX_DIAG_ICONS` (`fill_uxicino()`).
    pub incoming: Option<u64>,
}

/// What a backend found beside the rows for `-E`/`+E`, which no row
/// carries: each UNIX socket's ends, and each pseudoterminal master's index.
#[derive(Clone, Debug, Default)]
pub struct EndpointTables {
    /// [`UnixEnds`], by the socket's inode.
    pub unix: HashMap<u64, UnixEnds>,
    /// The `tty-index:` of each `/dev/ptmx` descriptor's fdinfo, by
    /// `(pid, tid, fd)`: the slave it is the master of.
    pub pty_index: HashMap<(u32, Option<u32>, u64), u32>,
}

/// What a row is an end of.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Key {
    /// A FIFO, by its inode alone, as the C keys it (`Lf->inode`): a pipe,
    /// or a named FIFO open in two places.
    Pipe(u64),
    /// An established TCP or UDP socket, by its inode.
    Inet(u64),
    /// A UNIX socket, by its inode.
    Unix(u64),
    /// A row on the `mqueue` file system, by its inode.
    Mq(u64),
    /// An eventfd, by its `eventfd-id`.
    EventFd(u32),
    /// A pseudoterminal, by its index: a master's `tty-index`, a slave's
    /// minor. One table holds both, as the C's `PtyInfo` does.
    Pty(u32),
}

/// `makedev(5, 2)`, `/dev/ptmx`, as `st_rdev` encodes it (`is_pty_ptmx()`).
const PTMX: u32 = 0x502;

/// The device's major and minor, from `st_rdev` as glibc encodes it.
fn major_minor(rdev: u32) -> (u32, u32) {
    (
        (rdev >> 8) & 0xfff,
        (rdev & 0xff) | ((rdev >> 12) & 0xf_ff00),
    )
}

/// A Unix98 pseudoterminal slave's major: 136 to 143
/// (`UNIX98_PTY_SLAVE_MAJOR`, `UNIX98_PTY_MAJOR_COUNT`; `is_pty_slave()`).
fn is_pty_slave(major: u32) -> bool {
    (136..144).contains(&major)
}

/// An eventfd's id, from the NAME the backend gave it, `[eventfd:N]`, the C's
/// own spelling of `eventfd-id: N` (`dproc.c:1285-1290`).
fn eventfd_id(f: &OpenFile) -> Option<u32> {
    if f.file_type != FileType::Other("a_inode".into()) {
        return None;
    }
    let digits = f
        .base_name()?
        .strip_prefix("[eventfd:")?
        .strip_suffix(']')?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // The C's `int`, a value past which it reads as no id (`dproc.c:536-541`).
    digits.parse::<u32>().ok().filter(|&n| n <= i32::MAX as u32)
}

/// Which side of a pseudoterminal a row is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Side {
    Master,
    Slave,
}

/// One row on an object: who holds it, and how the C names that.
#[derive(Clone, Debug)]
struct Holder {
    pid: u32,
    tid: Option<u32>,
    fd: FdType,
    /// The side of a pseudoterminal this row is; `None` for anything else.
    side: Option<Side>,
    /// `PID,cmd,FDmode`, in printed form ([`cut_command`]).
    text: String,
}

/// `cmd` as `%.*s` with `CmdLim` cuts it, bytes and none under `+c 0`, and
/// as `safestrprt()` then prints it: in printed form, the text escaped and
/// each byte that is no character `\xNN`. So a cut inside a character
/// prints the bytes it kept, `aaaaaaaa\xc3`, as the C does (measured), where
/// a lossy decode had made a U+FFFD that neither the C nor COMMAND shows.
fn cut_command(cmd: &[u8], width: CommandWidth) -> String {
    let n = match width {
        CommandWidth::Standard => crate::selection::DEFAULT_COMMAND_WIDTH,
        CommandWidth::Unlimited => 0,
        CommandWidth::Chars(n) => n,
    };
    let kept = cmd.get(..n.min(cmd.len())).unwrap_or_default();
    Escaper::for_host().bytes(kept).into_owned()
}

fn access_char(a: AccessMode) -> char {
    match a {
        AccessMode::Read => 'r',
        AccessMode::Write => 'w',
        AccessMode::ReadWrite => 'u',
        AccessMode::Unknown => ' ',
    }
}

/// One piece of a row's addition, and the row it names, if any (`+E` lists
/// that row).
struct Piece<'a> {
    text: Cow<'a, str>,
    holder: Option<&'a Holder>,
}

impl<'a> Piece<'a> {
    fn of(h: &'a Holder) -> Piece<'a> {
        Piece {
            text: Cow::Borrowed(&h.text),
            holder: Some(h),
        }
    }
}

/// Every end the gathered rows hold, as the C's tables hold them.
pub(crate) struct Index {
    /// Each pipe's, message queue's, eventfd's and pseudoterminal's rows in
    /// the order the C met them.
    in_order: HashMap<Key, Vec<Holder>>,
    /// Each Internet and UNIX socket's rows in the order met; the C
    /// prepends, so they are named last first.
    sockets: HashMap<Key, Vec<Holder>>,
    /// Each Internet socket's other end.
    peer: HashMap<u64, u64>,
    /// What the backend found beside the rows.
    tables: EndpointTables,
    /// The device of the `mqueue` file system the mount table recorded
    /// (`MqueueDev`): a row on it is a message queue's end.
    mqueue_device: Option<u64>,
}

/// The order the C reads the gathered entries in: by PID, a process's tasks
/// before the process itself (`dproc.c:349-406`), each in order.
fn reading_order(procs: &[Process]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..procs.len()).collect();
    order.sort_by_key(|&i| {
        let p = &procs[i];
        (p.pid, p.tid.is_none(), p.tid)
    });
    order
}

impl Index {
    /// [`Index::build_with`] with no tables and no `mqueue` file system: the
    /// ends the rows alone name.
    #[cfg(test)]
    pub(crate) fn build(procs: &[Process], width: CommandWidth) -> Index {
        Index::build_with(procs, width, EndpointTables::default(), None)
    }

    pub(crate) fn build_with(
        procs: &[Process],
        width: CommandWidth,
        tables: EndpointTables,
        mqueue_device: Option<u64>,
    ) -> Index {
        let mut index = Index {
            in_order: HashMap::new(),
            sockets: HashMap::new(),
            peer: HashMap::new(),
            tables,
            mqueue_device,
        };
        // A row is entered once: a task's descriptor is its process's, and
        // the C keeps the first (`endpoint_enter()`'s uniqueness check).
        let mut seen: HashSet<(Key, u32, FdType)> = HashSet::new();
        // Each socket's addresses, for the pairing, by family and protocol.
        let mut inet: Vec<(u64, bool, Protocol, SocketAddr, SocketAddr)> = Vec::new();
        for i in reading_order(procs) {
            let p = &procs[i];
            let mut cmd: Option<String> = None;
            for f in &p.files {
                let Some((k, side)) = index.key(p, f) else {
                    continue;
                };
                if !seen.insert((k, p.pid, f.fd.clone())) {
                    continue;
                }
                let cmd = cmd.get_or_insert_with(|| cut_command(p.command_bytes(), width));
                let holder = Holder {
                    pid: p.pid,
                    tid: p.tid,
                    fd: f.fd.clone(),
                    side,
                    text: format!(
                        "{},{},{}{}",
                        p.pid,
                        cmd,
                        f.fd.column_code(),
                        access_char(f.access)
                    ),
                };
                match k {
                    Key::Inet(ino) => {
                        let list = index.sockets.entry(k).or_default();
                        if list.is_empty() {
                            if let Some(s) = f.socket.as_deref() {
                                if let (Some(l), Some(r)) = (s.local, s.remote) {
                                    let v6 = f.file_type == FileType::Ipv6;
                                    inet.push((ino, v6, s.protocol, l, r));
                                }
                            }
                        }
                        list.push(holder);
                    }
                    Key::Unix(_) => index.sockets.entry(k).or_default().push(holder),
                    _ => index.in_order.entry(k).or_default().push(holder),
                }
            }
        }
        // `get_netpeeri()`: a socket's peer is the first one not yet paired
        // whose addresses are its own the other way round.
        let mut by_addr: HashMap<(bool, Protocol, SocketAddr, SocketAddr), Vec<u64>> =
            HashMap::new();
        for &(ino, v6, proto, l, r) in &inet {
            by_addr.entry((v6, proto, l, r)).or_default().push(ino);
        }
        for &(ino, v6, proto, l, r) in &inet {
            if index.peer.contains_key(&ino) {
                continue;
            }
            let found = by_addr
                .get(&(v6, proto, r, l))
                .and_then(|c| c.iter().copied().find(|c| !index.peer.contains_key(c)));
            if let Some(other) = found {
                index.peer.insert(ino, other);
                index.peer.insert(other, ino);
            }
        }
        index
    }

    /// What `f`, a row of entry `p`, is an end of, and which side of a
    /// pseudoterminal it is.
    fn key(&self, p: &Process, f: &OpenFile) -> Option<(Key, Option<Side>)> {
        let ino = |cell: &Option<String>| cell.as_deref()?.parse::<u64>().ok();
        let k = match f.file_type {
            FileType::Fifo => ino(&f.node).map(Key::Pipe),
            // An Internet socket's inode is its DEVICE cell; NODE is `TCP`.
            FileType::Ipv4 | FileType::Ipv6 => {
                let s = f.socket.as_deref()?;
                let established = s.state == Some(SockState::Tcp(TcpState::Established));
                let tcp_udp = matches!(s.protocol, Protocol::Tcp | Protocol::Udp);
                (established && tcp_udp && s.local.is_some() && s.remote.is_some())
                    .then(|| ino(&f.device))
                    .flatten()
                    .map(Key::Inet)
            }
            FileType::Unix => ino(&f.node).map(Key::Unix),
            FileType::Chr => {
                let rdev = f.rdev?.get();
                if rdev == PTMX {
                    let FdType::Handle(n) = f.fd else { return None };
                    let index = self.tables.pty_index.get(&(p.pid, p.tid, n))?;
                    return Some((Key::Pty(*index), Some(Side::Master)));
                }
                let (major, minor) = major_minor(rdev);
                if is_pty_slave(major) {
                    return Some((Key::Pty(minor), Some(Side::Slave)));
                }
                None
            }
            _ => None,
        };
        if let Some(k) = k {
            return Some((k, None));
        }
        // `Lf->dev == MqueueDev`, whatever the row is, before an eventfd.
        if self.mqueue_device.is_some() && f.fs_device == self.mqueue_device {
            return ino(&f.node).map(|i| (Key::Mq(i), None));
        }
        eventfd_id(f).map(|id| (Key::EventFd(id), None))
    }

    /// The rows named at `f`, a row of entry `p`, in the order the C adds
    /// them. `forced` is a row `+E` added (`process_*info(ctx, 1)`), where a
    /// UNIX socket names its pending connection only when it has no peer.
    fn ends(&self, p: &Process, f: &OpenFile, forced: bool) -> Vec<Piece<'_>> {
        let Some((k, side)) = self.key(p, f) else {
            return Vec::new();
        };
        let others = |k: &Key| {
            self.in_order
                .get(k)
                .into_iter()
                .flatten()
                .filter(|h| h.pid != p.pid || h.fd != f.fd)
                .map(Piece::of)
                .collect()
        };
        match k {
            Key::Pipe(_) | Key::Mq(_) | Key::EventFd(_) => others(&k),
            Key::Inet(ino) => self
                .peer
                .get(&ino)
                .and_then(|peer| self.sockets.get(&Key::Inet(*peer)))
                .into_iter()
                .flat_map(|l| l.iter().rev())
                .map(Piece::of)
                .collect(),
            Key::Unix(ino) => self.unix_ends(ino, forced),
            Key::Pty(n) => {
                let want = match side {
                    Some(Side::Master) => Side::Slave,
                    _ => Side::Master,
                };
                let mut out: Vec<Piece<'_>> = self
                    .in_order
                    .get(&k)
                    .into_iter()
                    .flatten()
                    .filter(|h| h.side == Some(want))
                    .map(Piece::of)
                    .collect();
                // The master names the slave's device before its first row.
                if side == Some(Side::Master) {
                    if let Some(first) = out.first_mut() {
                        first.text = Cow::Owned(format!("->/dev/pts/{n} {}", first.text));
                    }
                }
                out
            }
        }
    }

    /// `prt_uxs()` for a UNIX socket's peer, then, as `process_uxsinfo()`
    /// walks them, for its pending connection: `->INO=N`, then each row on
    /// socket N, last met first.
    fn unix_ends(&self, ino: u64, forced: bool) -> Vec<Piece<'_>> {
        let mut out = Vec::new();
        let ends = self.tables.unix.get(&ino).copied().unwrap_or_default();
        // `if (p && p->inode)`: a socket of inode 0 is named by no one.
        if let Some(peer) = ends.peer.filter(|&p| p != 0) {
            self.unix_socket(peer, &mut out);
            if forced {
                return out;
            }
        }
        // `p = tp->icons; while (p && p != tp) { if (p->inode) …; p =
        // p->icons; }`: one pending connection's own pending connection, and
        // so on, each once. A pending connection whose client has closed is
        // the kernel's inode 0 (`/proc/net/unix` lists the embryo so): it is
        // the listener's first, so a live one after it is never reached, and
        // it is not printed, as the C prints none (measured: a listener
        // whose first pending client closed shows `(LISTEN)` alone).
        let mut walked = HashSet::new();
        let mut next = ends.incoming;
        while let Some(n) = next {
            if n == ino || !walked.insert(n) {
                break;
            }
            if n != 0 {
                self.unix_socket(n, &mut out);
            }
            next = self.tables.unix.get(&n).and_then(|e| e.incoming);
        }
        out
    }

    /// `prt_uxs()`: `->INO=N`, then each row on UNIX socket N, last met
    /// first.
    fn unix_socket<'a>(&'a self, n: u64, out: &mut Vec<Piece<'a>>) {
        out.push(Piece {
            text: Cow::Owned(format!("->INO={n}")),
            holder: None,
        });
        out.extend(
            self.sockets
                .get(&Key::Unix(n))
                .into_iter()
                .flat_map(|l| l.iter().rev())
                .map(Piece::of),
        );
    }
}

/// The rows `+E` may add: each keyed row of each entry, by its place.
pub(crate) struct Candidates {
    /// Each entry with its keyed rows alone, in the gathered order.
    entries: Vec<Process>,
}

impl Candidates {
    pub(crate) fn of(procs: &[Process], index: &Index) -> Candidates {
        let keyed = |p: &Process, f: &OpenFile| index.key(p, f).is_some();
        let entries = procs
            .iter()
            .filter(|p| p.files.iter().any(|f| keyed(p, f)))
            .map(|p| Process {
                files: p.files.iter().filter(|f| keyed(p, f)).cloned().collect(),
                ..header(p)
            })
            .collect();
        Candidates { entries }
    }
}

/// Name the ends of every keyed row in `out`, the processes chosen to be
/// printed; under `+E`, add each end not printed yet, with its own ends.
pub(crate) fn annotate(
    index: &Index,
    out: &mut Vec<Process>,
    candidates: Option<Candidates>,
    mode: EndpointMode,
) {
    let mut forced: HashSet<(u32, Option<u32>, FdType)> = HashSet::new();
    for p in out.iter_mut() {
        let header = header(p);
        for f in &mut p.files {
            for piece in index.ends(&header, f, false) {
                if let (EndpointMode::Files, Some(h)) = (mode, piece.holder) {
                    forced.insert((h.pid, h.tid, h.fd.clone()));
                }
                f.add_printed_addition(&piece.text);
            }
        }
    }
    let Some(candidates) = candidates else { return };
    if forced.is_empty() {
        return;
    }
    let shown: HashSet<(u32, Option<u32>, FdType)> = out
        .iter()
        .flat_map(|p| p.files.iter().map(move |f| (p.pid, p.tid, f.fd.clone())))
        .collect();
    for mut c in candidates.entries {
        c.files.retain(|f| {
            forced.contains(&(c.pid, c.tid, f.fd.clone()))
                && !shown.contains(&(c.pid, c.tid, f.fd.clone()))
        });
        if c.files.is_empty() {
            continue;
        }
        let header = header(&c);
        for f in &mut c.files {
            for piece in index.ends(&header, f, true) {
                f.add_printed_addition(&piece.text);
            }
        }
        match out.iter().position(|p| p.pid == c.pid && p.tid == c.tid) {
            Some(i) => {
                let files = &mut out[i].files;
                for f in c.files {
                    // Among the descriptors, by number, as they were read.
                    let n = fd_number(&f.fd);
                    let at = files
                        .iter()
                        .position(|g| fd_number(&g.fd).is_some_and(|m| Some(m) > n))
                        .unwrap_or(files.len());
                    files.insert(at, f);
                }
            }
            None => {
                let at = out
                    .iter()
                    .position(|p| (p.pid, p.tid) > (c.pid, c.tid))
                    .unwrap_or(out.len());
                out.insert(at, c);
            }
        }
    }
}

/// `p` without its rows.
fn header(p: &Process) -> Process {
    Process {
        pid: p.pid,
        ppid: p.ppid,
        command: p.command.clone(),
        user: p.user.clone(),
        tid: p.tid,
        task_command: p.task_command.clone(),
        uid: p.uid,
        pgid: p.pgid,
        files: Vec::new(),
        endpoint_peer: p.endpoint_peer,
        unlisted: p.unlisted,
        // The command's own bytes, where it is not UTF-8: a row `+E` adds
        // prints them as the process's own rows do (DIVERGENCES 93).
        raw_names: p.raw_names.clone(),
    }
}

fn fd_number(fd: &FdType) -> Option<u64> {
    match fd {
        FdType::Handle(n) => Some(*n),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SocketInfo;

    fn row(fd: u64, ty: FileType, node: &str, access: AccessMode) -> OpenFile {
        OpenFile {
            rdev: None,
            fs_device: None,
            file_flags: None,
            lock: None,
            fd: FdType::Handle(fd),
            access,
            file_type: ty,
            name: "pipe".into(),
            device: None,
            size: None,
            offset: Some(0),
            node: Some(node.into()),
            links: None,
            socket: None,
            name_addition: None,
        }
    }

    fn tcp(fd: u64, inode: &str, l: &str, r: &str) -> OpenFile {
        let mut f = row(fd, FileType::Ipv4, "TCP", AccessMode::ReadWrite);
        f.device = Some(inode.into());
        f.name = format!("{l}->{r}");
        f.socket = Some(Box::new(SocketInfo {
            protocol: Protocol::Tcp,
            local: Some(l.parse().unwrap()),
            remote: Some(r.parse().unwrap()),
            state: Some(SockState::Tcp(TcpState::Established)),
            tcp: None,
            bound: None,
        }));
        f
    }

    fn proc_(pid: u32, cmd: &str, files: Vec<OpenFile>) -> Process {
        Process {
            pid,
            tid: None,
            task_command: None,
            ppid: None,
            pgid: None,
            uid: None,
            user: None,
            command: cmd.into(),
            files,
            endpoint_peer: false,
            unlisted: false,
            raw_names: None,
        }
    }

    #[test]
    fn a_pipe_names_its_other_rows_in_order_and_not_itself() {
        let procs = vec![
            proc_(
                10,
                "writer",
                vec![row(4, FileType::Fifo, "77", AccessMode::Write)],
            ),
            proc_(
                20,
                "a-very-long-name",
                vec![
                    row(3, FileType::Fifo, "77", AccessMode::Read),
                    row(5, FileType::Fifo, "77", AccessMode::Unknown),
                ],
            ),
        ];
        let index = Index::build(&procs, CommandWidth::Standard);
        let mut out = vec![procs[0].clone()];
        annotate(&index, &mut out, None, EndpointMode::Info);
        assert_eq!(out[0].files[0].name, "pipe 20,a-very-lo,3r 20,a-very-lo,5 ");
        assert_eq!(out[0].files[0].base_name(), Some("pipe"));
        // `+c 0`: `%.*s` with a precision of 0.
        let index = Index::build(&procs, CommandWidth::Unlimited);
        let mut out = vec![procs[1].clone()];
        annotate(&index, &mut out, None, EndpointMode::Info);
        assert_eq!(out[0].files[0].name, "pipe 10,,4w 20,,5 ");
        assert_eq!(out[0].files[1].name, "pipe 10,,4w 20,,3r");
    }

    #[test]
    fn a_local_connection_names_its_peers_holders_last_first() {
        let procs = vec![
            proc_(
                10,
                "srv",
                vec![tcp(3, "100", "127.0.0.1:80", "127.0.0.1:5000")],
            ),
            proc_(
                20,
                "cli",
                vec![tcp(4, "200", "127.0.0.1:5000", "127.0.0.1:80")],
            ),
            proc_(
                30,
                "cli2",
                vec![tcp(7, "200", "127.0.0.1:5000", "127.0.0.1:80")],
            ),
            // No peer: nothing.
            proc_(40, "far", vec![tcp(3, "300", "10.0.0.1:1", "10.0.0.2:2")]),
        ];
        let index = Index::build(&procs, CommandWidth::Standard);
        let mut out = vec![procs[0].clone(), procs[3].clone()];
        annotate(&index, &mut out, None, EndpointMode::Info);
        assert_eq!(
            out[0].files[0].name,
            "127.0.0.1:80->127.0.0.1:5000 30,cli2,7u 20,cli,4u"
        );
        assert_eq!(out[1].files[0].name, "10.0.0.1:1->10.0.0.2:2");
    }

    /// Only an established TCP or UDP socket is an end (`TcpUdpIPC` enters
    /// only `TCP_ESTABLISHED`, `dsock.c:2673`), and a socket's peer is the
    /// first not yet paired whose addresses are its own the other way round
    /// under the same protocol (`get_netpeeri()`).
    #[test]
    fn a_peer_is_established_of_the_same_protocol_and_not_yet_paired() {
        let with = |f: OpenFile, proto: Protocol, state: TcpState| {
            let mut f = f;
            if let Some(s) = f.socket.as_mut() {
                s.protocol = proto;
                s.state = Some(SockState::Tcp(state));
            }
            f
        };
        let l = "127.0.0.1:80";
        let r = "127.0.0.1:5000";
        // E1: a SYN_SENT socket is no end, though its tuple fits.
        let procs = vec![
            proc_(10, "a", vec![tcp(3, "100", l, r)]),
            proc_(
                20,
                "b",
                vec![with(tcp(4, "200", r, l), Protocol::Tcp, TcpState::SynSent)],
            ),
        ];
        let index = Index::build(&procs, CommandWidth::Standard);
        let mut out = vec![procs[0].clone()];
        annotate(&index, &mut out, None, EndpointMode::Info);
        assert_eq!(out[0].files[0].name, format!("{l}->{r}"));
        // E2: a protocol neither TCP nor UDP is no end.
        let procs = vec![
            proc_(
                10,
                "a",
                vec![with(
                    tcp(3, "100", l, r),
                    Protocol::Other("RAW"),
                    TcpState::Established,
                )],
            ),
            proc_(
                20,
                "b",
                vec![with(
                    tcp(4, "200", r, l),
                    Protocol::Other("RAW"),
                    TcpState::Established,
                )],
            ),
        ];
        let index = Index::build(&procs, CommandWidth::Standard);
        let mut out = vec![procs[0].clone()];
        annotate(&index, &mut out, None, EndpointMode::Info);
        assert_eq!(out[0].files[0].name, format!("{l}->{r}"));
        // E4: UDP is no TCP socket's peer, whatever its tuple.
        let procs = vec![
            proc_(10, "a", vec![tcp(3, "100", l, r)]),
            proc_(
                20,
                "b",
                vec![with(
                    tcp(4, "200", r, l),
                    Protocol::Udp,
                    TcpState::Established,
                )],
            ),
        ];
        let index = Index::build(&procs, CommandWidth::Standard);
        let mut out = procs.clone();
        annotate(&index, &mut out, None, EndpointMode::Info);
        assert_eq!(out[0].files[0].name, format!("{l}->{r}"));
        assert_eq!(out[1].files[0].name, format!("{r}->{l}"));
        // E7: of two sockets on the reversed tuple, the first pairs with
        // the one, and the second finds it taken: no end.
        let procs = vec![
            proc_(10, "a", vec![tcp(3, "100", l, r)]),
            proc_(20, "b", vec![tcp(4, "200", r, l)]),
            proc_(30, "c", vec![tcp(5, "300", r, l)]),
        ];
        let index = Index::build(&procs, CommandWidth::Standard);
        let mut out = procs.clone();
        annotate(&index, &mut out, None, EndpointMode::Info);
        assert_eq!(out[0].files[0].name, format!("{l}->{r} 20,b,4u"));
        assert_eq!(out[1].files[0].name, format!("{r}->{l} 10,a,3u"));
        assert_eq!(out[2].files[0].name, format!("{r}->{l}"));
    }

    /// E17: `+E` puts a forced row of a printed process among its rows by
    /// number, after every one with a lower number: at the end when none is
    /// higher.
    #[test]
    fn plus_e_puts_a_forced_row_after_the_lower_numbered_ones() {
        let procs = vec![
            proc_(
                10,
                "w",
                vec![row(4, FileType::Fifo, "77", AccessMode::Write)],
            ),
            proc_(
                20,
                "r",
                vec![
                    row(1, FileType::Regular, "5", AccessMode::Write),
                    row(9, FileType::Fifo, "77", AccessMode::Read),
                ],
            ),
        ];
        let index = Index::build(&procs, CommandWidth::Standard);
        let mut out = vec![
            procs[0].clone(),
            proc_(
                20,
                "r",
                vec![row(1, FileType::Regular, "5", AccessMode::Write)],
            ),
        ];
        out[1]
            .files
            .push(row(2, FileType::Regular, "6", AccessMode::Read));
        annotate(
            &index,
            &mut out,
            Some(Candidates::of(&procs, &index)),
            EndpointMode::Files,
        );
        let fds: Vec<String> = out[1].files.iter().map(|f| f.fd.code()).collect();
        assert_eq!(fds, ["1", "2", "9"]);
    }

    #[test]
    fn plus_e_adds_each_end_with_its_own_ends() {
        let procs = vec![
            proc_(
                10,
                "w",
                vec![row(4, FileType::Fifo, "77", AccessMode::Write)],
            ),
            proc_(
                20,
                "r",
                vec![
                    row(1, FileType::Regular, "5", AccessMode::Write),
                    row(3, FileType::Fifo, "77", AccessMode::Read),
                ],
            ),
        ];
        let index = Index::build(&procs, CommandWidth::Standard);
        let mut out = vec![procs[0].clone()];
        annotate(
            &index,
            &mut out,
            Some(Candidates::of(&procs, &index)),
            EndpointMode::Files,
        );
        assert_eq!(out.len(), 2);
        assert_eq!(out[1].pid, 20);
        assert_eq!(out[1].files.len(), 1, "only the end is added");
        assert_eq!(out[1].files[0].name, "pipe 10,w,4w");
        // An end already printed is not added again, and keeps one name.
        let mut out = procs.clone();
        annotate(
            &index,
            &mut out,
            Some(Candidates::of(&procs, &index)),
            EndpointMode::Files,
        );
        assert_eq!(out[1].files.len(), 2);
        assert_eq!(out[1].files[1].name, "pipe 10,w,4w");
        // Into a printed process, among its descriptors by number.
        let mut out = vec![
            procs[0].clone(),
            proc_(
                20,
                "r",
                vec![row(1, FileType::Regular, "5", AccessMode::Write)],
            ),
        ];
        out[1]
            .files
            .push(row(9, FileType::Regular, "6", AccessMode::Read));
        annotate(
            &index,
            &mut out,
            Some(Candidates::of(&procs, &index)),
            EndpointMode::Files,
        );
        let fds: Vec<String> = out[1].files.iter().map(|f| f.fd.code()).collect();
        assert_eq!(fds, ["1", "3", "9"]);
    }

    #[test]
    fn a_tasks_row_is_entered_before_its_process_and_once() {
        let mut task = proc_(
            20,
            "r",
            vec![row(3, FileType::Fifo, "77", AccessMode::Read)],
        );
        task.tid = Some(21);
        let procs = vec![
            proc_(
                10,
                "w",
                vec![row(4, FileType::Fifo, "77", AccessMode::Write)],
            ),
            proc_(
                20,
                "r",
                vec![row(3, FileType::Fifo, "77", AccessMode::Read)],
            ),
            task,
        ];
        let index = Index::build(&procs, CommandWidth::Standard);
        let holders = &index.in_order[&Key::Pipe(77)];
        assert_eq!(holders.len(), 2);
        assert_eq!((holders[1].pid, holders[1].tid), (20, Some(21)));
    }

    #[test]
    fn a_command_cut_inside_a_character_prints_the_bytes_it_kept() {
        let w9 = CommandWidth::Standard;
        // `aaaaaaaa\xc3\xa9zz`, valid UTF-8, cut at 9 bytes: the C's
        // `pipe 446,aaaaaaaa\xc3,3r` (measured).
        assert_eq!(cut_command("aaaaaaaaézz".as_bytes(), w9), "aaaaaaaa\\xc3");
        assert_eq!(cut_command("é".as_bytes(), CommandWidth::Chars(1)), "\\xc3");
        // Three bytes of a four-byte character.
        assert_eq!(
            cut_command("😀".as_bytes(), CommandWidth::Chars(3)),
            "\\xf0\\x9f\\x98"
        );
        // A whole character is text; a command that is not UTF-8 is its bytes.
        assert_eq!(cut_command("abé".as_bytes(), CommandWidth::Chars(4)), "abé");
        assert_eq!(
            cut_command(b"abcd\xc3\xa9\xff", CommandWidth::Chars(15)),
            "abcdé\\xff"
        );
        assert_eq!(cut_command(b"ab", w9), "ab");
        // Windows paths keep `\` bare (`Escaper::WINDOWS`); elsewhere the
        // C doubles it.
        let bs = if cfg!(windows) { "\\" } else { "\\\\" };
        assert_eq!(cut_command(b"a b\\\x1b", w9), format!("a b{bs}^["));
        assert_eq!(cut_command(b"abc", CommandWidth::Unlimited), "");
    }

    /// The text is stored printed: the table and `-F n` print the cut byte
    /// as `\xc3`, and JSON's name is the base alone.
    #[test]
    fn an_end_with_a_cut_command_prints_its_bytes_escaped() {
        let procs = vec![
            proc_(
                10,
                "w",
                vec![row(4, FileType::Fifo, "77", AccessMode::Write)],
            ),
            proc_(
                20,
                "aaaaaaaaézz",
                vec![row(3, FileType::Fifo, "77", AccessMode::Read)],
            ),
        ];
        let index = Index::build(&procs, CommandWidth::Standard);
        let mut out = vec![procs[0].clone()];
        annotate(&index, &mut out, None, EndpointMode::Info);
        let f = &out[0].files[0];
        assert_eq!(f.printed_name(&Escaper::UNIX), "pipe 20,aaaaaaaa\\xc3,3r");
        assert_eq!(f.base_name(), Some("pipe"));
        // The raw bytes of a command that is not UTF-8, not its lossy text.
        let mut raw = procs.clone();
        raw[1].command = "\u{fffd}x".into();
        raw[1].raw_names = Some(Box::new(crate::model::RawNames {
            command: Some(b"\xffx".to_vec().into()),
            login: None,
        }));
        let index = Index::build(&raw, CommandWidth::Standard);
        let mut out = vec![raw[0].clone()];
        annotate(&index, &mut out, None, EndpointMode::Info);
        assert_eq!(
            out[0].files[0].printed_name(&Escaper::UNIX),
            "pipe 20,\\xffx,3r"
        );
    }

    fn unix(fd: u64, ino: &str) -> OpenFile {
        let mut f = row(fd, FileType::Unix, ino, AccessMode::ReadWrite);
        f.name = "type=STREAM".into();
        f
    }

    fn chr(fd: u64, rdev: u32, access: AccessMode) -> OpenFile {
        let mut f = row(fd, FileType::Chr, "94", access);
        f.rdev = std::num::NonZeroU32::new(rdev);
        f.name = "/dev/x".into();
        f
    }

    fn named(out: &[Process], pid: u32, fd: u64) -> String {
        let p = out.iter().find(|p| p.pid == pid).expect("the process");
        let f = p
            .files
            .iter()
            .find(|f| f.fd == FdType::Handle(fd))
            .expect("the row");
        f.printed_name(&Escaper::UNIX).into_owned()
    }

    fn tables(unix: &[(u64, Option<u64>, Option<u64>)]) -> EndpointTables {
        EndpointTables {
            unix: unix
                .iter()
                .map(|&(i, peer, incoming)| (i, UnixEnds { peer, incoming }))
                .collect(),
            pty_index: HashMap::new(),
        }
    }

    /// Measured: `type=STREAM ->INO=2650 495,python3,5u 493,python3,5u`, the
    /// peer's holders last met first, the row's own process among them; a
    /// listener's first pending connection the same way; and a peer no row
    /// holds `->INO=N` alone.
    #[test]
    fn a_unix_socket_names_its_peer_and_a_listener_its_first_pending_connection() {
        let procs = vec![
            proc_(
                10,
                "srv",
                vec![
                    unix(3, "100"),
                    unix(4, "101"),
                    unix(6, "300"),
                    unix(7, "400"),
                ],
            ),
            proc_(
                20,
                "cli",
                vec![unix(4, "101"), unix(5, "200"), unix(9, "201")],
            ),
        ];
        let t = tables(&[
            (100, Some(200), None),
            (200, Some(100), None),
            (300, None, Some(201)),
            (400, Some(999), None),
        ]);
        let index = Index::build_with(&procs, CommandWidth::Standard, t, None);
        let mut out = procs.clone();
        annotate(&index, &mut out, None, EndpointMode::Info);
        assert_eq!(named(&out, 10, 3), "type=STREAM ->INO=200 20,cli,5u");
        assert_eq!(named(&out, 20, 5), "type=STREAM ->INO=100 10,srv,3u");
        assert_eq!(named(&out, 10, 6), "type=STREAM ->INO=201 20,cli,9u");
        assert_eq!(named(&out, 10, 7), "type=STREAM ->INO=999");
        // A socket with no end named, and one held twice, are left alone.
        assert_eq!(named(&out, 10, 4), "type=STREAM");
        assert_eq!(named(&out, 20, 9), "type=STREAM");
        // JSON's name is the base.
        let f = &out[0].files[0];
        assert_eq!(f.base_name(), Some("type=STREAM"));
    }

    #[test]
    fn a_unix_peers_holders_are_named_last_met_first_each_once() {
        // The peer held by both processes and by a task of the first, whose
        // row is the process's own descriptor: entered once.
        let mut task = proc_(10, "a", vec![unix(5, "2")]);
        task.tid = Some(11);
        let procs = vec![
            proc_(10, "a", vec![unix(4, "1"), unix(5, "2")]),
            task,
            proc_(30, "b", vec![unix(5, "2")]),
        ];
        let t = tables(&[(1, Some(2), None), (2, Some(1), None)]);
        let index = Index::build_with(&procs, CommandWidth::Standard, t, None);
        let mut out = vec![procs[0].clone()];
        annotate(&index, &mut out, None, EndpointMode::Info);
        assert_eq!(named(&out, 10, 4), "type=STREAM ->INO=2 30,b,5u 10,a,5u");
    }

    /// A listener's first pending connection whose client closed is inode 0
    /// (`/proc/net/unix` lists the embryo so): `if (p->inode)`, it is not
    /// printed, and the walk goes on from it, which names nothing more;
    /// measured, `/tmp/l1 type=STREAM (LISTEN)`, where lsof-rs had printed
    /// `->INO=0`. A peer of inode 0 is named by no one either, and a forced
    /// row then names its pending connection, as for no peer.
    #[test]
    fn a_pending_connection_or_peer_of_inode_0_is_not_named() {
        let procs = vec![proc_(10, "srv", vec![unix(3, "100"), unix(4, "300")])];
        let t = tables(&[
            (100, None, Some(0)),
            (0, None, Some(200)),
            (300, Some(0), Some(400)),
        ]);
        let index = Index::build_with(&procs, CommandWidth::Standard, t, None);
        let mut out = procs.clone();
        annotate(&index, &mut out, None, EndpointMode::Info);
        assert_eq!(named(&out, 10, 3), "type=STREAM ->INO=200");
        assert_eq!(named(&out, 10, 4), "type=STREAM ->INO=400");
        // With no entry for 0, the walk ends at it.
        let t = tables(&[(100, None, Some(0))]);
        let index = Index::build_with(&procs, CommandWidth::Standard, t, None);
        let mut out = procs.clone();
        annotate(&index, &mut out, None, EndpointMode::Info);
        assert_eq!(named(&out, 10, 3), "type=STREAM");
        assert!(index.unix_ends(300, true).is_empty());
        let t = tables(&[(300, Some(0), Some(400))]);
        let index = Index::build_with(&procs, CommandWidth::Standard, t, None);
        let forced: Vec<String> = index
            .unix_ends(300, true)
            .into_iter()
            .map(|p| p.text.into_owned())
            .collect();
        assert_eq!(forced, ["->INO=400"], "no peer: its pending connection");
    }

    /// The pending connections are walked each once: a dump whose listeners
    /// name each other, which no sane kernel sends, and one that names
    /// itself, end the walk where the C's `p != tp` and a visit ends it,
    /// rather than looping without end.
    #[test]
    fn the_pending_walk_ends_at_a_cycle_or_the_listener_itself() {
        let procs = vec![proc_(10, "srv", vec![unix(3, "1"), unix(4, "5")])];
        let t = tables(&[
            (1, None, Some(2)),
            (2, None, Some(3)),
            (3, None, Some(2)),
            (5, None, Some(5)),
        ]);
        let index = Index::build_with(&procs, CommandWidth::Standard, t, None);
        let mut out = procs.clone();
        annotate(&index, &mut out, None, EndpointMode::Info);
        assert_eq!(named(&out, 10, 3), "type=STREAM ->INO=2 ->INO=3");
        assert_eq!(named(&out, 10, 4), "type=STREAM", "its own is not named");
        // Two listeners that name each other: each names the other, once.
        let t = tables(&[(1, None, Some(5)), (5, None, Some(1))]);
        let index = Index::build_with(&procs, CommandWidth::Standard, t, None);
        let mut out = procs.clone();
        annotate(&index, &mut out, None, EndpointMode::Info);
        assert_eq!(named(&out, 10, 3), "type=STREAM ->INO=5 10,srv,4u");
        assert_eq!(named(&out, 10, 4), "type=STREAM ->INO=1 10,srv,3u");
    }

    /// A row `+E` adds keeps its process's command bytes (DIVERGENCES 93):
    /// `p<child>` `cx?y\xff,z…` as the C prints it, not U+FFFD.
    #[test]
    fn a_row_plus_e_adds_keeps_its_commands_bytes() {
        let mut child = proc_(20, "x\u{fffd}", vec![unix(4, "2")]);
        child.raw_names = Some(Box::new(crate::model::RawNames {
            command: Some(b"x\xff".to_vec().into()),
            login: None,
        }));
        let procs = vec![proc_(10, "a", vec![unix(3, "1")]), child];
        let t = tables(&[(1, Some(2), None), (2, Some(1), None)]);
        let index = Index::build_with(&procs, CommandWidth::Standard, t, None);
        let mut out = vec![procs[0].clone()];
        let c = Candidates::of(&procs, &index);
        annotate(&index, &mut out, Some(c), EndpointMode::Files);
        assert_eq!(out.len(), 2);
        assert_eq!(out[1].command_bytes(), b"x\xff");
        assert_eq!(named(&out, 10, 3), "type=STREAM ->INO=2 20,x\\xff,4u");
    }

    /// A descriptor of 10000 or more is `*%03d` in a holder's text, as the
    /// C's `fd_to_string()` prints it (measured: `PID,python3,*000u` for fd
    /// 10000); not on Windows, which has no C.
    #[test]
    fn a_holder_of_fd_10000_or_more_is_star_and_three_digits() {
        let procs = vec![
            proc_(
                10,
                "a",
                vec![row(9999, FileType::Fifo, "7", AccessMode::Write)],
            ),
            proc_(
                20,
                "b",
                vec![
                    row(10_000, FileType::Fifo, "7", AccessMode::Read),
                    row(12_345, FileType::Fifo, "7", AccessMode::Read),
                ],
            ),
        ];
        let index = Index::build(&procs, CommandWidth::Standard);
        let mut out = vec![procs[0].clone()];
        annotate(&index, &mut out, None, EndpointMode::Info);
        let want = if cfg!(windows) {
            "pipe 20,b,10000r 20,b,12345r"
        } else {
            "pipe 20,b,*000r 20,b,*345r"
        };
        assert_eq!(named(&out, 10, 9999), want);
        let mut out = vec![procs[1].clone()];
        annotate(&index, &mut out, None, EndpointMode::Info);
        assert!(named(&out, 20, 10_000).starts_with("pipe 10,a,9999w"));
        // The column the same; `-F f` and JSON print [`FdType::code`], the
        // number whole (measured: `f10000`).
        let col = |n| FdType::Handle(n).column_code();
        if cfg!(windows) {
            assert_eq!(col(10_000), "10000");
        } else {
            assert_eq!(
                (col(9999), col(10_000), col(10_999)),
                ("9999".into(), "*000".into(), "*999".into())
            );
            assert_eq!(col(1_234_567), "*567");
        }
        assert_eq!(FdType::Handle(10_000).code(), "10000");
        assert_eq!(FdType::Cwd.column_code(), "cwd");
    }

    /// `+E`: the peer's rows are listed, each naming its own peer; a forced
    /// listener names its pending connection only for want of a peer.
    #[test]
    fn plus_e_lists_a_unix_peers_rows() {
        let procs = vec![
            proc_(10, "a", vec![unix(3, "1")]),
            proc_(20, "b", vec![unix(4, "2"), unix(8, "50")]),
        ];
        let t = tables(&[(1, Some(2), None), (2, Some(1), Some(1))]);
        let index = Index::build_with(&procs, CommandWidth::Standard, t, None);
        let mut out = vec![procs[0].clone()];
        let c = Candidates::of(&procs, &index);
        annotate(&index, &mut out, Some(c), EndpointMode::Files);
        assert_eq!(out.len(), 2);
        assert_eq!(named(&out, 10, 3), "type=STREAM ->INO=2 20,b,4u");
        assert_eq!(named(&out, 20, 4), "type=STREAM ->INO=1 10,a,3u");
        assert!(out[1].files.iter().all(|f| f.fd != FdType::Handle(8)));
        // Unforced, both are named.
        let mut out = vec![procs[1].clone()];
        annotate(&index, &mut out, None, EndpointMode::Info);
        assert_eq!(
            named(&out, 20, 4),
            "type=STREAM ->INO=1 10,a,3u ->INO=1 10,a,3u"
        );
    }

    /// Measured: `/dev/ptmx ->/dev/pts/0 686,python3,8u` on the master, and
    /// `/dev/pts/0 684,python3,7u` on the slave; a master names every slave
    /// row, the device before the first alone.
    #[test]
    fn a_pseudoterminal_names_its_other_side() {
        let slave0 = 136 << 8; // 136,0
        let slave_far = (143 << 8) | (0x1200 << 12) | 0x34; // 143,0x1234
        let procs = vec![
            proc_(
                10,
                "m",
                vec![
                    chr(7, PTMX, AccessMode::ReadWrite),
                    chr(9, PTMX, AccessMode::ReadWrite),
                ],
            ),
            proc_(
                20,
                "s",
                vec![
                    chr(0, slave0, AccessMode::Read),
                    chr(1, slave0, AccessMode::Write),
                ],
            ),
            proc_(
                30,
                "t",
                vec![
                    chr(2, slave0, AccessMode::ReadWrite),
                    chr(3, slave_far, AccessMode::Read),
                ],
            ),
            // /dev/null and /dev/tty are no pseudoterminal ends.
            proc_(
                40,
                "n",
                vec![
                    chr(4, 0x103, AccessMode::Read),
                    chr(5, 0x500, AccessMode::Read),
                ],
            ),
        ];
        let mut t = EndpointTables::default();
        t.pty_index.insert((10, None, 7), 0);
        t.pty_index.insert((10, None, 9), 0x1234);
        let index = Index::build_with(&procs, CommandWidth::Standard, t, None);
        let mut out = procs.clone();
        annotate(&index, &mut out, None, EndpointMode::Info);
        assert_eq!(
            named(&out, 10, 7),
            "/dev/x ->/dev/pts/0 20,s,0r 20,s,1w 30,t,2u"
        );
        assert_eq!(named(&out, 10, 9), "/dev/x ->/dev/pts/4660 30,t,3r");
        assert_eq!(named(&out, 20, 0), "/dev/x 10,m,7u");
        assert_eq!(named(&out, 30, 3), "/dev/x 10,m,9u");
        assert_eq!(named(&out, 40, 4), "/dev/x");
        assert_eq!(named(&out, 40, 5), "/dev/x");
        // A master whose index was not read names nothing.
        let index = Index::build(&procs, CommandWidth::Standard);
        let mut out = procs.clone();
        annotate(&index, &mut out, None, EndpointMode::Info);
        assert_eq!(named(&out, 10, 7), "/dev/x");
        assert_eq!(named(&out, 20, 0), "/dev/x");
    }

    /// Measured: `/lsofrs-mq 684,python3,4r 686,python3,3u 686,python3,4r`,
    /// every other row on the queue in the order met, only once the mount
    /// table recorded the `mqueue` file system; a cwd on it is an end too.
    #[test]
    fn a_message_queue_names_its_other_rows_on_the_mqueue_device() {
        let mq = |fd: FdType, access| {
            let mut f = row(0, FileType::Other("PSXMQ".into()), "1841", access);
            f.fd = fd;
            f.fs_device = Some(0x14);
            f.name = "/q".into();
            f
        };
        let procs = vec![
            proc_(
                10,
                "a",
                vec![
                    mq(FdType::Cwd, AccessMode::Unknown),
                    mq(FdType::Handle(3), AccessMode::ReadWrite),
                ],
            ),
            proc_(20, "b", vec![mq(FdType::Handle(4), AccessMode::Read)]),
        ];
        let index = Index::build_with(
            &procs,
            CommandWidth::Standard,
            EndpointTables::default(),
            Some(0x14),
        );
        let mut out = procs.clone();
        annotate(&index, &mut out, None, EndpointMode::Info);
        assert_eq!(named(&out, 10, 3), "/q 10,a,cwd  20,b,4r");
        assert_eq!(named(&out, 20, 4), "/q 10,a,cwd  10,a,3u");
        // No mqueue recorded (`-b`, or none mounted): no ends.
        let index = Index::build(&procs, CommandWidth::Standard);
        let mut out = procs.clone();
        annotate(&index, &mut out, None, EndpointMode::Info);
        assert_eq!(named(&out, 10, 3), "/q");
    }

    /// Measured: `[eventfd:6] 684,python3,6u 686,python3,5u 686,python3,6u`.
    #[test]
    fn an_eventfd_names_its_other_rows_by_its_id() {
        let ev = |fd, name: &str| {
            let mut f = row(
                fd,
                FileType::Other("a_inode".into()),
                "1030",
                AccessMode::ReadWrite,
            );
            f.name = name.into();
            f
        };
        let procs = vec![
            proc_(
                10,
                "a",
                vec![
                    ev(5, "[eventfd:6]"),
                    ev(6, "[eventfd:6]"),
                    ev(7, "[eventfd:7]"),
                ],
            ),
            proc_(
                20,
                "b",
                vec![
                    ev(5, "[eventfd:6]"),
                    ev(8, "[eventfd]"),
                    ev(9, "[eventpoll:5]"),
                ],
            ),
        ];
        let index = Index::build(&procs, CommandWidth::Standard);
        let mut out = procs.clone();
        annotate(&index, &mut out, None, EndpointMode::Info);
        assert_eq!(named(&out, 10, 5), "[eventfd:6] 10,a,6u 20,b,5u");
        assert_eq!(named(&out, 20, 5), "[eventfd:6] 10,a,5u 10,a,6u");
        assert_eq!(named(&out, 10, 7), "[eventfd:7]");
        assert_eq!(named(&out, 20, 8), "[eventfd]");
        assert_eq!(named(&out, 20, 9), "[eventpoll:5]");
    }

    #[test]
    fn an_eventfd_id_is_the_cs_int() {
        let ev = |name: &str| {
            let mut f = row(1, FileType::Other("a_inode".into()), "1", AccessMode::Read);
            f.name = name.into();
            f
        };
        assert_eq!(eventfd_id(&ev("[eventfd:0]")), Some(0));
        assert_eq!(
            eventfd_id(&ev("[eventfd:2147483647]")),
            Some(i32::MAX as u32)
        );
        for no in [
            "[eventfd:2147483648]",
            "[eventfd:]",
            "[eventfd:-1]",
            "[eventfd:+1]",
            "[eventfd:1",
            "eventfd:1]",
        ] {
            assert_eq!(eventfd_id(&ev(no)), None, "{no}");
        }
        let mut f = ev("[eventfd:3]");
        f.file_type = FileType::Regular;
        assert_eq!(eventfd_id(&f), None, "a file so named is none");
    }

    #[test]
    fn a_devices_major_and_minor_are_glibcs() {
        assert_eq!(major_minor(0x502), (5, 2));
        assert_eq!(major_minor(136 << 8), (136, 0));
        assert_eq!(
            major_minor((143 << 8) | (0xab00 << 12) | 0xcd),
            (143, 0xabcd)
        );
        assert!(is_pty_slave(136) && is_pty_slave(143));
        assert!(!is_pty_slave(135) && !is_pty_slave(144));
    }
}
