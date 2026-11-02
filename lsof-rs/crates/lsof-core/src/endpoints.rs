//! `-E` and `+E` where the backend leaves them to the core (Linux;
//! [`Selection::endpoints_in_core`](crate::Selection::endpoints_in_core)): a pipe's other ends and a local TCP or
//! UDP connection's other end, named as the C names them, from the rows every
//! process gave (DIVERGENCES 56).
//!
//! The C reads every process under `-E`/`+E` (`process_id()`: `if (!FeptE)
//! return (1)`), enters each pipe and each established TCP or UDP socket it
//! meets in a table, and once the processes to print are chosen, adds to the
//! NAME of each of their selected rows, as `Lf->nma`, the `PID,cmd,FDmode` of
//! the other rows on the same object (`main.c:1389-1504`): for a pipe, every
//! other descriptor on the pipe, in the order the C met them
//! (`find_pepti()`, `dnode.c:144-232`); for a socket whose local and remote
//! addresses another established socket of the same protocol has the other
//! way round, every descriptor on that one, last met first
//! (`get_netpeeri()`, `prt_nets_common()`, `dsock.c:1214-1410`). Under `+E`
//! those other rows are listed too, each with its own ends, whatever else
//! selected or dropped them (`Lf->sf = Selflags`, `lib/proc.c:958-972`).
//!
//! The command is cut to the `+c` width (`%.*s` with `CmdLim`: 9 by default,
//! and `+c 0` prints none of it); the access letter is a blank when unknown
//! (`access_to_char()`). The table prints the addition before a socket's
//! state, `-F n` with the name, and JSON not at all, as the C does.
//!
//! Not yet: a UNIX socket's peer (the C asks `NETLINK_SOCK_DIAG`, which needs
//! a binding this crate's dependency policy has not taken), a pseudoterminal,
//! a POSIX message queue and an eventfd (DIVERGENCES 56).

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

use crate::model::{
    AccessMode, FdType, FileType, OpenFile, Process, Protocol, SockState, TcpState,
};
use crate::render::escape::Escaper;
use crate::selection::{CommandWidth, EndpointMode};

/// What a row is an end of.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Key {
    /// A FIFO, by its inode alone, as the C keys it (`Lf->inode`): a pipe,
    /// or a named FIFO open in two places.
    Pipe(u64),
    /// An established TCP or UDP socket, by its inode.
    Inet(u64),
}

fn key(f: &OpenFile) -> Option<Key> {
    let ino = |cell: &Option<String>| cell.as_deref()?.parse::<u64>().ok();
    match f.file_type {
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
        _ => None,
    }
}

/// One row on an object: who holds it, and how the C names that.
#[derive(Clone, Debug)]
struct Holder {
    pid: u32,
    tid: Option<u32>,
    fd: FdType,
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

/// Every end the gathered rows hold, as the C's tables hold them.
pub(crate) struct Index {
    /// Each pipe's rows in the order the C met them.
    pipes: HashMap<u64, Vec<Holder>>,
    /// Each socket's rows in the order met; the C prepends, so they are
    /// named last first.
    inet: HashMap<u64, Vec<Holder>>,
    /// Each socket's other end.
    peer: HashMap<u64, u64>,
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
    pub(crate) fn build(procs: &[Process], width: CommandWidth) -> Index {
        let mut index = Index {
            pipes: HashMap::new(),
            inet: HashMap::new(),
            peer: HashMap::new(),
        };
        // A row is entered once: a task's descriptor is its process's, and
        // the C keeps the first (`endpoint_enter()`'s uniqueness check).
        let mut seen: HashSet<(Key, u32, FdType)> = HashSet::new();
        // Each socket's addresses, for the pairing, by family and protocol.
        let mut sockets: Vec<(u64, bool, Protocol, SocketAddr, SocketAddr)> = Vec::new();
        for i in reading_order(procs) {
            let p = &procs[i];
            let mut cmd: Option<String> = None;
            for f in &p.files {
                let Some(k) = key(f) else { continue };
                if !seen.insert((k, p.pid, f.fd.clone())) {
                    continue;
                }
                let cmd = cmd.get_or_insert_with(|| cut_command(p.command_bytes(), width));
                let holder = Holder {
                    pid: p.pid,
                    tid: p.tid,
                    fd: f.fd.clone(),
                    text: format!("{},{},{}{}", p.pid, cmd, f.fd.code(), access_char(f.access)),
                };
                match k {
                    Key::Pipe(ino) => index.pipes.entry(ino).or_default().push(holder),
                    Key::Inet(ino) => {
                        let list = index.inet.entry(ino).or_default();
                        if list.is_empty() {
                            if let Some(s) = f.socket.as_deref() {
                                if let (Some(l), Some(r)) = (s.local, s.remote) {
                                    let v6 = f.file_type == FileType::Ipv6;
                                    sockets.push((ino, v6, s.protocol, l, r));
                                }
                            }
                        }
                        list.push(holder);
                    }
                }
            }
        }
        // `get_netpeeri()`: a socket's peer is the first one not yet paired
        // whose addresses are its own the other way round.
        let mut by_addr: HashMap<(bool, Protocol, SocketAddr, SocketAddr), Vec<u64>> =
            HashMap::new();
        for &(ino, v6, proto, l, r) in &sockets {
            by_addr.entry((v6, proto, l, r)).or_default().push(ino);
        }
        for &(ino, v6, proto, l, r) in &sockets {
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

    /// The rows named at `f`, a row of entry `p`: the pipe's other rows, or
    /// the peer socket's.
    fn ends(&self, p: &Process, f: &OpenFile) -> Vec<&Holder> {
        match key(f) {
            Some(Key::Pipe(ino)) => self
                .pipes
                .get(&ino)
                .into_iter()
                .flatten()
                .filter(|h| h.pid != p.pid || h.fd != f.fd)
                .collect(),
            Some(Key::Inet(ino)) => self
                .peer
                .get(&ino)
                .and_then(|peer| self.inet.get(peer))
                .into_iter()
                .flat_map(|l| l.iter().rev())
                .collect(),
            None => Vec::new(),
        }
    }
}

/// The rows `+E` may add: each keyed row of each entry, by its place.
pub(crate) struct Candidates {
    /// Each entry with its keyed rows alone, in the gathered order.
    entries: Vec<Process>,
}

impl Candidates {
    pub(crate) fn of(procs: &[Process]) -> Candidates {
        let entries = procs
            .iter()
            .filter(|p| p.files.iter().any(|f| key(f).is_some()))
            .map(|p| Process {
                files: p
                    .files
                    .iter()
                    .filter(|f| key(f).is_some())
                    .cloned()
                    .collect(),
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
            for h in index.ends(&header, f) {
                if mode == EndpointMode::Files {
                    forced.insert((h.pid, h.tid, h.fd.clone()));
                }
                f.add_printed_addition(&h.text);
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
            for h in index.ends(&header, f) {
                f.add_printed_addition(&h.text);
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
        raw_names: None,
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
            Some(Candidates::of(&procs)),
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
            Some(Candidates::of(&procs)),
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
            Some(Candidates::of(&procs)),
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
            Some(Candidates::of(&procs)),
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
        let holders = &index.pipes[&77];
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
        assert_eq!(cut_command(b"a b\\\x1b", w9), "a b\\\\^[");
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
}
