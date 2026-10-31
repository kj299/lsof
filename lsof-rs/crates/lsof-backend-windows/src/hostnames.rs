//! Reverse DNS for the socket rows of one run: which runs need it at all, and
//! looking each distinct address up once, on a small bounded pool.
//!
//! A socket's NAME used to resolve its local and its remote host one at a
//! time, each a fresh `resolve::host_name` call that waits up to 2 s, and
//! nothing remembered an answer. A host's sockets repeat a handful of
//! addresses (`127.0.0.1`, `::1`, its own, a few peers) across every row, so on
//! a resolver that does not answer PTR queries the run paid 2 s per endpoint,
//! serially: measured on a Windows 11 host, an unelevated `lsof` with 145
//! socket endpoints spent **83 s** here, and `lsof -N -V`, which can never
//! print a socket, 66 s. Now each distinct address is looked up once, at most
//! [`WORKERS`] lookups dispatched at a time, and every row is formatted from
//! the answers; and a run in which no socket row can print, or that gave `-n`,
//! looks nothing up.
//!
//! Portable (not `#[cfg(windows)]`) so its rules are unit-tested on Linux: the
//! lookup itself is the caller's (`resolve::host_name` on Windows), handed in
//! as a closure. The whole decision of the backend's call site is
//! [`socket_host_names`]; what stays Windows-only is the call itself, the
//! formatting of each row from the answers (`sockets::resolve_name`) and the
//! per-lookup bound inside `resolve::host_name`.

#![deny(clippy::arithmetic_side_effects)]

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use lsof_core::model::OpenFile;
use lsof_core::selection::{SelKinds, Selection};

/// The most lookups the pool dispatches at once: its worker threads. Enough
/// that a few dozen distinct addresses against a silent resolver cost a few
/// rounds of the per-lookup timeout rather than one per address; few enough
/// that a host with hundreds of peers does not start hundreds of lookups at
/// once.
///
/// It bounds the lookups *waited on*, not the OS queries in flight: a lookup
/// that `resolve::host_name` abandons at [`LOOKUP_TIMEOUT`] leaves its
/// `GetNameInfoW` thread running until the OS resolver gives up, while the
/// worker moves on to its next address. So with a resolver slower than the
/// timeout more than this many OS queries can be outstanding; the threads of
/// the phase stay bounded by the distinct addresses plus these workers, one
/// lookup thread per address at most.
pub const WORKERS: usize = 8;

/// What one lookup may take before its address is shown numerically — the
/// bound `resolve::host_name` applies to each call.
pub const LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);

/// Headroom over the rounds of [`LOOKUP_TIMEOUT`] for thread start-up and
/// scheduling, so a lookup the per-call bound lets finish is never cut off by
/// the phase's own.
const PHASE_SLACK: Duration = Duration::from_secs(1);

/// Each looked-up address and what it resolved to; `None` is "no name" (no
/// PTR record, a failure, or a timeout). An address absent from the map was
/// not answered within the phase budget. Either way the row shows it
/// numerically, as a lookup that timed out always has.
pub type HostNames = HashMap<IpAddr, Option<String>>;

/// Whether any socket row this run gathers can be printed with its NAME, so
/// that resolving host names for it can change the output. Only what is
/// provable from the selection says no:
///
/// * a path or directory argument (`FILE`, `+d`, `+D`), which a socket never
///   matches by name and which skipped resolution before;
/// * `-t`, which prints PIDs alone — and `-F`/`-J`/`-j`, the formats that
///   could show a name, are refused beside it;
/// * `-N` under `-a`, or `-N` as the only selecter: a row needs every
///   specified kind under `-a`, and some kind under the OR, and the NFS kind
///   is set only for a file on an NFS file system's device. A socket row has
///   no file-system device, so it can never carry it, and the process kinds
///   a row inherits never include it.
///
/// Anything else may print a socket, including under the OR a process
/// selecter beside `-N` (`-N -p P` lists P's sockets).
pub fn socket_names_printable(sel: &Selection) -> bool {
    if sel.has_path_filter() || sel.terse {
        return false;
    }
    if sel.nfs_only && (sel.and_mode || sel.specified() == SelKinds::NFS) {
        return false;
    }
    true
}

/// The distinct addresses among `ips` worth a lookup, in first-seen order. The
/// unspecified address is always shown as `*` and never looked up.
pub fn distinct_hosts(ips: impl IntoIterator<Item = IpAddr>) -> Vec<IpAddr> {
    let mut seen = HashSet::new();
    ips.into_iter()
        .filter(|ip| !ip.is_unspecified() && seen.insert(*ip))
        .collect()
}

/// The addresses of the socket rows among `files` whose host names a row can
/// show: every local and remote host, each once ([`distinct_hosts`]). A row
/// without a socket has none.
pub fn hosts_of<'a>(files: impl IntoIterator<Item = &'a OpenFile>) -> Vec<IpAddr> {
    distinct_hosts(
        files
            .into_iter()
            .filter_map(|f| f.socket.as_deref())
            .flat_map(|s| [s.local, s.remote])
            .flatten()
            .map(|a| a.ip()),
    )
}

/// The addresses this run looks up for the socket rows `files`: none when no
/// socket NAME can print ([`socket_names_printable`]) or `-n` keeps hosts
/// numeric, else [`hosts_of`] them.
pub fn hosts_to_resolve<'a>(
    sel: &Selection,
    files: impl IntoIterator<Item = &'a OpenFile>,
) -> Vec<IpAddr> {
    if !socket_names_printable(sel) || sel.no_host_resolve {
        return Vec::new();
    }
    hosts_of(files)
}

/// The backend's whole decision for the socket rows `files` it keeps.
///
/// `None`: no socket NAME can print, so the rows keep the numeric name they
/// were collected with and nothing is looked up or reformatted. `Some(hosts)`:
/// format every row from `hosts` — empty under `-n`, so every host is numeric
/// without a lookup; otherwise each of [`hosts_to_resolve`] looked up once
/// with `lookup` on [`WORKERS`] threads, each lookup bounded by
/// [`LOOKUP_TIMEOUT`] ([`resolve_all`]). `trace` gets a start and a done line
/// around the lookups (`LSOF_RS_TRACE`).
pub fn socket_host_names<'a, F>(
    sel: &Selection,
    files: impl IntoIterator<Item = &'a OpenFile>,
    lookup: F,
    trace: impl Fn(&str),
) -> Option<HostNames>
where
    F: Fn(IpAddr) -> Option<String> + Send + Sync + 'static,
{
    if !socket_names_printable(sel) {
        return None;
    }
    let addrs = hosts_to_resolve(sel, files);
    if addrs.is_empty() {
        return Some(HostNames::new());
    }
    trace(&format!(
        "gather: resolve hosts start ({} distinct)",
        addrs.len()
    ));
    let hosts = resolve_all(addrs, WORKERS, LOOKUP_TIMEOUT, lookup);
    trace(&format!(
        "gather: resolve hosts done ({} answered, {} named)",
        hosts.len(),
        hosts.values().filter(|h| h.is_some()).count()
    ));
    Some(hosts)
}

/// The whole phase's ceiling for `distinct` lookups on `workers` threads, each
/// lookup bounded by `per_lookup`: the rounds the pool needs, plus slack. It
/// is a backstop, not the normal path — the phase ends as soon as every answer
/// is in — for a lookup that overruns its own bound.
pub fn phase_budget(distinct: usize, workers: usize, per_lookup: Duration) -> Duration {
    let rounds = distinct.div_ceil(workers.max(1));
    u32::try_from(rounds)
        .ok()
        .and_then(|r| per_lookup.checked_mul(r))
        .and_then(|d| d.checked_add(PHASE_SLACK))
        .unwrap_or(Duration::MAX)
}

/// The loop one pool worker runs.
type Job = Box<dyn FnOnce() + Send + 'static>;

/// Start `job` on a named, detached thread; `false` if the OS refuses one.
fn spawn_thread(job: Job) -> bool {
    std::thread::Builder::new()
        .name("lsof-rdns".to_string())
        .spawn(job)
        .is_ok()
}

/// Look up every address in `addrs` (already distinct) with `lookup`, on at
/// most `workers` threads, each lookup expected within `per_lookup`.
///
/// Each worker takes the next address not yet taken, so no address is looked
/// up twice. The wait ends as soon as every answer is in, or every worker has
/// stopped (one whose lookup panicked included), or at the backstop
/// [`phase_budget`] of the workers that actually started. A worker is never
/// joined: one still inside `lookup` at the backstop is abandoned (its address
/// is then absent from the result), and it stops at its next send, which
/// fails once this function has returned, looking nothing more up; process
/// exit does not wait for it. A worker the OS refuses to start is not
/// started, the backstop counts only those that did, and its share is done by
/// them; if none starts, nothing is looked up and every address shows
/// numerically.
pub fn resolve_all<F>(
    addrs: Vec<IpAddr>,
    workers: usize,
    per_lookup: Duration,
    lookup: F,
) -> HostNames
where
    F: Fn(IpAddr) -> Option<String> + Send + Sync + 'static,
{
    resolve_with(addrs, workers, per_lookup, lookup, spawn_thread)
}

/// [`resolve_all`] with the worker start-up handed in, so a refused spawn is
/// testable.
fn resolve_with<F>(
    addrs: Vec<IpAddr>,
    workers: usize,
    per_lookup: Duration,
    lookup: F,
    mut spawn: impl FnMut(Job) -> bool,
) -> HostNames
where
    F: Fn(IpAddr) -> Option<String> + Send + Sync + 'static,
{
    let mut out = HostNames::with_capacity(addrs.len());
    if addrs.is_empty() {
        return out;
    }
    let want = addrs.len();
    let addrs = Arc::new(addrs);
    let next = Arc::new(AtomicUsize::new(0));
    let lookup = Arc::new(lookup);
    let (tx, rx) = mpsc::channel();
    let mut started: usize = 0;
    for _ in 0..workers.clamp(1, want) {
        let (addrs, next, lookup, tx) = (
            Arc::clone(&addrs),
            Arc::clone(&next),
            Arc::clone(&lookup),
            tx.clone(),
        );
        // A refused spawn drops the job, and its sender with it.
        let job: Job = Box::new(move || {
            // `fetch_add` hands each index to exactly one worker. It cannot
            // wrap: each worker stops at the first index past the end, so the
            // counter ends at most `workers` beyond `want`.
            while let Some(&ip) = addrs.get(next.fetch_add(1, Ordering::Relaxed)) {
                if tx.send((ip, lookup(ip))).is_err() {
                    break; // the phase is over; nobody reads this answer
                }
            }
        });
        if spawn(job) {
            started = started.saturating_add(1);
        }
    }
    // Ours dropped, the channel closes once every worker is done, dead or
    // never started, which ends the wait without spending the budget.
    drop(tx);
    let deadline = Instant::now().checked_add(phase_budget(want, started, per_lookup));
    while out.len() < want {
        let got = match deadline {
            Some(d) => {
                let left = d.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    break;
                }
                rx.recv_timeout(left).ok()
            }
            None => rx.recv().ok(),
        };
        let Some((ip, name)) = got else { break };
        out.insert(ip, name);
    }
    out
}

/// The name `hosts` gives `ip`, if a lookup found one.
pub fn cached_name(hosts: &HostNames, ip: IpAddr) -> Option<String> {
    hosts.get(&ip).cloned().flatten()
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Mutex;

    fn v4(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, n))
    }

    #[test]
    fn distinct_hosts_dedups_in_order_and_skips_unspecified() {
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let lo6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let any = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let any6 = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
        let got = distinct_hosts([lo, any, v4(1), lo, lo6, any6, v4(1), lo6]);
        assert_eq!(got, vec![lo, v4(1), lo6]);
        assert!(distinct_hosts([any, any6]).is_empty());
    }

    fn sock(local: &str, remote: Option<&str>) -> OpenFile {
        use lsof_core::model::{AccessMode, FdType, FileType, Protocol, SocketInfo};
        OpenFile {
            rdev: None,
            fs_device: None,
            file_flags: None,
            lock: None,
            fd: FdType::Unknown,
            access: AccessMode::ReadWrite,
            file_type: FileType::Ipv4,
            name: String::new(),
            device: None,
            size: None,
            offset: None,
            node: Some("TCP".to_string()),
            links: None,
            socket: Some(Box::new(SocketInfo {
                bound: None,
                protocol: Protocol::Tcp,
                local: Some(local.parse().unwrap()),
                remote: remote.map(|r| r.parse().unwrap()),
                state: None,
                tcp: None,
            })),
            name_addition: None,
        }
    }

    #[test]
    fn hosts_of_takes_both_ends_of_every_socket_once() {
        let mut plain = sock("192.0.2.9:1", None);
        plain.socket = None;
        let files = [
            sock("127.0.0.1:5000", Some("127.0.0.1:6000")),
            sock("0.0.0.0:135", None),
            sock("[::1]:80", Some("[2001:db8::1]:443")),
            plain,
            sock("192.0.2.1:7", Some("127.0.0.1:9")),
        ];
        let got = hosts_of(&files);
        let want: Vec<IpAddr> = ["127.0.0.1", "::1", "2001:db8::1", "192.0.2.1"]
            .iter()
            .map(|a| a.parse().unwrap())
            .collect();
        assert_eq!(got, want);
    }

    #[test]
    fn each_address_is_looked_up_once() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&calls);
        let addrs = distinct_hosts((0..40).map(|i| v4(i % 10)));
        let got = resolve_all(addrs, 4, Duration::from_secs(10), move |ip| {
            seen.lock().unwrap().push(ip);
            (ip == v4(3)).then(|| "three.example".to_string())
        });
        let mut calls = calls.lock().unwrap().clone();
        calls.sort();
        let mut want: Vec<IpAddr> = (0..10).map(v4).collect();
        want.sort();
        assert_eq!(calls, want, "every distinct address, once");
        assert_eq!(got.len(), 10, "and every answer kept, \"no name\" too");
        assert_eq!(cached_name(&got, v4(3)).as_deref(), Some("three.example"));
        assert_eq!(got.get(&v4(4)), Some(&None));
        assert_eq!(cached_name(&got, v4(4)), None);
        assert_eq!(cached_name(&got, v4(200)), None, "never asked");
    }

    /// A lookup that holds until `target` lookups are inside it at once (or
    /// `hold` passes), recording the most that were.
    fn gathering_lookup(
        target: usize,
        hold: Duration,
    ) -> (
        Arc<AtomicUsize>,
        Arc<AtomicUsize>,
        impl Fn(IpAddr) -> Option<String> + Send + Sync + 'static,
    ) {
        let calls = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let live = Arc::new(AtomicUsize::new(0));
        let (c, p) = (Arc::clone(&calls), Arc::clone(&peak));
        let lookup = move |_| {
            c.fetch_add(1, Ordering::SeqCst);
            let now = live.fetch_add(1, Ordering::SeqCst) + 1;
            p.fetch_max(now, Ordering::SeqCst);
            let t0 = Instant::now();
            while live.load(Ordering::SeqCst) < target && t0.elapsed() < hold {
                std::thread::sleep(Duration::from_millis(1));
            }
            std::thread::sleep(Duration::from_millis(5));
            live.fetch_sub(1, Ordering::SeqCst);
            None
        };
        (calls, peak, lookup)
    }

    #[test]
    fn exactly_workers_lookups_run_at_once() {
        let (_, peak, lookup) = gathering_lookup(6, Duration::from_millis(500));
        let addrs: Vec<IpAddr> = (0..48).map(v4).collect();
        let got = resolve_all(addrs, 6, Duration::from_secs(10), lookup);
        assert_eq!(got.len(), 48);
        assert_eq!(peak.load(Ordering::SeqCst), 6, "lookups at once");
    }

    #[test]
    fn slow_lookups_cost_rounds_not_addresses() {
        // 16 lookups of 400 ms: 6.4 s one at a time, 1.6 s on 4 workers, 0.8 s
        // on 8.
        let addrs: Vec<IpAddr> = (0..16).map(v4).collect();
        let start = Instant::now();
        let got = resolve_all(addrs, 8, Duration::from_secs(10), |_| {
            std::thread::sleep(Duration::from_millis(400));
            None
        });
        assert_eq!(got.len(), 16);
        let took = start.elapsed();
        assert!(took < Duration::from_millis(1400), "took {took:?}");
    }

    #[test]
    fn the_pool_constants_are_pinned() {
        // The brief's bound per lookup, kept from before the pool: a longer
        // one lets names that used to time out resolve, changing output.
        assert_eq!(LOOKUP_TIMEOUT, Duration::from_secs(2));
        assert!((8..=16).contains(&WORKERS), "WORKERS = {WORKERS}");
    }

    #[test]
    fn a_panicking_lookup_ends_the_wait_without_the_budget() {
        // A 10 s per-lookup bound makes the backstop over 20 s; the wait must
        // end once the workers have stopped, the panicked one included.
        let addrs = vec![v4(1), v4(2), v4(3)];
        let start = Instant::now();
        let got = resolve_all(addrs, 2, Duration::from_secs(10), |ip| {
            if ip == v4(2) {
                panic!("lookup failed");
            }
            Some(format!("h{ip}"))
        });
        let took = start.elapsed();
        assert!(took < Duration::from_secs(5), "took {took:?}");
        assert!(!got.contains_key(&v4(2)));
        assert_eq!(cached_name(&got, v4(1)).as_deref(), Some("h192.0.2.1"));
        assert_eq!(cached_name(&got, v4(3)).as_deref(), Some("h192.0.2.3"));
    }

    #[test]
    fn abandoned_workers_look_nothing_more_up() {
        // One worker, 100 lookups of 50 ms (5 s) against a backstop of
        // 100 x 1 ms + slack: cut off after about a fifth.
        let calls = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&calls);
        let addrs: Vec<IpAddr> = (0..100).map(v4).collect();
        let got = resolve_all(addrs, 1, Duration::from_millis(1), move |_| {
            c.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(50));
            None
        });
        assert!(got.len() < 100, "the backstop cut the phase off");
        let at_return = calls.load(Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(400));
        let later = calls.load(Ordering::SeqCst);
        assert!(
            later <= at_return + 1,
            "{at_return} lookups at return, {later} after"
        );
    }

    #[test]
    fn the_backstop_counts_the_workers_that_started() {
        // 8 asked for, 1 started: 6 lookups of 300 ms take 1.8 s, inside its
        // backstop of 6 x 300 ms + slack, though one round for 8 workers
        // (300 ms + slack) would cut them off.
        let mut asked = 0;
        let addrs: Vec<IpAddr> = (0..6).map(v4).collect();
        let got = resolve_with(
            addrs,
            8,
            Duration::from_millis(300),
            |_| {
                std::thread::sleep(Duration::from_millis(300));
                None
            },
            |job| {
                asked += 1;
                asked == 1 && spawn_thread(job)
            },
        );
        assert_eq!(asked, 6, "one start asked for per address, at most");
        assert_eq!(got.len(), 6, "every lookup answered");
    }

    #[test]
    fn no_worker_started_looks_nothing_up() {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&calls);
        let start = Instant::now();
        let got = resolve_with(
            vec![v4(1), v4(2)],
            8,
            Duration::from_secs(10),
            move |_| {
                c.fetch_add(1, Ordering::SeqCst);
                None
            },
            |_| false,
        );
        assert!(got.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_lookup_that_never_returns_is_abandoned_at_the_budget() {
        let addrs = vec![v4(1), v4(2), v4(3)];
        let start = Instant::now();
        let got = resolve_all(addrs, 8, Duration::from_millis(200), |ip| {
            if ip == v4(2) {
                std::thread::sleep(Duration::from_secs(30));
            }
            Some(format!("h{ip}"))
        });
        let took = start.elapsed();
        assert!(took < Duration::from_secs(5), "took {took:?}");
        assert_eq!(cached_name(&got, v4(1)).as_deref(), Some("h192.0.2.1"));
        assert_eq!(cached_name(&got, v4(3)).as_deref(), Some("h192.0.2.3"));
        assert!(
            !got.contains_key(&v4(2)),
            "the wedged one shows numerically"
        );
    }

    #[test]
    fn the_wait_ends_when_the_answers_are_in() {
        let start = Instant::now();
        let got = resolve_all(vec![v4(1)], 8, Duration::from_secs(30), |_| None);
        assert_eq!(got.len(), 1);
        assert!(start.elapsed() < Duration::from_secs(10));
        assert!(resolve_all(Vec::new(), 8, Duration::ZERO, |_| unreachable!()).is_empty());
    }

    #[test]
    fn zero_workers_still_resolves() {
        let got = resolve_all(vec![v4(1), v4(2)], 0, Duration::from_secs(10), |_| {
            Some("x".to_string())
        });
        assert_eq!(got.len(), 2);
    }

    #[test]
    fn the_budget_is_rounds_of_the_timeout_plus_slack() {
        let t = Duration::from_secs(2);
        assert_eq!(phase_budget(0, 8, t), PHASE_SLACK);
        assert_eq!(phase_budget(1, 8, t), t + PHASE_SLACK);
        assert_eq!(phase_budget(8, 8, t), t + PHASE_SLACK);
        assert_eq!(phase_budget(9, 8, t), 2 * t + PHASE_SLACK);
        assert_eq!(phase_budget(145, 8, t), 19 * t + PHASE_SLACK);
        assert_eq!(phase_budget(3, 0, t), 3 * t + PHASE_SLACK, "0 workers is 1");
        assert_eq!(phase_budget(usize::MAX, 1, t), Duration::MAX, "saturates");
        assert_eq!(phase_budget(1, 1, Duration::MAX), Duration::MAX);
    }

    fn sel() -> Selection {
        Selection::default()
    }

    #[test]
    fn names_are_resolved_wherever_a_socket_can_print() {
        assert!(socket_names_printable(&sel()), "bare lsof");
        let mut inet = sel();
        inet.inet.enabled = true;
        assert!(socket_names_printable(&inet), "-i");
        let pid = Selection {
            pids: vec![4],
            ..sel()
        };
        assert!(socket_names_printable(&pid), "-p");
        // Under the OR a process selecter lists the process's sockets, NFS
        // or not.
        let nfs_or_pid = Selection {
            nfs_only: true,
            ..pid.clone()
        };
        assert!(socket_names_printable(&nfs_or_pid), "-N -p");
        let nfs_or_inet = Selection {
            nfs_only: true,
            ..inet.clone()
        };
        assert!(socket_names_printable(&nfs_or_inet), "-N -i");
        let and_pid = Selection {
            and_mode: true,
            ..pid
        };
        assert!(socket_names_printable(&and_pid), "-a -p");
        let verbose = Selection {
            verbose: true,
            ..sel()
        };
        assert!(socket_names_printable(&verbose), "-V");
    }

    #[test]
    fn names_are_skipped_only_where_no_socket_can_print() {
        let terse = Selection {
            terse: true,
            ..sel()
        };
        assert!(!socket_names_printable(&terse), "-t");
        let mut terse_inet = terse.clone();
        terse_inet.inet.enabled = true;
        assert!(!socket_names_printable(&terse_inet), "-t -i");
        let nfs = Selection {
            nfs_only: true,
            ..sel()
        };
        assert!(!socket_names_printable(&nfs), "-N");
        let nfs_v = Selection {
            verbose: true,
            ..nfs.clone()
        };
        assert!(!socket_names_printable(&nfs_v), "-N -V");
        let and_nfs_pid = Selection {
            and_mode: true,
            pids: vec![4],
            ..nfs
        };
        assert!(!socket_names_printable(&and_nfs_pid), "-a -N -p");
        let path = Selection {
            paths: vec!["C:\\x".into()],
            ..sel()
        };
        assert!(!socket_names_printable(&path), "a path argument");
    }

    /// `socket_host_names` over `files`, with a lookup that counts its calls
    /// and names every address, and the trace lines it printed.
    fn plan(sel: &Selection, files: &[OpenFile]) -> (Option<HostNames>, usize, Vec<String>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&calls);
        let lines = std::cell::RefCell::new(Vec::new());
        let got = socket_host_names(
            sel,
            files,
            move |ip| {
                c.fetch_add(1, Ordering::SeqCst);
                Some(format!("h{ip}"))
            },
            |l| lines.borrow_mut().push(l.to_string()),
        );
        (got, calls.load(Ordering::SeqCst), lines.into_inner())
    }

    fn rows() -> Vec<OpenFile> {
        vec![
            sock("127.0.0.1:5000", Some("127.0.0.1:6000")),
            sock("192.0.2.1:7", Some("[2001:db8::1]:443")),
        ]
    }

    #[test]
    fn the_call_site_resolves_each_host_once_by_default() {
        let (got, calls, lines) = plan(&sel(), &rows());
        let got = got.expect("rows are formatted");
        assert_eq!(calls, 3);
        assert_eq!(got.len(), 3);
        assert_eq!(
            cached_name(&got, "2001:db8::1".parse().unwrap()).as_deref(),
            Some("h2001:db8::1")
        );
        assert_eq!(
            lines,
            [
                "gather: resolve hosts start (3 distinct)",
                "gather: resolve hosts done (3 answered, 3 named)"
            ]
        );
        let pid = Selection {
            pids: vec![4],
            ..sel()
        };
        assert_eq!(hosts_to_resolve(&pid, &rows()).len(), 3, "-p");
    }

    #[test]
    fn dash_n_formats_the_rows_but_looks_nothing_up() {
        let n = Selection {
            no_host_resolve: true,
            ..sel()
        };
        let mut n_inet = n.clone();
        n_inet.inet.enabled = true;
        let n_pid = Selection {
            pids: vec![4],
            ..n.clone()
        };
        for (s, what) in [(&n, "-n"), (&n_inet, "-n -i"), (&n_pid, "-n -p")] {
            assert!(hosts_to_resolve(s, &rows()).is_empty(), "{what}");
            let (got, calls, lines) = plan(s, &rows());
            assert_eq!(got, Some(HostNames::new()), "{what}: formatted, numeric");
            assert_eq!(calls, 0, "{what}: no lookup");
            assert!(lines.is_empty(), "{what}: no phase");
        }
    }

    #[test]
    fn where_no_socket_can_print_rows_are_left_alone() {
        let terse = Selection {
            terse: true,
            ..sel()
        };
        let nfs = Selection {
            nfs_only: true,
            ..sel()
        };
        let path = Selection {
            paths: vec!["C:\\x".into()],
            ..sel()
        };
        let and_nfs_pid = Selection {
            and_mode: true,
            pids: vec![4],
            ..nfs.clone()
        };
        for (s, what) in [
            (&terse, "-t"),
            (&nfs, "-N"),
            (&path, "a path"),
            (&and_nfs_pid, "-a -N -p"),
        ] {
            assert!(hosts_to_resolve(s, &rows()).is_empty(), "{what}");
            let (got, calls, _) = plan(s, &rows());
            assert_eq!(got, None, "{what}: not reformatted");
            assert_eq!(calls, 0, "{what}: no lookup");
        }
    }

    #[test]
    fn the_call_site_uses_the_whole_pool() {
        let (_, peak, lookup) = gathering_lookup(WORKERS, Duration::from_millis(500));
        let files: Vec<OpenFile> = (0..WORKERS)
            .map(|i| sock(&format!("192.0.2.{}:1", i + 1), None))
            .collect();
        let got = socket_host_names(&sel(), &files, lookup, |_| {});
        assert_eq!(got.map(|h| h.len()), Some(WORKERS));
        assert_eq!(peak.load(Ordering::SeqCst), WORKERS);
    }
}
