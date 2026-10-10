//! lsof-rs CLI entry point — produces the `lsof` binary.
//!
//! Parses lsof-compatible options, asks the platform [`Backend`] to gather
//! processes and their open files, applies the selection, and renders the
//! chosen format. On Windows and Linux it uses the native backend; on any
//! other host it falls back to the mock backend so the pipeline runs anywhere.
//!
//! `#![forbid(unsafe_code)]`: the CLI only ever calls the backends, never the
//! platform. A bin and a lib in one package are two crates and the attribute
//! does not cross between them, so this is not a duplicate of `lib.rs`'s —
//! drop it and the binary is unconstrained while the library still looks safe.
#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};

use lsof_cli::args::{parse_with, Action};
use lsof_core::readlink::ReadlinkError;
use lsof_core::render::{fields, json, table, Escaper, Format, TableOpts};
use lsof_core::selection::filesystems_named;
use lsof_core::{
    errno_text, Backend, DirArg, FileId, FilesystemArgs, Located, PathItem, SafeFs, Selection,
    TaskMode, UidSel, UserLookup,
};

#[cfg(target_os = "linux")]
use lsof_backend_linux::LinuxBackend;
#[cfg(windows)]
use lsof_backend_windows::WindowsBackend;
#[cfg(not(any(windows, target_os = "linux")))]
use lsof_core::mock::MockBackend;

/// The resolved runtime environment: a backend plus context for messaging.
struct Env {
    backend: Box<dyn Backend>,
    elevated: bool,
    note: Option<String>,
}

#[cfg(windows)]
fn make_env() -> Env {
    let backend = WindowsBackend::new();
    let elevated = backend.is_elevated();
    Env {
        backend: Box::new(backend),
        elevated,
        note: None,
    }
}

#[cfg(target_os = "linux")]
fn make_env() -> Env {
    let backend = LinuxBackend::new();
    // Running as root is Linux's analog of an elevated Windows token: it is what
    // makes other users' /proc/<pid>/fd readable.
    let elevated = backend.is_root();
    Env {
        backend: Box::new(backend),
        elevated,
        // Phase L1 classifies sockets from /proc/net, so the L0 note that `-i`
        // matched nothing no longer applies and would now be a false warning.
        note: None,
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
fn make_env() -> Env {
    Env {
        backend: Box::new(MockBackend),
        elevated: false,
        note: Some("no native backend for this platform: showing sample (mock) data".to_string()),
    }
}

/// Least-privilege hint predicate: the hint prints only in table mode (machine
/// formats stay clean) and only when the run will attempt system-wide handle
/// enumeration — not for `-i` network queries, `-U`, or path lookups, which
/// need no elevation. `-w` suppresses it per the lsof convention.
///
/// Kept as a pure, portable function (only the printing call site is
/// Windows-only) so both elevation branches are unit-tested on every CI push —
/// hosted runners are always elevated, so a live unelevated invocation can't
/// happen in CI; see `docs/road-to-1.0.md` (the elevation blind spot).
#[cfg_attr(not(windows), allow(dead_code))]
fn wants_privilege_hint(elevated: bool, selection: &Selection, format: &Format) -> bool {
    !elevated
        && !selection.suppress_warnings
        && matches!(format, Format::Table)
        && !selection.inet.enabled
        && !selection.unix_only
        && !selection.has_path_filter()
}

fn usage() -> String {
    // Real newlines, not `\n\` continuations: a continuation also eats the
    // next line's leading spaces, which printed every line flush left.
    format!(
        "lsof-rs {ver} - a memory-safe lsof (list open files)

USAGE:
    lsof [options] [--] [path ...]

SELECTION:
    -p <pids>     select by PID (comma separated; ^pid excludes)
    -u <users>    select by owning user, login name or UID (^ excludes)
    -c <cmd>      select by command name: a prefix (case-insensitive substring
                  on Windows); ^cmd excludes. -c /regex/ is not supported
    -g [pgids]    process groups: the PGID column, and with pgids, selection
                  (^ excludes). On Windows: select children of these PPIDs
    -d <fds>      filter by FD: cwd,rtd,txt,mem,DEL,NOFD,unk,fd (every number),
                  numbers, a-b ranges; all ^excluded or none. Repeats add up
    -i [spec]     Internet sockets; spec = [46][tcp|udp|icmp|raw][@addr][:ports]
                  ports may be a list and ranges (:22,80,1000-2000); each -i
                  is its own item, ORed. Host and service names are refused.
                  On Windows icmp/raw come from the ETW capture (Administrator)
    -s [p:s]      TCP and UDP sockets by TCP state: TCP:LISTEN,ESTABLISHED
                  lists only those, TCP:^TIME_WAIT excludes one; each listed
                  state is a search item. A bare -s shows sizes, in a SIZE
                  column
    -U            list UNIX-domain (AF_UNIX) sockets (on Windows through ETW,
                  which needs Administrator)
    -N            list NFS files
    -K [i]        list threads: on Linux in TID and TASKCMD columns, as the C
                  does; on Windows as `task` rows, the TID in NODE. -K i: none
    -T [fqsw]     TCP info on socket rows: s=state, q=queue sizes, w=window
                  (Windows); f is accepted and shows nothing. The letters
                  select: -T alone shows none, +T the state alone (the
                  default). On Windows q and w need Administrator
    -a            AND the selectors together (default is OR); needs one
    <path>        find who has this FILE open; +d <dir> = the dir and its
                  entries, +D <dir> = the whole tree beneath it.
                  On Linux a path matches by identity (a hard link to it
                  counts), and a MOUNT POINT's absolute path (or the block
                  device it was mounted from, or a link to either) selects
                  every open file on that file system; `/mnt/.` or a
                  relative `mnt` names the directory alone. On Windows a
                  path matches by name
    -x [fl]       with +d/+D: cross into other file systems (f), follow
                  symbolic links (l); -x alone does both
    -f / +f       never / always read a path argument as a file system;
                  +f also accepts a non-block mount source, and complains
                  if an argument names no mount

OUTPUT:
    -n            do not resolve host names (Windows; Linux never does)
    -P            do not resolve port names (Windows; Linux never does)
    -R            add a PPID (parent PID) column
    -o [n]        an OFFSET column (0t<decimal>, 0x<hex> past n digits,
                  default 8); -o <n> alone sets the digit limit and keeps
                  SIZE/OFF
    -H            human-readable sizes in the SIZE column (2.0M); -F and the
                  JSON forms keep bytes
    -t            terse: PIDs only
    -E            (Windows) pipe endpoint info: append peer server/client
                  PID+command to pipe NAMEs (GetNamedPipe*ProcessId)
    +E            same, and also list the peer processes' own pipe rows.
                  Linux accepts -E and +E and ignores them
    -l            numeric USER: the UID on Linux, the SID string on Windows
    +L [count]    an NLINK (link count) column; with a count, also select the
                  files with fewer links (`+L 1` = unlinked but still open).
                  -L: no NLINK column (the default)
    +f g / +f G   (Linux) a FILE-FLAG column: each file's open flags by name
                  (W,AP,LG), or in hex; -f g hides it again
    -V            verbose: report inaccessible / unmatched search items
    -F [fields]   field (machine-readable) output; 0 = NUL terminators;
                  -F ? lists the field letters
    -J            aggregated JSON object
    -j            JSON Lines (one object per file)
    -r [delay]    repeat every <delay>s (default 15) until interrupted
    +c <n>        cap COMMAND column width at <n> characters

MISCELLANEOUS:
    -Q            quiet: mute search failures, exit status included
    -w / +w       leave out / report files that cannot be read, and suppress /
                  enable non-fatal stderr warnings (default: report, on)
    -X            toggle: leave TCP and UDP sockets unidentified, without
                  reading their tables; -i is refused while it is on
    -e <fs>       do not stat files on this mounted file system; they show
                  as UNKN... rows
    -Z            SELinux security contexts: not supported (exits 1)
    -b            make none of the calls that can block on a file system
                  (stat, lstat, readlink) for a path given or a mount point;
                  say so unless -w. A path argument then fails, and +d/+D
                  after it ends the run
    -O / +O       make / stop making those calls in lsof itself, with no
                  time limit
                  (*RISKY*: a file system that does not answer hangs lsof)
    -S [t]        give each of those calls t seconds (default 15, at least
                  2), in a helper process (Linux; elsewhere they are made in
                  lsof). One that times out fails: `Connection timed out`
    --            end of options; remaining args are paths

    --etw         (Windows, opt-in) short ETW capture against the AFD
                  provider to extend `-i` coverage to socket families
                  IP Helper doesn't enumerate (raw/ICMP/AF_UNIX).
                  Needs Administrator. Linux accepts it and ignores it
    --unicode     (Windows) switch the console to UTF-8 (CP 65001) at
                  startup. The output is the same either way: a printable
                  non-ASCII name prints as it is
    --ascii       accepted; changes nothing

    -h, -?, --help    show this help
    -v, --version     show version

Without elevation, lsof-rs shows the processes you can access; run as
Administrator (Windows) or root (Linux) for a system-wide view. On Windows,
privileges are enabled only for the operations that need them.
",
        ver = env!("CARGO_PKG_VERSION")
    )
}

/// Resolve a user-typed path selector (`+D` directory, bare path) to its
/// canonical long form so the literal prefix/equality match in the selection
/// engine sees the same spelling the backend reports — on a backend that
/// matches names (Windows). This is what bridges 8.3 short names
/// (`C:\Users\RUNNER~1\...` — the default %TEMP% on hosted Windows CI),
/// relative paths, and symlinked directories. `std::fs::canonicalize` returns
/// Windows paths in verbatim form (`\\?\C:\...`, `\\?\UNC\srv\...`); strip
/// that the same way the backend's `normalize_final` does, so both sides of
/// the comparison use one spelling. A path that can't be resolved (it doesn't
/// exist) is left as typed — the unmatched-item reporting owns that.
fn canonicalize_selector(p: &mut String) {
    let Ok(resolved) = std::fs::canonicalize(&*p) else {
        return;
    };
    *p = strip_verbatim(&resolved.to_string_lossy());
}

/// `path` without the slashes that end it, keeping one: the C's rule for a
/// path argument before it `stat`s it (`arg.c`, "Remove terminating `/'
/// characters from paths longer than one").
#[cfg_attr(not(unix), allow(dead_code))]
fn without_trailing_slashes(path: &[u8]) -> &[u8] {
    let mut end = path.len();
    while end > 1 && path[end - 1] == b'/' {
        end -= 1;
    }
    &path[..end]
}

/// A path argument as the C spells it before it looks at it (`arg.c`,
/// `ck_file_arg`): its `Readlink()`, less the slashes that end it. So `FILE/`
/// is FILE, `mnt` from `/` stays `mnt`, which no mount point is, and a
/// `/proc/PID/fd/N` link is the text it holds (DIVERGENCES 65). lsof-rs had
/// used `canonicalize()`, which made `lsof mnt` a file system and followed
/// such a link to the file behind it. Where names are matched instead
/// (Windows), the argument as [`spell_names_as_reported`] left it.
fn spell_path(typed: &str, identified: bool, fs: &SafeFs) -> Result<OsString, ReadlinkError> {
    #[cfg(unix)]
    if identified {
        use std::os::unix::ffi::OsStringExt;
        let mut path = lsof_core::readlink::resolve(typed.as_ref(), fs)?.into_vec();
        path.truncate(without_trailing_slashes(&path).len());
        return Ok(OsString::from_vec(path));
    }
    let _ = (identified, fs);
    Ok(typed.into())
}

/// On a backend that matches names (Windows), the path arguments and the `+D`
/// trees in the long form the backend reports, which is what selection
/// compares a row's name with; see [`canonicalize_selector`]. Without it an
/// 8.3 short name (`RUNNER~1`, the hosted runner's `%TEMP%`) selects nothing.
/// A backend that identifies files needs none of it: the C's spelling is
/// [`spell_path`]'s.
fn spell_names_as_reported(sel: &mut Selection) {
    if sel.paths_identified {
        return;
    }
    for p in sel.paths.iter_mut().chain(sel.dir_trees.iter_mut()) {
        canonicalize_selector(p);
    }
}

/// How many entries a `+d`/`+D` walk takes, and how many bytes of their
/// names. The C walks on: a tree of 200,000 entries and more is taken whole,
/// and two links to `.` under `-x l` make 2^40 paths it never finishes. lsof-rs
/// stops, and says so (DIVERGENCES 81). Names count as well as entries: under
/// `-x l` a link to `.` makes every name longer than the last, and 200,000
/// of them reached a gigabyte.
const WALK_ENTRIES: usize = 200_000;
const WALK_NAME_BYTES: usize = 16 << 20;

/// What a walk has left of [`WALK_ENTRIES`] and [`WALK_NAME_BYTES`].
struct WalkBudget {
    entries: usize,
    bytes: usize,
}

impl WalkBudget {
    fn new() -> Self {
        WalkBudget {
            entries: WALK_ENTRIES,
            bytes: WALK_NAME_BYTES,
        }
    }

    /// Take one entry with a name of `len` bytes, or `false` if that would
    /// exceed either limit.
    fn take(&mut self, len: usize) -> bool {
        if self.entries == 0 || self.bytes < len {
            return false;
        }
        self.entries -= 1;
        self.bytes -= len;
        true
    }
}

/// One `+d`/`+D` directory and what is in it, entered as the C's
/// `enter_dir()` enters them (`arg.c`): the directory under the name
/// `Readlink()` gave it when the option was checked, then each entry as that
/// name, a `/` unless it ends in one, and the entry's own name, byte for byte.
/// So `+D rel` reports `rel/y`, not `$PWD/rel/y`, `+d rel-link` reports
/// `rel/y` (DIVERGENCES 63), and an entry whose name is not UTF-8 is found by
/// it, where a lossy name had found nothing (DIVERGENCES 65).
///
/// Each entry is described by ONE `lstat`, as the C's (`arg.c:1014`): it
/// decides the `-x f` test, whether the entry is a link, whether it is
/// descended into, and what it is (DIVERGENCES 111). Only a link under `-x
/// l` gets one more call, the `stat` that follows it, and that result then
/// stands for the entry. The directory itself is what the option's one
/// `stat` said ([`DirArg::stat`]); the walk only lists it. Every call it
/// makes — each listing, each `lstat`, each follow — goes through the
/// bounded layer under the `-b`, `-O` and `-S` given before the option
/// (DIVERGENCES 94): an entry on a file system that does not answer is a
/// `can't lstat(P): Connection timed out` and the walk goes on, as the C's
/// (its first timeout, DIVERGENCES 118). Its warnings go where the layer's
/// do, stderr, so that a test can hold them.
fn expand_dir(sel: &mut Selection, dir: &DirArg, backend: &dyn Backend, esc: Escaper, fs: &SafeFs) {
    fn enter(sel: &mut Selection, path: &Path, id: Option<FileId>) {
        if let Some(id) = id {
            sel.path_ids.insert(id);
            sel.path_names.insert(path.as_os_str().to_os_string());
        }
        sel.path_items.push(PathItem {
            id,
            fs_device: None,
            name: path.as_os_str().to_os_string(),
        });
    }
    let fs = fs.with(dir.blocking, dir.warn);
    let identified = sel.paths_identified;
    // Where names are matched, a `+D` keeps the long-form name it had.
    let base = if identified || !dir.recursive {
        PathBuf::from(&dir.dir)
    } else {
        let mut p = dir.dir.to_string_lossy().into_owned();
        canonicalize_selector(&mut p);
        PathBuf::from(p)
    };
    // The directory is the option's one `stat` (`arg.c:876`): its device and
    // inode are its search item's (`arg.c:915`), and its `st_dev` is `ddev`,
    // the file system every entry is held to unless `-x f` (`arg.c:905`),
    // through a followed link too. Nothing at walk time asks again, so a
    // directory gone since is still the item the C enters, before it tries
    // to open it (`arg.c:915,930`), and is reported unlocated. Where names
    // are matched there is no identity, and `ddev` is `None`, which switches
    // the `-x f` rule off rather than guessing.
    let (top, ddev) = if identified {
        (backend.identify_stat(&dir.stat), Some(dir.stat.dev))
    } else {
        (None, None)
    };
    enter(sel, &base, top);
    let shown = |p: &Path| esc.bytes(p.as_os_str().as_encoded_bytes()).into_owned();
    let mut budget = WalkBudget::new();
    let mut stack = vec![base.clone()];
    while let Some(dn) = stack.pop() {
        let names = match fs.read_dir(&dn) {
            Ok(names) => names,
            Err(e) => {
                if dir.warn && e.kind() != std::io::ErrorKind::NotFound {
                    fs.tell(&format!(
                        "lsof: WARNING: can't opendir({}): {}",
                        shown(&dn),
                        errno_text(&e)
                    ));
                }
                continue;
            }
        };
        for name in names {
            // `dn`, a `/` unless it ends in one, and the entry's name: the C's
            // spelling, and `DirEntry::path()`'s.
            let path = dn.join(&name);
            if !budget.take(path.as_os_str().len()) {
                if dir.warn {
                    fs.tell(&format!(
                        "lsof: WARNING: stopped walking {} after {} entries",
                        shown(&base),
                        WALK_ENTRIES - budget.entries
                    ));
                }
                return;
            }
            // The entry is `lstat`ed, once; then the two cross-over rules, in
            // the C's order (`arg.c:1029-1061`):
            //
            //   unless -x / -x f, skip an entry whose st_dev is not the
            //         directory's — do not leave this file system;
            //   unless -x / -x l, skip a symbolic link outright. With it, the
            //         link is followed: the TARGET is what is searched for,
            //         and for `+D` what is descended into, as the C stacks a
            //         directory by the `stat` that followed the link
            //         (DIVERGENCES 78).
            //
            // `-x` is the one in force when the option was checked
            // (DIVERGENCES 75). The type is the `lstat`'s, never the listing's
            // `d_type`, as the C's is (`arg.c:1038,1067`).
            let st = match fs.lstat(&path) {
                Ok(st) => Some(st),
                // `lstat` failed: gone, not ours to see, or timed out. The
                // C's words, with that call's own error.
                Err(err) if identified => {
                    if dir.warn && err.kind() != std::io::ErrorKind::NotFound {
                        fs.tell(&format!(
                            "lsof: WARNING: can't lstat({}): {}",
                            shown(&path),
                            errno_text(&err)
                        ));
                    }
                    continue;
                }
                // Where names are matched, the name is still an item.
                Err(_) => None,
            };
            // The link's own device, before it is followed: a link here to a
            // file elsewhere is entered under `-x l` alone (`arg.c:1035`).
            if !dir.cross_filesystems {
                if let (Some(d), Some(st)) = (ddev, st) {
                    if d != st.dev {
                        continue;
                    }
                }
            }
            // Under `-x l` a link is followed by one `stat`, whose result
            // replaces the `lstat` (`arg.c:1047`): it is what the entry is,
            // and whether it is descended into. The name stays the link's.
            let st = match st {
                Some(st) if st.is_symlink() => {
                    if !dir.cross_symlinks {
                        continue;
                    }
                    match fs.stat(&path) {
                        Ok(st) => Some(st),
                        Err(err) => {
                            // The C's words, its spelling included.
                            if dir.warn && err.kind() != std::io::ErrorKind::NotFound {
                                fs.tell(&format!(
                                    "lsof: WARNING: can't stat({}) symbolc link: {}",
                                    shown(&path),
                                    errno_text(&err)
                                ));
                            }
                            continue;
                        }
                    }
                }
                st => st,
            };
            // The identity of the call just made, never of another: a second
            // `stat` would describe whatever the name led to by then. The C
            // hands `ck_file_arg()` this one (`arg.c:1077`).
            let id = if identified {
                st.and_then(|st| backend.identify_stat(&st))
            } else {
                None
            };
            if dir.recursive && st.is_some_and(|st| st.is_dir()) {
                stack.push(path.clone());
            }
            enter(sel, &path, id);
        }
    }
}

/// `\\?\C:\x` -> `C:\x`; `\\?\UNC\srv\share` -> `\\srv\share`; anything else
/// unchanged — the same spelling the backend's `normalize_final` produces.
fn strip_verbatim(s: &str) -> String {
    if let Some(rest) = s.strip_prefix("\\\\?\\UNC\\") {
        format!("\\\\{rest}")
    } else if let Some(rest) = s.strip_prefix("\\\\?\\") {
        rest.to_string()
    } else {
        s.to_string()
    }
}

/// Every search item this run did not locate, as the lines `-V` prints for
/// them — in the C's order and its words (`main.c`, the block after the
/// listing): commands, files, Internet addresses, `-i`, NFS, PIDs, process
/// groups, users. Every line is a `printf` there, so they go to stdout, and
/// they come **after** the listing; lsof-rs had printed them before it, which
/// no case caught because no case printed both.
///
/// The count is what matters when nothing is printed: lsof exits 1 on any
/// unlocated item, `-V` or not, so `lsof -t <file> && …` and `if lsof …;
/// then` work. `-Q` mutes both, which the caller decides.
///
/// What "located" means differs by kind, and each is the C's:
///
/// * `-p`/`-g`/`-u`/`-c` — a gathered process matched it, before any file is
///   selected ([`Selection::locate`]): `lsof -a -p P -d 999` still exits 0.
/// * a path — a file the C examined is it, by identity, or (for a file
///   system argument) is on it, or is a socket bound at it, printed or not
///   ([`Selection::locate`]).
/// * `-i` (the bare form, and each specification) and `-N` — a file KEPT for
///   a process that passed selection, printed or not, as the C sets `Fnet`
///   and `Fnfs` when it links the file ([`Selection::locate`]).
fn unlocated(sel: &Selection, located: &Located, esc: Escaper) -> Vec<String> {
    let mut miss = Vec::new();
    // `-c`. The C keeps these in a list it PREPENDS to (`Cmdl = lpt`), so it
    // reports them last-given first.
    for (c, hit) in sel.commands.iter().zip(&located.commands).rev() {
        if !hit {
            miss.push(format!("lsof: command not located: {}", esc.text(c)));
        }
    }
    // Every path argument must be located or the run exits 1, and for
    // `+d`/`+D` each expanded ENTRY is its own item — verified against the C:
    // a directory whose every entry is open exits 0, and adding one unopened
    // file makes it 1. Identity is what "located" means, so a file queried
    // through a hard link counts as found under its other name.
    //
    // Last entered, first reported: `ck_file_arg()` PREPENDS each item to
    // `Sfile`, which the report walks. So bare paths come last given first,
    // then each `+d`/`+D` expansion backwards — its entries before the
    // directory itself — the latest option first (DIVERGENCES 52). The items
    // are entered in the C's order (`+d`/`+D` first, each walked as
    // `enter_dir` walks), so reversing them is the C's report.
    for (item, &hit) in sel.path_items.iter().zip(&located.paths).rev() {
        let PathItem {
            fs_device,
            name: display,
            ..
        } = item;
        if !hit {
            // `sfp->type ? "" : " system"` — a file-system argument has its
            // own wording, measured: `no file system use located: /mnt/x`.
            let kind = if fs_device.is_some() {
                "file system"
            } else {
                "file"
            };
            miss.push(format!(
                "lsof: no {kind} use located: {}",
                esc.bytes(display.as_encoded_bytes())
            ));
        }
    }
    // Each `-i` address specification. The C keeps them in a list it
    // prepends to, so it reports the last given first, and a text given twice
    // is one item — found if either copy was (`main.c`: "If any Internet
    // address derived from the same argument was found, consider all
    // derivations found").
    let mut reported: Vec<&str> = Vec::new();
    for spec in sel.inet.specs.iter().rev() {
        let text = spec.text.as_str();
        if reported.contains(&text) {
            continue;
        }
        reported.push(text);
        let found = sel
            .inet
            .specs
            .iter()
            .zip(&located.inet)
            .any(|(s, hit)| s.text == text && *hit);
        if !found {
            miss.push(format!(
                "lsof: Internet address not located: {}",
                esc.text(text)
            ));
        }
    }
    // A bare `-i`/`-i4`/`-i6` is a search item of its own: `main.c` keeps
    // `Fnet` at 1 until some file it KEEPS for a selected process carries
    // `SELNET`, and `if (Fnet && Fnet < 2)` at the end is a search failure.
    // So `lsof -a -i -p 1` exits 1 — pid 1 exists and was located, but has no
    // Internet file at all. `-U` has no such rule, which is why this tests
    // the inet selector alone. See `Selection::locate` for "keeps".
    if sel.inet.bare() && !located.inet_all {
        miss.push("lsof: no Internet files located".to_string());
    }
    // Each `-s TCP:` state included: `main.c` walks its state TABLE and names
    // every entry still at 1, so the order is the table's (the kernel's
    // numbering on Linux: `CLOSED` before `SYN_SENT` before `LISTEN`), not
    // the order given, and the name is the table's spelling, not the user's.
    if let Some(filter) = &sel.state_filter {
        for state in lsof_core::model::tcp_state_table() {
            let missed = filter
                .include
                .iter()
                .zip(&located.states)
                .any(|(want, hit)| want == state && !hit);
            if missed {
                miss.push(format!("lsof: TCP state not located: {}", state.as_str()));
            }
        }
    }
    // `-N` is the same shape (`main.c`'s `Fnfs < 2`), and the message is the
    // same sentence with the noun changed. Measured on a host with no NFS
    // mount: `lsof -N` and `lsof -a -N -p 1` both exit 1, and so does
    // `lsof -N -p 1`, which DOES list the pid's files — the `-N` item was
    // still never located.
    if sel.nfs_only && !located.nfs {
        miss.push("lsof: no NFS files located".to_string());
    }
    for (pid, hit) in sel.pids.iter().zip(&located.pids) {
        if !hit {
            miss.push(format!("lsof: process ID not located: {pid}"));
        }
    }
    // `-K` is a search item of its own, after the PIDs as the C reports it
    // (`main.c`, `Ftask < 2`): located by a row of a task, printed or not.
    // So `lsof -K -a -p P` exits 1 on a single-threaded P, which is not a task
    // and has none, and `-K i` asks for nothing to be located (DIVERGENCES 33).
    if sel.tasks == TaskMode::Always && !located.tasks {
        miss.push("lsof: no tasks located".to_string());
    }
    for (pgid, hit) in sel.pgids.iter().zip(&located.pgids) {
        if !hit {
            miss.push(format!("lsof: process group ID not located: {pgid}"));
        }
    }
    // A user given by name is reported by name AND ID, one given by number
    // by number: `login name (UID 1000) not located: alice`, `user ID not
    // located: 12345` — both measured.
    for (u, hit) in sel.uids.iter().zip(&located.uids) {
        if !hit {
            miss.push(match &u.login {
                Some(login) => format!(
                    "lsof: login name (UID {}) not located: {}",
                    u.uid,
                    esc.text(login)
                ),
                None => format!("lsof: user ID not located: {}", u.uid),
            });
        }
    }
    // Where users are matched by name (Windows) there is no ID to report.
    for (u, hit) in sel.users.iter().zip(&located.users) {
        if !hit {
            miss.push(format!("lsof: login name not located: {}", esc.text(u)));
        }
    }
    miss
}

/// `-u`, resolved the way the platform names users ([`Backend::lookup_user`]):
/// on Linux each value becomes a numeric ID, and a name the password file
/// does not have is an error, as it is to the C (`can't get UID for X`, then
/// the usage message, exit 1). The C enters each UID once and refuses one
/// that is both selected and excluded — `UID 0 has been included and
/// excluded.` — so `-u root,^0` is an error, not an empty listing.
fn resolve_users(sel: &mut Selection, backend: &dyn Backend) -> Result<(), Vec<String>> {
    let esc = Escaper::for_host();
    let mut errors = Vec::new();
    let mut by_name = Vec::new();
    for v in std::mem::take(&mut sel.users) {
        match backend.lookup_user(&v) {
            UserLookup::Uid(uid) => {
                if !sel.uids.iter().any(|s| s.uid == uid) {
                    let login = (!v.bytes().all(|b| b.is_ascii_digit())).then(|| v.clone());
                    sel.uids.push(UidSel { uid, login });
                }
            }
            UserLookup::Unknown => errors.push(format!("can't get UID for {}", esc.text(&v))),
            UserLookup::ByName => by_name.push(v),
        }
    }
    sel.users = by_name;
    let mut by_name = Vec::new();
    for v in std::mem::take(&mut sel.user_excludes) {
        match backend.lookup_user(&v) {
            UserLookup::Uid(uid) => {
                if !sel.uid_excludes.contains(&uid) {
                    sel.uid_excludes.push(uid);
                }
            }
            UserLookup::Unknown => errors.push(format!("can't get UID for {}", esc.text(&v))),
            UserLookup::ByName => by_name.push(v),
        }
    }
    sel.user_excludes = by_name;
    if let Some(s) = sel.uids.iter().find(|s| sel.uid_excludes.contains(&s.uid)) {
        errors.push(format!("UID {} has been included and excluded.", s.uid));
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// What a failed write to stdout means (LESSONS #063).
///
/// **A closed pipe is not an error for lsof.** `lsof | head -1` is ordinary
/// use, and the C dies of `SIGPIPE` silently; the shell reports 141 for it.
/// This port had been ending the same pipeline with a panic —
/// `failed printing to stdout: Broken pipe (os error 32)`, exit 101 — because
/// `print!` panics on any write error, and the whole table went out in one
/// `print!`. Re-raising the signal needs `unsafe` and this crate forbids it,
/// so the port exits with the status the shell shows for the C, 141, which is
/// the same `$?` and the same verdict under `set -o pipefail`, and says
/// nothing. Any other write failure — a full disk under `lsof > file` — is a
/// real error and is reported as one, not as a panic.
fn exit_on_write_error(r: std::io::Result<()>) {
    if let Err(e) = r {
        if e.kind() == std::io::ErrorKind::BrokenPipe {
            std::process::exit(141);
        }
        eprintln!("lsof: write error: {e}");
        std::process::exit(1);
    }
}

fn main() {
    // The bounded layer's helper is this binary, re-executed with an argument
    // no user types (`lsof_backend_linux::safefs`). It is served before
    // anything else is looked at — options, the locale, the environment,
    // which the helper does not have — and nothing else.
    #[cfg(target_os = "linux")]
    if std::env::args_os().nth(1).as_deref()
        == Some(std::ffi::OsStr::new(lsof_backend_linux::safefs::HELPER_ARG))
    {
        std::process::exit(lsof_backend_linux::safefs::serve());
    }

    // `args_os`, not `args`: `std::env::args()` PANICS on an argument that is
    // not UTF-8, and a Linux file name may hold any byte but `/` and NUL —
    // `lsof /tmp/$'\xff'` exited 101 with a panic message. lsof-rs keeps
    // arguments as `String`s, so such an argument cannot be looked up yet;
    // it is refused, in one line, rather than crashing on (DIVERGENCES).
    let argv: Vec<String> = match std::env::args_os()
        .skip(1)
        .map(std::ffi::OsString::into_string)
        .collect::<Result<_, _>>()
    {
        Ok(argv) => argv,
        Err(bad) => {
            eprintln!(
                "lsof: an argument is not valid UTF-8, which lsof-rs cannot take: {}",
                Escaper::for_host().text(&bad.to_string_lossy())
            );
            std::process::exit(1);
        }
    };

    // Default output is ASCII (safe on PowerShell 5.1 / cmd.exe whose console
    // is Windows-1252). Users on modern terminals can pass `--unicode` to
    // switch the console code page to UTF-8 (and opt in to Unicode glyphs in
    // any future output).
    #[cfg(windows)]
    if argv.iter().any(|a| a == "--unicode") {
        lsof_backend_windows::enable_utf8_console();
    }

    // Where a path the user named is `stat`ed and its links read: a helper
    // process that gives each call `-S` seconds (DIVERGENCES 94, 110). One
    // at a time, started by the first call that needs it — a `+d` while the
    // options are parsed, the mount table, or a path argument — replaced
    // after a call that times out, and ended with the run.
    #[cfg(target_os = "linux")]
    let calls = lsof_backend_linux::safefs::Helper::new();
    #[cfg(not(target_os = "linux"))]
    let calls = lsof_core::InProcess;
    let fs = SafeFs::new(&calls, &lsof_core::safefs::to_stderr);

    let action = match parse_with(argv, &fs) {
        Ok(a) => a,
        Err(e) => {
            // An argument is escaped where the message quotes it, as the C
            // escapes it with `safestrprt()` where it does. An error the C
            // makes in silence under `-w` or `-t` comes back empty: the run
            // still ends, with the usage hint alone.
            if !e.is_empty() {
                eprintln!("lsof: {e}");
            }
            eprintln!("Try 'lsof -h' for usage.");
            std::process::exit(1);
        }
    };

    let (selection, format, repeat, columns) = match action {
        Action::Help => {
            print!("{}", usage());
            return;
        }
        // To stderr, as the C writes it, and exit 0.
        Action::FieldHelp => {
            eprint!("{}", fields::field_help());
            return;
        }
        Action::Version => {
            println!("lsof-rs {} (memory-safe lsof)", env!("CARGO_PKG_VERSION"));
            return;
        }
        Action::Run {
            selection,
            format,
            repeat,
            columns,
        } => (selection, format, repeat, columns),
    };
    let env = make_env();
    let selection = {
        let mut sel = selection;
        if let Err(errors) = resolve_users(&mut sel, env.backend.as_ref()) {
            for e in errors {
                eprintln!("lsof: {e}");
            }
            eprintln!("Try 'lsof -h' for usage.");
            std::process::exit(1);
        }
        sel
    };
    // The path arguments, as the C's `ck_file_arg()` enters them once its
    // options are parsed (`arg.c`), and then the `+d`/`+D` directories the
    // parser checked, expanded now that a backend exists to identify what is
    // in them. lsof matches a path by what the file IS: `lsof /a/hardlink`
    // finds it under its other name, and naming a directory matches that
    // directory, not everything beneath it.
    //
    // An argument the C drops — `Readlink()` gave up on it, `+f` found no
    // file system, `stat()` failed — says why on its own, is no search item,
    // and makes the run exit 1, as the C's `ErrStat` does (`main.c`: `if (!rv
    // && ErrStat) rv = LSOF_EXIT_ERROR`). lsof-rs had made a search item of it
    // as well, so `-V` reported it a second time (DIVERGENCES 62).
    let mut dropped_an_argument = false;
    let selection = {
        let mut sel = selection;
        // lsof reads a path argument as a FILE SYSTEM name when it matches a
        // mounted-on directory — or a block-device mount source, which is why
        // `lsof /dev/vda` means the root filesystem — and then selects every
        // open file on it. `-f` forbids that reading, `+f` forces it and
        // widens the source test to any mount source.
        // Only a bare path argument is compared with a mount's source, so
        // only a run that names one asks the backend to spell the sources.
        //
        // The C reads the table at the first `+d`/`+D`, while it is still
        // reading its options, so the `-b`, `-O`, `-S` and `-w` in force there
        // are the ones its `stat`s are made under: `+d D -b` examines every
        // mount, `-b +d D` never gets that far. Without one, the options as
        // they ended. `None` is a table not read at all.
        let table_fs = match sel.dir_args.first() {
            Some(first) => fs.with(first.blocking, first.warn),
            None => fs.with(sel.blocking, !sel.omit_unreadable),
        };
        let mounts = match sel.filesystem_args {
            FilesystemArgs::NeverFilesystem => None,
            _ => Some(env.backend.mounts(!sel.paths.is_empty(), &table_fs)),
        };
        let table_empty = mounts.as_ref().is_some_and(Vec::is_empty);
        let mounts = mounts.unwrap_or_default();
        sel.paths_identified = env.backend.identifies_paths();
        // `-Z` is gated on whether SELinux is ENABLED, which the C asks with
        // `is_selinux_enabled()` — a check for a mounted selinuxfs, not for
        // the `/sys/fs/selinux` directory. On a host where the directory
        // exists unmounted (this port's own test box) a presence check answers
        // "enabled" where the C answers "disabled", so the mount table is what
        // decides, using the type `-N` already taught it to read.
        if sel.selinux.is_some() {
            let enabled = mounts.iter().any(|m| m.fstype == "selinuxfs");
            if !enabled {
                // The C's exact line, and its status.
                eprintln!("lsof: -Z limited to SELinux");
                std::process::exit(1);
            }
            // SELinux IS enabled, and this port does not implement the column.
            // Deliberately NOT written blind: `print.c:902` puts CONTEXT in the
            // PROCESS columns with a width that grows to the longest value, and
            // no host available to this port can show where it sits relative to
            // USER and FD. Guessing produces silently misaligned output on
            // exactly the hosts that use the option. A loud refusal is the
            // honest failure; DIVERGENCES records it.
            eprintln!("lsof: -Z (SELinux context) is not implemented");
            std::process::exit(1);
        }
        // `-N` selects on file-system TYPE, so the mount table is what turns
        // the flag into a set of devices a row can be compared against.
        // `nfs` and `nfs4` are the two Linux spells; a type that merely starts
        // with them (there is none today) is deliberately not matched.
        if sel.nfs_only {
            for m in &mounts {
                if m.fstype == "nfs" || m.fstype == "nfs4" {
                    sel.nfs_devices.insert(m.device);
                }
            }
        }
        // `-e`/`+e` name a MOUNT POINT, and the C checks that before it does
        // anything else: `lsof: "-e /nosuch" is not a mounted file system.`,
        // then exit 1. A trailing slash is tolerated (`-e /dev/shm/` was
        // accepted), so the comparison is made on a normalised form. It
        // checks only a table that holds something (`main.c`: `if ((mp =
        // readmnt(ctx)))`): under `-b`, which drops every mount it would
        // `stat`, `-b -e /nosuch` exits 0 (measured).
        for e in sel.exempt_fs.iter().filter(|_| !table_empty) {
            let want = {
                let t = e.trim_end_matches('/');
                if t.is_empty() {
                    "/"
                } else {
                    t
                }
            };
            // A value is UTF-8 (`main` refuses any other argument), so a
            // mount point that is not can never be it.
            if !mounts.iter().any(|m| {
                m.dir
                    .to_str()
                    .is_some_and(|dir| dir.trim_end_matches('/') == want.trim_end_matches('/'))
                    || (want == "/" && m.dir == "/")
            }) {
                eprintln!("lsof: \"-e {e}\" is not a mounted file system.");
                std::process::exit(1);
            }
        }
        let esc = Escaper::for_host();
        spell_names_as_reported(&mut sel);
        // `+d`/`+D` first: the C expands them as it parses its options, so
        // their entries are search items before any bare path is, their
        // warnings come before a bare path's status error, and they come even
        // when every bare path is then dropped. The order matters to `-V`,
        // which reports the items last-entered first (DIVERGENCES 52).
        for dir in sel.dir_args.clone() {
            expand_dir(&mut sel, &dir, env.backend.as_ref(), esc, &fs);
        }
        let identified = sel.paths_identified;
        // A bare path is examined under the options as they ended, as the C
        // examines it once they are all read (`ck_file_arg()`).
        let arg_fs = fs.with(sel.blocking, !sel.omit_unreadable);
        let mut survived = 0usize;
        for typed in sel.paths.clone() {
            let path = match spell_path(&typed, identified, &arg_fs) {
                Ok(path) => path,
                Err(e) => {
                    // A warning: `-w` mutes it, `-Q` does not.
                    if !sel.omit_unreadable {
                        eprintln!("lsof: {}", e.message(&esc.text(&typed)));
                    }
                    dropped_an_argument = true;
                    continue;
                }
            };
            // Where files have identities, the argument is reported, and
            // compared with a socket's bound path, as typed: the C's `aname`.
            let name: OsString = if identified {
                typed.as_str().into()
            } else {
                path.clone()
            };
            let devs = filesystems_named(&mounts, &path, sel.filesystem_args);
            if !devs.is_empty() {
                sel.path_names.insert(typed.as_str().into());
                for dev in devs {
                    sel.path_fs_devices.insert(dev);
                    sel.path_items.push(PathItem {
                        id: None,
                        fs_device: Some(dev),
                        name: name.clone(),
                    });
                }
                survived += 1;
                continue;
            }
            if sel.filesystem_args == FilesystemArgs::AlwaysFilesystem {
                // `+f` promised a file system. The C says this is none
                // (unless `-Q`), drops it, and lists the rest; lsof-rs had
                // ended the run (DIVERGENCES 76). `safestrprt(av[i], …)`: as
                // typed, escaped, since a script may pass along a file name
                // it did not choose.
                if !sel.quiet {
                    eprintln!("lsof: not a file system: {}", esc.text(&typed));
                }
                dropped_an_argument = true;
                continue;
            }
            if !identified {
                // Matched by name, as the backend spells names.
                sel.path_items.push(PathItem {
                    id: None,
                    fs_device: None,
                    name,
                });
                survived += 1;
                continue;
            }
            // ONE `stat`, bounded, and its own error if it fails: a path on
            // a file system that does not answer is `Connection timed out`
            // after `-S` seconds, and under `-b` `Resource temporarily
            // unavailable` (DIVERGENCES 94). lsof-rs had `stat`ed a failed
            // argument a second time, unbounded, to word the message.
            match arg_fs
                .stat(Path::new(&path))
                .map(|st| env.backend.identify_stat(&st))
            {
                Ok(Some(id)) => {
                    sel.path_ids.insert(id);
                    sel.path_names.insert(typed.as_str().into());
                    sel.path_items.push(PathItem {
                        id: Some(id),
                        fs_device: None,
                        name,
                    });
                    survived += 1;
                }
                // A backend that identifies paths always says what a `stat`
                // found; a `None` here is an item nothing matches, since names
                // are compared only where paths are not identified.
                Ok(None) => {
                    sel.path_items.push(PathItem {
                        id: None,
                        fs_device: None,
                        name,
                    });
                    survived += 1;
                }
                Err(e) => {
                    // Named as the C names it, by its `Readlink()`: a link
                    // to `/nonexistent/f` is `status error on
                    // /nonexistent/f`, and a `/proc/PID/fd/N` pipe is `status
                    // error on /proc/PID/fd/pipe:[N]`. `-w` does not mute it.
                    if !sel.quiet {
                        eprintln!(
                            "lsof: status error on {}: {}",
                            esc.bytes(path.as_encoded_bytes()),
                            errno_text(&e)
                        );
                    }
                    dropped_an_argument = true;
                }
            }
        }
        // With no argument left, `ck_file_arg` returns non-zero and `main.c`
        // answers with `Error()`: the run ends before anything is listed, `+d`
        // and `+D` or not, as the C entered those while it parsed (DIVERGENCES
        // 77). So `lsof /a/real/file /nope` still lists the first file (and
        // exits 1), while `lsof -p 123 /nope` lists nothing at all. `-Q` makes
        // it non-fatal.
        if !sel.paths.is_empty() && survived == 0 && !sel.quiet {
            std::process::exit(1);
        }
        // Every bounded call this run makes is made by now. A helper killed
        // while one outlived its limit still holds what it opened for it, on
        // the file system that did not answer: the scan must not `stat` that
        // (DIVERGENCES 123), or it waits there itself.
        sel.helpers = lsof_core::FsCalls::helper_pids(&calls);
        sel
    };

    let _ = env.elevated; // read on all platforms; used for the hint on Windows.
    if let Some(note) = &env.note {
        eprintln!("lsof: {note}");
    }

    #[cfg(windows)]
    if wants_privilege_hint(env.elevated, &selection, &format) {
        eprintln!(
            "lsof: showing your accessible processes; re-run as Administrator for a system-wide view"
        );
    }

    // The between-cycle separator `-r` prints is format-aware (see
    // `Format::repeat_marker`). Captured before `run_cycle` moves `format` in.
    let repeat_marker = format.repeat_marker();
    // Captured before `run_cycle` takes `selection`: `-Q` decides the exit
    // status, and the closure needs the selection itself.
    let quiet = selection.quiet;
    // The C reports what it did not locate once, after its repeat loop, and a
    // plain `-r` loop ends only on a signal, which kills it first: under `-r`
    // there is no report at all (DIVERGENCES 54). lsof-rs refuses `+r` and a
    // repeat count, the two ways the C's loop can end by itself.
    let repeating = repeat.is_some();

    let run_cycle = move || -> usize {
        let gathered = match env.backend.gather(&selection) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("lsof: {e}");
                std::process::exit(1);
            }
        };
        // The process-level search items, marked from what the backend
        // gathered BEFORE any file is selected, so a PID whose files `-a`
        // drops is still located; see `Selection::locate`.
        let located = selection.locate(&gathered);
        let procs = selection.apply(gathered);
        // COMMAND/NAME/USER are escaped like the C's safestrprt(); the one
        // platform rule is whether `\` is (Unix) or is the path separator
        // (Windows). See lsof_core::render::escape.
        let esc = Escaper::for_host();
        let misses = if repeating {
            Vec::new()
        } else {
            unlocated(&selection, &located, esc)
        };
        // Written as it is formatted rather than built into one String and
        // printed: the table was being held three times over at the end of a
        // run (the rows, every cell, then the text), and it grows with the
        // host (DIVERGENCES 30). `-F` and JSON still build their text first.
        let stdout = std::io::stdout();
        let mut sink = std::io::BufWriter::new(stdout.lock());
        let written = match &format {
            Format::Table => table::render_to(
                &mut sink,
                &procs,
                TableOpts {
                    terse: selection.terse,
                    show_ppid: columns.ppid,
                    show_pgid: columns.pgid,
                    show_offset: columns.offset,
                    show_size: columns.size,
                    offset_digits: columns.offset_digits,
                    show_links: columns.nlink,
                    file_flags: columns.file_flags,
                    human_size: selection.human_size,
                    command_width: selection.command_width.cap(),
                    tcp_show: selection.tcp_info(),
                    ..TableOpts::new(esc)
                },
            ),
            Format::Fields { nul, only } => sink.write_all(
                fields::render_with_offset_digits(
                    &procs,
                    *nul,
                    only.as_deref(),
                    selection.tcp_info(),
                    esc,
                    columns.offset_digits,
                    columns.file_flags,
                )
                .as_bytes(),
            ),
            Format::Json => {
                let mut s = json::render_aggregated(&procs);
                s.push('\n');
                sink.write_all(s.as_bytes())
            }
            Format::JsonLines => sink.write_all(json::render_lines(&procs).as_bytes()),
        };
        // `-V`'s lines follow the listing, on the same stream, as the C's do.
        // `-Q` does not mute them: it changes only the exit status, as the
        // C's `FsearchErr` does (DIVERGENCES 53).
        let written = written.and_then(|()| {
            if selection.verbose {
                for m in &misses {
                    writeln!(sink, "{m}")?;
                }
            }
            sink.flush()
        });
        exit_on_write_error(written);
        misses.len()
    };

    // `-r`: repeat until interrupted, printing the format-aware cycle marker.
    // Exit promptly after the final cycle: handle enumeration may have abandoned
    // a worker thread blocked uninterruptibly in `NtQueryObject` (a synchronous
    // pipe/device), which can otherwise stall normal process teardown. lsof's
    // exit status is 1 when a specified `-p`/path search item was not located.
    match repeat {
        Some(delay) => loop {
            run_cycle();
            // lsof flushes each cycle so a piped consumer sees output promptly.
            let mut out = std::io::stdout();
            exit_on_write_error(
                out.write_all(repeat_marker.as_bytes())
                    .and_then(|()| out.flush()),
            );
            std::thread::sleep(std::time::Duration::from_secs(delay));
        },
        None => {
            // `-Q` suppresses the search-failure status as well as the
            // message: `main.c` clears `ErrStat` under it and never sets
            // `LSOF_SEARCH_FAILURE`, so `lsof -Q /nope` and `lsof -Q -p 999999`
            // both exit 0. lsof-rs had muted the message alone and still
            // exited 1, which is the half that scripts actually branch on.
            let code = if (run_cycle() > 0 || dropped_an_argument) && !quiet {
                1
            } else {
                0
            };
            // The helper is idle; closing its pipe ends it. Kept until now so
            // that, like the C's child, it is there when lsof lists itself.
            #[cfg(target_os = "linux")]
            calls.finish();
            #[cfg(windows)]
            lsof_backend_windows::exit_now(code);
            #[cfg(not(windows))]
            std::process::exit(code);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::canonicalize_selector;
    use super::wants_privilege_hint;
    use lsof_cli::args::{parse, Action};
    use lsof_core::render::Format;
    use lsof_core::Selection;

    /// Parse argv exactly as `main` does and hand back the hint inputs.
    fn parsed(argv: &[&str]) -> (Selection, Format) {
        match parse(argv.iter().map(|s| s.to_string()).collect()) {
            Ok(Action::Run {
                selection, format, ..
            }) => (selection, format),
            other => panic!("expected Action::Run for {argv:?}, got {other:?}"),
        }
    }

    /// The predicate behind the "re-run as Administrator" stderr hint. Hosted
    /// CI runners are always elevated, so the live smoke cases for the
    /// unelevated branch (`privilege-hint-unelevated`, `suppress-warnings-
    /// dash-w`) SKIP there and only run on real hardware; these tests pin the
    /// same argv → hint decisions portably on every push. The residue a unit
    /// test cannot cover — `is_elevated()`'s token query itself — is the
    /// per-release manual checkpoint in docs/road-to-1.0.md.
    #[test]
    fn privilege_hint_prints_only_unelevated_table_mode() {
        // The smoke case `privilege-hint-unelevated`: plain `-p <pid>` run.
        let (sel, fmt) = parsed(&["-p", "1234"]);
        assert!(wants_privilege_hint(false, &sel, &fmt));
        // Elevated: same argv, no hint (the smoke case's Skip branch).
        assert!(!wants_privilege_hint(true, &sel, &fmt));
        // A bare system-wide run hints too.
        let (sel, fmt) = parsed(&[]);
        assert!(wants_privilege_hint(false, &sel, &fmt));
    }

    #[test]
    fn privilege_hint_suppressed_by_dash_w() {
        // The smoke case `suppress-warnings-dash-w`: `-w -p <pid>`, unelevated.
        let (sel, fmt) = parsed(&["-w", "-p", "1234"]);
        assert!(!wants_privilege_hint(false, &sel, &fmt));
    }

    #[test]
    fn privilege_hint_absent_for_queries_needing_no_elevation() {
        // The smoke case `inet-no-privilege-hint`: `-i` never hints.
        let (sel, fmt) = parsed(&["-nP", "-i"]);
        assert!(!wants_privilege_hint(false, &sel, &fmt));
        // `-U` implies the ETW path with its own explicit privilege error.
        let (sel, fmt) = parsed(&["-U"]);
        assert!(!wants_privilege_hint(false, &sel, &fmt));
        // Path lookups go through the Restart Manager, no elevation needed.
        let (sel, fmt) = parsed(&["C:\\some\\file.txt"]);
        assert!(!wants_privilege_hint(false, &sel, &fmt));
        let temp = std::env::temp_dir().to_string_lossy().into_owned();
        let (sel, fmt) = parsed(&["+D", &temp]);
        assert!(!wants_privilege_hint(false, &sel, &fmt));
    }

    #[test]
    fn privilege_hint_never_touches_machine_formats() {
        // -F / -J / -j consumers parse the stream; the hint is table-only.
        // (`-t` is terse *table* output and keeps the hint — on stderr, so
        // `kill $(lsof -t ...)` still reads clean stdout, as with C lsof.)
        for argv in [&["-F"][..], &["-J"], &["-j"]] {
            let (sel, fmt) = parsed(argv);
            assert!(
                !wants_privilege_hint(false, &sel, &fmt),
                "hint must stay off for {argv:?}"
            );
        }
        let (sel, fmt) = parsed(&["-t"]);
        assert!(wants_privilege_hint(false, &sel, &fmt));
    }

    #[test]
    fn canonicalize_resolves_relative_and_keeps_missing() {
        // A real relative path resolves to an absolute one.
        let dir = std::env::temp_dir().join("lsof_rs_canon_test");
        std::fs::create_dir_all(&dir).unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let mut p = ".".to_string();
        canonicalize_selector(&mut p);
        std::env::set_current_dir(prev).unwrap();
        assert!(
            std::path::Path::new(&p).is_absolute(),
            "relative selector should resolve absolute: {p:?}"
        );
        assert!(
            !p.starts_with("\\\\?\\"),
            "verbatim prefix must be stripped: {p:?}"
        );
        // A path that doesn't exist stays exactly as typed.
        let mut missing = "definitely/not/a/real/path-xyzzy".to_string();
        canonicalize_selector(&mut missing);
        assert_eq!(missing, "definitely/not/a/real/path-xyzzy");
    }

    /// Where names are matched, the path arguments and the `+D` trees are
    /// selected by their long form; `+d` stays as typed, as it always has. A
    /// backend that identifies files keeps every argument as typed, for
    /// `Readlink()` to spell. The Windows smoke suite found this dropped: `+D
    /// %TEMP%`, an 8.3 name on the runner, selected nothing.
    #[test]
    fn names_are_spelt_as_reported_only_where_names_are_matched() {
        use super::spell_names_as_reported;
        use lsof_core::Selection;
        let missing = "definitely/not/a/real/path-xyzzy".to_string();
        let dir = std::env::temp_dir();
        let typed = dir.join(".").to_string_lossy().into_owned();
        let selection = |identified: bool| Selection {
            paths: vec![typed.clone(), missing.clone()],
            dir_trees: vec![typed.clone()],
            dirs_one_level: vec![typed.clone()],
            paths_identified: identified,
            ..Default::default()
        };
        let mut sel = selection(false);
        spell_names_as_reported(&mut sel);
        let long = {
            let mut p = typed.clone();
            super::canonicalize_selector(&mut p);
            p
        };
        assert_ne!(
            long, typed,
            "the test needs a spelling canonicalize changes"
        );
        assert_eq!(sel.paths, [long.clone(), missing.clone()]);
        assert_eq!(sel.dir_trees, [long]);
        assert_eq!(sel.dirs_one_level, std::slice::from_ref(&typed));
        let mut sel = selection(true);
        spell_names_as_reported(&mut sel);
        assert_eq!(sel.paths, [typed.clone(), missing]);
        assert_eq!(sel.dir_trees, [typed]);
    }

    /// The help keeps its layout: an option four columns in, its wrapped
    /// lines eighteen, and nothing past eighty. A `\n\` continuation in the
    /// literal eats the next line's leading spaces, which once printed every
    /// line flush left.
    #[test]
    fn the_help_keeps_its_indentation_and_width() {
        let help = super::usage();
        assert!(help
            .lines()
            .any(|l| l.starts_with("    -p <pids>     select by PID")));
        assert!(help
            .lines()
            .any(|l| l.starts_with("                  on Windows); ^cmd excludes")));
        for line in help.lines() {
            assert!(line.chars().count() <= 80, "too wide: {line:?}");
        }
    }

    /// A walk stops at whichever limit it meets first, entries or the bytes
    /// of their names, and never goes below either.
    #[test]
    fn a_walk_budget_counts_entries_and_name_bytes() {
        use super::{WalkBudget, WALK_ENTRIES, WALK_NAME_BYTES};
        let mut b = WalkBudget::new();
        let mut taken = 0;
        while b.take(1) {
            taken += 1;
        }
        assert_eq!(taken, WALK_ENTRIES);
        let mut b = WalkBudget::new();
        assert!(b.take(WALK_NAME_BYTES - 1));
        assert!(b.take(1));
        assert!(!b.take(1), "no bytes left");
        assert_eq!(b.entries, WALK_ENTRIES - 2);
        let mut b = WalkBudget::new();
        assert!(!b.take(WALK_NAME_BYTES + 1), "one name past the limit");
        assert_eq!((b.entries, b.bytes), (WALK_ENTRIES, WALK_NAME_BYTES));
    }

    #[test]
    fn strip_verbatim_matches_backend_spelling() {
        // Must mirror the backend's normalize_final so both sides of the
        // selection comparison use one spelling.
        use super::strip_verbatim;
        assert_eq!(strip_verbatim("\\\\?\\C:\\a\\b.txt"), "C:\\a\\b.txt");
        assert_eq!(
            strip_verbatim("\\\\?\\UNC\\srv\\share\\f"),
            "\\\\srv\\share\\f"
        );
        assert_eq!(strip_verbatim("C:\\plain"), "C:\\plain");
        assert_eq!(strip_verbatim("/unix/path"), "/unix/path");
    }

    /// `-K`'s search item is reported after the PIDs, and only for an
    /// explicit `-K`, the last of `-K` and `-K i` deciding (DIVERGENCES 33).
    #[test]
    fn no_tasks_located_follows_the_pids_and_only_under_dash_k() {
        use lsof_core::render::Escaper;
        use lsof_core::Located;
        let lines = |argv: &[&str], tasks: bool| {
            let (sel, _) = parsed(argv);
            let located = Located {
                pids: vec![false],
                tasks,
                ..Default::default()
            };
            super::unlocated(&sel, &located, Escaper::UNIX)
        };
        assert_eq!(
            lines(&["-K", "-p", "1"], false),
            ["lsof: process ID not located: 1", "lsof: no tasks located"]
        );
        assert_eq!(
            lines(&["-K", "-p", "1"], true),
            ["lsof: process ID not located: 1"]
        );
        assert_eq!(
            lines(&["-K", "-K", "i", "-p", "1"], false),
            ["lsof: process ID not located: 1"]
        );
        assert_eq!(
            lines(&["-K", "i", "-K", "-p", "1"], false),
            ["lsof: process ID not located: 1", "lsof: no tasks located"]
        );
        assert_eq!(
            lines(&["-p", "1"], false),
            ["lsof: process ID not located: 1"]
        );
    }

    /// The C strips trailing slashes from a path argument longer than one
    /// character before it stats it (`arg.c`), keeping one.
    #[test]
    fn trailing_slashes_go_but_one_stays() {
        use super::without_trailing_slashes as strip;
        assert_eq!(strip(b"/d/f/"), b"/d/f");
        assert_eq!(strip(b"f//"), b"f");
        assert_eq!(strip(b"/"), b"/");
        assert_eq!(strip(b"//"), b"/");
        assert_eq!(strip(b"f"), b"f");
        assert_eq!(strip(b""), b"");
        assert_eq!(strip(b"nu/\xff/"), b"nu/\xff");
    }

    /// A path item `Selection::locate` did not mark is reported in its own
    /// words, as typed: `no file use located`, or `no file system use
    /// located` for one that named a file system (DIVERGENCES 60) — and the
    /// last one entered first, as the C walks the list it prepended to
    /// (DIVERGENCES 52).
    #[test]
    fn an_unlocated_path_is_reported_as_typed() {
        use lsof_core::render::Escaper;
        use lsof_core::{Located, PathItem, Selection};
        let sel = Selection {
            path_items: vec![
                PathItem {
                    id: Some(lsof_core::FileId {
                        dev: 0xfe00,
                        ino: 11,
                    }),
                    fs_device: None,
                    name: "./x".into(),
                },
                PathItem {
                    id: None,
                    fs_device: Some(42),
                    name: "mnt".into(),
                },
            ],
            ..Default::default()
        };
        let lines = |paths: Vec<bool>| {
            let located = Located {
                paths,
                ..Default::default()
            };
            super::unlocated(&sel, &located, Escaper::UNIX)
        };
        assert_eq!(
            lines(vec![false, false]),
            [
                "lsof: no file system use located: mnt",
                "lsof: no file use located: ./x"
            ]
        );
        assert_eq!(
            lines(vec![true, false]),
            ["lsof: no file system use located: mnt"]
        );
        assert!(lines(vec![true, true]).is_empty());
    }

    /// A walk over a tree held in memory: each call it makes, through the
    /// bounded layer, with the limit `-S` gave where the `+D` stood; an
    /// entry whose `lstat` times out is said in the C's words and the walk
    /// goes on to the next; `-w` there mutes it (DIVERGENCES 94, 118). The
    /// tree is spelt with `/`; the walk joins names with the host's separator
    /// (`\\` on Windows), which the tree reads as `/`.
    #[test]
    fn a_walk_makes_every_call_through_the_layer_and_goes_on_past_a_timeout() {
        use lsof_core::safefs::{timed_out, Blocking, FileStat, FsCalls};
        use lsof_core::{Backend, DirArg, Escaper, SafeFs, Selection};
        use std::cell::RefCell;
        use std::ffi::OsString;
        use std::io;
        use std::path::Path;

        struct Tree(RefCell<Vec<(&'static str, String, u32)>>);
        impl Tree {
            fn note(&self, call: &'static str, p: &Path, limit: u32) -> String {
                let p = p.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
                self.0.borrow_mut().push((call, p.clone(), limit));
                p
            }
            fn node(p: &str, follow: bool) -> io::Result<FileStat> {
                let (mode, ino) = match p {
                    "/w" | "/w/sub" => (0o040_755, p.len() as u64),
                    "/w/a" => (0o100_644, 4),
                    "/w/hung" => return Err(timed_out()),
                    "/w/l" if !follow => (0o120_777, 3),
                    "/w/l" => (0o100_644, 4),
                    _ => return Err(io::Error::from(io::ErrorKind::NotFound)),
                };
                Ok(FileStat {
                    dev: 1,
                    ino,
                    mode,
                    ..FileStat::default()
                })
            }
        }
        impl FsCalls for Tree {
            fn stat(&self, p: &Path, limit: u32) -> io::Result<FileStat> {
                Tree::node(&self.note("stat", p, limit), true)
            }
            fn lstat(&self, p: &Path, limit: u32) -> io::Result<FileStat> {
                Tree::node(&self.note("lstat", p, limit), false)
            }
            fn readlink(&self, p: &Path, limit: u32) -> io::Result<OsString> {
                self.note("readlink", p, limit);
                Err(io::Error::from(io::ErrorKind::InvalidInput))
            }
            fn read_dir(&self, p: &Path, limit: u32) -> io::Result<Vec<OsString>> {
                match self.note("read_dir", p, limit).as_str() {
                    "/w" => Ok(["a", "hung", "l", "sub"].map(OsString::from).to_vec()),
                    _ => Ok(Vec::new()),
                }
            }
        }
        struct Ids;
        impl Backend for Ids {
            fn name(&self) -> &str {
                "ids"
            }
            fn identify_stat(&self, st: &FileStat) -> Option<lsof_core::FileId> {
                Some(lsof_core::FileId {
                    dev: st.dev,
                    ino: st.ino,
                })
            }
            fn identifies_paths(&self) -> bool {
                true
            }
            fn gather(
                &self,
                _: &Selection,
            ) -> Result<Vec<lsof_core::model::Process>, lsof_core::BackendError> {
                Ok(Vec::new())
            }
        }

        let tree = Tree(RefCell::new(Vec::new()));
        let said = RefCell::new(Vec::<String>::new());
        let say = |l: &str| said.borrow_mut().push(l.to_string());
        let fs = SafeFs::new(&tree, &say);
        let dir = DirArg {
            recursive: true,
            dir: "/w".into(),
            cross_filesystems: false,
            cross_symlinks: true,
            warn: true,
            blocking: Blocking {
                limit: 7,
                ..Blocking::default()
            },
            // What the option's `stat` of `/w` said.
            stat: Tree::node("/w", true).unwrap(),
        };
        let mut sel = Selection {
            paths_identified: true,
            ..Selection::default()
        };
        super::expand_dir(&mut sel, &dir, &Ids, Escaper::for_host(), &fs);
        let made = tree.0.take();
        for (c, p, limit) in &made {
            assert_eq!(*limit, 7, "{c} {p}: the limit where +D stood");
        }
        let calls: Vec<(&str, &str)> = made.iter().map(|(c, p, _)| (*c, p.as_str())).collect();
        // One `lstat` an entry, one `stat` more for the link `-x l` follows,
        // and none of the directory itself, which the option `stat`ed
        // (DIVERGENCES 111): the C's calls (`arg.c:876,930,1014,1047`).
        assert_eq!(
            calls,
            [
                ("read_dir", "/w"),
                ("lstat", "/w/a"),
                ("lstat", "/w/hung"),
                ("lstat", "/w/l"),
                ("stat", "/w/l"),
                ("lstat", "/w/sub"),
                ("read_dir", "/w/sub"),
            ]
        );
        // Exactly the C's words; under miri, whose strerror adds `(os error
        // 110)`, those words first.
        let hung = Path::new("/w").join("hung");
        let want = format!(
            "lsof: WARNING: can't lstat({}): Connection timed out",
            hung.display()
        );
        let warned = said.borrow();
        assert_eq!(warned.len(), 1, "{warned:?}");
        assert!(
            warned[0] == want || (cfg!(miri) && warned[0].starts_with(&want)),
            "{warned:?}"
        );
        drop(warned);
        let items: Vec<String> = sel
            .path_items
            .iter()
            .map(|i| {
                i.name
                    .to_string_lossy()
                    .replace(std::path::MAIN_SEPARATOR, "/")
            })
            .collect();
        assert_eq!(
            items,
            ["/w", "/w/a", "/w/l", "/w/sub"],
            "on past the timeout"
        );
        // Each is its one call's device and inode (DIVERGENCES 101, 111):
        // the directory's from the option's `stat`, an entry's from its
        // `lstat`, and the link's from the `stat` that followed it, its
        // target's (4), not its own (3).
        let ids: Vec<Option<(u64, u64)>> = sel
            .path_items
            .iter()
            .map(|i| i.id.map(|id| (id.dev, id.ino)))
            .collect();
        assert_eq!(
            ids,
            [Some((1, 2)), Some((1, 4)), Some((1, 4)), Some((1, 6))]
        );

        // `-w` where the `+D` stood mutes it; nothing else changes.
        said.borrow_mut().clear();
        let quiet = DirArg { warn: false, ..dir };
        let mut sel = Selection {
            paths_identified: true,
            ..Selection::default()
        };
        super::expand_dir(&mut sel, &quiet, &Ids, Escaper::for_host(), &fs);
        assert!(said.borrow().is_empty(), "{:?}", said.borrow());
        assert_eq!(sel.path_items.len(), 4);
    }

    /// The walk's rules (DIVERGENCES 111), each on a tree held in memory
    /// whose `lstat` and `stat` of one path may answer differently, as a
    /// rename between two calls makes them answer: a walk that asked twice
    /// would take the second answer, and these tests see which it took.
    /// Every call is logged. The tree is spelt with `/`; the walk joins with
    /// the host's separator, which the log reads as `/`.
    mod walk {
        use lsof_core::safefs::{FileStat, FsCalls};
        use lsof_core::{errno_text, Backend, DirArg, Escaper, SafeFs, Selection};
        use std::cell::RefCell;
        use std::ffi::OsString;
        use std::io;
        use std::path::Path;

        // `EACCES`, `ENOTDIR` and `ELOOP`. Their words are whatever this
        // host's `strerror` says, which is what lsof prints, so a test asks
        // `errno_text` for them rather than spelling them.
        const EACCES: i32 = 13;
        const ENOTDIR: i32 = 20;
        const ELOOP: i32 = 40;

        /// One answer of the tree: a file, an error number, or gone.
        #[derive(Clone, Copy, Debug)]
        pub enum Is {
            St(FileStat),
            Errno(i32),
            Gone,
        }

        impl Is {
            fn answer(self) -> io::Result<FileStat> {
                match self {
                    Is::St(st) => Ok(st),
                    Is::Errno(n) => Err(io::Error::from_raw_os_error(n)),
                    Is::Gone => Err(io::Error::from(io::ErrorKind::NotFound)),
                }
            }
        }

        fn st(dev: u64, ino: u64, mode: u32) -> FileStat {
            FileStat {
                dev,
                ino,
                mode,
                ..FileStat::default()
            }
        }
        pub fn reg(dev: u64, ino: u64) -> Is {
            Is::St(st(dev, ino, 0o100_644))
        }
        pub fn dir(dev: u64, ino: u64) -> Is {
            Is::St(st(dev, ino, 0o040_755))
        }
        pub fn lnk(dev: u64, ino: u64) -> Is {
            Is::St(st(dev, ino, 0o120_777))
        }

        /// The top directory as the option's one `stat` saw it: device 1,
        /// inode 1. The tree's own answers for `/v` differ from it, so an
        /// item that carried them would show it.
        pub fn top() -> FileStat {
            st(1, 1, 0o040_755)
        }

        #[derive(Default)]
        pub struct Tree {
            /// A path, its `lstat` and its `stat`.
            pub nodes: Vec<(&'static str, Is, Is)>,
            /// A directory's names, or the error its listing fails with. Any
            /// other path is no directory, and its listing fails as one does.
            pub lists: Vec<(&'static str, Result<Vec<&'static str>, Is>)>,
            log: RefCell<Vec<(&'static str, String)>>,
        }

        impl Tree {
            fn note(&self, call: &'static str, p: &Path) -> String {
                let p = p.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");
                self.log.borrow_mut().push((call, p.clone()));
                p
            }
            fn node(&self, p: &str) -> Option<(Is, Is)> {
                self.nodes
                    .iter()
                    .find(|(n, _, _)| *n == p)
                    .map(|(_, l, s)| (*l, *s))
            }
            /// Each call the walk made, in order.
            pub fn calls(&self) -> Vec<(&'static str, String)> {
                self.log.borrow().clone()
            }
            /// How many times the walk made `call` of `p`.
            pub fn count(&self, call: &str, p: &str) -> usize {
                self.log
                    .borrow()
                    .iter()
                    .filter(|(c, q)| *c == call && q == p)
                    .count()
            }
        }

        impl FsCalls for Tree {
            fn stat(&self, p: &Path, _: u32) -> io::Result<FileStat> {
                let p = self.note("stat", p);
                self.node(&p).map_or(Is::Gone, |(_, s)| s).answer()
            }
            fn lstat(&self, p: &Path, _: u32) -> io::Result<FileStat> {
                let p = self.note("lstat", p);
                self.node(&p).map_or(Is::Gone, |(l, _)| l).answer()
            }
            fn readlink(&self, p: &Path, _: u32) -> io::Result<OsString> {
                self.note("readlink", p);
                Err(io::Error::from(io::ErrorKind::InvalidInput))
            }
            fn read_dir(&self, p: &Path, _: u32) -> io::Result<Vec<OsString>> {
                let p = self.note("read_dir", p);
                match self.lists.iter().find(|(n, _)| *n == p) {
                    Some((_, Ok(names))) => Ok(names.iter().map(OsString::from).collect()),
                    Some((_, Err(e))) => e.answer().map(|_| Vec::new()),
                    None => Err(io::Error::from_raw_os_error(ENOTDIR)),
                }
            }
        }

        /// A backend that identifies a file by its device and inode, as
        /// Linux's does.
        struct Ids;
        impl Backend for Ids {
            fn name(&self) -> &str {
                "ids"
            }
            fn identify_stat(&self, st: &FileStat) -> Option<lsof_core::FileId> {
                Some(lsof_core::FileId {
                    dev: st.dev,
                    ino: st.ino,
                })
            }
            fn identifies_paths(&self) -> bool {
                true
            }
            fn gather(
                &self,
                _: &Selection,
            ) -> Result<Vec<lsof_core::model::Process>, lsof_core::BackendError> {
                Ok(Vec::new())
            }
        }

        /// What a walk entered: each item's name, with `/`, and identity.
        pub type Items = Vec<(String, Option<(u64, u64)>)>;

        /// `+d /v`, or `+D /v` when `recursive`, under the `-x` that `x`
        /// spells (`""`, `"f"`, `"l"` or `"fl"`), with warnings on unless
        /// `-w` stood before it, on a backend that identifies files or, with
        /// `identified` false, one that matches names. What it entered, and
        /// what it said.
        pub fn walk_as(
            tree: &Tree,
            recursive: bool,
            x: &str,
            warn: bool,
            identified: bool,
        ) -> (Items, Vec<String>) {
            let said = RefCell::new(Vec::<String>::new());
            let say = |l: &str| said.borrow_mut().push(l.to_string());
            let fs = SafeFs::new(tree, &say);
            let arg = DirArg {
                recursive,
                dir: "/v".into(),
                cross_filesystems: x.contains('f'),
                cross_symlinks: x.contains('l'),
                warn,
                blocking: lsof_core::Blocking::default(),
                stat: top(),
            };
            let mut sel = Selection {
                paths_identified: identified,
                ..Selection::default()
            };
            super::super::expand_dir(&mut sel, &arg, &Ids, Escaper::for_host(), &fs);
            let items = sel
                .path_items
                .iter()
                .map(|i| {
                    let name = i
                        .name
                        .to_string_lossy()
                        .replace(std::path::MAIN_SEPARATOR, "/");
                    (name, i.id.map(|id| (id.dev, id.ino)))
                })
                .collect();
            (items, said.into_inner())
        }

        pub fn walk(tree: &Tree, recursive: bool, x: &str) -> (Items, Vec<String>) {
            walk_as(tree, recursive, x, true, true)
        }

        fn item(name: &str, id: (u64, u64)) -> (String, Option<(u64, u64)>) {
            (name.to_string(), Some(id))
        }

        /// A warning in the C's words: `lsof: WARNING: can't CALL(P)TAIL:
        /// E`, `P` spelt as the walk spells it, `E` this host's words for the
        /// error.
        fn warning(call: &str, name: &str, tail: &str, e: io::Error) -> String {
            let p = Path::new("/v").join(name);
            format!(
                "lsof: WARNING: can't {call}({}){tail}: {}",
                p.display(),
                errno_text(&e)
            )
        }

        /// T1: an entry is what its one `lstat` says. Its `stat` names
        /// another file, on another device, which a second call would have
        /// found; no such call is made.
        #[test]
        fn an_entry_is_identified_by_its_one_lstat() {
            let tree = Tree {
                nodes: vec![("/v/e", reg(1, 10), reg(2, 99))],
                lists: vec![("/v", Ok(vec!["e"]))],
                ..Tree::default()
            };
            let (items, said) = walk(&tree, false, "");
            assert_eq!(items, [item("/v", (1, 1)), item("/v/e", (1, 10))]);
            assert!(said.is_empty(), "{said:?}");
            assert_eq!(tree.count("lstat", "/v/e"), 1);
            assert_eq!(tree.count("stat", "/v/e"), 0, "{:?}", tree.calls());
        }

        /// T2: a link, by its `lstat`, is passed over without `-x l`, with no
        /// other call and nothing said, whatever it leads to.
        #[test]
        fn a_link_by_its_lstat_is_skipped_without_x_l() {
            let tree = Tree {
                nodes: vec![("/v/l", lnk(1, 3), reg(1, 5))],
                lists: vec![("/v", Ok(vec!["l"]))],
                ..Tree::default()
            };
            for x in ["", "f"] {
                let (items, said) = walk(&tree, true, x);
                assert_eq!(items, [item("/v", (1, 1))], "-x {x}");
                assert!(said.is_empty(), "{said:?}");
            }
            assert_eq!(tree.count("stat", "/v/l"), 0, "{:?}", tree.calls());
        }

        /// T3: `+D` descends into what the `lstat` calls a directory, and
        /// into nothing else, whatever a `stat` would say now: a name that
        /// is a file to its `lstat` is not listed, so no `can't opendir` is
        /// said of it, and one that is a directory to its `lstat` is. `+d`
        /// descends into none.
        #[test]
        fn descent_is_decided_by_the_lstat_mode() {
            let tree = || Tree {
                nodes: vec![
                    ("/v/d", dir(1, 20), reg(1, 21)),
                    ("/v/f", reg(1, 30), dir(1, 31)),
                    ("/v/d/in", reg(1, 22), reg(1, 23)),
                    ("/v/f/hidden", reg(1, 32), reg(1, 32)),
                ],
                lists: vec![
                    ("/v", Ok(vec!["d", "f"])),
                    ("/v/d", Ok(vec!["in"])),
                    ("/v/f", Ok(vec!["hidden"])),
                ],
                ..Tree::default()
            };
            let t = tree();
            let (items, said) = walk(&t, true, "");
            assert_eq!(
                items,
                [
                    item("/v", (1, 1)),
                    item("/v/d", (1, 20)),
                    item("/v/f", (1, 30)),
                    item("/v/d/in", (1, 22)),
                ]
            );
            assert!(said.is_empty(), "{said:?}");
            assert_eq!(t.count("read_dir", "/v/d"), 1);
            assert_eq!(t.count("read_dir", "/v/f"), 0, "{:?}", t.calls());
            assert_eq!(t.count("stat", "/v/d") + t.count("stat", "/v/f"), 0);
            let t = tree();
            let (items, _) = walk(&t, false, "");
            assert_eq!(items.len(), 3, "{items:?}");
            assert_eq!(t.count("read_dir", "/v/d"), 0, "{:?}", t.calls());
        }

        /// T4: under `-x l` a link is followed by exactly one `stat`, and
        /// that `stat` is the entry: its identity, on another device here,
        /// and the directory `+D` then lists, by the link's name.
        #[test]
        fn under_x_l_a_link_is_followed_exactly_once() {
            let tree = Tree {
                nodes: vec![
                    ("/v/l", lnk(1, 3), dir(2, 7)),
                    ("/v/l/x", reg(1, 8), reg(1, 8)),
                ],
                lists: vec![("/v", Ok(vec!["l"])), ("/v/l", Ok(vec!["x"]))],
                ..Tree::default()
            };
            let (items, said) = walk(&tree, true, "l");
            assert_eq!(
                items,
                [
                    item("/v", (1, 1)),
                    item("/v/l", (2, 7)),
                    item("/v/l/x", (1, 8)),
                ]
            );
            assert!(said.is_empty(), "{said:?}");
            assert_eq!(tree.count("lstat", "/v/l"), 1);
            assert_eq!(tree.count("stat", "/v/l"), 1, "{:?}", tree.calls());
            assert_eq!(tree.count("read_dir", "/v/l"), 1);
        }

        /// T5: `-x f` is judged on the `lstat`'s device, the link's own, and
        /// before the link is followed: a link on the directory's file
        /// system to a file on another is entered under `-x l` alone, as
        /// that file; a file on another file system is passed over without
        /// `-x f`, and entered with it.
        #[test]
        fn x_f_is_judged_on_the_lstat_device() {
            let tree = || Tree {
                nodes: vec![
                    ("/v/l", lnk(1, 3), reg(2, 8)),
                    ("/v/r", reg(2, 9), reg(2, 9)),
                    ("/v/far", lnk(2, 4), reg(1, 5)),
                ],
                lists: vec![("/v", Ok(vec!["l", "r", "far"]))],
                ..Tree::default()
            };
            let t = tree();
            let (items, said) = walk(&t, false, "l");
            assert_eq!(items, [item("/v", (1, 1)), item("/v/l", (2, 8))]);
            assert!(said.is_empty(), "{said:?}");
            // A link on another file system is passed over before it is
            // followed.
            assert_eq!(t.count("stat", "/v/far"), 0, "{:?}", t.calls());
            let (items, _) = walk(&tree(), false, "fl");
            assert_eq!(
                items,
                [
                    item("/v", (1, 1)),
                    item("/v/l", (2, 8)),
                    item("/v/r", (2, 9)),
                    item("/v/far", (1, 5)),
                ]
            );
            let (items, _) = walk(&tree(), false, "f");
            assert_eq!(items, [item("/v", (1, 1)), item("/v/r", (2, 9))]);
        }

        /// T6: every entry is held to the top directory's file system, its
        /// option-time `st_dev`, those of a directory reached through a
        /// link to another file system too, until `-x f`.
        #[test]
        fn ddev_is_the_top_directory_device_throughout() {
            let tree = || Tree {
                nodes: vec![
                    ("/v/l", lnk(1, 3), dir(2, 7)),
                    ("/v/l/x", reg(2, 8), reg(2, 8)),
                    ("/v/l/y", reg(1, 9), reg(1, 9)),
                ],
                lists: vec![("/v", Ok(vec!["l"])), ("/v/l", Ok(vec!["x", "y"]))],
                ..Tree::default()
            };
            let (items, _) = walk(&tree(), true, "l");
            assert_eq!(
                items,
                [
                    item("/v", (1, 1)),
                    item("/v/l", (2, 7)),
                    item("/v/l/y", (1, 9)),
                ]
            );
            let (items, _) = walk(&tree(), true, "fl");
            assert_eq!(
                items,
                [
                    item("/v", (1, 1)),
                    item("/v/l", (2, 7)),
                    item("/v/l/x", (2, 8)),
                    item("/v/l/y", (1, 9)),
                ]
            );
        }

        /// T7: an entry whose `lstat` fails is said once, in the C's words
        /// and with that call's error, unless it is gone; it is no search
        /// item, it is not asked again, and the walk goes on.
        #[test]
        fn an_lstat_error_warns_once_unless_enoent() {
            let tree = Tree {
                nodes: vec![
                    ("/v/a", Is::Errno(EACCES), reg(1, 10)),
                    ("/v/b", Is::Gone, reg(1, 11)),
                    ("/v/c", reg(1, 12), reg(1, 12)),
                ],
                lists: vec![("/v", Ok(vec!["a", "b", "c"]))],
                ..Tree::default()
            };
            let (items, said) = walk(&tree, true, "fl");
            assert_eq!(items, [item("/v", (1, 1)), item("/v/c", (1, 12))]);
            let e = io::Error::from_raw_os_error(EACCES);
            assert_eq!(said, [warning("lstat", "a", "", e)]);
            for p in ["/v/a", "/v/b"] {
                assert_eq!(tree.count("lstat", p), 1, "{p}");
                assert_eq!(tree.count("stat", p), 0, "{p}");
            }
        }

        /// T8: a link `-x l` cannot follow is said in the C's words, its
        /// spelling included (`symbolc`), unless it dangles; it is no search
        /// item either way.
        #[test]
        fn a_follow_error_warns_symbolc_unless_enoent() {
            let tree = Tree {
                nodes: vec![
                    ("/v/loop", lnk(1, 3), Is::Errno(ELOOP)),
                    ("/v/dangle", lnk(1, 4), Is::Gone),
                ],
                lists: vec![("/v", Ok(vec!["loop", "dangle"]))],
                ..Tree::default()
            };
            let (items, said) = walk(&tree, true, "l");
            assert_eq!(items, [item("/v", (1, 1))]);
            let e = io::Error::from_raw_os_error(ELOOP);
            assert_eq!(said, [warning("stat", "loop", " symbolc link", e)]);
        }

        /// T10: the walk makes no call on the top directory but its listing.
        /// The directory's item is what the option's `stat` said, and it is
        /// entered before it is listed, so one gone since is still the item,
        /// unlocated, and its listing's `ENOENT` says nothing; another
        /// listing error is said in the C's words.
        #[test]
        fn the_top_directory_is_not_stated_at_walk_time() {
            let tree = Tree {
                nodes: vec![("/v", dir(9, 90), dir(9, 91))],
                lists: vec![("/v", Ok(vec![]))],
                ..Tree::default()
            };
            let (items, said) = walk(&tree, true, "fl");
            assert_eq!(items, [item("/v", (1, 1))]);
            assert!(said.is_empty(), "{said:?}");
            assert_eq!(tree.calls(), [("read_dir", "/v".to_string())]);
            let gone = Tree {
                lists: vec![("/v", Err(Is::Gone))],
                ..Tree::default()
            };
            let (items, said) = walk(&gone, false, "");
            assert_eq!(items, [item("/v", (1, 1))]);
            assert!(said.is_empty(), "{said:?}");
            let shut = Tree {
                lists: vec![("/v", Err(Is::Errno(EACCES)))],
                ..Tree::default()
            };
            let (items, said) = walk(&shut, false, "");
            assert_eq!(items, [item("/v", (1, 1))]);
            let want = format!(
                "lsof: WARNING: can't opendir(/v): {}",
                errno_text(&io::Error::from_raw_os_error(EACCES))
            );
            assert_eq!(said, [want]);
        }

        /// T11: a `-w` given before the option mutes every warning its walk
        /// would give, and changes nothing else.
        #[test]
        fn dash_w_before_the_option_mutes_every_walk_warning() {
            let tree = || Tree {
                nodes: vec![
                    ("/v/a", Is::Errno(EACCES), reg(1, 10)),
                    ("/v/loop", lnk(1, 3), Is::Errno(ELOOP)),
                    ("/v/d", dir(1, 20), dir(1, 20)),
                    ("/v/c", reg(1, 12), reg(1, 12)),
                ],
                lists: vec![
                    ("/v", Ok(vec!["a", "loop", "d", "c"])),
                    ("/v/d", Err(Is::Errno(EACCES))),
                ],
                ..Tree::default()
            };
            let (loud, said) = walk_as(&tree(), true, "l", true, true);
            assert_eq!(said.len(), 3, "{said:?}");
            let (quiet, said) = walk_as(&tree(), true, "l", false, true);
            assert!(said.is_empty(), "{said:?}");
            assert_eq!(quiet, loud);
        }

        /// Where names are matched (Windows), the walk is by name, as it
        /// was: nothing is identified, so no entry is `stat`ed for it; an
        /// entry whose `lstat` fails is still an item, and nothing is said;
        /// and there is no device to hold an entry to, so `-x f` is moot.
        #[test]
        fn where_names_are_matched_the_walk_is_by_name() {
            let tree = Tree {
                nodes: vec![
                    ("/v/a", Is::Errno(EACCES), reg(1, 10)),
                    ("/v/r", reg(2, 9), reg(3, 9)),
                    ("/v/l", lnk(1, 3), dir(2, 7)),
                ],
                lists: vec![("/v", Ok(vec!["a", "r", "l"])), ("/v/l", Ok(vec![]))],
                ..Tree::default()
            };
            let (items, said) = walk_as(&tree, true, "l", true, false);
            let names: Vec<&str> = items.iter().map(|(n, _)| n.as_str()).collect();
            assert_eq!(names, ["/v", "/v/a", "/v/r", "/v/l"]);
            assert!(items.iter().all(|(_, id)| id.is_none()), "{items:?}");
            assert!(said.is_empty(), "{said:?}");
            assert_eq!(tree.count("stat", "/v/r"), 0);
            assert_eq!(tree.count("read_dir", "/v/l"), 1);
        }
    }
}
