//! lsof-rs CLI entry point — produces the `lsof` binary.
//!
//! Parses lsof-compatible options, asks the platform [`Backend`] to gather
//! processes and their open files, applies the selection, and renders the
//! chosen format. On Windows it uses the native backend; on other hosts it
//! falls back to the mock backend so the pipeline runs anywhere.
//!
//! `#![forbid(unsafe_code)]`: the CLI only ever calls the backends, never the
//! platform. A bin and a lib in one package are two crates and the attribute
//! does not cross between them, so this is not a duplicate of `lib.rs`'s —
//! drop it and the binary is unconstrained while the library still looks safe.
#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};

use lsof_cli::args::{parse, Action};
use lsof_core::readlink::ReadlinkError;
use lsof_core::render::{fields, json, table, Escaper, Format, TableOpts};
use lsof_core::selection::filesystems_named;
use lsof_core::{
    errno_text, Backend, DirArg, FilesystemArgs, Located, PathItem, Selection, TaskMode, UidSel,
    UserLookup,
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
    format!(
        "lsof-rs {ver} - a memory-safe, Windows-native lsof (list open files)\n\
\n\
USAGE:\n\
    lsof [options]\n\
\n\
SELECTION:\n\
    -p <pids>     select by PID (comma separated; ^pid excludes)\n\
    -u <users>    select by owning user, login name or UID (^ excludes)\n\
    -c <cmd>      select by command name: a prefix (case-insensitive substring\n\
                  on Windows); ^cmd excludes. -c /regex/ is not supported\n\
    -g [pgids]    process groups: the PGID column, and with pgids, selection\n\
                  (^ excludes). On Windows: select children of these PPIDs\n\
    -d <fds>      filter by FD: cwd,rtd,txt,mem,DEL,NOFD,fd (every number),\n\
                  numbers, a-b ranges; all ^excluded or none. Repeats add up\n\
    -i [spec]     Internet sockets; spec = [46][tcp|udp|icmp|raw][@addr][:ports]\n\
                  ports may be a list and ranges (:22,80,1000-2000); each -i\n\
                  is its own item, ORed. Host and service names are not resolved\n\
                  (icmp/raw come from the ETW capture; needs Admin)\n\
    -s [p:s]      TCP and UDP sockets by TCP state: TCP:LISTEN,ESTABLISHED\n\
                  lists only those, TCP:^TIME_WAIT excludes one; each listed\n\
                  state is a search item. A bare -s shows sizes, in a SIZE column\n\
    -U            list UNIX-domain (AF_UNIX) sockets (via ETW; needs Admin)\n\
    -K            list each process's threads as `task` rows (TID in NODE)\n\
    -T [fqsw]     TCP info on socket rows: q=queue, s=state, w=window\n\
                  (q/w need Administrator; IPv4 + IPv6; bare -T = qs)\n\
    -a            AND the selectors together (default is OR); needs one\n\
    <path>        find who has this FILE open, matched by identity (a hard\n\
                  link to it counts); +d <dir> = the dir and its entries,\n\
                  +D <dir> = the whole tree beneath it\n\
                  A MOUNT POINT's absolute path (or the block device it\n\
                  was mounted from, or a link to either) selects every open\n\
                  file on that filesystem; `/mnt/.` or a relative `mnt`\n\
                  names the directory alone.\n\
    -f / +f       never / always read a path argument as a file system;\n\
                  +f also accepts a non-block mount source, and complains\n\
                  if an argument names no mount\n\
\n\
OUTPUT:\n\
    -n            do not resolve host names\n\
    -P            do not resolve port names (show numeric ports)\n\
    -R            add a PPID (parent PID) column\n\
    -o [n]        an OFFSET column (0t<decimal>, 0x<hex> past n digits, default 8);\n\
                  -o <n> alone sets the digit limit and keeps SIZE/OFF\n\
    -t            terse: PIDs only\n\
    -E            pipe endpoint info: append peer server/client PID+command\n\
                  to pipe NAMEs (GetNamedPipe*ProcessId)\n\
    +E            same, and also list the peer processes' own pipe rows\n\
    -l            numeric USER (show SID string instead of resolved name)\n\
    +L [count]    an NLINK (link count) column; with a count, also select the\n\
                  files with fewer links (`+L 1` = unlinked but still open).\n\
                  -L: no NLINK column (the default)\n\
    +f g / +f G   (Linux) a FILE-FLAG column: each file's open flags by name\n\
                  (W,AP,LG), or in hex; -f g hides it again\n\
    -V            verbose: report inaccessible / unmatched search items\n\
    -F [fields]   field (machine-readable) output; 0 = NUL terminators;\n\
                  -F ? lists the field letters\n\
    -J            aggregated JSON object\n\
    -j            JSON Lines (one object per file)\n\
    -r [delay]    repeat every <delay>s (default 15) until interrupted\n\
    +c <n>        cap COMMAND column width at <n> characters\n\
\n\
MISCELLANEOUS:\n\
    -Q            quiet: mute search failures, exit status included\n\
    -w / +w       leave out / report files that cannot be read, and suppress /\n\
                  enable non-fatal stderr warnings (default: report, on)\n\
    -O            no-op (Unix-specific perf hint; accepted for portability)\n\
    --            end of options; remaining args are paths\n\
\n\
    --etw         (Windows, opt-in) short ETW capture against the AFD\n\
                  provider to extend `-i` coverage to socket families\n\
                  IP Helper doesn't enumerate (raw/ICMP/AF_UNIX).\n\
                  Needs Administrator.\n\
    --unicode     emit UTF-8 (switches the Windows console to CP 65001 at\n\
                  startup). Default is plain ASCII output — safer on PS 5.1\n\
                  and legacy cmd.exe whose default console is Windows-1252.\n\
    --ascii       force ASCII output (the default; flag kept for symmetry).\n\
\n\
    -h, -?, --help    show this help\n\
    -v, --version     show version\n\
\n\
Without elevation, lsof-rs shows the processes you can access; run as\n\
Administrator for a system-wide view. Privileges are requested only for the\n\
specific operations that need them.\n",
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
fn spell_path(typed: &str, identified: bool) -> Result<OsString, ReadlinkError> {
    #[cfg(unix)]
    if identified {
        use std::os::unix::ffi::OsStringExt;
        let mut path = lsof_core::readlink::resolve(typed.as_ref())?.into_vec();
        path.truncate(without_trailing_slashes(&path).len());
        return Ok(OsString::from_vec(path));
    }
    let _ = identified;
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

/// One `+d`/`+D` directory and what is in it, entered as the C's
/// `enter_dir()` enters them (`arg.c`): the directory under the name
/// `Readlink()` gave it when the option was checked, then each entry as that
/// name, a `/` unless it ends in one, and the entry's own name, byte for byte.
/// So `+D rel` reports `rel/y`, not `$PWD/rel/y`, `+d rel-link` reports
/// `rel/y` (DIVERGENCES 63), and an entry whose name is not UTF-8 is found by
/// it, where a lossy name had found nothing (DIVERGENCES 65).
fn expand_dir(sel: &mut Selection, dir: &DirArg, backend: &dyn Backend, esc: Escaper) {
    fn enter(sel: &mut Selection, path: &Path, id: Option<(String, String)>) {
        if let Some(id) = &id {
            sel.path_ids.insert(id.clone());
            sel.path_names.insert(path.as_os_str().to_os_string());
        }
        sel.path_items.push(PathItem {
            id,
            fs_device: None,
            name: path.as_os_str().to_os_string(),
        });
    }
    let identified = sel.paths_identified;
    // Where names are matched, a `+D` keeps the long-form name it had.
    let base = if identified || !dir.recursive {
        PathBuf::from(&dir.dir)
    } else {
        let mut p = dir.dir.to_string_lossy().into_owned();
        canonicalize_selector(&mut p);
        PathBuf::from(p)
    };
    let id = backend.identify_path(&base);
    if identified && id.is_none() {
        // Gone since the option was checked.
        return;
    }
    enter(sel, &base, id);
    // The directory's own file system, for the cross-over rule below. `None`
    // on a backend with no such notion, which switches the rule off rather
    // than guessing.
    let dir_fs = backend.path_fs_device(&base);
    let shown = |p: &Path| esc.bytes(p.as_os_str().as_encoded_bytes()).into_owned();
    let mut stack = vec![base];
    let mut budget = 200_000usize; // a tree walk is not a licence to hang
    while let Some(dn) = stack.pop() {
        let entries = match std::fs::read_dir(&dn) {
            Ok(entries) => entries,
            Err(e) => {
                if dir.warn && e.kind() != std::io::ErrorKind::NotFound {
                    eprintln!(
                        "lsof: WARNING: can't opendir({}): {}",
                        shown(&dn),
                        errno_text(&e)
                    );
                }
                continue;
            }
        };
        for e in entries.flatten() {
            if budget == 0 {
                return;
            }
            budget -= 1;
            // `dn`, a `/` unless it ends in one, and the entry's name: the C's
            // spelling, and `DirEntry::path()`'s.
            let path = e.path();
            // The entry is `lstat`ed first; then the two cross-over rules, in
            // the C's order (`arg.c`):
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
            // (DIVERGENCES 75).
            let dev = backend.path_fs_device(&path);
            if identified && dev.is_none() {
                // `lstat` failed: gone, or not ours to see.
                if dir.warn {
                    if let Err(err) = std::fs::symlink_metadata(&path) {
                        if err.kind() != std::io::ErrorKind::NotFound {
                            eprintln!(
                                "lsof: WARNING: can't lstat({}): {}",
                                shown(&path),
                                errno_text(&err)
                            );
                        }
                    }
                }
                continue;
            }
            if !dir.cross_filesystems {
                if let (Some(d), Some(e_dev)) = (dir_fs, dev) {
                    if d != e_dev {
                        continue;
                    }
                }
            }
            let Ok(kind) = e.file_type() else {
                continue;
            };
            let is_dir = if kind.is_symlink() {
                if !dir.cross_symlinks {
                    continue;
                }
                match std::fs::metadata(&path) {
                    Ok(m) => m.is_dir(),
                    Err(err) => {
                        // The C's words, its spelling included.
                        if dir.warn && err.kind() != std::io::ErrorKind::NotFound {
                            eprintln!(
                                "lsof: WARNING: can't stat({}) symbolc link: {}",
                                shown(&path),
                                errno_text(&err)
                            );
                        }
                        continue;
                    }
                }
            } else {
                kind.is_dir()
            };
            let id = backend.identify_path(&path);
            if identified && id.is_none() {
                continue;
            }
            if dir.recursive && is_dir {
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
    for (item, &hit) in sel.path_items.iter().zip(&located.paths) {
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

    let action = match parse(argv) {
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
            println!(
                "lsof-rs {} (memory-safe lsof for Windows)",
                env!("CARGO_PKG_VERSION")
            );
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
        let mounts = match sel.filesystem_args {
            FilesystemArgs::NeverFilesystem => Vec::new(),
            _ => env.backend.mounts(),
        };
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
        // accepted), so the comparison is made on a normalised form.
        for e in &sel.exempt_fs {
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
        let identified = sel.paths_identified;
        let mut survived = 0usize;
        for typed in sel.paths.clone() {
            let path = match spell_path(&typed, identified) {
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
            match env.backend.identify_path(Path::new(&path)) {
                Some(id) => {
                    sel.path_ids.insert(id.clone());
                    sel.path_names.insert(typed.as_str().into());
                    sel.path_items.push(PathItem {
                        id: Some(id),
                        fs_device: None,
                        name,
                    });
                    survived += 1;
                }
                None => {
                    // Named as the C names it, by its `Readlink()`: a link
                    // to `/nonexistent/f` is `status error on
                    // /nonexistent/f`, and a `/proc/PID/fd/N` pipe is `status
                    // error on /proc/PID/fd/pipe:[N]`.
                    if !sel.quiet {
                        let why = std::fs::metadata(&path)
                            .err()
                            .map(|e| errno_text(&e))
                            .unwrap_or_else(|| "status error".to_string());
                        eprintln!(
                            "lsof: status error on {}: {why}",
                            esc.bytes(path.as_encoded_bytes())
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
        for dir in sel.dir_args.clone() {
            expand_dir(&mut sel, &dir, env.backend.as_ref(), esc);
        }
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
        let misses = unlocated(&selection, &located, esc);
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
        let written = written.and_then(|()| {
            if selection.verbose && !selection.quiet {
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
    /// located` for one that named a file system (DIVERGENCES 60).
    #[test]
    fn an_unlocated_path_is_reported_as_typed() {
        use lsof_core::render::Escaper;
        use lsof_core::{Located, PathItem, Selection};
        let sel = Selection {
            path_items: vec![
                PathItem {
                    id: Some(("254,0".into(), "11".into())),
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
                "lsof: no file use located: ./x",
                "lsof: no file system use located: mnt"
            ]
        );
        assert_eq!(
            lines(vec![true, false]),
            ["lsof: no file system use located: mnt"]
        );
        assert!(lines(vec![true, true]).is_empty());
    }
}
