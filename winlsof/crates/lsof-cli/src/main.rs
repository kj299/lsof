//! winlsof CLI entry point — produces the `lsof` binary.
//!
//! Parses lsof-compatible options, asks the platform [`Backend`] to gather
//! processes and their open files, applies the selection, and renders the
//! chosen format. On Windows it uses the native backend; on other hosts it
//! falls back to the mock backend so the pipeline runs anywhere.

use std::collections::HashSet;

use lsof_cli::args::{parse, Action};
use lsof_core::render::{fields, json, table, Format};
use lsof_core::{Backend, Process, Selection};

#[cfg(windows)]
use lsof_backend_windows::WindowsBackend;
#[cfg(not(windows))]
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

#[cfg(not(windows))]
fn make_env() -> Env {
    Env {
        backend: Box::new(MockBackend),
        elevated: false,
        note: Some("non-Windows build: showing sample (mock) data".to_string()),
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
        "winlsof {ver} - a memory-safe, Windows-native lsof (list open files)\n\
\n\
USAGE:\n\
    lsof [options]\n\
\n\
SELECTION:\n\
    -p <pids>     select by PID (comma/space separated)\n\
    -u <users>    select by owning user (comma separated)\n\
    -c <cmd>      select by command/image name (prefix/substring)\n\
    -g <ppids>    select children of these PPIDs (Windows extension of -g)\n\
    -d <fds>      filter by FD: cwd,rtd,txt,mem, numbers, a-b ranges, ^exclude\n\
    -i [spec]     only Internet sockets; spec = [46][tcp|udp|icmp|raw][@host][:port]\n\
                  (icmp/raw come from the ETW capture; needs Admin)\n\
    -s [p:s]      filter sockets by protocol+state, e.g. TCP:LISTEN\n\
                  (comma-separated, `^` prefix excludes)\n\
    -U            list UNIX-domain (AF_UNIX) sockets (via ETW; needs Admin)\n\
    -K            list each process's threads as `task` rows (TID in NODE)\n\
    -T [fqsw]     TCP info on socket rows: q=queue, s=state, w=window\n\
                  (q/w need Administrator; IPv4 + IPv6; bare -T = qs)\n\
    -a            AND the selectors together (default is OR)\n\
    <path>        exact-file lookup; +D/+d <dir> = directory-tree lookup\n\
\n\
OUTPUT:\n\
    -n            do not resolve host names\n\
    -P            do not resolve port names (show numeric ports)\n\
    -R            add a PPID (parent PID) column\n\
    -o            show file offset in SIZE/OFF (0t<decimal>)\n\
    -t            terse: PIDs only\n\
    -E            pipe endpoint info: append peer server/client PID+command\n\
                  to pipe NAMEs (GetNamedPipe*ProcessId)\n\
    +E            same, and also list the peer processes' own pipe rows\n\
    -l            numeric USER (show SID string instead of resolved name)\n\
    -L            show NLINK (link count) column\n\
    +L <count>    keep only files with link count < <count>; implies -L\n\
                  (`+L 1` = unlinked-but-still-open files; security check)\n\
    -V            verbose: report inaccessible / unmatched search items\n\
    -F[fields]    field (machine-readable) output; -F0 uses NUL terminators\n\
    -J            aggregated JSON object\n\
    -j            JSON Lines (one object per file)\n\
    -r [delay]    repeat every <delay>s (default 15) until interrupted\n\
    +c <n>        cap COMMAND column width at <n> characters\n\
\n\
MISCELLANEOUS:\n\
    -Q            quiet: suppress 'no matching open files' on empty result\n\
    -w / +w       suppress / enable non-fatal stderr warnings (default on)\n\
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
Without elevation, winlsof shows the processes you can access; run as\n\
Administrator for a system-wide view. Privileges are requested only for the\n\
specific operations that need them.\n",
        ver = env!("CARGO_PKG_VERSION")
    )
}

/// Resolve a user-typed path selector (`+d`/`+D` directory, bare path) to its
/// canonical long form so the literal prefix/equality match in the selection
/// engine sees the same spelling the backend reports. This is what bridges 8.3
/// short names (`C:\Users\RUNNER~1\...` — the default %TEMP% on hosted Windows
/// CI), relative paths, and symlinked directories. `std::fs::canonicalize`
/// returns Windows paths in verbatim form (`\\?\C:\...`, `\\?\UNC\srv\...`);
/// strip that the same way the backend's `normalize_final` does, so both sides
/// of the comparison use one spelling. A path that can't be resolved (it
/// doesn't exist) is left as typed — the unmatched-item reporting owns that.
fn canonicalize_selector(p: &mut String) {
    let Ok(resolved) = std::fs::canonicalize(&*p) else {
        return;
    };
    *p = strip_verbatim(&resolved.to_string_lossy());
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

/// Report `-p` PIDs and path/dir search items that could not be located, and
/// return how many. `-p` PIDs are checked against the *located* set (the PIDs
/// the backend gathered, before selection filtering): a PID that exists but is
/// filtered out by e.g. `-a` was still located, so it is not "unmatched". Paths
/// are checked against the selected result. The message is printed only under
/// `-V` (and never under `-Q`), as before — but the count is returned
/// regardless, because lsof exits 1 on an unlocated search item even when it
/// prints nothing (so `lsof -t <file> && ...` and `if lsof ...; then` work).
fn report_unmatched(sel: &Selection, located: &HashSet<u32>, procs: &[Process]) -> usize {
    let print = sel.verbose && !sel.quiet;
    let mut unmatched = 0usize;
    for &pid in &sel.pids {
        if !located.contains(&pid) {
            unmatched += 1;
            if print {
                eprintln!("lsof: PID {pid}: no matching open files");
            }
        }
    }
    for path in sel.paths.iter().chain(sel.dir_trees.iter()) {
        let needle = path.to_ascii_lowercase();
        let hit = procs.iter().flat_map(|p| &p.files).any(|f| {
            let n = f.name.to_ascii_lowercase();
            n == needle || n.starts_with(&needle)
        });
        if !hit {
            unmatched += 1;
            if print {
                eprintln!("lsof: {path}: no process found with it open");
            }
        }
    }
    unmatched
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();

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
            eprintln!("lsof: {e}");
            eprintln!("Try 'lsof -h' for usage.");
            std::process::exit(1);
        }
    };

    let (selection, format, repeat, show_ppid, show_offset) = match action {
        Action::Help => {
            print!("{}", usage());
            return;
        }
        Action::Version => {
            println!(
                "winlsof {} (memory-safe lsof for Windows)",
                env!("CARGO_PKG_VERSION")
            );
            return;
        }
        Action::Run {
            selection,
            format,
            repeat,
            show_ppid,
            show_offset,
        } => (selection, format, repeat, show_ppid, show_offset),
    };
    let selection = {
        let mut sel = selection;
        // Path selectors are literal prefix/equality matches against the
        // long-form names the backend reports, so resolve what the user typed
        // first — otherwise an 8.3 short name (`C:\Users\RUNNER~1\...`, the
        // hosted-CI %TEMP%), a relative path, or a symlink silently matches
        // nothing. A path that doesn't resolve is kept as typed; the
        // unmatched-item reporting handles it.
        for p in sel.paths.iter_mut().chain(sel.dir_trees.iter_mut()) {
            canonicalize_selector(p);
        }
        sel
    };

    let env = make_env();
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

    let run_cycle = move || -> usize {
        let gathered = match env.backend.gather(&selection) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("lsof: {e}");
                std::process::exit(1);
            }
        };
        // PIDs the backend actually located, captured before selection filtering
        // so a PID dropped by e.g. `-a` isn't misreported as "not found".
        let located: HashSet<u32> = gathered.iter().map(|p| p.pid).collect();
        let procs = selection.apply(gathered);
        let unmatched = report_unmatched(&selection, &located, &procs);
        let out = match &format {
            Format::Table => table::render(
                &procs,
                selection.terse,
                show_ppid,
                show_offset,
                selection.command_width,
                selection.show_links,
            ),
            Format::Fields { nul, only } => fields::render(&procs, *nul, only.as_deref()),
            Format::Json => {
                let mut s = json::render_aggregated(&procs);
                s.push('\n');
                s
            }
            Format::JsonLines => json::render_lines(&procs),
        };
        print!("{out}");
        unmatched
    };

    // `-r`: repeat until interrupted, printing the format-aware cycle marker.
    // Exit promptly after the final cycle: handle enumeration may have abandoned
    // a worker thread blocked uninterruptibly in `NtQueryObject` (a synchronous
    // pipe/device), which can otherwise stall normal process teardown. lsof's
    // exit status is 1 when a specified `-p`/path search item was not located.
    match repeat {
        Some(delay) => loop {
            use std::io::Write;
            run_cycle();
            print!("{repeat_marker}");
            // lsof flushes each cycle so a piped consumer sees output promptly.
            let _ = std::io::stdout().flush();
            std::thread::sleep(std::time::Duration::from_secs(delay));
        },
        None => {
            let code = if run_cycle() > 0 { 1 } else { 0 };
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
        let (sel, fmt) = parsed(&["+D", "C:\\temp"]);
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
        let dir = std::env::temp_dir().join("winlsof_canon_test");
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
}
