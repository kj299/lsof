//! winlsof CLI entry point — produces the `lsof` binary.
//!
//! Parses lsof-compatible options, asks the platform [`Backend`] to gather
//! processes and their open files, applies the selection, and renders the
//! chosen format. On Windows it uses the native backend; on other hosts it
//! falls back to the mock backend so the pipeline runs anywhere.

mod args;

use args::{parse, Action};
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

fn usage() -> String {
    format!(
        "winlsof {ver} — a memory-safe, Windows-native lsof (list open files)\n\
\n\
USAGE:\n\
    lsof [options]\n\
\n\
SELECTION:\n\
    -p <pids>     select by PID (comma/space separated)\n\
    -u <users>    select by owning user (comma separated)\n\
    -c <cmd>      select by command/image name (prefix/substring)\n\
    -d <fds>      filter by FD: cwd,rtd,txt,mem, numbers, a-b ranges, ^exclude\n\
    -i [spec]     only Internet sockets; spec = [46][tcp|udp][@host][:port]\n\
    -a            AND the selectors together (default is OR)\n\
    <path>        exact-file lookup; +D/+d <dir> = directory-tree lookup\n\
\n\
OUTPUT:\n\
    -n            do not resolve host names\n\
    -P            do not resolve port names (show numeric ports)\n\
    -R            add a PPID (parent PID) column\n\
    -o            show file offset in SIZE/OFF (0t<decimal>)\n\
    -t            terse: PIDs only\n\
    -V            verbose: report inaccessible / unmatched search items\n\
    -F[fields]    field (machine-readable) output; -F0 uses NUL terminators\n\
    -J            aggregated JSON object\n\
    -j            JSON Lines (one object per file)\n\
    -r [delay]    repeat every <delay>s (default 15) until interrupted\n\
\n\
    -h, --help        show this help\n\
    -v, --version     show version\n\
\n\
Without elevation, winlsof shows the processes you can access; run as\n\
Administrator for a system-wide view. Privileges are requested only for the\n\
specific operations that need them.\n",
        ver = env!("CARGO_PKG_VERSION")
    )
}

/// `-V`: report `-p` PIDs and path/dir search items that matched nothing.
fn report_unmatched(sel: &Selection, procs: &[Process]) {
    for &pid in &sel.pids {
        if !procs.iter().any(|p| p.pid == pid) {
            eprintln!("lsof: PID {pid}: no matching open files");
        }
    }
    for path in sel.paths.iter().chain(sel.dir_trees.iter()) {
        let needle = path.to_ascii_lowercase();
        let hit = procs.iter().flat_map(|p| &p.files).any(|f| {
            let n = f.name.to_ascii_lowercase();
            n == needle || n.starts_with(&needle)
        });
        if !hit {
            eprintln!("lsof: {path}: no process found with it open");
        }
    }
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();

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

    let env = make_env();
    let _ = env.elevated; // read on all platforms; used for the hint on Windows.
    if let Some(note) = &env.note {
        eprintln!("lsof: {note}");
    }

    // Least-privilege hint: only in table mode (machine formats stay clean) and
    // only when the run will attempt system-wide handle enumeration — not for
    // `-i` network queries or path lookups, which need no elevation.
    #[cfg(windows)]
    if !env.elevated
        && matches!(format, Format::Table)
        && !selection.inet.enabled
        && !selection.has_path_filter()
    {
        eprintln!(
            "lsof: showing your accessible processes; re-run as Administrator for a system-wide view"
        );
    }

    let run_cycle = move || {
        let procs = match env.backend.gather(&selection) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("lsof: {e}");
                std::process::exit(1);
            }
        };
        let procs = selection.apply(procs);
        if selection.verbose {
            report_unmatched(&selection, &procs);
        }
        let out = match &format {
            Format::Table => table::render(&procs, selection.terse, show_ppid, show_offset),
            Format::Fields { nul, only } => fields::render(&procs, *nul, only.as_deref()),
            Format::Json => {
                let mut s = json::render_aggregated(&procs);
                s.push('\n');
                s
            }
            Format::JsonLines => json::render_lines(&procs),
        };
        print!("{out}");
    };

    // `-r`: repeat until interrupted, printing lsof's `=======` separator.
    match repeat {
        Some(delay) => loop {
            run_cycle();
            println!("=======");
            std::thread::sleep(std::time::Duration::from_secs(delay));
        },
        None => run_cycle(),
    }
}
