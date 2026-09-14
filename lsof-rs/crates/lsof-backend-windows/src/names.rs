//! The Windows backend's **text-parsing surface**, in portable safe Rust.
//!
//! Every function here turns a string the OS handed us into something a row
//! shows: an NT device path into a drive letter, a `\\?\` final path into a
//! clean one, a kernel object type name into an lsof TYPE code, a UTF-16
//! buffer into a `String`. None of it calls Win32 — the Win32 calls live in
//! [`crate::handles`] and friends and pass their results through here.
//!
//! # Why this module is not `#[cfg(windows)]`
//!
//! Because the kit's fuzz gate applies **per backend crate**, and "input"
//! includes text the OS hands you (porting-kit LESSONS #21). That rule had
//! never reached this crate: all nine fuzz targets cover the Linux backend,
//! the CLI and the core, while `check_ledgers.py` counted nine and reported
//! `present`. The parsers below are the crate's share of that gate, and they
//! can only be fuzzed on the Linux runner that hosts `cargo fuzz` if they
//! compile there — which they do, because none of them needs Windows.
//!
//! Moving them out of `handles.rs` also means their unit tests now run on
//! **every** platform rather than only on the Windows CI job.

use lsof_core::model::FileType;

/// `\Device\HarddiskVolume3\Users\me\f.txt` → `C:\Users\me\f.txt`.
///
/// The match must end on a path boundary: `\Device\HarddiskVolume3` must not
/// swallow `\Device\HarddiskVolume33`, which is a different volume.
pub fn device_to_dos(nt_name: &str, dos_map: &[(String, String)]) -> String {
    for (dos, dev) in dos_map {
        if let Some(rest) = nt_name.strip_prefix(dev.as_str()) {
            if rest.is_empty() || rest.starts_with('\\') {
                return format!("{dos}{rest}");
            }
        }
    }
    nt_name.to_string()
}

/// The `C:` of a DOS path, when it has one.
pub fn drive_of(path: &str) -> Option<String> {
    if path.len() >= 2 && path.as_bytes()[1] == b':' {
        Some(path[..2].to_string())
    } else {
        None
    }
}

/// Strip the `\\?\` / `\\?\UNC\` prefixes from a final-path string.
pub fn normalize_final(s: &str) -> String {
    if let Some(rest) = s.strip_prefix("\\\\?\\UNC\\") {
        format!("\\\\{rest}")
    } else if let Some(rest) = s.strip_prefix("\\\\?\\") {
        rest.to_string()
    } else {
        s.to_string()
    }
}

/// `\Device\NamedPipe\foo` → `\\.\pipe\foo`.
pub fn pipe_display(nt_name: &str) -> String {
    match nt_name.strip_prefix("\\Device\\NamedPipe") {
        Some(rest) => format!("\\\\.\\pipe{rest}"),
        None => nt_name.to_string(),
    }
}

/// A kernel object type name → the TYPE code lsof prints.
pub fn win_type_to_filetype(type_name: &str) -> FileType {
    match type_name {
        "Key" => FileType::Key,
        "Event" => FileType::Event,
        "Mutant" => FileType::Mutant,
        "Section" => FileType::Section,
        "Process" => FileType::Process,
        "Thread" => FileType::Thread,
        "Token" => FileType::Token,
        "Semaphore" => FileType::Other("SEM".into()),
        "Timer" | "IRTimer" => FileType::Other("TMR".into()),
        "Job" => FileType::Other("JOB".into()),
        "IoCompletion" => FileType::Other("IOCP".into()),
        "TpWorkerFactory" => FileType::Other("TPWF".into()),
        "ALPC Port" => FileType::Other("ALPC".into()),
        "Directory" => FileType::Other("ODIR".into()),
        "SymbolicLink" => FileType::Other("LINK".into()),
        "Desktop" => FileType::Other("DESK".into()),
        "WindowStation" => FileType::Other("WSTA".into()),
        "KeyedEvent" => FileType::Other("KEVT".into()),
        "WmiGuid" => FileType::Other("WMI".into()),
        "EtwRegistration" => FileType::Other("ETW".into()),
        other => FileType::Other(short_type_code(other)),
    }
}

/// A short, upper-case TYPE code for an object type without a dedicated
/// mapping (e.g. "Partition" -> "PARTITIO").
///
/// The contract the table renderer depends on: never empty, never longer than
/// eight characters, ASCII-alphanumeric throughout — so it cannot widen a
/// column without bound or smuggle whitespace into a whitespace-split row.
pub fn short_type_code(name: &str) -> String {
    let code: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .take(8)
        .collect();
    if code.is_empty() {
        "OBJ".to_string()
    } else {
        code
    }
}

/// A NUL-terminated UTF-16 buffer from a Win32 `…W` call → a `String`.
///
/// Every wide string in this backend arrives this way. Unpaired surrogates are
/// replaced rather than rejected: a path lsof cannot render perfectly is still
/// worth showing, and the alternative is dropping the row.
pub fn wide_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map() -> Vec<(String, String)> {
        vec![
            ("C:".to_string(), "\\Device\\HarddiskVolume3".to_string()),
            ("D:".to_string(), "\\Device\\HarddiskVolume33".to_string()),
        ]
    }

    #[test]
    fn maps_device_path_to_drive() {
        assert_eq!(
            device_to_dos("\\Device\\HarddiskVolume3\\Users\\me\\f.txt", &map()),
            "C:\\Users\\me\\f.txt"
        );
    }

    #[test]
    fn respects_path_boundary() {
        // Volume3 must not swallow the longer Volume33.
        assert_eq!(
            device_to_dos("\\Device\\HarddiskVolume33\\x", &map()),
            "D:\\x"
        );
    }

    #[test]
    fn unmapped_device_passes_through() {
        let s = "\\Device\\NamedPipe\\foo";
        assert_eq!(device_to_dos(s, &map()), s);
    }

    #[test]
    fn normalizes_final_paths() {
        assert_eq!(normalize_final("\\\\?\\C:\\a\\b.txt"), "C:\\a\\b.txt");
        assert_eq!(
            normalize_final("\\\\?\\UNC\\srv\\share\\f"),
            "\\\\srv\\share\\f"
        );
        assert_eq!(normalize_final("C:\\plain"), "C:\\plain");
    }

    #[test]
    fn pipe_display_names() {
        assert_eq!(pipe_display("\\Device\\NamedPipe\\foo"), "\\\\.\\pipe\\foo");
    }

    #[test]
    fn drive_prefix() {
        assert_eq!(drive_of("C:\\x"), Some("C:".to_string()));
        assert_eq!(drive_of("\\\\srv\\share"), None);
    }

    #[test]
    fn maps_windows_type_names_to_lsof_codes() {
        // The classification table the all-handle scan drives. Named variants
        // and the `Other` long tail both have to produce a TYPE code.
        for (name, code) in [
            ("Key", "KEY"),
            ("Event", "EVT"),
            ("Mutant", "MUT"),
            ("Section", "SECT"),
            ("Process", "PROC"),
            ("Thread", "THRD"),
            ("Token", "TOKN"),
            ("Semaphore", "SEM"),
            ("Job", "JOB"),
            ("IoCompletion", "IOCP"),
            ("ALPC Port", "ALPC"),
        ] {
            assert_eq!(win_type_to_filetype(name).code(), code, "type {name}");
        }
        assert_eq!(win_type_to_filetype("Partition").code(), "PARTITIO");
        assert_eq!(win_type_to_filetype("").code(), "OBJ");
    }

    #[test]
    fn wide_strings_stop_at_the_nul() {
        assert_eq!(wide_to_string(&[0x43, 0x3a, 0x00, 0x58]), "C:");
        assert_eq!(wide_to_string(&[]), "");
        // No terminator: the whole buffer is the string.
        assert_eq!(wide_to_string(&[0x61, 0x62]), "ab");
    }
}
