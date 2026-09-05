//! The lock character lsof appends to the FD cell, from `/proc/locks`.
//!
//! `lsof` shows `8uW` for an fd holding a whole-file write lock — the column
//! that answers "who is holding this file locked". The C reads the same
//! kernel table (`lib/dialects/linux/dnode.c:get_locks`).
//!
//! A line is
//! `1: POSIX  ADVISORY  WRITE 489 fe:00:1884163 0 EOF`, whose fields, after
//! treating `:` as a separator like the C's `get_fields(…, ":", …)` does, are
//! id, kind (`POSIX`/`FLOCK`/`OFDLCK`), advisory-or-mandatory, `READ`/`WRITE`,
//! pid, device major and minor in **hex**, inode in decimal, and the byte
//! range. A lock covering `0` to `EOF` is the whole file, which is what
//! separates `W` from `w` and `R` from `r`.
//!
//! The table is global — one file for the whole system, with a pid column — so
//! it is read once per gather rather than per process.

use std::collections::HashMap;

use lsof_core::model::LockKind;

/// Locks indexed by the three things that identify the locked file from a
/// row's point of view: `(pid, device, inode)`, with device and inode rendered
/// the way the rest of the backend renders them (`254,0` and a decimal inode)
/// so the lookup is a plain string compare against a built row.
pub type LockTable = HashMap<(u32, String, String), LockKind>;

/// Parse `/proc/locks`.
///
/// Pure, so the fuzz target can drive it with arbitrary bytes; it must never
/// panic. Anything unparseable is skipped rather than guessed — a wrong lock
/// character is worse than no lock character.
pub fn parse_locks(text: &str) -> LockTable {
    let mut out = HashMap::new();
    for line in text.lines() {
        // The C splits on `:` as well as whitespace, which is what turns
        // `fe:00:1884163` into three fields.
        let f: Vec<&str> = line
            .split(|c: char| c == ':' || c.is_whitespace())
            .filter(|s| !s.is_empty())
            .collect();
        if f.len() < 10 {
            continue;
        }
        // `1: -> POSIX ...` is a *blocked* waiter, not a held lock.
        if f[1] == "->" {
            continue;
        }
        let write = match f[3].as_bytes().first() {
            Some(b'W') => true,
            Some(b'R') => false,
            _ => continue, // e.g. UNLCK
        };
        // An OFD lock reports pid -1: it belongs to the open file description,
        // not to a process, so there is no row to attach it to.
        let Ok(pid) = f[4].parse::<u32>() else {
            continue;
        };
        let (Ok(maj), Ok(min)) = (u32::from_str_radix(f[5], 16), u32::from_str_radix(f[6], 16))
        else {
            continue;
        };
        // The inode is the lookup key, so it is stored re-rendered from the
        // parsed number rather than as the text that was read. Rust's integer
        // parser accepts a leading `+`, so `+0` would otherwise be keyed as
        // "+0" and never match a row whose node is "0" — a lock silently
        // missed where the C, which keys on the number, finds it. The
        // `proc_locks` fuzz target found exactly that.
        let Ok(inode) = f[7].parse::<u64>() else {
            continue;
        };
        let Ok(start) = f[8].parse::<u64>() else {
            continue;
        };
        // `EOF` is how the kernel writes "to the end of the file".
        let whole_file = start == 0 && f[9] == "EOF";
        out.insert(
            (pid, format!("{maj},{min}"), inode.to_string()),
            LockKind::new(write, whole_file),
        );
    }
    out
}

/// Read the system lock table, or an empty one if `/proc/locks` is unreadable.
pub fn load() -> LockTable {
    std::fs::read_to_string("/proc/locks")
        .map(|t| parse_locks(&t))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Byte-exact lines from a live /proc/locks: a whole-file read lock, a
    // partial write lock (bytes 5..14), a whole-file write lock, and a blocked
    // waiter queued behind one of them.
    const SAMPLE: &str = "\
1: POSIX  ADVISORY  READ 3808 fe:00:1892433 0 EOF
2: POSIX  ADVISORY  WRITE 3808 fe:00:1892432 5 14
3: FLOCK  ADVISORY  WRITE 3808 fe:00:1892421 0 EOF
3: -> FLOCK  ADVISORY  WRITE 9999 fe:00:1892421 0 EOF
4: OFDLCK ADVISORY  READ -1 fe:00:1892440 0 EOF
";

    fn kind(t: &LockTable, pid: u32, ino: &str) -> Option<LockKind> {
        t.get(&(pid, "254,0".to_string(), ino.to_string())).copied()
    }

    #[test]
    fn whole_file_and_partial_locks_get_different_characters() {
        let t = parse_locks(SAMPLE);
        assert_eq!(kind(&t, 3808, "1892433"), Some(LockKind::ReadFull));
        assert_eq!(kind(&t, 3808, "1892432"), Some(LockKind::WritePartial));
        assert_eq!(kind(&t, 3808, "1892421"), Some(LockKind::WriteFull));
        assert_eq!(LockKind::ReadFull.code(), 'R');
        assert_eq!(LockKind::WritePartial.code(), 'w');
    }

    #[test]
    fn a_blocked_waiter_is_not_a_held_lock() {
        // The `-> ` line is a process *waiting* for lock 3. Counting it would
        // put a W on an fd that does not hold anything.
        let t = parse_locks(SAMPLE);
        assert_eq!(kind(&t, 9999, "1892421"), None);
    }

    #[test]
    fn an_ofd_lock_has_no_owning_process() {
        // pid -1: the lock belongs to the open file description, so there is no
        // process row to attach it to.
        let t = parse_locks(SAMPLE);
        assert!(t.keys().all(|(pid, _, _)| *pid != 0));
        assert_eq!(t.len(), 3, "the OFD line and the waiter are both skipped");
    }

    #[test]
    fn the_device_is_hex_in_the_file_and_decimal_in_the_key() {
        // fe:00 is hex; every other row in the backend renders 254,0.
        let t = parse_locks("1: POSIX ADVISORY WRITE 5 ff:1f:7 0 EOF\n");
        assert_eq!(
            t.get(&(5, "255,31".to_string(), "7".to_string())),
            Some(&LockKind::WriteFull)
        );
    }

    #[test]
    fn the_inode_key_is_canonical_however_it_was_spelled() {
        // Found by the proc_locks fuzz target: Rust's integer parser accepts a
        // leading `+`, so keying on the raw text would store "+0" and never
        // match a row whose node is "0". The C keys on the number.
        let t = parse_locks("1: POSIX ADVISORY WRITE 5 fe:00:+7 0 EOF\n");
        assert_eq!(
            t.get(&(5, "254,0".to_string(), "7".to_string())),
            Some(&LockKind::WriteFull),
            "the key must be the number, not the spelling"
        );
    }

    #[test]
    fn arbitrary_text_never_panics_and_guesses_nothing() {
        for s in [
            "",
            "\n\n",
            "1:",
            "garbage garbage",
            "1: POSIX ADVISORY WRITE notapid fe:00:7 0 EOF",
            "1: POSIX ADVISORY WRITE 5 zz:zz:7 0 EOF",
            "1: POSIX ADVISORY WRITE 5 fe:00:notanum 0 EOF",
            "1: POSIX ADVISORY UNLCK 5 fe:00:7 0 EOF",
            "1: POSIX ADVISORY WRITE 5 fe:00:7 notanum EOF",
            "\u{FFFD}: \u{FFFD} \u{FFFD} \u{FFFD} \u{FFFD} \u{FFFD}:\u{FFFD}:\u{FFFD} 0 EOF",
        ] {
            assert!(parse_locks(s).is_empty(), "guessed a lock from {s:?}");
        }
    }
}
