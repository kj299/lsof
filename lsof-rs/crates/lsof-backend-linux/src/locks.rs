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

/// Locks indexed by the three things that identify the locked file:
/// `(pid, device, inode)`, the device a `dev_t` packed as `makedev()` packs
/// it, which is what a row's `stat` (`st_dev`) and a maps line give too. The
/// key is the file's own device and never the one a device node names: a
/// lock on `/dev/null` is held on a devtmpfs inode, and keying on the DEVICE
/// cell (`1,3`) missed it. Numbers, so a lookup allocates nothing.
pub type LockTable = HashMap<(u32, u64, u64), LockKind>;

/// Parse `/proc/locks`.
///
/// Pure, so the fuzz target can drive it with arbitrary bytes; it must never
/// panic. Anything unparseable is skipped rather than guessed — a wrong lock
/// character is worse than no lock character.
///
/// One file can hold several of a process's locks — byte ranges of
/// different kinds, as SQLite takes them — and one character is shown. The
/// C chains each lock onto its hash bucket's head unless the same kind is
/// already there for that file (`get_locks()`), and `check_lock()` takes the
/// first it meets: the latest kind *new to that file*. The kernel lists each
/// CPU's locks newest first, so `w` at 0, `r` at 10, `w` at 20, taken on one
/// CPU, read back `w` 20, `r` 10, `w` 0 and show `r` — measured, `3ur` from
/// the C where taking the last line showed `3uw`.
pub fn parse_locks(text: &str) -> LockTable {
    let mut out = HashMap::new();
    // The kinds each file has had so far, one bit apiece.
    let mut seen: HashMap<(u32, u64, u64), u8> = HashMap::new();
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
        // The inode is keyed as the number, as the C keys it. (When the key
        // was text, Rust's parser accepting a leading `+` made `+0` a key no
        // row's "0" could match — the `proc_locks` fuzz target found that.)
        let Ok(inode) = f[7].parse::<u64>() else {
            continue;
        };
        let Ok(start) = f[8].parse::<u64>() else {
            continue;
        };
        // `EOF` is how the kernel writes "to the end of the file".
        let whole_file = start == 0 && f[9] == "EOF";
        let key = (pid, crate::files::makedev(maj, min), inode);
        let kind = LockKind::new(write, whole_file);
        let bit = match kind {
            LockKind::ReadPartial => 1,
            LockKind::ReadFull => 2,
            LockKind::WritePartial => 4,
            LockKind::WriteFull => 8,
        };
        let had = seen.entry(key).or_insert(0);
        if *had & bit == 0 {
            *had |= bit;
            out.insert(key, kind);
        }
    }
    out
}

/// Read the system lock table, or an empty one if `/proc/locks` is unreadable.
pub fn load() -> LockTable {
    crate::text::read_lossy("/proc/locks")
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

    /// `fe:00`, the device every SAMPLE line names.
    const FE00: u64 = 0xfe00;

    fn kind(t: &LockTable, pid: u32, ino: u64) -> Option<LockKind> {
        t.get(&(pid, FE00, ino)).copied()
    }

    #[test]
    fn whole_file_and_partial_locks_get_different_characters() {
        let t = parse_locks(SAMPLE);
        assert_eq!(kind(&t, 3808, 1892433), Some(LockKind::ReadFull));
        assert_eq!(kind(&t, 3808, 1892432), Some(LockKind::WritePartial));
        assert_eq!(kind(&t, 3808, 1892421), Some(LockKind::WriteFull));
        assert_eq!(LockKind::ReadFull.code(), 'R');
        assert_eq!(LockKind::WritePartial.code(), 'w');
    }

    #[test]
    fn a_blocked_waiter_is_not_a_held_lock() {
        // The `-> ` line is a process *waiting* for lock 3. Counting it would
        // put a W on an fd that does not hold anything.
        let t = parse_locks(SAMPLE);
        assert_eq!(kind(&t, 9999, 1892421), None);
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
    fn the_device_is_hex_in_the_file_and_a_dev_t_in_the_key() {
        // ff:1f is hex, and keyed as `makedev(255, 31)`, the `st_dev` a row
        // of a file on that device has.
        let t = parse_locks("1: POSIX ADVISORY WRITE 5 ff:1f:7 0 EOF\n");
        assert_eq!(t.get(&(5, 0xff1f, 7)), Some(&LockKind::WriteFull));
        // A minor past 255 is where `major << 8 | minor` and `makedev()`
        // part: 0,301 is 0x10002d.
        let t = parse_locks("1: POSIX ADVISORY WRITE 5 00:12d:7 0 EOF\n");
        assert_eq!(t.get(&(5, 0x10_002d, 7)), Some(&LockKind::WriteFull));
    }

    #[test]
    fn the_latest_kind_new_to_a_file_is_the_one_shown() {
        // Measured: the kernel lists the newest lock first, and for these
        // three the C prints `3ur` — the read lock, the latest kind it had
        // not yet chained. Taking the last line said `w`.
        let t = parse_locks(
            "2: POSIX  ADVISORY  WRITE 2287 fe:00:1900990 20 21\n\
             3: POSIX  ADVISORY  READ 2287 fe:00:1900990 10 11\n\
             4: POSIX  ADVISORY  WRITE 2287 fe:00:1900990 0 1\n",
        );
        assert_eq!(t.get(&(2287, FE00, 1900990)), Some(&LockKind::ReadPartial));
        // A new kind does take over.
        let t = parse_locks(
            "1: POSIX  ADVISORY  READ 7 fe:00:9 0 1\n\
             2: POSIX  ADVISORY  WRITE 7 fe:00:9 0 EOF\n",
        );
        assert_eq!(t.get(&(7, FE00, 9)), Some(&LockKind::WriteFull));
    }

    #[test]
    fn the_inode_key_is_canonical_however_it_was_spelled() {
        // Found by the proc_locks fuzz target: Rust's integer parser accepts a
        // leading `+`, so keying on the raw text would store "+0" and never
        // match a row whose node is "0". The C keys on the number.
        let t = parse_locks("1: POSIX ADVISORY WRITE 5 fe:00:+7 0 EOF\n");
        assert_eq!(
            t.get(&(5, FE00, 7)),
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
