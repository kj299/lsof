//! The mount table, as the C's FreeBSD `readmnt()` makes it (`dmnt.c`) from
//! `getmntinfo(…, MNT_NOWAIT)`: what makes a path argument naming a mount
//! point select the whole file system, and `-e` and `-N` mean anything.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use lsof_core::{MountEntry, MountKind, MountRequest, MountTable, SafeFs};

use crate::kinfo::StatFs;

const INCOMPLETE: &str = "      Output information may be incomplete.";

/// The table from `getfsstat(2)`'s records, mount by mount in the kernel's
/// order:
///
/// 1. A record with no type (`f_type` 0) is skipped.
/// 2. The mounted-on directory is spelt by `Readlink()`; one it gives up on
///    is dropped with its message and the `Output information` line unless
///    `-w`; one that does not start with `/` is dropped in silence.
/// 3. The directory is `stat`ed. One that cannot be is **kept**, unlike on
///    Linux: the C warns `can't stat() TYPE file system DIR`, then `assuming
///    "dev=…" from mount table`, and records `f_fsid.val[0]` as its device.
/// 4. The source, `f_mntfromname`, is spelt by `Readlink()` when it is a
///    path and `stat`ed for whether it is a block device — which on FreeBSD
///    nothing is, disks being character devices, so a mount's source never
///    names its file system as an argument here, as in the C.
///
/// An `-e`/`+e` mount is neither `stat`ed nor, for `+e`, read the links of,
/// as on Linux. No two rows are merged: the C's FreeBSD table keeps every
/// mount, a directory mounted over twice included. Both rows of such a
/// directory have the device its one `stat` gives, the top mount's, so the
/// order they are kept in (the kernel's, as the trait asks) selects the same
/// files whichever a path argument meets first.
pub fn resolve(list: &[StatFs], req: &MountRequest, fs: &SafeFs) -> MountTable {
    let esc = lsof_core::Escaper::UNIX;
    let mut table = MountTable::default();
    for m in list {
        if m.ftype == 0 {
            continue;
        }
        let raw_dir = OsStr::from_bytes(&m.mnton);
        let exempt = req.exempt.iter().find(|e| e.path == raw_dir);
        let (no_readlink, no_stat) = exempt.map_or((false, false), |e| (e.plus, true));
        let dir = if no_readlink {
            raw_dir.to_os_string()
        } else {
            match lsof_core::readlink::resolve(raw_dir, fs) {
                Ok(d) => d,
                Err(e) => {
                    if fs.warns() {
                        fs.tell(&format!("lsof: {}", e.message(&esc.bytes(&m.mnton))));
                        fs.tell(INCOMPLETE);
                    }
                    continue;
                }
            }
        };
        if dir.as_bytes().first() != Some(&b'/') {
            continue;
        }
        let device = if no_stat {
            None
        } else {
            match fs.stat(Path::new(&dir)) {
                Ok(st) => Some(st.dev),
                Err(_) => {
                    let dev = u64::from(m.fsid0);
                    if fs.warns() {
                        fs.tell(&format!(
                            "lsof: WARNING: can't stat() {} file system {}",
                            esc.bytes(&m.fstypename),
                            esc.bytes(&m.mnton)
                        ));
                        fs.tell(INCOMPLETE);
                        fs.tell(&format!("      assuming \"dev={dev:x}\" from mount table"));
                    }
                    Some(dev)
                }
            }
        };
        let kind = if m.fstypename.eq_ignore_ascii_case(b"nfs") {
            if table.has_nfs < 2 {
                table.has_nfs = 2;
            }
            MountKind::Nfs
        } else {
            MountKind::Regular
        };
        let (source_resolved, source_is_block) = source(&m.mntfrom, exempt, fs, esc);
        table.entries.push(MountEntry {
            dir,
            device,
            source_resolved,
            source_is_block,
            kind,
        });
    }
    table
}

fn source(
    raw: &[u8],
    exempt: Option<&lsof_core::ExemptFs>,
    fs: &SafeFs,
    esc: lsof_core::Escaper,
) -> (Option<OsString>, bool) {
    let raw_os = OsStr::from_bytes(raw);
    if exempt.is_some_and(|e| e.plus) || raw.first() != Some(&b'/') {
        return (Some(raw_os.to_os_string()), false);
    }
    match lsof_core::readlink::resolve(raw_os, fs) {
        Ok(path) => {
            let is_block = exempt.is_none()
                && fs
                    .stat(Path::new(&path))
                    .is_ok_and(|st| st.is_block_device());
            (Some(path), is_block)
        }
        Err(e) => {
            if fs.warns() {
                fs.tell(&format!("lsof: {}", e.message(&esc.bytes(raw))));
            }
            (None, false)
        }
    }
}

/// Whether a mount of type `fstype` is listed, by name alone.
pub fn has_type(list: &[StatFs], fstype: &str) -> bool {
    list.iter().any(|m| m.fstypename == fstype.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(ftype: u32, ty: &str, from: &str, on: &str) -> StatFs {
        StatFs {
            ftype,
            fsid0: 0x1234,
            fstypename: ty.into(),
            mntfrom: from.into(),
            mnton: on.into(),
        }
    }

    #[test]
    fn mounts_are_recorded_in_order_and_an_unstatable_one_is_assumed() {
        let tmp = std::env::temp_dir();
        let lines: std::cell::RefCell<Vec<String>> = Default::default();
        let say = |l: &str| lines.borrow_mut().push(l.to_string());
        let fs = SafeFs::new(&lsof_core::InProcess, &say);
        let list = [
            m(1, "ufs", "/dev/ada0p2", "/"),
            m(0, "none", "x", "/nothing"),
            m(2, "nfs", "srv:/export", "/lsof-rs-no-such-dir-xyz"),
            m(3, "tmpfs", "tmpfs", tmp.to_str().unwrap()),
        ];
        let t = resolve(&list, &MountRequest::default(), &fs);
        let dirs: Vec<_> = t.entries.iter().map(|e| e.dir.clone()).collect();
        assert_eq!(dirs.len(), 3, "{dirs:?}");
        assert_eq!(dirs[0], OsString::from("/"));
        let nfs = &t.entries[1];
        assert_eq!((nfs.kind, nfs.device), (MountKind::Nfs, Some(0x1234)));
        assert_eq!(
            nfs.source_resolved.as_deref(),
            Some(OsStr::new("srv:/export"))
        );
        assert_eq!(t.has_nfs, 2);
        let said = lines.borrow().join("\n");
        assert!(
            said.contains("can't stat() nfs file system /lsof-rs-no-such-dir-xyz")
                && said.contains("assuming \"dev=1234\" from mount table"),
            "{said}"
        );
        assert!(has_type(&list, "nfs") && !has_type(&list, "zfs"));
    }
}
