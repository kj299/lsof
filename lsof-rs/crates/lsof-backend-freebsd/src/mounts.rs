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
/// 4. The source, `f_mntfromname`, is spelt by `Readlink()`, a path or not
///    (`devfs` is read as a name in lsof's directory), and `stat`ed for
///    whether it is a block device — which on FreeBSD nothing is, disks
///    being character devices, so a mount's source never names its file
///    system as an argument here, as in the C.
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
                    // `sb.st_dev = (dev_t)mb->f_fsid.val[0]` (`dmnt.c:131`):
                    // an `int32_t` widened to the 64-bit `dev_t`, its sign
                    // with it.
                    let dev = i64::from(m.fsid0 as i32) as u64;
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
        // The table's `has_nfs` stays 0: it is the Linux dialect's `HasNFS`,
        // under which that dialect makes its per-file calls through the
        // child. FreeBSD's `readmnt()` notes nothing of the kind, and `-N`
        // goes by each vnode's own file system (DIVERGENCES 182).
        let kind = if m.fstypename.eq_ignore_ascii_case(b"nfs") {
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
            fsname: <std::ffi::OsString as std::os::unix::ffi::OsStringExt>::from_vec(
                m.mntfrom.clone(),
            ),
            kind,
            supplied: false,
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
    if exempt.is_some_and(|e| e.plus) {
        return (Some(raw_os.to_os_string()), false);
    }
    // Whatever the source is, a path or a name like `devfs`: the dialect's
    // `readmnt()` hands every `f_mntfromname` to `Readlink()` and then to
    // `statsafely()` (`dmnt.c:167-177`), where Linux's asks only of a path.
    // Measured on FreeBSD 14.5: `lsof -b /` says `avoiding readlink(devfs)`
    // and `avoiding stat(devfs)` after `/dev`'s own lines.
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
        assert_eq!(t.has_nfs, 0, "Linux's HasNFS: not FreeBSD's");
        let said = lines.borrow().join("\n");
        assert!(
            said.contains("can't stat() nfs file system /lsof-rs-no-such-dir-xyz")
                && said.contains("assuming \"dev=1234\" from mount table"),
            "{said}"
        );
        assert!(has_type(&list, "nfs") && !has_type(&list, "zfs"));
    }

    /// Under `-b` every call the read would make says so, a mount at a
    /// time: its directory's `Readlink()` and `stat`, then its source's,
    /// whether that is a path or a name. Measured against the C on FreeBSD
    /// 14.5 (`lsof -b /`): after `/dev`'s lines, `avoiding readlink(devfs)`
    /// and `avoiding stat(devfs)`.
    #[test]
    fn a_source_is_read_and_stated_path_or_not() {
        let lines: std::cell::RefCell<Vec<String>> = Default::default();
        let say = |l: &str| lines.borrow_mut().push(l.to_string());
        let avoid = lsof_core::Blocking {
            avoid: true,
            ..Default::default()
        };
        let fs = SafeFs::new(&lsof_core::InProcess, &say).with(avoid, true);
        let mut dev = m(5, "devfs", "devfs", "/dev");
        dev.fsid0 = 0x7100_ff00;
        let t = resolve(
            &[m(1, "ufs", "/dev/gpt/rootfs", "/"), dev],
            &MountRequest::default(),
            &fs,
        );
        assert_eq!(
            *lines.borrow(),
            [
                "lsof: avoiding readlink(/): -b was specified.",
                "lsof: avoiding stat(/): -b was specified.",
                "lsof: WARNING: can't stat() ufs file system /",
                "      Output information may be incomplete.",
                "      assuming \"dev=1234\" from mount table",
                "lsof: avoiding readlink(/dev/gpt/rootfs): -b was specified.",
                "lsof: avoiding stat(/dev/gpt/rootfs): -b was specified.",
                "lsof: avoiding readlink(/dev): -b was specified.",
                "lsof: avoiding stat(/dev): -b was specified.",
                "lsof: WARNING: can't stat() devfs file system /dev",
                "      Output information may be incomplete.",
                "      assuming \"dev=7100ff00\" from mount table",
                "lsof: avoiding readlink(devfs): -b was specified.",
                "lsof: avoiding stat(devfs): -b was specified.",
            ]
        );
        assert_eq!(
            t.entries[1].source_resolved.as_deref(),
            Some(OsStr::new("devfs"))
        );
        assert!(!t.entries[1].source_is_block);
    }

    /// `f_fsid.val[0]` is an `int32_t`, and the C's cast to `dev_t` keeps its
    /// sign: a negative one is assumed, and printed (`%lx`), as 64 bits.
    #[test]
    fn an_assumed_device_keeps_the_sign_of_the_fsid() {
        let lines: std::cell::RefCell<Vec<String>> = Default::default();
        let say = |l: &str| lines.borrow_mut().push(l.to_string());
        let fs = SafeFs::new(&lsof_core::InProcess, &say);
        let mut gone = m(2, "ufs", "/dev/x", "/lsof-rs-no-such-dir-xyz");
        gone.fsid0 = 0x8a9a_cc5c;
        let t = resolve(&[gone], &MountRequest::default(), &fs);
        assert_eq!(t.entries[0].device, Some(0xffff_ffff_8a9a_cc5c));
        assert!(
            lines
                .borrow()
                .iter()
                .any(|l| l == "      assuming \"dev=ffffffff8a9acc5c\" from mount table"),
            "{:?}",
            lines.borrow()
        );
    }
}
