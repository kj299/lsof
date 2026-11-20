//! An open file's flags as the C prints them (`print_fflags()`, `print.c`):
//! by name under `+f g` (`W,AP,LG,CX`), in hex under `+f G` and in `-F`'s `G`
//! field (`0x88401;0x0`).
//!
//! The names are the platform's `Pff_tab[]`: Linux's (`lib/dialects/linux/
//! dstore.c`), the numbers the kernel's as `fdinfo` reports them, or on
//! FreeBSD that dialect's (`lib/dialects/freebsd/dstore.c`), the numbers
//! `sys/fcntl.h`'s as `xf_flag` holds them (DIVERGENCES 142). A Windows row
//! has none.
//!
//! FreeBSD's file structure has more than flags to show: its count, address
//! and node address ([`FsValues`], `+f c`, `+f f`, `+f n`), which no other
//! platform records.

/// How the flags are shown, and whether at all: the C's `Fsv & FSV_FG` (the
/// FILE-FLAG column, and the `G` field) and its `FsvFlagX` (hex).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FileFlags {
    /// Not shown: the default, and what `-f g` asks for.
    #[default]
    Off,
    /// By name, with any bit that has none in hex: `+f g`.
    Names,
    /// In hex: `+f G`, and `-F`'s own choice for its `G` field.
    Hex,
}

// Three of the named flags have other numbers on aarch64. These are the
// kernel's `asm-generic/fcntl.h` values, which x86_64 uses and which the
// differential measures; the aarch64 ones are read from
// `arch/arm64/include/uapi/asm/fcntl.h` and not measured. That header moves
// `O_LARGEFILE` too, but the C never uses the kernel's: see [`LARGEFILE`].
#[cfg(target_arch = "aarch64")]
mod arch {
    pub const O_DIRECTORY: u32 = 0o40000;
    pub const O_NOFOLLOW: u32 = 0o100000;
    pub const O_DIRECT: u32 = 0o200000;
}
#[cfg(not(target_arch = "aarch64"))]
mod arch {
    pub const O_DIRECT: u32 = 0o40000;
    pub const O_DIRECTORY: u32 = 0o200000;
    pub const O_NOFOLLOW: u32 = 0o400000;
}

/// The C's `LG` entry. glibc defines `O_LARGEFILE` as 0 for a 64-bit program,
/// so `dstore.c` falls back to 0100000 whatever the architecture — which on
/// aarch64 is `O_NOFOLLOW`'s bit, and `NFLK`, earlier in the table, takes it.
const LARGEFILE: u32 = 0o100000;

/// `Pff_tab[]`, in its order. The order decides which name a bit two entries
/// share goes to: `O_SYNC` contains `O_DSYNC`'s bit and comes first, so the C
/// prints an `O_DSYNC` file as `SYN` and never prints `DSYN` at all (measured).
pub const LINUX_NAMES: &[(u32, &str)] = &[
    (0o1, "W"),
    (0o2, "RW"),
    (0o100, "CR"),
    (0o200, "EXCL"),
    (0o400, "NTTY"),
    (0o1000, "TR"),
    (0o2000, "AP"),
    (0o4000, "ND"),
    (0o4010000, "SYN"),
    (0o20000, "ASYN"),
    (arch::O_DIRECT, "DIR"),
    (arch::O_DIRECTORY, "DTY"),
    (arch::O_NOFOLLOW, "NFLK"),
    (0o1000000, "NATM"),
    (0o10000, "DSYN"),
    (0o4010000, "RSYN"),
    (LARGEFILE, "LG"),
    (0o2000000, "CX"),
    (0o10000000, "PATH"),
    (0o20000000 | arch::O_DIRECTORY, "TMPF"),
];

/// FreeBSD's `Pff_tab[]` (`lib/dialects/freebsd/dstore.c`), in its order,
/// with `sys/fcntl.h`'s numbers as the C compiles them (`FMARK` and `FDEFER`,
/// which the table has under `#if`, are not defined on 14 or 15): measured by
/// preprocessing the C's headers against FreeBSD 14.3's and 15.0's. `FNDELAY`
/// is `FNONBLOCK`, so `ND` is never printed. Its `Pof_tab[]` has `CX`, but the
/// dialect never sets a row's `pof`.
pub const FREEBSD_NAMES: &[(u32, &str)] = &[
    (0x1, "R"),
    (0x2, "W"),
    (0x4, "NB"),
    (0x4, "ND"),
    (0x8, "AP"),
    (0x40, "ASYN"),
    (0x80, "FSYN"),
    (0x4000, "LCK"),
    (0x8000, "NTTY"),
];

/// This platform's table.
#[cfg(target_os = "freebsd")]
const TABLE: &[(u32, &str)] = FREEBSD_NAMES;
#[cfg(not(target_os = "freebsd"))]
const TABLE: &[(u32, &str)] = LINUX_NAMES;

/// Which of the file structure's other values are shown: the C's `Fsv`
/// bits `FSV_FA`, `FSV_CT` and `FSV_NI`, which `+f f`, `+f c` and `+f n` set
/// (and `-F`'s `F`, `C` and `N`), and their `-` forms clear. FreeBSD's alone
/// (DIVERGENCES 142); each is its own column, FILE-ADDR, FCT and NODE-ID.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FsValues {
    pub addr: bool,
    pub count: bool,
    pub node: bool,
}

/// The file structure's columns and fields: the flags, as [`FileFlags`]
/// says, and the other values, as [`FsValues`] says.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FsShow {
    pub flags: FileFlags,
    pub values: FsValues,
}

impl From<FileFlags> for FsShow {
    fn from(flags: FileFlags) -> Self {
        FsShow {
            flags,
            values: FsValues::default(),
        }
    }
}

/// A kernel address as the C's `print_kptr()` prints FILE-ADDR and NODE-ID:
/// `0x%08lx`. The backend has already cut it to the width of the C's
/// `KA_T`.
pub fn kptr(addr: u64) -> String {
    format!("0x{addr:08x}")
}

/// Whether a row with these flags has anything to show. The C prints nothing
/// for flags of 0 unless it was asked for hex (`print.c`: `FsvFlagX ||
/// Lf->ffg || Lf->pof`), and nothing at all while the flags are off.
pub fn shown(flags: u32, style: FileFlags) -> bool {
    match style {
        FileFlags::Off => false,
        FileFlags::Names => flags != 0,
        FileFlags::Hex => true,
    }
}

/// The flags as `print_fflags()` writes them.
///
/// By name: each table entry whose bits are still set, in table order, joined
/// with commas, its bits then cleared; what is left over follows in hex. In
/// hex: all of it. Then the process's own open-file flags, which Linux does not
/// have (its `Pof_tab[]` is empty): nothing by name, and `;0x0` in hex.
pub fn text(flags: u32, style: FileFlags) -> String {
    text_in(TABLE, flags, style)
}

/// [`text`] by `table`'s names.
pub fn text_in(table: &[(u32, &str)], flags: u32, style: FileFlags) -> String {
    let hex = style == FileFlags::Hex;
    let mut out = String::new();
    let mut left = flags;
    if !hex {
        for &(bits, name) in table {
            if left & bits != 0 {
                if !out.is_empty() {
                    out.push(',');
                }
                out.push_str(name);
                left &= !bits;
            }
        }
    }
    if left != 0 || hex {
        if !out.is_empty() {
            out.push(',');
        }
        out.push_str(&format!("0x{left:x}"));
    }
    if hex {
        out.push_str(";0x0");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every row the C printed for the flags fixture of 2026-09-28, by name and
    /// in hex, from the `fdinfo` flags each fd had.
    #[test]
    fn flags_read_as_the_c_reads_them() {
        let names = |f: u32| text_in(LINUX_NAMES, f, FileFlags::Names);
        assert_eq!(names(0o100000), "LG");
        assert_eq!(names(0o100001), "W,LG");
        assert_eq!(names(0o2102001), "W,AP,LG,CX");
        assert_eq!(names(0o2104002), "RW,ND,LG,CX");
        assert_eq!(names(0o2110001), "W,SYN,LG,CX", "O_DSYNC is SYN");
        assert_eq!(names(0o6110001), "W,SYN,LG,CX");
        assert_eq!(names(0o3100000), "NATM,LG,CX");
        assert_eq!(names(0o12000000), "CX,PATH");
        assert_eq!(names(0o12200000), "DTY,CX,PATH");
        assert_eq!(names(0o2500000), "NFLK,LG,CX");
        assert_eq!(names(0o2100003), "W,RW,LG,CX", "access mode 3");
        assert_eq!(names(0o22300002), "RW,DTY,LG,CX,TMPF");
        assert_eq!(names(0o2000000), "CX");
        assert_eq!(names(0o2000002), "RW,CX");
        assert_eq!(
            text_in(LINUX_NAMES, 0o2102001, FileFlags::Hex),
            "0x88401;0x0"
        );
        assert_eq!(
            text_in(LINUX_NAMES, 0o12000000, FileFlags::Hex),
            "0x280000;0x0"
        );
        assert_eq!(
            text_in(LINUX_NAMES, 0o22300002, FileFlags::Hex),
            "0x498002;0x0"
        );
    }

    #[test]
    fn a_bit_with_no_name_is_left_in_hex_and_zero_only_in_hex() {
        assert_eq!(
            text_in(LINUX_NAMES, 0o40000000 | 0o1, FileFlags::Names),
            "W,0x800000"
        );
        assert_eq!(
            text_in(LINUX_NAMES, 0o40000000, FileFlags::Names),
            "0x800000"
        );
        assert_eq!(text_in(LINUX_NAMES, 0, FileFlags::Names), "");
        assert_eq!(text_in(LINUX_NAMES, 0, FileFlags::Hex), "0x0;0x0");
        assert!(!shown(0, FileFlags::Names) && shown(0, FileFlags::Hex));
        assert!(shown(1, FileFlags::Names) && !shown(1, FileFlags::Off));
    }

    /// FreeBSD's table, by `dstore.c`'s order: `FNDELAY` is `FNONBLOCK`, so
    /// `NB` takes the bit and `ND` never prints; a bit with no name is left
    /// in hex, `O_CLOEXEC` (0x100000) and `O_DIRECT` among them.
    #[test]
    fn freebsd_flags_read_by_freebsds_names() {
        let names = |f: u32| text_in(FREEBSD_NAMES, f, FileFlags::Names);
        assert_eq!(names(0x1), "R");
        assert_eq!(names(0x3), "R,W");
        assert_eq!(names(0x2 | 0x4 | 0x8), "W,NB,AP");
        assert_eq!(names(0x40 | 0x80 | 0x4000 | 0x8000), "ASYN,FSYN,LCK,NTTY");
        assert_eq!(names(0x1 | 0x10_0000), "R,0x100000");
        assert_eq!(
            text_in(FREEBSD_NAMES, 0x3, FileFlags::Hex),
            "0x3;0x0",
            "hex is the same everywhere"
        );
        assert_eq!(kptr(0x1234), "0x00001234");
        assert_eq!(kptr(0xffff_f800_0a1b_2c3d), "0xfffff8000a1b2c3d");
        assert_eq!(FsShow::from(FileFlags::Hex).values, FsValues::default());
    }
}
