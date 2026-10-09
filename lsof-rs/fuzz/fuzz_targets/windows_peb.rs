#![no_main]

// Fuzz the Windows backend's PEB walk (lsof-backend-windows, `peb_walk`): the
// PEB → ProcessParameters → CurrentDirectory.DosPath chain behind the `cwd`
// row, which follows pointers the TARGET process wrote into its own PEB.
//
// THREAT-MODEL.md recorded this row as having no fuzz target. The walk added
// its offsets to such a pointer with a plain `+`; a ProcessParameters above
// 0xFFFF_FFFF_FFFF_FFC7 wrapped in the release build (so lsof read the DosPath
// from wherever the wrap landed, in 0x0..0x37) and panicked under overflow
// checks. It now runs over a reader closure, so this target can hand it any
// memory image, on Linux.
//
// The input is a sparse address space: records of an 8-byte little-endian
// address, a 1-byte length and that many bytes. The walk is run from a fixed
// PEB, from each of the first records (so a record can be the PEB itself), and
// from bases at the top of the address space. Checked:
//
//   - nothing panics;
//   - every read the walk asks for is at the TRUE sum of a pointer and a
//     field offset, computed here in u128 where nothing can wrap: the
//     documented offsets are the Windows ABI, so they are spelled out here
//     rather than imported;
//   - a cwd comes only from a complete walk, and is at most the 32,767 UTF-16
//     units a u16 byte length holds.

use std::cell::RefCell;
use std::collections::BTreeMap;

use libfuzzer_sys::fuzz_target;
use lsof_backend_windows::fuzz_api::{cwd32, cwd64};

/// Bytes at addresses; a read is served only from within one run, as
/// `ReadProcessMemory` fails on a range that is not wholly readable.
fn get(mem: &BTreeMap<usize, Vec<u8>>, addr: usize, len: usize) -> Option<Vec<u8>> {
    let (&base, bytes) = mem.range(..=addr).next_back()?;
    let from = addr.checked_sub(base)?;
    bytes.get(from..from.checked_add(len)?).map(<[u8]>::to_vec)
}

fn le(bytes: &[u8]) -> u128 {
    bytes
        .iter()
        .rev()
        .fold(0u128, |acc, &b| (acc << 8) | u128::from(b))
}

/// The walk's reads, as `(offset from the pointer, bytes)`, for a 64-bit and a
/// WOW64 target: ProcessParameters, DosPath.Length, DosPath.Buffer.
const WALK64: [(u128, usize); 3] = [(0x20, 8), (0x38, 2), (0x40, 8)];
const WALK32: [(u128, usize); 3] = [(0x10, 4), (0x24, 2), (0x28, 4)];

/// Runs one walk and checks every read it made against the true addresses.
fn check(
    mem: &BTreeMap<usize, Vec<u8>>,
    base: usize,
    walk: [(u128, usize); 3],
    run: impl FnOnce(&mut dyn FnMut(usize, usize) -> Option<Vec<u8>>) -> Option<String>,
) {
    let reads = RefCell::new(Vec::new());
    let mut reader = |addr: usize, len: usize| {
        reads.borrow_mut().push((addr, len));
        get(mem, addr, len)
    };
    let cwd = run(&mut reader);
    let reads = reads.into_inner();
    assert!(reads.len() <= 4, "the walk made {} reads", reads.len());

    // The pointer each read hangs off: the PEB, then the ProcessParameters
    // the first read returned (twice), then the Buffer the third returned.
    let value = |i: usize| -> u128 {
        let (addr, len) = reads[i];
        le(&get(mem, addr, len).expect("the walk went on past a read that failed"))
    };
    for (i, &(addr, len)) in reads.iter().enumerate() {
        let (want, want_len) = match i {
            0 => (base as u128 + walk[0].0, walk[0].1),
            1 | 2 => (value(0) + walk[i].0, walk[i].1),
            _ => (value(2), usize::from(u16::try_from(value(1)).unwrap())),
        };
        assert_eq!(
            (addr as u128, len),
            (want, want_len),
            "read {i} is not the unwrapped field address (base {base:#x}, reads {reads:x?})"
        );
    }
    if let Some(s) = cwd {
        assert_eq!(reads.len(), 4, "a cwd from an incomplete walk: {s:?}");
        assert!(
            s.encode_utf16().count() <= usize::from(u16::MAX) / 2,
            "more UTF-16 than a u16 byte length holds"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let mut mem = BTreeMap::new();
    let mut addrs = Vec::new();
    let mut rest = data;
    while let [a0, a1, a2, a3, a4, a5, a6, a7, n, tail @ ..] = rest {
        let addr = u64::from_le_bytes([*a0, *a1, *a2, *a3, *a4, *a5, *a6, *a7]) as usize;
        let n = usize::from(*n).min(tail.len());
        mem.insert(addr, tail[..n].to_vec());
        addrs.push(addr);
        rest = &tail[n..];
    }

    let mut bases = vec![0x1000, usize::MAX, usize::MAX - 0x10, usize::MAX - 0x1f];
    // A record can be the PEB itself: the base whose ProcessParameters field
    // (+0x20 on 64-bit, +0x10 on WOW64) is that record. Explicit wrapping:
    // this is the harness choosing bases, not the code under test.
    for &a in addrs.iter().take(4) {
        bases.extend([a, a.wrapping_sub(0x20), a.wrapping_sub(0x10)]);
    }
    for &base in &bases {
        check(&mem, base, WALK64, |r| cwd64(base, &mut |a, n| r(a, n)));
        check(&mem, base, WALK32, |r| cwd32(base, &mut |a, n| r(a, n)));
    }
});
