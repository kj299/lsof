//! The zone files `-r m<fmt>`'s marker is printed in, opened as glibc 2.39's
//! `__tzfile_read()` opens them, without the waits it can make
//! (DIVERGENCES 152).
//!
//! glibc opens a zone file with a plain `fopen(file, "rce")`: no
//! `O_NONBLOCK`, no look at what the file is. A FIFO with no writer holds
//! that open for ever (measured: `TZ=/fifo` kills nothing but itself under
//! `timeout`), a writer that stalls holds its reads, and a device is read
//! as a stream. What glibc can use of such a file is only a version 1
//! file's data, the length its header gives: a version 2 file needs a seek
//! a pipe refuses and an `st_size` a device does not have.
//!
//! So here the file is opened with `O_RDONLY|O_CLOEXEC|O_NONBLOCK` (a FIFO's
//! open does not wait for a writer, a terminal's not for its carrier) and
//! `fstat`ed. A regular file is handed on to be read as glibc reads it,
//! bounded by `st_size`. Anything else is read as glibc's stdio would read
//! it, each read after `poll(POLLIN)` says there is something (a FIFO no
//! writer has opened reads as its end at once, which glibc's blocking open
//! never sees), for at most [`STREAM_DEADLINE`] in all: the 44-byte header,
//! and, where it is a version 1 file's, its data. Where glibc would still
//! be waiting at the deadline, it is what it read by then, which fails as a
//! short file fails in glibc. A socket's open fails (`ENXIO`), as glibc's
//! does; a directory's read fails (`EISDIR`), as glibc's does.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::rc::Rc;
use std::time::{Duration, Instant};

use lsof_core::timefmt::{stream_data_len, FileKey, ZoneFs, ZoneSource, DATA_IN_MEMORY};
use rustix::event::{poll, PollFd, PollFlags, Timespec};
use rustix::fs::{fstat, open, FileType, Mode, OFlags};

/// How long a zone file that is not a regular file is waited on, in all:
/// the user's choice (2026-11-18). glibc waits for ever.
pub const STREAM_DEADLINE: Duration = Duration::from_secs(3);

/// Zone files as lsof-rs opens them on Linux ([`ZoneFs`]).
#[derive(Clone, Copy, Debug)]
pub struct LinuxZoneFs {
    /// [`STREAM_DEADLINE`]; shorter in tests.
    pub deadline: Duration,
}

impl Default for LinuxZoneFs {
    fn default() -> Self {
        LinuxZoneFs {
            deadline: STREAM_DEADLINE,
        }
    }
}

fn key_of(st: &rustix::fs::Stat) -> FileKey {
    FileKey {
        dev: st.st_dev,
        ino: st.st_ino,
        mtime: st.st_mtime,
    }
}

impl ZoneFs for LinuxZoneFs {
    fn stat(&mut self, path: &[u8]) -> Option<FileKey> {
        rustix::fs::stat(OsStr::from_bytes(path))
            .ok()
            .map(|st| key_of(&st))
    }

    fn open(&mut self, path: &[u8]) -> Option<ZoneSource> {
        let fd = open(
            OsStr::from_bytes(path),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .ok()?;
        let st = fstat(&fd).ok()?;
        let key = key_of(&st);
        if FileType::from_raw_mode(st.st_mode) == FileType::RegularFile {
            return Some(ZoneSource::Regular {
                key,
                size: u64::try_from(st.st_size).unwrap_or(0),
                data: Rc::new(std::fs::File::from(fd)),
            });
        }
        Some(ZoneSource::Stream {
            key,
            bytes: read_stream(&fd, Instant::now() + self.deadline),
        })
    }
}

/// What a stream gives by `deadline`: its 44-byte header, then, where that
/// is a version 1 file's, as much of its data as the header says, at most
/// [`DATA_IN_MEMORY`] of it. Each read is of what is still wanted, after
/// `poll()` says the descriptor is ready; its end, an error or the deadline
/// ends it, and a stream that ends short is a file glibc refuses.
fn read_stream(fd: &rustix::fd::OwnedFd, deadline: Instant) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(44);
    let mut want: u64 = 44;
    loop {
        if bytes.len() as u64 >= want {
            if want == 44 {
                match stream_data_len(&bytes) {
                    Some(len) if len > 0 && len <= DATA_IN_MEMORY => {
                        want = 44 + len;
                        continue;
                    }
                    _ => return bytes,
                }
            }
            return bytes;
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return bytes;
        }
        let timeout = Timespec {
            tv_sec: i64::try_from(left.as_secs()).unwrap_or(i64::MAX),
            tv_nsec: i64::from(left.subsec_nanos()),
        };
        let mut fds = [PollFd::new(fd, PollFlags::IN)];
        match poll(&mut fds, Some(&timeout)) {
            Ok(0) => return bytes,
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(_) => return bytes,
        }
        let ready = fds[0].revents();
        if !ready.intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR | PollFlags::NVAL) {
            continue;
        }
        let need = usize::try_from(want - bytes.len() as u64)
            .unwrap_or(usize::MAX)
            .min(1 << 16);
        let mut buf = vec![0u8; need];
        match rustix::io::read(fd, &mut buf[..]) {
            Ok(0) => return bytes,
            Ok(n) => bytes.extend_from_slice(buf.get(..n).unwrap_or_default()),
            Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {
                // Ready and nothing yet (a writer between writes): wait on.
                if ready.intersects(PollFlags::HUP | PollFlags::ERR | PollFlags::NVAL)
                    && !ready.contains(PollFlags::IN)
                {
                    return bytes;
                }
            }
            Err(_) => return bytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn path(p: &std::path::Path) -> Vec<u8> {
        p.as_os_str().as_bytes().to_vec()
    }

    fn short() -> LinuxZoneFs {
        LinuxZoneFs {
            deadline: Duration::from_millis(200),
        }
    }

    /// A regular file is handed on whole; a missing one, a socket fail at
    /// the open; a directory and `/dev/null` give nothing, `/dev/zero` one
    /// header of zeros (glibc: one 4096-byte read, the magic refused), each
    /// at once.
    #[test]
    #[cfg_attr(miri, ignore = "makes files, a socket, and polls")]
    fn each_kind_of_file_is_opened_as_glibc_finds_it() {
        let dir = std::env::temp_dir().join(format!("lsof-rs-zonefs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("z"), b"TZif-anything").unwrap();
        let mut fs = short();
        let started = Instant::now();
        assert!(matches!(
            fs.open(&path(&dir.join("z"))),
            Some(ZoneSource::Regular { size: 13, .. })
        ));
        assert!(fs.stat(&path(&dir.join("z"))).is_some());
        assert!(fs.open(&path(&dir.join("nosuch"))).is_none());
        let _l = std::os::unix::net::UnixListener::bind(dir.join("sock")).unwrap();
        assert!(fs.open(&path(&dir.join("sock"))).is_none());
        assert!(
            matches!(fs.open(&path(&dir)), Some(ZoneSource::Stream { ref bytes, .. }) if bytes.is_empty())
        );
        assert!(
            matches!(fs.open(b"/dev/null"), Some(ZoneSource::Stream { ref bytes, .. }) if bytes.is_empty())
        );
        assert!(
            matches!(fs.open(b"/dev/zero"), Some(ZoneSource::Stream { ref bytes, .. }) if bytes == &[0u8; 44])
        );
        assert!(
            started.elapsed() < Duration::from_millis(150),
            "{:?}",
            started.elapsed()
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The key glibc keeps: device, inode and whole-second modification
    /// time, each from `stat()`, so a second later is another file and half
    /// a second is not (measured: glibc reads it again at +1 s, not +0.5 s).
    #[test]
    #[cfg_attr(miri, ignore = "makes a file")]
    fn the_key_is_dev_ino_and_whole_seconds() {
        let dir = std::env::temp_dir().join(format!("lsof-rs-zonekey-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("z");
        std::fs::write(&p, b"x").unwrap();
        let at = |secs: u64, nanos: u32| {
            let f = std::fs::OpenOptions::new().write(true).open(&p).unwrap();
            f.set_modified(std::time::UNIX_EPOCH + Duration::new(secs, nanos))
                .unwrap();
        };
        let mut fs = LinuxZoneFs::default();
        at(1_000_000_000, 0);
        let k0 = fs.stat(&path(&p)).unwrap();
        assert_eq!(k0.mtime, 1_000_000_000);
        at(1_000_000_000, 500_000_000);
        assert_eq!(fs.stat(&path(&p)), Some(k0));
        at(1_000_000_001, 0);
        assert_ne!(fs.stat(&path(&p)), Some(k0));
        let opened = match fs.open(&path(&p)) {
            Some(ZoneSource::Regular { key, .. }) => key,
            other => panic!("{other:?}"),
        };
        assert_eq!(Some(opened), fs.stat(&path(&p)));
        assert_ne!(opened.ino, 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A FIFO: with no writer, nothing by the deadline (glibc's open waits
    /// for ever); with one that sends a version 1 file and closes, the file,
    /// header and data, and no byte more.
    #[test]
    #[cfg_attr(miri, ignore = "makes a FIFO and polls")]
    fn a_fifo_is_waited_on_until_the_deadline() {
        let dir = std::env::temp_dir().join(format!("lsof-rs-zonefifo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let fifo = dir.join("f");
        if !std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .is_ok_and(|s| s.success())
        {
            eprintln!("skipped: no mkfifo");
            return;
        }
        let mut fs = short();
        let started = Instant::now();
        assert!(
            matches!(fs.open(&path(&fifo)), Some(ZoneSource::Stream { ref bytes, .. }) if bytes.is_empty())
        );
        let took = started.elapsed();
        assert!(
            took >= Duration::from_millis(190) && took < Duration::from_secs(5),
            "{took:?}"
        );
        // A version 1 file with one type, then junk past its data.
        let mut v1 = b"TZif\0".to_vec();
        v1.extend_from_slice(&[0; 15]);
        for c in [0u32, 0, 0, 0, 1, 4] {
            v1.extend_from_slice(&c.to_be_bytes());
        }
        v1.extend_from_slice(&3600i32.to_be_bytes());
        v1.extend_from_slice(&[0, 0]);
        v1.extend_from_slice(b"ABC\0");
        let mut sent = v1.clone();
        sent.extend_from_slice(b"junk");
        let to = fifo.clone();
        let writer = std::thread::spawn(move || {
            let mut w = std::fs::OpenOptions::new().write(true).open(&to).unwrap();
            w.write_all(&sent).unwrap();
        });
        let mut fs = LinuxZoneFs {
            deadline: Duration::from_secs(20),
        };
        let got = fs.open(&path(&fifo));
        writer.join().unwrap();
        assert!(
            matches!(got, Some(ZoneSource::Stream { ref bytes, .. }) if bytes == &v1),
            "{got:?}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
