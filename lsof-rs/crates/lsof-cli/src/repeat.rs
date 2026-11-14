//! `-r` and `+r`: the C's repeat loop (`main.c:1338-1610`), its clock and
//! its sleep handed in, so that what it prints, when it sleeps and how it
//! ends is tested without a second going by (DIVERGENCES 54, 152).

use std::io::{self, Write};

use lsof_core::timefmt::{Marker, Zone};

use crate::args::Repeat;

/// How a cycle's marker is printed, by format (`main.c:1580-1600`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Marking {
    /// `=======`, or the `m<fmt>` marker, and a newline (`puts()`).
    Table,
    /// `m`, the marker, then the field terminator, and a newline after a
    /// NUL one (`-F0`).
    Fields { nul: bool },
    /// `-J`: nothing; each cycle is its own document.
    JsonDoc,
    /// `-j`: an empty line after each cycle of a repeating run, printed
    /// before `+r` looks at what the cycle listed.
    JsonLines,
}

/// What the loop needs of the run.
pub trait Cycles {
    /// One cycle: gather, select, print. Whether it printed a process (the
    /// C's `n`, what `+r` ends on).
    fn cycle(&mut self) -> bool;
    /// `time(NULL)`.
    fn now(&mut self) -> i64;
    /// `sleep(secs)`.
    fn sleep(&mut self, secs: u64);
    /// Standard output, where the markers go.
    fn out(&mut self) -> &mut dyn Write;
}

/// How the loop ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ended {
    /// `ev`: `+r` was given and no cycle that repeats listed anything — the
    /// exit status is 1 unless a search failure already made it so. A `+r`
    /// with no delay (`+r0`) runs once and leaves it set, as the C does
    /// (measured: it lists and exits 1).
    pub idle_error: bool,
    /// How many cycles ran.
    pub cycles: u64,
}

/// The C's loop: a cycle; under `-j` and a delay, an empty line; then, with
/// a delay, `+r`'s test (a cycle that listed nothing ends the run before
/// its marker), the marker (`m<fmt>` formatted anew for the time now in
/// `zone`), a flush and the sleep; then the count, which ends the run once
/// that many cycles have run, each followed by its sleep (measured: `-r 1c3`
/// takes three seconds). No delay is one cycle and no marker.
pub fn run(
    repeat: &Repeat,
    marker: &mut Option<Marker>,
    zone: &Zone,
    marking: Marking,
    host: &mut dyn Cycles,
) -> io::Result<Ended> {
    let mut delay = repeat.delay;
    let mut ended = Ended {
        idle_error: repeat.until_idle,
        cycles: 0,
    };
    loop {
        let listed = host.cycle();
        ended.cycles = ended.cycles.saturating_add(1);
        if marking == Marking::JsonLines && delay > 0 {
            host.out().write_all(b"\n")?;
        }
        if delay > 0 {
            if repeat.until_idle {
                if !listed {
                    break;
                }
                ended.idle_error = false;
            }
            let now = host.now();
            let text: Option<Vec<u8>> = marker.as_mut().map(|m| m.at(zone, now).to_vec());
            match marking {
                Marking::JsonDoc | Marking::JsonLines => {}
                Marking::Fields { nul } => {
                    let out = host.out();
                    out.write_all(b"m")?;
                    out.write_all(text.as_deref().unwrap_or_default())?;
                    out.write_all(if nul { b"\0\n" } else { b"\n" })?;
                }
                Marking::Table => {
                    let out = host.out();
                    out.write_all(text.as_deref().unwrap_or(b"======="))?;
                    out.write_all(b"\n")?;
                }
            }
            host.out().flush()?;
            host.sleep(delay);
        }
        if repeat.count > 0 && ended.cycles == repeat.count {
            delay = 0;
        }
        if delay == 0 {
            break;
        }
    }
    host.out().flush()?;
    Ok(ended)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lsof_core::timefmt::PosixTz;

    /// A run whose cycles list what `listed` says, in turn, and whose clock
    /// moves only when it sleeps.
    struct Script {
        listed: Vec<bool>,
        cycle: usize,
        now: i64,
        slept: Vec<u64>,
        out: Vec<u8>,
        events: Vec<String>,
    }

    impl Script {
        fn new(listed: &[bool]) -> Self {
            Script {
                listed: listed.to_vec(),
                cycle: 0,
                now: 1_794_624_000,
                slept: Vec::new(),
                out: Vec::new(),
                events: Vec::new(),
            }
        }
    }

    impl Cycles for Script {
        fn cycle(&mut self) -> bool {
            let listed = self.listed.get(self.cycle).copied().unwrap_or(true);
            self.cycle += 1;
            self.events.push(format!("cycle{}", self.cycle));
            self.out
                .extend_from_slice(format!("<{}>", self.cycle).as_bytes());
            listed
        }
        fn now(&mut self) -> i64 {
            self.now
        }
        fn sleep(&mut self, secs: u64) {
            self.events.push(format!("sleep{secs}"));
            self.slept.push(secs);
            self.now += i64::try_from(secs).unwrap();
        }
        fn out(&mut self) -> &mut dyn Write {
            &mut self.out
        }
    }

    fn utc() -> Zone {
        Zone::Rules(PosixTz::utc(b"UTC"))
    }

    fn go(r: Repeat, marking: Marking, listed: &[bool], fmt: Option<&[u8]>) -> (Ended, Script) {
        let zone = utc();
        let mut marker = fmt.map(|f| Marker::new(f, &zone, 0).expect("a format"));
        let mut s = Script::new(listed);
        let ended = run(&r, &mut marker, &zone, marking, &mut s).unwrap();
        (ended, s)
    }

    fn rep(delay: u64, count: u64, until_idle: bool) -> Repeat {
        Repeat {
            delay,
            count,
            until_idle,
            marker: None,
        }
    }

    #[test]
    fn a_count_ends_the_run_after_its_last_sleep() {
        let (ended, s) = go(rep(1, 3, false), Marking::Table, &[], None);
        assert_eq!(ended.cycles, 3);
        assert_eq!(s.slept, [1, 1, 1]);
        assert_eq!(
            String::from_utf8(s.out).unwrap(),
            "<1>=======\n<2>=======\n<3>=======\n"
        );
        assert!(!ended.idle_error);
    }

    /// A reader gone: the first write after the cycle fails, and the run
    /// ends there, its error the caller's to turn into the closed-pipe
    /// exit (row 36), and no second cycle starts. The C, with SIGPIPE
    /// ignored, writes on into the dead pipe until its count or `+r` ends
    /// it (measured; DIVERGENCES 152, residue); with SIGPIPE left alone both
    /// die at that write.
    #[test]
    fn a_write_that_fails_ends_the_run() {
        struct Gone(Script);
        impl Cycles for Gone {
            fn cycle(&mut self) -> bool {
                self.0.cycle()
            }
            fn now(&mut self) -> i64 {
                self.0.now()
            }
            fn sleep(&mut self, secs: u64) {
                self.0.sleep(secs)
            }
            fn out(&mut self) -> &mut dyn Write {
                self
            }
        }
        impl Write for Gone {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
        }
        for until_idle in [false, true] {
            let zone = utc();
            let mut host = Gone(Script::new(&[]));
            let got = run(
                &rep(1, 3, until_idle),
                &mut None,
                &zone,
                Marking::Table,
                &mut host,
            );
            assert_eq!(got.err().map(|e| e.kind()), Some(io::ErrorKind::BrokenPipe));
            assert_eq!(host.0.events, ["cycle1"], "+r: {until_idle}");
        }
    }

    #[test]
    fn no_delay_is_one_cycle_and_no_marker() {
        let (ended, s) = go(rep(0, 3, false), Marking::Table, &[], None);
        assert_eq!((ended.cycles, s.slept.len()), (1, 0));
        assert_eq!(s.out, b"<1>");
        // `+r0`: once, and the status stays an error, as the C's `ev` does.
        let (ended, _) = go(rep(0, 0, true), Marking::Table, &[true], None);
        assert_eq!((ended.cycles, ended.idle_error), (1, true));
    }

    #[test]
    fn plus_r_ends_at_the_first_cycle_that_lists_nothing() {
        // Two cycles list, the third does not: no marker and no sleep after
        // it, and exit 0 (measured).
        let (ended, s) = go(rep(1, 0, true), Marking::Table, &[true, true, false], None);
        assert_eq!((ended.cycles, ended.idle_error), (3, false));
        assert_eq!(
            String::from_utf8(s.out).unwrap(),
            "<1>=======\n<2>=======\n<3>"
        );
        assert_eq!(s.slept, [1, 1]);
        // Nothing listed at all: exit 1, at once.
        let (ended, s) = go(rep(1, 0, true), Marking::Table, &[false], None);
        assert_eq!(
            (ended.cycles, ended.idle_error, s.slept.len()),
            (1, true, 0)
        );
        // `+r` with a count: whichever comes first.
        let (ended, _) = go(rep(1, 2, true), Marking::Table, &[true, true, true], None);
        assert_eq!((ended.cycles, ended.idle_error), (2, false));
    }

    #[test]
    fn markers_follow_the_format() {
        let (_, s) = go(rep(1, 2, false), Marking::Fields { nul: false }, &[], None);
        assert_eq!(s.out, b"<1>m\n<2>m\n");
        let (_, s) = go(rep(1, 1, false), Marking::Fields { nul: true }, &[], None);
        assert_eq!(s.out, b"<1>m\0\n");
        let (_, s) = go(rep(1, 2, false), Marking::JsonDoc, &[], None);
        assert_eq!(s.out, b"<1><2>");
        // `-j`: the empty line comes before `+r` looks, so even the cycle
        // that ends it has one (measured: `+r 1 -j -p 999999` prints `\n`).
        let (_, s) = go(rep(1, 0, true), Marking::JsonLines, &[true, false], None);
        assert_eq!(s.out, b"<1>\n<2>\n");
        let (_, s) = go(rep(0, 0, false), Marking::JsonLines, &[], None);
        assert_eq!(s.out, b"<1>");
    }

    #[test]
    fn a_marker_format_is_formatted_at_each_cycle() {
        let (_, s) = go(rep(5, 2, false), Marking::Table, &[], Some(b"%s %%"));
        assert_eq!(
            String::from_utf8(s.out).unwrap(),
            "<1>1794624000 %\n<2>1794624005 %\n"
        );
        let (_, s) = go(
            rep(1, 1, false),
            Marking::Fields { nul: false },
            &[],
            Some(b"X"),
        );
        assert_eq!(s.out, b"<1>mX\n");
        // `%n` in the table marker is a new line in it (measured: `02` and
        // `%x` lines).
        let (_, s) = go(rep(1, 1, false), Marking::Table, &[], Some(b"%H%n%%x"));
        assert_eq!(s.out, b"<1>02\n%x\n");
    }
}
