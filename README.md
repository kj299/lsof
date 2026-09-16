# lsof — a memory-safe rewrite in Rust, with the original C as its oracle

This repository is a fork of [lsof](https://en.wikipedia.org/wiki/Lsof) (the
classic "LiSt Open Files" utility) whose active work is
**[`lsof-rs/`](lsof-rs/) — a from-scratch Rust reimplementation** that
eliminates the memory-unsafety bug class inherent to the original C while
keeping lsof's command-line surface and output formats.

The inherited C tree is **not** legacy being replaced in place. It is the
**differential oracle**: CI builds `lsof` from this tree on every run and diffs
it against `lsof-rs` over 87 cases on the same host, at the same instant, so
the port is validated against the reference implementation itself rather than
against a substitute.

## Layout

| Path | What it is |
|---|---|
| [`lsof-rs/`](lsof-rs/) | The Rust rewrite: a Cargo workspace with a platform-agnostic core and native Windows and Linux backends |
| [`porting-kit/`](porting-kit/) | The reusable C→Rust porting methodology this project runs on — playbook, prompts, and the CI harnesses that enforce its gates |
| `lib/`, `src/`, `include/` | The original C `lsof`, built unchanged as the oracle |
| `lib/dialects/` | Per-OS C backends ("dialects"); `linux/` is the one the differential builds |
| `tests/`, `lib/dialects/*/tests/` | The C test suite (`make check`) |
| `docs/` | End-user lsof documentation (tutorial, options, FAQ) |

## Status

| Backend | State |
|---|---|
| **Windows** (Rust) | Complete and field-validated — see [releases](https://github.com/kj299/lsof/releases) |
| **Linux** (Rust) | Phase L2 — processes, fds, `cwd`/`rtd`/`txt`, sockets (`-i`, `-U`), mapped files, locks |
| **C oracle** | Built on Linux (differential) and macOS (`build.yml`) |

Known, deliberate differences between the two implementations are tracked in
[`lsof-rs/DIVERGENCES.md`](lsof-rs/DIVERGENCES.md); everything else must match,
stdout and exit code alike.

## Building

The Rust port:

```
cd lsof-rs && cargo build --release
```

The C oracle:

```
autoreconf -vif && ./configure && make
```

## How lsof works

```
$ cat > /tmp/LOG &
[1] 18083
$ lsof -p 18083
COMMAND   PID   USER   FD   TYPE DEVICE  SIZE/OFF     NODE NAME
cat     18083 yamato  cwd    DIR   0,44      1580 43460784 /tmp/lsof
cat     18083 yamato  rtd    DIR  253,2      4096        2 /
cat     18083 yamato  txt    REG  253,2     47432   678364 /usr/bin/cat
cat     18083 yamato  mem    REG  253,2   2119256   679775 /usr/lib64/libc-2.27.so
cat     18083 yamato    0u   CHR  136,3       0t0        6 /dev/pts/3
cat     18083 yamato    1w   REG   0,44         0 54550934 /tmp/LOG
cat     18083 yamato    2u   CHR  136,3       0t0        6 /dev/pts/3
```

## Upstream

lsof was originally developed and maintained by Vic Abell, and is maintained
upstream by the [lsof-org team](https://github.com/lsof-org/lsof), from which
this repository is forked. Original documentation is preserved in the `00*`
files at the root and rendered in [`docs/`](docs/). Attribution and licensing
are unchanged — see [`COPYING`](COPYING) and [`00CREDITS`](00CREDITS).
