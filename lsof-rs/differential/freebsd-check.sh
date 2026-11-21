#!/bin/sh
# lsof-rs on FreeBSD, side by side with the C lsof built from the same tree.
#
# There is no FreeBSD runner in .github/workflows, so this is the FreeBSD
# differential: a script a person (or .cirrus.yml) runs on a FreeBSD host.
# Run the steps in this order; each says who runs it:
#
#   1. as root:            sh freebsd-check.sh install    (pkg install of the build tools)
#   2. as root:            sh freebsd-check.sh sources    (the kernel sources the C needs)
#   3. as a normal user:   sh freebsd-check.sh build      (both binaries, and the tests)
#   4. as a normal user:   sh freebsd-check.sh compare    (C and lsof-rs, what a user sees)
#   5. as root:            sh freebsd-check.sh compare    (the same, system-wide)
#
# Steps 3-5 each write one file in the current directory,
# lsof-rs-freebsd-<step>-<user>.txt. Nothing is installed outside pkg and
# /usr/src; everything else lives under $DIR (default /tmp/lsof-check).
# Delete it when done.
#
# The tree is cloned from $REPO at $BRANCH (default master), or copied from
# $SRC, an existing checkout, when that is set (a host with no network):
#   SRC=$HOME/lsof sh freebsd-check.sh build
# Binaries built elsewhere can be compared with LSOF_C and LSOF_RS:
#   LSOF_C=/usr/local/sbin/lsof LSOF_RS=$HOME/lsof sh freebsd-check.sh compare
#
# Every lsof run here has -n -P: no name is looked up, nothing leaves the host.
# What the comparison is expected to show is DIVERGENCES.md's (rows 140-148,
# 180-185); differential/README.md says how to read it.

set -u
if (set -o pipefail) 2>/dev/null; then set -o pipefail; fi
DIR=${DIR:-/tmp/lsof-check}
BRANCH=${BRANCH:-master}
REPO=${REPO:-https://github.com/kj299/lsof.git}
SRC=${SRC:-}
step=${1:-}
me=$(id -un)
out="$PWD/lsof-rs-freebsd-$step-$me.txt"

header() {
    echo "### $step as $me (uid $(id -u)) on $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    uname -a
    freebsd-version -ku 2>/dev/null
    command -v rustc >/dev/null && rustc -V
    [ -d "$DIR/src/.git" ] && git -C "$DIR/src" log --oneline -1
    echo
}

case "$step" in
install)
    if [ "$(id -u)" -ne 0 ]; then echo "install must run as root" >&2; exit 1; fi
    pkg install -y rust git autoconf automake libtool pkgconf
    ;;

sources)
    # The C's FreeBSD dialect compiles against the kernel's own headers
    # (-I/usr/src/sys: the autotools build and ./Configure alike), which a
    # release image does not always carry.
    if [ -f /usr/src/sys/sys/param.h ] && [ -d /usr/src/sys/kern ]; then
        echo "kernel sources: /usr/src/sys is there ($(ls /usr/src/sys | wc -l | tr -d ' ') entries)"
        exit 0
    fi
    if [ "$(id -u)" -ne 0 ]; then
        echo "no kernel sources in /usr/src/sys; run this step as root to fetch them" >&2
        exit 1
    fi
    rel=$(freebsd-version -u | sed 's/-p[0-9]*$//')
    arch=$(uname -m)
    case "$rel" in
    *-RELEASE)
        url="https://download.freebsd.org/releases/$arch/$rel/src.txz"
        echo "fetching $url (usr/src/sys of it)"
        if fetch -o - "$url" | tar -C / -xJf - usr/src/sys; then
            [ -f /usr/src/sys/sys/param.h ] && { echo "kernel sources: fetched"; exit 0; }
        fi
        echo "fetch failed; trying git" >&2
        ;;
    esac
    branch="releng/$(echo "$rel" | cut -d- -f1)"
    case "$rel" in *-STABLE*) branch="stable/$(echo "$rel" | cut -d. -f1)" ;; *-CURRENT*) branch=main ;; esac
    command -v git >/dev/null || { echo "no git: run the install step first" >&2; exit 1; }
    git clone --depth 1 --branch "$branch" https://git.FreeBSD.org/src.git /usr/src || exit 1
    [ -f /usr/src/sys/sys/param.h ] || { echo "no /usr/src/sys/sys/param.h after the clone" >&2; exit 1; }
    echo "kernel sources: cloned $branch"
    ;;

build)
    if [ "$(id -u)" -eq 0 ]; then echo "build must run as a normal user" >&2; exit 1; fi
    {
        header
        if [ ! -f /usr/src/sys/sys/param.h ]; then
            echo "no kernel sources in /usr/src/sys: the C will not build (run the sources step as root)"
        fi
        rm -rf "$DIR" && mkdir -p "$DIR" && chmod 755 "$DIR"
        if [ -n "$SRC" ]; then
            # A copy without what a build left there.
            mkdir "$DIR/src" || exit 1
            (cd "$SRC" && tar --exclude ./lsof-rs/target --exclude ./lsof-rs/fuzz/target -cf - .) \
                | tar -C "$DIR/src" -xf - || exit 1
            (cd "$DIR/src" && [ -f Makefile ] && make distclean >/dev/null 2>&1)
        else
            git clone -q --depth 1 -b "$BRANCH" "$REPO" "$DIR/src" || exit 1
        fi
        header
        cd "$DIR/src" || exit 1
        echo "=== build the C lsof (autotools, as .cirrus.yml does)"
        { autoreconf -vif && ./configure && make lsof; } > "$DIR/c-build.log" 2>&1
        echo "rc=$?"; tail -5 "$DIR/c-build.log"
        echo "=== build lsof-rs"
        cd lsof-rs || exit 1
        cargo build --release 2>&1 | tail -20; echo "rc=$?"
        echo "=== lsof-rs tests (FreeBSD backend, core, cli), every suite to its end"
        cargo test -p lsof-backend-freebsd -p lsof-core -p lsof-cli --no-fail-fast 2>&1 \
            | grep -E '^(test result|failures:|    [a-z_:]+$|---- |thread |error|     Running)' | head -300
        echo "=== done"
    } > "$out" 2>&1
    echo "wrote $out"
    ;;

compare)
    C=${LSOF_C:-$DIR/src/lsof}
    RS=${LSOF_RS:-$DIR/src/lsof-rs/target/release/lsof}
    [ -x "$C" ] && [ -x "$RS" ] || { echo "run the build step first (or set LSOF_C and LSOF_RS)" >&2; exit 1; }
    mkdir -p "$DIR" 2>/dev/null
    work="$DIR/work-$me"
    rm -rf "$work"; mkdir -p "$work/small" "$work/big" || exit 1
    for i in 1 2 3 4 5; do : > "$work/small/f$i"; done
    (cd "$work/big" && jot 50000 | xargs touch)

    # Two fixtures of our own, built with the base system's compiler: a
    # process holding one socket of each kind lsof names differently, and one
    # with four threads. Without a compiler those comparisons are skipped.
    cat > "$work/socks.c" <<'EOF'
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static void at(int fd, int want) {
    if (fd < 0) fd = open("/dev/null", O_RDONLY);
    if (fd != want) { dup2(fd, want); close(fd); }
}
static struct sockaddr_in a4(const char *ip, int port) {
    struct sockaddr_in s; memset(&s, 0, sizeof s);
    s.sin_len = sizeof s; s.sin_family = AF_INET; s.sin_port = htons(port);
    inet_pton(AF_INET, ip, &s.sin_addr); return s;
}
static struct sockaddr_in6 a6(const char *ip, int port) {
    struct sockaddr_in6 s; memset(&s, 0, sizeof s);
    s.sin6_len = sizeof s; s.sin6_family = AF_INET6; s.sin6_port = htons(port);
    inet_pton(AF_INET6, ip, &s.sin6_addr); return s;
}
int main(int argc, char **argv) {
    int b = argc > 1 ? atoi(argv[1]) : 41000, off = 0, i;
    struct sockaddr_in s4; struct sockaddr_in6 s6;
    for (i = 3; i < 40; i++) close(i);
    at(socket(AF_INET, SOCK_STREAM, 0), 3);                     /* TCP, unbound */
    at(socket(AF_INET, SOCK_STREAM, 0), 4);                     /* TCP listener */
    s4 = a4("127.0.0.1", b); bind(4, (void *)&s4, sizeof s4); listen(4, 5);
    at(socket(AF_INET, SOCK_STREAM, 0), 5);                     /* its client */
    connect(5, (void *)&s4, sizeof s4);
    at(accept(4, NULL, NULL), 6);                               /* and the accepted end */
    at(socket(AF_INET, SOCK_DGRAM, 0), 7);                      /* UDP, unbound */
    at(socket(AF_INET, SOCK_DGRAM, 0), 8);                      /* UDP, bound */
    s4 = a4("127.0.0.1", b + 1); bind(8, (void *)&s4, sizeof s4);
    at(socket(AF_INET, SOCK_DGRAM, 0), 9);                      /* UDP, connected */
    connect(9, (void *)&s4, sizeof s4);
    at(socket(AF_INET6, SOCK_STREAM, 0), 10);                   /* TCP6, unbound */
    at(socket(AF_INET6, SOCK_STREAM, 0), 11);                   /* TCP6 listener */
    s6 = a6("::1", b + 2); bind(11, (void *)&s6, sizeof s6); listen(11, 5);
    at(socket(AF_INET6, SOCK_STREAM, 0), 12);
    connect(12, (void *)&s6, sizeof s6);
    at(accept(11, NULL, NULL), 13);
    at(socket(AF_INET6, SOCK_DGRAM, 0), 14);                    /* UDP6, unbound */
    at(socket(AF_INET6, SOCK_DGRAM, 0), 15);                    /* UDP6, bound */
    s6 = a6("::1", b + 3); bind(15, (void *)&s6, sizeof s6);
    at(socket(AF_INET6, SOCK_DGRAM, 0), 16);                    /* UDP6, connected */
    connect(16, (void *)&s6, sizeof s6);
    at(socket(AF_INET6, SOCK_STREAM, 0), 17);                   /* dual-stack listener */
    setsockopt(17, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof off);
    s6 = a6("::", b + 4); bind(17, (void *)&s6, sizeof s6); listen(17, 5);
    at(socket(AF_INET, SOCK_STREAM, 0), 18);                    /* its IPv4 client */
    s4 = a4("127.0.0.1", b + 4); connect(18, (void *)&s4, sizeof s4);
    at(accept(17, NULL, NULL), 19);                             /* IPv6, v4-mapped ends */
    at(socket(AF_INET6, SOCK_DGRAM, 0), 20);                    /* UDP6 on a mapped address */
    setsockopt(20, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof off);
    s6 = a6("::ffff:127.0.0.1", b + 5); bind(20, (void *)&s6, sizeof s6);
    at(socket(AF_INET, SOCK_RAW, 1), 21);                       /* raw (root) */
    at(socket(AF_INET6, SOCK_RAW, 58), 22);                     /* raw6 (root) */
    at(socket(AF_ROUTE, SOCK_RAW, 0), 23);                      /* routing */
    at(socket(AF_INET, SOCK_DGRAM, 136), 24);                   /* UDP-Lite */
    at(socket(AF_INET, SOCK_STREAM, 0), 25);                    /* a client that shut down */
    s4 = a4("127.0.0.1", b); connect(25, (void *)&s4, sizeof s4); shutdown(25, SHUT_WR);
    at(accept(4, NULL, NULL), 26);
    puts("ready"); fflush(stdout);
    pause();
    return 0;
}
EOF
    cat > "$work/threads.c" <<'EOF'
#include <pthread.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
static void *idle(void *arg) { (void)arg; for (;;) pause(); return NULL; }
int main(void) {
    pthread_t t[3]; int i;
    (void)open("/etc/passwd", O_RDONLY);
    for (i = 0; i < 3; i++) pthread_create(&t[i], NULL, idle, NULL);
    sleep(1); puts("ready"); fflush(stdout);
    for (;;) pause();
}
EOF
    port=$(( 41000 + $(id -u) % 500 * 20 ))
    SK=; TH=
    if (cd "$work" && cc -o socks socks.c && cc -o threads threads.c -lpthread) > "$work/cc.log" 2>&1; then
        "$work/socks" "$port" > "$work/socks.out" 2>&1 < /dev/null & SK=$!
        "$work/threads" > "$work/threads.out" 2>&1 < /dev/null & TH=$!
    fi

    # Fixtures: a plain reader, a kqueue user (tail -f), a TCP listener.
    sleep 600 < /etc/passwd & P=$!
    tail -f /etc/passwd > /dev/null 2>&1 & K=$!
    nc -l 127.0.0.1 39999 > /dev/null 2>&1 & N=$!
    trap 'kill $P $K $N $SK $TH 2>/dev/null' EXIT INT TERM
    sleep 2
    S=$$

    same=0; differ=0
    # run ARGS...: both binaries, byte for byte.
    # runu ARGS...: the same, the C's usage block and lsof-rs's usage line
    #   left out (DIVERGENCES 114): for an option error.
    # runo ARGS...: the same, the rows of processes named lsof left out: for
    #   a listing that holds the lsof that makes it (its path, PID and
    #   output file are its own).
    # runj ARGS...: the same, "lsof_version" masked (DIVERGENCES 91): JSON.
    # runjs ARGS...: as runj, and the "name" lsof-rs gives an Internet
    #   socket's object left out, which the C's has none of (DIVERGENCES
    #   134): JSON that holds such sockets.
    # runs ARGS...: the same, of lsof's own numbered descriptors: its PID,
    #   and its output file's name and inode, masked.
    cmp_runs() {
        how=$1; shift
        echo "=== lsof $*"
        "$C" "$@" > "$work/c.out" 2>&1; crc=$?
        "$RS" "$@" > "$work/rs.out" 2>&1; rrc=$?
        echo "rc: C=$crc lsof-rs=$rrc   lines: C=$(wc -l < "$work/c.out") lsof-rs=$(wc -l < "$work/rs.out")"
        case "$how" in
        usage)
            sed -e '/^lsof [0-9][0-9.]*$/,/^Use the ``-h/d' "$work/c.out" > "$work/c.cmp"
            sed -e "/^Try 'lsof -h' for usage\.\$/d" "$work/rs.out" > "$work/rs.cmp"
            note=" (the usage block and the usage line aside)" ;;
        own)
            grep -v '^lsof  *[0-9]' "$work/c.out" > "$work/c.cmp"
            grep -v '^lsof  *[0-9]' "$work/rs.out" > "$work/rs.cmp"
            note=" (the rows of the lsof processes aside: C $(grep -c '^lsof  *[0-9]' "$work/c.out"), lsof-rs $(grep -c '^lsof  *[0-9]' "$work/rs.out"))" ;;
        json)
            sed -e 's/"lsof_version":"[^"]*"/"lsof_version":"V"/' "$work/c.out" > "$work/c.cmp"
            sed -e 's/"lsof_version":"[^"]*"/"lsof_version":"V"/' "$work/rs.out" > "$work/rs.cmp"
            note=" (lsof_version aside)" ;;
        jsonsock)
            for f in c rs; do
                sed -e 's/"lsof_version":"[^"]*"/"lsof_version":"V"/' \
                    -e 's/\("type":"IPv[46]"[^{}]*\),"name":"[^"]*"/\1/g' "$work/$f.out" > "$work/$f.cmp"
            done
            note=" (lsof_version, and lsof-rs's name of each Internet socket: $(grep -o '"type":"IPv[46]"[^{}]*,"name":"[^"]*"' "$work/rs.out" | wc -l | tr -d ' '), aside)" ;;
        self)
            for f in c rs; do
                sed -E -e 's/^lsof +[0-9]+ /lsof PID /' \
                    -e 's/ +[0-9]+ ([^ ]*)\/(c|rs)\.out / NODE \1\/X.out /' "$work/$f.out" > "$work/$f.cmp"
            done
            note=" (lsof's PID and its output file's name and inode aside)" ;;
        *)
            cp "$work/c.out" "$work/c.cmp"; cp "$work/rs.out" "$work/rs.cmp"; note= ;;
        esac
        if [ "$crc" = "$rrc" ] && cmp -s "$work/c.cmp" "$work/rs.cmp"; then
            echo "SAME$note"; same=$((same + 1))
        else
            diff -u "$work/c.cmp" "$work/rs.cmp" | head -300; differ=$((differ + 1))
        fi
        echo
    }
    run() { cmp_runs exact "$@"; }
    runu() { cmp_runs usage "$@"; }
    runo() { cmp_runs own "$@"; }
    runj() { cmp_runs json "$@"; }
    runjs() { cmp_runs jsonsock "$@"; }
    runs() { cmp_runs self "$@"; }

    {
        header
        echo "C:       $C"
        echo "lsof-rs: $RS"
        echo "fixtures: sleep=$P tail=$K nc=$N shell=$S socks=${SK:-none} threads=${TH:-none}"; echo
        # The C keeps a device cache file in the home directory, lsof-rs
        # none (DIVERGENCES 148). What the C says of it on its first run is
        # shown here, once, so that no comparison below holds it.
        echo "=== the C's device cache, as its first run finds it"
        "$C" -n -P -p "$P" 2>&1 >/dev/null | grep -i 'cache' || echo "(nothing said)"
        "$C" -D '?' 2>&1 | grep 'Personal path:' | sort -u
        echo
        # Row 142: +f c/f/g/G/n and their -F / JSON forms.
        run -n -P -p "$P"
        run -n -P +fcfgn -p "$P"
        run -n -P +fG -p "$P"
        run -n -P -F pfnCFGN -p "$P"
        runj -n -P -J -p "$P"
        run -n -P -j -p "$P"
        # Row 145: KQUEUE DEVICE.
        run -n -P -a -p "$K"
        run -n -P -a -p "$K" -F pfdtD
        # Row 147: -T f / q / s, socket options, state, TCP flags, MSS.
        run -n -P -a -p "$N" -T fqs
        run -n -P -a -p "$N" -F pfnT
        runjs -n -P -a -p "$N" -J
        run -n -P -i -T fqs
        run -n -P -U -a -p "$S"
        # Row 146: device names; terminals.
        run -n -P -a -d 0-2 -p "$S"
        run -n -P /dev/null
        # Rows 143/144/182: mount points, +d/+D, -S, -b, -O.
        runo -n -P /
        run -n -P +d "$work/small"
        run -n -P -S 2 +D "$work/small"
        run -n -P -b -p "$P"
        run -n -P -O -p "$P"
        # Row 141: -K.
        runo -n -P -K -p "$P"
        # Row 39 on FreeBSD: user names.
        runu -n -P -u nosuch-user-x
        run -n -P -a -u "$me" -p "$P"
        run -n -P -l -p "$P"
        # The whole host: as it is (the lsof that lists is its own), and with
        # the lsof processes' rows left out.
        run -n -P
        runo -n -P

        # Row 182: what reads no mount table and starts no helper.
        run -n -P -b -N
        run -n -P -b -U
        runo -n -P -b
        run -n -P -N
        run -n -P -b /
        run -n -P -w -b /
        runs -n -P -c lsof -a -d 0-9
        # A pipe is a row under -i beside another selector (Selinet is not set).
        runo -n -P -u "$me" -i TCP:1
        run -n -P -V -K -a -p "$P" -U
        # Row 148: -D, which the C reads and lsof-rs reads and ignores.
        run -n -P -D i -p "$P"
        run -n -P -D r -p "$P"
        runu -n -P -D x -p "$P"
        runu -n -P -D
        runu -n -P -D '??'
        echo "=== lsof -D ? (the C reports its cache paths, lsof-rs that it has none)"
        "$C" -D '?' > "$work/c.out" 2>&1; crc=$?
        "$RS" -D '?' > "$work/rs.out" 2>&1; rrc=$?
        echo "rc: C=$crc lsof-rs=$rrc"
        echo "--- C"; cat "$work/c.out"
        echo "--- lsof-rs"; cat "$work/rs.out"; echo
        # Row 183: the options FreeBSD's C has and has not.
        runu -n -P -e /tmp -p "$P"
        runu -n -P -E -p "$P"
        runu -n -P -X -p "$P"
        runu -n -P -Z -p "$P"
        run -n -P -M -p "$P"
        run -n -P +M -p "$P"
        runu -n -P -s UDP:Idle
        runu -n -P -s TCP:CLOSE
        runu -n -P -K x
        if [ -n "$SK" ]; then
            # Row 180: Internet sockets, each kind; -i by end and by family.
            run -n -P -a -p "$SK" -d 3-30
            run -n -P -a -p "$SK" -d 3-30 -T fqs
            run -n -P -a -p "$SK" -d 3-30 -F fnPtT
            runjs -n -P -a -p "$SK" -d 3-30 -J
            for spec in '' 4 6 TCP UDP :0 :0-5 :1-65535 @127.0.0.1 '@[::1]' 4TCP 6TCP 4UDP 6UDP \
                "4:$((port + 4))" "6:$((port + 4))" "4:$((port + 5))" "6:$((port + 5))" "TCP@127.0.0.1:$port"; do
                run -n -P -a -p "$SK" -F f -i$spec
            done
            # Row 181: -s with -i.
            run -n -P -a -p "$SK" -F f -i -s TCP:CLOSED
            run -n -P -a -p "$SK" -F f -i -s TCP:LISTEN
            run -n -P -a -p "$SK" -F f -i -s TCP:^LISTEN
            run -n -P -a -p "$SK" -F f -i 4 -s TCP:ESTABLISHED
            run -n -P -a -p "$SK" -F f -s TCP:LISTEN
        else
            echo "=== no compiler: the socket and thread fixtures were not built"; cat "$work/cc.log"; echo
        fi
        if [ -n "$TH" ]; then
            # Row 141: tasks, of a process with four threads and of one with one.
            run -n -P -K -a -p "$TH"
            run -n -P -K -a -p "$TH" -d 0,3 -F pKMcftn
            runj -n -P -K -a -p "$TH" -d 3 -J
            run -n -P -K -a -p "$TH" -d 3 -j
            run -n -P -K -a -p "$TH" -t
            run -n -P -K -a -p "$P"
            run -n -P -K i -a -p "$TH"
            run -n -P -a -p "$TH"
            run -n -P -V -K -a -p 99999
            run -n -P -V -K -a -p "$TH" -U
            run -n -P -K -a -c threads -d cwd -R -g
        fi

        echo "=== large directory, +d over 50000 files (seconds)"
        for b in "$C" "$RS"; do
            t0=$(date +%s)
            "$b" -n -P +d "$work/big" > /dev/null 2>&1
            echo "$b rc=$? $(( $(date +%s) - t0 ))s"
        done
        echo
        echo "=== the helper's hidden argument from a terminal or /dev/null must be refused"
        "$RS" --lsof-rs-freebsd-bounded-calls-helper < /dev/null; echo "rc=$?"
        echo
        echo "=== summary: $same comparisons the same, $differ with a difference"
        echo "=== done"
    } > "$out" 2>&1
    echo "wrote $out"
    ;;

*)
    sed -n '2,31p' "$0"
    exit 2
    ;;
esac
