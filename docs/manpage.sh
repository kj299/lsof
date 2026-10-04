#!/bin/sh
# Regenerate manpage.md from ../lsof.man, which the autotools `make lsof.man`
# builds (it needs groff's soelim). Check the inputs first: without them this
# used to truncate the tracked manpage.md and still exit 0.
if [ ! -r ../lsof.man ] || ! command -v nroff >/dev/null 2>&1 \
    || ! command -v col >/dev/null 2>&1; then
    echo "manpage.sh: needs ../lsof.man (make lsof.man), nroff and col" >&2
    exit 1
fi
tmp=$(mktemp) || exit 1
{
    echo "# Manpage"
    echo "\`\`\`manpage"
    # nroff: render manpage
    # col: -b remove backspace, -x use spaces instead of tabs
    # cat: -s remove consecutive blank lines
    nroff -man ../lsof.man | col -bx | cat -s
    echo "\`\`\`"
} > "$tmp" && mv "$tmp" manpage.md
