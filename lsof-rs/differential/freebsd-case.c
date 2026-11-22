/* freebsd-case.c: the table behind crates/lsof-core/src/posix_regex/freebsd_case.rs
 * (DIVERGENCES 183). On FreeBSD:
 *   cc -O2 -o freebsd-case freebsd-case.c && ./freebsd-case > casedump.txt
 * A "C c l u ULA" line for every character towlower() or towupper() changes in C.UTF-8
 * (hex; ULA iswupper, iswlower, iswalpha as 0 or 1), then an "A lo hi" line for each
 * range of iswalpha(). freebsd_case.rs is the C lines, sorted, as Rust.
 */
#include <locale.h>
#include <stdio.h>
#include <wctype.h>
int main(void) {
    if (!setlocale(LC_CTYPE, "C.UTF-8")) return 1;
    for (unsigned c = 0; c <= 0x10FFFF; c++) {
        if (c >= 0xD800 && c <= 0xDFFF) continue;
        unsigned l = towlower(c), u = towupper(c);
        if (l != c || u != c)
            printf("C %x %x %x %d%d%d\n", c, l, u, !!iswupper(c), !!iswlower(c), !!iswalpha(c));
    }
    int in = 0; unsigned start = 0;
    for (unsigned c = 0; c <= 0x110000; c++) {
        int a = c <= 0x10FFFF && !(c >= 0xD800 && c <= 0xDFFF) && iswalpha(c);
        if (a && !in) { start = c; in = 1; }
        if (!a && in) { printf("A %x %x\n", start, c - 1); in = 0; }
    }
    return 0;
}
