/* freebsd-regex.c: the oracle behind crates/lsof-core/tests/posix_regex_freebsd.txt
 * (DIVERGENCES 183). On FreeBSD, under LC_CTYPE=C.UTF-8:
 *   cc -O2 -o freebsd-regex freebsd-regex.c
 *   ./freebsd-regex < table-in.txt > posix_regex_freebsd.txt
 * The input is posix_regex_glibc.txt's shape (an H line of hex commands, then a hex
 * expression and its flags a line; any answer after them is ignored); the output the
 * same lines with this libc's answer: a 0 or 1 a command, or ! and regerror()'s text.
 */
#include <locale.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int unhex(const char *t, size_t n, char *out) {
    if (n == 1 && t[0] == '-') { out[0] = 0; return 0; }
    for (size_t i = 0; i + 1 < n + 1 && i < n; i += 2) {
        unsigned v; sscanf(t + i, "%2x", &v); out[i / 2] = (char)v;
    }
    out[n / 2] = 0; return (int)(n / 2);
}
static char cmds[256][256]; static int ncmd;
int main(void) {
    setlocale(LC_CTYPE, "");
    static char line[1 << 16];
    while (fgets(line, sizeof line, stdin)) {
        line[strcspn(line, "\n")] = 0;
        if (line[0] == '#') continue;
        if (line[0] == 'H' && line[1] == ' ') {
            printf("%s\n", line);
            char *p = line + 2;
            while (*p) {
                char *e = strchr(p, ' '); size_t n = e ? (size_t)(e - p) : strlen(p);
                if (n) unhex(p, n, cmds[ncmd++]);
                if (!e) break; p = e + 1;
            }
            continue;
        }
        char *sp1 = strchr(line, ' '); if (!sp1) continue; *sp1 = 0;
        char *flags = sp1 + 1; char *sp2 = strchr(flags, ' '); if (sp2) *sp2 = 0;
        static char expr[1 << 15]; unhex(line, strlen(line), expr);
        int co = REG_NOSUB;
        if (!strchr(flags, 'b')) co |= REG_EXTENDED;
        if (strchr(flags, 'i')) co |= REG_ICASE;
        regex_t r; int rc = regcomp(&r, expr, co);
        printf("%s %s ", line, flags);
        if (rc) { char b[256]; regerror(rc, &r, b, sizeof b); printf("!%s\n", b); continue; }
        for (int i = 0; i < ncmd; i++) putchar(regexec(&r, cmds[i], 0, NULL, 0) == 0 ? '1' : '0');
        putchar('\n'); regfree(&r);
    }
    return 0;
}
