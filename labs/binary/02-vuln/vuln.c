/*
 * Lab 02: an intentionally vulnerable program with mitigations turned off.
 *
 * Compare `rex checksec build/vuln` with `rex checksec build/crackme`.
 * The Makefile builds this with -fno-stack-protector -no-pie -z execstack
 * -z norelro so that every classic mitigation is missing. DO NOT deploy.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *gets(char *s); /* removed from C11 headers, still exported by glibc */

void win(void) {
    puts("You redirected control flow to win(). Congratulations!");
    system("/bin/echo pwned");
}

void greet(const char *name) {
    char buf[32];
    strcpy(buf, name); /* CWE-120: unbounded copy */
    printf("Hello, %s\n", buf);
}

int main(void) {
    char line[64];
    printf("name? ");
    fflush(stdout);
    gets(line); /* CWE-242: never safe */
    greet(line);
    return 0;
}
