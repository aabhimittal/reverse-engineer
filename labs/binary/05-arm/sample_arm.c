/*
 * ARM / AArch64 lab: a freestanding program with a password check, a checksum loop and calls
 * into a shared library through the PLT. Built for aarch64 and 32-bit ARM by
 * scripts/build-fixtures.sh. Never run; it exists to be analysed.
 */
extern int stub_log(const char *msg);
extern void stub_exit(int code) __attribute__((noreturn));

static const char banner[] = "rex arm lab";
static const char secret[] = "open-sesame";

static int streq(const char *a, const char *b) {
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return *a == *b;
}

__attribute__((noinline)) int check(const char *pw) { return streq(pw, secret); }

__attribute__((noinline)) unsigned checksum(const unsigned char *p, unsigned n) {
    unsigned s = 0;
    for (unsigned i = 0; i < n; i++)
        s += p[i];
    return s;
}

int main(int argc, char **argv) {
    stub_log(banner);
    if (argc > 1 && check(argv[1])) {
        stub_log("access granted");
        return (int)checksum((const unsigned char *)banner, sizeof banner);
    }
    stub_log("denied");
    stub_exit(1);
}

#if defined(__aarch64__)
/* Same shape as glibc's _start: main's address goes in x0 for __libc_start_main.
 * GOT_START builds the form glibc's PIE crt1 uses: load main's address from its GOT slot. */
extern int __libc_start_main(int (*)(int, char **), int, char **);
#if defined(GOT_START)
#define LOAD_MAIN "  adrp x0, :got:main\n  ldr x0, [x0, :got_lo12:main]\n"
#else
#define LOAD_MAIN "  adrp x0, main\n  add x0, x0, :lo12:main\n"
#endif
__asm__(".globl _start\n_start:\n"
        "  mov x29, #0\n  mov x30, #0\n"
        "  ldr x1, [sp]\n  add x2, sp, #8\n"
        LOAD_MAIN
        "  bl __libc_start_main\n  brk #0\n");
#else
void start_c(long *sp) {
    int argc = (int)*sp;
    stub_exit(main(argc, (char **)(sp + 1)));
}
__asm__(".arm\n.globl _start\n_start:\n  mov r0, sp\n  bl start_c\n  udf #0\n");
#endif
