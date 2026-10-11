/* A tiny shared library the lab links against, so the lab binary has a real PLT. */
int stub_log(const char *msg) { (void)msg; return 0; }
void stub_exit(int code) { (void)code; for (;;) { } }

/* Stands in for glibc so the AArch64 lab's `_start` can follow the real startup convention
 * (main's address is passed as the first argument to __libc_start_main). */
int __libc_start_main(int (*m)(int, char **), int argc, char **argv) {
    stub_exit(m(argc, argv));
    return 0;
}
