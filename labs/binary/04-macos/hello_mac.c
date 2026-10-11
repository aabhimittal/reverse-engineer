/* Lab 04: a tiny Mach-O for exploring load commands, stubs and checksec. */
int printf(const char *, ...);
int strcmp(const char *, const char *);
int puts(const char *);

int verify(const char *s) {
    return strcmp(s, "open-sesame") == 0;
}

int main(int argc, char **argv) {
    printf("rex lab 04 (%d args)\n", argc);
    if (argc > 1 && verify(argv[1])) {
        puts("verified");
        return 0;
    }
    puts("nope");
    return 1;
}
