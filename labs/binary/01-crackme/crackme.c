/*
 * Lab 01: crackme
 *
 * A classic first reversing exercise: find the password without reading
 * this source. Build with `make` (see labs/Makefile), then use
 *
 *     rex analyze build/crackme
 *     rex disasm build/crackme --function check_password
 *
 * The password is not stored in plain text: it is XOR-encoded, so `strings`
 * alone will not reveal it. You must read the code.
 */
#include <stdio.h>
#include <string.h>

static const unsigned char secret[] = {0x31, 0x2c, 0x33, 0x26, 0x31, 0x30, 0x26, 0x7a, 0x00};
#define KEY 0x43 /* 'C' */

int check_password(const char *input) {
    size_t n = strlen(input);
    if (n != sizeof(secret) - 1) {
        return 0;
    }
    for (size_t i = 0; i < n; i++) {
        if ((unsigned char)(input[i] ^ KEY) != secret[i]) {
            return 0;
        }
    }
    return 1;
}

static void banner(void) {
    puts("== rex lab 01: crackme ==");
    puts("Find the password. Hint: https://github.com/aabhimittal/reverse-engineer/tree/main/labs");
}

int main(int argc, char **argv) {
    banner();
    if (argc != 2) {
        printf("usage: %s <password>\n", argv[0]);
        return 2;
    }
    if (check_password(argv[1])) {
        puts("Access granted. Well done!");
        return 0;
    }
    puts("Access denied.");
    return 1;
}
