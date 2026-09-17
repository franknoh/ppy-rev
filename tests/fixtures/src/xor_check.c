#include <stdio.h>
#include <string.h>

static const unsigned char expected[] = {
    0x30, 0x27, 0x34, 0x1d, 0x2b, 0x31, 0x1d, 0x27, 0x23, 0x31, 0x3b,
};

__attribute__((noinline)) static int check(const char *input) {
    if (strlen(input) != sizeof(expected)) {
        return 0;
    }
    for (size_t i = 0; i < sizeof(expected); i++) {
        if ((unsigned char)(input[i] ^ 0x42) != expected[i]) {
            return 0;
        }
    }
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        puts("usage: xor_check <input>");
        return 2;
    }
    if (check(argv[1])) {
        puts("Correct!");
        return 0;
    }
    puts("Wrong!");
    return 1;
}
