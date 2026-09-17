#include <stdio.h>

static const unsigned char secret[] = {0x73, 0x61, 0x64, 0x7f, 0x7f, 0x63, 0x7a, 0x60, 0x7c};

__attribute__((noinline)) static int check(const char *text, unsigned index) {
    if (index == sizeof secret) {
        return text[index] == '\0';
    }
    if (((unsigned char)text[index] ^ (index * 3 + 1)) != secret[index]) {
        return 0;
    }
    return check(text, index + 1);
}

int main(int argc, char **argv) {
    if (argc == 2 && check(argv[1], 0)) {
        puts("Correct!");
        return 0;
    }
    puts("Wrong!");
    return 1;
}
