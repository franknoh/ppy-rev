#include <stdint.h>
#include <stdio.h>
#include <string.h>

__attribute__((noinline)) static uint32_t rotl(uint32_t value, unsigned amount) {
    return (value << (amount & 31)) | (value >> ((32 - amount) & 31));
}

__attribute__((noinline)) static uint32_t mix(uint32_t a, uint32_t b) {
    return rotl(a ^ 0x5bd1e995u, 13) + b * 5u;
}

__attribute__((noinline)) static uint32_t read_word(const char *text) {
    return (uint32_t)(unsigned char)text[0] | (uint32_t)(unsigned char)text[1] << 8 |
           (uint32_t)(unsigned char)text[2] << 16 | (uint32_t)(unsigned char)text[3] << 24;
}

int main(int argc, char **argv) {
    if (argc != 2 || strlen(argv[1]) != 8) {
        puts("Wrong!");
        return 1;
    }
    uint32_t first = read_word(argv[1]);
    uint32_t second = read_word(argv[1] + 4);
    if (mix(first, second) == 0x62a0e076u && mix(second, first) == 0x8591d05cu) {
        puts("Correct!");
        return 0;
    }
    puts("Wrong!");
    return 1;
}
