#include <stdint.h>
#include <stdio.h>
#include <string.h>

__attribute__((noinline)) static uint32_t fnv1a(const char *text, size_t length) {
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < length; i++) {
        hash ^= (unsigned char)text[i];
        hash *= 16777619u;
    }
    return hash;
}

int main(int argc, char **argv) {
    if (argc != 2 || strlen(argv[1]) != 4) {
        puts("Wrong");
        return 1;
    }
    for (int i = 0; i < 4; i++) {
        if (argv[1][i] < '0' || argv[1][i] > '9') {
            puts("Wrong");
            return 1;
        }
    }
    if (fnv1a(argv[1], 4) == 0x448760f2u) {
        puts("Correct");
        return 0;
    }
    puts("Wrong");
    return 1;
}
