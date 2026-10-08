#include <stdio.h>
#include <stdlib.h>

/* Each byte is tested twice through a helper that exits on an unprintable byte, and the
   second test sits between the first one and the join, so the loop only collapses to
   one path per byte if a branch region may contain a call that can end the program. A
   mismatch clears the flag rather than breaking out, which is what makes every byte
   matter at once. */

static const unsigned char first[16] = {
    0x6c, 0x31, 0x71, 0x63, 0x36, 0x59, 0x73, 0x60,
    0x3a, 0x55, 0x6c, 0x79, 0x39, 0x7c, 0x6b, 0x21,
};
static const unsigned char second[16] = {
    0x61, 0x32, 0x73, 0x64, 0x35, 0x56, 0x77, 0x68,
    0x39, 0x5a, 0x6b, 0x7c, 0x3d, 0x7e, 0x6f, 0x20,
};

__attribute__((noinline)) static unsigned char scramble(char c, int key) {
    if (c < 0x20 || c == 0x7f) {
        exit(1);
    }
    return (unsigned char)(c ^ (key & 0x0f));
}

int main(void) {
    char line[32] = {0};
    puts("Key:");
    if (fgets(line, sizeof line, stdin) == NULL) {
        return 2;
    }
    int ok = 1;
    for (int i = 0; i < 16; i++) {
        if (scramble(line[i], i + 1) != first[i] || scramble(line[i], first[i]) != second[i]) {
            ok = 0;
        }
    }
    if (ok) {
        puts("Correct!");
        return 0;
    }
    puts("Wrong");
    return 1;
}
