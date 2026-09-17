#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const unsigned char target[16] = {
    0x21, 0x3e, 0x64, 0x07, 0x3b, 0x6b, 0x35, 0x68, 0x2f, 0x27,
    0x00, 0x51, 0x12, 0x3d, 0x0c, 0x0f,
};

int main(void) {
    unsigned char buffer[32];
    ssize_t count = read(0, buffer, sizeof buffer);
    if (count < 16) {
        puts("Too short");
        return 1;
    }
    for (int i = 0; i < 16; i++) {
        buffer[i] ^= (unsigned char)(0x55 + i);
    }
    if (memcmp(buffer, target, sizeof target) == 0) {
        puts("Success!");
        return 0;
    }
    puts("Nope.");
    return 1;
}
