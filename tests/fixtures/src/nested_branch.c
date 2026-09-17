#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        return 2;
    }
    const unsigned char *s = (const unsigned char *)argv[1];
    if (strlen(argv[1]) == 8) {
        if (s[0] == 'n') {
            if ((s[1] ^ s[0]) == 0x01) {
                if (s[2] + s[3] == 0xd1 && s[2] - s[3] == 0x0b) {
                    if ((unsigned char)(s[4] * 3) == 0x3b && s[5] == s[2]) {
                        if (s[6] == '!' && (s[7] | 0x20) == 0x7a && s[7] < 'a') {
                            puts("Congratulations");
                            return 0;
                        }
                    }
                }
            }
        }
    }
    puts("Try again");
    return 1;
}
