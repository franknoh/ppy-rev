#include <ctype.h>
#include <stdio.h>
#include <string.h>

/* Every character is classified; only the right mix of classes and a checksum pass. */
int main(int argc, char **argv) {
    if (argc != 2 || strlen(argv[1]) != 12) {
        puts("Nope");
        return 1;
    }
    unsigned digits = 0, upper = 0, lower = 0, sum = 0;
    for (size_t i = 0; i < 12; i++) {
        unsigned char c = (unsigned char)argv[1][i];
        if (isdigit(c)) {
            digits++;
            sum = sum * 3 + (unsigned)(c - '0');
        } else if (isupper(c)) {
            upper++;
            sum ^= (unsigned)c << (i % 8);
        } else if (islower(c)) {
            lower++;
            sum += (unsigned)c * 7;
        } else {
            puts("Nope");
            return 1;
        }
    }
    if (digits == 4 && upper == 4 && lower == 4 && (sum & 0xfff) == 0x5a1) {
        puts("Correct!");
        return 0;
    }
    puts("Nope");
    return 1;
}
