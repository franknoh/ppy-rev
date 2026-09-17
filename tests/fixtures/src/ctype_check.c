#include <ctype.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    static const char expected[] = "RDTFVVOI";
    if (argc != 2 || strlen(argv[1]) != sizeof expected - 1) {
        puts("Nope");
        return 1;
    }
    for (size_t i = 0; argv[1][i]; i++) {
        unsigned char c = (unsigned char)argv[1][i];
        if (!isalpha(c)) {
            puts("Nope");
            return 1;
        }
        if ((toupper(c) ^ (int)i) != expected[i]) {
            puts("Nope");
            return 1;
        }
    }
    puts("Well done");
    return 0;
}
