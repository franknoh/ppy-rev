#include <stdio.h>
#include <string.h>

/* Floating point in the check itself: byte to double, arithmetic, comparisons, and a
   truncation back to an integer. One byte of input keeps the solving cheap. */
int main(int argc, char **argv) {
    if (argc != 2 || strlen(argv[1]) != 1) {
        puts("usage: float_check <character>");
        return 2;
    }
    double scaled = (double)(unsigned char)argv[1][0] * 1.5 + 0.25;
    if (scaled > 63.0 && scaled < 64.0 && (int)scaled == 63) {
        puts("Correct!");
        return 0;
    }
    puts("Wrong!");
    return 1;
}
