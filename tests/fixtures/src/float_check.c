#include <stdio.h>
#include <stdlib.h>

/* Floating point in the check itself: int to double, arithmetic, and comparisons. */
int main(int argc, char **argv) {
    if (argc != 2) {
        puts("usage: float_check <number>");
        return 2;
    }
    double value = (double)atoi(argv[1]);
    double scaled = value * 1.5 + 0.25;
    if (scaled > 63.0 && scaled < 64.0 && (int)scaled == 63) {
        puts("Correct!");
        return 0;
    }
    puts("Wrong!");
    return 1;
}
