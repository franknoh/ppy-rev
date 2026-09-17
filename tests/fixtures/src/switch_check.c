#include <stdio.h>
#include <string.h>

__attribute__((noinline)) static int step(int state, char c) {
    switch (state) {
    case 0: return c == 'S' ? 1 : -1;
    case 1: return c == 'W' ? 2 : -1;
    case 2: return c == 'I' ? 3 : -1;
    case 3: return c == 'T' ? 4 : -1;
    case 4: return c == 'C' ? 5 : -1;
    case 5: return c == 'H' ? 6 : -1;
    default: return -1;
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        return 2;
    }
    int state = 0;
    for (const char *p = argv[1]; *p != '\0' && state >= 0; p++) {
        state = step(state, *p);
    }
    if (state == 6) {
        puts("You got it");
        return 0;
    }
    puts("Nope");
    return 1;
}
