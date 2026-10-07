/* A staged driver in the shape of a binary bomb: a loop reads one line per phase, and
   every phase gates on a shared explode() sink that ends the program. Each phase here is
   independently solvable, so `solve --chain` can detect the phases and the sink, crack
   each in isolation, and chain the per-phase lines into the input the whole program takes. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void explode(void) {
    puts("BOOM");
    exit(1);
}

static void read_line(char *buffer, int size) {
    if (!fgets(buffer, size, stdin)) {
        explode();
    }
    size_t length = strlen(buffer);
    if (length && buffer[length - 1] == '\n') {
        buffer[length - 1] = '\0';
    }
}

static void phase_1(const char *line) {
    if (strcmp(line, "open sesame") != 0) {
        explode();
    }
    puts("Phase 1 defused.");
}

static void phase_2(const char *line) {
    int a, b;
    if (sscanf(line, "%d %d", &a, &b) != 2) {
        explode();
    }
    if (a != 3 || a + b != 10) {
        explode();
    }
    puts("Phase 2 defused.");
}

static void phase_3(const char *line) {
    int value;
    if (sscanf(line, "%d", &value) != 1) {
        explode();
    }
    if (value != 42) {
        explode();
    }
    puts("Phase 3 defused.");
}

int main(void) {
    char line[128];
    read_line(line, sizeof line);
    phase_1(line);
    read_line(line, sizeof line);
    phase_2(line);
    read_line(line, sizeof line);
    phase_3(line);
    puts("Congratulations! All phases defused.");
    return 0;
}
