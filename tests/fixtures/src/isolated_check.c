#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A check reached only through a helper, guarded by a "bomb" on the wrong answer. Solving
   it from `main` would wade through argv setup; solving `check` in isolation with a
   symbolic buffer (--from) goes straight at the condition, the way a bomb phase is cracked. */
__attribute__((noinline)) void boom(void) {
    puts("BOOM");
    exit(1);
}

__attribute__((noinline)) void check(const char *s) {
    if (strcmp(s, "sesame") != 0) {
        boom();
    }
    puts("open");
}

int main(int argc, char **argv) {
    if (argc > 1) {
        check(argv[1]);
    }
    return 0;
}
