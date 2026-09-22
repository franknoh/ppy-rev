#include <stdio.h>
#include <string.h>

/* A rolling hash compared to a constant. Small input (a 4-digit PIN), but the check is the
   kind of whole-input comparison that is cheaper to brute force than to reason about. The
   constant is the hash of "4271". */
int main(void) {
    char buf[16];
    if (fgets(buf, sizeof buf, stdin) == NULL) {
        return 2;
    }
    buf[strcspn(buf, "\n")] = 0;
    unsigned int h = 5381;
    for (int i = 0; buf[i] != 0; i++) {
        h = ((h << 5) + h) ^ (unsigned char)buf[i];
    }
    if (strlen(buf) == 4 && h == 0x7c515265u) {
        puts("Correct!");
        return 0;
    }
    puts("Wrong");
    return 1;
}
