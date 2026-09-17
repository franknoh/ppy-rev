/* Reports what glibc's scanf, strtol, and ctype functions do, for comparison with the models. */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *const formats[] = {
    "%s",    "%3s",  "%s %s", "%d",   "%2d",     "%d%d",  "%d %d", "%ld",   "%hhd", "%hd",
    "%c",    "%3c",  " %c",   "%*d %d", "x%d",   "%d,%d", "%%%d",  "%s\n",  "%5s%d", "%d %s",
};

static void dump(const unsigned char *buffer) {
    for (int i = 0; i < 16; i++) {
        printf("%02x", buffer[i]);
    }
    printf("\n");
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "strtol") == 0) {
        char *end;
        long value = strtol(argv[2], &end, 10);
        printf("%ld %ld %d\n", value, (long)(end - argv[2]), atoi(argv[2]));
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "ctype") == 0) {
        for (int c = -128; c < 256; c++) {
            printf("%d %d %d %d %d %d %d %d\n", c, isalpha(c), isdigit(c), isspace(c), isalnum(c),
                   ispunct(c), toupper(c), tolower(c));
        }
        return 0;
    }
    if (argc != 3 || strcmp(argv[1], "scanf") != 0) {
        return 2;
    }
    unsigned char buffers[4][64];
    memset(buffers, 0, sizeof buffers);
    int result = scanf(formats[atoi(argv[2])], buffers[0], buffers[1], buffers[2], buffers[3]);
    printf("%d\n", result);
    for (int i = 0; i < 4; i++) {
        dump(buffers[i]);
    }
    int c;
    while ((c = getchar()) != EOF) {
        printf("%02x", c);
    }
    printf("\n");
    return 0;
}
