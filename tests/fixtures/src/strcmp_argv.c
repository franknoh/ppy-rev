#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char buffer[32];
    if (argc < 2 || strlen(argv[1]) >= sizeof buffer) {
        puts("usage: strcmp_argv <key>");
        return 2;
    }
    size_t i = 0;
    for (; argv[1][i] != '\0'; i++) {
        char c = argv[1][i];
        if (c >= 'a' && c <= 'z') {
            c = (char)('a' + (c - 'a' + 13) % 26);
        }
        buffer[i] = c;
    }
    buffer[i] = '\0';
    if (strcmp(buffer, "ebg13_vf_sha") == 0) {
        puts("Correct!");
        return 0;
    }
    puts("Wrong!");
    return 1;
}
