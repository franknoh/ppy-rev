#include <stdio.h>
#include <string.h>

static const char secret[] = "gh1dr4_p4ss";

__attribute__((noinline)) static void transform(char *text) {
    for (size_t i = 0; text[i] != '\0'; i++) {
        text[i] = (char)(text[i] + (char)(i % 3));
    }
}

int main(void) {
    char buffer[64];
    puts("Password:");
    if (fgets(buffer, sizeof buffer, stdin) == NULL) {
        return 2;
    }
    for (size_t i = 0; buffer[i] != '\0'; i++) {
        if (buffer[i] == '\n') {
            buffer[i] = '\0';
            break;
        }
    }
    transform(buffer);
    if (strcmp(buffer, secret) == 0) {
        puts("Access granted");
        return 0;
    }
    puts("Access denied");
    return 1;
}
