/* The success message is a printf format, so its text never appears in the output verbatim. */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 2 || strcmp(argv[1], "0pen") != 0) {
        puts("Denied");
        return 1;
    }
    printf("Welcome back, %s! Your flag is CTF{%s_sesame}\n", argv[1], argv[1]);
    return 0;
}
