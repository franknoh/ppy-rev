#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        puts("usage: atoi_check <number>");
        return 2;
    }
    int value = atoi(argv[1]);
    if (value * 7 - 1234 == 85181) {
        puts("Correct!");
        return 0;
    }
    puts("Wrong!");
    return 1;
}
