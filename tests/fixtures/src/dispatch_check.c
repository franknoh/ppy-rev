#include <stdio.h>
#include <string.h>

typedef int (*rule)(unsigned char);

__attribute__((noinline)) static int rule_even(unsigned char c) { return (c & 1) == 0; }
__attribute__((noinline)) static int rule_upper(unsigned char c) { return c >= 'A' && c <= 'Z'; }
__attribute__((noinline)) static int rule_digit(unsigned char c) { return c >= '0' && c <= '9'; }
__attribute__((noinline)) static int rule_sum(unsigned char c) { return (c * 7 + 3) % 11 == 5; }

static const rule rules[] = {rule_upper, rule_digit, rule_even, rule_sum};
static const unsigned char order[] = {0, 1, 3, 2, 0, 1, 2, 3};

int main(int argc, char **argv) {
    if (argc != 2 || strlen(argv[1]) != sizeof order) {
        puts("Access denied");
        return 1;
    }
    unsigned total = 0;
    for (size_t i = 0; i < sizeof order; i++) {
        if (!rules[order[i]]((unsigned char)argv[1][i])) {
            puts("Access denied");
            return 1;
        }
        total += (unsigned char)argv[1][i];
    }
    if (total != 500) {
        puts("Access denied");
        return 1;
    }
    puts("Access granted");
    return 0;
}
