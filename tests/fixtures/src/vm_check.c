/* A small stack-machine crackme: the check runs as bytecode inside an interpreter loop. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum {
    OP_HALT = 0x00,
    OP_PUSH = 0x11, /* push imm8 */
    OP_INPUT = 0x22, /* push input[imm8] */
    OP_XOR = 0x33,
    OP_ADD = 0x44,
    OP_MUL = 0x55,
    OP_JNE = 0x66, /* pop b, pop a; if a != b jump to imm8 */
    OP_FAIL = 0x77,
    OP_DUP = 0x88,
};

static const uint8_t program[] = {
    0x22, 0, 0x11, 0x5a, 0x33, 0x11, 0x0c, 0x66, 59,
    0x22, 1, 0x22, 2, 0x44, 0x11, 0xcc, 0x66, 59,
    0x22, 2, 0x11, 3, 0x55, 0x11, 0x1d, 0x66, 59,
    0x22, 3, 0x88, 0x44, 0x11, 0x60, 0x66, 59,
    0x22, 4, 0x11, 0x13, 0x33, 0x22, 5, 0x44, 0x11, 0x99, 0x66, 59,
    0x22, 5, 0x11, 0x21, 0x66, 59,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x77,
};

__attribute__((noinline)) static int run(const uint8_t *input) {
    uint8_t stack[16];
    unsigned sp = 0;
    unsigned pc = 0;
    for (;;) {
        uint8_t op = program[pc++];
        switch (op) {
        case OP_HALT:
            return 1;
        case OP_PUSH:
            stack[sp++] = program[pc++];
            break;
        case OP_INPUT:
            stack[sp++] = input[program[pc++]];
            break;
        case OP_XOR:
            sp--;
            stack[sp - 1] ^= stack[sp];
            break;
        case OP_ADD:
            sp--;
            stack[sp - 1] += stack[sp];
            break;
        case OP_MUL:
            sp--;
            stack[sp - 1] *= stack[sp];
            break;
        case OP_DUP:
            stack[sp] = stack[sp - 1];
            sp++;
            break;
        case OP_JNE: {
            uint8_t target = program[pc++];
            uint8_t b = stack[--sp];
            uint8_t a = stack[--sp];
            if (a != b) {
                pc = target;
            }
            break;
        }
        case OP_FAIL:
        default:
            return 0;
        }
    }
}

int main(int argc, char **argv) {
    if (argc != 2 || strlen(argv[1]) != 6) {
        puts("Denied");
        return 1;
    }
    if (run((const uint8_t *)argv[1])) {
        puts("Granted");
        return 0;
    }
    puts("Denied");
    return 1;
}
