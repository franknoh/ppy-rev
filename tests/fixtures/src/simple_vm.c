/* A register-machine crackme: the input is validated by bytecode run in an interpreter. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct vm {
    uint32_t pc;
    uint32_t reg[8];
    uint32_t flag;
    const uint8_t *code;
    const uint8_t *input;
};

/* Opcodes: LOADI r imm, LOADX r ri (input[reg[ri]]), ADD r r, XOR r r, MULI r imm,
   CMP r r, JNE target, JMP target, DEC r, ANDI r imm, TABLE r ri base, ACCEPT, REJECT. */
static const uint8_t bytecode[] = {
    0x01, 0x01, 0x00, 0x01, 0x02, 0x5b, 0x01, 0x06, 0x08, 0x01, 0x05, 0x01, 0x02, 0x03,
    0x01, 0x04, 0x03, 0x02, 0x0b, 0x04, 0x01, 0x30, 0x06, 0x03, 0x04, 0x07, 0x2f, 0x05,
    0x02, 0x03, 0x01, 0x07, 0x07, 0x03, 0x02, 0x07, 0x0a, 0x02, 0xff, 0x03, 0x01, 0x05,
    0x09, 0x06, 0x07, 0x0c, 0xf0, 0xff, 0x2d, 0x55, 0x10, 0x98, 0xd2, 0xd6, 0x63, 0x6d,
};

__attribute__((noinline)) static int execute(struct vm *vm) {
    for (;;) {
        const uint8_t *at = vm->code + vm->pc;
        switch (at[0]) {
        case 0x01:
            vm->reg[at[1] & 7] = at[2];
            vm->pc += 3;
            break;
        case 0x02:
            vm->reg[at[1] & 7] = vm->input[vm->reg[at[2] & 7]];
            vm->pc += 3;
            break;
        case 0x03:
            vm->reg[at[1] & 7] += vm->reg[at[2] & 7];
            vm->pc += 3;
            break;
        case 0x04:
            vm->reg[at[1] & 7] ^= vm->reg[at[2] & 7];
            vm->pc += 3;
            break;
        case 0x05:
            vm->reg[at[1] & 7] *= at[2];
            vm->pc += 3;
            break;
        case 0x06:
            vm->flag = vm->reg[at[1] & 7] == vm->reg[at[2] & 7];
            vm->pc += 3;
            break;
        case 0x07:
            vm->pc = vm->flag ? vm->pc + 2 : at[1];
            break;
        case 0x08:
            vm->pc = at[1];
            break;
        case 0x09:
            vm->reg[at[1] & 7] -= 1;
            vm->flag = vm->reg[at[1] & 7] == 0;
            vm->pc += 2;
            break;
        case 0x0a:
            vm->reg[at[1] & 7] &= at[2];
            vm->pc += 3;
            break;
        case 0x0b:
            vm->reg[at[1] & 7] = vm->code[at[3] + vm->reg[at[2] & 7]];
            vm->pc += 4;
            break;
        case 0xf0:
            return 1;
        default:
            return 0;
        }
    }
}

int main(int argc, char **argv) {
    if (argc != 2 || strlen(argv[1]) != 8) {
        puts("Rejected");
        return 1;
    }
    struct vm vm = {.code = bytecode, .input = (const uint8_t *)argv[1]};
    if (execute(&vm)) {
        puts("Accepted");
        return 0;
    }
    puts("Rejected");
    return 1;
}
