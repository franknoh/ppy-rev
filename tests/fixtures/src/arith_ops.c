/* Differential probes: every function maps (a, b) to a 64-bit result.
 * Usage: lines of "name a b" on stdin; prints one decimal result per line. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(__clang__)
#define PROBE __attribute__((noinline, used))
#else
#define PROBE __attribute__((noipa, used))
#endif

PROBE uint64_t add32(uint64_t a, uint64_t b) { return (uint32_t)((uint32_t)a + (uint32_t)b); }
PROBE uint64_t sub8(uint64_t a, uint64_t b) { return (uint8_t)((uint8_t)a - (uint8_t)b); }
PROBE uint64_t mul16(uint64_t a, uint64_t b) { return (uint16_t)((uint16_t)a * (uint16_t)b); }
PROBE uint64_t mul64_high(uint64_t a, uint64_t b) {
    return (uint64_t)(((unsigned __int128)a * b) >> 64);
}
PROBE uint64_t smul64_high(uint64_t a, uint64_t b) {
    return (uint64_t)(((__int128)(int64_t)a * (int64_t)b) >> 64);
}
PROBE uint64_t udiv32(uint64_t a, uint64_t b) { return (uint32_t)a / ((uint32_t)b | 1u); }
PROBE uint64_t sdiv32(uint64_t a, uint64_t b) {
    int32_t d = (int32_t)b;
    if (d == 0 || (d == -1 && (int32_t)a == INT32_MIN)) d = 7;
    return (uint64_t)(int64_t)((int32_t)a / d);
}
PROBE uint64_t srem64(uint64_t a, uint64_t b) {
    int64_t d = (int64_t)b;
    if (d == 0 || (d == -1 && (int64_t)a == INT64_MIN)) d = 13;
    return (uint64_t)((int64_t)a % d);
}
PROBE uint64_t urem64(uint64_t a, uint64_t b) { return a % (b | 1u); }
PROBE uint64_t div_const(uint64_t a, uint64_t b) {
    return (uint64_t)((int64_t)a / 10) ^ (a / 7) ^ (uint64_t)((int32_t)b % -3);
}
PROBE uint64_t shl_var(uint64_t a, uint64_t b) { return (uint32_t)((uint32_t)a << (b & 31)); }
PROBE uint64_t shr_var(uint64_t a, uint64_t b) { return a >> (b & 63); }
PROBE uint64_t sar_var(uint64_t a, uint64_t b) { return (uint64_t)((int64_t)a >> (b & 63)); }
PROBE uint64_t sar16(uint64_t a, uint64_t b) { return (uint16_t)((int16_t)a >> (b & 15)); }
PROBE uint64_t rotl32(uint64_t a, uint64_t b) {
    uint32_t x = (uint32_t)a;
    unsigned r = b & 31;
    return (uint32_t)((x << r) | (x >> ((32 - r) & 31)));
}
PROBE uint64_t rotr8(uint64_t a, uint64_t b) {
    uint8_t x = (uint8_t)a;
    unsigned r = b & 7;
    return (uint8_t)((x >> r) | (x << ((8 - r) & 7)));
}
PROBE uint64_t cmp_signed(uint64_t a, uint64_t b) {
    return (uint64_t)((int32_t)a < (int32_t)b) | ((uint64_t)((int64_t)a <= (int64_t)b) << 1) |
           ((uint64_t)((int8_t)a > (int8_t)b) << 2);
}
PROBE uint64_t cmp_unsigned(uint64_t a, uint64_t b) {
    return (uint64_t)((uint32_t)a < (uint32_t)b) | ((uint64_t)(a >= b) << 1) |
           ((uint64_t)((uint16_t)a == (uint16_t)b) << 2);
}
PROBE uint64_t sext_mix(uint64_t a, uint64_t b) {
    return (uint64_t)((int64_t)(int8_t)a + (int64_t)(int16_t)b);
}
PROBE uint64_t add_carry128(uint64_t a, uint64_t b) {
    unsigned __int128 x = ((unsigned __int128)a << 64) | b;
    unsigned __int128 y = ((unsigned __int128)b << 64) | a;
    unsigned __int128 sum = x + y;
    return (uint64_t)(sum >> 64) ^ (uint64_t)sum;
}
PROBE uint64_t bswap32(uint64_t a, uint64_t b) { return __builtin_bswap32((uint32_t)(a ^ b)); }
PROBE uint64_t clz64(uint64_t a, uint64_t b) {
    uint64_t x = a | b;
    return x ? (uint64_t)__builtin_clzll(x) : 64;
}
PROBE uint64_t popcount64(uint64_t a, uint64_t b) { return (uint64_t)__builtin_popcountll(a ^ b); }
PROBE uint64_t cond_select(uint64_t a, uint64_t b) {
    return (int64_t)a > (int64_t)b ? a - b : b * 3;
}
PROBE uint64_t overflow_check(uint64_t a, uint64_t b) {
    int32_t r;
    uint64_t overflow = __builtin_add_overflow((int32_t)a, (int32_t)b, &r);
    return overflow | ((uint64_t)(uint32_t)r << 1);
}
PROBE uint64_t neg_not(uint64_t a, uint64_t b) { return (uint64_t)(-(int64_t)a) ^ ~b; }
PROBE uint64_t bool_logic(uint64_t a, uint64_t b) {
    return (uint64_t)((a && !b) || ((a & 1) != (b & 1)));
}
PROBE uint64_t loop_sum(uint64_t a, uint64_t b) {
    uint64_t s = 0;
    for (unsigned i = 0; i < (b & 15); i++) s = s * 31 + (a >> i);
    return s;
}
PROBE uint64_t switch_table(uint64_t a, uint64_t b) {
    switch (a % 8) {
    case 0: return b;
    case 1: return b + 1;
    case 2: return b ^ 0x55;
    case 3: return b << 3;
    case 4: return ~b;
    case 5: return b * b;
    case 6: return b >> 7;
    default: return 42;
    }
}

struct probe {
    const char *name;
    uint64_t (*function)(uint64_t, uint64_t);
};

static const struct probe probes[] = {
    {"add32", add32},         {"sub8", sub8},
    {"mul16", mul16},         {"mul64_high", mul64_high},
    {"smul64_high", smul64_high}, {"udiv32", udiv32},
    {"sdiv32", sdiv32},       {"srem64", srem64},
    {"urem64", urem64},       {"div_const", div_const},
    {"shl_var", shl_var},     {"shr_var", shr_var},
    {"sar_var", sar_var},     {"sar16", sar16},
    {"rotl32", rotl32},       {"rotr8", rotr8},
    {"cmp_signed", cmp_signed}, {"cmp_unsigned", cmp_unsigned},
    {"sext_mix", sext_mix},   {"add_carry128", add_carry128},
    {"bswap32", bswap32},     {"clz64", clz64},
    {"popcount64", popcount64}, {"cond_select", cond_select},
    {"overflow_check", overflow_check}, {"neg_not", neg_not},
    {"bool_logic", bool_logic}, {"loop_sum", loop_sum},
    {"switch_table", switch_table},
};

int main(void) {
    char name[64];
    unsigned long long a, b;
    while (scanf("%63s %llu %llu", name, &a, &b) == 3) {
        const struct probe *found = NULL;
        for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
            if (strcmp(probes[i].name, name) == 0) found = &probes[i];
        }
        if (found == NULL) return 2;
        printf("%llu\n", (unsigned long long)found->function(a, b));
    }
    return 0;
}
