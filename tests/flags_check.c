/* The runtime's flag helpers (runtime/cpu.h DEF_FLAGS, DEF_RC) on cases read from stdin, for tests/flags_check.py,
 * which compares them with the emulator. One case per line: op bits a b flags_in (hex), op a name below; prints
 * the result and EFLAGS (CF PF AF ZF SF OF) in hex. */
#include "cpu.h"

#include <stdio.h>
#include <string.h>

uint8_t *g_mem;

static uint32_t packed(const CPU *c) {
    return (uint32_t)c->cf | (uint32_t)PF(c) << 2 | (uint32_t)c->af << 4 | (uint32_t)c->zf << 6 |
           (uint32_t)c->sf << 7 | (uint32_t)c->of << 11;
}

#define OPS(B, T)                                                                                   \
    if (!strcmp(op, "add")) r = add##B(&c, (T)a, (T)b);                                            \
    else if (!strcmp(op, "adc")) r = adc##B(&c, (T)a, (T)b);                                       \
    else if (!strcmp(op, "sub")) r = sub##B(&c, (T)a, (T)b);                                       \
    else if (!strcmp(op, "sbb")) r = sbb##B(&c, (T)a, (T)b);                                       \
    else if (!strcmp(op, "and")) r = logic##B(&c, (T)(a & b));                                     \
    else if (!strcmp(op, "or")) r = logic##B(&c, (T)(a | b));                                      \
    else if (!strcmp(op, "xor")) r = logic##B(&c, (T)(a ^ b));                                     \
    else if (!strcmp(op, "inc")) r = inc##B(&c, (T)a);                                             \
    else if (!strcmp(op, "dec")) r = dec##B(&c, (T)a);                                             \
    else if (!strcmp(op, "neg")) r = neg##B(&c, (T)a);                                             \
    else if (!strcmp(op, "shl")) r = shl##B(&c, (T)a, b);                                          \
    else if (!strcmp(op, "shr")) r = shr##B(&c, (T)a, b);                                          \
    else if (!strcmp(op, "sar")) r = sar##B(&c, (T)a, b);                                          \
    else if (!strcmp(op, "rol")) r = rol##B(&c, (T)a, b);                                          \
    else if (!strcmp(op, "ror")) r = ror##B(&c, (T)a, b);                                          \
    else if (!strcmp(op, "rcl")) r = rcl##B(&c, (T)a, b);                                          \
    else if (!strcmp(op, "rcr")) r = rcr##B(&c, (T)a, b);                                          \
    else { fprintf(stderr, "unknown op %s\n", op); return 1; }

int main(void) {
    char op[8];
    unsigned bits;
    uint32_t a, b, f;
    while (scanf("%7s %u %x %x %x", op, &bits, &a, &b, &f) == 5) {
        CPU c;
        memset(&c, 0, sizeof c);
        c.cf = f & 1; c.pf_byte = (f >> 2) & 1 ? 0 : 1; c.af = (f >> 4) & 1; c.zf = (f >> 6) & 1;
        c.sf = (f >> 7) & 1; c.of = (f >> 11) & 1;
        uint32_t r;
        if (bits == 8) { OPS(8, uint8_t) }
        else if (bits == 16) { OPS(16, uint16_t) }
        else { OPS(32, uint32_t) }
        printf("%x %x\n", r, packed(&c));
    }
    return 0;
}
