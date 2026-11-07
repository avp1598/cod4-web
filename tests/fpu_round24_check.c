/* Checks fpu_round24 (runtime/cpu.h: 24-bit x87 precision control) against an integer reference.
   clang -O1 -frounding-math -Iruntime tests/fpu_round24_check.c -o build/fpu_round24_check -lm && build/fpu_round24_check */
#include <fenv.h>
#include <stdio.h>
#include <stdlib.h>
#include "cpu.h"

/* the reference: round the 53-bit significand to 24 bits in each mode, with integers */
static double ref(double v, int mode) {
    if (v == 0 || v != v || isinf(v)) return v;
    int e; double m = frexp(fabs(v), &e);            /* 0.5 <= m < 1 */
    unsigned long long s = (unsigned long long)ldexp(m, 53), q = s >> 29, rem = s & ((1ull << 29) - 1);
    int neg = v < 0, up;
    switch (mode) {
    case FE_TONEAREST: up = rem > (1ull << 28) || (rem == (1ull << 28) && (q & 1)); break;
    case FE_DOWNWARD: up = rem && neg; break;
    case FE_UPWARD: up = rem && !neg; break;
    default: up = 0;
    }
    double r = ldexp((double)(q + up), e - 24);
    return neg ? -r : r;
}
int main(void) {
    int modes[4] = { FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO };
    srand(7);
    long n = 0;
    for (int k = 0; k < 4; k++) {
        fesetround(modes[k]);
        for (int i = 0; i < 400000; i++) {
            unsigned long long b = ((unsigned long long)rand() << 33) ^ ((unsigned long long)rand() << 11) ^ rand();
            /* exponents across the whole double range, concentrated near float's limits */
            int ex = (i % 3 == 0) ? 1023 + 127 + (rand() % 8) - 4 : (i % 3 == 1) ? 1023 - 126 + (rand() % 8) - 4 : 1 + rand() % 2045;
            b = (b & 0x800fffffffffffffull) | ((unsigned long long)ex << 52);
            double v; memcpy(&v, &b, 8);
            double got = fpu_round24(v), want = ref(v, modes[k]);
            if (memcmp(&got, &want, 8)) { printf("FAIL mode %d v=%a got %a want %a\n", k, v, got, want); return 1; }
            n++;
        }
    }
    double nan_in; unsigned long long nb = 0x7ff8000012345678ull; memcpy(&nan_in, &nb, 8);
    double nan_out = fpu_round24(nan_in);
    if (memcmp(&nan_in, &nan_out, 8)) { printf("FAIL NaN payload changed\n"); return 1; }
    printf("ok fpu_round24: %ld values, 4 rounding modes; NaN payload kept\n", n);
    return 0;
}
