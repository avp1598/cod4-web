/* Runtime for recompiled code: guest memory, PE image loading, function dispatch, traps. */
#include "runtime.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdlib.h>
#include <sys/mman.h>

uint8_t *g_mem;

/* ------------------------------------------------------------------ function table */

typedef struct { uint32_t addr; GuestFn fn; } FnEntry;
static FnEntry *g_fns;
#define FN_BITS 17                 /* ~32K functions: a quarter full, so lookups rarely probe */
#define FN_CAP (1u << FN_BITS)
/* Fibonacci hashing takes the product's top bits: most function addresses are 16-byte aligned, so the
   low bits of addr * k are mostly zero and would pile entries into a sixteenth of the table. */
static inline uint32_t fn_slot(uint32_t addr) { return (addr * 2654435761u) >> (32 - FN_BITS); }

void register_function(uint32_t addr, GuestFn fn) {
    if (!g_fns) g_fns = calloc(FN_CAP, sizeof *g_fns);
    uint32_t i = fn_slot(addr);
    while (g_fns[i].fn && g_fns[i].addr != addr) i = (i + 1) & (FN_CAP - 1);
    g_fns[i].addr = addr;
    g_fns[i].fn = fn;
}

GuestFn lookup_function(uint32_t addr) {
    if (!g_fns) return NULL;
    uint32_t i = fn_slot(addr);
    while (g_fns[i].fn) {
        if (g_fns[i].addr == addr) return g_fns[i].fn;
        i = (i + 1) & (FN_CAP - 1);
    }
    return NULL;
}

static void unimplemented_import(CPU *c);
static int g_log_imports = -1;
__thread uint32_t g_import_target;  /* which host slot the current import call came through */

static uint32_t g_trace_call = 1;   /* RC_TRACE_CALL=addr: log indirect calls to that function */

/* A call or jump to a host import slot: records which slot (g_import_target: COM dispatch and the difftest
   replay read it), logs it with RC_LOG_IMPORTS, and traps on an import no handler implements. */
static void enter_import(CPU *c, uint32_t target, GuestFn fn) {
    const char *name = import_name(target);
    if (g_log_imports < 0) g_log_imports = getenv("RC_LOG_IMPORTS") != NULL;
    if (g_log_imports && name)
        fprintf(stderr, "[import] %-40s from %08x  args %08x %08x %08x %08x\n", name, R32(c->esp),
                R32(c->esp + 4), R32(c->esp + 8), R32(c->esp + 12), R32(c->esp + 16));
    g_import_target = target;
    if (fn == unimplemented_import) {
        static char msg[160];
        snprintf(msg, sizeof msg, "unimplemented Windows import %s (called from %08x)",
                 name ? name : "?", R32(c->esp));
        guest_trap(c, target, msg);
    }
}

void call_indirect(CPU *c, uint32_t target) {
    if (g_trace_call == 1) g_trace_call = getenv("RC_TRACE_CALL") ? (uint32_t)strtoul(getenv("RC_TRACE_CALL"), NULL, 16) : 0;
    if (g_trace_call && target == g_trace_call) {
        static int n;
        if (n++ < 40)
            fprintf(stderr, "[call] %08x from %08x ecx=%08x args %08x %08x %08x %08x\n", target, R32(c->esp), c->ecx,
                    R32(c->esp + 4), R32(c->esp + 8), R32(c->esp + 12), R32(c->esp + 16));
    }
    GuestFn fn = lookup_function(target);
    if (!fn && dyncode_contains(target)) { interp_call(c, target); return; }
    if (!fn) {
        static char msg[96];
        snprintf(msg, sizeof msg, "indirect call to unknown function (return address %08x)", R32(c->esp));
        guest_trap(c, target, msg);
    }
    if (target >= IMPORT_BASE) enter_import(c, target, fn);
    fn(c);
}

void jump_indirect(CPU *c, uint32_t target, uint32_t from) {
    (void)from;
    /* An indirect jump that isn't a known switch case: to a function, a tail call. Anywhere else, control is
       going back to code an active frame will continue (longjmp to a setjmp's return address, a jump to a
       return address that was popped): unwind to the frame whose call returns there (see CPU.ret_to). If no
       frame does, guest_enter traps. */
    GuestFn fn = lookup_function(target);
    if (fn) {
        if (target >= IMPORT_BASE) enter_import(c, target, fn);   /* `jmp [iat]` import thunks */
        fn(c);
        return;
    }
    c->ret_to = target;
}

void guest_bounds_fail(uint32_t a, int n) {
    fprintf(stderr, "\n*** guest write of %d bytes at %08x is outside guest memory\n", n, a);
    __builtin_trap();   /* the engine's stack trace names the recompiled function */
}

volatile uint8_t g_guest_lock;

jmp_buf *g_trap_jmp;        /* when set (tests), traps longjmp here instead of aborting */
char g_trap_msg[256];

void guest_trap(CPU *c, uint32_t addr, const char *why) {
    if (g_trap_jmp) {
        snprintf(g_trap_msg, sizeof g_trap_msg, "%08x: %s", addr, why);
        longjmp(*g_trap_jmp, 1);
    }
    fprintf(stderr, "\n*** guest trap at %08x: %s\n", addr, why);
    fprintf(stderr, "    eax=%08x ecx=%08x edx=%08x ebx=%08x esp=%08x ebp=%08x esi=%08x edi=%08x\n",
            c->eax, c->ecx, c->edx, c->ebx, c->esp, c->ebp, c->esi, c->edi);
    /* Stack words that look like return addresses into .text, plus the memory eax/ecx point at. */
    fprintf(stderr, "    stack:");
    for (int i = 0; i < 64; i++) {
        uint32_t v = R32(c->esp + 4 * i);
        if (v >= 0x401000 && v < 0x900000) fprintf(stderr, " [%d]%08x", i, v);
    }
    fprintf(stderr, "\n");
    uint32_t regs[2] = { c->eax, c->ecx };
    for (int r = 0; r < 2; r++) {
        if (regs[r] < GUEST_HEAP_BASE || regs[r] >= GUEST_HEAP_HI) continue;
        fprintf(stderr, "    [%s]:", r ? "ecx" : "eax");
        for (int i = -4; i < 12; i++) fprintf(stderr, " %08x", R32(regs[r] + 4 * i));
        fprintf(stderr, "\n");
    }
    if (addr >= GUEST_HEAP_BASE && addr < GUEST_VALLOC_HI) {
        fprintf(stderr, "    code at %08x:", addr);
        for (int i = 0; i < 64; i++) fprintf(stderr, "%s%02x", i % 32 ? "" : "\n      ", R8(addr + i));
        fprintf(stderr, "\n");
    }
    abort();
}

/* ------------------------------------------------------------------ tracing (--trace builds) */

TraceRec *g_trace;
uint32_t g_trace_len, g_trace_cap;

void trace_insn(CPU *c, uint32_t addr) {
    if (!g_trace || g_trace_len >= g_trace_cap) return;
    TraceRec *r = &g_trace[g_trace_len++];
    r->addr = addr;
    r->regs[0] = c->eax; r->regs[1] = c->ecx; r->regs[2] = c->edx; r->regs[3] = c->ebx;
    r->regs[4] = c->esp; r->regs[5] = c->ebp; r->regs[6] = c->esi; r->regs[7] = c->edi;
    r->st0 = c->st[c->top];
    r->top = (uint32_t)c->top;
    memcpy(r->xmm, c->xmm, sizeof r->xmm);
    memcpy(r->mm, c->mm, sizeof r->mm);
}

/* ------------------------------------------------------------------ x87 helpers */

static double round_mode(CPU *c, double v) {
    switch ((c->fpu_cw >> 10) & 3) {
    case 0: return nearbyint(v); /* host default mode is round-to-nearest-even */
    case 1: return floor(v);
    case 2: return ceil(v);
    default: return trunc(v);
    }
}

/* An already-rounded value as a `bits`-bit integer, or that size's "integer indefinite" (its most negative
   value) when it is NaN or out of range. */
static int64_t to_int_or_indefinite(double r, int bits) {
    double hi = ldexp(1.0, bits - 1);
    if (!(r >= -hi && r < hi)) return -(int64_t)(((uint64_t)1 << (bits - 1)) - 1) - 1;
    return (int64_t)r;
}

int16_t fpu_to_int16(CPU *c, double v) { return (int16_t)to_int_or_indefinite(round_mode(c, v), 16); }
int32_t fpu_to_int32(CPU *c, double v) { return (int32_t)to_int_or_indefinite(round_mode(c, v), 32); }
int64_t fpu_to_int64(CPU *c, double v) { return to_int_or_indefinite(round_mode(c, v), 64); }
int16_t fpu_trunc_to_int16(double v) { return (int16_t)to_int_or_indefinite(trunc(v), 16); }
int32_t fpu_trunc_to_int32(double v) { return (int32_t)to_int_or_indefinite(trunc(v), 32); }
int64_t fpu_trunc_to_int64(double v) { return to_int_or_indefinite(trunc(v), 64); }

/* Rounds to an integer in MXCSR rounding mode `rc` using only floor/ceil/trunc, which do not depend on the
   host rounding mode (that one follows the x87 control word). */
static double round_sse(double v, unsigned rc) {
    switch (rc & 3) {
    case 0: {  /* nearest, ties to even */
        double f = floor(v), d = v - f;  /* exact: v and f are within one unit of each other */
        if (d > 0.5 || (d == 0.5 && fmod(f, 2.0) != 0.0)) f += 1.0;
        return f;
    }
    case 1: return floor(v);
    case 2: return ceil(v);
    default: return trunc(v);
    }
}

int32_t sse_to_int32(uint32_t mxcsr, double v, int truncate) {
    if (v != v) return INT32_MIN;
    return (int32_t)to_int_or_indefinite(truncate ? trunc(v) : round_sse(v, mxcsr >> 13), 32);
}

float sse_int_to_float(uint32_t mxcsr, int32_t v) {
    double x = (double)v;  /* exact */
    float f = (float)x;    /* rounded in the host mode; corrected to the MXCSR mode below */
    if ((double)f == x) return f;
    float lo = (double)f < x ? f : nextafterf(f, -INFINITY), hi = nextafterf(lo, INFINITY);
    switch ((mxcsr >> 13) & 3) {
    case 0: {
        double dl = x - (double)lo, dh = (double)hi - x;
        if (dl != dh) return dl < dh ? lo : hi;
        uint32_t bits;
        memcpy(&bits, &lo, 4);
        return (bits & 1) ? hi : lo;  /* tie: the even significand */
    }
    case 1: return lo;
    case 2: return hi;
    default: return x > 0 ? lo : hi;
    }
}

/* ------------------------------------------------------------------ x86 NaN rules (see cpu.h) */

static uint64_t bits_of(double v) { uint64_t b; memcpy(&b, &v, 8); return b; }
static double double_of(uint64_t b) { double v; memcpy(&v, &b, 8); return v; }
static uint32_t bits_of_f(float v) { uint32_t b; memcpy(&b, &v, 4); return b; }
static float float_of(uint32_t b) { float v; memcpy(&v, &b, 4); return v; }
#define QUIET64 0x0008000000000000ull
#define INDEFINITE64 0xfff8000000000000ull
#define QUIET32 0x00400000u
#define INDEFINITE32 0xffc00000u

double x87_nan1(double a) {
    return a != a ? double_of(bits_of(a) | QUIET64) : double_of(INDEFINITE64);
}

double x87_nan2(double a, double b) {
    int an = a != a, bn = b != b;
    if (!an && !bn) return double_of(INDEFINITE64);
    if (an != bn) return x87_nan1(an ? a : b);
    uint64_t A = bits_of(a), B = bits_of(b);
    if ((A & QUIET64) != (B & QUIET64)) return (A & QUIET64) ? a : b;  /* SNaN and QNaN: the QNaN */
    uint64_t sa = A & 0x000fffffffffffffull, sb = B & 0x000fffffffffffffull;
    if (sa != sb) return double_of((sa > sb ? A : B) | QUIET64);
    return double_of(((A >> 63) ? B : A) | QUIET64);                   /* equal: the positive one */
}

double sse_nan1d(double a) { return x87_nan1(a); }

/* Intel SDM Vol. 2A, FYL2X, table "FYL2X Results": an operation with no defined result (x < 0; x = +-0 with
   y = +-0; x = +inf with y = +-0; x = +1 with y = +-inf) raises IE and gives the real indefinite; x = +-0 with
   a finite nonzero y raises ZE and gives an infinity of the sign opposite to y's. The remaining special cases
   (x = +-0 with an infinite y; x = +inf, x = +1, x off 1 with an infinite y) are what y * log2(x) gives. NaN
   operands follow the x87 NaN rules; a signalling one raises IE. */
double fpu_yl2x(double y, double x, uint16_t *sw) {
    if (x != x || y != y) {
        if ((x != x && !(bits_of(x) & QUIET64)) || (y != y && !(bits_of(y) & QUIET64))) *sw |= 0x0001;
        return x87_nan2(y, x);
    }
    double r = y * log2(x);
    if (r != r) {
        *sw |= 0x0001;
        return double_of(INDEFINITE64);
    }
    if (x == 0 && y != 0 && isfinite(y)) *sw |= 0x0004;
    return r;
}

double sse_nan2d(double a, double b) {
    if (a != a) return double_of(bits_of(a) | QUIET64);
    if (b != b) return double_of(bits_of(b) | QUIET64);
    return double_of(INDEFINITE64);
}

float sse_nan1f(float a) {
    return a != a ? float_of(bits_of_f(a) | QUIET32) : float_of(INDEFINITE32);
}

float sse_nan2f(float a, float b) {
    if (a != a) return float_of(bits_of_f(a) | QUIET32);
    if (b != b) return float_of(bits_of_f(b) | QUIET32);
    return float_of(INDEFINITE32);
}

double fpu_scale(double a, double b) {
    if (a != a || b != b) return x87_nan2(a, b);
    if (isinf(b)) {
        if (b > 0) return a == 0 ? double_of(INDEFINITE64) : a * b;       /* 0 * 2^inf is invalid */
        return isinf(a) ? double_of(INDEFINITE64) : copysign(0.0, a);    /* inf * 2^-inf is invalid */
    }
    double n = trunc(b);
    if (n > 100000.0) n = 100000.0;    /* any count past the exponent range gives the same result */
    if (n < -100000.0) n = -100000.0;
    return ldexp(a, (int)n);
}

/* Tag of one physical register as FNSAVE/FNSTENV store it: 11 empty, 01 zero, 10 special (NaN, infinity,
   denormal: an 80-bit register holds every double denormal as a normal number, so only NaN and infinity),
   00 valid. */
static unsigned x87_tag(CPU *c, int p) {
    if (!(c->ftags & (1u << p))) return 3;
    double v = c->st[p];
    if (v == 0) return 1;
    if (v != v || isinf(v)) return 2;
    return 0;
}

void fpu_save(CPU *c, uint32_t a) {
    unsigned tw = 0;
    for (int p = 0; p < 8; p++) tw |= x87_tag(c, p) << (2 * p);
    W32(a + 0, 0xffff0000u | c->fpu_cw);
    W32(a + 4, 0xffff0000u | FNSTSW(c));
    W32(a + 8, 0xffff0000u | tw);
    for (int k = 12; k < 28; k += 4) W32(a + k, 0);  /* FPU IP, CS/opcode, operand pointer and selector */
    for (int i = 0; i < 8; i++) WF80(a + 28 + 10 * i, c->st[(c->top + i) & 7]);
    c->fpu_cw = 0x037f; c->fpu_sw = 0; c->top = 0; c->ftags = 0;  /* then FNINIT */
    fpu_sync_rounding(c);
}

void fpu_restore(CPU *c, uint32_t a) {
    c->fpu_cw = R16(a + 0);
    uint16_t sw = R16(a + 4), tw = R16(a + 8);
    c->top = (sw >> 11) & 7;
    c->fpu_sw = sw & ~0x3800;
    c->ftags = 0;
    for (int p = 0; p < 8; p++)
        if (((tw >> (2 * p)) & 3) != 3) c->ftags |= (uint8_t)(1u << p);
    for (int i = 0; i < 8; i++) c->st[(c->top + i) & 7] = RF80(a + 28 + 10 * i);
    fpu_sync_rounding(c);
}

/* 32-bit Windows (XP): CS 0x1b, DS/ES/SS 0x23 (flat user segments), FS 0x3b (thread information block), GS 0 */
uint16_t g_seg_selector[6] = { 0x23, 0x1b, 0x23, 0x23, 0x3b, 0x00 };

double fpu_round(CPU *c, double v) { return round_mode(c, v); }

#include <fenv.h>
void fpu_sync_rounding(CPU *c) {
    static const int modes[4] = { FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO };
    static __thread int current = -1;  /* MSVC's _ftol switches modes twice per conversion: skip no-ops */
    int rc = (c->fpu_cw >> 10) & 3;
    if (rc != current) { fesetround(modes[rc]); current = rc; }
}

double RF80(uint32_t a) {
    uint64_t mant = R64(a);
    uint16_t se = R16(a + 8);
    int sign = se >> 15, exp = se & 0x7fff;
    double v;
    if (exp == 0 && mant == 0) v = 0.0;
    else if (exp == 0x7fff) {
        uint64_t frac = mant & 0x7fffffffffffffffull;
        if (!frac) {
            v = INFINITY;
        } else {
            /* a NaN keeps its sign, quiet bit and the top 51 payload bits a double holds. A signalling NaN
               whose payload lies only in the low bits a double cannot hold is kept as quiet (with no payload
               left, a double with that sign and exponent would be an infinity). */
            uint64_t f = frac >> 11;
            if (!f) f = QUIET64;
            return double_of(((uint64_t)sign << 63) | 0x7ff0000000000000ull | f);
        }
    }
    else v = ldexp((double)mant, exp - 16383 - 63);
    return sign ? -v : v;
}

void WF80(uint32_t a, double v) {
    uint16_t se = signbit(v) ? 0x8000 : 0;
    uint64_t mant = 0;
    v = fabs(v);
    if (isnan(v)) { se |= 0x7fff; mant = 0x8000000000000000ull | (bits_of(v) & 0x000fffffffffffffull) << 11; }
    else if (isinf(v)) { se |= 0x7fff; mant = 0x8000000000000000ull; }
    else if (v != 0) {
        int e;
        double m = frexp(v, &e);           /* v = m * 2^e, 0.5 <= m < 1 */
        mant = (uint64_t)ldexp(m, 64);      /* explicit integer bit at bit 63 */
        se |= (uint16_t)(e - 1 + 16383);
    }
    W64(a, mant);
    W16(a + 8, se);
}

/* ------------------------------------------------------------------ CPUID / RDTSC */

void cpuid(CPU *c) {
    switch (c->eax) {
    case 0:  /* max standard leaf 1, "GenuineIntel" */
        c->eax = 1; c->ebx = 0x756e6547; c->edx = 0x49656e69; c->ecx = 0x6c65746e; break;
    case 1:  /* family 6, model 8; FPU, TSC, CX8, CMOV only: deliberately no MMX (bit 23) or SSE (25/26) */
        c->eax = 0x00000683; c->ebx = 0; c->ecx = 0; c->edx = (1u << 0) | (1u << 4) | (1u << 8) | (1u << 15); break;
    case 0x80000000u:  /* no extended leaves, so no 3DNow! */
        c->eax = 0x80000000u; c->ebx = c->ecx = c->edx = 0; break;
    default:
        c->eax = c->ebx = c->ecx = c->edx = 0;
    }
}

#include <time.h>
/* A 2 GHz timestamp counter, consistent with the CPU speed reported through the registry. */
uint64_t (*g_rdtsc_hook)(void);   /* set by the host for deterministic runs */
int g_preempt_on;
void (*g_preempt_fn)(void);       /* the deterministic scheduler's yield */
void guest_preempt(CPU *c) { c->preempt_ticks = 0; if (g_preempt_fn) g_preempt_fn(); }
void rdtsc(CPU *c) {
    if (g_rdtsc_hook) { uint64_t t = g_rdtsc_hook(); c->eax = (uint32_t)t; c->edx = (uint32_t)(t >> 32); return; }
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t t = (uint64_t)ts.tv_sec * 2000000000ull + (uint64_t)ts.tv_nsec * 2ull;
    c->eax = (uint32_t)t; c->edx = (uint32_t)(t >> 32);
}

/* ------------------------------------------------------------------ imports */

typedef struct { char name[96]; GuestFn fn; } ImportSlot;
static ImportSlot g_imports[4096];  /* PE imports + GetProcAddress results + COM method slots */
static uint32_t g_nimports;

static void unimplemented_import(CPU *c) {
    /* The return address on the stack identifies the caller; the slot is found from the IAT
       value the caller used, which call_indirect passed as the target. */
    guest_trap(c, R32(c->esp), "call to an unimplemented Windows import");
}

static ImportHandler *g_import_handlers;
static uint32_t g_nhandlers;

void set_import_handlers(ImportHandler *h, uint32_t n) { g_import_handlers = h; g_nhandlers = n; }

static GuestFn find_handler(const char *name) {
    for (uint32_t i = 0; i < g_nhandlers; i++)
        if (!strcmp(g_import_handlers[i].name, name)) return g_import_handlers[i].fn;
    return NULL;
}

uint32_t add_dynamic_import(const char *name, GuestFn fn) {
    ImportSlot *sl = &g_imports[g_nimports];
    snprintf(sl->name, sizeof sl->name, "%s", name);
    sl->fn = fn;
    uint32_t magic = IMPORT_BASE + g_nimports * 16;
    register_function(magic, fn);
    g_nimports++;
    return magic;
}

GuestFn find_import_handler(const char *name) { return find_handler(name); }

const char *import_name(uint32_t addr) {
    if (addr < IMPORT_BASE || addr >= IMPORT_BASE + g_nimports * 16) return NULL;
    return g_imports[(addr - IMPORT_BASE) / 16].name;
}

/* ------------------------------------------------------------------ PE loading */

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t rd32(const uint8_t *p) { return p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24; }

uint32_t g_image_lo, g_image_hi;
uint32_t g_state_lo, g_state_hi;

int load_image(const char *path, LoadedImage *out) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return -1; }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *file = malloc(size);
    if (fread(file, 1, size, f) != (size_t)size) { fclose(f); return -1; }
    fclose(f);

    const uint8_t *pe = file + rd32(file + 0x3c);
    uint16_t nsec = rd16(pe + 6);
    uint16_t optsz = rd16(pe + 20);
    const uint8_t *opt = pe + 24;
    uint32_t image_base = rd32(opt + 28);
    uint32_t entry = rd32(opt + 16);
    uint32_t hdr_size = rd32(opt + 60);
    uint32_t imp_rva = rd32(opt + 96 + 8);

    memcpy(HP(image_base), file, hdr_size);
    const uint8_t *sec = opt + optsz;
    for (int i = 0; i < nsec; i++, sec += 40) {
        uint32_t vsize = rd32(sec + 8), va = rd32(sec + 12), rawsz = rd32(sec + 16), rawptr = rd32(sec + 20);
        uint32_t n = rawsz < vsize ? rawsz : vsize;
        memset(HP(image_base + va), 0, vsize);
        memcpy(HP(image_base + va), file + rawptr, n);
        if (rd32(sec + 36) & 0x80000000u) {   /* IMAGE_SCN_MEM_WRITE */
            if (!g_state_lo || image_base + va < g_state_lo) g_state_lo = image_base + va;
            if (image_base + va + vsize > g_state_hi) g_state_hi = image_base + va + vsize;
        }
    }

    /* Resolve imports: each IAT slot gets a magic address that dispatches to a host handler. */
    for (uint32_t d = image_base + imp_rva; R32(d + 12); d += 20) {
        const char *dll = (const char *)HP(image_base + R32(d + 12));
        uint32_t ilt = R32(d) ? R32(d) : R32(d + 16), iat = R32(d + 16);
        for (uint32_t k = 0;; k++) {
            uint32_t thunk = R32(image_base + ilt + 4 * k);
            if (!thunk) break;
            ImportSlot *s = &g_imports[g_nimports];
            if (thunk & 0x80000000u)
                snprintf(s->name, sizeof s->name, "%s!#%u", dll, thunk & 0xffff);
            else
                snprintf(s->name, sizeof s->name, "%s!%s", dll, (const char *)HP(image_base + thunk + 2));
            for (char *p = s->name; *p && *p != '!'; p++) *p = (char)toupper((unsigned char)*p);
            GuestFn fn = find_handler(s->name);
            s->fn = fn ? fn : unimplemented_import;
            uint32_t magic = IMPORT_BASE + g_nimports * 16;
            W32(image_base + iat + 4 * k, magic);
            register_function(magic, s->fn);
            g_nimports++;
        }
    }
    free(file);
    out->image_base = image_base;
    g_image_lo = image_base;
    g_image_hi = image_base + rd32(opt + 56);   /* SizeOfImage */
    out->entry = image_base + entry;
    out->num_imports = g_nimports;
    return 0;
}

/* ------------------------------------------------------------------ memory + CPU setup */

void runtime_init(CPU *c) {
    /* +64 KiB so multi-byte accesses straddling 0xFFFFFFFF stay inside the mapping */
#ifdef __EMSCRIPTEN__
    g_mem = calloc(1, (size_t)GUEST_SPACE + 0x10000);
    if (!g_mem) { fprintf(stderr, "cannot allocate guest memory\n"); exit(1); }
#else
    g_mem = mmap(NULL, GUEST_SPACE + 0x10000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON | MAP_NORESERVE, -1, 0);
    if (g_mem == MAP_FAILED) { perror("mmap 4GiB guest space"); exit(1); }
#endif
    memset(c, 0, sizeof *c);
    c->esp = GUEST_STACK_TOP;
    c->fpu_cw = 0x027f; /* MSVC default: 53-bit precision, round to nearest, exceptions masked */
    fpu_sync_rounding(c);
    c->mxcsr = 0x1f80;
    c->fs_base = GUEST_TIB;
    W32(GUEST_TIB + 0x00, 0xffffffffu);    /* empty SEH chain */
    W32(GUEST_TIB + 0x18, GUEST_TIB);       /* self pointer */
    W32(GUEST_TIB + 0x04, GUEST_STACK_TOP); /* stack base */
    W32(GUEST_TIB + 0x08, GUEST_STACK_TOP - GUEST_STACK_SIZE);
}

uint32_t g_heap_next = GUEST_HEAP_BASE;

uint32_t guest_alloc(uint32_t size) {
    uint32_t a = (g_heap_next + 15) & ~15u;
    g_heap_next = a + size;
    return a;
}

/* Calls a recompiled function the way the original would be called: arguments are pushed
   right-to-left and a sentinel return address is pushed. The callee pops what its convention says. */
void guest_call(CPU *c, GuestFn fn, int nargs, const uint32_t *args) {
    for (int i = nargs - 1; i >= 0; i--) PUSH32(c, args[i]);
    PUSH32(c, GUEST_RETURN_SENTINEL);
    uint32_t saved = c->ret_to;
    c->ret_to = GUEST_RETURN_SENTINEL;
    fn(c);
    if (c->ret_to != GUEST_RETURN_SENTINEL)
        guest_trap(c, c->ret_to, "control returned to an address no active caller returns to");
    c->ret_to = saved;
}

void guest_enter(CPU *c, uint32_t target) {
    uint32_t saved = c->ret_to;  /* a host function called from guest code may be calling back into it */
    c->ret_to = GUEST_RETURN_SENTINEL;
    call_indirect(c, target);
    if (c->ret_to != GUEST_RETURN_SENTINEL)
        guest_trap(c, c->ret_to, "control returned to an address no active caller returns to");
    c->ret_to = saved;
}
