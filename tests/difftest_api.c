/* Small C API over the recompiled code so a Python driver can run single functions
 * (see difftest.py, which compares them against the original x86 under Unicorn). */
#include "runtime.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

static sigjmp_buf g_alarm_jb;
static void on_alarm(int sig) { (void)sig; siglongjmp(g_alarm_jb, 1); }

static CPU g_cpu;
static LoadedImage g_img;

/* ---------------------------------------------------------------- Windows imports
 * The emulator side runs each import in tests/winmodel.py and records what it did: the slot, the stack pointer,
 * every memory read (with the bytes it saw), write and zero-fill in order, and the registers it returned. Here
 * every import slot replays the next record, after checking that it is the same import at the same stack
 * pointer and that each byte the model read is the same in this side's memory (see winmodel.py). */
enum { OP_READ, OP_WRITE, OP_ZERO };
static uint8_t *g_rp;
static uint32_t g_rp_len, g_rp_pos, g_rp_count, g_rp_next;
/* The emulator's run may end at an import the model does not run: then this side must make that call next, at the
   same stack pointer, and stops there too (dt_run returns 5) so that both states are compared at that point. */
static uint32_t g_rp_end, g_rp_end_slot, g_rp_end_esp;
static int g_rp_ended;

void dt_set_imports(const uint8_t *buf, uint32_t len) {
    free(g_rp);
    g_rp = malloc(len);
    memcpy(g_rp, buf, len);
    g_rp_len = len;
    g_rp_pos = 4;
    memcpy(&g_rp_count, g_rp, 4);
    memcpy(&g_rp_end, g_rp + len - 12, 4);   /* the record ends with: ended?, slot, esp */
    memcpy(&g_rp_end_slot, g_rp + len - 8, 4);
    memcpy(&g_rp_end_esp, g_rp + len - 4, 4);
    g_rp_len = len - 12;
    g_rp_next = 0;
}
uint32_t dt_imports_replayed(void) { return g_rp_next; }
uint32_t dt_num_imports(void) { return g_img.num_imports; }
const char *dt_import_name(uint32_t k) { return import_name(IMPORT_BASE + 16 * k); }

static uint32_t rp_u32(CPU *c) {
    if (g_rp_pos + 4 > g_rp_len) guest_trap(c, g_import_target, "import replay: record truncated (harness bug)");
    uint32_t v;
    memcpy(&v, g_rp + g_rp_pos, 4);
    g_rp_pos += 4;
    return v;
}

static void replay_import(CPU *c) {
    static char msg[256];
    uint32_t slot = (g_import_target - IMPORT_BASE) / 16, k = g_rp_next;
    const char *name = import_name(g_import_target);
    if (k == g_rp_count) {
        if (!g_rp_end) {
            snprintf(msg, sizeof msg, "import call %u, %s: the emulator made only %u import calls", k + 1, name, k);
            guest_trap(c, g_import_target, msg);
        }
        if (slot != g_rp_end_slot || c->esp != g_rp_end_esp) {
            snprintf(msg, sizeof msg, "import call %u is %s at esp %08x; the emulator stopped at %s at esp %08x",
                     k + 1, name, c->esp, import_name(IMPORT_BASE + 16 * g_rp_end_slot), g_rp_end_esp);
            guest_trap(c, g_import_target, msg);
        }
        g_rp_ended = 1;   /* where the emulator stopped: stop too, with the state as it is at the call */
        guest_trap(c, g_import_target, "stopped at the emulator's last import call");
    }
    uint32_t eslot = rp_u32(c), esp = rp_u32(c), mask = rp_u32(c), eax = rp_u32(c), ecx = rp_u32(c),
             edx = rp_u32(c), esp_out = rp_u32(c), ret_to = rp_u32(c), nops = rp_u32(c);
    if (eslot != slot) {
        snprintf(msg, sizeof msg, "import call %u is %s, the emulator's is %s", k + 1, name,
                 import_name(IMPORT_BASE + 16 * eslot));
        guest_trap(c, g_import_target, msg);
    }
    if (c->esp != esp) {
        snprintf(msg, sizeof msg, "import call %u, %s: esp %08x, the emulator's %08x", k + 1, name, c->esp, esp);
        guest_trap(c, g_import_target, msg);
    }
    for (uint32_t i = 0; i < nops; i++) {
        uint32_t kind = rp_u32(c), addr = rp_u32(c), len = rp_u32(c);
        if (kind == OP_ZERO) { memset(HP(addr), 0, len); continue; }
        uint32_t padded = (len + 3) & ~3u;
        if (kind > OP_ZERO || g_rp_pos + padded > g_rp_len)
            guest_trap(c, g_import_target, "import replay: malformed record (harness bug)");
        const uint8_t *data = g_rp + g_rp_pos;
        g_rp_pos += padded;
        if (kind == OP_WRITE) { memcpy(HP(addr), data, len); continue; }
        for (uint32_t j = 0; j < len; j++)
            if (*HP(addr + j) != data[j]) {
                snprintf(msg, sizeof msg, "import call %u, %s: reads %02x at %08x, the emulator read %02x", k + 1,
                         name, *HP(addr + j), addr + j, data[j]);
                guest_trap(c, g_import_target, msg);
            }
    }
    if (mask & 1) c->eax = eax;
    if (mask & 2) c->ecx = ecx;
    if (mask & 4) c->edx = edx;
    c->ret_to = ret_to;   /* the import returns like `ret`: to the address the model read at esp */
    c->esp = esp_out;
    g_rp_next++;
}

/* A slot for a function reached only through GetProcAddress (winmodel.Model.dynamic_names): the runtime's next
   dynamic import slot, which replays like the IAT's. Returns its address. */
uint32_t dt_add_import(const char *name) { return add_dynamic_import(name, replay_import); }

int dt_init(const char *exe) {
    runtime_init(&g_cpu);
    if (load_image(exe, &g_img)) return -1;
    register_all_functions();
    for (uint32_t k = 0; k < g_img.num_imports; k++) register_function(IMPORT_BASE + 16 * k, replay_import);
    return 0;
}

uint8_t *dt_mem(void) { return g_mem; }
const char *dt_trap_msg(void) { return g_trap_msg; }

/* regs: eax ecx edx ebx esp ebp esi edi (in/out), then EFLAGS (out: CF PF AF ZF SF DF OF). Returns 0 = returned normally, 1 = trapped,
   2 = no such function, 3 = timed out, 4 = returned having made fewer import calls than the emulator, 5 = stopped
   at the import call where the emulator's run ended (see dt_set_imports, which must come first). The caller has already pushed the arguments and a return address. */
int dt_run(uint32_t addr, uint32_t *regs, uint16_t fpu_cw) {
    GuestFn fn = lookup_function(addr);
    if (!fn) return 2;
    CPU *c = &g_cpu;
    memset(c, 0, sizeof *c);
    c->eax = regs[0]; c->ecx = regs[1]; c->edx = regs[2]; c->ebx = regs[3];
    c->esp = regs[4]; c->ebp = regs[5]; c->esi = regs[6]; c->edi = regs[7];
    c->fpu_cw = fpu_cw; c->mxcsr = 0x1f80; c->fs_base = GUEST_TIB;
    c->pf_byte = 1; /* EFLAGS = 0x202: PF clear */
    fpu_sync_rounding(c);
    g_rp_pos = 4;
    g_rp_next = 0;
    g_rp_ended = 0;
    jmp_buf jb;
    g_trap_jmp = &jb;
    int rc = 0;
    /* Watchdog: a recompiled function that diverges into an endless loop reports rc = 3. */
    signal(SIGALRM, on_alarm);
    struct itimerval tv = { {0, 0}, {2, 0} }, off = { {0, 0}, {0, 0} };
    if (sigsetjmp(g_alarm_jb, 1)) {
        rc = 3;
    } else {
        setitimer(ITIMER_REAL, &tv, NULL);
        /* difftest.py pushed GUEST_RETURN_SENTINEL as the return address, so this runs the function as the host
           does: returning, or jumping, to the sentinel ends the run (as Unicorn's ends there) */
        if (setjmp(jb) == 0) guest_enter(c, addr);
        else rc = g_rp_ended ? 5 : 1;
    }
    setitimer(ITIMER_REAL, &off, NULL);
    g_trap_jmp = NULL;
    if (rc == 0 && (g_rp_next != g_rp_count || g_rp_end)) rc = 4;
    c->fpu_cw = 0x027f;
    fpu_sync_rounding(c); /* back to round-to-nearest for the host */
    regs[0] = c->eax; regs[1] = c->ecx; regs[2] = c->edx; regs[3] = c->ebx;
    regs[4] = c->esp; regs[5] = c->ebp; regs[6] = c->esi; regs[7] = c->edi;
    regs[8] = (uint32_t)c->cf | (uint32_t)PF(c) << 2 | (uint32_t)c->af << 4 | (uint32_t)c->zf << 6 |
              (uint32_t)c->sf << 7 | (uint32_t)c->df << 10 | (uint32_t)c->of << 11;
    return rc;
}

/* Tracing: record up to `cap` instructions of the next dt_run (needs a --trace build). */
void dt_trace_start(uint32_t cap) {
    free(g_trace);
    g_trace = calloc(cap, sizeof *g_trace);
    g_trace_cap = cap;
    g_trace_len = 0;
}
uint32_t dt_trace_len(void) { return g_trace_len; }
TraceRec *dt_trace_buf(void) { return g_trace; }
