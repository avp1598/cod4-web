"""Differential tester: original x86 (under Unicorn) vs recompiled C, on identical random inputs.

For every selected function and several random trials, both sides start from the same image,
registers, stack (8 random arguments + a sentinel return address) and a 64 KiB random scratch
buffer. After the function returns we compare all general registers and every byte of memory
either side could have touched.

Usage: difftest.py <exe> <functions.json> <build/librecomp.dylib> [--max N] [--trials K] [--only 0xADDR]

Pass the translator's out_all/functions_translated.json as <functions.json> to test exactly the functions
that were translated (Ghidra's plus the entries the translator found itself), with the instruction ranges
it decoded.

Outcomes, per function over all its trials:
  fail      some trial differs (registers or memory), or the recompiled code trapped or did not return
  pass      every trial that could run on both sides matched (the reason names any trial that could not)
  nan       as pass, except NaN bit patterns differ
  fp_range  fails, but passes on inputs of moderate magnitude: values beyond the double exponent range
  x87_ext   fails, but every failing trial matches when the emulator holds its x87 registers at double
            precision as the recompiled code does (tests/x87ref.py): the 80-bit precision the model drops
  skip      no trial could run to the end in the emulator (the reason says why), or not selected
The emulator's x87 is corrected where it departs from the hardware (tests/x87ref.py).
"""
import argparse
import ctypes
import json
import os
import random
import struct
import sys

import pefile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))   # run with -I: this directory is not on the path
import x87ref  # noqa: E402
from capstone import CS_ARCH_X86, CS_MODE_32, CS_OP_IMM, CS_OP_MEM, Cs
from unicorn import UC_PROT_READ, UC_PROT_WRITE, UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_INSN, UC_HOOK_MEM_FETCH_UNMAPPED, UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE, \
    UC_HOOK_MEM_WRITE_UNMAPPED, UC_MODE_32, Uc, UcError
from unicorn.x86_const import (UC_X86_REG_FPTAG, UC_X86_INS_CPUID, UC_X86_REG_EAX, UC_X86_REG_EBP, UC_X86_REG_EBX, UC_X86_REG_ECX,
                               UC_X86_REG_EDI, UC_X86_REG_EDX, UC_X86_REG_EIP, UC_X86_REG_ESI,
                               UC_X86_REG_ESP, UC_X86_REG_FPCW, UC_X86_REG_EFLAGS, UC_X86_REG_FS,
                               UC_X86_REG_GDTR, UC_X86_REG_SS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_CS,
                               UC_X86_REG_GS)

# x86 Sreg encoding order (es, cs, ss, ds, fs, gs), as runtime/cpu.h's g_seg_selector is indexed
SREGS = [UC_X86_REG_ES, UC_X86_REG_CS, UC_X86_REG_SS, UC_X86_REG_DS, UC_X86_REG_FS, UC_X86_REG_GS]
REGS = [UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EBX,
        UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_ESI, UC_X86_REG_EDI]
NAMES = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
PAGE = 0x1000
SENTINEL = 0xDEADBEEF
SCRATCH, SCRATCH_SIZE = 0x20000000, 0x10000
STACK_LO, STACK_HI = 0x002F0000, 0x00300000
# x87 control word both sides start with (--fpu-cw): by default MSVC's, 53-bit precision and round to
# nearest. Direct3D switches the FPU to 24-bit precision (0x007F) when it creates a device without
# D3DCREATE_FPU_PRESERVE, so that is the other regime the game's code runs in.
FPU_CW = 0x027F
TIB = 0x00010000   # GUEST_TIB in runtime.h: fs:[0] is the SEH chain head
GDT = 0x00001000
# The last page of the 32-bit space. A multi-byte access there wraps to address 0 on x86 (and in Unicorn), but
# not in the recompiled code's flat guest memory. Neither can happen in the game: everything from 0x80000000 up
# is kernel space in a 32-bit Windows process, so trials whose random pointers reach this page are skipped.
TOP_PAGE = 0xFFFFF000


def gdt_entry(base, limit, access, flags):
    v = (limit & 0xffff) | (base & 0xffffff) << 16 | (access & 0xff) << 40 | ((limit >> 16) & 0xf) << 48 \
        | (flags & 0xf) << 52 | ((base >> 24) & 0xff) << 56
    return struct.pack("<Q", v)


# GDT page: [2] flat 32-bit data segment for SS/DS/ES (once a GDT is loaded, Unicorn otherwise treats SS as
# 16-bit), [3] fs -> thread information block. Ring 0, like Unicorn itself. The same bytes are written into
# the recompiled side's memory, since code following a random small pointer can read this page.
GDT_PAGE = (bytes(16) + gdt_entry(0, 0xfffff, 0x80 | 0x10 | 0x2 | 0x1, 0xc)  # accessed bit pre-set: loading SS sets it
            + gdt_entry(TIB, PAGE - 1, 0x80 | 0x10 | 0x2 | 0x1, 0x4)).ljust(PAGE, b"\0")


def pick_functions(prog_img, base, funcs, jumptables, allow_calls=False):
    """Splits funcs into the ones difftest can run and the ones it can't. Returns (picked, filtered), where
    filtered holds (function, reason) so every function left out is reported as a skip with its reason."""
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    out, filtered = [], []
    for f in funcs:
        why, n = None, 0
        for a, b in f["ranges"]:
            for ins in md.disasm(prog_img[a - base:b - base], a):
                n += 1
                m = ins.mnemonic
                if m == "call" and not allow_calls:
                    why = f"calls other functions ({ins.address:08x})"
                elif m.startswith(("int", "in ", "out", "hlt", "cpuid", "rdtsc")):
                    why = f"uses {m} ({ins.address:08x})"
                elif m == "jmp" and ins.operands and ins.operands[0].type != CS_OP_IMM and ins.address not in jumptables:
                    why = f"indirect jmp that is not a known jump table ({ins.address:08x})"
                elif m == "jmp" and not allow_calls and ins.operands and ins.operands[0].type == CS_OP_IMM and not any(
                        x <= ins.operands[0].imm < y for x, y in f["ranges"]):
                    why = f"tail call ({ins.address:08x})"
                elif any(ins.reg_name(r).startswith("mm") for r in ins.regs_access()[0] + ins.regs_access()[1]):
                    why = f"uses MMX registers ({ins.address:08x})"
                if why:
                    break
            if why:
                break
        if why is None and n < 3:
            why = f"fewer than 3 instructions ({n})"
        if why:
            filtered.append((f, why))
        else:
            out.append(f)
    return out, filtered


class Tester:
    def __init__(self, exe, lib, fpu_cw=FPU_CW):
        self.fpu_cw = fpu_cw
        self.lib = ctypes.CDLL(lib)
        self.lib.dt_mem.restype = ctypes.c_void_p
        self.lib.dt_trap_msg.restype = ctypes.c_char_p
        self.lib.dt_run.argtypes = [ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32), ctypes.c_uint16]
        if self.lib.dt_init(exe.encode()) != 0:
            raise SystemExit("dt_init failed")
        self.mem = self.lib.dt_mem()
        # Selectors read by `mov r/m, Sreg`: the recompiled side reports whatever the emulator's segments are
        self.selectors = (ctypes.c_uint16 * 6).in_dll(self.lib, "g_seg_selector")
        pe = pefile.PE(exe, fast_load=True)
        self.base = pe.OPTIONAL_HEADER.ImageBase
        self.size = (pe.OPTIONAL_HEADER.SizeOfImage + PAGE - 1) & ~(PAGE - 1)
        # Snapshot the loaded image from the C side (it includes the patched import table).
        self.image = ctypes.string_at(self.mem + self.base, self.size)
        self.tib = ctypes.string_at(self.mem + TIB, PAGE)
        self.corrections = x87ref.Corrections(self.image, self.base, TIB)   # sites: find_correction_sites
        # rdtsc makes a run nondeterministic (games often seed their RNG with it): find every occurrence
        # (byte pattern 0F 31; a false match only turns a test into a skip)
        self.rdtsc_sites = []
        for sec in pe.sections:
            if not sec.Characteristics & 0x20000000:   # IMAGE_SCN_MEM_EXECUTE
                continue
            lo = sec.VirtualAddress
            text = self.image[lo:lo + sec.Misc_VirtualSize]
            k = text.find(b"\x0f\x31")
            while k >= 0:
                self.rdtsc_sites.append(self.base + lo + k)
                k = text.find(b"\x0f\x31", k + 1)

    def find_correction_sites(self, exe_funcs):
        """The instructions whose emulation tests/x87ref.py corrects, in the translated functions' code."""
        self.corrections.find_sites(exe_funcs)

    def cwrite(self, addr, data):
        ctypes.memmove(self.mem + addr, data, len(data))

    def cread(self, addr, n):
        return ctypes.string_at(self.mem + addr, n)

    def setup_state(self, rng, sane=False):
        if sane:  # every word is a moderate float (|x| in [2^-10, 2^10]); as doubles the high words are moderate too
            words = [(rng.getrandbits(1) << 31) | ((127 + rng.randrange(-10, 11)) << 23) | rng.getrandbits(23)
                     for _ in range(SCRATCH_SIZE // 4)]
            scratch = b"".join(w.to_bytes(4, "little") for w in words)
        else:
            scratch = rng.randbytes(SCRATCH_SIZE)
        ptr = lambda: SCRATCH + rng.randrange(0x100, SCRATCH_SIZE - 0x1000) & ~3
        small = lambda: rng.choice([0, 1, 2, 3, 4, 7, 8, 16, 31, 100, 255, 0x7fffffff, rng.randrange(1 << 16)])
        args = [ptr() if rng.random() < 0.5 else small() for _ in range(8)]
        esp = STACK_HI - 0x800
        stack = SENTINEL.to_bytes(4, "little") + b"".join(a.to_bytes(4, "little") for a in args)
        regs = [small(), ptr(), ptr(), small(), esp, ptr(), ptr(), ptr()]
        return scratch, stack, regs

    def run_unicorn(self, entry, scratch, stack, regs, code_hook=None, write_hook=None, double_model=False):
        """double_model: hold the x87 registers at double precision, as the recompiled code does (x87_ext)."""
        uc = Uc(UC_ARCH_X86, UC_MODE_32)
        if double_model:   # first, so the other hooks of an instruction see the registers as the model holds them
            uc.hook_add(UC_HOOK_CODE, x87ref.hold_as_doubles)
        if code_hook:
            uc.hook_add(UC_HOOK_CODE, code_hook)
        if write_hook:
            uc.hook_add(UC_HOOK_MEM_WRITE, write_hook)
        uc.mem_map(self.base, self.size)
        uc.mem_write(self.base, self.image)
        uc.mem_map(SCRATCH, SCRATCH_SIZE)
        uc.mem_write(SCRATCH, scratch)
        uc.mem_map(STACK_LO, STACK_HI - STACK_LO)
        uc.mem_write(regs[4], stack)
        # fs: -> thread information block, through a GDT entry (Unicorn has no fs base in 32-bit mode)
        uc.mem_map(GDT, PAGE)
        uc.mem_write(GDT, GDT_PAGE)
        uc.reg_write(UC_X86_REG_GDTR, (0, GDT, PAGE - 1, 0))
        for seg in (UC_X86_REG_SS, UC_X86_REG_DS, UC_X86_REG_ES):
            uc.reg_write(seg, 2 << 3)
        uc.reg_write(UC_X86_REG_FS, 3 << 3)
        uc.mem_map(TIB, PAGE)
        uc.mem_write(TIB, self.tib)
        demand = []

        def on_unmapped(uc_, access, addr, size, value, data):
            if access == UC_HOOK_MEM_FETCH_UNMAPPED or addr == SENTINEL:
                return False
            page = addr & ~(PAGE - 1)
            if page == TOP_PAGE or addr + size > 1 << 32:
                top.append(addr)
            uc_.mem_map(page, PAGE, UC_PROT_READ | UC_PROT_WRITE)  # data only: calling into it is a crash
            demand.append(page)
            if (addr + size - 1) & ~(PAGE - 1) != page:
                uc_.mem_map(page + PAGE, PAGE, UC_PROT_READ | UC_PROT_WRITE)
                demand.append(page + PAGE)
            return True

        top = []  # accesses to the last page: there a multi-byte access wraps to address 0 (see TOP_PAGE)
        uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, on_unmapped)
        # Page 0 is hit constantly through small random "pointers". Map it up front: QEMU can drop the
        # rest of a `rep movs` whose destination page gets mapped on demand mid-instruction.
        uc.mem_map(0, PAGE, UC_PROT_READ | UC_PROT_WRITE)
        demand.append(0)
        nondet = []
        for a in self.rdtsc_sites:
            uc.hook_add(UC_HOOK_CODE, lambda uc_, addr, size, d: (nondet.append(addr), uc_.emu_stop()), begin=a, end=a)
        uc.hook_add(UC_HOOK_INSN, cpuid_hook, None, 1, 0, UC_X86_INS_CPUID)
        for r, v in zip(REGS, regs):
            uc.reg_write(r, v)
        uc.reg_write(UC_X86_REG_FPCW, self.fpu_cw)
        uc.reg_write(UC_X86_REG_FPTAG, 0xFFFF)  # every register empty, as a Windows thread starts (and the C side)
        self.corrections.install(uc)
        uc.reg_write(UC_X86_REG_EFLAGS, 0x202)  # user-mode Windows: IF set
        try:
            uc.emu_start(entry, SENTINEL, timeout=2_000_000, count=2_000_000)
        except UcError as e:
            if uc.reg_read(UC_X86_REG_EIP) != SENTINEL:
                return None, f"unicorn: {e} at eip={uc.reg_read(UC_X86_REG_EIP):08x}", demand
        if top:
            return None, f"unicorn: access at {top[0]:08x}, in the top page of the 4 GiB space", demand
        if nondet:
            return None, "unicorn: nondeterministic (rdtsc)", demand
        if uc.reg_read(UC_X86_REG_EIP) != SENTINEL:
            return None, "unicorn: instruction limit", demand
        return uc, None, demand

    def run(self, f, trials, seed):
        """The function's outcome over all trials (see combine), with float-only differences classified."""
        outs = self.run_mode(f, trials, seed, sane=False)
        status, why = combine(outs, trials)
        failed = [t for t, (s, w) in enumerate(outs) if s == "fail"]
        if failed and self.uses_fp(f) and not any("trap" in outs[t][1] or "watchdog" in outs[t][1] for t in failed):
            if combine(self.run_mode(f, trials, seed, sane=True), trials)[0] in ("pass", "nan"):
                return "fp_range", why  # differs only for magnitudes beyond the double exponent range
            # The same inputs again, with the emulator's x87 registers held at double precision as the recompiled
            # code's are. If every failing trial then matches, and no trial fails, the difference is the extended
            # precision the model does not keep (80-bit constants and loads, results at 64-bit precision control)
            dm = self.run_mode(f, trials, seed, sane=False, double_model=True)
            if all(dm[t][0] in ("pass", "nan") for t in failed) and not any(s == "fail" for s, _ in dm):
                return "x87_ext", why
        return status, why

    def uses_fp(self, f):
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        for a, b in f["ranges"]:
            for ins in md.disasm(self.image[a - self.base:b - self.base], a):
                if ins.mnemonic.startswith("f") or ins.mnemonic.endswith(("ss", "ps")):
                    return True
        return False

    def run_mode(self, f, trials, seed, sane, double_model=False):
        """(status, reason) of each trial: pass, nan (only NaN bit patterns differ), fail or skip."""
        return [self.run_trial(f, t, seed, sane, double_model) for t in range(trials)]

    def run_trial(self, f, t, seed, sane, double_model):
        entry = f["entry"]
        nan_only = False
        rng = random.Random(seed * 1000003 + entry * 31 + t + (7777 if sane else 0))
        scratch, stack, regs = self.setup_state(rng, sane)
        uc, err, demand = self.run_unicorn(entry, scratch, stack, regs, double_model=double_model)
        if uc is None:
            return "skip", err
        # C side from the identical state
        for k, r in enumerate(SREGS):
            self.selectors[k] = uc.reg_read(r)
        self.cwrite(self.base, self.image)
        self.cwrite(SCRATCH, scratch)
        self.cwrite(STACK_LO, bytes(STACK_HI - STACK_LO))
        self.cwrite(TIB, self.tib)
        self.cwrite(GDT, GDT_PAGE)
        self.cwrite(regs[4], stack)
        for p in demand:
            self.cwrite(p, bytes(PAGE))
        cregs = (ctypes.c_uint32 * 8)(*regs)
        rc = self.lib.dt_run(entry, cregs, self.fpu_cw)
        if rc == 1:
            return "fail", f"trap {self.lib.dt_trap_msg().decode()}"
        if rc == 2:
            return "skip", "not recompiled"
        if rc == 3:
            return "fail", f"trial {t}: recompiled code did not return (watchdog)"
        for i, r in enumerate(REGS):
            u = uc.reg_read(r)
            if u != cregs[i] and nan_word(u.to_bytes(4, "little"), cregs[i].to_bytes(4, "little"), 0):
                nan_only = True
            elif u != cregs[i]:
                return "fail", f"trial {t}: {NAMES[i]} unicorn={u:08x} recomp={cregs[i]:08x}"
        regions = [(self.base, self.size), (SCRATCH, SCRATCH_SIZE), (STACK_LO, STACK_HI - STACK_LO), (TIB, PAGE), (GDT, PAGE)]
        regions += [(p, PAGE) for p in demand]
        for a, n in regions:
            um, cm = bytes(uc.mem_read(a, n)), self.cread(a, n)
            if um != cm:
                diffs = [i for i in range(n) if um[i] != cm[i]]
                if all(nan_word(um, cm, i) for i in diffs):
                    nan_only = True
                    continue
                k = next(i for i in diffs if not nan_word(um, cm, i))
                return "fail", f"trial {t}: memory differs at {a + k:08x} (unicorn {um[k]:02x}, recomp {cm[k]:02x})"
        return ("nan", "only NaN bit patterns differ") if nan_only else ("pass", None)


def combine(outs, trials):
    """One outcome from the trials': fail if any trial failed (its reason); otherwise pass, or nan if only NaN bit
    patterns differed, when at least one trial ran to the end on both sides (the reason then names the trials
    that could not run); skip if none could."""
    for t, (s, why) in enumerate(outs):
        if s == "fail":
            return "fail", why if why.startswith("trial") else f"trial {t}: {why}"
    compared = [s for s, _ in outs if s in ("pass", "nan")]
    skipped = [(t, why) for t, (s, why) in enumerate(outs) if s == "skip"]
    if not compared:
        return "skip", skipped[0][1]
    status = "nan" if "nan" in compared else "pass"
    notes = ["only NaN bit patterns differ"] if status == "nan" else []
    if skipped:
        notes.append(f"{len(compared)}/{trials} trials compared; trial {skipped[0][0]} skipped: {skipped[0][1]}")
    return status, "; ".join(notes) or None


def cpuid_hook(uc, data):
    """Same answers as runtime.c cpuid(): a plain Pentium-class CPU without MMX/SSE/3DNow!."""
    leaf = uc.reg_read(UC_X86_REG_EAX)
    vals = {0: (1, 0x756e6547, 0x6c65746e, 0x49656e69), 1: (0x683, 0, 0, 0x8111),
            0x80000000: (0x80000000, 0, 0, 0)}.get(leaf, (0, 0, 0, 0))
    for r, v in zip((UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX), vals):
        uc.reg_write(r, v)
    return True


def nan_word(um, cm, i):
    """True if byte i lies inside a float32/float64 (any alignment) that is NaN on both sides."""
    for size, mask_e, mask_m in ((4, 0x7f800000, 0x007fffff), (8, 0x7ff0000000000000, 0x000fffffffffffff)):
        for j in range(max(0, i - size + 1), i + 1):
            if j + size > len(um):
                continue
            a, b = int.from_bytes(um[j:j + size], "little"), int.from_bytes(cm[j:j + size], "little")
            if (a & mask_e) == mask_e and (a & mask_m) and (b & mask_e) == mask_e and (b & mask_m):
                return True
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("exe")
    ap.add_argument("functions_json")
    ap.add_argument("lib")
    ap.add_argument("--max", type=int, default=0)
    ap.add_argument("--trials", type=int, default=5)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--only", default="")
    ap.add_argument("--report", default="")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--shard", default="", help="k/n: test every n-th function starting at k")
    ap.add_argument("--allow-calls", action="store_true", help="also test functions that call others (whole call trees run on both sides)")
    ap.add_argument("--fpu-cw", default="0x027f", help="x87 control word both sides start with (see FPU_CW)")
    a = ap.parse_args()

    tester = Tester(a.exe, a.lib, int(a.fpu_cw, 16))
    d = json.load(open(a.functions_json))
    tester.find_correction_sites([f for f in d["functions"] if f["ranges"]])
    jumptables = {j["at"] for j in d["jumptables"]}
    funcs = [f for f in d["functions"] if f["ranges"]]
    filtered = []
    if a.only:
        funcs = [f for f in funcs if f["entry"] == int(a.only, 16)]
    else:
        funcs, filtered = pick_functions(tester.image, tester.base, funcs, jumptables, a.allow_calls)
    if a.max:
        funcs = funcs[:a.max]
    if a.shard:
        k, n = map(int, a.shard.split("/"))
        funcs = funcs[k::n]
        filtered = filtered[k::n]
    print(f"testing {len(funcs)} functions x {a.trials} trials ({len(filtered)} not selected)", flush=True)
    results = {"pass": [], "nan": [], "fp_range": [], "x87_ext": [], "fail": [], "skip": []}
    for f, why in filtered:
        results["skip"].append((f"0x{f['entry']:08x}", f["name"], f"not selected: {why}"))
    for i, f in enumerate(funcs):
        if a.verbose: print(f"  run 0x{f['entry']:08x}", flush=True)
        status, why = tester.run(f, a.trials, a.seed)
        results[status].append((f"0x{f['entry']:08x}", f["name"], why))
        if status == "fail":
            print(f"FAIL 0x{f['entry']:08x} {f['name']}: {why}", flush=True)
        if (i + 1) % 500 == 0:
            print(f"  ... {i + 1}: pass={len(results['pass'])} fail={len(results['fail'])} skip={len(results['skip'])}", flush=True)
    print("\n" + " ".join(f"{k}={len(v)}" for k, v in results.items()))
    if a.report:
        json.dump(results, open(a.report, "w"), indent=1)


if __name__ == "__main__":
    main()
