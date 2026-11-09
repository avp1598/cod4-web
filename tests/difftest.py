"""Differential tester: original x86 (under Unicorn) vs recompiled C, on identical random inputs.

For every selected function and several random trials, both sides start from the same image,
registers, stack (8 random arguments + a sentinel return address) and a 64 KiB random scratch
buffer. After the function returns we compare all general registers, the arithmetic flags and DF, and every
byte of memory either side could have touched.

Usage: difftest.py <exe> <functions.json> <build/librecomp.dylib> [--max N] [--trials K] [--only 0xADDR]

Pass the translator's out_all/functions_translated.json as <functions.json> to test exactly the functions
that were translated (Ghidra's plus the entries the translator found itself), with the instruction ranges
it decoded.

Outcomes, per function over all its trials:
  fail      some trial differs (registers or memory), or the recompiled code trapped or did not return
  pass      every trial that could run on both sides matched (the reason names any trial that could not)
  nan       as pass, except NaN bit patterns differ
  partial   no trial ran to the end, but trials matched up to a call into an import the model does not run (or
            whose effect is undefined there): both sides stop at that call, which the recompiled side must make
            next at the same stack pointer, and compare all registers and memory there
  fp_range  fails, but passes on inputs of moderate magnitude: values beyond the double exponent range
  x87_ext   fails, but every failing trial matches when the emulator holds its x87 registers at double
            precision as the recompiled code does (tests/x87ref.py): the 80-bit precision the model drops
  skip      no trial could run to the end in the emulator (the reason says why), or not selected
The emulator's x87 is corrected where it departs from the hardware (tests/x87ref.py). Windows imports run in a
deterministic model on the emulator side and are replayed, with their inputs checked, on the recompiled side
(tests/winmodel.py); a trial that reaches an import the model does not implement is skipped.
"""
import argparse
import collections
import ctypes
import json
import os
import random
import struct
import sys

import pefile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))   # run with -I: this directory is not on the path
import winmodel  # noqa: E402
import x87ref  # noqa: E402
from uchooks import bytes_or_zero, guarded  # noqa: E402
from capstone import CS_ARCH_X86, CS_MODE_32, CS_OP_IMM, CS_OP_MEM, Cs
from unicorn import UC_PROT_ALL, UC_PROT_EXEC, UC_PROT_NONE, UC_PROT_READ, UC_PROT_WRITE, UC_ARCH_X86, UC_HOOK_CODE, \
    UC_HOOK_INSN, UC_HOOK_MEM_FETCH_UNMAPPED, UC_HOOK_MEM_READ, UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE, \
    UC_HOOK_MEM_WRITE_UNMAPPED, UC_MEM_WRITE, UC_MODE_32, Uc, UcError
from unicorn.x86_const import (UC_X86_REG_FPTAG, UC_X86_INS_CPUID, UC_X86_REG_EAX, UC_X86_REG_EBP, UC_X86_REG_EBX, UC_X86_REG_ECX,
                               UC_X86_REG_EDI, UC_X86_REG_EDX, UC_X86_REG_EIP, UC_X86_REG_ESI,
                               UC_X86_REG_ESP, UC_X86_REG_FPCW, UC_X86_REG_EFLAGS, UC_X86_REG_FS,
                               UC_X86_REG_GDTR, UC_X86_REG_SS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_CS,
                               UC_X86_REG_GS, UC_X86_REG_MXCSR)

# x86 Sreg encoding order (es, cs, ss, ds, fs, gs), as runtime/cpu.h's g_seg_selector is indexed
SREGS = [UC_X86_REG_ES, UC_X86_REG_CS, UC_X86_REG_SS, UC_X86_REG_DS, UC_X86_REG_FS, UC_X86_REG_GS]
REGS = [UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EBX,
        UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_ESI, UC_X86_REG_EDI]
NAMES = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
PAGE = 0x1000
MAX_INSN = 15   # the longest x86 instruction, in bytes
SENTINEL = 0xDEADBEEF
LEFT_FRAME_TRAP = "control returned to an address no active caller returns to"   # runtime.c guest_enter
# EFLAGS compared after a run: CF PF AF ZF SF DF OF (the system flags are the harness's, and the same on both sides)
EFLAGS_COMPARED = 0xCD5
SCRATCH, SCRATCH_SIZE = 0x20000000, 0x10000
STACK_LO, STACK_HI = 0x002F0000, 0x00300000
# x87 control word both sides start with (--fpu-cw): by default MSVC's, 53-bit precision and round to
# nearest. Direct3D switches the FPU to 24-bit precision (0x007F) when it creates a device without
# D3DCREATE_FPU_PRESERVE, so that is the other regime the game's code runs in.
FPU_CW = 0x027F
TIB = 0x00010000   # GUEST_TIB in runtime.h: fs:[0] is the SEH chain head
GDT = 0x00001000
# The process start (Tester.boot): the entry point runs from the top of the stack with nothing but a return address
# on it, at the control word a Windows process starts with, for at most this many instructions
BOOT_ESP = STACK_HI - 0x100
BOOT_FPU_CW = 0x027F
# MXCSR a Windows thread starts with (and the processor after reset): every SSE exception masked, round to nearest.
# Unicorn 2.1 starts at 0, which code reading it back (stmxcsr) sees. The recompiled side: tests/difftest_api.c.
MXCSR_START = 0x1F80
BOOT_LIMIT = 200_000_000
TRIAL_LIMIT = 2_000_000
# Runs are bounded by instruction count only: a time limit would make outcomes depend on the machine's load
# (and on hooks such as difftrace's). Unicorn's emu_start takes 0 for "no time limit".
NO_TIME_LIMIT = 0
# A trial's frame lies this far below WinMain's (the booted stack above it stays intact: its SEH chain, the CRT's frame)
TRIAL_STACK_GAP = 0x800
# The last page of the 32-bit space. A multi-byte access there wraps to address 0 on x86 (and in Unicorn), but
# not in the recompiled code's flat guest memory. Neither can happen in the game: everything from 0x80000000 up
# is kernel space in a 32-bit Windows process, so trials whose random pointers reach this page are skipped.
TOP_PAGE = 0xFFFFF000
# Pages on-demand mapping maps only when an access lands in them (not along with the rest of their 64 KiB granule,
# see Tester.run_unicorn map_ordinary): accesses there are checked (TOP_PAGE above). The sentinel's page lies in the
# model's arena, which is mapped whole (see run_unicorn on_arena_access).
TOUCHED_ONLY = {TOP_PAGE}


def in_arena(page):
    """True for a page of the import model's VirtualAlloc arena (mapped whole: see Tester.run_unicorn)."""
    return winmodel.VALLOC_LO <= page < winmodel.VALLOC_HI


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
        self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        self.md.detail = True
        self.lib = ctypes.CDLL(lib)
        self.lib.dt_mem.restype = ctypes.c_void_p
        self.lib.dt_trap_msg.restype = ctypes.c_char_p
        self.lib.dt_run.argtypes = [ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32), ctypes.c_uint16]
        self.lib.dt_set_imports.argtypes = [ctypes.c_char_p, ctypes.c_uint32]
        self.lib.dt_import_name.restype = ctypes.c_char_p
        self.lib.dt_import_name.argtypes = [ctypes.c_uint32]
        self.lib.dt_imports_replayed.restype = ctypes.c_uint32
        self.lib.dt_num_imports.restype = ctypes.c_uint32
        self.lib.dt_add_import.restype = ctypes.c_uint32
        self.lib.dt_add_import.argtypes = [ctypes.c_char_p]
        if self.lib.dt_init(exe.encode()) != 0:
            raise SystemExit("dt_init failed")
        # the import slots the loader gave the IAT (runtime.c load_image), named as the runtime names them, then a
        # slot for each function the model implements that only GetProcAddress reaches
        names = [self.lib.dt_import_name(k).decode() for k in range(self.lib.dt_num_imports())]
        for n in winmodel.Model.dynamic_names(names):
            if self.lib.dt_add_import(n.encode()) != winmodel.IMPORT_BASE + winmodel.SLOT * len(names):
                raise SystemExit(f"dt_add_import({n}) did not return the next import slot")
            names.append(n)
        self.import_size = (len(names) * winmodel.SLOT + PAGE - 1) & ~(PAGE - 1)
        self.mem = self.lib.dt_mem()
        # Selectors read by `mov r/m, Sreg`: the recompiled side reports whatever the emulator's segments are
        self.selectors = (ctypes.c_uint16 * 6).in_dll(self.lib, "g_seg_selector")
        pe = pefile.PE(exe, fast_load=True)
        self.base = pe.OPTIONAL_HEADER.ImageBase
        self.entry = self.base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
        self.size = (pe.OPTIONAL_HEADER.SizeOfImage + PAGE - 1) & ~(PAGE - 1)
        # The image's page protections as Windows maps them: headers read-only, each section by its characteristics,
        # anything between them inaccessible. So in the emulator, as in the game, data cannot be called and
        # read-only sections cannot be written (the recompiled side can only call translated code at all).
        self.image_prot = [(self.base, (pe.OPTIONAL_HEADER.SizeOfHeaders + PAGE - 1) & ~(PAGE - 1), UC_PROT_READ)]
        for sec in pe.sections:
            ch = sec.Characteristics
            perms = (UC_PROT_READ if ch & 0x40000000 else 0) | (UC_PROT_WRITE if ch & 0x80000000 else 0) \
                | (UC_PROT_EXEC if ch & 0x20000000 else 0)
            self.image_prot.append((self.base + sec.VirtualAddress, (sec.Misc_VirtualSize + PAGE - 1) & ~(PAGE - 1), perms))
        # Snapshot the loaded image from the C side (it includes the patched import table).
        self.image = ctypes.string_at(self.mem + self.base, self.size)
        # The TEB as runtime_init writes it, with the client id the import model reports (winmodel.py)
        tib = bytearray(ctypes.string_at(self.mem + TIB, PAGE))
        struct.pack_into("<II", tib, winmodel.TEB_PROCESS_ID, winmodel.PROCESS_ID, winmodel.THREAD_ID)
        self.tib = bytes(tib)
        self.model = winmodel.Model(names, TIB, self.base)
        # The state trials start from: the loaded image until boot() replaces it with the process after start-up
        self.stack = bytes(STACK_HI - STACK_LO)
        self.boot_pages = {}      # ordinary pages the start-up touched -> their contents
        self.boot_model = None    # the import model's state after start-up (winmodel.Model.snapshot)
        self.trial_esp = STACK_HI - TRIAL_STACK_GAP
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

    def find_winmain(self):
        """WinMain: what the CRT start-up calls with the image base as hInstance (`push ImageBase; call WinMain`), in
        the start-up function MSVC's entry point jumps to (`call __security_init_cookie; jmp __tmainCRTStartup`)."""
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        md.detail = True
        head = list(md.disasm(self.image[self.entry - self.base:self.entry - self.base + 16], self.entry, 2))
        if [i.mnemonic for i in head] != ["call", "jmp"] or head[1].operands[0].type != CS_OP_IMM:
            raise SystemExit(f"entry point {self.entry:08x} is not MSVC's `call; jmp` start-up")
        start = head[1].operands[0].imm
        found, prev = [], None
        for ins in md.disasm(self.image[start - self.base:start - self.base + 0x400], start):
            if ins.mnemonic == "call" and ins.operands[0].type == CS_OP_IMM and prev is not None \
                    and prev.mnemonic == "push" and prev.operands[0].type == CS_OP_IMM and prev.operands[0].imm == self.base:
                found.append(ins.operands[0].imm)
            prev = ins
        if len(found) != 1:
            raise SystemExit(f"start-up at {start:08x}: {len(found)} calls with the image base pushed, expected one (WinMain)")
        return found[0]

    def boot(self):
        """Starts the process: runs the exe from its entry point (the CRT's start-up: security cookie, heap, TLS,
        locks, I/O, command line, environment, C and C++ initializers) to the entry of WinMain, under the emulator
        and the import model, and makes that the state every trial starts from. Every function of the game runs
        after start-up, inside WinMain's call, so random inputs over a CRT that never started (no heap, no per-thread
        data) would test states the game cannot be in."""
        winmain = self.find_winmain()
        regs = [0] * 8
        regs[4] = BOOT_ESP
        uc, err, demand = self.run_unicorn(self.entry, bytes(SCRATCH_SIZE), SENTINEL.to_bytes(4, "little"), regs,
                                           boot=winmain)
        if uc is None:
            raise SystemExit(f"start-up from {self.entry:08x} did not reach WinMain at {winmain:08x}: {err}")
        self.image = bytes(uc.mem_read(self.base, self.size))
        self.tib = bytes(uc.mem_read(TIB, PAGE))
        self.stack = bytes(uc.mem_read(STACK_LO, STACK_HI - STACK_LO))
        self.boot_pages = {p: bytes(uc.mem_read(p, PAGE)) for p in demand}
        self.boot_model = self.model.snapshot(uc)
        self.trial_esp = (uc.reg_read(UC_X86_REG_ESP) - TRIAL_STACK_GAP) & ~0xF
        calls = collections.Counter(self.model.names[c.slot] for c in self.model.records)
        return winmain, len(self.model.records), calls

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
        esp = self.trial_esp
        stack = SENTINEL.to_bytes(4, "little") + b"".join(a.to_bytes(4, "little") for a in args)
        regs = [small(), ptr(), ptr(), small(), esp, ptr(), ptr(), ptr()]
        return scratch, stack, regs

    def run_unicorn(self, entry, scratch, stack, regs, code_hook=None, write_hook=None, double_model=False, boot=None):
        """A trial from the booted state (see boot), ending at the sentinel return address; or with boot=WinMain's
        address, the process start, from the loaded image to WinMain. Returns (uc, None, the pages mapped on demand,
        to compare) or (None, why it could not run to the end, ...).
        A trial also ends at a `ret` that pops a slot above its return address to where no active call returns:
        code reached by a jump, not a call, that runs in a caller's frame it does not have here, returning to one of
        the random arguments. The emulator is left as after that `ret`, and self.left_frame holds (address of the
        ret, where it returned); the recompiled side traps there (runtime.c guest_enter). A ret to the return
        address of a call still active (one the trial made after moving ESP above its return address) continues,
        on both sides: the recompiled code's ret_to unwinds to that call.
        double_model: hold the x87 registers at double precision, as the recompiled code does (x87_ext)."""
        until = SENTINEL if boot is None else boot
        uc = Uc(UC_ARCH_X86, UC_MODE_32)
        if double_model:   # first, so the other hooks of an instruction see the registers as the model holds them
            uc.hook_add(UC_HOOK_CODE, guarded(x87ref.hold_as_doubles))
        if code_hook:
            uc.hook_add(UC_HOOK_CODE, guarded(code_hook))
        if write_hook:
            uc.hook_add(UC_HOOK_MEM_WRITE, guarded(write_hook))
        uc.mem_map(self.base, self.size)
        uc.mem_write(self.base, self.image)
        uc.mem_protect(self.base, self.size, UC_PROT_NONE)
        for lo, n, perms in self.image_prot:
            uc.mem_protect(lo, n, perms)
        uc.mem_map(SCRATCH, SCRATCH_SIZE, UC_PROT_READ | UC_PROT_WRITE)   # heap-like data and a stack: not code
        uc.mem_write(SCRATCH, scratch)
        uc.mem_map(STACK_LO, STACK_HI - STACK_LO, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_write(STACK_LO, self.stack)
        uc.mem_write(regs[4], stack)
        # fs: -> thread information block, through a GDT entry (Unicorn has no fs base in 32-bit mode)
        uc.mem_map(GDT, PAGE, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_write(GDT, GDT_PAGE)
        uc.reg_write(UC_X86_REG_GDTR, (0, GDT, PAGE - 1, 0))
        for seg in (UC_X86_REG_SS, UC_X86_REG_DS, UC_X86_REG_ES):
            uc.reg_write(seg, 2 << 3)
        uc.reg_write(UC_X86_REG_FS, 3 << 3)
        uc.mem_map(TIB, PAGE, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_write(TIB, self.tib)
        # The model's arena, mapped whole: a Unicorn region per reservation made trials with thousands of
        # allocations crawl. The model's page states (reserved, committed, protection) are enforced by the arena
        # hooks below; its other pages are ordinary memory, given out as the code touches them.
        uc.mem_map(winmodel.VALLOC_LO, winmodel.VALLOC_HI - winmodel.VALLOC_LO, UC_PROT_ALL)
        for a, n in winmodel.runs(p for p in self.boot_pages if not in_arena(p)):
            uc.mem_map(a, n, UC_PROT_READ | UC_PROT_WRITE)
        for p, data in self.boot_pages.items():
            uc.mem_write(p, data)
        demand = []
        stopped = []   # why a hook ended the run (a skip)
        self.left_frame = None
        left = []      # (ret address, target, its slot, the slot's bytes) of a ret leaving the trial's frame
        calls = {}     # slot above the trial's return address -> return address a call in the trial pushed there

        def insn_at(uc_):
            eip = uc_.reg_read(UC_X86_REG_EIP)
            return next(self.md.disasm(bytes_or_zero(uc_, eip, MAX_INSN), eip, count=1), None)

        def drop_calls_below(esp):
            """Calls whose return address slot is below ESP have returned (or been unwound past)."""
            for s in [s for s in calls if s < esp]:
                del calls[s]

        def on_stack_write(uc_, access, addr, size, value, data):
            """Writes above the trial's return address: a call pushing its return address, or other data (which
            replaces any return address there)."""
            for s in range(addr - 3, addr + size):
                calls.pop(s, None)
            ins = insn_at(uc_)
            if ins is not None and ins.mnemonic == "call" and addr == (uc_.reg_read(UC_X86_REG_ESP) - 4) & 0xFFFFFFFF:
                calls[addr] = ins.address + ins.size

        def on_stack_read(uc_, access, addr, size, value, data):
            """Reads above the trial's return address: arguments, or a ret, which may leave the trial's frame."""
            ins = insn_at(uc_)
            if ins is None or ins.mnemonic != "ret" or addr != uc_.reg_read(UC_X86_REG_ESP):
                return
            slot = bytes(uc_.mem_read(addr, 4))
            target = int.from_bytes(slot, "little")
            if any(s >= addr and ra == target for s, ra in calls.items()):   # returns to an active call
                drop_calls_below(addr + 4 + (ins.operands[0].imm if ins.operands else 0))
                return
            # Leaves the frame. The run must end after this ret, not inside it: stopped from within an instruction
            # (emu_stop here), Unicorn restores its lazily computed flags wrongly when a code hook is installed (as
            # the instruction limit's always is): AF after add, CF and OF after shl or imul. So the ret is sent to
            # the sentinel, where the run ends after it; the slot's bytes and the real target are put back below.
            left.append((ins.address, target, addr, slot))
            uc_.mem_write(addr, SENTINEL.to_bytes(4, "little"))

        def on_unmapped(uc_, access, addr, size, value, data):
            """Accesses outside everything mapped (the arena is mapped whole: see on_arena_access)."""
            if access == UC_HOOK_MEM_FETCH_UNMAPPED:
                return False
            page = addr & ~(PAGE - 1)
            if page == TOP_PAGE or addr + size > 1 << 32:
                top.append(addr)
            pages = [page] if (addr + size - 1) & ~(PAGE - 1) == page else [page, page + PAGE]
            for p in pages:
                if not any(lo <= p <= hi for lo, hi, _ in uc_.mem_regions()):
                    why = map_ordinary(uc_, p)
                    if why is not None:
                        stopped.append(f"access at {addr:08x}: {why}")
                        return False
            return True

        def map_ordinary(uc_, page):
            """Maps ordinary memory on demand as zeroed data (not executable: calling into it is a crash): the free
            pages of `page`'s 64 KiB allocation granule at once, as few Unicorn regions (see winmodel.runs), so a
            run walking through memory does not map thousands of single pages. Every such page is zero on both
            sides and compared (demand). Outside the model's arena only (no reservation lies here). The top page
            is mapped only when touched itself, so on_unmapped still sees those accesses. Ordinary memory, here
            and in the arena, is bounded (see within_limit); beyond it the access faults and the reason is
            returned (None when mapped)."""
            lo = page & ~(winmodel.GRANULARITY - 1)
            mapped = list(uc_.mem_regions())
            new = [p for p in range(lo, lo + winmodel.GRANULARITY, PAGE)
                   if (p == page or p not in TOUCHED_ONLY) and not any(a <= p <= b for a, b, _ in mapped)]
            why = within_limit(len(new))
            if why is not None:
                return why
            for a, n in winmodel.runs(new):
                uc_.mem_map(a, n, UC_PROT_READ | UC_PROT_WRITE)
            demand.extend(new)
            return None

        def within_limit(n):
            """Why `n` more pages of ordinary memory cannot be given out, or None. At most winmodel.COMMIT_LIMIT
            bytes, the memory of the machine the model stands for: without a bound, a loop striding through memory
            from a random pointer takes a page per step until the instruction limit (and each such page is
            compared, and outside the arena mapped as a Unicorn region, whose cost grows faster than quadratically
            in their number)."""
            if (len(demand) + n) * PAGE > winmodel.COMMIT_LIMIT:
                return (f"more than {winmodel.COMMIT_LIMIT >> 20} MiB touched outside the image, stack and the "
                        "model's allocations (the modelled machine's memory, winmodel.COMMIT_LIMIT)")
            return None

        def arena_ordinary(page):
            """An arena page outside the model's reservations, touched: ordinary memory, zero on both sides and
            compared, as map_ordinary gives out (a page at a time: the model's placement avoids these pages).
            Returns why it cannot be given out, or None."""
            if page in self.model.ordinary:
                return None
            why = within_limit(1)
            if why is None:
                self.model.give_ordinary(page)
                demand.append(page)
            return why

        def arena_fault(page, need):
            """Why an access needing `need` to an arena page faults (as Windows would), or None."""
            if self.model.region_of(page) is not None:
                return self.model.fault_in_arena(page, need)
            if need == UC_PROT_EXEC:
                return "execution in ordinary memory (data pages, not executable)"
            return arena_ordinary(page)

        def arena_pages(addr, size):
            last = min(addr + size, winmodel.VALLOC_HI) - 1
            return range(max(addr, winmodel.VALLOC_LO) & ~(PAGE - 1), (last & ~(PAGE - 1)) + PAGE, PAGE)

        def on_arena_access(uc_, access, addr, size, value, data):
            """Reads and writes in (or reaching into) the arena, faulting where Windows would: a reserved page not
            committed, a protection without the access, more ordinary memory than the limit; and a data access at
            the sentinel address (the return address no code may read: it is unmapped on Windows)."""
            if addr == SENTINEL:
                fault(uc_, addr, "the sentinel return address, read or written as data (unmapped on Windows)")
                return
            need = UC_PROT_WRITE if access == UC_MEM_WRITE else UC_PROT_READ
            for page in arena_pages(addr, size):
                why = arena_fault(page, need)
                if why is not None:
                    fault(uc_, addr, why)
                    return

        def on_arena_exec(uc_, addr, size, data):
            for page in arena_pages(addr, size):
                why = arena_fault(page, UC_PROT_EXEC)
                if why is not None:
                    fault(uc_, addr, why)
                    return

        def fault(uc_, addr, why):
            """Ends the run as Windows' access violation would end the trial: a skip, saying why."""
            stopped.append(f"access at {addr:08x}: {why}")
            uc_.emu_stop()

        def ensure(uc_, page):
            """For the import model: an ordinary page's protection, given out as the code's accesses are."""
            if in_arena(page):
                why = arena_ordinary(page)
            else:
                for lo, hi, perms in uc_.mem_regions():
                    if lo <= page <= hi:
                        return perms
                why = map_ordinary(uc_, page)
            if why is not None:
                raise winmodel.Skip(f"an import's access at {page:08x}: {why}")
            return UC_PROT_READ | UC_PROT_WRITE

        def on_import(uc_, addr, size, data):
            if (addr - winmodel.IMPORT_BASE) % winmodel.SLOT:
                stopped.append(f"execution at {addr:08x}, inside an import slot")
                uc_.emu_stop()
                return
            try:
                self.model.call(uc_, (addr - winmodel.IMPORT_BASE) // winmodel.SLOT)
                drop_calls_below(uc_.reg_read(UC_X86_REG_ESP))   # the import returned (no hooked read pops it)
            except winmodel.Skip as e:
                stopped.append(str(e))
                uc_.emu_stop()
            except UcError as e:   # the model's own use of Unicorn: a bug, not the code under test faulting
                raise winmodel.ModelError(f"import model at {addr:08x}: {e}") from e

        # Import slots: the IAT holds IMPORT_BASE + 16 * k (runtime.c), so a call through it lands here
        uc.mem_map(winmodel.IMPORT_BASE, self.import_size, UC_PROT_READ | UC_PROT_EXEC)
        uc.hook_add(UC_HOOK_CODE, guarded(on_import), begin=winmodel.IMPORT_BASE, end=winmodel.IMPORT_BASE + self.import_size - 1)
        base = None if boot is not None else self.boot_model
        if base is not None:
            winmodel.Model.write_snapshot(uc, base)
        self.model.reset(ensure, [p for p in self.boot_pages if in_arena(p)], base)
        # From a page below the arena: an access starting there can reach into it
        uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, guarded(on_arena_access),
                    begin=winmodel.VALLOC_LO - PAGE, end=winmodel.VALLOC_HI - 1)
        uc.hook_add(UC_HOOK_CODE, guarded(on_arena_exec), begin=winmodel.VALLOC_LO, end=winmodel.VALLOC_HI - 1)

        top = []  # accesses to the last page: there a multi-byte access wraps to address 0 (see TOP_PAGE)
        uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, guarded(on_unmapped))
        # Page 0 is hit constantly through small random "pointers". Map it up front: QEMU can drop the
        # rest of a `rep movs` whose destination page gets mapped on demand mid-instruction.
        if 0 not in self.boot_pages:
            uc.mem_map(0, PAGE, UC_PROT_READ | UC_PROT_WRITE)
            demand.append(0)
        nondet = []
        for a in self.rdtsc_sites:
            uc.hook_add(UC_HOOK_CODE, guarded(lambda uc_, addr, size, d: (nondet.append(addr), uc_.emu_stop())), begin=a, end=a)
        uc.hook_add(UC_HOOK_INSN, guarded(cpuid_hook), None, 1, 0, UC_X86_INS_CPUID)
        if boot is None:
            uc.hook_add(UC_HOOK_MEM_READ, guarded(on_stack_read), begin=regs[4] + 4, end=STACK_HI - 1)
            uc.hook_add(UC_HOOK_MEM_WRITE, guarded(on_stack_write), begin=regs[4] + 4, end=STACK_HI - 1)
        for r, v in zip(REGS, regs):
            uc.reg_write(r, v)
        uc.reg_write(UC_X86_REG_FPCW, self.fpu_cw if boot is None else BOOT_FPU_CW)
        uc.reg_write(UC_X86_REG_FPTAG, 0xFFFF)  # every register empty, as a Windows thread starts (and the C side)
        uc.reg_write(UC_X86_REG_MXCSR, MXCSR_START)
        self.corrections.install(uc, guarded)
        uc.reg_write(UC_X86_REG_EFLAGS, 0x202)  # user-mode Windows: IF set
        try:
            uc.emu_start(entry, until, timeout=NO_TIME_LIMIT, count=TRIAL_LIMIT if boot is None else BOOT_LIMIT)
        except UcError as e:
            if stopped and self.model.end is None:
                return None, stopped[0], demand
            if uc.reg_read(UC_X86_REG_EIP) != until:
                return None, f"unicorn: {e} at eip={uc.reg_read(UC_X86_REG_EIP):08x}", demand
        if stopped and (self.model.end is None or boot is not None):
            return None, stopped[0], demand
        if top:
            return None, f"unicorn: access at {top[0]:08x}, in the top page of the 4 GiB space", demand
        if self.model.end is not None:   # stopped at an import the model cannot run: compared as it is there
            return uc, None, demand + self.model.pages()
        if left:   # the ret that left the trial's frame ran to the sentinel: its real target and slot put back
            at, target, slot, data = left[0]
            uc.mem_write(slot, data)
            uc.reg_write(UC_X86_REG_EIP, target)
            self.left_frame = (at, target)
            return uc, None, demand + self.model.pages()
        if nondet:
            return None, "unicorn: nondeterministic (rdtsc)", demand
        if uc.reg_read(UC_X86_REG_EIP) != until:
            return None, "unicorn: instruction limit", demand
        if boot is not None:
            return uc, None, demand
        return uc, None, demand + self.model.pages()

    def prepare_recomp(self, uc, scratch, stack, regs, demand):
        """The recompiled side's starting state, identical to the emulator's (uc: its run, or None if it did not
        finish), and the emulator's import calls to replay."""
        for k, r in enumerate(SREGS):
            self.selectors[k] = uc.reg_read(r) if uc is not None else 0
        self.cwrite(self.base, self.image)
        self.cwrite(SCRATCH, scratch)
        self.cwrite(STACK_LO, self.stack)
        self.cwrite(TIB, self.tib)
        self.cwrite(GDT, GDT_PAGE)
        self.cwrite(regs[4], stack)
        self.cwrite(winmodel.IMPORT_BASE, bytes(self.import_size))
        for p in demand:
            self.cwrite(p, bytes(PAGE))
        for p, data in self.boot_pages.items():   # after the zeroed pages: model pages from start-up keep contents
            self.cwrite(p, data)
        if self.boot_model is not None:
            for p, (prot, data) in self.boot_model[1].items():
                self.cwrite(p, data)
        record = self.model.serialize()
        self.lib.dt_set_imports(record, len(record))

    def run(self, f, trials, seed):
        """The function's outcome over all trials (see combine), with float-only differences classified."""
        outs = self.run_mode(f, trials, seed, sane=False)
        status, why = combine(outs, trials)
        failed = [t for t, (s, w) in enumerate(outs) if s == "fail"]
        if failed and self.uses_fp(f) and not any("trap" in outs[t][1] or "watchdog" in outs[t][1] for t in failed):
            if combine(self.run_mode(f, trials, seed, sane=True), trials)[0] in ("pass", "nan", "partial"):
                return "fp_range", why  # differs only for magnitudes beyond the double exponent range
            # The same inputs again, with the emulator's x87 registers held at double precision as the recompiled
            # code's are. If every failing trial then matches, and no trial fails, the difference is the extended
            # precision the model does not keep (80-bit constants and loads, results at 64-bit precision control)
            dm = self.run_mode(f, trials, seed, sane=False, double_model=True)
            if all(dm[t][0] in ("pass", "nan", "partial") for t in failed) and not any(s == "fail" for s, _ in dm):
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
        self.prepare_recomp(uc, scratch, stack, regs, demand)
        cregs = (ctypes.c_uint32 * 9)(*regs, 0)   # [8]: EFLAGS out
        rc = self.lib.dt_run(entry, cregs, self.fpu_cw)
        trap = self.lib.dt_trap_msg().decode() if rc == 1 else None
        if self.left_frame is not None:
            at, target = self.left_frame
            if trap != f"{target:08x}: {LEFT_FRAME_TRAP}":
                return "fail", (f"trial {t}: the ret at {at:08x} returned above the trial's return address, to "
                                f"{target:08x}, where the recompiled code should trap; it gave rc={rc}"
                                + (f", trap {trap}" if trap else ""))
        elif rc == 1:
            return "fail", f"trap {trap}"
        if rc == 2:
            return "skip", "not recompiled"
        if rc == 3:
            return "fail", f"trial {t}: recompiled code did not return (watchdog)"
        if rc == 4:
            end = f", then the call where it stopped ({self.model.end[2]})" if self.model.end else ""
            return "fail", (f"trial {t}: recompiled code returned after {self.lib.dt_imports_replayed()} of the "
                            f"emulator's {len(self.model.records)} import calls{end}")
        if rc == 5 and self.model.end is None:
            raise SystemExit("dt_run stopped at an import end the emulator's record does not have (harness bug)")
        for i, r in enumerate(REGS):
            u = uc.reg_read(r)
            if u != cregs[i] and nan_word(u.to_bytes(4, "little"), cregs[i].to_bytes(4, "little"), 0):
                nan_only = True
            elif u != cregs[i]:
                return "fail", f"trial {t}: {NAMES[i]} unicorn={u:08x} recomp={cregs[i]:08x}"
        uf = uc.reg_read(UC_X86_REG_EFLAGS) & EFLAGS_COMPARED
        if uf != cregs[8]:
            return "fail", f"trial {t}: eflags unicorn={uf:03x} recomp={cregs[8]:03x} (CF PF AF ZF SF DF OF)"
        regions = [(self.base, self.size), (SCRATCH, SCRATCH_SIZE), (STACK_LO, STACK_HI - STACK_LO), (TIB, PAGE), (GDT, PAGE),
                   (winmodel.IMPORT_BASE, self.import_size)] + [(p, PAGE) for p in self.boot_pages]
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
        if self.model.end is not None:
            return "partial", f"matched up to the call where the emulator stopped: {self.model.end[2]}" + \
                ("; only NaN bit patterns differ" if nan_only else "")
        if self.left_frame is not None:
            return "partial", (f"matched up to the ret at {self.left_frame[0]:08x}, which returns from above the "
                               "trial's return address: code reached by a jump, run in a caller's frame it does not "
                               "have here" + ("; only NaN bit patterns differ" if nan_only else ""))
        return ("nan", "only NaN bit patterns differ") if nan_only else ("pass", None)


def combine(outs, trials):
    """One outcome from the trials': fail if any trial failed (its reason); otherwise pass, or nan if only NaN bit
    patterns differed, when at least one trial ran to the end on both sides (the reason then names the trials
    that did not); partial if trials matched only up to an import the model does not run (the first one's
    reason); skip if none could run."""
    for t, (s, why) in enumerate(outs):
        if s == "fail":
            return "fail", why if why.startswith("trial") else f"trial {t}: {why}"
    compared = [s for s, _ in outs if s in ("pass", "nan")]
    partial = [(t, why) for t, (s, why) in enumerate(outs) if s == "partial"]
    skipped = [(t, why) for t, (s, why) in enumerate(outs) if s == "skip"]
    if not compared:
        if partial:
            return "partial", f"trial {partial[0][0]}: {partial[0][1]}"
        return "skip", skipped[0][1]
    status = "nan" if "nan" in compared else "pass"
    notes = ["only NaN bit patterns differ"] if status == "nan" else []
    if partial:
        notes.append(f"{len(partial)}/{trials} trials matched up to an import the model does not run")
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
    winmain, ncalls, calls = tester.boot()
    print(f"start-up: entry {tester.entry:08x} to WinMain {winmain:08x}, {ncalls} import calls", flush=True)
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
    results = {"pass": [], "nan": [], "partial": [], "fp_range": [], "x87_ext": [], "fail": [], "skip": []}
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
