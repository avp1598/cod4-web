"""Finds where a difftest failure starts: runs one function on one trial under Unicorn and in the recompiled
code (a TRACE=1 build), records the state before every instruction on both sides, and prints the first
instruction where the address or a general register differs, with the instructions leading up to it.

  difftrace.py <exe> <functions.json> <build/librecomp_trace.dylib> 0xENTRY [--trial T] [--seed S] [--sane]

The inputs are exactly those tests/difftest.py used for that function, trial and seed.
"""
import argparse
import ctypes
import os
import random
import sys
from fractions import Fraction

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from difftest import GDT, GDT_PAGE, NAMES, PAGE, REGS, SCRATCH, SREGS, STACK_HI, STACK_LO, TIB, Tester  # noqa: E402
from capstone import CS_ARCH_X86, CS_MODE_32, Cs  # noqa: E402
from unicorn import x86_const  # noqa: E402

FP_REGS = [getattr(x86_const, f"UC_X86_REG_FP{i}") for i in range(8)]


def uc_st0(uc):
    """ST(0) under Unicorn as an exact Fraction (the 80-bit register value), or the string 'nan'/'inf'."""
    top = (uc.reg_read(x86_const.UC_X86_REG_FPSW) >> 11) & 7
    mant, se = uc.reg_read(FP_REGS[top])
    sign, e = -1 if se & 0x8000 else 1, se & 0x7fff
    if e == 0x7fff:
        frac = mant & ((1 << 63) - 1)
        # NaN: sign, quiet bit and the payload bits a double can hold; infinity: its sign
        return ("nan", sign, frac >> 11) if frac else ("inf", sign)
    return sign * Fraction(mant) * Fraction(2) ** ((e if e else 1) - 16383 - 63)


def exact(d):
    import struct
    bits = struct.unpack("<Q", struct.pack("<d", d))[0]
    sign = -1 if bits >> 63 else 1
    if d != d:
        return ("nan", sign, bits & ((1 << 52) - 1))
    if d in (float("inf"), float("-inf")):
        return ("inf", sign)
    return Fraction(d)


class TraceRec(ctypes.Structure):
    _fields_ = [("addr", ctypes.c_uint32), ("regs", ctypes.c_uint32 * 8), ("st0", ctypes.c_double),
                ("top", ctypes.c_uint32)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("exe")
    ap.add_argument("functions_json")
    ap.add_argument("lib")
    ap.add_argument("entry")
    ap.add_argument("--trial", type=int, default=0)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--sane", action="store_true", help="the moderate-float inputs difftest's fp_range retry uses")
    ap.add_argument("--context", type=int, default=12)
    ap.add_argument("--fpu-cw", default="0x027f", help="x87 control word both sides start with")
    a = ap.parse_args()

    entry = int(a.entry, 16)
    t = Tester(a.exe, a.lib, int(a.fpu_cw, 16))
    import json
    t.find_fsave_sites([f for f in json.load(open(a.functions_json))["functions"] if f["ranges"]])
    md = Cs(CS_ARCH_X86, CS_MODE_32)

    def dis(addr):
        ins = next(md.disasm(t.image[addr - t.base:addr - t.base + 16], addr, count=1), None)
        return f"{ins.mnemonic} {ins.op_str}" if ins else "??"

    lib = t.lib
    lib.dt_trace_buf.restype = ctypes.POINTER(TraceRec)
    rng = random.Random(a.seed * 1000003 + entry * 31 + a.trial + (7777 if a.sane else 0))
    scratch, stack, regs = t.setup_state(rng, a.sane)

    utrace = []
    writer = {}  # guest address -> (step, eip) of the instruction that last wrote it under Unicorn

    ust0 = []

    def hook(uc, addr, size, data):
        utrace.append((addr, [uc.reg_read(r) for r in REGS]))
        ust0.append(uc_st0(uc))

    def on_write(uc, access, addr, size, value, data):
        for i in range(size):
            writer[addr + i] = (len(utrace) - 1, utrace[-1][0] if utrace else 0)

    uc, err, demand = t.run_unicorn(entry, scratch, stack, regs, code_hook=hook, write_hook=on_write)
    if uc is None:
        print("unicorn did not finish:", err)
    for k, r in enumerate(SREGS):
        t.selectors[k] = uc.reg_read(r) if uc is not None else 0
    t.cwrite(t.base, t.image)
    t.cwrite(SCRATCH, scratch)
    t.cwrite(STACK_LO, bytes(STACK_HI - STACK_LO))
    t.cwrite(TIB, t.tib)
    t.cwrite(GDT, GDT_PAGE)
    t.cwrite(regs[4], stack)
    for p in demand:
        t.cwrite(p, bytes(PAGE))
    cap = len(utrace) + 100000
    lib.dt_trace_start(cap)
    cregs = (ctypes.c_uint32 * 8)(*regs)
    rc = lib.dt_run(entry, cregs, t.fpu_cw)
    n = lib.dt_trace_len()
    buf = lib.dt_trace_buf()
    ctrace = [(buf[i].addr, list(buf[i].regs)) for i in range(n)]
    cst0 = [exact(buf[i].st0) for i in range(n)]
    for j in range(1, min(len(ust0), len(cst0))):
        if ust0[j] != cst0[j] and utrace[j][0] == ctrace[j][0]:
            u, r = ust0[j], cst0[j]
            show = lambda v: (f"{v[0]}(sign {v[1]}, payload {v[2]:#x})" if v[0] == "nan" else f"{v[1] * float('inf')}") \
                if isinstance(v, tuple) else f"{float(v)!r}"
            print(f"x87 ST(0) first differs before step {j}: unicorn {show(u)} recomp {show(r)}"
                  + (f" (relative {float(abs(u - r) / abs(u)):.3g})" if not isinstance(u, tuple) and not isinstance(r, tuple) and u else ""))
            print(f"  produced by step {j - 1}: {utrace[j - 1][0]:08x} {dis(utrace[j - 1][0])}")
            break
    print(f"rc={rc} trap={lib.dt_trap_msg().decode() if rc == 1 else ''} unicorn={len(utrace)} insns, recomp={n} insns")

    k = 0
    while k < min(len(utrace), len(ctrace)):
        (ua, ur), (ca, cr) = utrace[k], ctrace[k]
        if ua != ca or ur != cr:
            break
        k += 1
    if k == min(len(utrace), len(ctrace)) and len(utrace) == len(ctrace):
        print("register traces identical; memory differences and the Unicorn instruction that last wrote each:")
        regions = [(t.base, t.size), (SCRATCH, len(scratch)), (STACK_LO, STACK_HI - STACK_LO)] + [(p, PAGE) for p in demand]
        shown = 0
        for lo, n in regions:
            um, cm = bytes(uc.mem_read(lo, n)), t.cread(lo, n)
            for i in range(n):
                if um[i] != cm[i] and shown < 12:
                    step, eip = writer.get(lo + i, (-1, 0))
                    print(f"  {lo + i:08x} unicorn {um[i]:02x} recomp {cm[i]:02x}   written at step {step} by "
                          f"{eip:08x} {dis(eip) if eip else '(not written: initial value)'}")
                    shown += 1
        return
    for j in range(max(0, k - a.context), k):
        addr, r = utrace[j]
        print(f"  {j:7d} {addr:08x} {dis(addr):40s}")
    print(f"first difference at step {k}:")
    if k < len(utrace):
        ua, ur = utrace[k]
        print(f"  unicorn {ua:08x} {dis(ua):40s} " + " ".join(f"{NAMES[i]}={ur[i]:08x}" for i in range(8)))
    if k < len(ctrace):
        ca, cr = ctrace[k]
        print(f"  recomp  {ca:08x} {dis(ca):40s} " + " ".join(f"{NAMES[i]}={cr[i]:08x}" for i in range(8)))
    if k < len(utrace) and k < len(ctrace):
        diff = [NAMES[i] for i in range(8) if utrace[k][1][i] != ctrace[k][1][i]]
        print("  differing registers:", diff, "(state before the instruction; the previous one produced it)")


if __name__ == "__main__":
    main()
