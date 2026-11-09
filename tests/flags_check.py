"""Checks the runtime's integer flag helpers (runtime/cpu.h) against the emulator difftest uses: every operation,
in 8, 16 and 32 bits, on random operands and incoming flags; the result and all of CF, PF, AF, ZF, SF and OF must
match. Where the SDM leaves a flag undefined the helpers follow the emulator (QEMU 5.0), so this checks those too.

  python -I tests/flags_check.py            (builds tests/flags_check.c with clang into the scratch directory given
                                             by --out, default: next to this file under results/)
"""
import argparse
import os
import random
import subprocess

from unicorn import UC_ARCH_X86, UC_MODE_32, Uc
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EFLAGS

HERE = os.path.dirname(os.path.abspath(__file__))
FLAGS = 0x8D5   # CF PF AF ZF SF OF
# op -> (opcode for 8 bits, opcode for 16/32 bits, ModRM): dst = al/ax/eax, src = bl/bx/ebx, count = cl
TWO = {"add": (0x00, 0x01), "adc": (0x10, 0x11), "sub": (0x28, 0x29), "sbb": (0x18, 0x19),
       "and": (0x20, 0x21), "or": (0x08, 0x09), "xor": (0x30, 0x31)}
ONE = {"inc": 0xC0, "dec": 0xC8, "neg": 0xD8}
SHIFT = {"rol": 0xC0, "ror": 0xC8, "rcl": 0xD0, "rcr": 0xD8, "shl": 0xE0, "shr": 0xE8, "sar": 0xF8}


def encode(op, bits):
    pre = b"\x66" if bits == 16 else b""
    if op in TWO:
        return pre + bytes([TWO[op][0 if bits == 8 else 1], 0xD8])
    if op in ONE:
        if op == "neg":
            return pre + bytes([0xF6 if bits == 8 else 0xF7, ONE[op]])
        return pre + bytes([0xFE if bits == 8 else 0xFF, ONE[op]])
    return pre + bytes([0xD2 if bits == 8 else 0xD3, SHIFT[op]])


def emulate(code, a, b, f):
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(0x1000, 0x1000)
    uc.mem_write(0x1000, code)
    uc.reg_write(UC_X86_REG_EAX, a)
    uc.reg_write(UC_X86_REG_EBX, b)
    uc.reg_write(UC_X86_REG_ECX, b)
    uc.reg_write(UC_X86_REG_EFLAGS, 0x2 | f)
    uc.emu_start(0x1000, 0x1000 + len(code))
    return uc.reg_read(UC_X86_REG_EAX), uc.reg_read(UC_X86_REG_EFLAGS) & FLAGS


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(HERE, "results"))
    ap.add_argument("--cases", type=int, default=3000, help="per operation and width")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    exe = os.path.join(a.out, "flags_check")
    subprocess.run(["clang", "-O1", "-I", os.path.join(HERE, "..", "runtime"), os.path.join(HERE, "flags_check.c"),
                    "-o", exe], check=True)
    rng = random.Random(11)
    cases = []
    for op in list(TWO) + list(ONE) + list(SHIFT):
        for bits in (8, 16, 32):
            m = (1 << bits) - 1
            for _ in range(a.cases):
                x = rng.choice([rng.getrandbits(bits), 0, m, 1 << (bits - 1), (1 << (bits - 1)) - 1, rng.getrandbits(5)])
                y = rng.choice([rng.getrandbits(bits), 0, 1, m, rng.getrandbits(6)]) if op not in SHIFT else \
                    rng.choice([0, 1, 2, bits - 1, bits, bits + 1, 31, 32, 33, rng.getrandbits(8)])
                f = sum(rng.getrandbits(1) << k for k in (0, 2, 4, 6, 7, 11))
                cases.append((op, bits, x, y, f))
    out = subprocess.run([exe], input="".join(f"{op} {bits} {x:x} {y:x} {f:x}\n" for op, bits, x, y, f in cases),
                         capture_output=True, text=True, check=True).stdout.split("\n")
    fails = 0
    for (op, bits, x, y, f), line in zip(cases, out):
        r, flags = (int(v, 16) for v in line.split())
        m = (1 << bits) - 1
        ur, uflags = emulate(encode(op, bits), x, y, f)
        if (ur & m) != (r & m) or uflags != flags:
            fails += 1
            if fails <= 20:
                print(f"FAIL {op}{bits} a={x:#x} b={y:#x} flags_in={f:#x}: helper {r & m:#x} {flags:#05x}, "
                      f"emulator {ur & m:#x} {uflags:#05x}")
    print(f"{len(cases)} cases, {fails} failures")
    raise SystemExit(1 if fails else 0)


if __name__ == "__main__":
    main()
