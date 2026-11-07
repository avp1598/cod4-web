"""Checks tests/x87ref.py against the hardware results the Intel SDM specifies, running small x87 programs under
Unicorn with the corrections installed. Exits nonzero on the first mismatch.

  python -I tests/x87ref_check.py
"""
import math
import os
import random
import struct
import sys
from fractions import Fraction

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import x87ref  # noqa: E402
from unicorn import UC_ARCH_X86, UC_MODE_32, Uc  # noqa: E402
from unicorn import x86_const as ux  # noqa: E402

CODE, DATA, SLOT = 0x1000, 0x8000, 16   # operand k is at DATA + 16k
FLD_M64 = lambda k: b"\xdd\x05" + struct.pack("<I", DATA + SLOT * k)        # fld qword [operand k]
FLD_M80 = lambda k: b"\xdb\x2d" + struct.pack("<I", DATA + SLOT * k)        # fld tword [operand k]
FIDIV_M32 = lambda k: b"\xda\x35" + struct.pack("<I", DATA + SLOT * k)      # fidiv dword [operand k]
FDIV_M64 = lambda k: b"\xdc\x35" + struct.pack("<I", DATA + SLOT * k)       # fdiv qword [operand k]
FDIVP = b"\xde\xf9"     # fdivp st(1), st(0): st(1) = st(1) / st(0), pop
FDIVRP = b"\xde\xf1"    # fdivrp st(1), st(0): st(1) = st(0) / st(1), pop
FYL2X = b"\xd9\xf1"
INF, NAN = float("inf"), float("nan")
SNAN = struct.unpack("<d", struct.pack("<Q", 0x7FF4000000000000))[0]
SNAN80 = (0xA000000000000000).to_bytes(8, "little") + (0x7FFF).to_bytes(2, "little")   # fld m80 keeps it signalling


def run(code, values, cw=0x027F):
    code += b"\x90"   # a fixup applies as the next instruction starts: there always is one
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(CODE, 0x1000)
    uc.mem_map(DATA, 0x1000)
    uc.mem_write(CODE, code)
    uc.mem_write(DATA, b"".join((v if isinstance(v, bytes) else struct.pack("<d", v)).ljust(SLOT, b"\0")
                                for v in values))
    uc.reg_write(ux.UC_X86_REG_FPCW, cw)
    uc.reg_write(ux.UC_X86_REG_FPTAG, 0xFFFF)
    corr = x87ref.Corrections(code, CODE, 0)
    corr.find_sites([{"ranges": [(CODE, CODE + len(code))]}])
    corr.install(uc)
    uc.emu_start(CODE, CODE + len(code))
    return uc


def describe(v):
    if v.kind in ("zero", "finite"):
        return float(v.value()) if v.kind == "finite" else (-0.0 if v.sign else 0.0)
    if v.kind == "inf":
        return -INF if v.sign else INF
    return f"{v.kind}({'-' if v.sign else '+'}{v.mant:#x})"


def check(name, got, want):
    if got != want:
        sys.exit(f"FAIL {name}: got {got!r}, want {want!r}")
    print(f"ok   {name}: {got!r}")


def same_double(a, b):
    return struct.pack("<d", a) == struct.pack("<d", b)


def fyl2x_case(y, x, want, flags):
    load = lambda k, v: FLD_M80(k) if isinstance(v, bytes) else FLD_M64(k)
    uc = run(load(0, y) + load(1, x) + FYL2X, [y, x])   # st(1) = y, st(0) = x
    sw = uc.reg_read(ux.UC_X86_REG_FPSW)
    got = describe(x87ref.st(uc, 0))
    ok_value = (got == want) if not isinstance(want, float) or not isinstance(got, float) else same_double(got, want)
    if not ok_value or (sw & 0x3F) != flags or (sw >> 11) & 7 != 7:
        sys.exit(f"FAIL fyl2x y={y!r} x={x!r}: got {got!r} sw={sw:#06x}, want {want!r} flags={flags:#x} top=7")
    print(f"ok   fyl2x y={y!r} x={x!r}: {got!r} flags={sw & 0x3f:#x}")


def div_case(name, code, values, flags):
    uc = run(code, values)
    sw = uc.reg_read(ux.UC_X86_REG_FPSW)
    check(f"{name} flags", sw & 0x3F, flags)


def main():
    indef = "qnan(-0xc000000000000000)"
    # SDM Vol. 2A FYL2X results: (y, x) -> result, flags
    fyl2x_case(0.0, 0.0, indef, x87ref.IE)
    fyl2x_case(-0.0, 0.0, indef, x87ref.IE)
    fyl2x_case(2.0, 0.0, -INF, x87ref.ZE)
    fyl2x_case(-2.0, -0.0, INF, x87ref.ZE)
    fyl2x_case(INF, 0.0, -INF, 0)
    fyl2x_case(-INF, 0.0, INF, 0)
    fyl2x_case(2.0, -1.0, indef, x87ref.IE)
    fyl2x_case(2.0, -INF, indef, x87ref.IE)
    fyl2x_case(0.0, INF, indef, x87ref.IE)
    fyl2x_case(-3.0, INF, -INF, 0)
    fyl2x_case(INF, 1.0, indef, x87ref.IE)
    fyl2x_case(INF, 0.5, -INF, 0)
    fyl2x_case(INF, 2.0, INF, 0)
    fyl2x_case(-INF, 2.0, -INF, 0)
    fyl2x_case(3.0, 8.0, 9.0, 0)                 # an ordinary operand pair: the emulator's own result
    fyl2x_case(NAN, 2.0, "qnan(+0xc000000000000000)", 0)
    fyl2x_case(SNAN80, 2.0, "qnan(+0xe000000000000000)", x87ref.IE)
    fyl2x_case(2.0, -NAN, "qnan(-0xc000000000000000)", 0)

    # division flags: 0/0 IE; x/0 ZE; inf/0, NaN/0, inf/1: none; inf/inf IE; signalling NaN operand IE
    div_case("0/0", FLD_M64(0) + FLD_M64(1) + FDIVP, [0.0, 0.0], x87ref.IE)
    div_case("1/0", FLD_M64(0) + FLD_M64(1) + FDIVP, [1.0, 0.0], x87ref.ZE)
    div_case("0/1", FLD_M64(0) + FLD_M64(1) + FDIVP, [0.0, 1.0], 0)
    div_case("inf/0", FLD_M64(0) + FLD_M64(1) + FDIVP, [INF, 0.0], 0)
    div_case("nan/0", FLD_M64(0) + FLD_M64(1) + FDIVP, [NAN, 0.0], 0)
    div_case("inf/inf", FLD_M64(0) + FLD_M64(1) + FDIVP, [INF, -INF], x87ref.IE)
    div_case("0/1 reversed (1/0)", FLD_M64(0) + FLD_M64(1) + FDIVRP, [0.0, 1.0], x87ref.ZE)
    div_case("0 / int 0", FLD_M64(0) + FIDIV_M32(1), [0.0, bytes(8)], x87ref.IE)
    div_case("5 / int 0", FLD_M64(0) + FIDIV_M32(1), [5.0, bytes(8)], x87ref.ZE)
    div_case("1 / m64 snan", FLD_M64(0) + FDIV_M64(1), [1.0, SNAN], x87ref.IE)
    div_case("1e300 / m64 1e-300", FLD_M64(0) + FDIV_M64(1), [1e300, 1e-300], 0)
    div_case("-2^1000 / m64 0", FLD_M64(0) + FDIV_M64(1), [-2.0 ** 1000, 0.0], x87ref.ZE)
    div_case("denormal / m64 0", FLD_M64(0) + FDIV_M64(1), [5e-324, 0.0], x87ref.ZE)
    div_case("0 / m64 denormal", FLD_M64(0) + FDIV_M64(1), [0.0, -5e-324], 0)
    # every kind of double converts exactly (from_ieee) to the value it is
    rng0 = random.Random(9)
    for k in range(40000):
        n, fmt = (8, "<d") if k % 2 else (4, "<f")
        raw = rng0.getrandbits(8 * n).to_bytes(n, "little")
        d = struct.unpack(fmt, raw)[0]
        x = x87ref.from_ieee(raw)
        if d != d:
            assert x.nan and x.sign == raw[-1] >> 7, raw.hex()
        elif math.isinf(d):
            assert x.kind == "inf", raw.hex()
        elif x.value() != Fraction(d) or (x.kind == "zero") != (d == 0):
            sys.exit(f"FAIL from_ieee {raw.hex()}: {x.mant:#x} {x.se:#x}")
    print("ok   from_ieee: 20000 random doubles, 20000 random floats")
    div_case("sticky ZE stays", FLD_M64(0) + FLD_M64(1) + FDIVP + FLD_M64(2) + FLD_M64(3) + FDIVP,
             [1.0, 0.0, 1.0, 2.0], x87ref.ZE)

    # round_to_double: nearest-even against Python's correctly rounded conversion; directed modes bracket it
    rng = random.Random(5)
    for _ in range(20000):
        mant = rng.getrandbits(64) | 1 << 63
        e = rng.choice([rng.randrange(16383 - 1080, 16383 - 1000), rng.randrange(16383 - 60, 16383 + 60),
                        rng.randrange(16383 + 1000, 16383 + 1030)])
        se = e | (0x8000 if rng.random() < 0.5 else 0)
        exact = x87ref.Ext(mant, se).value()
        got = {rc: x87ref.Ext(*x87ref.round_to_double(mant, se, rc)) for rc in range(4)}
        val = {rc: (math.copysign(INF, -1 if g.sign else 1) if g.kind == "inf" else g.value()) for rc, g in got.items()}
        try:
            want0 = float(exact)
        except OverflowError:
            want0 = INF if exact > 0 else -INF
        if val[0] != want0 and not (math.isinf(want0) and val[0] == want0):
            sys.exit(f"FAIL nearest {mant:#x} {se:#x}: {val[0]} vs {want0}")
        if not (val[1] <= exact <= val[2]) or abs(val[3]) > abs(exact):
            sys.exit(f"FAIL directed {mant:#x} {se:#x}: {val}")
        for rc in range(4):
            v = val[rc]
            if not math.isinf(v) and Fraction(float(v)) != v:
                sys.exit(f"FAIL not a double: rc={rc} {mant:#x} {se:#x}")
    print("ok   round_to_double: 20000 values, 4 rounding modes")
    print("all checks passed")


if __name__ == "__main__":
    main()
