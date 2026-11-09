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
from uchooks import guarded  # noqa: E402
from unicorn import UC_ARCH_X86, UC_MODE_32, Uc  # noqa: E402
from unicorn import x86_const as ux  # noqa: E402

CODE, DATA, SLOT = 0x1000, 0x8000, 16   # operand k is at DATA + 16k
FLD_M64 = lambda k: b"\xdd\x05" + struct.pack("<I", DATA + SLOT * k)        # fld qword [operand k]
FLD_M80 = lambda k: b"\xdb\x2d" + struct.pack("<I", DATA + SLOT * k)        # fld tword [operand k]
FLD_M32 = lambda k: b"\xd9\x05" + struct.pack("<I", DATA + SLOT * k)        # fld dword [operand k]
FSTP_M32 = lambda k: b"\xd9\x1d" + struct.pack("<I", DATA + SLOT * k)       # fstp dword [operand k]
FST_M32 = lambda k: b"\xd9\x15" + struct.pack("<I", DATA + SLOT * k)        # fst dword [operand k]
FSTP_M64 = lambda k: b"\xdd\x1d" + struct.pack("<I", DATA + SLOT * k)       # fstp qword [operand k]
FST_M64 = lambda k: b"\xdd\x15" + struct.pack("<I", DATA + SLOT * k)        # fst qword [operand k]
FIDIV_M32 = lambda k: b"\xda\x35" + struct.pack("<I", DATA + SLOT * k)      # fidiv dword [operand k]
FDIV_M64 = lambda k: b"\xdc\x35" + struct.pack("<I", DATA + SLOT * k)       # fdiv qword [operand k]
FDIVP = b"\xde\xf9"     # fdivp st(1), st(0): st(1) = st(1) / st(0), pop
FDIVRP = b"\xde\xf1"    # fdivrp st(1), st(0): st(1) = st(0) / st(1), pop
FYL2X = b"\xd9\xf1"
TRIG = {"fsin": b"\xd9\xfe", "fcos": b"\xd9\xff", "fsincos": b"\xd9\xfb", "fptan": b"\xd9\xf2"}
INF, NAN = float("inf"), float("nan")
SNAN = struct.unpack("<d", struct.pack("<Q", 0x7FF4000000000000))[0]
SNAN80 = (0xA000000000000000).to_bytes(8, "little") + (0x7FFF).to_bytes(2, "little")   # fld m80 keeps it signalling


def run(code, values, cw=0x027F, xmm=None):
    """Runs code with operand k at DATA + 16k (and, given xmm, xmm0 and xmm1 set to its two values)."""
    code += b"\x90"   # a fixup applies as the next instruction starts: there always is one
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    if xmm is not None:
        uc.reg_write(ux.UC_X86_REG_XMM0, xmm[0])
        uc.reg_write(ux.UC_X86_REG_XMM1, xmm[1])
    uc.mem_map(CODE, 0x1000)
    uc.mem_map(DATA, 0x1000)
    uc.mem_write(CODE, code)
    uc.mem_write(DATA, b"".join((v if isinstance(v, bytes) else struct.pack("<d", v)).ljust(SLOT, b"\0")
                                for v in values))
    uc.reg_write(ux.UC_X86_REG_FPCW, cw)
    uc.reg_write(ux.UC_X86_REG_FPTAG, 0xFFFF)
    corr = x87ref.Corrections(code, CODE, 0)
    corr.find_sites([{"ranges": [(CODE, CODE + len(code))]}])
    corr.install(uc, guarded)
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


def trig_case(op, x, want):
    """want: the results from ST(0) up (one for FSIN/FCOS, two for FSINCOS/FPTAN), with C2 clear."""
    load = FLD_M80(0) if isinstance(x, bytes) else FLD_M64(0)
    uc = run(load + TRIG[op], [x])
    sw = uc.reg_read(ux.UC_X86_REG_FPSW)
    got = [describe(x87ref.st(uc, i)) for i in range(len(want))]
    if got != want or sw & 0x0400 or (sw >> 11) & 7 != (8 - len(want)) & 7:
        sys.exit(f"FAIL {op} {x!r}: got {got!r} sw={sw:#06x}, want {want!r}, C2 clear, top {(8 - len(want)) & 7}")
    print(f"ok   {op} {x!r}: {got!r}")


SSE_OPS = {"add": 0x58, "sub": 0x5C, "mul": 0x59, "div": 0x5E}
SSE_PREFIX = {"ps": b"", "pd": b"\x66", "ss": b"\xf3", "sd": b"\xf2"}


def sse_nan_rule(op_bits, a, b):
    """The SDM's result lane for a NaN operand (Vol. 1 Table 4-7): the first source if it is a NaN, else the
    second, quieted; None if neither is a NaN."""
    frac = 23 if op_bits == 32 else 52
    exp = ((1 << op_bits) - 1 >> 1) & ~((1 << frac) - 1)
    nan = lambda v: v & exp == exp and v & ((1 << frac) - 1)
    q = 1 << (frac - 1)
    return a | q if nan(a) else b | q if nan(b) else None


def sse_cases(count):
    """Every SSE arithmetic form, register and memory sources, on random lanes that are often NaNs."""
    rng = random.Random(17)
    checked = 0
    for op, opc in SSE_OPS.items():
        for form, pre in SSE_PREFIX.items():
            bits, n = x87ref.SSE_ARITH[op + form]
            frac = 23 if bits == 32 else 52
            ones = ((1 << bits) - 1 >> 1) & ~((1 << frac) - 1)

            def lane():
                k = rng.randrange(3)
                sign = rng.getrandbits(1) << (bits - 1)
                if k == 0:
                    return sign | ones | 1 << (frac - 1) | rng.getrandbits(frac - 1)   # quiet NaN
                if k == 1:
                    return sign | ones | (rng.getrandbits(frac - 1) or 1)               # signalling NaN
                return rng.getrandbits(bits)
            for mem in (False, True):
                code = pre + bytes([0x0F, opc]) + (b"\x05" + struct.pack("<I", DATA) if mem else b"\xc1")
                for _ in range(count):
                    a = [lane() for _ in range(128 // bits)]
                    b = [lane() for _ in range(128 // bits)]
                    pa = sum(v << (bits * i) for i, v in enumerate(a))
                    pb = sum(v << (bits * i) for i, v in enumerate(b))
                    uc = run(code, [pb.to_bytes(16, "little")], xmm=(pa, pb))
                    r = uc.reg_read(ux.UC_X86_REG_XMM0)
                    for i in range(n):
                        want = sse_nan_rule(bits, a[i], b[i])
                        got = r >> (bits * i) & ((1 << bits) - 1)
                        if want is not None and got != want:
                            sys.exit(f"FAIL {op}{form} {'m' if mem else 'reg'} lane {i}: {a[i]:#x} {b[i]:#x} -> "
                                     f"{got:#x}, want {want:#x}")
                        checked += want is not None
    print(f"ok   SSE arithmetic NaN lanes: {checked} checked over add/sub/mul/div ps/pd/ss/sd, register and memory")


def load_case(name, code, raw, want):
    """FLD m32/m64 of raw: ST(0) as describe gives it."""
    check(name, describe(x87ref.st(run(code, [raw]), 0)), want)


def store_case(name, code, value, n, want):
    """FLD m80 of value, then the store in code to operand 1: its n bytes, as an integer."""
    uc = run(FLD_M80(0) + code, [value, bytes(8)])
    check(name, f"{int.from_bytes(bytes(uc.mem_read(DATA + SLOT, n)), 'little'):#0{2 * n + 2}x}", f"{want:#0{2 * n + 2}x}")


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

    # trigonometry of infinities (invalid: the real indefinite) and NaNs (the NaN, quieted, in every result)
    neg_nan = struct.unpack("<d", struct.pack("<Q", 0xFFF8000000000001))[0]
    for op in TRIG:
        n = 2 if op in ("fsincos", "fptan") else 1
        trig_case(op, INF, [indef] * n)
        trig_case(op, -INF, [indef] * n)
        trig_case(op, neg_nan, ["qnan(-0xc000000000000800)"] * n)
        trig_case(op, SNAN80, ["qnan(+0xe000000000000000)"] * n)
    trig_case("fsin", 0.0, [0.0])                     # ordinary operands: the emulator's own results
    trig_case("fptan", 0.0, [1.0, 0.0])

    # signalling NaNs converted from and to single/double precision: quieted, sign and payload kept (SDM Vol. 1
    # 4.8.3.4); a quiet NaN or a number goes through unchanged
    m32 = lambda v: v.to_bytes(4, "little")
    m64 = lambda v: v.to_bytes(8, "little")
    load_case("fld m32 snan", FLD_M32(0), m32(0x7F9A0001), "qnan(+0xda00010000000000)")
    load_case("fld m32 -snan, payload 1", FLD_M32(0), m32(0xFF800001), "qnan(-0xc000010000000000)")
    load_case("fld m32 qnan", FLD_M32(0), m32(0x7FDA0001), "qnan(+0xda00010000000000)")
    load_case("fld m32 1.5", FLD_M32(0), m32(0x3FC00000), 1.5)
    load_case("fld m64 snan", FLD_M64(0), m64(0x7FF05A0000000001), "qnan(+0xc2d0000000000800)")
    load_case("fld m64 -snan", FLD_M64(0), m64(0xFFF0000000000001), "qnan(-0xc000000000000800)")
    load_case("fld m64 qnan", FLD_M64(0), m64(0xFFF8000000000001), "qnan(-0xc000000000000800)")
    neg_low_snan = (0x8000000123456789).to_bytes(8, "little") + (0xFFFF).to_bytes(2, "little")
    store_case("fstp m32 snan", FSTP_M32(1), SNAN80, 4, 0x7FE00000)
    store_case("fst m32 snan", FST_M32(1), SNAN80, 4, 0x7FE00000)
    store_case("fstp m32 -snan, payload below single's", FSTP_M32(1), neg_low_snan, 4, 0xFFC00000)
    store_case("fstp m64 snan", FSTP_M64(1), SNAN80, 8, 0x7FFC000000000000)
    store_case("fst m64 -snan, low payload", FST_M64(1), neg_low_snan, 8, 0xFFF80000002468AC)
    store_case("fstp m32 qnan", FSTP_M32(1), (0xC000000000000000).to_bytes(8, "little") + (0x7FFF).to_bytes(2, "little"),
               4, 0x7FC00000)
    store_case("fstp m64 2.0", FSTP_M64(1), (1 << 63).to_bytes(8, "little") + (0x4000).to_bytes(2, "little"),
               8, 0x4000000000000000)

    sse_cases(300)

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
