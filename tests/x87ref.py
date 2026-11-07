"""x87 state under Unicorn for difftest.py: where the emulator (Unicorn 2.1, whose x87 is QEMU 5.0's) departs from
the hardware, the corrections applied while a function runs, and the double-precision register model behind the
x87_ext outcome.

Corrections (each restores what the Intel SDM specifies; the recompiled code implements the same):
  * FNSAVE/FSAVE/FNSTENV/FSTENV images. The recompiled code does not model the instruction and operand pointers
    (FIP, FCS/FOP, FDP, FDS; only exception handlers read them) and stores 0 there; QEMU stores the last x87
    instruction's address in FIP and zeros the rest. QEMU also leaves the reserved upper halves of the control,
    status and tag words 0 where the hardware sets them to 1 (the 80486 does, per Linux's math-emu; Bochs does
    the same). The emulator's image is brought to the modelled one.
  * Division flags. QEMU sets ZE whenever the divisor is zero, including 0/0 (the hardware: IE), inf/0 and NaN/0
    (the hardware: no flag), and never sets IE (0/0, inf/inf, a signalling NaN operand). SDM Vol. 1 §4.9.1.2 and
    §8.5.2/§8.5.3; Vol. 2A, FDIV/FDIVP/FIDIV and FDIVR/FDIVRP/FIDIVR. The value QEMU computes (softfloat) is
    the hardware's; only IE and ZE are replaced.
  * FYL2X. QEMU 5.0 computes y * log2(x) in host doubles and, unless x > 0, leaves the stack and the result
    alone and sets C2 instead; it raises no flags. Wherever x is not a positive finite number or y is not finite,
    the instruction is performed here per SDM Vol. 2A, FYL2X, table "FYL2X Results".

Not modelled by either side, so neither corrected nor compared as such: DE, OE, UE and PE; C1 (set when a result
was rounded up); the stack fault (SF, and IE for stack underflow/overflow: both sides read an empty register's
stale value); exceptions left unmasked by the control word; IE for invalid operations other than division and
FYL2X. Unsupported 80-bit encodings (unnormals, pseudo-NaNs, pseudo-infinities) are outside the recompiled
code's double registers, and are left to the emulator.
"""
from fractions import Fraction

from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from capstone.x86_const import X86_REG_FS
from unicorn import UC_HOOK_CODE
from unicorn import x86_const as ux

FP_REGS = [getattr(ux, f"UC_X86_REG_FP{i}") for i in range(8)]
IE, ZE = 0x0001, 0x0004
INT_BIT = 1 << 63
QUIET_BIT = 1 << 62
FRAC_MASK = (1 << 63) - 1
INDEFINITE = (0xC000000000000000, 0xFFFF)   # (significand, sign|exponent)
SAVE_MNEMONICS = ("fnsave", "fsave", "fnstenv", "fstenv")
DIV_MNEMONICS = ("fdiv", "fdivp", "fdivr", "fdivrp", "fidiv", "fidivr")


class Ext:
    """One 80-bit register or memory value: kind is zero, finite, inf, qnan, snan or unsupported."""

    def __init__(self, mant, se):
        self.mant, self.se = mant, se
        self.sign = se >> 15
        e = se & 0x7FFF
        if e == 0x7FFF:
            if not mant & INT_BIT:
                self.kind = "unsupported"        # pseudo-infinity / pseudo-NaN
            elif not mant & FRAC_MASK:
                self.kind = "inf"
            else:
                self.kind = "qnan" if mant & QUIET_BIT else "snan"
        elif e == 0:
            self.kind = "zero" if mant == 0 else "finite"   # denormals and pseudo-denormals are finite
        else:
            self.kind = "finite" if mant & INT_BIT else "unsupported"   # an unnormal

    @property
    def nan(self):
        return self.kind in ("qnan", "snan")

    def value(self):
        """The exact value of a zero or finite operand."""
        e = self.se & 0x7FFF
        v = Fraction(self.mant) * Fraction(2) ** ((e if e else 1) - 16383 - 63)
        return -v if self.sign else v

    @classmethod
    def of_fraction(cls, v):
        """A value with at most 64 significant bits, given exactly, as an 80-bit value (normalised)."""
        if v == 0:
            return cls(0, 0)
        sign, m = (0x8000, -v) if v < 0 else (0, v)
        n, d = m.numerator, m.denominator
        if d & (d - 1):
            raise ValueError(f"{v} is not a binary fraction")
        top_bit = n.bit_length() - 1 - (d.bit_length() - 1)   # value = 1.xxx * 2^top_bit
        shift = 64 - n.bit_length()
        if shift < 0 and n & ((1 << -shift) - 1):
            raise ValueError(f"{v} has more than 64 significant bits")
        return cls(n << shift if shift >= 0 else n >> -shift, sign | (top_bit + 16383))


def inf(sign):
    return (INT_BIT, 0x7FFF | (0x8000 if sign else 0))


def nan_result(a, b):
    """The x87 NaN rule (SDM Vol. 1, table 4-7) for operands a, b, at least one a NaN: a single NaN quieted; of a
    QNaN and an SNaN the QNaN; of two of a kind the larger significand, equal significands the positive one."""
    quiet = lambda x: (x.mant | QUIET_BIT, x.se)
    if not (a.nan and b.nan):
        return quiet(a if a.nan else b)
    if a.kind != b.kind:
        return quiet(a if a.kind == "qnan" else b)
    fa, fb = a.mant & FRAC_MASK & ~QUIET_BIT, b.mant & FRAC_MASK & ~QUIET_BIT
    if fa != fb:
        return quiet(a if fa > fb else b)
    return quiet(b if a.sign else a)


def top(uc):
    return (uc.reg_read(ux.UC_X86_REG_FPSW) >> 11) & 7


def st(uc, i):
    return Ext(*uc.reg_read(FP_REGS[(top(uc) + i) & 7]))


class Corrections:
    """Finds the instructions to correct in the translated functions' code and hooks them into one run."""

    def __init__(self, image, base, tib):
        self.image, self.base, self.tib = image, base, tib
        self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        self.md.detail = True
        self.sites = {}   # address -> (size, kind)

    def find_sites(self, funcs):
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        for f in funcs:
            for a, b in f["ranges"]:
                for ins in md.disasm(self.image[a - self.base:b - self.base], a):
                    m = ins.mnemonic
                    kind = "save" if m in SAVE_MNEMONICS else "div" if m in DIV_MNEMONICS else \
                        "fyl2x" if m == "fyl2x" else None
                    if kind:
                        self.sites[ins.address] = (ins.size, kind)

    def install(self, uc):
        pending = []   # fixups the instruction just executed left for the start of the next one
        for a, (size, kind) in self.sites.items():
            uc.hook_add(UC_HOOK_CODE, getattr(self, f"before_{kind}"), (size, pending), begin=a, end=a)
            if kind != "fyl2x":   # FYL2X is either left to the emulator or performed in full before it
                uc.hook_add(UC_HOOK_CODE, self.apply_pending, pending, begin=a + size, end=a + size)

    @staticmethod
    def apply_pending(uc, addr, size, pending):
        while pending:
            pending.pop()(uc)

    def decode(self, uc, addr, size, mnemonics):
        """The instruction now at a site, if it is still one of these: the image is writable, and a function's
        stores through random test pointers can overwrite code (the emulator then runs what is there)."""
        ins = next(self.md.disasm(bytes(uc.mem_read(addr, size)), addr, count=1), None)
        return ins if ins is not None and ins.size == size and ins.mnemonic in mnemonics else None

    def ea(self, uc, ins):
        m = ins.operands[0].mem
        reg = lambda r: uc.reg_read(getattr(ux, f"UC_X86_REG_{ins.reg_name(r).upper()}")) if r else 0
        seg = self.tib if m.segment == X86_REG_FS else 0   # fs: is the thread information block; the rest flat
        return (seg + reg(m.base) + reg(m.index) * m.scale + m.disp) & 0xFFFFFFFF

    # ---- FNSAVE/FNSTENV: pointer fields and reserved halves
    def before_save(self, uc, addr, size, data):
        _, pending = data
        ins = self.decode(uc, addr, size, SAVE_MNEMONICS)
        if ins is None:
            return
        ea = self.ea(uc, ins)

        def fix(uc_):
            for k in (2, 6, 10):
                uc_.mem_write(ea + k, b"\xff\xff")
            uc_.mem_write(ea + 12, bytes(16))
        pending.append(fix)

    # ---- division: IE and ZE as the hardware sets them
    def div_operands(self, uc, ins):
        """(dividend, divisor) of an FDIV-family instruction, decoded from its opcode and ModRM byte."""
        op, modrm = ins.opcode[0], ins.modrm
        reverse = (modrm >> 3) & 7 == 7   # memory forms: /6 FDIV(I) ST(0) / m, /7 FDIVR/FIDIVR m / ST(0)
        if modrm >> 6 != 3:
            a = self.ea(uc, ins)
            raw = bytes(uc.mem_read(a, {0xD8: 4, 0xDC: 8, 0xDA: 4, 0xDE: 2}[op]))
            if op in (0xDA, 0xDE):
                mem = Ext.of_fraction(Fraction(int.from_bytes(raw, "little", signed=True)))
            else:
                mem = from_ieee(raw)
            return (mem, st(uc, 0)) if reverse else (st(uc, 0), mem)
        # Register forms, reg field 7: D8 F8+i FDIVR ST(0), ST(i) and DC/DE F8+i FDIV(P) ST(i), ST(0) all divide
        # ST(i) by ST(0); reg field 6 (D8 F0+i FDIV, DC/DE F0+i FDIVR(P)) divides ST(0) by ST(i)
        i = modrm & 7
        return (st(uc, i), st(uc, 0)) if reverse else (st(uc, 0), st(uc, i))

    def before_div(self, uc, addr, size, data):
        _, pending = data
        ins = self.decode(uc, addr, size, DIV_MNEMONICS)
        if ins is None:
            return
        a, b = self.div_operands(uc, ins)
        if "unsupported" in (a.kind, b.kind):
            return
        if a.kind == "snan" or b.kind == "snan":
            flags = IE
        elif a.nan or b.nan:
            flags = 0
        elif (a.kind, b.kind) in (("zero", "zero"), ("inf", "inf")):
            flags = IE
        elif b.kind == "zero" and a.kind == "finite":
            flags = ZE
        else:
            flags = 0
        before = uc.reg_read(ux.UC_X86_REG_FPSW) & (IE | ZE)

        def fix(uc_):
            sw = uc_.reg_read(ux.UC_X86_REG_FPSW)
            uc_.reg_write(ux.UC_X86_REG_FPSW, (sw & ~(IE | ZE)) | before | flags)
        pending.append(fix)

    # ---- FYL2X
    def before_fyl2x(self, uc, addr, size, data):
        if self.decode(uc, addr, size, ("fyl2x",)) is None:
            return
        x, y = st(uc, 0), st(uc, 1)
        if "unsupported" in (x.kind, y.kind):
            return
        if x.kind == "finite" and not x.sign and y.kind in ("zero", "finite"):
            return   # y * log2(x) for x > 0: the emulator computes it (in doubles; see x87_ext)
        flags = 0
        if x.nan or y.nan:
            flags = IE if "snan" in (x.kind, y.kind) else 0
            r = nan_result(y, x)
        elif x.sign and x.kind != "zero":                # x < 0, including -inf
            flags, r = IE, INDEFINITE
        elif x.kind == "zero":
            if y.kind == "zero":
                flags, r = IE, INDEFINITE
            elif y.kind == "inf":
                r = inf(not y.sign)
            else:
                flags, r = ZE, inf(not y.sign)
        elif x.kind == "inf":                            # +inf
            if y.kind == "zero":
                flags, r = IE, INDEFINITE
            else:
                r = inf(y.sign)
        else:                                            # x finite and positive, y infinite
            v = x.value()
            if v == 1:
                flags, r = IE, INDEFINITE
            else:
                r = inf(y.sign if v > 1 else not y.sign)
        t = top(uc)
        uc.reg_write(FP_REGS[(t + 1) & 7], r)
        uc.reg_write(ux.UC_X86_REG_FPTAG, uc.reg_read(ux.UC_X86_REG_FPTAG) | 3 << (2 * t))   # pop: ST(0) empty
        sw = uc.reg_read(ux.UC_X86_REG_FPSW)
        uc.reg_write(ux.UC_X86_REG_FPSW, (sw & ~0x3800) | flags | ((t + 1) & 7) << 11)
        uc.reg_write(ux.UC_X86_REG_EIP, addr + size)


def from_ieee(raw):
    """A 32- or 64-bit IEEE value as the 80-bit value it loads as (exactly; signalling NaNs stay signalling)."""
    n = len(raw)
    bits = int.from_bytes(raw, "little")
    fbits, ebits = (23, 8) if n == 4 else (52, 11)
    sign = bits >> (n * 8 - 1)
    e = (bits >> fbits) & ((1 << ebits) - 1)
    f = bits & ((1 << fbits) - 1)
    s = 0x8000 if sign else 0
    if e == (1 << ebits) - 1:
        return Ext(INT_BIT | f << (63 - fbits), s | 0x7FFF)
    if e == 0 and f == 0:
        return Ext(0, s)
    bias = (1 << (ebits - 1)) - 1
    v = Fraction(f if e == 0 else f | 1 << fbits) * Fraction(2) ** ((e if e else 1) - bias - fbits)
    return Ext.of_fraction(-v if sign else v)


# ---- the recompiled code's register model, for classifying x87_ext differences
def round_to_double(mant, se, rc):
    """An 80-bit finite nonzero value rounded to double precision and range under rounding control rc
    (0 nearest-even, 1 down, 2 up, 3 toward zero), as the 80-bit value it is then held as."""
    sign = se >> 15
    e = se & 0x7FFF
    k = (e if e else 1) - 16383 - 63            # value = mant * 2^k
    n = mant.bit_length()
    q = max(k + n - 53, -1074)                  # exponent of the result's last bit
    r = mant
    if q > k:
        shift = q - k
        r, rem = mant >> shift, mant & ((1 << shift) - 1)
        half = 1 << (shift - 1)
        up = {0: rem > half or (rem == half and r & 1), 1: rem != 0 and sign, 2: rem != 0 and not sign, 3: False}[rc]
        r += 1 if up else 0
    else:
        q = k
    if r == 0:
        return 0, se & 0x8000
    bl = r.bit_length()
    top_bit = q + bl - 1
    if top_bit > 1023:                          # beyond the largest double
        if rc == 0 or (rc == 1 and sign) or (rc == 2 and not sign):
            return inf(sign)
        return ((1 << 53) - 1) << 11, (se & 0x8000) | (1023 + 16383)
    return r << (64 - bl), (se & 0x8000) | (top_bit + 16383)


def hold_as_doubles(uc, addr, size, data):
    """UC_HOOK_CODE over every instruction: each register holding a value is held at double precision and range,
    as the recompiled code's registers are, rounded under the control word's rounding control."""
    tags = uc.reg_read(ux.UC_X86_REG_FPTAG)
    rc = (uc.reg_read(ux.UC_X86_REG_FPCW) >> 10) & 3
    for p in range(8):
        if (tags >> (2 * p)) & 3 == 3:
            continue
        v = Ext(*uc.reg_read(FP_REGS[p]))
        if v.kind == "finite":
            r = round_to_double(v.mant, v.se, rc)
            if r != (v.mant, v.se):
                uc.reg_write(FP_REGS[p], r)
