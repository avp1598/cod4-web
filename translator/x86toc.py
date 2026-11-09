"""Static recompiler: translates the game's 32-bit x86 functions into C.

Each guest function becomes `void f_XXXXXXXX(CPU *c)`. Registers, flags, the x87 stack and XMM
registers live in the CPU struct; guest memory is addressed through R*/W* helpers (see
runtime/cpu.h). Branches inside a function become gotos; calls push a real return address so the
guest stack layout is exact.

Usage:
  x86toc.py <exe> <functions.json> <outdir> [--roots 0x67a97a,0x67aa76 | --all] [--per-file N]
"""
import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, CS_OP_IMM, CS_OP_MEM, CS_OP_REG, Cs
from capstone import x86_const as X

GP32 = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
GP16 = {"ax": "eax", "cx": "ecx", "dx": "edx", "bx": "ebx", "sp": "esp", "bp": "ebp", "si": "esi", "di": "edi"}
GP8L = {"al": "eax", "cl": "ecx", "dl": "edx", "bl": "ebx"}
GP8H = {"ah": "eax", "ch": "ecx", "dh": "edx", "bh": "ebx"}
SETJMP_NAME = re.compile(r"_{0,2}setjmp3?|_{0,2}setjmpex")   # setjmp, _setjmp, _setjmp3, __setjmp3, _setjmpex
UT = {1: "uint8_t", 2: "uint16_t", 4: "uint32_t", 8: "uint64_t"}
ST_ = {1: "int8_t", 2: "int16_t", 4: "int32_t", 8: "int64_t"}
BITS = {1: 8, 2: 16, 4: 32}

COND = {
    "o": "c->of", "no": "!c->of", "b": "c->cf", "ae": "!c->cf", "e": "c->zf", "ne": "!c->zf",
    "be": "(c->cf || c->zf)", "a": "(!c->cf && !c->zf)", "s": "c->sf", "ns": "!c->sf",
    "p": "PF(c)", "np": "!PF(c)", "l": "(c->sf != c->of)", "ge": "(c->sf == c->of)",
    "le": "(c->zf || c->sf != c->of)", "g": "(!c->zf && c->sf == c->of)",
}


# Every encoding of a near return. MSVC emits f3 c3 ("repz ret", the return AMD recommends after a branch)
# in CRT routines such as __security_check_cookie; f2 c3 decodes as "bnd ret". Both prefixes are ignored by
# the CPU on a return.
RET = ("ret", "retn", "repz ret", "rep ret", "bnd ret")

# Mnemonics that never occur in code a Win32 compiler emits for user mode: privileged or I/O instructions,
# far transfers, and opcodes that only make sense in 16-bit or BCD code. A candidate entry whose code
# contains one is data that happened to look like a function start.
NOT_USER_CODE = frozenset((
    "arpl", "bound", "les", "lds", "lcall", "ljmp", "retf", "retfw", "iret", "iretd", "in", "out", "insb", "insw",
    "insd", "outsb", "outsw", "outsd", "hlt", "cli", "sti", "into", "aaa", "aas", "daa", "das", "aam", "aad",
    "salc", "lgdt", "lidt", "lldt", "ltr", "lmsw", "clts", "invd", "wbinvd", "rdmsr", "wrmsr", "sysexit",
    "int1",
))

SEGMENT_REGS = ("es", "cs", "ss", "ds", "fs", "gs")


def not_user_code(ins):
    """True for an instruction compiled 32-bit Windows user-mode code of this era never contains: see
    NOT_USER_CODE, plus pushes/pops of segment registers, loads into segment registers, VEX/XOP-encoded
    instructions (AVX and XOP postdate 2007) and MPX "bnd" branches."""
    m = ins.mnemonic
    if m.startswith("lock "):
        m = m[5:]
    if m in NOT_USER_CODE or m.startswith(("bnd ", "v")):
        return True
    o = ins.operands
    if m in ("push", "pop") and o and o[0].type == CS_OP_REG and ins.reg_name(o[0].reg) in SEGMENT_REGS:
        return True
    return m == "mov" and o and o[0].type == CS_OP_REG and ins.reg_name(o[0].reg) in SEGMENT_REGS


# Segment selectors the game sees on 32-bit Windows (read only by MSVC's __report_gsfailure, which copies
# them into an exception record). Index = x86 Sreg encoding: es, cs, ss, ds, fs, gs.
SREG_INDEX = {"es": 0, "cs": 1, "ss": 2, "ds": 3, "fs": 4, "gs": 5}


class Unsupported(Exception):
    pass


# ------------------------------------------------------------ register cache
# Instructions are first translated against the CPU struct (c->eax, add32(c, ...), ST(0), c->xmm[1]). A
# recompiled function then keeps the general registers, arithmetic flags, x87 stack and SSE/MMX registers it
# uses in locals instead (Regs and X87 in runtime/cpu.h): guest stores go through a char pointer that may
# alias anything, so values kept in the CPU struct had to be reloaded after every store, and every flag a
# helper computed had to be stored. The locals never escape, so the C compiler keeps them in machine
# registers and drops flags nobody reads. Their values go back to the CPU only where other code can see
# them: before a call (then everything is reloaded, since the callee may change any of it), before a
# return, and before a trap. A forward dataflow over the function finds which values may have changed
# since the last write-back, so only those are stored.
CACHED = GP32 + ["cf", "zf", "sf", "of", "pf_byte", "af"]
CBIT = {n: 1 << i for i, n in enumerate(CACHED)}
FLAG_BITS = CBIT["cf"] | CBIT["zf"] | CBIT["sf"] | CBIT["of"] | CBIT["pf_byte"] | CBIT["af"]
X87_BIT = 1 << len(CACHED)
XMM_BIT = [1 << (len(CACHED) + 1 + k) for k in range(8)]
MM_BIT = [1 << (len(CACHED) + 9 + k) for k in range(8)]

_ASSIGN = r"\s*(?:[-+*/%&|^]|<<|>>)?=(?!=)"
_FLAG_HELPERS = r"(?:add|adc|sub|sbb|logic|inc|dec|neg|shl|shr|sar|rol|ror|rcl|rcr)(?:8|16|32)"
_REWRITES = [
    (re.compile(r"\bc->(" + "|".join(CACHED) + r")\b"), r"r->\1"),
    (re.compile(r"\b(" + _FLAG_HELPERS + r")\(c,"), r"\1r(r,"),
    (re.compile(r"\bPUSH32\(c,"), "PUSH32r(r,"),
    (re.compile(r"\bPOP32\(c\)"), "POP32r(r)"),
    (re.compile(r"\bPF\(c\)"), "PFr(r)"),
    (re.compile(r"\bFCOMI\(c,"), "FCOMIr(r,"),
    (re.compile(r"&c->mm\[(\d)\]"), r"&M_[\1]"),
    (re.compile(r"\bc->xmm\[(\d)\]"), r"V_[\1]"),
]
# x87 (statements that move the stack top directly, finit/fincstp/fdecstp, run on the CPU struct instead)
_X87_REWRITES = [
    (re.compile(r"\bST\((\d)\)"), r"x->s[\1]"),
    (re.compile(r"\b(FPUSH|FCOM|FPRES|FDIV|FYL2X|FTRIG)\(c,"), r"\1x(x,"),
    (re.compile(r"\b(FPOP|FNSTSW)\(c\)"), r"\1x(x)"),
    (re.compile(r"\bc->fpu_sw\b"), "x->sw"),
    (re.compile(r"\bc->fpu_cw = "), "x->cw = C->fpu_cw = "),   # written through (fldcw)
    (re.compile(r"\bc->fpu_cw\b"), "x->cw"),
    (re.compile(r"\bC->fpu_cw\b"), "c->fpu_cw"),
]
# calls that see the whole CPU: write back before them; after an ordinary call, reload everything
_SYNC_CALL = re.compile(r"\b(f_[0-9a-f]{8}|call_indirect|jump_indirect|guest_trap|cpuid|rdtsc|trace_insn)"
                        r"\(c\b[^;]*\);(\s*return;)?")
_RETURN = re.compile(r"\breturn;")
_TRACE_PREFIX = re.compile(r"trace_insn\(c, 0x[0-9a-f]{8}u\); ")
_WRITES = [   # (pattern, bits, or a function of the match giving the bits)
    (re.compile(r"\br->(\w+)" + _ASSIGN + r"|\br->(\w+)\s*(?:\+\+|--)|(?:\+\+|--)\s*r->(\w+)"),
     lambda m: CBIT[m.group(1) or m.group(2) or m.group(3)]),
    (re.compile(r"\b" + _FLAG_HELPERS + r"r\(r,|\bFCOMIr\(r,"), FLAG_BITS),
    (re.compile(r"\bPUSH32r\(r,|\bPOP32r\(r\)"), CBIT["esp"]),
    (re.compile(r"\bx->(?:s\[\d\]|top|sw|tags)" + _ASSIGN + r"|\b(?:FPUSHx|FPOPx|FCOMx|FDIVx|FYL2Xx|FTRIGx)\(x"), X87_BIT),
    (re.compile(r"\bV_\[(\d)\](?:\.\w+(?:\[\d+\])?)?" + _ASSIGN + r"|\bmem(?:cpy|set)\((?:\(uint8_t \*\))?V_\[(\d)\]"),
     lambda m: XMM_BIT[int(m.group(1) or m.group(2))]),
    (re.compile(r"\bmem(?:cpy|set)\((?:\(uint8_t \*\))?&M_\[(\d)\]"), lambda m: MM_BIT[int(m.group(1))]),
]
# helpers that receive the CPU but read only state that stays there (the control word, written through)
_CPU_ONLY = {"fpu_to_int16", "fpu_to_int32", "fpu_to_int64", "fpu_round", "fpu_sync_rounding", "fpu_save",
             "fpu_restore"}
# helpers that work on the CPU's whole x87 state: statements calling them run in x87-sync mode, like those
# that move the stack top
_X87_SYNC_HELPERS = ("fpu_save(", "fpu_restore(")
_GOTO = re.compile(r"goto L_([0-9a-f]{8});")


class RegisterCache:
    """Rewrites one function's translated statements [(insn or None, text)] to use the cached state and
    adds the loads, write-backs and reloads around them."""

    def __init__(self, body):
        self.body = body
        self.x87_sync = []
        texts = []
        for _, stmt in body:
            for rx, rep in _REWRITES:
                stmt = rx.sub(rep, stmt)
            sync = "c->top" in stmt or any(h in stmt for h in _X87_SYNC_HELPERS)
            if not sync:
                for rx, rep in _X87_REWRITES:
                    stmt = rx.sub(rep, stmt)
            self.x87_sync.append(sync)
            for m in re.finditer(r"\b(\w+)\(c[,)]", stmt):
                if m.group(1) not in _CPU_ONLY and not _SYNC_CALL.match(stmt, m.start()):
                    raise RuntimeError(f"register cache: unhandled call {m.group(1)}(c) in: {stmt}")
            texts.append(stmt)
        self.texts = texts
        joined = "\n".join(texts)
        self.x87 = bool(re.search(r"\bx->|\(x[,)]", joined)) or any(self.x87_sync)
        self.xmm = sorted({int(k) for k in re.findall(r"\bV_\[(\d)\]", joined)})
        self.mm = sorted({int(k) for k in re.findall(r"&M_\[(\d)\]", joined)})
        self.all_bits = (1 << len(CACHED)) - 1 | (X87_BIT if self.x87 else 0)
        for k in self.xmm:
            self.all_bits |= XMM_BIT[k]
        for k in self.mm:
            self.all_bits |= MM_BIT[k]

    def load(self):
        out = ["Regs R_ = { " + ", ".join(f"c->{n}" for n in CACHED) + " }; Regs *const r = &R_;"]
        if self.x87:
            out.append("X87 F_; X87 *const x = &F_; X87_LOAD(x, c);")
        if self.xmm:
            out.append("XMM V_[8]; " + " ".join(f"V_[{k}] = c->xmm[{k}];" for k in self.xmm))
        if self.mm:
            out.append("uint64_t M_[8]; " + " ".join(f"M_[{k}] = c->mm[{k}];" for k in self.mm))
        return " ".join(out)

    def reload(self):
        out = [f"r->{n} = c->{n};" for n in CACHED]
        if self.x87:
            out.append("X87_LOAD(x, c);")
        out += [f"V_[{k}] = c->xmm[{k}];" for k in self.xmm] + [f"M_[{k}] = c->mm[{k}];" for k in self.mm]
        return " ".join(out)

    @staticmethod
    def spill(dirty):
        out = [f"c->{n} = r->{n}; " for n in CACHED if dirty & CBIT[n]]
        if dirty & X87_BIT:
            out.append("X87_STORE(x, c); ")
        out += [f"c->xmm[{k}] = V_[{k}]; " for k in range(8) if dirty & XMM_BIT[k]]
        out += [f"c->mm[{k}] = M_[{k}]; " for k in range(8) if dirty & MM_BIT[k]]
        return "".join(out)

    def events(self, k):
        """(start, end, kind, value) in text order: writes, calls that see the CPU, returns."""
        stmt = self.texts[k]
        if self.x87_sync[k]:   # the whole statement works on the CPU's x87 state
            t = _TRACE_PREFIX.match(stmt)
            if t:  # a --trace build's trace call first: it sees the whole CPU, like any call
                return [(0, t.end(), "call", t.group(0).strip()), (t.end(), len(stmt), "x87sync", stmt[t.end():])]
            return [(0, len(stmt), "x87sync", stmt)]
        ev = []
        for m in _SYNC_CALL.finditer(stmt):
            kind = "trap" if m.group(1) == "guest_trap" else "tail" if m.group(2) else "call"
            ev.append((m.start(), m.end(), kind, m.group(0)))
        inside = lambda pos: any(a <= pos < b for a, b, _, _ in ev)
        ev += [(m.start(), m.end(), "ret", None) for m in _RETURN.finditer(stmt) if not inside(m.start())]
        for rx, bits in _WRITES:
            ev += [(m.start(), m.start(), "write", bits(m) if callable(bits) else bits) for m in rx.finditer(stmt)]
        return sorted(ev, key=lambda e: e[0])

    @staticmethod
    def transfer(events, dirty):
        for _, _, kind, v in events:
            if kind == "write":
                dirty |= v
            elif kind == "call":   # written back before it and reloaded after: nothing changed since
                dirty = 0
            elif kind == "x87sync":
                dirty &= ~X87_BIT
        return dirty

    def emit(self, k, dirty):
        stmt, out, pos = self.texts[k], [], 0
        for a, b, kind, v in self.events(k):
            if kind == "write":
                dirty |= v
                continue
            out.append(stmt[pos:a])
            pos = b
            if kind == "ret":
                out.append(f"{{ {self.spill(dirty)}return; }}")
            elif kind == "call":
                out.append(f"{{ {self.spill(dirty)}{v} {self.reload()} }}")
                dirty = 0
            elif kind == "x87sync":
                out.append(f"{{ X87_STORE(x, c); {v} X87_LOAD(x, c); }}")
            else:   # a tail call or a trap ends this path; the text after it belongs to the other path
                out.append(f"{{ {self.spill(dirty)}{v.strip()} }}")
        out.append(stmt[pos:])
        return "".join(out)

    def run(self):
        body, n = self.body, len(self.body)
        at = {ins.address: k for k, (ins, _) in enumerate(body) if ins is not None}
        events = [self.events(k) for k in range(n)]
        succ = []
        for k, (ins, _) in enumerate(body):
            out = [at[int(t, 16)] for t in _GOTO.findall(self.texts[k])]
            if ins is not None and not FunctionTranslator.is_terminator(ins) and k + 1 < n:
                out.append(k + 1)
            succ.append(out)
        # forward dataflow: what may differ from the CPU struct on entry to each statement
        din, dout = [0] * n, [-1] * n
        work = list(range(n - 1, -1, -1))
        while work:
            k = work.pop()
            d = self.transfer(events[k], din[k])
            if d != dout[k]:
                dout[k] = d
                for s in succ[k]:
                    if din[s] | d != din[s]:
                        din[s] |= d
                        work.append(s)
        return [self.emit(k, din[k]) for k in range(n)]


class FunctionTranslator:
    def __init__(self, prog, func):
        self.p = prog
        self.f = func
        self.entry = func["entry"]
        self.out = []
        self.labels = set()

    # ------------------------------------------------------------ operands

    def reg_read(self, name):
        if name in GP32:
            return f"c->{name}"
        if name in GP16:
            return f"((uint16_t)c->{GP16[name]})"
        if name in GP8L:
            return f"((uint8_t)c->{GP8L[name]})"
        if name in GP8H:
            return f"((uint8_t)(c->{GP8H[name]} >> 8))"
        if name.startswith("xmm"):
            return f"c->xmm[{name[3:]}]"
        raise Unsupported(f"register {name}")

    def reg_write(self, name, val):
        if name in GP32:
            return f"c->{name} = (uint32_t)({val});"
        if name in GP16:
            r = GP16[name]
            return f"c->{r} = (c->{r} & 0xffff0000u) | (uint16_t)({val});"
        if name in GP8L:
            r = GP8L[name]
            return f"c->{r} = (c->{r} & 0xffffff00u) | (uint8_t)({val});"
        if name in GP8H:
            r = GP8H[name]
            return f"c->{r} = (c->{r} & 0xffff00ffu) | ((uint32_t)(uint8_t)({val}) << 8);"
        raise Unsupported(f"register write {name}")

    def addr(self, ins, op):
        m = op.mem
        parts = []
        if m.base:
            parts.append(self.reg_read(ins.reg_name(m.base)))
        if m.index:
            idx = self.reg_read(ins.reg_name(m.index))
            parts.append(f"{idx} * {m.scale}" if m.scale != 1 else idx)
        if m.disp or not parts:
            parts.append(f"0x{m.disp & 0xffffffff:x}u")
        if m.segment and ins.reg_name(m.segment) == "fs":
            parts.append("c->fs_base")
        return "(uint32_t)(" + " + ".join(parts) + ")"

    def read(self, ins, op, size=None):
        size = size or op.size
        if op.type == CS_OP_REG:
            return self.reg_read(ins.reg_name(op.reg))
        if op.type == CS_OP_IMM:
            return f"({UT[size]})0x{op.imm & ((1 << (8 * size)) - 1):x}u"
        if op.type == CS_OP_MEM:
            return f"R{BITS[size]}({self.addr(ins, op)})"
        raise Unsupported("operand")

    def write(self, ins, op, val, size=None):
        size = size or op.size
        if op.type == CS_OP_REG:
            return self.reg_write(ins.reg_name(op.reg), val)
        if op.type == CS_OP_MEM:
            return f"W{BITS[size]}({self.addr(ins, op)}, ({UT[size]})({val}));"
        raise Unsupported("write operand")

    def rmw(self, ins, op, expr_of):
        """Read-modify-write that evaluates a memory address only once."""
        size = op.size
        if op.type == CS_OP_MEM:
            return (f"{{ uint32_t a_ = {self.addr(ins, op)}; "
                    f"W{BITS[size]}(a_, ({UT[size]})({expr_of(f'R{BITS[size]}(a_)')})); }}")
        return self.write(ins, op, expr_of(self.read(ins, op)))

    # ------------------------------------------------------------ control flow helpers

    def target_stmt(self, target, tail=True):
        """Branch to an address: goto inside this function, otherwise a tail call."""
        if target in self.insn_addrs:
            self.labels.add(target)
            return f"goto L_{target:08x};"
        # a tail call: whatever the callee returns to is this function's caller's business, except code of this
        # function that it pushed as a return address itself
        after = self.unwind_stmt() if self.resume_points else "return;"
        if target in self.p.entries:
            return f"{{ f_{target:08x}(c); {after} }}"
        return f"{{ jump_indirect(c, 0x{target:08x}u, 0x{self.cur:08x}u); {after} }}"

    def unwind_stmt(self):
        """After a call that returned somewhere other than its return address (CPU.ret_to): continue here if
        that is code of this function which it pushed as a return address itself (`push offset label; jmp f`),
        otherwise return so that a frame further up can."""
        cases = " ".join(f"case 0x{t:08x}u: goto L_{t:08x};" for t in sorted(self.resume_points))
        for t in self.resume_points:
            self.labels.add(t)
        return f"switch (c->ret_to) {{ {cases} default: return; }}" if cases else "return;"

    def call_stmt(self, ins, target_expr, direct_target=None):
        ret = ins.address + ins.size
        check = f"if (c->ret_to != 0x{ret:08x}u) {{ {self.unwind_stmt()} }}"
        if direct_target is not None:
            if direct_target in self.p.entries:
                return f"PUSH32(c, 0x{ret:08x}u); c->ret_to = 0x{ret:08x}u; f_{direct_target:08x}(c); {check}"
            return f"PUSH32(c, 0x{ret:08x}u); c->ret_to = 0x{ret:08x}u; call_indirect(c, 0x{direct_target:08x}u); {check}"
        return (f"{{ uint32_t t_ = {target_expr}; PUSH32(c, 0x{ret:08x}u); c->ret_to = 0x{ret:08x}u; "
                f"call_indirect(c, t_); {check} }}")

    # ------------------------------------------------------------ translation

    def decode(self):
        """Recursive-descent disassembly from the entry. Ghidra's body ranges are only used as the
        span a branch may stay within; they can split instructions (e.g. around shared bytes)."""
        lo = min(a for a, _ in self.f["ranges"])
        # Ghidra sometimes leaves pieces of a function (branch targets) outside its body ranges, so the
        # span also extends to the next known entry point.
        hi = max(max(b for _, b in self.f["ranges"]), self.p.next_entry(self.entry))
        # Pointer-derived entries can sit mid-function; they don't split it (that would strand branch
        # targets in another fragment), so only Ghidra's function starts stop decoding.
        inside = lambda t: lo <= t < hi and (t == self.entry or t not in self.p.ghidra_entries)
        seen, todo = {}, [self.entry]
        self.undecodable = []  # addresses reached by flow that hold no valid instruction
        while todo:
            a = todo.pop()
            while a not in seen and inside(a):
                ins = next(self.p.md.disasm(self.p.code(a, a + 16), a, count=1), None)
                if ins is None:
                    self.undecodable.append(a)
                    break
                seen[a] = ins
                m = ins.mnemonic
                op = ins.operands[0] if ins.operands else None
                if (m == "jmp" or (m.startswith("j") and m[1:] in COND) or m in ("jecxz", "jcxz", "loop", "loope", "loopne")) \
                        and op is not None and op.type == CS_OP_IMM and inside(op.imm):
                    todo.append(op.imm)
                if m == "jmp" and op is not None and op.type != CS_OP_IMM:
                    if not self.p.jumptables.get(a):  # Ghidra lists unresolved jumps with no targets
                        self.p.jumptables[a] = self.recover_table(op, inside)
                    todo.extend(t for t in self.p.jumptables.get(a, []) if inside(t))
                if self.is_terminator(ins):
                    break
                a += ins.size
        return sorted(seen.values(), key=lambda i: i.address)

    def recover_table(self, op, inside):
        """Switch tables Ghidra missed: `jmp [reg*4 + table]` -> read entries while they point into
        this function."""
        if op.type != CS_OP_MEM or op.mem.scale != 4 or op.mem.base or not op.mem.index:
            return []
        table, targets = op.mem.disp & 0xffffffff, []
        for k in range(512):
            ent = table + 4 * k - self.p.base
            if ent < 0 or ent + 4 > len(self.p.img):
                break
            t = int.from_bytes(self.p.img[ent:ent + 4], "little")
            if not inside(t):
                break
            targets.append(t)
        return targets

    @staticmethod
    def is_locked(ins):
        for b in ins.bytes:   # leading prefixes
            if b == 0xF0:
                return True
            if b not in (0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65, 0x66, 0x67):
                break
        return ins.mnemonic == "xchg" and any(op.type == CS_OP_MEM for op in ins.operands)

    def translate(self):
        insns = self.decode()
        self.insns = insns
        self.insn_addrs = {i.address for i in insns}
        # code of this function it pushes as a return address itself: where a call can come back to (unwind_stmt);
        # and the return address of each of its setjmp calls, where a longjmp comes back to
        self.resume_points = {i.operands[0].imm & 0xffffffff for i in insns if i.mnemonic == "push" and i.operands
                              and i.operands[0].type == CS_OP_IMM and (i.operands[0].imm & 0xffffffff) in self.insn_addrs}
        self.resume_points |= {i.address + i.size for i in insns if i.mnemonic == "call" and i.operands
                               and i.operands[0].type == CS_OP_IMM and i.operands[0].imm in self.p.setjmp_entries
                               and i.address + i.size in self.insn_addrs}
        body = []
        unsupported = []
        if insns and insns[0].address != self.entry:
            # The body is emitted in address order, but a function can own code below its entry (Ghidra puts
            # shared tails and out-of-line blocks in the function that jumps to them): start at the entry.
            self.cur = self.entry
            body.append((None, self.target_stmt(self.entry)))
        for k, ins in enumerate(insns):
            self.cur = ins.address
            try:
                stmt = self.insn(ins)
            except Unsupported as e:
                unsupported.append(f"{ins.mnemonic} ({e})")
                stmt = f'guest_trap(c, 0x{ins.address:08x}u, "unsupported: {ins.mnemonic} {ins.op_str}");'
            if self.is_locked(ins):
                # x86 atomics (lock prefix, xchg with memory): run under the runtime's global guest lock
                # so spinlocks and interlocked counters stay correct with truly parallel threads
                stmt = f"{{ guest_lock(); {stmt} guest_unlock(); }}"
            body.append((ins, stmt))
            nxt = ins.address + ins.size
            following = insns[k + 1].address if k + 1 < len(insns) else None
            if following != nxt and not self.is_terminator(ins):
                body.append((None, self.target_stmt(nxt)))
        if self.p.trace:
            body = [(ins, f"trace_insn(c, 0x{ins.address:08x}u); {stmt}" if ins is not None else stmt)
                    for ins, stmt in body]
        cache = RegisterCache(body)
        texts = cache.run()
        lines = [f"void f_{self.entry:08x}(CPU *c) {{ /* {self.f['name']} */", "    PREEMPT_POLL(c);",
                 f"    {cache.load()}"]
        for (ins, _), stmt in zip(body, texts):
            if ins is not None:
                if ins.address in self.labels:
                    lines.append(f"L_{ins.address:08x}:;")
                lines.append(f"    {stmt} /* {ins.mnemonic} {ins.op_str} */")
            else:
                lines.append(f"    {stmt}")
        lines.append(f"    {cache.spill(cache.all_bits)}")   # every path ends in a return or tail call; just in case
        lines.append("}")
        return "\n".join(lines) + "\n", unsupported, len(insns)

    @staticmethod
    def is_terminator(ins):
        return ins.mnemonic in RET or ins.mnemonic in ("jmp", "int3", "hlt", "ud2")

    def insn(self, ins):
        m = ins.mnemonic
        if m.startswith("lock "):  # Capstone folds the prefix into the mnemonic; is_locked() handles the lock
            m = m[5:]
        ops = ins.operands
        pre = ins.prefix
        rep = 0xF3 in pre or 0xF2 in pre

        if m in RET:
            return self.i_ret(ins, ops)
        if m.startswith("rep ") or m.startswith("repne ") or m.startswith("repe "):
            return self.string_op(ins, m.split()[1], m.split()[0])
        if m in ("movsb", "movsw", "stosb", "stosw", "stosd", "lodsb", "lodsw", "lodsd",
                 "scasb", "scasw", "scasd", "cmpsb", "cmpsw", "cmpsd") or (
                m == "movsd" and len(ops) == 2 and ops[0].type == CS_OP_MEM and ops[1].type == CS_OP_MEM):
            return self.string_op(ins, m, "rep" if rep else None)

        h = getattr(self, "i_" + m, None)
        if h:
            return h(ins, ops)
        if m.startswith("j") and m[1:] in COND:
            return f"if ({COND[m[1:]]}) {self.target_stmt(ops[0].imm)}"
        if m.startswith("set") and m[3:] in COND:
            return self.write(ins, ops[0], f"{COND[m[3:]]} ? 1 : 0")
        if m.startswith("cmov") and m[4:] in COND:
            return f"if ({COND[m[4:]]}) {self.write(ins, ops[0], self.read(ins, ops[1]))}"
        if m.startswith("f") and m != "femms":
            return self.x87(ins, m, ops)
        v = self.vector_int(ins, m, ops)
        if v is not None:
            return v
        return self.sse(ins, m, ops)

    # --- data movement
    def i_mov(self, ins, o):
        if o[1].type == CS_OP_REG and ins.reg_name(o[1].reg) in SREG_INDEX:
            # mov r/m16, Sreg stores the 16-bit selector; with a 32-bit register destination the P6 and
            # later zero the upper half
            sel = f"(uint32_t)g_seg_selector[{SREG_INDEX[ins.reg_name(o[1].reg)]}]"
            return self.write(ins, o[0], sel, 2 if o[0].type == CS_OP_MEM else o[0].size)
        if o[0].type == CS_OP_REG and ins.reg_name(o[0].reg) in SREG_INDEX:
            raise Unsupported("mov to segment register")
        return self.write(ins, o[0], self.read(ins, o[1], o[0].size))

    def i_movzx(self, ins, o):
        return self.write(ins, o[0], f"(uint32_t){self.read(ins, o[1])}")

    def i_movsx(self, ins, o):
        return self.write(ins, o[0], f"(uint32_t)(int32_t)({ST_[o[1].size]}){self.read(ins, o[1])}")

    def i_lea(self, ins, o):
        a = self.addr(ins, o[1]).replace(" + c->fs_base", "")
        return self.write(ins, o[0], a)

    def i_xchg(self, ins, o):
        s = o[0].size
        if o[0].type == CS_OP_REG and o[1].type == CS_OP_REG and o[0].reg == o[1].reg:
            return ";"
        a, b = self.read(ins, o[0]), self.read(ins, o[1])
        return f"{{ {UT[s]} t0_ = {a}, t1_ = {b}; {self.write(ins, o[0], 't1_')} {self.write(ins, o[1], 't0_')} }}"

    def i_push(self, ins, o):
        if o[0].size == 2:
            return f"c->esp -= 2; W16(c->esp, {self.read(ins, o[0])});"
        v = self.read(ins, o[0], 4)
        if o[0].type == CS_OP_IMM:
            v = f"0x{o[0].imm & 0xffffffff:x}u"
        return f"{{ uint32_t v_ = {v}; PUSH32(c, v_); }}"

    def i_pop(self, ins, o):
        if o[0].type == CS_OP_MEM:  # address is computed after ESP is incremented
            return f"{{ uint32_t v_ = R32(c->esp); c->esp += 4; {self.write(ins, o[0], 'v_')} }}"
        return f"{{ uint32_t v_ = POP32(c); {self.write(ins, o[0], 'v_')} }}"

    def i_pushal(self, ins, o):
        return ("{ uint32_t s_ = c->esp; PUSH32(c, c->eax); PUSH32(c, c->ecx); PUSH32(c, c->edx); "
                "PUSH32(c, c->ebx); PUSH32(c, s_); PUSH32(c, c->ebp); PUSH32(c, c->esi); PUSH32(c, c->edi); }")

    def i_pushaw(self, ins, o):
        # 16-bit pusha: the low words of the eight registers, SP as it was before the first push
        regs = ["c->eax", "c->ecx", "c->edx", "c->ebx", "s_", "c->ebp", "c->esi", "c->edi"]
        return ("{ uint32_t s_ = c->esp; " + " ".join(f"c->esp -= 2; W16(c->esp, (uint16_t){r});" for r in regs)
                + " }")

    def i_popaw(self, ins, o):
        # 16-bit popa: replaces only the low words; the saved SP is skipped
        regs = ["edi", "esi", "ebp", None, "ebx", "edx", "ecx", "eax"]
        return "{ " + " ".join(
            "c->esp += 2;" if r is None else
            f"c->{r} = (c->{r} & 0xffff0000u) | R16(c->esp); c->esp += 2;" for r in regs) + " }"

    def i_popal(self, ins, o):
        return ("c->edi = POP32(c); c->esi = POP32(c); c->ebp = POP32(c); c->esp += 4; "
                "c->ebx = POP32(c); c->edx = POP32(c); c->ecx = POP32(c); c->eax = POP32(c);")

    FLAGS_PACK = ("((uint32_t)c->cf | (PF(c) << 2) | ((uint32_t)c->af << 4) | ((uint32_t)c->zf << 6) | "
                  "((uint32_t)c->sf << 7) | ((uint32_t)c->df << 10) | ((uint32_t)c->of << 11) | "
                  "((uint32_t)c->idf << 21) | 0x202u)")

    def i_pushfd(self, ins, o):
        return f"PUSH32(c, {self.FLAGS_PACK});"

    def i_popfd(self, ins, o):
        return ("{ uint32_t f_ = POP32(c); c->cf = f_ & 1; c->pf_byte = (f_ >> 2) & 1 ? 0 : 1; "
                "c->af = (f_ >> 4) & 1; c->zf = (f_ >> 6) & 1; c->sf = (f_ >> 7) & 1; c->df = (f_ >> 10) & 1; c->of = (f_ >> 11) & 1; "
                "c->idf = (f_ >> 21) & 1; }")

    def i_lahf(self, ins, o):
        return self.reg_write("ah", "(c->cf | (PF(c) << 2) | 2 | (c->af << 4) | (c->zf << 6) | (c->sf << 7))")

    def i_sahf(self, ins, o):
        return ("{ uint32_t f_ = (c->eax >> 8) & 0xff; c->cf = f_ & 1; c->pf_byte = (f_ >> 2) & 1 ? 0 : 1; "
                "c->af = (f_ >> 4) & 1; c->zf = (f_ >> 6) & 1; c->sf = (f_ >> 7) & 1; }")

    def i_cdq(self, ins, o):
        return "c->edx = (uint32_t)((int32_t)c->eax >> 31);"

    def i_cwde(self, ins, o):
        return "c->eax = (uint32_t)(int32_t)(int16_t)c->eax;"

    def i_cbw(self, ins, o):
        return self.reg_write("ax", "(uint16_t)(int16_t)(int8_t)c->eax")

    def i_cwd(self, ins, o):
        return self.reg_write("dx", "((int16_t)c->eax < 0) ? 0xffff : 0")

    def i_bswap(self, ins, o):
        return self.write(ins, o[0], f"__builtin_bswap32({self.read(ins, o[0])})")

    # --- arithmetic / logic
    def arith(self, ins, o, op, store=True):
        s = o[0].size
        b = self.read(ins, o[1], s)
        if not store:
            return f"(void){op}{BITS[s]}(c, {self.read(ins, o[0])}, {b});"
        return self.rmw(ins, o[0], lambda a: f"{op}{BITS[s]}(c, {a}, {b})")

    def i_add(self, ins, o): return self.arith(ins, o, "add")
    def i_adc(self, ins, o): return self.arith(ins, o, "adc")
    def i_sub(self, ins, o): return self.arith(ins, o, "sub")
    def i_sbb(self, ins, o): return self.arith(ins, o, "sbb")
    def i_cmp(self, ins, o): return self.arith(ins, o, "sub", store=False)

    def logic(self, ins, o, cop, store=True):
        s = o[0].size
        if store and cop == "^" and o[0].type == CS_OP_REG and o[1].type == CS_OP_REG and o[0].reg == o[1].reg:
            return self.write(ins, o[0], f"logic{BITS[s]}(c, 0)")
        b = self.read(ins, o[1], s)
        if not store:
            return f"(void)logic{BITS[s]}(c, ({UT[s]})({self.read(ins, o[0])} {cop} {b}));"
        return self.rmw(ins, o[0], lambda a: f"logic{BITS[s]}(c, ({UT[s]})({a} {cop} {b}))")

    def i_and(self, ins, o): return self.logic(ins, o, "&")
    def i_or(self, ins, o): return self.logic(ins, o, "|")
    def i_xor(self, ins, o): return self.logic(ins, o, "^")
    def i_test(self, ins, o): return self.logic(ins, o, "&", store=False)

    def i_not(self, ins, o):
        s = o[0].size
        return self.rmw(ins, o[0], lambda a: f"({UT[s]})~{a}")

    def unary(self, ins, o, fn):
        s = o[0].size
        return self.rmw(ins, o[0], lambda a: f"{fn}{BITS[s]}(c, {a})")

    def i_inc(self, ins, o): return self.unary(ins, o, "inc")
    def i_dec(self, ins, o): return self.unary(ins, o, "dec")
    def i_neg(self, ins, o): return self.unary(ins, o, "neg")

    def shift(self, ins, o, fn):
        s = o[0].size
        n = "1" if len(o) == 1 else (str(o[1].imm) if o[1].type == CS_OP_IMM else "(c->ecx & 0xff)")
        return self.rmw(ins, o[0], lambda a: f"{fn}{BITS[s]}(c, {a}, {n})")

    def i_shl(self, ins, o): return self.shift(ins, o, "shl")
    def i_sal(self, ins, o): return self.shift(ins, o, "shl")
    def i_shr(self, ins, o): return self.shift(ins, o, "shr")
    def i_sar(self, ins, o): return self.shift(ins, o, "sar")
    def i_rol(self, ins, o): return self.shift(ins, o, "rol")
    def i_ror(self, ins, o): return self.shift(ins, o, "ror")
    def i_rcl(self, ins, o): return self.shift(ins, o, "rcl")
    def i_rcr(self, ins, o): return self.shift(ins, o, "rcr")

    def i_xlatb(self, ins, o):
        return self.reg_write("al", "R8(c->ebx + (uint8_t)c->eax)")

    def i_cpuid(self, ins, o):
        return "cpuid(c);"

    def i_rdtsc(self, ins, o):
        return "rdtsc(c);"

    def i_shld(self, ins, o):
        n = str(o[2].imm) if o[2].type == CS_OP_IMM else "(c->ecx & 0xff)"
        src = self.read(ins, o[1])
        return self.rmw(ins, o[0], lambda a: (
            f"({{ unsigned n_ = {n} & 31; uint32_t r_ = n_ ? (({a} << n_) | ({src} >> (32 - n_))) : {a}; "
            f"if (n_) {{ uint32_t s_ = (uint32_t)(((((uint64_t){a} << 32) | {src}) << (n_ - 1)) >> 32); "
            f"c->cf = ({a} >> (32 - n_)) & 1; c->zf = r_ == 0; c->sf = (int32_t)r_ < 0; c->pf_byte = (uint8_t)r_; "
            f"c->of = (s_ ^ r_) >> 31; c->af = 0; }} r_; }})"))

    def i_shrd(self, ins, o):
        n = str(o[2].imm) if o[2].type == CS_OP_IMM else "(c->ecx & 0xff)"
        src = self.read(ins, o[1])
        return self.rmw(ins, o[0], lambda a: (
            f"({{ unsigned n_ = {n} & 31; uint32_t r_ = n_ ? (({a} >> n_) | ({src} << (32 - n_))) : {a}; "
            f"if (n_) {{ uint32_t s_ = (uint32_t)((((uint64_t){src} << 32) | {a}) >> (n_ - 1)); "
            f"c->cf = ({a} >> (n_ - 1)) & 1; c->zf = r_ == 0; c->sf = (int32_t)r_ < 0; c->pf_byte = (uint8_t)r_; "
            f"c->of = (s_ ^ r_) >> 31; c->af = 0; }} r_; }})"))

    @staticmethod
    def mul_flags(r, size):
        """ZF, SF and PF of a MUL/IMUL, which the SDM leaves undefined: QEMU's, from the low `size` bytes of the
        product (what the destination holds; AL, AX or EAX for one operand); AF clear. CF and OF are the caller's."""
        return (f" c->zf = ({UT[size]}){r} == 0; c->sf = ({ST_[size]}){r} < 0; c->pf_byte = (uint8_t){r};"
                " c->af = 0;")

    def i_imul(self, ins, o):
        if len(o) == 1:
            s = o[0].size
            if s == 4:
                return ("{ int64_t r_ = (int64_t)(int32_t)c->eax * (int32_t)" + self.read(ins, o[0]) +
                        "; c->eax = (uint32_t)r_; c->edx = (uint32_t)(r_ >> 32); c->cf = c->of = r_ != (int32_t)r_;"
                        + self.mul_flags("r_", 4) + " }")
            if s == 2:
                return ("{ int32_t r_ = (int16_t)c->eax * (int16_t)" + self.read(ins, o[0]) +
                        "; " + self.reg_write("ax", "r_") + " " + self.reg_write("dx", "r_ >> 16") +
                        " c->cf = c->of = r_ != (int16_t)r_;" + self.mul_flags("r_", 2) + " }")
            return ("{ int16_t r_ = (int8_t)c->eax * (int8_t)" + self.read(ins, o[0]) + "; " +
                    self.reg_write("ax", "r_") + " c->cf = c->of = r_ != (int8_t)r_;" + self.mul_flags("r_", 1) + " }")
        s = o[0].size
        a = self.read(ins, o[0]) if len(o) == 2 else self.read(ins, o[1])
        b = self.read(ins, o[1]) if len(o) == 2 else self.read(ins, o[2], s)
        return ("{ int64_t r_ = (int64_t)(" + ST_[s] + ")" + a + " * (" + ST_[s] + ")" + b + "; " +
                self.write(ins, o[0], "r_") + f" c->cf = c->of = r_ != ({ST_[s]})r_;" + self.mul_flags("r_", s) + " }")

    def i_mul(self, ins, o):
        s = o[0].size
        if s == 4:
            return ("{ uint64_t r_ = (uint64_t)c->eax * " + self.read(ins, o[0]) +
                    "; c->eax = (uint32_t)r_; c->edx = (uint32_t)(r_ >> 32); c->cf = c->of = c->edx != 0;"
                    + self.mul_flags("r_", 4) + " }")
        if s == 2:
            return ("{ uint32_t r_ = (uint32_t)(uint16_t)c->eax * " + self.read(ins, o[0]) + "; " +
                    self.reg_write("ax", "r_") + " " + self.reg_write("dx", "r_ >> 16") + " c->cf = c->of = (r_ >> 16) != 0;"
                    + self.mul_flags("r_", 2) + " }")
        return ("{ uint16_t r_ = (uint16_t)((uint8_t)c->eax * " + self.read(ins, o[0]) + "); " +
                self.reg_write("ax", "r_") + " c->cf = c->of = (r_ >> 8) != 0;" + self.mul_flags("r_", 1) + " }")

    def i_div(self, ins, o):
        s = o[0].size
        d = self.read(ins, o[0])
        if s == 4:
            return ("{ uint32_t d_ = " + d + "; uint64_t n_ = ((uint64_t)c->edx << 32) | c->eax; "
                    f"if (!d_) guest_trap(c, 0x{ins.address:08x}u, \"divide by zero\"); "
                    "c->eax = (uint32_t)(n_ / d_); c->edx = (uint32_t)(n_ % d_); }")
        if s == 2:
            return ("{ uint32_t d_ = " + d + "; uint32_t n_ = ((c->edx & 0xffff) << 16) | (c->eax & 0xffff); "
                    f"if (!d_) guest_trap(c, 0x{ins.address:08x}u, \"divide by zero\"); "
                    + self.reg_write("ax", "n_ / d_") + " " + self.reg_write("dx", "n_ % d_") + " }")
        return ("{ uint32_t d_ = " + d + "; uint32_t n_ = c->eax & 0xffff; "
                f"if (!d_) guest_trap(c, 0x{ins.address:08x}u, \"divide by zero\"); "
                + self.reg_write("al", "n_ / d_") + " " + self.reg_write("ah", "n_ % d_") + " }")

    def i_idiv(self, ins, o):
        s = o[0].size
        d = self.read(ins, o[0])
        if s == 4:
            return ("{ int32_t d_ = (int32_t)" + d + "; int64_t n_ = (int64_t)(((uint64_t)c->edx << 32) | c->eax); "
                    f"if (!d_) guest_trap(c, 0x{ins.address:08x}u, \"divide by zero\"); "
                    "c->eax = (uint32_t)(int32_t)(n_ / d_); c->edx = (uint32_t)(int32_t)(n_ % d_); }")
        if s == 2:
            return ("{ int32_t d_ = (int16_t)" + d + "; int32_t n_ = (int32_t)(((c->edx & 0xffff) << 16) | (c->eax & 0xffff)); "
                    f"if (!d_) guest_trap(c, 0x{ins.address:08x}u, \"divide by zero\"); "
                    + self.reg_write("ax", "n_ / d_") + " " + self.reg_write("dx", "n_ % d_") + " }")
        return ("{ int32_t d_ = (int8_t)" + d + "; int32_t n_ = (int16_t)c->eax; "
                f"if (!d_) guest_trap(c, 0x{ins.address:08x}u, \"divide by zero\"); "
                + self.reg_write("al", "n_ / d_") + " " + self.reg_write("ah", "n_ % d_") + " }")

    def bitop(self, ins, o, kind):
        s = o[0].size
        if o[1].type == CS_OP_IMM:
            bit = f"{o[1].imm % BITS[s]}u"
            base = None
        else:
            bit = f"({self.read(ins, o[1])})"
            base = o[0].type == CS_OP_MEM
        if base:  # bt [mem], reg addresses the whole bit string
            a = self.addr(ins, o[0])
            body = (f"{{ int32_t b_ = (int32_t){bit}; uint32_t a_ = {a} + (uint32_t)((b_ >> 3) & ~3); "
                    f"unsigned k_ = b_ & 31; uint32_t v_ = R32(a_); c->cf = (v_ >> k_) & 1;")
            upd = {"bt": "", "bts": " W32(a_, v_ | (1u << k_));", "btr": " W32(a_, v_ & ~(1u << k_));",
                   "btc": " W32(a_, v_ ^ (1u << k_));"}[kind]
            return body + upd + " }"
        k = f"({bit} % {BITS[s]})"
        cf = f"c->cf = ({self.read(ins, o[0])} >> {k}) & 1;"
        if kind == "bt":
            return cf
        expr = {"bts": "|", "btr": "& ~", "btc": "^"}[kind]
        return "{ " + cf + " " + self.rmw(ins, o[0], lambda a: f"({UT[s]})({a} {expr} ((({UT[s]})1) << {k}))") + " }"

    def i_bt(self, ins, o): return self.bitop(ins, o, "bt")
    def i_bts(self, ins, o): return self.bitop(ins, o, "bts")
    def i_btr(self, ins, o): return self.bitop(ins, o, "btr")
    def i_btc(self, ins, o): return self.bitop(ins, o, "btc")

    # BSF/BSR define only ZF (source zero); the other flags are QEMU's: CF, OF, AF clear, SF and PF of the source
    def bit_scan_flags(self, size):
        return (f"c->zf = v_ == 0; c->sf = ({ST_[size]})v_ < 0; c->pf_byte = (uint8_t)v_; c->cf = 0; c->of = 0; "
                "c->af = 0;")

    def i_bsf(self, ins, o):
        s = o[0].size
        v = self.read(ins, o[1])
        return (f"{{ {UT[s]} v_ = {v}; {self.bit_scan_flags(s)} "
                f"if (v_) {{ {self.write(ins, o[0], '__builtin_ctz(v_)')} }} }}")

    def i_bsr(self, ins, o):
        s = o[0].size
        v = self.read(ins, o[1])
        return (f"{{ {UT[s]} v_ = {v}; {self.bit_scan_flags(s)} "
                f"if (v_) {{ {self.write(ins, o[0], f'{8 * s - 1} - (__builtin_clz(v_) - {32 - 8 * s})')} }} }}")

    def i_xadd(self, ins, o):
        s = o[0].size
        return (f"{{ {UT[s]} d_ = {self.read(ins, o[0])}, s_ = {self.read(ins, o[1])}; "
                f"{self.write(ins, o[1], 'd_')} {self.write(ins, o[0], f'add{BITS[s]}(c, d_, s_)')} }}")

    def i_cmpxchg(self, ins, o):
        s = o[0].size
        acc = {1: "al", 2: "ax", 4: "eax"}[s]
        return (f"{{ {UT[s]} d_ = {self.read(ins, o[0])}; (void)sub{BITS[s]}(c, {self.reg_read(acc)}, d_); "
                f"if (c->zf) {{ {self.write(ins, o[0], self.read(ins, o[1]))} }} else {{ {self.reg_write(acc, 'd_')} }} }}")

    # --- flags
    def i_clc(self, ins, o): return "c->cf = 0;"
    def i_stc(self, ins, o): return "c->cf = 1;"
    def i_cmc(self, ins, o): return "c->cf ^= 1;"
    def i_cld(self, ins, o): return "c->df = 0;"
    def i_std(self, ins, o): return "c->df = 1;"
    def i_nop(self, ins, o): return ";"
    def i_fwait(self, ins, o): return ";"
    def i_wait(self, ins, o): return ";"

    def i_int3(self, ins, o):
        return f'guest_trap(c, 0x{ins.address:08x}u, "int3");'

    def i_hlt(self, ins, o):
        return f'guest_trap(c, 0x{ins.address:08x}u, "hlt");'

    def i_ud2(self, ins, o):
        return f'guest_trap(c, 0x{ins.address:08x}u, "ud2");'

    def i_int(self, ins, o):
        return f'guest_trap(c, 0x{ins.address:08x}u, "int {ins.op_str}");'

    # --- control flow
    def i_jmp(self, ins, o):
        if o[0].type == CS_OP_IMM:
            return self.target_stmt(o[0].imm)
        v = self.read(ins, o[0], 4)
        targets = self.p.jumptables.get(ins.address, [])
        cases = " ".join(f"case 0x{t:08x}u: goto L_{t:08x};" for t in sorted(set(targets)) if t in self.insn_addrs)
        for t in targets:
            if t in self.insn_addrs:
                self.labels.add(t)
        after = self.unwind_stmt() if self.resume_points else "return;"
        return (f"{{ uint32_t t_ = {v}; switch (t_) {{ {cases} default: jump_indirect(c, t_, 0x{ins.address:08x}u); {after} }} }}")

    def i_call(self, ins, o):
        if o[0].type == CS_OP_IMM:
            return self.call_stmt(ins, None, o[0].imm)
        return self.call_stmt(ins, self.read(ins, o[0], 4))

    def i_ret(self, ins, o):
        n = 4 + (o[0].imm if o else 0)
        return f"c->ret_to = R32(c->esp); c->esp += {n}; return;"

    i_retn = i_ret

    def i_enter(self, ins, o):
        # enter size, 0: push ebp; mov ebp, esp; sub esp, size. Nesting levels above 0 copy frame pointers.
        if o[1].imm & 0x1f:
            raise Unsupported("enter with nesting level")
        return f"PUSH32(c, c->ebp); c->ebp = c->esp; c->esp -= {o[0].imm & 0xffff}u;"

    def i_leave(self, ins, o):
        return "c->esp = c->ebp; c->ebp = POP32(c);"

    def i_jecxz(self, ins, o):
        return f"if (c->ecx == 0) {self.target_stmt(o[0].imm)}"

    def i_jcxz(self, ins, o):
        return f"if ((c->ecx & 0xffff) == 0) {self.target_stmt(o[0].imm)}"

    def i_loop(self, ins, o):
        return f"if (--c->ecx != 0) {self.target_stmt(o[0].imm)}"

    def i_loope(self, ins, o):   # loop does not change the flags; the ZF test reads the last flag-setting op
        return f"if (--c->ecx != 0 && c->zf) {self.target_stmt(o[0].imm)}"

    def i_loopne(self, ins, o):
        return f"if (--c->ecx != 0 && !c->zf) {self.target_stmt(o[0].imm)}"

    # --- string instructions
    def string_op(self, ins, m, rep):
        size = {"b": 1, "w": 2, "d": 4}[m[-1]]
        base = m[:-1]
        bits, T = BITS[size], UT[size]
        step = f"(c->df ? -{size} : {size})"
        acc = {1: "al", 2: "ax", 4: "eax"}[size]
        if base == "movs":
            one = f"W{bits}(c->edi, R{bits}(c->esi)); c->esi += {step}; c->edi += {step};"
        elif base == "stos":
            one = f"W{bits}(c->edi, ({T}){self.reg_read(acc)}); c->edi += {step};"
        elif base == "lods":
            one = self.reg_write(acc, f"R{bits}(c->esi)") + f" c->esi += {step};"
        elif base == "scas":
            one = f"(void)sub{bits}(c, {self.reg_read(acc)}, R{bits}(c->edi)); c->edi += {step};"
        elif base == "cmps":
            one = f"(void)sub{bits}(c, R{bits}(c->esi), R{bits}(c->edi)); c->esi += {step}; c->edi += {step};"
        else:
            raise Unsupported(m)
        if not rep:
            return one
        if base in ("movs", "stos", "lods"):
            if base == "movs" and size == 4:
                # Fast path only when a forward dword-by-dword copy equals memmove: x86 copies forward,
                # so a destination overlapping just ahead of the source replicates data (memmove wouldn't).
                return ("if (!c->df && (c->edi - c->esi >= c->ecx * 4u || c->edi <= c->esi)) { "
                        "memmove(HP(c->edi), HP(c->esi), (size_t)c->ecx * 4); "
                        "c->esi += c->ecx * 4; c->edi += c->ecx * 4; c->ecx = 0; } "
                        f"else while (c->ecx) {{ {one} c->ecx--; }}")
            return f"while (c->ecx) {{ {one} c->ecx--; }}"
        stop = "!c->zf" if rep in ("rep", "repe", "repz") else "c->zf"
        return f"while (c->ecx) {{ {one} c->ecx--; if ({stop}) break; }}"

    # --- x87
    def st_idx(self, ins, op):
        n = ins.reg_name(op.reg)
        if not n.startswith("st"):
            raise Unsupported(f"x87 reg {n}")
        return int(n[3]) if "(" in n else 0

    def fmem(self, ins, op, integer=False):
        a = self.addr(ins, op)
        if integer:
            return {2: f"(double)(int16_t)R16({a})", 4: f"(double)(int32_t)R32({a})",
                    8: f"(double)(int64_t)R64({a})"}[op.size]
        return {4: f"fld_f32(R32({a}))", 8: f"fld_f64(R64({a}))", 10: f"RF80({a})"}[op.size]

    def x87(self, ins, m, o):
        binops = {"fadd": "{a} + {b}", "fmul": "{a} * {b}", "fsub": "{a} - {b}", "fsubr": "{b} - {a}",
                  "fdiv": "FDIV(c, {a}, {b})", "fdivr": "FDIV(c, {b}, {a})"}

        def arith(dst, e, a, b):
            # dst = e(a, b) rounded to the precision control; a NaN result takes x86's NaN (see x87_nan2)
            return (f"{{ double a_ = {a}, b_ = {b}; double r_ = {e.format(a='a_', b='b_')}; "
                    f"if (r_ != r_) r_ = x87_nan2(a_, b_); {dst} = FPRES(c, r_); }}")

        base = m.rstrip("p") if m not in ("fsubp", "fdivp", "faddp", "fmulp", "fsubrp", "fdivrp") else m[:-1]
        if m in ("fiadd", "fisub", "fisubr", "fimul", "fidiv", "fidivr"):
            return arith("ST(0)", binops["f" + m[2:]], "ST(0)", self.fmem(ins, o[0], integer=True))
        if base in binops:
            e = binops[base]
            pop = m.endswith("p") and m not in ("fsubr",) and m != "fsub"
            if len(o) == 0:  # faddp with no operands == faddp st(1), st(0)
                return arith("ST(1)", e, "ST(1)", "ST(0)") + " FPOP(c);"
            if o[0].type == CS_OP_MEM:
                return arith("ST(0)", e, "ST(0)", self.fmem(ins, o[0]))
            if len(o) == 1:
                i = self.st_idx(ins, o[0])
                if pop:  # "fsubp st(i)" == FSUBP ST(i), ST(0)
                    return arith(f"ST({i})", e, f"ST({i})", "ST(0)") + " FPOP(c);"
                # "fsub st(i)" == FSUB ST(0), ST(i)
                return arith("ST(0)", e, "ST(0)", f"ST({i})")
            d, s = self.st_idx(ins, o[0]), self.st_idx(ins, o[1])
            # Intel semantics: "fsubp st(i), st(0)" => st(i) = st(i) - st(0); "fsubrp" => st(0) - st(i)
            return arith(f"ST({d})", e, f"ST({d})", f"ST({s})") + (" FPOP(c);" if pop else "")
        if m == "fld":
            if o[0].type == CS_OP_MEM:
                return f"FPUSH(c, {self.fmem(ins, o[0])});"
            return f"{{ double v_ = ST({self.st_idx(ins, o[0])}); FPUSH(c, v_); }}"
        if m == "fild":
            return f"FPUSH(c, {self.fmem(ins, o[0], integer=True)});"
        if m in ("fst", "fstp"):
            pop = " FPOP(c);" if m == "fstp" else ""
            if o[0].type == CS_OP_MEM:
                a = self.addr(ins, o[0])
                w = {4: f"W32({a}, fst_f32(ST(0)));", 8: f"W64({a}, fst_f64(ST(0)));", 10: f"WF80({a}, ST(0));"}[o[0].size]
                return w + pop
            return f"ST({self.st_idx(ins, o[0])}) = ST(0);" + pop
        if m in ("fist", "fistp", "fisttp"):
            a = self.addr(ins, o[0])
            # out-of-range values store the "integer indefinite" of the destination size (0x8000, 0x80000000,
            # 0x8000000000000000); fisttp always truncates, the others round per the control word
            conv = {2: "fpu_to_int16", 4: "fpu_to_int32", 8: "fpu_to_int64"}[o[0].size]
            if m == "fisttp":
                conv_e = f"{conv.replace('fpu_to', 'fpu_trunc_to')}(ST(0))"
            else:
                conv_e = f"{conv}(c, ST(0))"
            w = {2: f"W16({a}, (uint16_t)(int16_t){conv_e});", 4: f"W32({a}, (uint32_t){conv_e});",
                 8: f"W64({a}, (uint64_t){conv_e});"}[o[0].size]
            return w + (" FPOP(c);" if m != "fist" else "")
        if m == "fxch":
            i = self.st_idx(ins, o[-1]) if o else 1  # Capstone: "fxch st(1)" has operands [st(0), st(1)]
            return f"{{ double t_ = ST(0); ST(0) = ST({i}); ST({i}) = t_; }}"
        consts = {"fld1": "1.0", "fldz": "0.0", "fldpi": "M_PI", "fldl2e": "M_LOG2E", "fldln2": "M_LN2",
                  "fldlg2": "0.30102999566398119521", "fldl2t": "3.32192809488736234787"}
        if m in consts:
            return f"FPUSH(c, {consts[m]});"
        unary = {"fchs": "-ST(0)", "fabs": "fabs(ST(0))", "frndint": "fpu_round(c, ST(0))"}
        if m in unary:
            return f"ST(0) = {unary[m]};"
        # one-operand maths whose NaN results follow x86 (x87_nan1)
        nan1 = {"fsqrt": "FPRES(c, {r})", "fsin": "{r}", "fcos": "{r}", "f2xm1": "{r}"}
        fn1 = {"fsqrt": "sqrt(v_)", "fsin": "FTRIG(c, v_, sin)", "fcos": "FTRIG(c, v_, cos)",
               "f2xm1": "(exp2(v_) - 1.0)"}
        if m in nan1:
            return (f"{{ double v_ = ST(0), r_ = {fn1[m]}; if (r_ != r_) r_ = x87_nan1(v_); "
                    f"ST(0) = {nan1[m].format(r='r_')}; }}")
        # FSINCOS/FPTAN: a NaN gives that NaN (quieted) as both results and an infinity, an invalid operand, the
        # real indefinite as both (SDM Vol. 2A results tables; x87_nan1 gives either), C2 clear; |x| >= 2^63 is out
        # of range: C2 set, the operand left. The host's sin/cos/tan do not keep a NaN's sign.
        if m == "fsincos":
            return ("{ double v_ = ST(0); if (v_ != v_ || isinf(v_)) { double n_ = x87_nan1(v_); "
                    "c->fpu_sw &= ~0x0400; ST(0) = n_; FPUSH(c, n_); } "
                    "else if (fabs(v_) >= 9223372036854775808.0) c->fpu_sw |= 0x0400; "
                    "else { c->fpu_sw &= ~0x0400; ST(0) = sin(v_); FPUSH(c, cos(v_)); } }")
        if m == "fptan":
            return ("{ double v_ = ST(0); if (v_ != v_ || isinf(v_)) { double n_ = x87_nan1(v_); "
                    "c->fpu_sw &= ~0x0400; ST(0) = n_; FPUSH(c, n_); } "
                    "else if (fabs(v_) >= 9223372036854775808.0) c->fpu_sw |= 0x0400; "
                    "else { c->fpu_sw &= ~0x0400; ST(0) = tan(v_); FPUSH(c, 1.0); } }")
        if m == "fpatan":
            return ("{ double a_ = ST(1), b_ = ST(0), r_ = atan2(a_, b_); if (r_ != r_) r_ = x87_nan2(a_, b_); "
                    "ST(1) = r_; FPOP(c); }")
        if m == "fyl2x":
            return "{ double y_ = ST(1), x_ = ST(0); ST(1) = FYL2X(c, y_, x_); FPOP(c); }"
        if m == "fscale":
            return "ST(0) = fpu_scale(ST(0), ST(1));"
        if m in ("fprem", "fprem1"):
            fn = "fmod" if m == "fprem" else "remainder"
            return (f"{{ double a_ = ST(0), b_ = ST(1), r_ = {fn}(a_, b_); if (r_ != r_) r_ = x87_nan2(a_, b_); "
                    f"ST(0) = r_; c->fpu_sw &= ~0x0400; }}")
        if m in ("fcom", "fcomp", "fucom", "fucomp", "ficom", "ficomp"):
            if not o:
                b = "ST(1)"
            elif o[0].type == CS_OP_MEM:
                b = self.fmem(ins, o[0], integer=m.startswith("fi"))
            else:
                b = f"ST({self.st_idx(ins, o[-1])})"
            return f"FCOM(c, ST(0), {b});" + (" FPOP(c);" if m.endswith("p") else "")
        if m in ("fcompp", "fucompp"):
            return "FCOM(c, ST(0), ST(1)); FPOP(c); FPOP(c);"
        if m in ("fcompi", "fucompi"):  # Capstone's spelling of fcomip / fucomip
            m = m[:-2] + "ip"
        if m in ("fcomi", "fucomi", "fcomip", "fucomip"):
            i = self.st_idx(ins, o[-1])
            return f"FCOMI(c, ST(0), ST({i}));" + (" FPOP(c);" if m.endswith("p") else "")
        fcmov = {"fcmovb": "c->cf", "fcmove": "c->zf", "fcmovbe": "(c->cf || c->zf)", "fcmovu": "PF(c)",
                 "fcmovnb": "!c->cf", "fcmovne": "!c->zf", "fcmovnbe": "(!c->cf && !c->zf)", "fcmovnu": "!PF(c)"}
        if m in fcmov:
            return f"if ({fcmov[m]}) ST(0) = ST({self.st_idx(ins, o[-1])});"
        if m == "ftst":
            return "FCOM(c, ST(0), 0.0);"
        if m == "fxam":
            # C3 C2 C0: empty 1 0 1, NaN 0 0 1, infinity 0 1 1, zero 1 0 0, normal 0 1 0; C1 = sign
            return ("{ double v_ = c->st[c->top]; uint16_t sw_ = c->fpu_sw & ~0x4700; if (signbit(v_)) sw_ |= 0x0200; "
                    "if (!((c->ftags >> c->top) & 1)) sw_ |= 0x4100; "
                    "else if (isnan(v_)) sw_ |= 0x0100; else if (isinf(v_)) sw_ |= 0x0500; else if (v_ == 0) sw_ |= 0x4000; "
                    "else sw_ |= 0x0400; c->fpu_sw = sw_; }")
        if m in ("fnstsw", "fstsw"):
            if o and o[0].type == CS_OP_REG:
                return self.reg_write("ax", "FNSTSW(c)")
            return f"W16({self.addr(ins, o[0])}, FNSTSW(c));"
        if m in ("fnstcw", "fstcw"):
            return f"W16({self.addr(ins, o[0])}, c->fpu_cw);"
        if m == "fldcw":
            return f"c->fpu_cw = R16({self.addr(ins, o[0])}); fpu_sync_rounding(c);"
        if m in ("fnclex", "fclex"):
            return "c->fpu_sw &= 0x7f00;"
        if m in ("fninit", "finit"):
            return "c->fpu_cw = 0x037f; c->fpu_sw = 0; c->top = 0; c->ftags = 0; fpu_sync_rounding(c);"
        if m == "ffree":
            return f"c->ftags &= (uint8_t)~(1u << ((c->top + {self.st_idx(ins, o[0])}) & 7));"
        if m in ("fnsave", "fsave"):
            return f"fpu_save(c, {self.addr(ins, o[0])});"
        if m == "frstor":
            return f"fpu_restore(c, {self.addr(ins, o[0])});"
        if m == "fincstp":
            return "c->top = (c->top + 1) & 7;"
        if m == "fdecstp":
            return "c->top = (c->top - 1) & 7;"
        raise Unsupported(m)

    # --- packed integer: MMX (mm, 8 bytes) and SSE2 (xmm, 16 bytes) share the helpers in runtime/simd.h
    VBIN = {
        "paddb": "v_add(a_, b_, N, 1, 0)", "paddw": "v_add(a_, b_, N, 2, 0)", "paddd": "v_add(a_, b_, N, 4, 0)",
        "paddq": "v_add(a_, b_, N, 8, 0)", "paddsb": "v_add(a_, b_, N, 1, 1)", "paddsw": "v_add(a_, b_, N, 2, 1)",
        "paddusb": "v_add(a_, b_, N, 1, 2)", "paddusw": "v_add(a_, b_, N, 2, 2)",
        "psubb": "v_sub(a_, b_, N, 1, 0)", "psubw": "v_sub(a_, b_, N, 2, 0)", "psubd": "v_sub(a_, b_, N, 4, 0)",
        "psubq": "v_sub(a_, b_, N, 8, 0)", "psubsb": "v_sub(a_, b_, N, 1, 1)", "psubsw": "v_sub(a_, b_, N, 2, 1)",
        "psubusb": "v_sub(a_, b_, N, 1, 2)", "psubusw": "v_sub(a_, b_, N, 2, 2)",
        "pmullw": "v_mulw(a_, b_, N, 0)", "pmulhw": "v_mulw(a_, b_, N, 1)", "pmulhuw": "v_mulw(a_, b_, N, 2)",
        "pmaddwd": "v_pmaddwd(a_, b_, N)", "pmuludq": "v_pmuludq(a_, b_, N)",
        "pand": "v_logic(a_, b_, N, 0)", "pandn": "v_logic(a_, b_, N, 1)", "por": "v_logic(a_, b_, N, 2)",
        "pxor": "v_logic(a_, b_, N, 3)",
        "punpcklbw": "v_unpack(a_, b_, N, 1, 0)", "punpcklwd": "v_unpack(a_, b_, N, 2, 0)",
        "punpckldq": "v_unpack(a_, b_, N, 4, 0)", "punpcklqdq": "v_unpack(a_, b_, N, 8, 0)",
        "punpckhbw": "v_unpack(a_, b_, N, 1, 1)", "punpckhwd": "v_unpack(a_, b_, N, 2, 1)",
        "punpckhdq": "v_unpack(a_, b_, N, 4, 1)", "punpckhqdq": "v_unpack(a_, b_, N, 8, 1)",
        "packsswb": "v_pack(a_, b_, N, 2, 1)", "packuswb": "v_pack(a_, b_, N, 2, 0)", "packssdw": "v_pack(a_, b_, N, 4, 1)",
        "pcmpeqb": "v_cmp(a_, b_, N, 1, 0)", "pcmpeqw": "v_cmp(a_, b_, N, 2, 0)", "pcmpeqd": "v_cmp(a_, b_, N, 4, 0)",
        "pcmpgtb": "v_cmp(a_, b_, N, 1, 1)", "pcmpgtw": "v_cmp(a_, b_, N, 2, 1)", "pcmpgtd": "v_cmp(a_, b_, N, 4, 1)",
        "pmaxsw": "v_minmax(a_, b_, N, 0)", "pminsw": "v_minmax(a_, b_, N, 1)", "pmaxub": "v_minmax(a_, b_, N, 2)",
        "pminub": "v_minmax(a_, b_, N, 3)", "pavgb": "v_minmax(a_, b_, N, 4)", "pavgw": "v_minmax(a_, b_, N, 5)",
        "psadbw": "v_psadbw(a_, b_, N)",
    }
    VSHIFT = {"psllw": (2, 0), "pslld": (4, 0), "psllq": (8, 0), "psrlw": (2, 1), "psrld": (4, 1), "psrlq": (8, 1),
              "psraw": (2, 2), "psrad": (4, 2)}

    def vreg(self, ins, op):
        if op.type != CS_OP_REG:
            return None
        n = ins.reg_name(op.reg)
        if n.startswith("xmm"):
            return f"c->xmm[{n[3:]}].b", 16
        if n.startswith("mm"):
            return f"&c->mm[{n[2:]}]", 8
        return None

    def vload(self, ins, op, var, n):
        r = self.vreg(ins, op)
        if r:
            return f"memcpy({var}, {r[0]}, {n});"
        return f"memcpy({var}, HP({self.addr(ins, op)}), {n});"

    def vector_int(self, ins, m, o):
        if m in ("emms", "femms"):
            return ";"
        if not o or m in ("cvtpi2ps", "cvtps2pi", "cvttps2pi"):  # MMX <-> XMM conversions: see sse()
            return None
        d = self.vreg(ins, o[0])
        if m in self.VBIN and d and len(o) == 2:
            dst, n = d
            return (f"{{ uint8_t a_[16], b_[16]; memcpy(a_, {dst}, {n}); {self.vload(ins, o[1], 'b_', n)} "
                    f"{self.VBIN[m].replace('N', str(n))}; memcpy({dst}, a_, {n}); }}")
        if m in self.VSHIFT and d:
            dst, n = d
            lane, kind = self.VSHIFT[m]
            if o[1].type == CS_OP_IMM:
                cnt = f"{o[1].imm & 0xff}u"
            else:
                cnt = "cnt_"
            pre = "" if o[1].type == CS_OP_IMM else f"uint8_t c8_[16]; {self.vload(ins, o[1], 'c8_', 8)} uint64_t cnt_; memcpy(&cnt_, c8_, 8); "
            return (f"{{ uint8_t a_[16]; {pre}memcpy(a_, {dst}, {n}); v_shift(a_, {cnt}, {n}, {lane}, {kind}); "
                    f"memcpy({dst}, a_, {n}); }}")
        if m in ("pslldq", "psrldq") and d:
            dst, n = d
            return (f"{{ uint8_t a_[16]; memcpy(a_, {dst}, {n}); v_bshift(a_, {o[1].imm}u, {n}, {int(m == 'pslldq')}); "
                    f"memcpy({dst}, a_, {n}); }}")
        if m in ("pshufw", "pshufd", "pshuflw", "pshufhw") and d:
            dst, n = d
            lane, words, base = {"pshufw": (2, 4, 0), "pshufd": (4, 4, 0), "pshuflw": (2, 4, 0),
                                 "pshufhw": (2, 4, 8)}[m]
            return (f"{{ uint8_t a_[16], b_[16]; {self.vload(ins, o[1], 'b_', n)} memcpy(a_, b_, {n}); "
                    f"v_pshufw(a_, b_, {o[2].imm}u, {lane}, {words}, {base}); memcpy({dst}, a_, {n}); }}")
        if m == "movd":
            if d:
                dst, n = d
                return f"{{ uint32_t v_ = {self.read(ins, o[1], 4)}; memset({dst}, 0, {n}); memcpy({dst}, &v_, 4); }}"
            sreg = self.vreg(ins, o[1])
            if sreg:
                return f"{{ uint32_t v_; memcpy(&v_, {sreg[0]}, 4); {self.write(ins, o[0], 'v_', 4)} }}"
            return None
        if m in ("movq", "movntq", "movq2dq", "movdq2q"):
            s_ = self.vreg(ins, o[1])
            if d:
                dst, n = d
                src = (f"memcpy(&v_, {s_[0]}, 8);" if s_ else f"v_ = R64({self.addr(ins, o[1])});")
                return f"{{ uint64_t v_; {src} memset({dst}, 0, {n}); memcpy({dst}, &v_, 8); }}"
            if s_ and o[0].type == CS_OP_MEM:
                return f"{{ uint64_t v_; memcpy(&v_, {s_[0]}, 8); W64({self.addr(ins, o[0])}, v_); }}"
            return None
        if m == "pextrw":
            s_ = self.vreg(ins, o[1])
            if s_:
                return (f"{{ uint16_t w_; memcpy(&w_, (uint8_t *){s_[0]} + 2 * ({o[2].imm}u % {s_[1] // 2}), 2); "
                        f"{self.write(ins, o[0], '(uint32_t)w_', 4)} }}")
        if m == "pinsrw" and d:
            dst, n = d
            src = self.read(ins, o[1], 4) if o[1].type == CS_OP_REG else f"R16({self.addr(ins, o[1])})"
            return f"{{ uint16_t w_ = (uint16_t)({src}); memcpy((uint8_t *){dst} + 2 * ({o[2].imm}u % {n // 2}), &w_, 2); }}"
        if m == "pmovmskb":
            s_ = self.vreg(ins, o[1])
            if s_:
                return self.write(ins, o[0], f"v_movmskb((const uint8_t *){s_[0]}, {s_[1]})", 4)
        if (d and ins.reg_name(o[0].reg).startswith("mm")) or (len(o) > 1 and self.vreg(ins, o[1]) and
                                                               self.vreg(ins, o[1])[1] == 8):
            raise Unsupported(f"MMX {m}")
        return None

    # --- SSE (the subset this binary's hand-written vector maths uses)
    def xmm(self, ins, op):
        if op.type != CS_OP_REG or not ins.reg_name(op.reg).startswith("xmm"):
            raise Unsupported("MMX/non-XMM operand")
        return f"c->xmm[{ins.reg_name(op.reg)[3:]}]"

    def sse2_double(self, ins, m, o):
        """The SSE2 double-precision instructions this binary contains (the CRT's SSE2 maths). Arithmetic NaN
        results follow x86 (sse_nan2d); conversions to integers give 0x80000000 when out of range."""
        def src(k):  # lane k of the second operand
            if o[1].type == CS_OP_MEM:
                return f"RF64({self.addr(ins, o[1])} + {8 * k})"
            return f"{self.xmm(ins, o[1])}.d[{k}]"

        def srcq(k):
            if o[1].type == CS_OP_MEM:
                return f"R64({self.addr(ins, o[1])} + {8 * k})"
            return f"{self.xmm(ins, o[1])}.q[{k}]"

        arith = {"addsd": "+", "subsd": "-", "mulsd": "*", "divsd": "/",
                 "addpd": "+", "subpd": "-", "mulpd": "*", "divpd": "/"}
        if m in arith:
            d, n = self.xmm(ins, o[0]), (1 if m.endswith("sd") else 2)
            loads = " ".join(f"double s{k}_ = {src(k)};" for k in range(n))
            body = " ".join(f"{{ double r_ = {d}.d[{k}] {arith[m]} s{k}_; if (r_ != r_) r_ = sse_nan2d({d}.d[{k}], s{k}_); "
                            f"{d}.d[{k}] = r_; }}" for k in range(n))
            return f"{{ {loads} {body} }}"
        if m in ("sqrtsd", "sqrtpd"):
            d, n = self.xmm(ins, o[0]), (1 if m == "sqrtsd" else 2)
            loads = " ".join(f"double s{k}_ = {src(k)};" for k in range(n))
            body = " ".join(f"{{ double r_ = sqrt(s{k}_); {d}.d[{k}] = r_ != r_ ? sse_nan1d(s{k}_) : r_; }}" for k in range(n))
            return f"{{ {loads} {body} }}"
        if m in ("andpd", "andnpd", "orpd", "xorpd"):
            d = self.xmm(ins, o[0])
            e = {"andpd": "{d} & {s}", "andnpd": "~{d} & {s}", "orpd": "{d} | {s}", "xorpd": "{d} ^ {s}"}[m]
            loads = " ".join(f"uint64_t s{k}_ = {srcq(k)};" for k in range(2))
            return "{ " + loads + " " + " ".join(f"{d}.q[{k}] = " + e.format(d=f"{d}.q[{k}]", s=f"s{k}_") + ";"
                                                 for k in range(2)) + " }"
        if m == "movsd":  # the SSE2 move (the string movsd, with two memory operands, is handled earlier)
            if o[0].type == CS_OP_MEM:
                return f"W64({self.addr(ins, o[0])}, {self.xmm(ins, o[1])}.q[0]);"
            d = self.xmm(ins, o[0])
            if o[1].type == CS_OP_MEM:
                return f"{d}.q[0] = R64({self.addr(ins, o[1])}); {d}.q[1] = 0;"
            return f"{d}.q[0] = {self.xmm(ins, o[1])}.q[0];"
        if m in ("movlpd", "movhpd"):
            k = 0 if m == "movlpd" else 1
            if o[0].type == CS_OP_MEM:
                return f"W64({self.addr(ins, o[0])}, {self.xmm(ins, o[1])}.q[{k}]);"
            return f"{self.xmm(ins, o[0])}.q[{k}] = R64({self.addr(ins, o[1])});"
        if m in ("unpcklpd", "unpckhpd"):
            d, k = self.xmm(ins, o[0]), (0 if m == "unpcklpd" else 1)
            return f"{{ uint64_t a_ = {d}.q[{k}], b_ = {srcq(k)}; {d}.q[0] = a_; {d}.q[1] = b_; }}"
        if m == "shufpd":
            d, imm = self.xmm(ins, o[0]), o[2].imm
            return (f"{{ uint64_t a_ = {d}.q[{imm & 1}], b_ = {srcq((imm >> 1) & 1)}; "
                    f"{d}.q[0] = a_; {d}.q[1] = b_; }}")
        if m in ("comisd", "ucomisd"):
            return f"FCOMI(c, {self.xmm(ins, o[0])}.d[0], {src(0)});"
        pred = {"eq": "a_ == b_", "lt": "a_ < b_", "le": "a_ <= b_", "unord": "(a_ != a_ || b_ != b_)",
                "neq": "!(a_ == b_)", "nlt": "!(a_ < b_)", "nle": "!(a_ <= b_)", "ord": "(a_ == a_ && b_ == b_)"}
        if m.startswith("cmp") and m[-2:] in ("sd", "pd") and m[3:-2] in pred:
            d, n = self.xmm(ins, o[0]), (1 if m.endswith("sd") else 2)
            loads = " ".join(f"double s{k}_ = {src(k)};" for k in range(n))
            return "{ " + loads + " " + " ".join(
                f"{{ double a_ = {d}.d[{k}], b_ = s{k}_; {d}.q[{k}] = ({pred[m[3:-2]]}) ? ~0ull : 0; }}"
                for k in range(n)) + " }"
        if m in ("cvttsd2si", "cvtsd2si"):
            return self.write(ins, o[0], f"(uint32_t)sse_to_int32(c->mxcsr, {src(0)}, {int(m == 'cvttsd2si')})")
        if m == "cvtsi2sd":
            return f"{self.xmm(ins, o[0])}.d[0] = (double)(int32_t){self.read(ins, o[1], 4)};"  # exact
        if m == "cvtdq2pd":
            d = self.xmm(ins, o[0])
            if o[1].type == CS_OP_MEM:
                a = self.addr(ins, o[1])
                load = f"int32_t i0_ = (int32_t)R32({a}), i1_ = (int32_t)R32({a} + 4);"
            else:
                sx = self.xmm(ins, o[1])
                load = f"int32_t i0_ = (int32_t){sx}.u[0], i1_ = (int32_t){sx}.u[1];"
            return f"{{ {load} {d}.d[0] = i0_; {d}.d[1] = i1_; }}"  # exact
        return None

    def sse(self, ins, m, o):
        r = self.sse2_double(ins, m, o)
        if r is not None:
            return r
        packed = {"addps": "+", "subps": "-", "mulps": "*", "divps": "/"}
        scalar = {"addss": "+", "subss": "-", "mulss": "*", "divss": "/"}
        if m in packed or m in scalar:
            d = self.xmm(ins, o[0])
            n = 4 if m in packed else 1
            opr = (packed if m in packed else scalar)[m]
            if o[1].type == CS_OP_MEM:
                a = self.addr(ins, o[1])
                src = lambda k: f"RF32({a} + {4 * k})"
            else:
                s = self.xmm(ins, o[1])
                src = lambda k: f"{s}.f[{k}]"
            body = " ".join(f"{{ float r_ = {d}.f[{k}] {opr} s{k}_; if (r_ != r_) r_ = sse_nan2f({d}.f[{k}], s{k}_); "
                            f"{d}.f[{k}] = r_; }}" for k in range(n))
            loads = " ".join(f"float s{k}_ = {src(k)};" for k in range(n))
            return f"{{ {loads} {body} }}"
        if m in ("movaps", "movups", "movdqa", "movdqu", "movapd", "movupd"):
            if o[0].type == CS_OP_MEM:
                return f"memcpy(HP({self.addr(ins, o[0])}), {self.xmm(ins, o[1])}.b, 16);"
            if o[1].type == CS_OP_MEM:
                return f"memcpy({self.xmm(ins, o[0])}.b, HP({self.addr(ins, o[1])}), 16);"
            return f"{self.xmm(ins, o[0])} = {self.xmm(ins, o[1])};"
        if m == "movss":
            if o[0].type == CS_OP_MEM:
                return f"WF32({self.addr(ins, o[0])}, {self.xmm(ins, o[1])}.f[0]);"
            if o[1].type == CS_OP_MEM:
                d = self.xmm(ins, o[0])
                return f"{d}.f[0] = RF32({self.addr(ins, o[1])}); {d}.u[1] = {d}.u[2] = {d}.u[3] = 0;"
            return f"{self.xmm(ins, o[0])}.f[0] = {self.xmm(ins, o[1])}.f[0];"
        if m in ("movlps", "movhps"):
            k = 0 if m == "movlps" else 1
            if o[0].type == CS_OP_MEM:
                return f"W64({self.addr(ins, o[0])}, {self.xmm(ins, o[1])}.q[{k}]);"
            return f"{self.xmm(ins, o[0])}.q[{k}] = R64({self.addr(ins, o[1])});"
        if m == "movhlps":
            return f"{self.xmm(ins, o[0])}.q[0] = {self.xmm(ins, o[1])}.q[1];"
        if m == "movlhps":
            return f"{self.xmm(ins, o[0])}.q[1] = {self.xmm(ins, o[1])}.q[0];"
        if m in ("andps", "andnps", "orps", "xorps"):
            d = self.xmm(ins, o[0])
            if o[1].type == CS_OP_MEM:
                a = self.addr(ins, o[1])
                src = lambda k: f"R32({a} + {4 * k})"
            else:
                s = self.xmm(ins, o[1])
                src = lambda k: f"{s}.u[{k}]"
            e = {"andps": "{d} & {s}", "andnps": "~{d} & {s}", "orps": "{d} | {s}", "xorps": "{d} ^ {s}"}[m]
            loads = " ".join(f"uint32_t s{k}_ = {src(k)};" for k in range(4))
            return "{ " + loads + " " + " ".join(
                f"{d}.u[{k}] = " + e.format(d=f"{d}.u[{k}]", s=f"s{k}_") + ";" for k in range(4)) + " }"
        if m == "shufps":
            d, imm = self.xmm(ins, o[0]), o[2].imm
            if o[1].type == CS_OP_MEM:
                a = self.addr(ins, o[1])
                s = lambda k: f"RF32({a} + {4 * k})"
            else:
                sx = self.xmm(ins, o[1])
                s = lambda k: f"{sx}.f[{k}]"
            sel = [(imm >> (2 * k)) & 3 for k in range(4)]
            return (f"{{ XMM t_ = {d}; {d}.f[0] = t_.f[{sel[0]}]; {d}.f[1] = t_.f[{sel[1]}]; "
                    f"{d}.f[2] = {s(sel[2])}; {d}.f[3] = {s(sel[3])}; }}")
        if m in ("unpcklps", "unpckhps"):
            # moved as bit patterns: copying through float would quiet signalling NaNs
            d = self.xmm(ins, o[0])
            if o[1].type == CS_OP_MEM:
                load = f"XMM b_; memcpy(b_.b, HP({self.addr(ins, o[1])}), 16);"
            else:
                load = f"XMM b_ = {self.xmm(ins, o[1])};"
            b = 0 if m == "unpcklps" else 2
            return (f"{{ XMM a_ = {d}; {load} {d}.u[0] = a_.u[{b}]; {d}.u[1] = b_.u[{b}]; "
                    f"{d}.u[2] = a_.u[{b + 1}]; {d}.u[3] = b_.u[{b + 1}]; }}")
        sfn = {"sqrtss": "sse_sqrtf({})", "rsqrtss": "sse_rsqrtf({})", "rcpss": "sse_rcpf({})"}
        pfn = {"sqrtps": "sse_sqrtf({})", "rsqrtps": "sse_rsqrtf({})", "rcpps": "sse_rcpf({})"}
        if m in sfn:
            d = self.xmm(ins, o[0])
            s = f"RF32({self.addr(ins, o[1])})" if o[1].type == CS_OP_MEM else f"{self.xmm(ins, o[1])}.f[0]"
            return f"{d}.f[0] = {sfn[m].format(s)};"
        if m in ("sqrtps", "rsqrtps", "rcpps"):
            d, s = self.xmm(ins, o[0]), self.xmm(ins, o[1])
            return "{ XMM s_ = " + s + "; " + " ".join(f"{d}.f[{k}] = {pfn[m].format(f's_.f[{k}]')};" for k in range(4)) + " }"
        if m in ("minss", "maxss", "minps", "maxps"):
            d = self.xmm(ins, o[0])
            n = 1 if m.endswith("ss") else 4
            cmp = "<" if m.startswith("min") else ">"
            if o[1].type == CS_OP_MEM:
                a = self.addr(ins, o[1])
                src = lambda k: f"RF32({a} + {4 * k})"
            else:
                sx = self.xmm(ins, o[1])
                src = lambda k: f"{sx}.f[{k}]"
            return "{ " + " ".join(f"float s{k}_ = {src(k)}; {d}.f[{k}] = {d}.f[{k}] {cmp} s{k}_ ? {d}.f[{k}] : s{k}_;"
                                   for k in range(n)) + " }"
        if m in ("comiss", "ucomiss"):
            s = f"RF32({self.addr(ins, o[1])})" if o[1].type == CS_OP_MEM else f"{self.xmm(ins, o[1])}.f[0]"
            return f"FCOMI(c, {self.xmm(ins, o[0])}.f[0], {s});"
        if m == "cvtsi2ss":
            return f"{self.xmm(ins, o[0])}.f[0] = sse_int_to_float(c->mxcsr, (int32_t){self.read(ins, o[1], 4)});"
        if m in ("cvttss2si", "cvtss2si"):
            # NaN and out-of-range give 0x80000000; cvtss2si rounds per MXCSR, not the x87 control word
            s = f"RF32({self.addr(ins, o[1])})" if o[1].type == CS_OP_MEM else f"{self.xmm(ins, o[1])}.f[0]"
            return self.write(ins, o[0], f"(uint32_t)sse_to_int32(c->mxcsr, {s}, {int(m == 'cvttss2si')})")
        if m in ("cvtps2pi", "cvttps2pi"):
            # two floats -> two int32 in an MMX register
            d = self.vreg(ins, o[0])
            if o[1].type == CS_OP_MEM:
                a = self.addr(ins, o[1])
                src = lambda k: f"RF32({a} + {4 * k})"
            else:
                sx = self.xmm(ins, o[1])
                src = lambda k: f"{sx}.f[{k}]"
            t = int(m == "cvttps2pi")
            return (f"{{ int32_t r_[2] = {{ sse_to_int32(c->mxcsr, {src(0)}, {t}), sse_to_int32(c->mxcsr, {src(1)}, {t}) }}; "
                    f"memcpy({d[0]}, r_, 8); }}")
        if m == "cvtpi2ps":
            # two int32 -> two floats in the low half; the high half is kept. int32 -> float rounds per MXCSR.
            d = self.xmm(ins, o[0])
            if o[1].type == CS_OP_MEM:
                a = self.addr(ins, o[1])
                load = f"int32_t i_[2] = {{ (int32_t)R32({a}), (int32_t)R32({a} + 4) }};"
            else:
                load = f"int32_t i_[2]; memcpy(i_, {self.vreg(ins, o[1])[0]}, 8);"
            return (f"{{ {load} {d}.f[0] = sse_int_to_float(c->mxcsr, i_[0]); "
                    f"{d}.f[1] = sse_int_to_float(c->mxcsr, i_[1]); }}")
        if m == "movntps":
            # non-temporal store: only the cache hint differs from movaps
            return f"memcpy(HP({self.addr(ins, o[0])}), {self.xmm(ins, o[1])}.b, 16);"
        if m == "movd":
            if o[0].type == CS_OP_REG and ins.reg_name(o[0].reg).startswith("xmm"):
                d = self.xmm(ins, o[0])
                return f"{d}.u[0] = {self.read(ins, o[1], 4)}; {d}.u[1] = {d}.u[2] = {d}.u[3] = 0;"
            return self.write(ins, o[0], f"{self.xmm(ins, o[1])}.u[0]", 4)
        cmp_pred = {"eq": "a_ == b_", "lt": "a_ < b_", "le": "a_ <= b_", "unord": "(a_ != a_ || b_ != b_)",
                    "neq": "!(a_ == b_)", "nlt": "!(a_ < b_)", "nle": "!(a_ <= b_)", "ord": "(a_ == a_ && b_ == b_)"}
        if m.startswith("cmp") and m[-2:] in ("ps", "ss") and m[3:-2] in cmp_pred:
            d, n = self.xmm(ins, o[0]), (4 if m.endswith("ps") else 1)
            if o[1].type == CS_OP_MEM:
                a = self.addr(ins, o[1])
                src = lambda k: f"RF32({a} + {4 * k})"
            else:
                sx = self.xmm(ins, o[1])
                src = lambda k: f"{sx}.f[{k}]"
            pr = cmp_pred[m[3:-2]]
            return "{ " + " ".join(f"{{ float a_ = {d}.f[{k}], b_ = {src(k)}; {d}.u[{k}] = ({pr}) ? 0xffffffffu : 0; }}"
                                   for k in range(n)) + " }"
        if m in ("pxor", "pand", "por", "pandn") and ins.reg_name(o[0].reg).startswith("xmm"):
            d = self.xmm(ins, o[0])
            if o[1].type == CS_OP_MEM:
                a = self.addr(ins, o[1])
                src = lambda k: f"R64({a} + {8 * k})"
            else:
                sx = self.xmm(ins, o[1])
                src = lambda k: f"{sx}.q[{k}]"
            e = {"pxor": "{d} ^ {s}", "pand": "{d} & {s}", "por": "{d} | {s}", "pandn": "~{d} & {s}"}[m]
            return "{ " + " ".join(f"uint64_t s{k}_ = {src(k)};" for k in range(2)) + " " + " ".join(
                f"{d}.q[{k}] = " + e.format(d=f"{d}.q[{k}]", s=f"s{k}_") + ";" for k in range(2)) + " }"
        if m == "movq" and all(op.type == CS_OP_MEM or ins.reg_name(op.reg).startswith("xmm") for op in o):
            if o[0].type == CS_OP_MEM:
                return f"W64({self.addr(ins, o[0])}, {self.xmm(ins, o[1])}.q[0]);"
            d = self.xmm(ins, o[0])
            v = f"R64({self.addr(ins, o[1])})" if o[1].type == CS_OP_MEM else f"{self.xmm(ins, o[1])}.q[0]"
            return f"{{ uint64_t v_ = {v}; {d}.q[0] = v_; {d}.q[1] = 0; }}"
        if m == "cvtps2pd":
            d = self.xmm(ins, o[0])
            if o[1].type == CS_OP_MEM:
                a = self.addr(ins, o[1])
                return f"{{ float x_ = RF32({a}), y_ = RF32({a} + 4); {d}.d[0] = x_; {d}.d[1] = y_; }}"
            sx = self.xmm(ins, o[1])
            return f"{{ float x_ = {sx}.f[0], y_ = {sx}.f[1]; {d}.d[0] = x_; {d}.d[1] = y_; }}"
        if m in ("ldmxcsr",):
            return f"c->mxcsr = R32({self.addr(ins, o[0])});"
        if m in ("stmxcsr",):
            return f"W32({self.addr(ins, o[0])}, c->mxcsr);"
        if m in ("prefetchnta", "prefetcht0", "prefetcht1", "prefetcht2", "emms", "sfence", "lfence", "mfence"):
            return ";"
        raise Unsupported(m)


class Program:
    def __init__(self, exe, functions_json):
        pe = pefile.PE(exe, fast_load=True)
        self.base = pe.OPTIONAL_HEADER.ImageBase
        self.img = pe.get_memory_mapped_image()
        d = json.load(open(functions_json))
        self.functions = {f["entry"]: f for f in d["functions"] if f["ranges"]}
        self.entries = set(self.functions)
        self.ghidra_entries = set(self.entries)  # real function starts; only these bound decoding
        self.jumptables = {j["at"]: j["targets"] for j in d["jumptables"]}
        # setjmp: a call to it returns a second time when longjmp restores its jmp_buf, by jumping to the call's
        # return address with the caller's frame (CPU.ret_to unwinds to it). Ghidra's function ID names the
        # MSVC CRT's (_setjmp3); every function calling one resumes at that call's return address.
        self.setjmp_entries = {e for e, f in self.functions.items() if SETJMP_NAME.fullmatch(f["name"])}
        self.md = Cs(CS_ARCH_X86, CS_MODE_32)
        self.md.detail = True
        self.trace = False
        self.add_pointer_entries(pe)
        self.rejected = []        # (entry, reason) of candidate entries found to be data
        self.flow_entries = 0     # entries added because control flow or a pointer table reaches them
        self._analysis = {}
        self.settle()

    def add_entry(self, t):
        """A new function entry at t, spanning to the next known entry (decoding follows the flow from t)."""
        import bisect
        ordered = sorted(self.entries)
        k = bisect.bisect_right(ordered, t)
        nxt = ordered[k] if k < len(ordered) else self.text_range[1]
        self.functions[t] = {"entry": t, "name": f"PTR_{t:08x}", "ranges": [[t, nxt]]}
        self.entries.add(t)

    def analyze(self, e):
        """Decodes entry e by its control flow (FunctionTranslator.decode) once and caches: the instruction
        addresses, why it cannot be code (None if it can), the .text addresses it calls or jumps to outside its
        own instructions, the switch tables recovered while decoding it, the immediates its instructions
        carry (addresses it takes as values, e.g. `mov edx, offset table`), and the (start, end) byte extents of
        its instructions, sorted. Decoding depends only on Ghidra's
        entries and the jump tables, so adding or dropping other entries never invalidates it."""
        if e not in self._analysis:
            tlo, thi = self.text_range
            tables = set(self.jumptables)
            ft = FunctionTranslator(self, self.functions[e])
            insns = ft.decode()
            addrs = {i.address for i in insns}
            bad = next((i for i in insns if not_user_code(i)), None)
            why = (f"{bad.mnemonic} {bad.op_str} at {bad.address:08x}" if bad
                   else f"no valid instruction at {ft.undecodable[0]:08x}" if ft.undecodable else None)
            targets, consts = set(), set()
            for i in insns:
                for o in i.operands:
                    if o.type == CS_OP_IMM:
                        consts.add(o.imm & 0xffffffff)
                m, op = i.mnemonic, (i.operands[0] if i.operands else None)
                if op is None or op.type != CS_OP_IMM:
                    continue
                t = op.imm & 0xffffffff
                branch = m == "jmp" or (m.startswith("j") and m[1:] in COND) or m in ("jecxz", "jcxz", "loop", "loope",
                                                                                     "loopne")
                if tlo <= t < thi and (m == "call" or (branch and t not in addrs)):
                    targets.add(t)
            extents = sorted((i.address, i.address + i.size) for i in insns)
            self._analysis[e] = (addrs, why, targets, set(self.jumptables) - tables, consts, extents)
        return self._analysis[e]

    def settle(self):
        """Alternates discovery along control flow (close_over_flow) and rejection of data (reject_non_code)
        until neither changes anything, then does the same once more after adding the targets of pointer
        tables at unaligned addresses."""
        while self.close_over_flow() + self.reject_non_code():
            pass
        if self.add_unaligned_tables():
            while self.close_over_flow() + self.reject_non_code():
                pass

    def close_over_flow(self):
        """Makes every address a direct call reaches, and every address a direct jump reaches outside the
        function it is in, an entry of its own. Decoding follows real control flow, so this finds what
        add_pointer_entries' linear scan misses (e.g. `call` past a `jmp`). Returns the number added."""
        added, todo = 0, sorted(self.entries)
        while todo:
            new = set()
            for e in todo:
                new |= {t for t in self.analyze(e)[2] if t not in self.entries}
            for t in sorted(new):
                self.add_entry(t)
            added += len(new)
            todo = sorted(new)
        self.flow_entries += added
        return added

    def reject_non_code(self):
        """Drops entries that are not Ghidra's whose code reaches bytes that are no instruction, or an
        instruction compiled user-mode code never contains (not_user_code), or bytes a switch jump reads as its
        table (switch_data), or an instruction that overlaps one of trusted code without sharing its bounds
        (trusted_overlap), or that call or jump to such an entry: compiled code never branches into data nor has
        overlapping instructions, so all of them are data that looked like code. An entry a Ghidra function
        calls or jumps to is real code and is kept; that and Ghidra's functions are the trusted code. Returns
        the number dropped."""
        import bisect
        protected = set()
        for e in self.ghidra_entries & self.entries:
            protected |= self.analyze(e)[2]
        trusted = sorted({x for e in (self.ghidra_entries | protected) & self.entries for x in self.analyze(e)[5]})
        trusted_lo = [a for a, _ in trusted]

        def trusted_overlap(extents):
            """The first (instruction, trusted instruction) pair whose bytes overlap without being the same
            instruction: decoding started inside an instruction of trusted code, or ran across its bounds."""
            for a, b in extents:
                k = max(bisect.bisect_right(trusted_lo, a) - 1, 0)
                while k < len(trusted) and trusted[k][0] < b:
                    if a < trusted[k][1] and trusted[k] != (a, b):
                        return (a, b), trusted[k]
                    k += 1
            return None
        data = self.switch_data()
        bad = {}
        # the tables' bytes as disjoint intervals, each naming the first table that covers it
        merged = []
        for d in data:
            if d[0] >= d[1]:
                continue
            if merged and d[0] <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], d[1])
            else:
                merged.append([d[0], d[1], d])
        merged_lo = [m[0] for m in merged]

        def table_hit(extents):
            """The first switch table (from data) any of these instruction extents overlaps, and where."""
            for a, b in extents:
                k = bisect.bisect_left(merged_lo, b) - 1   # the last interval starting before the instruction ends
                if k >= 0 and merged[k][1] > a:
                    return merged[k][2], a
            return None

        for e in sorted(self.entries - self.ghidra_entries - protected):
            hit = table_hit(self.analyze(e)[5])
            lap = None if hit else trusted_overlap(self.analyze(e)[5])
            why = self.analyze(e)[1] or (hit and f"decodes the instruction at {hit[1]:08x} from the {hit[0][3]} table "
                                                 f"{hit[0][0]:08x}-{hit[0][1]:08x} read by the switch jump at "
                                                 f"{hit[0][2]:08x}") or \
                (lap and f"decodes an instruction at {lap[0][0]:08x}-{lap[0][1]:08x} overlapping the one at "
                         f"{lap[1][0]:08x}-{lap[1][1]:08x} of Ghidra's code or code it reaches")
            if why:
                bad[e] = why
        changed = True
        while changed:
            changed = False
            for e in sorted(self.entries - self.ghidra_entries - protected - set(bad)):
                hit = next((t for t in sorted(self.analyze(e)[2]) if t in bad), None)
                if hit is not None:
                    bad[e] = f"reaches {hit:08x} ({bad[hit]})"
                    changed = True
        for e, why in sorted(bad.items()):
            self.rejected.append((e, why))
            del self.functions[e]
            self.entries.discard(e)
            for t in self.analyze(e)[3]:  # switch tables recovered while decoding it
                self.jumptables.pop(t, None)
        return len(bad)

    def switch_data(self):
        """(lo, hi, jump address, kind) of the bytes in .text that switch jumps read as data: each table jump's
        `jmp [reg*4 + table]` dword table (the run of dwords at its displacement that are its known targets) and
        the byte index table MSVC indexes first (`movzx reg, byte ptr [x + index]` just before the jump), whose
        length the bounds check before it gives (`cmp x, n-1; ja default`)."""
        import bisect
        tlo, thi = self.text_range
        rd = lambda va: int.from_bytes(self.img[va - self.base:va - self.base + 4], "little")
        out = []
        code = None   # instruction addresses of Ghidra's functions, and entries: only needed for unguarded tables
        for at, targets in sorted(self.jumptables.items()):
            ins = next(self.md.disasm(self.code(at, at + 16), at, count=1), None)
            if ins is None or ins.mnemonic != "jmp" or ins.operands[0].type != CS_OP_MEM:
                continue
            m = ins.operands[0].mem
            table = m.disp & 0xffffffff
            if not (m.index and m.scale == 4 and tlo <= table < thi):
                continue
            ts, n = set(targets), 0
            while table + 4 * n + 4 <= thi and rd(table + 4 * n) in ts:
                n += 1
            out.append((table, table + 4 * n, at, "jump"))
            # the instructions just before the jump, in the function that contains it
            owner = next((e for e in sorted(self.entries) if at in self.analyze(e)[0]), None)
            if owner is None:
                continue
            addrs = sorted(self.analyze(owner)[0])
            k = bisect.bisect_left(addrs, at)
            prev = [next(self.md.disasm(self.code(a, a + 16), a, count=1)) for a in addrs[max(0, k - 64):k]]
            idx_reg = ins.reg_name(m.index)
            load = next((p for p in reversed(prev) if p.mnemonic == "movzx" and p.operands[0].type == CS_OP_REG
                         and p.reg_name(p.operands[0].reg) == idx_reg and p.operands[1].type == CS_OP_MEM
                         and p.operands[1].size == 1), None)
            if load is None:
                continue
            lm = load.operands[1].mem
            index = lm.disp & 0xffffffff
            if not tlo <= index < thi:
                continue
            sel = load.reg_name(lm.base or lm.index)
            # the bounds check: the unsigned jump to the default case before the load, and the instruction that
            # last set the flags it tests (the compiler may schedule other work in between)
            before = prev[:prev.index(load)]
            bound = next((p for p in reversed(before) if p.mnemonic in ("ja", "jae")), None)
            setter = bound and next((p for p in reversed(before[:before.index(bound)])
                                     if X.X86_REG_EFLAGS in p.regs_access()[1]), None)
            if setter is not None and setter.mnemonic == "cmp" and setter.operands[0].type == CS_OP_REG \
                    and setter.reg_name(setter.operands[0].reg) == sel and setter.operands[1].type == CS_OP_IMM:
                limit = setter.operands[1].imm & 0xffffffff
                out.append((index, index + limit + (1 if bound.mnemonic == "ja" else 0), at, "index"))
                continue
            if bound is not None or setter is not None:
                raise SystemExit(f"switch jump at {at:08x}: a bounds check this does not recognise for its index "
                                 f"table at {index:08x}")
            # No bounds check (the callers keep the selector in range): every byte of the table is an index into
            # the n-entry jump table, so it runs while bytes are below n, up to the next instruction or entry
            if code is None:
                code = set().union(*(self.analyze(e)[0] for e in self.ghidra_entries & self.entries)) | self.entries
            end = index
            while end < thi and end not in code and self.img[end - self.base] < n:
                end += 1
            out.append((index, end, at, "index"))
        return sorted(out)

    def add_unaligned_tables(self):
        """Pointer tables at addresses that are not 4-byte aligned (add_pointer_entries scans aligned words
        only): two or more consecutive dwords that all point into .text within 64 KiB of each other, at code
        that decodes as user-mode code, where code takes as a value (an immediate, not a memory operand: constant
        pools are read through displacements) an address at most 64 bytes before the table, its base, to which
        it adds an index. The targets must be distinct and lie within 64 KiB of that code: a dispatch table
        jumps into the module that indexes it, while an array of floats whose bytes, shifted, look like .text
        addresses repeats values and points anywhere. The CRT's x87 maths dispatches through one such table to handlers that
        nothing else reaches. Returns the number of entries added."""
        import bisect
        tlo, thi = self.text_range
        rd = lambda va: int.from_bytes(self.img[va - self.base:va - self.base + 4], "little")
        users = {}  # immediate -> entries whose code takes it as a value
        for e in sorted(self.entries):
            for v in self.analyze(e)[4]:
                users.setdefault(v, []).append(e)
        refs = sorted(users)

        def used_near(k, run):
            # code taking an address in [k - 64, k] as a value, within 64 KiB of every target
            lo_, hi_ = bisect.bisect_left(refs, k - 64), bisect.bisect_right(refs, k)
            return any(all(abs(t - e) < 0x10000 for t in run) for v in refs[lo_:hi_] for e in users[v])

        added = []
        for name in (".rdata", ".data"):
            lo, hi = self.sections[name]
            k = lo
            while k + 8 <= hi:
                if k % 4 == 0:
                    k += 1
                    continue
                run = []
                while k + 4 * (len(run) + 1) <= hi and tlo <= rd(k + 4 * len(run)) < thi:
                    run.append(rd(k + 4 * len(run)))
                if len(set(run)) >= 2 and max(run) - min(run) < 0x10000 and used_near(k, run):
                    fresh = sorted({v for v in run if v not in self.entries})
                    for v in fresh:
                        self.add_entry(v)
                    if all(self.analyze(v)[1] is None for v in fresh):
                        added += fresh
                        k += 4 * len(run)
                        continue
                    for v in fresh:  # not a table after all
                        del self.functions[v]
                        self.entries.discard(v)
                k += 1
        self.flow_entries += len(added)
        return len(added)

    def add_pointer_entries(self, pe):
        """Code reached only through pointers Ghidra never turned into functions (callbacks passed as
        `push offset label`, function tables in .data). Accept a target only if it looks like a function
        start: preceded by padding (int3/nop) or a ret (alignment alone admits round-number constants)."""
        secs = {s.Name.rstrip(b"\0").decode(): (self.base + s.VirtualAddress,
                                                 self.base + s.VirtualAddress + s.Misc_VirtualSize) for s in pe.sections}
        tlo, thi = secs[".text"]
        self.sections, self.text_range = secs, (tlo, thi)
        jt = {t for ts in self.jumptables.values() for t in ts}

        def plausible(t):
            if not (tlo <= t < thi) or t in self.entries or t in jt:
                return False
            prev = self.img[t - self.base - 1]
            prev3 = self.img[t - self.base - 3]
            return prev in (0xCC, 0x90, 0xC3) or prev3 == 0xC2

        md = Cs(CS_ARCH_X86, CS_MODE_32)
        md.detail = True
        insn_starts, imms, cross = set(), set(), set()
        in_insn = bytearray(thi - tlo)  # bytes of Ghidra's functions' instructions
        ordered_g = sorted(self.entries)
        import bisect
        for f in list(self.functions.values()):
            e = f["entry"]
            k = bisect.bisect_right(ordered_g, e)
            span_end = ordered_g[k] if k < len(ordered_g) else thi
            for a, b in f["ranges"]:
                for ins in md.disasm(self.code(a, b), a):
                    insn_starts.add(ins.address)
                    in_insn[ins.address - tlo:ins.address + ins.size - tlo] = b"\x01" * ins.size
                    if ins.mnemonic in ("push", "mov", "lea") and ins.operands and ins.operands[-1].type == CS_OP_IMM:
                        imms.add(ins.operands[-1].imm & 0xffffffff)
                    # direct jumps into the middle of another function (MSVC's strcpy jumps into strcat's
                    # copy loop; unwind funclets jump into their parent): those targets need entries too
                    if (ins.mnemonic == "jmp" or (ins.mnemonic.startswith("j") and ins.mnemonic[1:] in COND)) \
                            and ins.operands and ins.operands[0].type == CS_OP_IMM:
                        t = ins.operands[0].imm & 0xffffffff
                        if tlo <= t < thi and not (e <= t < span_end) and t not in self.entries:
                            cross.add(t)
        # Also accept exact instruction boundaries inside known functions: e.g. the CRT's x87 math
        # dispatcher jumps through a table to handlers in the middle of other functions.
        accept = lambda t: plausible(t) or (t in insn_starts and t not in self.entries and t not in jt)
        # Code no Ghidra function owns (e.g. the CRT's x87 math handlers, reached only via a .data table):
        # accept a data pointer there if it decodes to a few valid instructions.
        import bisect
        spans = sorted((a, b) for f in self.functions.values() for a, b in f["ranges"])
        starts = [a for a, _ in spans]

        def unowned_code(t):
            if not (tlo <= t < thi) or t in self.entries:
                return False
            k = bisect.bisect_right(starts, t) - 1
            if k >= 0 and spans[k][0] <= t < spans[k][1]:
                return False
            return len(list(md.disasm(self.code(t, t + 32), t, count=3))) == 3

        cands = {v for v in imms if accept(v)} | cross
        for name in (".rdata", ".data"):
            a, b = secs[name]
            for va in range(a, b - 3, 4):
                v = int.from_bytes(self.img[va - self.base:va - self.base + 4], "little")
                if accept(v) or unowned_code(v):
                    cands.add(v)
        # Function-pointer tables can also sit inside .text (e.g. right after a switch table); only take
        # targets on known instruction boundaries or that look like function starts.
        rd = lambda va: int.from_bytes(self.img[va - self.base:va - self.base + 4], "little")
        # Code Ghidra never claimed: gaps between known function bodies that decode as code (after
        # skipping int3/nop padding and any switch-table dwords) become functions of their own.
        gaps = 0
        prev_end = tlo
        for a, b in spans + [(thi, thi)]:
            if a > prev_end:
                g = prev_end
                while g < a and self.img[g - self.base] in (0xCC, 0x90):
                    g += 1
                while g + 4 <= a and tlo <= rd(g) < thi:  # table dwords pointing into code
                    g += 4
                while g < a and self.img[g - self.base] in (0xCC, 0x90):
                    g += 1
                if g < a and g not in self.entries:
                    insns = list(md.disasm(self.code(g, a), g, count=4))
                    if len(insns) >= 3 or (insns and (insns[-1].mnemonic in RET or insns[-1].mnemonic == "jmp")):
                        cands.add(g)
                        gaps += 1
                # Further functions inside the same gap: MSVC pads between functions with int3 and
                # aligns starts to 16, so a 16-aligned address right after int3 padding is a start.
                for x in range((g + 15) & ~15, a, 16):
                    if (self.img[x - 1 - self.base] == 0xCC and self.img[x - self.base] not in (0xCC, 0x90)
                            and x not in self.entries and x not in cands):
                        insns = list(md.disasm(self.code(x, a), x, count=4))
                        if len(insns) >= 3 or (insns and (insns[-1].mnemonic in RET or insns[-1].mnemonic == "jmp")):
                            cands.add(x)
                            gaps += 1
            prev_end = max(prev_end, b)
        self.gap_entries = gaps
        for va in range(tlo, thi - 3, 4):
            v = rd(va)
            if not (tlo <= v < thi) or any(in_insn[va - tlo:va + 4 - tlo]):
                continue   # not an address in .text, or bytes of an instruction (an immediate, a displacement)
            in_table = (tlo <= rd(va - 4) < thi) or (va + 8 <= thi and tlo <= rd(va + 4) < thi)
            if accept(v) or (in_table and unowned_code(v)):
                cands.add(v)
        # New entries can themselves jump or call into the middle of other functions (e.g. a static
        # initializer thunk `mov ecx, obj; jmp ctor` whose ctor Ghidra merged into a neighbour), so scan
        # them too, until no new targets appear. Direct calls to non-entries count as well.
        ordered_g = sorted(self.entries)
        todo = list(cands)
        seen = set(cands)
        for f in list(self.functions.values()):
            for a, b in f["ranges"]:
                for ins in md.disasm(self.code(a, b), a):
                    if ins.mnemonic == "call" and ins.operands and ins.operands[0].type == CS_OP_IMM:
                        t = ins.operands[0].imm & 0xffffffff
                        if tlo <= t < thi and t not in self.entries and t not in seen:
                            cands.add(t); seen.add(t); todo.append(t)
        while todo:
            e = todo.pop()
            k = bisect.bisect_right(ordered_g, e)
            span_end = ordered_g[k] if k < len(ordered_g) else thi
            for ins in md.disasm(self.code(e, span_end), e):
                m = ins.mnemonic
                if m in ("push", "mov", "lea") and ins.operands and ins.operands[-1].type == CS_OP_IMM:
                    v = ins.operands[-1].imm & 0xffffffff
                    if tlo <= v < thi and v not in self.entries and v not in seen and v not in jt:
                        nxt = next(md.disasm(self.code(v, v + 16), v, count=1), None)
                        if nxt is not None:
                            cands.add(v); seen.add(v); todo.append(v)
                if (m in ("jmp", "call") or (m.startswith("j") and m[1:] in COND)) and ins.operands \
                        and ins.operands[0].type == CS_OP_IMM:
                    t = ins.operands[0].imm & 0xffffffff
                    outside = not (e <= t < span_end) or m == "call"
                    if tlo <= t < thi and outside and t not in self.entries and t not in seen:
                        cands.add(t); seen.add(t); todo.append(t)
                if m in RET or m in ("jmp", "int3"):
                    break
        ordered = sorted(self.entries | cands)
        for t in cands:
            nxt = ordered[ordered.index(t) + 1] if t != ordered[-1] else thi
            self.functions[t] = {"entry": t, "name": f"PTR_{t:08x}", "ranges": [[t, nxt]]}
        self.entries |= cands
        self.pointer_entries = len(cands)

    def code(self, a, b):
        return self.img[a - self.base:b - self.base]

    def next_entry(self, e):
        import bisect
        if getattr(self, "_sorted_entries", None) is None:
            self._sorted_entries = sorted(self.ghidra_entries)
        k = bisect.bisect_right(self._sorted_entries, e)
        return self._sorted_entries[k] if k < len(self._sorted_entries) else e

    def direct_callees(self, f):
        """Direct call/jump targets plus function addresses used as constants (function pointers)."""
        out = set()
        for a, b in f["ranges"]:
            for ins in self.md.disasm(self.code(a, b), a):
                for op in ins.operands:
                    v = op.imm if op.type == CS_OP_IMM else (op.mem.disp & 0xffffffff if op.type == CS_OP_MEM else None)
                    if v in self.entries and v != f["entry"]:
                        out.add(v)
        return out

    def closure(self, roots):
        todo, seen = list(roots), set()
        while todo:
            e = todo.pop()
            if e in seen or e not in self.functions:
                continue
            seen.add(e)
            todo.extend(self.direct_callees(self.functions[e]))
        return seen


def insn_runs(insns):
    """The decoded instructions of a function as sorted, merged [start, end) address runs."""
    runs = []
    for i in sorted(insns, key=lambda i: i.address):
        if runs and runs[-1][1] == i.address:
            runs[-1][1] = i.address + i.size
        else:
            runs.append([i.address, i.address + i.size])
    return runs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("exe")
    ap.add_argument("functions_json")
    ap.add_argument("outdir")
    ap.add_argument("--roots", default="")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--per-file", type=int, default=400)
    ap.add_argument("--trace", action="store_true", help="call trace_insn() before every instruction")
    a = ap.parse_args()

    prog = Program(a.exe, a.functions_json)
    prog.trace = a.trace
    if a.all:
        chosen = set(prog.entries)
    else:
        chosen = prog.closure([int(x, 16) for x in a.roots.split(",") if x])
    os.makedirs(a.outdir, exist_ok=True)
    for old in os.listdir(a.outdir):  # chunk count can shrink between runs
        if old.startswith("recomp_") and old.endswith(".c"):
            os.remove(os.path.join(a.outdir, old))

    stats = Counter()
    unsup = Counter()
    bad_funcs = []
    chunks, cur = [], []
    translated = []  # what was translated, in functions.json's schema, for tests/difftest.py
    for e in sorted(chosen):
        ft = FunctionTranslator(prog, prog.functions[e])
        try:
            src, uns, n = ft.translate()
            translated.append({"entry": e, "name": prog.functions[e]["name"],
                               "origin": "ghidra" if e in prog.ghidra_entries else "added",
                               "ranges": insn_runs(ft.insns)})
        except Exception as ex:  # keep going; record the failure
            src = f"void f_{e:08x}(CPU *c) {{ guest_trap(c, 0x{e:08x}u, \"translator failed: {type(ex).__name__}\"); }}\n"
            uns, n = [f"translator crash: {type(ex).__name__}: {ex}"], 0
        stats["functions"] += 1
        stats["instructions"] += n
        if uns:
            stats["functions_with_unsupported"] += 1
            stats["unsupported_instructions"] += len(uns)
            bad_funcs.append(e)
            for u in uns:
                unsup[u.split(" (")[0]] += 1
        cur.append(src)
        if len(cur) >= a.per_file:
            chunks.append(cur)
            cur = []
    if cur:
        chunks.append(cur)

    hdr = ['#include "runtime.h"', '#include "simd.h"', '#include <math.h>', ""]
    hdr += [f"void f_{e:08x}(CPU *c);" for e in sorted(prog.entries)]
    with open(os.path.join(a.outdir, "recomp.h"), "w") as f:
        f.write("#ifndef RECOMP_H\n#define RECOMP_H\n" + "\n".join(hdr) + "\n#endif\n")
    for i, ch in enumerate(chunks):
        with open(os.path.join(a.outdir, f"recomp_{i:03d}.c"), "w") as f:
            f.write('#include "recomp.h"\n\n' + "\n".join(ch))
    # Functions referenced but not translated get trapping stubs so everything links.
    missing = sorted(prog.entries - chosen)
    with open(os.path.join(a.outdir, "recomp_stubs.c"), "w") as f:
        f.write('#include "recomp.h"\n\n')
        for e in missing:
            f.write(f'void f_{e:08x}(CPU *c) {{ guest_trap(c, 0x{e:08x}u, "function not recompiled"); }}\n')
        f.write("\nvoid register_all_functions(void) {\n")
        for e in sorted(prog.entries):
            f.write(f"    register_function(0x{e:08x}u, f_{e:08x});\n")
        f.write("}\n")

    stats["files"] = len(chunks)
    stats["pointer_entries"] = prog.pointer_entries
    stats["gap_entries"] = prog.gap_entries
    stats["rejected_entries"] = len(prog.rejected)
    stats["flow_entries"] = prog.flow_entries
    with open(os.path.join(a.outdir, "functions_translated.json"), "w") as f:
        json.dump({"functions": translated,
                   "jumptables": [{"at": k, "targets": v} for k, v in sorted(prog.jumptables.items())],
                   "rejected_entries": [{"entry": e, "why": w} for e, w in prog.rejected]}, f)
    print(json.dumps(dict(stats)))
    if unsup:
        print("unsupported by mnemonic:", unsup.most_common(25))
    with open(os.path.join(a.outdir, "translate_report.json"), "w") as f:
        json.dump({"stats": stats, "unsupported": unsup.most_common(), "functions_with_unsupported":
                   [f"0x{e:08x}" for e in bad_funcs]}, f, indent=1)


if __name__ == "__main__":
    main()
