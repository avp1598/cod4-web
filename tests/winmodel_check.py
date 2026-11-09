"""Checks tests/winmodel.py and the replay in tests/difftest_api.c.

  winmodel_check.py                                   the model's results against Windows' documented ones
  winmodel_check.py <exe> <functions.json> <lib> <function>
                                                      also: the replay catches a recompiled side that diverges
                                                      (<function>: one that passes difftest and calls imports)

The second part runs a trial of <function> normally (it must pass), then again with the emulator's record altered
in each way a divergence would show (a byte the model read, the import, the stack pointer, a call missing or
extra), and requires the recompiled side to fail each time.
"""
import os
import string
import struct
import sys

from unicorn import UC_ARCH_X86, UC_MODE_32, UC_PROT_ALL, UC_PROT_READ, UC_PROT_WRITE, Uc
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EIP, UC_X86_REG_ESP

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))   # run with -I: this directory is not on the path
import winmodel  # noqa: E402

TIB = 0x10000
STACK = 0x200000
BUF = 0x300000
FAILS = []
CHECKED = [0]


def check(what, got, want):
    CHECKED[0] += 1
    if got != want:
        FAILS.append(f"{what}: got {got!r}, want {want!r}")


class Rig:
    """The model on a bare Unicorn: a stack for the arguments, a TEB, and a buffer page."""

    def __init__(self):
        self.model = winmodel.Model(sorted(winmodel.Model.implemented()), TIB, 0x400000)
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        for a in (TIB, STACK, BUF):
            self.uc.mem_map(a, 0x10000, UC_PROT_READ | UC_PROT_WRITE)
        # the arena, mapped whole as tests/difftest.py maps it (the model keeps its page states itself)
        self.uc.mem_map(winmodel.VALLOC_LO, winmodel.VALLOC_HI - winmodel.VALLOC_LO, UC_PROT_ALL)
        self.model.reset(self.ensure, [])

    def ensure(self, uc, page):
        if winmodel.VALLOC_LO <= page < winmodel.VALLOC_HI:
            if page not in self.model.ordinary:
                self.model.give_ordinary(page)
            return UC_PROT_READ | UC_PROT_WRITE
        for lo, hi, perms in uc.mem_regions():
            if lo <= page <= hi:
                return perms
        uc.mem_map(page, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
        return UC_PROT_READ | UC_PROT_WRITE

    def call(self, name, *args):
        """Calls `name` (DLL!Function) with stdcall arguments; returns eax, or the Skip it raised."""
        esp = STACK + 0x8000
        self.uc.mem_write(esp, struct.pack(f"<{1 + len(args)}I", 0x401000, *[a & 0xFFFFFFFF for a in args]))
        self.uc.reg_write(UC_X86_REG_ESP, esp)
        try:
            self.model.call(self.uc, self.model.slot_of[name])
        except winmodel.Skip as e:
            return e
        check(f"{name} pops its arguments", self.uc.reg_read(UC_X86_REG_ESP), esp + 4 + 4 * len(args))
        return self.uc.reg_read(UC_X86_REG_EAX)

    def last_error(self):
        return struct.unpack("<I", self.uc.mem_read(TIB + winmodel.TEB_LAST_ERROR, 4))[0]

    def mem(self, a, n):
        return bytes(self.uc.mem_read(a, n))

    def put(self, a, data):
        self.uc.mem_write(a, data)


K = "KERNEL32.DLL!"


def check_model():
    r = Rig()
    # MulDiv: nearest, halves away from zero; -1 for a zero divisor or a result outside 32 bits
    for a, b, d, want in ((10, 3, 4, 8), (-10, 3, 4, -8), (7, 1, 2, 4), (-7, 1, 2, -4), (5, 1, 0, -1),
                          (0x7FFFFFFF, 2, 1, -1), (0x40000000, 4, 4, 0x40000000), (-6, -6, 4, 9)):
        check(f"MulDiv({a}, {b}, {d})", r.call(K + "MulDiv", a, b, d), want & 0xFFFFFFFF)

    # GetModuleFileNameA, Windows XP: at most n characters, NUL only if there is room, last error untouched
    path = winmodel.EXE_PATH
    r.put(BUF, b"\xAA" * 64)
    check("GetModuleFileNameA truncated", r.call(K + "GetModuleFileNameA", 0, BUF, 5), 5)
    check("GetModuleFileNameA truncated bytes", r.mem(BUF, 6), path[:5] + b"\xAA")
    check("GetModuleFileNameA", r.call(K + "GetModuleFileNameA", 0x400000, BUF, 64), len(path))
    check("GetModuleFileNameA bytes", r.mem(BUF, len(path) + 1), path + b"\0")
    check("GetModuleFileNameA unknown module", r.call(K + "GetModuleFileNameA", 0x12340000, BUF, 64), 0)
    check("GetModuleFileNameA unknown module error", r.last_error(), winmodel.ERROR_MOD_NOT_FOUND)

    # last error and TLS live in the TEB
    r.call(K + "SetLastError", 1234)
    check("GetLastError", r.call(K + "GetLastError"), 1234)
    i = r.call(K + "TlsAlloc")
    check("TlsAlloc first slot", i, 0)
    check("TlsSetValue", r.call(K + "TlsSetValue", i, 0xCAFE), 1)
    check("TlsGetValue", r.call(K + "TlsGetValue", i), 0xCAFE)
    check("TlsGetValue clears the last error", r.last_error(), 0)
    check("TlsGetValue out of range", r.call(K + "TlsGetValue", 5000), 0)
    check("TlsGetValue out of range error", r.last_error(), winmodel.ERROR_INVALID_PARAMETER)

    # Interlocked
    r.put(BUF, struct.pack("<I", 5))
    check("InterlockedCompareExchange (equal)", r.call(K + "InterlockedCompareExchange", BUF, 9, 5), 5)
    check("InterlockedCompareExchange wrote", r.mem(BUF, 4), struct.pack("<I", 9))
    check("InterlockedCompareExchange (unequal)", r.call(K + "InterlockedCompareExchange", BUF, 1, 5), 9)
    check("InterlockedCompareExchange kept", r.mem(BUF, 4), struct.pack("<I", 9))
    check("InterlockedExchangeAdd", r.call(K + "InterlockedExchangeAdd", BUF, -10), 9)
    check("InterlockedExchangeAdd wrote", r.mem(BUF, 4), struct.pack("<i", -1))
    check("InterlockedIncrement", r.call(K + "InterlockedIncrement", BUF), 0)

    # VirtualAlloc / VirtualFree
    MEM_COMMIT, MEM_RESERVE, MEM_DECOMMIT, MEM_RELEASE = 0x1000, 0x2000, 0x4000, 0x8000
    base = r.call(K + "VirtualAlloc", 0, 0x100000, MEM_RESERVE, 4)
    check("VirtualAlloc reserve: 64 KiB aligned, in the arena", (base % 0x10000, winmodel.VALLOC_LO <= base < winmodel.VALLOC_HI),
          (0, True))
    check("reserved, not committed: faults", r.model.reserved_page(base), True)
    check("VirtualAlloc commit inside", r.call(K + "VirtualAlloc", base + 0x1234, 0x10, MEM_COMMIT, 4), base + 0x1000)
    check("committed page accessible", r.model.reserved_page(base + 0x1000), False)
    check("committed page is zero", r.mem(base + 0x1000, 0x1000), bytes(0x1000))
    check("VirtualAlloc commit outside a reservation", r.call(K + "VirtualAlloc", 0x50000000, 0x1000, MEM_COMMIT, 4), 0)
    check("... error", r.last_error(), winmodel.ERROR_INVALID_ADDRESS)
    check("VirtualAlloc size 0", r.call(K + "VirtualAlloc", 0, 0, MEM_COMMIT, 4), 0)
    check("... error", r.last_error(), winmodel.ERROR_INVALID_PARAMETER)
    check("VirtualAlloc bad protection", r.call(K + "VirtualAlloc", 0, 0x1000, MEM_COMMIT, 0), 0)
    check("VirtualFree release with a size", r.call(K + "VirtualFree", base, 0x1000, MEM_RELEASE), 0)
    check("... error", r.last_error(), winmodel.ERROR_INVALID_PARAMETER)
    check("VirtualFree release not at the base", r.call(K + "VirtualFree", base + 0x1000, 0, MEM_RELEASE), 0)
    check("... error", r.last_error(), winmodel.ERROR_INVALID_ADDRESS)
    check("VirtualFree decommit", r.call(K + "VirtualFree", base + 0x1000, 0x1000, MEM_DECOMMIT), 1)
    check("decommitted page faults", r.model.reserved_page(base + 0x1000), True)
    check("VirtualFree release", r.call(K + "VirtualFree", base, 0, MEM_RELEASE), 1)
    check("released: no longer the model's", r.model.region_of(base), None)
    big = r.call(K + "VirtualAlloc", 0, winmodel.COMMIT_LIMIT + 0x1000, MEM_COMMIT | MEM_RESERVE, 4)
    check("VirtualAlloc beyond the commit limit", (big, r.last_error()), (0, winmodel.ERROR_COMMITMENT_LIMIT))

    # heaps
    h = r.call(K + "HeapCreate", 0, 0x1000, 0)
    a = r.call(K + "HeapAlloc", h, 0, 10)
    b = r.call(K + "HeapAlloc", h, 8, 3)   # HEAP_ZERO_MEMORY
    check("HeapAlloc: 8-aligned, distinct", (a % 8, b % 8, b >= a + 10), (0, 0, True))
    check("HeapSize", r.call(K + "HeapSize", h, 0, a), 10)
    r.put(a, b"0123456789")
    c = r.call(K + "HeapReAlloc", h, 0, a, 100)
    check("HeapReAlloc copies", r.mem(c, 10), b"0123456789")
    check("HeapReAlloc frees the old block", isinstance(r.call(K + "HeapSize", h, 0, a), winmodel.Skip), True)
    check("HeapReAlloc shrinks in place", r.call(K + "HeapReAlloc", h, 0, c, 4), c)
    check("HeapReAlloc in place only, growing", r.call(K + "HeapReAlloc", h, 0x10, c, 1000), 0)
    check("HeapFree", r.call(K + "HeapFree", h, 0, c), 1)
    check("HeapFree NULL", r.call(K + "HeapFree", h, 0, 0), 1)
    check("HeapFree twice: undefined, so a skip", isinstance(r.call(K + "HeapFree", h, 0, c), winmodel.Skip), True)
    check("HeapAlloc on a non-heap: a skip", isinstance(r.call(K + "HeapAlloc", 0, 0, 8), winmodel.Skip), True)
    fixed = r.call(K + "HeapCreate", 0, 0x1000, 0x100000)
    check("fixed heap: no block over 0x7FFF8", r.call(K + "HeapAlloc", fixed, 0, 0x80000), 0)

    # code pages: cp1252, with its five undefined bytes mapped to the control characters of the same value
    r.put(BUF, b"A\xe9\x80\x81\0")
    n = r.call(K + "MultiByteToWideChar", 0, 0, BUF, -1, BUF + 0x100, 16)
    check("MultiByteToWideChar", (n, r.mem(BUF + 0x100, 10).decode("utf-16-le")), (5, "Aé€\u0081\0"))
    check("MultiByteToWideChar size query", r.call(K + "MultiByteToWideChar", 0, 0, BUF, 4, 0, 0), 4)
    check("MultiByteToWideChar too small", r.call(K + "MultiByteToWideChar", 0, 0, BUF, 4, BUF + 0x100, 2), 0)
    check("... error", r.last_error(), winmodel.ERROR_INSUFFICIENT_BUFFER)
    r.put(BUF, "é€一\u0081".encode("utf-16-le"))
    n = r.call(K + "WideCharToMultiByte", 0, 0, BUF, 4, BUF + 0x100, 16, 0, BUF + 0x200)
    check("WideCharToMultiByte", (n, r.mem(BUF + 0x100, 4), r.mem(BUF + 0x200, 4)),
          (4, b"\xe9\x80?\x81", struct.pack("<I", 1)))

    # character types (CT_CTYPE1): ASCII against the C locale's classes, which Windows' table agrees with there
    r.put(BUF, b"".join(struct.pack("<H", u) for u in range(128)))
    check("GetStringTypeW", r.call(K + "GetStringTypeW", 1, BUF, 128, BUF + 0x400), 1)
    got = struct.unpack("<128H", r.mem(BUF + 0x400, 256))
    for u in range(128):
        ch = chr(u)
        want = winmodel.C1_DEFINED
        want |= winmodel.C1_UPPER | winmodel.C1_ALPHA if ch in string.ascii_uppercase else 0
        want |= winmodel.C1_LOWER | winmodel.C1_ALPHA if ch in string.ascii_lowercase else 0
        want |= winmodel.C1_DIGIT if ch in string.digits else 0
        want |= winmodel.C1_SPACE if ch in " \t\n\v\f\r" else 0
        want |= winmodel.C1_PUNCT if ch in string.punctuation else 0
        want |= winmodel.C1_CNTRL if u < 0x20 or u == 0x7F else 0
        want |= winmodel.C1_BLANK if ch in " \t" else 0
        want |= winmodel.C1_XDIGIT if ch in string.hexdigits else 0
        check(f"CT_CTYPE1 of {u:#04x}", got[u], want)
    check("CT_CTYPE1 of 'A' (0x381, as Windows documents)", got[ord("A")], 0x381)

    # case mapping: one character to one
    r.put(BUF, "aßÿ".encode("utf-16-le"))
    n = r.call(K + "LCMapStringW", 0x409, 0x200, BUF, 3, BUF + 0x100, 8)
    check("LCMapStringW upper", (n, r.mem(BUF + 0x100, 6).decode("utf-16-le")), (3, "AßŸ"))
    r.put(BUF, b"aZ\xe9\0")
    n = r.call(K + "LCMapStringA", 0x409, 0x200, BUF, -1, BUF + 0x100, 8)
    check("LCMapStringA upper", (n, r.mem(BUF + 0x100, 4)), (4, b"AZ\xc9\0"))

    # modules
    r.put(BUF, b"kernel32\0")
    k32 = r.call(K + "GetModuleHandleA", BUF)
    check("GetModuleHandleA('kernel32') = KERNEL32.DLL's", k32, r.model.modules["KERNEL32.DLL"])
    r.put(BUF, b"mscoree.dll\0")
    check("GetModuleHandleA of a module not loaded", (r.call(K + "GetModuleHandleA", BUF), r.last_error()),
          (0, winmodel.ERROR_MOD_NOT_FOUND))
    r.put(BUF, b"GetLastError\0")
    check("GetProcAddress of an implemented function", r.call(K + "GetProcAddress", k32, BUF),
          winmodel.IMPORT_BASE + winmodel.SLOT * r.model.slot_of[K + "GetLastError"])
    r.put(BUF, b"FlsAlloc\0")
    check("GetProcAddress of one the model lacks", (r.call(K + "GetProcAddress", k32, BUF), r.last_error()),
          (0, winmodel.ERROR_PROC_NOT_FOUND))

    # RtlUnwind: modelled only with no frame between the chain head and the target
    frame = BUF + 0x800
    r.put(frame, struct.pack("<II", 0xFFFFFFFF, 0x401500))   # one registration: next = end, handler
    r.put(TIB, struct.pack("<I", frame))
    check("RtlUnwind to the head frame returns ReturnValue", r.call(K + "RtlUnwind", frame, 0x401234, 0, 7), 7)
    check("... and continues at TargetIp", r.uc.reg_read(UC_X86_REG_EIP), 0x401234)
    check("RtlUnwind with TargetIp NULL returns", (r.call(K + "RtlUnwind", frame, 0, 0, 3),
                                                   r.uc.reg_read(UC_X86_REG_EIP)), (3, 0x401000))
    check("exit unwind through a frame: a skip", isinstance(r.call(K + "RtlUnwind", 0, 0, 0, 0), winmodel.Skip), True)
    check("unwind to a frame not on the chain: a skip",
          isinstance(r.call(K + "RtlUnwind", BUF + 0x900, 0, 0, 0), winmodel.Skip), True)
    r.put(TIB, struct.pack("<I", 0xFFFFFFFF))
    check("exit unwind of an empty chain returns", r.call(K + "RtlUnwind", 0, 0, 0, 5), 5)

    # the clock: host/core.c's virtual clock
    t0 = r.call("WINMM.DLL!timeGetTime")
    r.call(K + "Sleep", 250)
    check("Sleep(250) advances the clock by 250 ms", r.call("WINMM.DLL!timeGetTime") - t0, 250)


def check_replay(exe, funcs_json, lib, entry):
    import ctypes
    import json
    import random
    import difftest
    t = difftest.Tester(exe, lib)
    t.find_correction_sites([f for f in json.load(open(funcs_json))["functions"] if f["ranges"]])
    t.boot()

    def trial(alter, stop_at=None):
        """stop_at: end the emulator's run at that import call (index), as at an import the model cannot run."""
        rng = random.Random(entry)
        scratch, stack, regs = t.setup_state(rng)
        if stop_at is not None:
            real = t.model.call

            def call(uc, slot):
                if len(t.model.records) == stop_at:
                    t.model.end = (slot, uc.reg_read(UC_X86_REG_ESP), "stopped here by the check")
                    raise winmodel.Skip(t.model.end[2])
                return real(uc, slot)
            t.model.call = call
        try:
            uc, err, demand = t.run_unicorn(entry, scratch, stack, regs)
        finally:
            t.model.__dict__.pop("call", None)
        if uc is None:
            raise SystemExit(f"{entry:08x} does not run in the emulator: {err}")
        if not t.model.records and stop_at is None:
            raise SystemExit(f"{entry:08x} makes no import calls on this trial: pick another function")
        alter(t.model)
        t.prepare_recomp(uc, scratch, stack, regs, demand)
        rc = t.lib.dt_run(entry, (ctypes.c_uint32 * 9)(*regs, 0), t.fpu_cw)
        return rc, t.lib.dt_trap_msg().decode() if rc == 1 else ""

    def flip_read(model):
        for c in model.records:
            for k, (kind, addr, data) in enumerate(c.ops):
                if kind == winmodel.OP_READ:
                    c.ops[k] = (kind, addr, bytes([data[0] ^ 1]) + data[1:])
                    return
        raise SystemExit("no read to alter")

    def other_import(model):
        model.records[0].slot = (model.records[0].slot + 1) % len(t.model.names)

    def shift_esp(model):
        model.records[0].esp += 4

    def drop_last(model):
        model.records.pop()

    def add_one(model):
        model.records.append(model.records[-1])

    def end_elsewhere(model):
        model.end = ((model.end[0] + 1) % len(model.names), model.end[1], model.end[2])

    def end_esp(model):
        model.end = (model.end[0], model.end[1] + 4, model.end[2])

    check("unaltered record: the trial runs to the end", trial(lambda model: None)[0], 0)
    check("stopped at the first import: the recompiled side stops there too", trial(lambda model: None, 0)[0], 5)
    check("stopped at the second import", trial(lambda model: None, 1)[0], 5)
    for alter in (end_elsewhere, end_esp):
        rc, msg = trial(alter, 1)
        check(f"stop with {alter.__name__}", (rc, "the emulator stopped at" in msg), (1, True))
    for alter, want_rc, want_msg in ((flip_read, 1, "the emulator read"), (other_import, 1, "the emulator's is"),
                                     (shift_esp, 1, "esp"), (drop_last, 1, "the emulator made only"),
                                     (add_one, 4, "")):
        rc, msg = trial(alter)
        check(f"replay with {alter.__name__}", (rc, want_msg in msg), (want_rc, True))


def main():
    check_model()
    if len(sys.argv) == 5:
        check_replay(sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4], 16))
    for f in FAILS:
        print("FAIL", f)
    print(f"{CHECKED[0]} checks, {len(FAILS)} failures")
    sys.exit(1 if FAILS else 0)


if __name__ == "__main__":
    main()
