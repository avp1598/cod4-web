"""A deterministic model of the Windows imports, for difftest.

Unicorn has no Windows, so before this a function that called an import could only be skipped. Now the emulator
side runs the import here, and every memory access the model makes is recorded in order, together with the
registers it leaves. The recompiled side does not run its own copy: tests/difftest_api.c replays the record at
the same point of its run, after checking that it is the same import, at the same stack pointer, and that every
byte the model read has the same value there. An import's results depend only on its arguments, the memory it
reads and this model's state, so a replay that passes those checks is exactly what a second copy of the model
would have done, and any divergence in what the recompiled code passes to Windows is a failure.

The model is single-threaded, with Windows' documented semantics except where the system has a free choice
(addresses, ids, the clock), and there it follows host/kernel32.c in its deterministic mode (RC_DETERMINISTIC):

* per-thread state lives in the TEB at Windows' offsets (last error, client id, TLS slots), so it is in memory
  both sides compare; ids are host/kernel32.c's (process 0x1234, main thread 0x100)
* critical sections: their memory is not interpreted (as host/kernel32.c): a single thread never blocks, and
  ownership and recursion are counted here per address
* the clock: host/core.c's virtual clock (60 s at the start, every read adds 1 us, Sleep(ms) advances ms,
  Sleep(0) 1 ms)
* modules: the exe and the DLLs it imports from are loaded (handles as host/kernel32.c's FAKE_MODULE); a DLL
  exports the functions the exe imports from it and those this model implements, and GetProcAddress of anything
  else fails as for a function that DLL lacks (host/kernel32.c also returns NULL for what it does not implement).
  GetModuleFileNameA follows Windows XP, the version host/kernel32.c's GetVersionExA reports
* the CPU: IsProcessorFeaturePresent answers from the features difftest's cpuid reports
* the process (host/kernel32.c): Windows XP SP2, code pages 1252 (ANSI) and 437 (OEM), the command line is the
  quoted exe path, the environment is empty, STARTUPINFO is empty, and the standard handles are character
  devices
* locale: the user and system locale are 0x409 (English, US). Character types (GetStringType CT_CTYPE1) come
  from the Unicode general categories and case mapping (LCMapString) from Unicode's simple 1:1 mappings, the
  sources Windows' own tables derive from (as Wine's do); Windows' tables may differ for some characters above
  U+007F
* memory: VirtualAlloc reservations and heaps are placed in [VALLOC_LO, VALLOC_HI) at the lowest free 64 KiB
  boundary; committed pages are zero; reserved pages that are not committed fault, as on Windows. At most
  COMMIT_LIMIT bytes are committed, beyond which an allocation fails as on a machine out of commit charge.
  The harness maps the whole arena in Unicorn once and enforces these page states in a hook (fault_in_arena):
  a Unicorn region per reservation made trials with thousands of allocations crawl (see runs)

An import the model does not implement, or a call whose effect on Windows is undefined (freeing a pointer a heap
did not allocate, an invalid heap handle), ends the trial as a skip whose reason says which and why.
"""
import codecs
import collections
import copy
import struct
import unicodedata

from unicorn import UC_PROT_EXEC, UC_PROT_READ, UC_PROT_WRITE
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EIP, UC_X86_REG_ESP

PAGE = 0x1000
GRANULARITY = 0x10000            # allocation granularity: reservations start on 64 KiB boundaries
IMPORT_BASE = 0xF0000000         # runtime/cpu.h: import slot k is called at IMPORT_BASE + 16 * k
SLOT = 16

# TEB (x86): ClientId, LastErrorValue, TlsSlots[64], TlsExpansionSlots
TEB_PROCESS_ID, TEB_THREAD_ID, TEB_LAST_ERROR, TEB_TLS, TEB_TLS_EXPANSION = 0x20, 0x24, 0x34, 0xE10, 0xF94
TLS_MINIMUM_AVAILABLE, TLS_EXPANSION_SLOTS = 64, 1024
PROCESS_ID, THREAD_ID = 0x1234, 0x100              # host/kernel32.c GetCurrentProcessId, the main thread's id
EXE_PATH = b"C:\\Game\\iw3sp.exe"                  # host/profile.h's PROFILE_GUEST_ROOT and the executable's name
PSEUDO_PROCESS, PSEUDO_THREAD = 0xFFFFFFFF, 0xFFFFFFFE
COMMAND_LINE = b'"' + EXE_PATH + b'"'
STD_HANDLES = {-10 & 0xFFFFFFFF: 0xF0, -11 & 0xFFFFFFFF: 0xF4, -12 & 0xFFFFFFFF: 0xF8}   # host/kernel32.c STD_IN...
FILE_TYPE_UNKNOWN, FILE_TYPE_CHAR = 0, 2
INVALID_HANDLE_VALUE = 0xFFFFFFFF
# Windows XP SP2 (host/kernel32.c GetVersionExA): major, minor, build, VER_PLATFORM_WIN32_NT
OS_VERSION = (5, 1, 2600, 2)
OS_SERVICE_PACK = b"Service Pack 2"
CP_ACP, CP_OEMCP, ANSI_CP, OEM_CP = 0, 1, 1252, 437
LOCALE_US = 0x409
LOCALES = (0, 0x400, 0x800, LOCALE_US)   # neutral, LOCALE_USER_DEFAULT, LOCALE_SYSTEM_DEFAULT: all 0x409 here
CT_CTYPE1 = 1
C1_UPPER, C1_LOWER, C1_DIGIT, C1_SPACE, C1_PUNCT, C1_CNTRL, C1_BLANK, C1_XDIGIT, C1_ALPHA, C1_DEFINED = \
    0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x100, 0x200
LCMAP_LOWERCASE, LCMAP_UPPERCASE = 0x100, 0x200
MODULE_BASE = 0xF1000000                           # host/kernel32.c FAKE_MODULE(i): MODULE_BASE + i * 64 KiB
# handler method prefix -> the DLL it implements, named as runtime.c names import slots ("DLL!Function")
DLL_OF_PREFIX = {"k32_": "KERNEL32.DLL", "winmm_": "WINMM.DLL"}
# CPUID leaf 1 EDX that difftest reports (difftest.cpuid_hook, as runtime.c's cpuid): FPU, TSC, CX8, CMOV
CPUID_EDX = 0x8111
# IsProcessorFeaturePresent feature -> the CPUID leaf 1 EDX bit it reports (PF_* in winnt.h)
PF_CPUID_BIT = {2: 8, 3: 23, 6: 25, 8: 4, 9: 6, 10: 26}   # CMPXCHG8B, MMX, SSE, RDTSC, PAE, SSE2

VALLOC_LO, VALLOC_HI = 0x60000000, 0xE0000000      # runtime/runtime.h GUEST_VALLOC_LO/HI (native)
COMMIT_LIMIT = 64 << 20

ERROR_INVALID_HANDLE, ERROR_NOT_ENOUGH_MEMORY, ERROR_INVALID_PARAMETER, ERROR_INSUFFICIENT_BUFFER = 6, 8, 87, 122
ERROR_MOD_NOT_FOUND, ERROR_PROC_NOT_FOUND, ERROR_INVALID_ADDRESS, ERROR_COMMITMENT_LIMIT = 126, 127, 487, 1455

MEM_COMMIT, MEM_RESERVE, MEM_DECOMMIT, MEM_RELEASE, MEM_TOP_DOWN = 0x1000, 0x2000, 0x4000, 0x8000, 0x100000
PROTECT = {0x01: 0, 0x02: UC_PROT_READ, 0x04: UC_PROT_READ | UC_PROT_WRITE, 0x10: UC_PROT_EXEC,
           0x20: UC_PROT_READ | UC_PROT_EXEC, 0x40: UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC}
PROT_NAMES = {UC_PROT_READ: "read", UC_PROT_WRITE: "write", UC_PROT_EXEC: "execute"}
PAGE_GUARD, PAGE_NOCACHE, PAGE_WRITECOMBINE = 0x100, 0x200, 0x400

HEAP_NO_SERIALIZE, HEAP_GENERATE_EXCEPTIONS, HEAP_ZERO_MEMORY, HEAP_REALLOC_IN_PLACE_ONLY = 0x1, 0x4, 0x8, 0x10
HEAP_RESERVE = 64 << 20          # the reservation of a growable heap (HeapCreate with dwMaximumSize 0)
HEAP_MAX_BLOCK_FIXED = 0x7FFF8   # largest block of a fixed-size heap (HeapAlloc's documentation)
HEAP_ALIGN = 8

# Record operations (tests/difftest_api.c parses the same layout)
OP_READ, OP_WRITE, OP_ZERO = 0, 1, 2


class Skip(Exception):
    """The trial cannot go on: the import is not modelled, or what it would do on Windows is undefined."""


class ModelError(Exception):
    """A bug in the model or the harness (not a property of the code under test): it must stop the run, so it is
    not a UcError, which the harness reads as the emulated code faulting."""


def page_down(a):
    return a & ~(PAGE - 1)


def page_up(a):
    return (a + PAGE - 1) & ~(PAGE - 1)


def runs(pages):
    """Pages as maximal runs of consecutive pages, (first page, length in bytes): what is mapped or written in one
    Unicorn call. Unicorn keeps a region per mem_map, and each mem_map costs time that grows
    faster than quadratically in the number of regions, so mapping page by page makes long runs crawl."""
    out = []
    for p in sorted(pages):
        if out and out[-1][0] + out[-1][1] == p:
            out[-1][1] += PAGE
        else:
            out.append([p, PAGE])
    return [(a, n) for a, n in out]


class Call:
    """One import call: reads its arguments and memory through Unicorn, recording every access in order."""

    def __init__(self, model, uc, slot, name):
        self.model, self.uc, self.slot, self.name = model, uc, slot, name
        self.esp = uc.reg_read(UC_X86_REG_ESP)
        self.ops = []
        self.regs = {}

    def read(self, addr, n):
        """Memory as the import sees it: the emulator's, with this call's own (still pending) writes over it."""
        self.model.accessible(self.uc, addr, n, self.name)
        data = bytearray(self.uc.mem_read(addr, n))
        for kind, a, w in self.ops:
            if kind == OP_WRITE and a < addr + n and addr < a + len(w):
                lo, hi = max(a, addr), min(a + len(w), addr + n)
                data[lo - addr:hi - addr] = w[lo - a:hi - a]
        data = bytes(data)
        self.ops.append((OP_READ, addr, data))
        return data

    def u32(self, addr):
        return struct.unpack("<I", self.read(addr, 4))[0]

    def write(self, addr, data):
        """Recorded now, made in the emulator's memory when the import completes (Model.call): an import that ends
        the trial part-way (Skip) leaves memory as it was, as the recompiled side has it at that call."""
        self.model.accessible(self.uc, addr, len(data), self.name, write=True)
        self.ops.append((OP_WRITE, addr, bytes(data)))

    def w32(self, addr, v):
        self.write(addr, struct.pack("<I", v & 0xFFFFFFFF))

    def fresh_page(self, page):
        """A page just committed: Unicorn maps it zeroed; the replay fills it (rather than recording 4 KiB)."""
        self.ops.append((OP_ZERO, page, PAGE))

    def arg(self, i):
        return self.u32(self.esp + 4 + 4 * i)

    def cstr(self, addr):
        """A NUL-terminated string, read a byte at a time so that only the bytes Windows reads are recorded."""
        out = bytearray()
        while True:
            b = self.read(addr + len(out), 1)[0]
            if b == 0:
                return bytes(out)
            out.append(b)

    def ret(self, nargs, eax, to=None):
        """stdcall return: eax, the arguments and the return address popped; `to`: continue there instead of at the
        return address (with the stack as after the return)."""
        self.ret_to = self.u32(self.esp) if to is None else to
        self.regs[UC_X86_REG_EAX] = eax & 0xFFFFFFFF
        self.esp_out = self.esp + 4 + 4 * nargs

    def last_error(self, code):
        self.w32(self.model.tib + TEB_LAST_ERROR, code)


class Region:
    """A reservation: [base, base + size), its committed pages and their protection."""

    def __init__(self, base, size):
        self.base, self.size = base, size
        self.committed = {}   # page -> Unicorn protection

    def contains(self, a, n=1):
        return self.base <= a and a + n <= self.base + self.size


class Heap:
    def __init__(self, region, fixed):
        self.region, self.fixed = region, fixed
        self.next = region.base
        self.blocks = {}      # live block -> size requested


class Model:
    @classmethod
    def implemented(cls):
        """"DLL!Function" -> handler method name, for every function the model implements."""
        return {f"{dll}!{m[len(prefix):]}": m for m in dir(cls) for prefix, dll in DLL_OF_PREFIX.items()
                if m.startswith(prefix)}

    @classmethod
    def dynamic_names(cls, imported):
        """Functions the model implements that the exe does not import: reachable only through GetProcAddress, so
        the harness gives them import slots of their own (after the IAT's), in this order."""
        return sorted(set(cls.implemented()) - set(imported))

    def __init__(self, names, tib, image_base):
        self.names = names      # import slot -> "DLL!Function": the IAT's, as runtime.c names them, then dynamic_names
        self.slot_of = {n: k for k, n in enumerate(names)}
        self.tib = tib
        self.image_base = image_base
        self.handlers = {n: getattr(self, m) for n, m in self.implemented().items()}
        dlls = []
        for n in names:
            if n.split("!", 1)[0] not in dlls:
                dlls.append(n.split("!", 1)[0])
        self.modules = {dll: MODULE_BASE + (i + 1) * GRANULARITY for i, dll in enumerate(dlls)}
        self.ensure = None

    STATE = ("cs", "vtime_us", "regions", "committed", "heaps", "process_heap", "tls_used", "strings",
             "exception_filter", "error_mode")

    def reset(self, ensure, ordinary, base=None):
        """A run's starting state: Windows as a process starts, or `base` (a snapshot(), whose memory the caller
        has written with write_snapshot). ensure(uc, page) makes an ordinary page accessible the way the harness's
        hooks do for the code under test and returns its Unicorn protection. ordinary: the arena pages already given
        out as ordinary memory (by the start-up run); the harness adds more with give_ordinary. The arena is mapped
        whole, so Unicorn cannot tell them from free space; reservations avoid them, as they avoid mapped memory."""
        self.ensure = ensure
        self.records = []
        self.end = None   # (slot, esp, why): the import the run stopped at, unmodelled (see call)
        if base is not None:
            for k, v in zip(self.STATE, copy.deepcopy(base[0])):
                setattr(self, k, v)
            self.index(ordinary)
            return
        self.cs = {}            # critical section address -> recursion count of the (single) thread
        self.vtime_us = 0
        self.regions = []
        self.committed = 0
        self.heaps = {}         # handle -> Heap
        self.process_heap = None
        self.tls_used = set()
        self.strings = {}       # process strings Windows keeps (command line, environment) -> address
        self.exception_filter = 0   # SetUnhandledExceptionFilter: none until the process sets one
        self.error_mode = 0         # SetErrorMode: a process starts with 0 (every error box shown)
        self.index(ordinary)

    def index(self, ordinary):
        """The arena's occupancy, derived from the reservations and the ordinary pages: which Region reserves each
        64 KiB granule (a granule holds at most one: reservations start on granule boundaries), and a byte per
        granule, nonzero where anything (a reservation, an ordinary page) occupies it. Placement looks for runs of
        free granules in that bytearray, at C speed: rebuilding a sorted list of every busy range for each call
        took minutes in trials that call VirtualAlloc thousands of times."""
        self.granules = {}
        self.busy = bytearray((VALLOC_HI - VALLOC_LO) // GRANULARITY)
        self.ordinary = set()
        self.ordinary_in = collections.Counter()   # granule -> ordinary pages in it
        for r in self.regions:
            self.occupy(r)
        for p in ordinary:
            self.give_ordinary(p)

    def occupy(self, r):
        for g in range(r.base & ~(GRANULARITY - 1), r.base + r.size, GRANULARITY):
            self.granules[g] = r
            self.busy[(g - VALLOC_LO) // GRANULARITY] = 1

    def give_ordinary(self, page):
        """An arena page outside the reservations, now ordinary memory (see reset)."""
        g = page & ~(GRANULARITY - 1)
        self.ordinary.add(page)
        self.ordinary_in[g] += 1
        self.busy[(g - VALLOC_LO) // GRANULARITY] = 1

    def snapshot(self, uc):
        """The model's state and the contents of its committed pages, to start later runs from (reset(base=))."""
        pages = {p: (prot, bytes(uc.mem_read(p, PAGE))) for r in self.regions for p, prot in r.committed.items()}
        return copy.deepcopy(tuple(getattr(self, k) for k in self.STATE)), pages

    @staticmethod
    def write_snapshot(uc, base):
        """A snapshot's committed pages into the arena (mapped whole by the harness)."""
        for p, (prot, data) in base[1].items():
            uc.mem_write(p, data)

    # ---------------------------------------------------------------- the harness side

    def call(self, uc, slot):
        """Runs import slot `slot` on the emulator's state. Returns the record for the replay; raises Skip."""
        name = self.names[slot] if slot < len(self.names) else f"slot {slot}"
        fn = self.handlers.get(name)
        if fn is None:
            self.end = (slot, uc.reg_read(UC_X86_REG_ESP), f"calls {name}, which the import model does not implement")
            raise Skip(self.end[2])
        c = Call(self, uc, slot, name)
        try:
            fn(c)
        except Skip as e:
            # Handlers make every check that can end the call before they change the model's state, and memory
            # writes wait for the end: the state is as it was when the call was made, for both sides to compare.
            self.end = (slot, c.esp, str(e))
            raise
        for kind, a, data in c.ops:
            if kind == OP_WRITE:
                uc.mem_write(a, data)
        uc.reg_write(UC_X86_REG_ESP, c.esp_out)
        uc.reg_write(UC_X86_REG_EIP, c.ret_to)
        for r, v in c.regs.items():
            uc.reg_write(r, v)
        self.records.append(c)
        return c

    def region_of(self, a, n=1):
        r = self.granules.get(a & ~(GRANULARITY - 1))
        return r if r is not None and r.contains(a, n) else None

    def reserved_page(self, page):
        """True if `page` is reserved by the model but not committed: an access there faults, as on Windows."""
        r = self.region_of(page)
        return r is not None and page not in r.committed

    def fault_in_arena(self, page, need):
        """Why an access needing `need` (a UC_PROT_* bit) to `page`, in a reservation, faults on Windows, or None
        if it does not. Pages outside reservations are not the model's (ordinary memory: None)."""
        r = self.region_of(page)
        if r is None:
            return None
        prot = r.committed.get(page)
        if prot is None:
            return "memory VirtualAlloc reserved but did not commit (faults on Windows)"
        if not prot & need:
            return f"a page committed without {PROT_NAMES[need]} access (faults on Windows)"
        return None

    def accessible(self, uc, addr, n, name, write=False):
        """The pages an import touches: committed model memory with the right protection, or ordinary memory
        (mapped on demand, as the harness does for the code under test). Otherwise Windows would fault."""
        if addr + n > 0xFFFFF000:
            raise Skip(f"{name} accesses {addr:08x}, in the top page of the 4 GiB space")
        need = UC_PROT_WRITE if write else UC_PROT_READ
        for page in range(page_down(addr), page_up(addr + n), PAGE):
            r = self.region_of(page)
            prot = r.committed.get(page) if r is not None else self.ensure(uc, page)
            if prot is None or not prot & need:
                raise Skip(f"{name} would fault at {addr:08x} (reserved, uncommitted or protected memory)")

    def pages(self):
        """Committed model pages at the end of the trial: both sides compare them."""
        return sorted(p for r in self.regions for p in r.committed)

    def serialize(self):
        """The records as tests/difftest_api.c reads them (little-endian u32s):
           count, then per call: slot, esp, register mask, eax, ecx, edx, esp_out, ret_to, number of ops, then per
           op: kind, address, length, and for reads and writes the bytes padded to 4; last, whether the run ended
           at an import it could not run (self.end), and that call's slot and esp."""
        out = [struct.pack("<I", len(self.records))]
        for c in self.records:
            regs = [c.regs.get(r, None) for r in (UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX)]
            mask = sum(1 << i for i, v in enumerate(regs) if v is not None)
            out.append(struct.pack("<9I", c.slot, c.esp, mask, *[v or 0 for v in regs], c.esp_out, c.ret_to,
                                   len(c.ops)))
            for kind, addr, data in c.ops:
                if kind == OP_ZERO:
                    out.append(struct.pack("<3I", kind, addr, data))
                else:
                    out.append(struct.pack("<3I", kind, addr, len(data)) + data + bytes(-len(data) % 4))
        out.append(struct.pack("<3I", 1, *self.end[:2]) if self.end else struct.pack("<3I", 0, 0, 0))
        return b"".join(out)

    # ---------------------------------------------------------------- address space

    def find_free(self, size, top_down):
        """Lowest (highest with MEM_TOP_DOWN) 64 KiB-aligned range of `size` bytes in the arena that is neither
        reserved nor given out as ordinary memory (where the code under test touched it). Starts and the span are
        whole granules, so a range is free exactly when its granules are: a run of zero bytes in self.busy."""
        span = (size + GRANULARITY - 1) & ~(GRANULARITY - 1)
        if span == 0:
            raise ModelError("find_free of 0 bytes (callers reject a zero size first)")
        run = bytes(span // GRANULARITY)
        k = self.busy.rfind(run) if top_down else self.busy.find(run)
        return None if k < 0 else VALLOC_LO + k * GRANULARITY

    def range_free(self, base, size):
        if base < VALLOC_LO or base + size > VALLOC_HI:
            return False
        if any(self.granules.get(g) is not None and self.granules[g].base < base + size
               and base < self.granules[g].base + self.granules[g].size
               for g in range(base & ~(GRANULARITY - 1), base + size, GRANULARITY)):
            return False
        return not any(p in self.ordinary for p in range(page_down(base), base + size, PAGE))

    def commit(self, c, region, lo, hi, prot):
        """Commits [lo, hi) (page-aligned) inside region; pages already committed keep their contents."""
        new = [p for p in range(lo, hi, PAGE) if p not in region.committed]
        if self.committed + len(new) * PAGE > COMMIT_LIMIT:
            return False
        for a, n in runs(new):   # zero, as Windows commits pages (the arena keeps what a decommit left)
            c.uc.mem_write(a, bytes(n))
        for p in new:
            region.committed[p] = prot
            c.fresh_page(p)
        for p in range(lo, hi, PAGE):
            region.committed[p] = prot
        self.committed += len(new) * PAGE
        return True

    def decommit(self, c, region, lo, hi):
        for p in [p for p in range(lo, hi, PAGE) if p in region.committed]:
            del region.committed[p]
            self.committed -= PAGE

    def reserve(self, c, base, size):
        r = Region(base, size)
        self.regions.append(r)
        self.occupy(r)
        return r

    def release(self, region):
        self.regions.remove(region)
        for g in range(region.base, region.base + region.size, GRANULARITY):
            del self.granules[g]
            self.busy[(g - VALLOC_LO) // GRANULARITY] = 1 if self.ordinary_in[g] else 0

    # ---------------------------------------------------------------- kernel32: thread and process

    def k32_GetLastError(self, c):
        c.ret(0, c.u32(self.tib + TEB_LAST_ERROR))

    def k32_SetLastError(self, c):
        code = c.arg(0)
        c.last_error(code)
        c.ret(1, 0)

    def k32_GetCurrentThreadId(self, c):
        c.ret(0, c.u32(self.tib + TEB_THREAD_ID))

    def k32_GetCurrentProcessId(self, c):
        c.ret(0, c.u32(self.tib + TEB_PROCESS_ID))

    def k32_GetCurrentThread(self, c):
        c.ret(0, PSEUDO_THREAD)

    def k32_GetCurrentProcess(self, c):
        c.ret(0, PSEUDO_PROCESS)

    def k32_IsDebuggerPresent(self, c):
        c.ret(0, 0)

    def k32_RtlUnwind(self, c):
        """Unwinds the SEH chain (fs:[0]) down to TargetFrame (NULL: all of it, an exit unwind), calling each frame's
        handler on the way, then continues at TargetIp (NULL: the return address) as if returning, with eax =
        ReturnValue. Calling the handlers is calling back into guest code, which the model does not do: only an
        unwind with no frame in between is modelled."""
        target, target_ip, record, value = c.arg(0), c.arg(1), c.arg(2), c.arg(3)
        end = 0xFFFFFFFF if target == 0 else target   # an exit unwind ends at the end of the chain
        frames, f = 0, c.u32(self.tib)
        while f != end and f != 0xFFFFFFFF:
            frames += 1
            f = c.u32(f)
        if f != end:
            raise Skip(f"RtlUnwind to frame {target:08x}, which is not on the SEH chain (raises "
                       "STATUS_INVALID_UNWIND_TARGET)")
        if frames:
            kind = "an exit unwind (target frame NULL)" if target == 0 else f"RtlUnwind to frame {target:08x}"
            raise Skip(f"{kind} through {frames} SEH frames, whose handlers run in it (calls into guest code: not "
                       "modelled)")
        c.ret(4, value, to=target_ip or None)

    def k32_SetUnhandledExceptionFilter(self, c):
        old, self.exception_filter = self.exception_filter, c.arg(0)
        c.ret(1, old)

    def k32_SetErrorMode(self, c):
        old, self.error_mode = self.error_mode, c.arg(0)
        c.ret(1, old)

    # ---------------------------------------------------------------- kernel32: synchronization

    def k32_InitializeCriticalSection(self, c):
        cs = c.arg(0)
        c.write(cs, bytes(24))                # host/kernel32.c: zeroed, LockCount -1
        c.w32(cs + 4, 0xFFFFFFFF)
        self.cs[cs] = 0
        c.ret(1, 0)

    def k32_DeleteCriticalSection(self, c):
        self.cs.pop(c.arg(0), None)
        c.ret(1, 0)

    def k32_EnterCriticalSection(self, c):
        cs = c.arg(0)
        self.cs[cs] = self.cs.get(cs, 0) + 1   # the only thread: never contended
        c.ret(1, 0)

    def k32_TryEnterCriticalSection(self, c):
        cs = c.arg(0)
        self.cs[cs] = self.cs.get(cs, 0) + 1
        c.ret(1, 1)

    def k32_LeaveCriticalSection(self, c):
        cs = c.arg(0)
        if self.cs.get(cs, 0) > 0:
            self.cs[cs] -= 1
        c.ret(1, 0)

    def k32_InterlockedIncrement(self, c):
        p = c.arg(0)
        v = (c.u32(p) + 1) & 0xFFFFFFFF
        c.w32(p, v)
        c.ret(1, v)

    def k32_InterlockedDecrement(self, c):
        p = c.arg(0)
        v = (c.u32(p) - 1) & 0xFFFFFFFF
        c.w32(p, v)
        c.ret(1, v)

    def k32_InterlockedExchange(self, c):
        p, v = c.arg(0), c.arg(1)
        old = c.u32(p)
        c.w32(p, v)
        c.ret(2, old)

    def k32_InterlockedExchangeAdd(self, c):
        p, v = c.arg(0), c.arg(1)
        old = c.u32(p)
        c.w32(p, old + v)
        c.ret(2, old)

    def k32_InterlockedCompareExchange(self, c):
        p, exchange, comparand = c.arg(0), c.arg(1), c.arg(2)
        old = c.u32(p)
        if old == comparand:
            c.w32(p, exchange)
        c.ret(3, old)

    # ---------------------------------------------------------------- kernel32: thread-local storage

    def k32_TlsAlloc(self, c):
        free = [i for i in range(TLS_MINIMUM_AVAILABLE) if i not in self.tls_used]
        if not free:
            raise Skip("TlsAlloc beyond the 64 TEB slots (expansion slots are not modelled)")
        c.w32(self.tib + TEB_TLS + 4 * free[0], 0)   # Windows zeroes a new slot in every thread
        self.tls_used.add(free[0])
        c.ret(0, free[0])

    def k32_TlsFree(self, c):
        i = c.arg(0)
        if i not in self.tls_used:
            c.last_error(ERROR_INVALID_PARAMETER)
            c.ret(1, 0)
            return
        c.w32(self.tib + TEB_TLS + 4 * i, 0)
        self.tls_used.discard(i)
        c.ret(1, 1)

    def k32_TlsGetValue(self, c):
        i = c.arg(0)
        if i < TLS_MINIMUM_AVAILABLE:
            v = c.u32(self.tib + TEB_TLS + 4 * i)
        elif i < TLS_MINIMUM_AVAILABLE + TLS_EXPANSION_SLOTS:
            slots = c.u32(self.tib + TEB_TLS_EXPANSION)
            v = c.u32(slots + 4 * (i - TLS_MINIMUM_AVAILABLE)) if slots else 0
        else:
            c.last_error(ERROR_INVALID_PARAMETER)
            c.ret(1, 0)
            return
        c.last_error(0)
        c.ret(1, v)

    def k32_TlsSetValue(self, c):
        i, v = c.arg(0), c.arg(1)
        if i < TLS_MINIMUM_AVAILABLE:
            c.w32(self.tib + TEB_TLS + 4 * i, v)
        elif i < TLS_MINIMUM_AVAILABLE + TLS_EXPANSION_SLOTS:
            slots = c.u32(self.tib + TEB_TLS_EXPANSION)
            if not slots:
                raise Skip("TlsSetValue to an expansion slot of a thread that has none (not modelled)")
            c.w32(slots + 4 * (i - TLS_MINIMUM_AVAILABLE), v)
        else:
            c.last_error(ERROR_INVALID_PARAMETER)
            c.ret(2, 0)
            return
        c.ret(2, 1)

    # ---------------------------------------------------------------- the clock (host/core.c guest_seconds)

    def seconds(self):
        self.vtime_us += 1
        return 60.0 + self.vtime_us * 1e-6

    def sleep(self, ms):
        self.vtime_us += ms * 1000 if ms else 1000   # host/kernel32.c det_sleep: Sleep(0) lets 1 ms pass

    def winmm_timeGetTime(self, c):
        c.ret(0, int(self.seconds() * 1000.0))

    def k32_GetTickCount(self, c):
        c.ret(0, int(self.seconds() * 1000.0))

    def k32_QueryPerformanceFrequency(self, c):
        p = c.arg(0)
        c.write(p, struct.pack("<Q", 1000000000))
        c.ret(1, 1)

    def k32_QueryPerformanceCounter(self, c):
        p = c.arg(0)
        self.accessible(c.uc, p, 8, c.name, write=True)   # before the clock moves (see call)
        c.write(p, struct.pack("<Q", int(self.seconds() * 1e9)))
        c.ret(1, 1)

    def k32_GetSystemTimeAsFileTime(self, c):
        p = c.arg(0)
        self.accessible(c.uc, p, 8, c.name, write=True)   # before the clock moves (see call)
        c.write(p, struct.pack("<Q", 127804032000000000 + int((self.seconds() - 60.0) * 1e7)))
        c.ret(1, 0)

    def k32_Sleep(self, c):
        self.sleep(c.arg(0))
        c.ret(1, 0)

    def k32_SleepEx(self, c):
        self.sleep(c.arg(0))
        c.ret(2, 0)   # no APCs are ever queued: an alertable sleep runs to its end

    # ---------------------------------------------------------------- kernel32: modules and the CPU

    def module_named(self, c, name):
        """A module by the name LoadLibrary/GetModuleHandle take: no extension means ".DLL", a trailing "." means
        none; compared without case. Returns its handle, or 0 if it is not loaded."""
        if b"\\" in name or b"/" in name:
            raise Skip(f"{c.name} of a path, {name!r} (not modelled)")
        base = name.upper().decode("latin-1")
        base = base[:-1] if base.endswith(".") else base if "." in base else base + ".DLL"
        if base == EXE_PATH.rsplit(b"\\", 1)[1].upper().decode():
            return self.image_base
        return self.modules.get(base, 0)

    def dll_of(self, handle):
        return next((dll for dll, h in self.modules.items() if h == handle), None)

    def k32_GetModuleHandleA(self, c):
        p = c.arg(0)
        if p == 0:
            c.ret(1, self.image_base)
            return
        h = self.module_named(c, c.cstr(p))
        if h == 0:
            c.last_error(ERROR_MOD_NOT_FOUND)
        c.ret(1, h)

    def k32_LoadLibraryA(self, c):
        name = c.cstr(c.arg(0))
        h = self.module_named(c, name)
        if h == 0:
            raise Skip(f"LoadLibraryA of {name!r}, which the exe does not import from (loading it is not modelled)")
        c.ret(1, h)

    def k32_FreeLibrary(self, c):
        h = c.arg(0)
        if h != self.image_base and self.dll_of(h) is None:
            raise Skip(f"FreeLibrary of {h:08x}, not a loaded module (undefined on Windows)")
        c.ret(1, 1)   # the exe's own imports stay loaded whatever their reference count

    def k32_GetProcAddress(self, c):
        module, p = c.arg(0), c.arg(1)
        if p < 0x10000:
            raise Skip(f"GetProcAddress by ordinal {p} (not modelled)")
        name = c.cstr(p).decode("latin-1")
        if module in (0, self.image_base):   # the exe exports nothing
            c.last_error(ERROR_PROC_NOT_FOUND)
            c.ret(2, 0)
            return
        dll = self.dll_of(module)
        if dll is None:
            c.last_error(ERROR_MOD_NOT_FOUND)
            c.ret(2, 0)
            return
        slot = self.slot_of.get(f"{dll}!{name}")
        if slot is None:
            c.last_error(ERROR_PROC_NOT_FOUND)
            c.ret(2, 0)
            return
        c.ret(2, IMPORT_BASE + SLOT * slot)

    def k32_GetModuleFileNameA(self, c):
        module, buf, n = c.arg(0), c.arg(1), c.arg(2)
        if module not in (0, self.image_base):
            if self.dll_of(module) is not None:
                raise Skip("GetModuleFileNameA of a DLL (its path is not modelled)")
            c.last_error(ERROR_MOD_NOT_FOUND)
            c.ret(3, 0)
            return
        # Windows XP: copies at most n characters, terminated only if there is room; the last error is untouched
        k = min(len(EXE_PATH), n)
        c.write(buf, EXE_PATH[:k] + (b"\0" if k < n else b""))
        c.ret(3, k)

    def k32_IsProcessorFeaturePresent(self, c):
        bit = PF_CPUID_BIT.get(c.arg(0))
        c.ret(1, 1 if bit is not None and CPUID_EDX >> bit & 1 else 0)

    # ---------------------------------------------------------------- kernel32: the process

    def process_string(self, c, key, data):
        """A string Windows keeps for the life of the process (as in the PEB), in a committed page of its own."""
        if key not in self.strings:
            span = page_up(len(data))
            base = self.find_free(span, False)
            if base is None:
                raise ModelError("no address space left for the process strings")
            self.commit(c, self.reserve(c, base, span), base, base + span, UC_PROT_READ | UC_PROT_WRITE)
            c.write(base, data)
            self.strings[key] = base
        return self.strings[key]

    def k32_GetCommandLineA(self, c):
        c.ret(0, self.process_string(c, "command line", COMMAND_LINE + b"\0"))

    def k32_GetEnvironmentStringsW(self, c):
        c.ret(0, self.process_string(c, "environment W", b"\0\0\0\0"))   # empty: the terminating NUL

    def k32_GetEnvironmentStrings(self, c):
        c.ret(0, self.process_string(c, "environment A", b"\0\0"))

    def k32_GetEnvironmentStringsA(self, c):
        self.k32_GetEnvironmentStrings(c)

    def k32_FreeEnvironmentStringsW(self, c):
        c.ret(1, 1)

    def k32_FreeEnvironmentStringsA(self, c):
        c.ret(1, 1)

    def k32_GetStartupInfoA(self, c):
        p = c.arg(0)
        c.write(p, struct.pack("<I", 68) + bytes(64))   # STARTUPINFOA: cb, and nothing set (dwFlags 0)
        c.ret(1, 0)

    def k32_GetVersionExA(self, c):
        p = c.arg(0)
        size = c.u32(p)
        if size not in (148, 156):   # OSVERSIONINFOA, OSVERSIONINFOEXA
            c.last_error(ERROR_INSUFFICIENT_BUFFER)
            c.ret(1, 0)
            return
        c.write(p + 4, struct.pack("<4I", *OS_VERSION))
        c.write(p + 20, OS_SERVICE_PACK + b"\0")
        if size == 156:   # wServicePackMajor/Minor, wSuiteMask (VER_SUITE_SINGLEUSERTS), VER_NT_WORKSTATION
            c.write(p + 148, struct.pack("<HHHBB", 2, 0, 0x100, 1, 0))
        c.ret(1, 1)

    def k32_GetVersion(self, c):
        major, minor, build, _ = OS_VERSION
        c.ret(0, build << 16 | minor << 8 | major)   # bit 31 clear: Windows NT

    def k32_GetStdHandle(self, c):
        h = STD_HANDLES.get(c.arg(0))
        if h is None:
            c.last_error(ERROR_INVALID_HANDLE)
            c.ret(1, INVALID_HANDLE_VALUE)
            return
        c.ret(1, h)

    def k32_GetFileType(self, c):
        h = c.arg(0)
        if h in STD_HANDLES.values():
            c.ret(1, FILE_TYPE_CHAR)
            return
        c.last_error(ERROR_INVALID_HANDLE)   # no files are open: any other value is not a handle
        c.ret(1, FILE_TYPE_UNKNOWN)

    def k32_SetHandleCount(self, c):
        c.ret(1, c.arg(0))   # Win32: no effect, returns its argument

    def k32_GetACP(self, c):
        c.ret(0, ANSI_CP)

    def k32_GetOEMCP(self, c):
        c.ret(0, OEM_CP)

    def codec(self, c, cp):
        cp = {CP_ACP: ANSI_CP, CP_OEMCP: OEM_CP}.get(cp, cp)
        if cp not in (ANSI_CP, OEM_CP):
            raise Skip(f"{c.name} with code page {cp} (not modelled)")
        return codecs.lookup("cp1252" if cp == ANSI_CP else "cp437")

    @staticmethod
    def decode_byte(codec, b):
        """One byte of a single-byte code page as Windows maps it: the five bytes cp1252 leaves undefined map to the
        control character of the same value."""
        try:
            return codec.decode(bytes([b]))[0]
        except UnicodeDecodeError:
            return chr(b)

    def k32_MultiByteToWideChar(self, c):
        cp, flags, src, n, dst, cap = (c.arg(i) for i in range(6))
        codec = self.codec(c, cp)
        if flags & ~0x1:   # MB_PRECOMPOSED only (the default for these code pages)
            raise Skip(f"MultiByteToWideChar with flags {flags:#x} (not modelled)")
        n = n - (1 << 32) if n & 0x80000000 else n
        if n == 0 or n < -1:
            c.last_error(ERROR_INVALID_PARAMETER)
            c.ret(6, 0)
            return
        data = c.cstr(src) + b"\0" if n == -1 else c.read(src, n)
        out = "".join(self.decode_byte(codec, b) for b in data).encode("utf-16-le")
        if cap == 0:
            c.ret(6, len(out) // 2)
            return
        if cap < len(out) // 2:
            c.write(dst, out[:2 * cap])   # Windows writes what fits before failing
            c.last_error(ERROR_INSUFFICIENT_BUFFER)
            c.ret(6, 0)
            return
        c.write(dst, out)
        c.ret(6, len(out) // 2)

    def k32_WideCharToMultiByte(self, c):
        cp, flags, src, n, dst, cap, default, used = (c.arg(i) for i in range(8))
        codec = self.codec(c, cp)
        if flags:
            raise Skip(f"WideCharToMultiByte with flags {flags:#x} (not modelled)")
        n = n - (1 << 32) if n & 0x80000000 else n
        if n == 0 or n < -1:
            c.last_error(ERROR_INVALID_PARAMETER)
            c.ret(8, 0)
            return
        if n == -1:
            units = []
            while True:
                u = struct.unpack("<H", c.read(src + 2 * len(units), 2))[0]
                units.append(u)
                if u == 0:
                    break
        else:
            units = list(struct.unpack(f"<{n}H", c.read(src, 2 * n)))
        fallback = c.read(default, 1) if default else b"?"
        out, defaulted = bytearray(), False
        for u in units:
            ch = chr(u)
            try:
                b = codec.encode(ch)[0] if 0xD800 > u or u > 0xDFFF else None
            except UnicodeEncodeError:
                b = None
            if b is None and u < 0x100 and self.decode_byte(codec, u) == ch:
                b = bytes([u])
            if b is None:
                b, defaulted = fallback, True
            out += b
        if used:
            c.w32(used, 1 if defaulted else 0)
        if cap == 0:
            c.ret(8, len(out))
            return
        if cap < len(out):
            c.write(dst, bytes(out[:cap]))
            c.last_error(ERROR_INSUFFICIENT_BUFFER)
            c.ret(8, 0)
            return
        c.write(dst, bytes(out))
        c.ret(8, len(out))

    def k32_IsValidCodePage(self, c):
        cp = c.arg(0)
        if cp not in (ANSI_CP, OEM_CP):
            raise Skip(f"IsValidCodePage({cp}): which other code pages are installed is not modelled")
        c.ret(1, 1)

    def k32_GetCPInfo(self, c):
        cp, p = c.arg(0), c.arg(1)
        self.codec(c, cp)
        c.write(p, struct.pack("<I", 1) + b"?\0" + bytes(12))   # CPINFO: single-byte, default char '?', no lead bytes
        c.ret(2, 1)

    @staticmethod
    def ctype1(ch):
        """CT_CTYPE1 of a character, from its Unicode general category (see the module docstring)."""
        cat = unicodedata.category(ch)
        if cat == "Cn":
            return 0
        t = C1_DEFINED
        if cat == "Lu":
            t |= C1_UPPER | C1_ALPHA
        elif cat == "Ll":
            t |= C1_LOWER | C1_ALPHA
        elif cat == "Lt":
            t |= C1_UPPER | C1_LOWER | C1_ALPHA
        elif cat in ("Lm", "Lo"):
            t |= C1_ALPHA
        elif cat == "Nd":
            t |= C1_DIGIT
        elif cat[0] in "PS":
            t |= C1_PUNCT
        elif cat == "Cc":
            t |= C1_CNTRL
        if ch in " \t\n\v\f\r" or cat in ("Zs", "Zl", "Zp"):
            t |= C1_SPACE
        if ch in " \t" or cat == "Zs":
            t |= C1_BLANK
        if ch in "0123456789abcdefABCDEF":
            t |= C1_XDIGIT
        return t

    @staticmethod
    def case_map(ch, flags):
        m = ch.upper() if flags & LCMAP_UPPERCASE else ch.lower()
        return m if len(m) == 1 else ch   # simple mappings only: one character to one

    def locale_codec(self, c, locale):
        if locale not in LOCALES:
            raise Skip(f"{c.name} for locale {locale:#x} (not modelled)")
        return self.codec(c, ANSI_CP)

    def wide(self, c, src, n):
        """n UTF-16 units at src; n == -1: up to and including the NUL."""
        if n != -1:
            return [chr(u) for u in struct.unpack(f"<{n}H", c.read(src, 2 * n))]
        out = []
        while True:
            u = struct.unpack("<H", c.read(src + 2 * len(out), 2))[0]
            out.append(chr(u))
            if u == 0:
                return out

    @staticmethod
    def signed(v):
        return v - (1 << 32) if v & 0x80000000 else v

    def k32_GetStringTypeW(self, c):
        info, src, n, out = c.arg(0), c.arg(1), self.signed(c.arg(2)), c.arg(3)
        if info != CT_CTYPE1:
            raise Skip(f"GetStringTypeW info type {info} (only CT_CTYPE1 is modelled)")
        if n == 0 or n < -1:
            c.last_error(ERROR_INVALID_PARAMETER)
            c.ret(4, 0)
            return
        chars = self.wide(c, src, n)
        c.write(out, struct.pack(f"<{len(chars)}H", *(self.ctype1(ch) for ch in chars)))
        c.ret(4, 1)

    def k32_GetStringTypeA(self, c):
        locale, info, src, n, out = c.arg(0), c.arg(1), c.arg(2), self.signed(c.arg(3)), c.arg(4)
        codec = self.locale_codec(c, locale)
        if info != CT_CTYPE1:
            raise Skip(f"GetStringTypeA info type {info} (only CT_CTYPE1 is modelled)")
        if n == 0 or n < -1:
            c.last_error(ERROR_INVALID_PARAMETER)
            c.ret(5, 0)
            return
        data = c.cstr(src) + b"\0" if n == -1 else c.read(src, n)
        c.write(out, struct.pack(f"<{len(data)}H", *(self.ctype1(self.decode_byte(codec, b)) for b in data)))
        c.ret(5, 1)

    def lcmap_flags(self, c, flags):
        if flags not in (LCMAP_LOWERCASE, LCMAP_UPPERCASE):
            raise Skip(f"{c.name} with flags {flags:#x} (only LCMAP_LOWERCASE/UPPERCASE are modelled)")

    def k32_LCMapStringW(self, c):
        locale, flags, src, n, dst, cap = (c.arg(i) for i in range(6))
        self.locale_codec(c, locale)
        self.lcmap_flags(c, flags)
        n = self.signed(n)
        if n == 0 or n < -1:
            c.last_error(ERROR_INVALID_PARAMETER)
            c.ret(6, 0)
            return
        out = [self.case_map(ch, flags) for ch in self.wide(c, src, n)]
        if cap == 0:
            c.ret(6, len(out))
            return
        if cap < len(out):
            c.last_error(ERROR_INSUFFICIENT_BUFFER)
            c.ret(6, 0)
            return
        c.write(dst, "".join(out).encode("utf-16-le"))
        c.ret(6, len(out))

    def k32_LCMapStringA(self, c):
        locale, flags, src, n, dst, cap = (c.arg(i) for i in range(6))
        codec = self.locale_codec(c, locale)
        self.lcmap_flags(c, flags)
        n = self.signed(n)
        if n == 0 or n < -1:
            c.last_error(ERROR_INVALID_PARAMETER)
            c.ret(6, 0)
            return
        data = c.cstr(src) + b"\0" if n == -1 else c.read(src, n)
        out = bytearray()
        for b in data:
            m = self.case_map(self.decode_byte(codec, b), flags)
            try:
                out += codec.encode(m)[0]
            except UnicodeEncodeError:
                out.append(b)   # no single-byte form: Windows keeps the character
        if cap == 0:
            c.ret(6, len(out))
            return
        if cap < len(out):
            c.last_error(ERROR_INSUFFICIENT_BUFFER)
            c.ret(6, 0)
            return
        c.write(dst, bytes(out))
        c.ret(6, len(out))

    def k32_MulDiv(self, c):
        a, b, d = (self.signed(c.arg(i)) for i in range(3))
        if d == 0:
            c.ret(3, 0xFFFFFFFF)
            return
        q, r = divmod(abs(a * b), abs(d))
        q += 2 * r >= abs(d)   # nearest, halves away from zero
        q = -q if (a * b < 0) != (d < 0) else q
        c.ret(3, q & 0xFFFFFFFF if -(1 << 31) <= q < 1 << 31 else 0xFFFFFFFF)

    # ---------------------------------------------------------------- kernel32: virtual memory

    def k32_VirtualAlloc(self, c):
        addr, size, kind, protect = c.arg(0), c.arg(1), c.arg(2), c.arg(3)
        prot = PROTECT.get(protect & ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE))
        if kind & ~(MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN):
            raise Skip(f"VirtualAlloc with allocation type {kind:#x} (not modelled)")
        if protect & PAGE_GUARD:
            raise Skip("VirtualAlloc with PAGE_GUARD (not modelled)")
        if size == 0 or prot is None or not kind & (MEM_COMMIT | MEM_RESERVE):
            c.last_error(ERROR_INVALID_PARAMETER)
            c.ret(4, 0)
            return
        if addr == 0 or kind & MEM_RESERVE:
            if addr:
                base = addr & ~(GRANULARITY - 1)
                span = page_up(addr + size) - base
                if not self.range_free(base, span):
                    c.last_error(ERROR_INVALID_ADDRESS)
                    c.ret(4, 0)
                    return
            else:
                span = page_up(size)
                base = self.find_free(span, bool(kind & MEM_TOP_DOWN))
                if base is None:
                    c.last_error(ERROR_NOT_ENOUGH_MEMORY)
                    c.ret(4, 0)
                    return
            if kind & MEM_COMMIT and self.committed + span > COMMIT_LIMIT:
                c.last_error(ERROR_COMMITMENT_LIMIT)
                c.ret(4, 0)
                return
            r = self.reserve(c, base, span)
            if kind & MEM_COMMIT:
                self.commit(c, r, base, base + span, prot)
            c.ret(4, base)
            return
        # MEM_COMMIT alone at an address: pages of one existing reservation
        lo, hi = page_down(addr), page_up(addr + size)
        r = self.region_of(lo, hi - lo)
        if r is None:
            c.last_error(ERROR_INVALID_ADDRESS)
            c.ret(4, 0)
            return
        if not self.commit(c, r, lo, hi, prot):
            c.last_error(ERROR_COMMITMENT_LIMIT)
            c.ret(4, 0)
            return
        c.ret(4, lo)

    def k32_VirtualFree(self, c):
        addr, size, kind = c.arg(0), c.arg(1), c.arg(2)
        if kind not in (MEM_DECOMMIT, MEM_RELEASE):
            c.last_error(ERROR_INVALID_PARAMETER)
            c.ret(3, 0)
            return
        r = self.region_of(addr)
        if r is not None and any(h.region is r for h in self.heaps.values()):
            raise Skip(f"VirtualFree of {addr:08x}, inside a heap (corrupts it on Windows)")
        if r is None:
            c.last_error(ERROR_INVALID_ADDRESS)
            c.ret(3, 0)
            return
        if kind == MEM_RELEASE:
            if size != 0:
                c.last_error(ERROR_INVALID_PARAMETER)
                c.ret(3, 0)
                return
            if addr != r.base:
                c.last_error(ERROR_INVALID_ADDRESS)
                c.ret(3, 0)
                return
            self.decommit(c, r, r.base, r.base + r.size)
            self.release(r)
            c.ret(3, 1)
            return
        lo, hi = (r.base, r.base + r.size) if size == 0 and addr == r.base else (page_down(addr), page_up(addr + size))
        if size == 0 and addr != r.base or not r.contains(lo, hi - lo):
            c.last_error(ERROR_INVALID_ADDRESS)
            c.ret(3, 0)
            return
        self.decommit(c, r, lo, hi)
        c.ret(3, 1)

    # ---------------------------------------------------------------- kernel32: heaps

    def new_heap(self, c, maximum):
        span = page_up(maximum) if maximum else HEAP_RESERVE
        base = self.find_free(span, False)
        if base is None:
            return 0
        h = Heap(self.reserve(c, base, span), fixed=maximum != 0)
        self.heaps[base] = h
        return base

    def heap(self, c, handle):
        h = self.heaps.get(handle)
        if h is None:
            raise Skip(f"{c.name} on handle {handle:08x}, which is not a heap (undefined on Windows; the game's "
                       "heaps exist once its startup code has run)")
        return h

    def alloc(self, c, h, size, zero):
        """A block of `size` bytes: 8-byte aligned, after an 8-byte gap where Windows keeps the block header.
        Blocks are never reused, so fresh memory is zero with or without HEAP_ZERO_MEMORY."""
        if h.fixed and size > HEAP_MAX_BLOCK_FIXED:
            return 0
        a = (h.next + HEAP_ALIGN + HEAP_ALIGN - 1) & ~(HEAP_ALIGN - 1)
        end = a + max(size, 1)
        if end > h.region.base + h.region.size:
            return 0
        if not self.commit(c, h.region, page_down(h.next), page_up(end), UC_PROT_READ | UC_PROT_WRITE):
            return 0
        h.next = end
        h.blocks[a] = size
        if zero:
            c.write(a, bytes(size))
        return a

    def k32_GetProcessHeap(self, c):
        if self.process_heap is None:
            self.process_heap = self.new_heap(c, 0)
        c.ret(0, self.process_heap)

    def k32_HeapCreate(self, c):
        options, initial, maximum = c.arg(0), c.arg(1), c.arg(2)
        if options & ~(HEAP_NO_SERIALIZE | HEAP_GENERATE_EXCEPTIONS | 0x40000):   # HEAP_CREATE_ENABLE_EXECUTE
            raise Skip(f"HeapCreate with options {options:#x} (not modelled)")
        if maximum and initial > maximum:
            c.last_error(ERROR_INVALID_PARAMETER)
            c.ret(3, 0)
            return
        handle = self.new_heap(c, maximum)
        if handle == 0:
            c.last_error(ERROR_NOT_ENOUGH_MEMORY)
        c.ret(3, handle)

    def k32_HeapDestroy(self, c):
        handle = c.arg(0)
        h = self.heap(c, handle)
        if handle == self.process_heap:
            raise Skip("HeapDestroy of the process heap (undefined on Windows)")
        self.decommit(c, h.region, h.region.base, h.region.base + h.region.size)
        self.release(h.region)
        del self.heaps[handle]
        c.ret(1, 1)

    def no_memory(self, c, flags):
        if flags & HEAP_GENERATE_EXCEPTIONS:
            raise Skip(f"{c.name} out of memory with HEAP_GENERATE_EXCEPTIONS: raises STATUS_NO_MEMORY (SEH)")

    def k32_HeapAlloc(self, c):
        handle, flags, size = c.arg(0), c.arg(1), c.arg(2)
        a = self.alloc(c, self.heap(c, handle), size, flags & HEAP_ZERO_MEMORY)
        if a == 0:
            self.no_memory(c, flags)   # HeapAlloc does not set the last error
        c.ret(3, a)

    def block(self, c, h, p):
        if p not in h.blocks:
            raise Skip(f"{c.name} of {p:08x}, which the heap did not allocate or already freed (undefined on Windows)")
        return h.blocks[p]

    def k32_HeapFree(self, c):
        handle, flags, p = c.arg(0), c.arg(1), c.arg(2)
        h = self.heap(c, handle)
        if p:
            self.block(c, h, p)
            del h.blocks[p]
        c.ret(3, 1)

    def k32_HeapSize(self, c):
        handle, flags, p = c.arg(0), c.arg(1), c.arg(2)
        c.ret(3, self.block(c, self.heap(c, handle), p))

    def k32_HeapReAlloc(self, c):
        handle, flags, p, size = c.arg(0), c.arg(1), c.arg(2), c.arg(3)
        h = self.heap(c, handle)
        old = self.block(c, h, p)
        if size <= old:   # shrinking stays in place
            h.blocks[p] = size
            c.ret(4, p)
            return
        if flags & HEAP_REALLOC_IN_PLACE_ONLY:
            c.ret(4, 0)   # the next block may follow directly: the model never grows in place
            return
        a = self.alloc(c, h, size, False)
        if a == 0:
            self.no_memory(c, flags)
            c.ret(4, 0)
            return
        c.write(a, c.read(p, old))
        if flags & HEAP_ZERO_MEMORY:
            c.write(a + old, bytes(size - old))
        del h.blocks[p]
        c.ret(4, a)
