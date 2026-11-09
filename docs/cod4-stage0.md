# COD4 Stage 0 report

Call of Duty 4: Modern Warfare single player (`iw3sp.exe`), Steam app 7940, depot build **2737681**.
No game files, game code or translated C are in this repository; everything below is counts, addresses and
decisions. Commands assume the game at `../game` and generated files in `work/` (ignored by git).

## Steps

| Step | Result |
|---|---|
| 1. Download | SteamCMD, build 2737681 |
| 2. Unwrap | SteamStub variant 2.0, removed with Steamless 3.1.0.5 (run under native mono). `tools/unwrap_check.py`: `.text` entropy 6.70, entry `0x64371b` inside `.text` and decodes to the MSVC CRT start (`call 0x64c7a5; jmp 0x64353b`), 269/269 imports by name with unbound IAT slots. **F0.1 pass** |
| 3. Imports | `work/imports.txt` (`tools/dll_inventory.py`). Fixed base `0x400000`, no relocations, not large-address-aware, SizeOfImage `0x1d03000`. No ADVAPI32 and no Winsock in SP. D9 below |
| 4. Ghidra export | `work/functions.json` |
| 5. Translate | 9,733 functions, 788,044 instructions, **0 unsupported instructions** (by mnemonic: none). 2,261 entries from pointers, 697 from gaps between functions, 41 from control flow, 184 candidates rejected as data with a reason each (`out_all/functions_translated.json`) |
| 6. Difftest | see below: fail 0 at both x87 control words. **F0.2 pass**; every skip and partial grouped with a route or reason, **F0.3 pass** |
| 7. CoD4x / iw3sp_mod | A10 below |

## Difftest (`tests/run_difftest.sh … --allow-calls`, 5 trials, seed 1)

| x87 control word | pass | partial | nan | fp_range | x87_ext | fail | skip |
|---|---|---|---|---|---|---|---|
| `0x027f` (53-bit, MSVC default) | 6,282 | 2,313 | 0 | 4 | 8 | **0** | 1,126 |
| `0x007f` (24-bit, what Direct3D sets without `D3DCREATE_FPU_PRESERVE`) | 6,283 | 2,313 | 0 | 4 | 7 | **0** | 1,126 |

All 9,733 translated functions have an outcome (9,427 run, 306 not selected, below). 678 of the passes ran
some trials and skipped others; the reason names them.

* **partial**: compared, and equal, up to where the emulator had to stop: an import the model does not run,
  or a `ret` that leaves the trial's frame (code reached by a jump, running in a caller's frame the trial does
  not have). Groups and routes in F0.3.
* **nan**: only NaN bit patterns differ. Non-blocking per the plan. None left: the 14 of the earlier run were
  emulator departures (below).
* **fp_range**: fails only for magnitudes beyond the double exponent range (moderate inputs pass). Non-blocking.
  Both runs: `0x478930 0x4840c0 0x51db50 0x57b9c0`.
* **x87_ext**: last-bit differences from 80-bit precision that the double register model drops: 80-bit
  constants (`fldpi`, `fld tword` π/2 in the CRT), and CRT maths that switches the FPU to 64-bit precision.
  Classified only when rerunning the emulator with its registers held at double precision reproduces the
  recompiled result on every failing trial. Decision (yours): keep doubles; measure in Stages 1/3 whether any
  game-visible value depends on these before paying for exact 80-bit maths.
  53-bit: `0x483920 0x483f20 0x4adb00 0x4e2cf0 0x4f9fc0 0x5b2b40 0x5d7cd0 0x5f99f0`;
  24-bit: `0x483920 0x483f20 0x4a3fa0 0x4adb00 0x4e2cf0 0x4f9fc0 0x5b2b40`.
* **fpu_flags**: retired. It covered QEMU's division flags, which the emulator now gets right (below).

### Start-up state and the import model

Trials no longer start from a bare image. Difftest first runs the CRT start-up under Unicorn, from the entry
`0x64371b` to WinMain `0x595a30` (found from its `push 0x400000; call` site): 522 import calls, 0.16 s. Every
trial starts from that snapshot (heap, TLS, locale tables, `_ioinit`, the SEH chain), with its stack 2 KiB below
start-up's, so CRT functions see an initialised CRT instead of recursing through `_getptd`.

Windows imports run in `tests/winmodel.py`, a deterministic model (thread and process ids, last error and TLS in
the TEB, critical sections, Interlocked*, a virtual clock as `host/core.c`'s, VirtualAlloc/Free with
reserve/commit, heaps, modules and GetProcAddress, environment and command line, code pages 1252/437 and
the locale functions; about 70 functions). The emulator side records every import call: the slot and stack
pointer, each byte it read (with its value), each byte it wrote, the registers and the return. The
recompiled side replays the record (`tests/difftest_api.c`): it checks it is the same call at the same stack
pointer reading the same bytes, then applies the writes. Any difference traps. `tests/winmodel_check.py`
checks the model against documented Windows behaviour and the replay against tampered records (275 checks).

When a trial reaches an import the model does not run (window, file and thread functions), both sides stop
at that call and all state is compared there: outcome **partial**. A `ret` that pops above the trial's
return address (code reached by a jump that runs in a caller's frame) stops both sides the same way.

### Translator bugs found and fixed in this stage

* Calls that return somewhere other than their return address (the CRT's x87 error paths, longjmp,
  `_CallMemberFunction`): `ret` records its target and each call site unwinds to the frame that owns it.
* 24-bit precision control clamped the exponent to float range (`(double)(float)v`) where the x87 keeps the
  full range: 26 fails at `0x007f` (as ∞−∞ = NaN where the hardware has finite values). Now rounds the
  significand only (`fpu_round24`, checked by `tests/fpu_round24_check.c`).
* Division flags: IE for ∞/∞, nothing for ∞/0 (was ZE). FYL2X special cases and IE/ZE per the SDM table.
  80-bit loads and stores keep NaN sign and payload.
* Switch table data taken for code: dword jump tables and byte index tables became "functions" (26), and the
  `.text` pointer scan read `.text` addresses out of instruction immediates and displacements (230 bogus
  entries, all checked: padding, tables, or labels inside a function that only that function branches to).
* Entry not at the function's lowest address, x86 NaN rules, float→int conversions, SSE2 doubles, x87 tags,
  fnsave/frstor, segment-register moves and other instruction gaps (see the git log).
* `build.sh` cached objects by their C file only, so changes to `runtime/*.h` inlines did not reach unchanged
  files: the cache key now includes the headers.
* AF was not modelled: `pushfd` (the CRT's `__report_gsfailure` saves EFLAGS) gave bit 4 clear (17 fails once
  difftest reached it). AF is now kept like the other flags: carry or borrow out of bit 3 after add, adc, sub,
  sbb, cmp, inc, dec, neg, xadd and cmpxchg; cleared where QEMU clears it. Where the SDM leaves a flag
  undefined (SHR/SHLD/SHRD OF beyond a count of 1, RCL/RCR OF, the flags after MUL/IMUL and BSF/BSR), the
  runtime now sets it as QEMU does, so a `pushfd` reads the same on both sides. `tests/flags_check.py` checks
  every helper in 8, 16 and 32 bits against Unicorn (153,000 cases), and difftest now compares CF PF AF ZF SF
  DF OF at the end of every trial.
* `setjmp`: a `longjmp` returns a second time from the `__setjmp3` call. The call's return address was not a
  resume point of the calling function, so the unwinding `ret` found no frame that owns it (trap). Calls to
  `setjmp`/`_setjmp3` (by Ghidra's function ID name) now make their return address a resume point.
* MSVC's alignment fillers before switch tables (`mov edi, edi`, `lea ecx, [ecx]`) were taken as functions
  (from the scan of gaps between functions), whose "code" then ran on into the table. Entries whose decoded
  instructions overlap a switch table's bytes are now rejected as data (41 more entries, all fillers or table
  bytes).
* Entries made from pointer-like values that point into the middle of real instructions (`PTR_0065766f` is the
  last byte of `and ax, 0x7f`) decoded garbage that ran into real code at an address no function starts at,
  where the recompiled code cannot follow (one fail). Compiled code never has overlapping instructions, so an
  entry whose decoded instructions overlap one of trusted code (Ghidra's functions and the entries they call or
  jump to) without being the same instruction is now rejected as data, and so is any entry reaching it (35
  entries, each checked by hand against the trusted instruction it straddles: all garbage).
* x87 stores to m32/m64 now quiet a signalling NaN on the bits (`fst_f32`, `fst_f64`) rather than relying
  on the host's float conversion, which WebAssembly does not pin down for NaNs.
* Host functions (`RET` in `host/win32.h`, the COM return) set the unwinding return target like `ret`, and
  `jmp [iat]` import thunks now go through the same import entry as calls.

### Emulator corrections (tests/x87ref.py, checked by tests/x87ref_check.py)

Unicorn 2.1's x87 and SSE are QEMU 5.0's. Where they depart from the hardware, difftest applies the SDM's
behaviour:

* Division sets ZE for every zero divisor and never IE.
* FYL2X skips the instruction unless x > 0.
* fnsave writes 0 in the reserved halves and the last instruction pointer.
* FSIN/FCOS/FSINCOS/FPTAN treat an infinity as out of range (C2) where it is invalid, drop a NaN's sign
  (FCOS) and push 1.0 above a NaN (FPTAN).
* FLD m32/m64 and FST(P) m32/m64 convert a signalling NaN without quieting it, and a store whose payload is
  lost gives the negative default NaN (SDM Vol. 1 §4.8.3.4).
* SSE arithmetic with two NaN operands takes the x87 rule (larger significand) where SSE returns the first
  operand, quieted (SDM Vol. 1 Table 4-7); measured wrong in about half of such lanes for every
  add/sub/mul/div ps/pd/sd form.

The last two caused all 14 former `nan` outcomes (each traced, the SSE one with xmm registers now in the
trace): the recompiled code already matched the hardware, and all 14 now pass. Not modelled by either side
(so not compared): DE/OE/UE/PE, C1, stack faults, unmasked exceptions, IE for invalid operations other than
division and FYL2X.

### Harness bugs found and fixed

* A function's outcome was its first non-pass trial, so a skip on an early trial hid a later failing one.
  Now every trial runs; any failing trial makes the function fail. This surfaced the switch-table bug above.
* A shard that crashed left the merged totals silently short; the merge now fails.
* Trials ran under a wall-clock limit too, so a loaded machine (or difftrace's hooks) changed outcomes. Runs
  are now bounded by instruction count only.
* The emulator corrections hooked each corrected instruction separately (93,584 sites once SNaN loads/stores
  and SSE arithmetic were added). Unicorn checks every code hook at every hooked instruction, and the
  instruction limit hooks all of them, so a trial ran ~10^5 checks per instruction and a full run did not
  finish in 2 hours. One hook over the sites' span now dispatches by
  address (one function that took over 10 minutes takes 17 s, same outcome).
* Ordinary memory was mapped on demand a page at a time, and Unicorn's `mem_map` slows with the number of
  regions faster than quadratically (measured: 1,000 single pages 0.26 s, 4,000 19 s, 8,000 180 s). A trial
  walking memory through a random pointer (a `rep movs` with a random count, an SSE copy loop) ran for hours
  once the wall-clock limit was gone: a full run had not finished after 19 hours. Ordinary pages are now
  mapped a 64 KiB allocation granule at a time (zeroed on both sides and compared, as before; one page at a
  time where the model has a reservation in the granule, and the top and sentinel pages only when touched),
  and the model maps its commits as runs of pages. Granules alone did not end it: a loop striding 64 KiB or
  more from a random pointer for a random count (`0x467040`) still maps a region per step. Memory reached so
  is now bounded by the model's `COMMIT_LIMIT` (64 MiB, the modelled machine's memory); beyond it the access
  faults and the trial is a skip saying so. The three functions that held up the run take 7-11 s.
  The model's own allocations had the same cost: the game's allocator (`0x53f000`-`0x541000`, a dozen
  functions) calls VirtualAlloc thousands of times in a trial, a reservation and a Unicorn region each, and
  `find_free` tried every 64 KiB start in the 2 GiB arena against every busy range (0.1 s a call). The arena is
  now mapped once, whole; the model keeps its page states (reserved, committed, protection) and a hook on the
  arena faults where Windows would; arena pages outside reservations are ordinary memory given out a page at
  a time, as before. Placement keeps a byte per 64 KiB granule of the arena, set where anything occupies
  it: starts and spans are whole granules, so a range is free exactly when its granules are, and the search
  is one `find` of a run of zero bytes (76,156 random layouts, with releases, checked against the old scan:
  the same answers). The allocator functions take 8-10 s (were 215-272 s with only the arena change). One behaviour changed: a data access at exactly the sentinel address now always faults
  (before, only while no other access had mapped its page).
* A trial that left its frame was stopped from the memory hook of the `ret`, inside the instruction. With
  any code hook installed (the instruction limit is one), Unicorn then restores its lazily computed flags
  wrongly: measured AF after `add`, CF and AF after `neg`, CF and OF after `shl` and `imul`. Two such trials
  failed on EFLAGS (AF) though the recompiled code was right. The `ret` is now sent to the sentinel and the
  run ends after it; the slot's bytes and the real target are put back (4,000 checks against plain runs,
  `ret` and `ret n`, with and without code hooks: equal).
* Any `ret` popping above the trial's return address counted as leaving the frame, including one that
  returns to a call the trial itself made after moving ESP up (entries in the middle of a function). The
  recompiled code returns there (its `ret_to` unwinds to that call), so two trials failed. A write hook now
  records the return addresses calls push above the trial's return address; a `ret` to one still active
  continues, as on the recompiled side.
* The SNaN load correction read the `fld` operand before the instruction, and a page not mapped yet made
  that read raise. The binding re-raises a hook's exception out of `emu_start`, where it read as the
  emulated code faulting: the trial became a skip. Hooks now read such memory as the zeroed page the
  instruction will get (`tests/uchooks.py` `bytes_or_zero`), and every hook is wrapped so a `UcError` in
  the harness's own code ends the run as a `HarnessError` instead of passing for a fault.
* Unicorn 2.1 starts with MXCSR 0 (exceptions unmasked), where a Windows thread and the processor after reset
  have 0x1F80; the recompiled side had 0x1F80. Code reading it back (`stmxcsr`, the CRT's SSE2 checks) saw the
  difference (one fail). Runs now start the emulator at 0x1F80.
* Unicorn mapped scratch memory executable, so a jump through a random pointer "ran" random bytes. Pages now
  have Windows' protections (image sections by their characteristics; stack, heap, TIB not executable).

## F0.3: skipped and partly compared functions (53-bit run; the 24-bit run has the same groups)

`tests/skip_report.py work/merged_0x027f.json` gives these groups. Each has a route that tests it another way, or a
reason the comparison cannot be made or does not matter. **F0.3 pass.**

**Skipped (1,126)**

| Count | Reason | Route or reason |
|---|---|---|
| 326 + 68 + 51 | Calls or jumps through a pointer from the random inputs into data: non-executable pages (326), unmapped memory (68), ordinary memory in the arena (51) | Reason: the target is a random value, so what runs there is not the game's code. The game's own indirect calls run in Stage 1's native run |
| 257 | 2M-instruction limit: loops bounded by random counts or following random pointers | Route: the same functions under game inputs in Stage 1; 678 other passes hit it on some trials only |
| 215 | Not selected: fewer than 3 instructions (thunks, `ret` stubs) | Route: executed through their callers (`--allow-calls`) |
| 60 | Not selected: `int3` (assert breakpoints) | Reason: an assert stops the game; callers test the code up to the breakpoint |
| 39 | CPU exception: divide error from a random divisor (`div`/`idiv`; one `int3`) | Reason: the divisor is a random input, and a divide error raises an exception on Windows too; SEH paths are Stage 1 |
| 29 | Access to memory VirtualAlloc reserved but did not commit | Reason: faults on Windows; random pointers into the model's reservations |
| 23 | Access to the top 4 KiB page | Reason: kernel space in a 32-bit process, cannot happen in the game |
| 17 | Not selected: MMX | Route: add MMX comparison to difftest together with MMX aliasing of the x87 registers (Open for Stage 1) |
| 11 | Data access at the sentinel return address | Reason: code reading its return address slot as a pointer, reached by a jump with a frame it does not have |
| 10 + 2 + 4 | `rdtsc` (not selected 10, reached by a call 2), `cpuid` (4) | Reason: nondeterministic or machine-dependent by design (cpuid: difftest and runtime.c give the same fixed answers, A7); Stage 1 runs them natively |
| 9 | Write to a read-only image section | Reason: faults on Windows; random pointers into `.rdata`/`.text` |
| 5 | More than 64 MiB of ordinary memory touched | Reason: a walk over memory from a random pointer; bounded by the modelled machine's memory |

**Partly compared (2,313)**: equal up to the stop.

| Count | Stop | Route or reason |
|---|---|---|
| 690 | `UnhandledExceptionFilter`, from the CRT's fatal paths (`__invoke_watson`, `_abort`, `___report_gsfailure`) | Reason: the process ends there; random inputs fail the CRT's parameter and cookie checks |
| 657 | `ChangeDisplaySettingsA`, the first call of the game's fatal-error routine (`0x576a40`: resets the display mode, then the error dialog) | Reason: the game is ending with an error; random inputs reach its error paths |
| 449 | An exit unwind whose SEH handlers run guest code | Route: SEH with handlers in guest code is Stage 1 (the runtime runs them; the model does not) |
| 200 | A `ret` leaving the trial's frame | Reason: code reached by a jump in the middle of a function; its callers test it with a real frame |
| 269 | Imports the model does not implement, 78 of them (`WaitForSingleObject` 51, `GetActiveWindow` 21, `RaiseException` 19, `CreateFileA` 18, `FindFirstFileA` 11, MSS32 audio, Bink, Direct3D, window calls) | Route: the host implementations in Stage 1, run against the real host layer rather than a model |
| 30 + 6 + 1 | Calls whose effect on Windows is undefined or an error the model does not raise: `HeapFree`/`HeapReAlloc`/`HeapSize` of a pointer the heap did not allocate (30), `RtlUnwind` to a frame not on the SEH chain (6), `InterlockedExchangeAdd` on uncommitted memory (1) | Reason: the pointers and frames are random inputs, and Windows' behaviour for them is undefined or an exception; the game's own calls run in Stage 1 |
| 11 | Code pages and flags the model does not cover (`MultiByteToWideChar` with random code pages or flags, `GetCPInfo`, `IsValidCodePage`) | Reason: random arguments (code pages such as 536892748 do not exist); Stage 1 logs the code pages the game passes |

## D9: the game's DLLs

| DLL | Exe uses | Decision | Why |
|---|---|---|---|
| d3d9 | `Direct3DCreate9` | Host: D3D9 on WebGPU (Stage 2) | as cricket's D3D8 |
| d3dx9_34 (base `0x400000`, collides with the exe, has relocations) | `D3DXGetShaderConstantTable`, `…Input/OutputSemantics`, `D3DXCreateBuffer` (from `0x5f3380`, `0x5f29a0`); `D3DXCompileShader` (only from `0x5f2be0`) | Host implementation of the four bytecode functions (parse the shader's CTAB/semantics). `D3DXCompileShader` traps | The compile path is the raw-asset loader (`materials/` → `techsets/%s.techset` → `techniques/%s.tech` → `shaders/%s`, `vs_3_0`/`ps_3_0`); retail ships only `zone/*.ff` and no shader sources. **Assumption to confirm in Stage 1**: log any call |
| mss32 7.0w (base `0x21100000`) + `miles/*.flt, *.asi` | 52 AIL functions | Translate, on cricket's DirectSound host | plugins load at run time via RIB; msseax and mssds3d share base `0x22300000` and need relocation |
| binkw32 1.8x (base `0x18000000`) | 18 Bink functions | Translate | no Bink decoder exists in browsers |
| DDRAW | `DirectDrawCreateEx`, `DirectDrawEnumerateExA` (`0x62aba0`–`0x62adf0`) | Host: small object answering `GetAvailableVidMem` | only used for "available video memory" |
| steam_api | none | — | the SP exe does not link it |
| PB (PunkBuster) | not imported by SP | — | MP only |

## A7 (cpuid)

Callers: `0x64c889` (CRT `__get_sse2_info`, SSE2 = bit 26), `0x593f20` (game SSE check: bit 25 plus an
`xorps` probe), `0x593d70` (vendor and brand string), `0x593f90` (family, logical CPU count). The CRT also
uses `IsProcessorFeaturePresent`. Stage 1 logs every cpuid leaf and answer.

## A10 (CoD4x / iw3sp_mod)

iw3sp_mod ships its own `iw3sp_mod.exe`: only 7 of the 53 function addresses it patches match Steam's
`iw3sp.exe`, so it does not apply to this build. CoD4x targets `iw3mp.exe` 1.7: relevant to Stage 5 only.

## Open for Stage 1

* Device creation flags: whether the game passes `D3DCREATE_FPU_PRESERVE` (decides 24- vs 53-bit x87).
* SSE arithmetic rounds per the host mode synced to the x87 rounding control, not MXCSR: log `fldcw` and
  `ldmxcsr` values to see whether they ever disagree.
* `D3DXCompileShader` reached or not; registry reads; cpuid answers.
* MMX registers are kept apart from the x87 registers in the runtime (not aliased onto the significands as on
  the hardware); difftest compares neither (17 MMX functions not selected).
* Host `GetModuleFileNameA` ignores `hModule`; host `IsProcessorFeaturePresent` returns 0 even for CX8 and
  RDTSC; the host environment block differs between the A and W forms.
