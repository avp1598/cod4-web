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
| 5. Translate | 9,808 functions, 790,511 instructions, **0 unsupported instructions** (by mnemonic: none). 2,261 entries from pointers, 697 from gaps between functions, 41 from control flow, 109 candidates rejected as data with a reason each (`out_all/functions_translated.json`) |
| 6. Difftest | see below. **F0.2 pass** |
| 7. CoD4x / iw3sp_mod | A10 below |

## Difftest (`tests/run_difftest.sh … --allow-calls`, 5 trials, seed 1)

| x87 control word | pass | nan | fp_range | x87_ext | fail | skip |
|---|---|---|---|---|---|---|
| `0x027f` (53-bit, MSVC default) | 5,165 | 11 | 4 | 8 | **0** | 4,620 |
| `0x007f` (24-bit, what Direct3D sets without `D3DCREATE_FPU_PRESERVE`) | 5,168 | 11 | 4 | 7 | **0** | 4,618 |

963 of the passes ran some trials and skipped others; the reason names them.

* **nan**: only NaN bit patterns differ. Non-blocking per the plan.
* **fp_range**: fails only for magnitudes beyond the double exponent range (moderate inputs pass). Non-blocking.
* **x87_ext**: last-bit differences from 80-bit precision that the double register model drops: 80-bit
  constants (`fldpi`, `fld tword` π/2 in the CRT), and CRT maths that switches the FPU to 64-bit precision.
  Classified only when rerunning the emulator with its registers held at double precision reproduces the
  recompiled result on every failing trial. Decision (yours): keep doubles; measure in Stages 1/3 whether any
  game-visible value depends on these before paying for exact 80-bit maths.
  53-bit: `0x483920 0x483f20 0x4adb00 0x4e2cf0 0x4f9fc0 0x5b2b40 0x5d7cd0 0x5f99f0`;
  24-bit: `0x483920 0x483f20 0x4a3fa0 0x4adb00 0x4e2cf0 0x4f9fc0 0x5b2b40`.
* **fpu_flags**: retired. It covered QEMU's division flags, which the emulator now gets right (below).

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

### Emulator corrections (tests/x87ref.py, checked by tests/x87ref_check.py)

Unicorn 2.1's x87 is QEMU 5.0's. Where it departs from the hardware, difftest applies the SDM's behaviour:
division sets ZE for every zero divisor and never IE; FYL2X skips the instruction unless x > 0; fnsave
writes 0 in the reserved halves and the last instruction pointer. Not modelled by either side (so not
compared): DE/OE/UE/PE, C1, stack faults, unmasked exceptions, IE for invalid operations other than
division and FYL2X.

### Harness bugs found and fixed

* A function's outcome was its first non-pass trial, so a skip on an early trial hid a later failing one.
  Now every trial runs; any failing trial makes the function fail. This surfaced the switch-table bug above.
* A shard that crashed left the merged totals silently short; the merge now fails.

## F0.3: skipped functions (53-bit run)

| Count | Reason | Route |
|---|---|---|
| 3,289 | Reaches a Windows import (Unicorn has no Windows): GetLastError 1,130, EnterCriticalSection 913, GetCurrentThreadId 271, InterlockedIncrement 196, GetModuleFileNameA 126, VirtualAlloc 113, SleepEx 103 …, 96 imports in all; the top 8 cover 87% | **Next**: a deterministic model of these imports used by both sides of difftest |
| 378 + 121 | Calls through a pointer from its random inputs (page 0, or arbitrary addresses) | Inputs whose pointers are the game's vtables/callbacks; otherwise covered by the Stage 1 run |
| 307 | 2M-instruction limit (loops bounded by random counts) | Moderate-input rerun / higher limit |
| 218 | Fewer than 3 instructions (thunks, `ret` stubs) | Executed through their callers with `--allow-calls` |
| 96 | CPU exception on random inputs (divide error and similar) | Reason: the game's inputs do not fault; SEH paths are Stage 1 |
| 94 | `int3` (assert breakpoints) | Reason: an assert stops the game; tested up to the breakpoint by callers |
| 40 | Unmapped read/write that the harness's on-demand mapping did not cover | To check one by one |
| 24 | Invalid instruction under Unicorn | To check one by one |
| 19 | Touches the top 4 KiB page (kernel space in a 32-bit process) | Reason: cannot happen in the game |
| 17 | MMX | Add MMX register comparison to difftest |
| 12 + 4 | `rdtsc` / `cpuid` (nondeterministic / machine-dependent) | Same values on both sides via hooks |

F0.3 is **not yet met**: the import model (the largest group) and the per-instruction checks in the table
are still to do.

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
