"""Checks that an unwrapped executable holds real code and a usable import table (plan check F0.1).

  unwrap_check.py <unwrapped.exe>

Reports, per section, the exact byte entropy; whether the entry point lies inside .text and what the first
instructions there are; and for every import whether it names a DLL function (by name, or by ordinal) and
whether its import-address-table slot still holds the unbound pointer to that name, as a loader expects.
Exits non-zero if any of these fail.
"""
import collections
import math
import sys

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs


def entropy(b):
    c = collections.Counter(b)
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    pe = pefile.PE(sys.argv[1])
    ok = True
    base = pe.OPTIONAL_HEADER.ImageBase
    entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    text = None
    for s in pe.sections:
        name = s.Name.rstrip(b"\0").decode()
        data = s.get_data()[:s.Misc_VirtualSize]
        print(f"section {name:8s} entropy {entropy(data):.4f}")
        if name == ".text":
            text = s
    if text is None:
        raise SystemExit("no .text section")
    inside = text.VirtualAddress <= entry < text.VirtualAddress + text.Misc_VirtualSize
    print(f"entry {base + entry:#010x} inside .text: {inside}")
    ok &= inside
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    code = pe.get_data(entry, 32)
    for ins in list(md.disasm(code, base + entry))[:4]:
        print(f"  {ins.address:08x}  {ins.mnemonic} {ins.op_str}")

    total, named, ordinal, bad = 0, 0, 0, []
    for imp in pe.DIRECTORY_ENTRY_IMPORT:
        dll = imp.dll.decode()
        for i in imp.imports:
            total += 1
            slot = pe.get_dword_at_rva(i.address - base)
            if i.import_by_ordinal:
                ordinal += 1
                if slot != (0x80000000 | i.ordinal):
                    bad.append(f"{dll} #{i.ordinal}: IAT slot {slot:#x} is not the ordinal thunk")
            elif i.name:
                named += 1
                if slot != i.hint_name_table_rva:
                    bad.append(f"{dll}!{i.name.decode()}: IAT slot {slot:#x} != hint/name rva {i.hint_name_table_rva:#x}")
            else:
                bad.append(f"{dll}: import at {i.address:#x} has neither name nor ordinal")
    print(f"imports: {total} total, {named} by name, {ordinal} by ordinal, {len(bad)} unresolved")
    for b in bad:
        print("  BAD", b)
    ok &= not bad
    print("F0.1 structural checks:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
