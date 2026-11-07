"""Inventory of an executable's imports and of every PE module shipped in the game folder.

  dll_inventory.py <unwrapped.exe> <game folder>

Prints the executable's imports grouped by DLL, then every file in the game folder that is a PE image
(whatever its extension: Miles plugins are .asi/.flt/.m3d), with its machine, preferred base, size,
relocations, imports (by name or ordinal) and exports. Also lists the DLL names each module mentions in its
strings, since modules loaded with LoadLibrary at run time never appear in an import table.
"""
import os
import re
import sys

import pefile

DLL_NAME = re.compile(rb"[A-Za-z0-9_.\-]{2,40}\.(?:dll|asi|flt|m3d|drv)\b", re.I)


def imports_of(pe):
    out = []
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return out
    for imp in pe.DIRECTORY_ENTRY_IMPORT:
        names = sorted((i.name.decode() if i.name else f"#{i.ordinal}") for i in imp.imports)
        out.append((imp.dll.decode(), names))
    return out


def exports_of(pe):
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return []
    out = []
    for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        name = e.name.decode() if e.name else ""
        fwd = f" -> {e.forwarder.decode()}" if e.forwarder else ""
        out.append(f"#{e.ordinal} {name}{fwd}")
    return out


def strings_dlls(data, own_imports):
    seen = {m.group().decode().lower() for m in DLL_NAME.finditer(data)}
    wide = re.finditer(rb"(?:[A-Za-z0-9_.\-]\x00){2,40}\.\x00(?:[dDaAfFmM]\x00)(?:[A-Za-z0-9]\x00){2}", data)
    seen |= {m.group().decode("utf-16le").lower() for m in wide}
    return sorted(seen - {d.lower() for d in own_imports})


def describe(path, rel):
    data = open(path, "rb").read()
    pe = pefile.PE(data=data)
    oh, fh = pe.OPTIONAL_HEADER, pe.FILE_HEADER
    imps = imports_of(pe)
    exps = exports_of(pe)
    print(f"\n## {rel}")
    print(f"machine {fh.Machine:#x}  base {oh.ImageBase:#010x}  size {oh.SizeOfImage:#x}  "
          f"relocs {hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC')}  dll {bool(fh.Characteristics & 0x2000)}")
    for dll, names in imps:
        print(f"  import {dll} ({len(names)}): {', '.join(names)}")
    if exps:
        print(f"  exports ({len(exps)}): {', '.join(exps)}")
    extra = strings_dlls(data, [d for d, _ in imps])
    if extra:
        print(f"  dll names in strings (possible run-time loads): {', '.join(extra)}")


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    exe, folder = sys.argv[1], sys.argv[2]
    pe = pefile.PE(exe)
    print(f"# {os.path.basename(exe)} imports")
    for dll, names in imports_of(pe):
        print(f"\n{dll} ({len(names)})")
        for n in names:
            print(f"  {n}")
    print("\n# PE modules in the game folder")
    for root, dirs, files in os.walk(folder):
        dirs.sort()
        for f in sorted(files):
            p = os.path.join(root, f)
            with open(p, "rb") as fh:
                head = fh.read(0x400)
            if head[:2] != b"MZ":
                continue
            off = int.from_bytes(head[0x3c:0x40], "little")
            with open(p, "rb") as fh:
                fh.seek(off)
                if fh.read(4) != b"PE\0\0":
                    continue
            describe(p, os.path.relpath(p, folder))


if __name__ == "__main__":
    main()
