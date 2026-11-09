"""Hooks the harness adds to Unicorn, guarded so a failure of the harness's own code cannot pass for the emulated
code faulting.

The binding re-raises an exception from a hook out of emu_start. A UcError there (a hook's own mem_read of a page
not mapped yet, say) would read as the emulator stopping on a fault, and the trial would become a skip. Every hook
is added through guarded(), which turns it into a HarnessError: the run ends with the harness bug in plain sight.
"""
from unicorn import UC_ERR_READ_UNMAPPED, UcError


def bytes_or_zero(uc, addr, n):
    """The n bytes at addr as an instruction about to run will see them, read by a hook before it runs: a page not
    mapped yet reads as zero. The instruction's own access maps such a page on demand, zeroed (tests/difftest.py
    map_ordinary), or faults and ends the trial (so what the hook decides there does not matter); and bytes past
    the end of mapped code cannot be part of an instruction being executed (decoding 15 bytes at EIP)."""
    try:
        return bytes(uc.mem_read(addr, n))
    except UcError as e:
        if e.errno != UC_ERR_READ_UNMAPPED:
            raise
    out = bytearray(n)
    for k in range(n):
        try:
            out[k] = uc.mem_read((addr + k) & 0xFFFFFFFF, 1)[0]
        except UcError as e:
            if e.errno != UC_ERR_READ_UNMAPPED:
                raise
    return bytes(out)


class HarnessError(Exception):
    """A failure of the harness's own code inside a hook, as opposed to the code under test faulting."""


def guarded(callback):
    def hook(*args):
        try:
            return callback(*args)
        except UcError as e:
            raise HarnessError(f"hook {callback.__name__}: {e}") from e
    return hook
