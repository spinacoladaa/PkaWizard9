"""
find_export.py - Parse a PE export table (from disk) and print exports whose
(decorated) name contains a given substring, with their RVA.

Usage: python find_export.py <dll_path> <name_substring>
Example: python find_export.py "C:\\Program Files\\Cisco Packet Tracer 9.0.0\\bin\\Qt6Core.dll" qUncompress
"""
import sys
import struct


def u16(b, o): return struct.unpack_from("<H", b, o)[0]
def u32(b, o): return struct.unpack_from("<I", b, o)[0]


def parse_exports(path):
    with open(path, "rb") as f:
        data = f.read()

    if data[:2] != b"MZ":
        raise ValueError("not a PE (no MZ)")
    pe = u32(data, 0x3C)
    if data[pe:pe+4] != b"PE\0\0":
        raise ValueError("not a PE (no PE sig)")

    coff = pe + 4
    machine = u16(data, coff)
    num_sections = u16(data, coff + 2)
    opt = coff + 20
    magic = u16(data, opt)
    is64 = magic == 0x20B
    # Data directories start at offset 96 (PE32) / 112 (PE32+) within optional header
    dd_off = opt + (112 if is64 else 96)
    export_rva = u32(data, dd_off + 0 * 8)
    export_size = u32(data, dd_off + 0 * 8 + 4)

    # Build section table for RVA->file-offset mapping
    sec_off = opt + u16(data, coff + 16)  # SizeOfOptionalHeader
    sections = []
    for i in range(num_sections):
        s = sec_off + i * 40
        name = data[s:s+8].rstrip(b"\0").decode(errors="ignore")
        vsize = u32(data, s + 8)
        vaddr = u32(data, s + 12)
        rawsize = u32(data, s + 16)
        rawptr = u32(data, s + 20)
        sections.append((name, vaddr, vsize, rawptr, rawsize))

    def rva2off(rva):
        for name, vaddr, vsize, rawptr, rawsize in sections:
            if vaddr <= rva < vaddr + max(vsize, rawsize):
                return rawptr + (rva - vaddr)
        return None

    eo = rva2off(export_rva)
    if eo is None:
        raise ValueError("cannot map export directory")

    num_funcs = u32(data, eo + 0x14)
    num_names = u32(data, eo + 0x18)
    addr_funcs = u32(data, eo + 0x1C)
    addr_names = u32(data, eo + 0x20)
    addr_ords = u32(data, eo + 0x24)

    of_funcs = rva2off(addr_funcs)
    of_names = rva2off(addr_names)
    of_ords = rva2off(addr_ords)

    results = []
    for i in range(num_names):
        name_rva = u32(data, of_names + i * 4)
        name_off = rva2off(name_rva)
        end = data.index(b"\0", name_off)
        name = data[name_off:end].decode(errors="ignore")
        ordinal = u16(data, of_ords + i * 2)
        func_rva = u32(data, of_funcs + ordinal * 4)
        results.append((name, func_rva, ordinal))
    return machine, is64, results


def main():
    path = sys.argv[1]
    needle = sys.argv[2] if len(sys.argv) > 2 else ""
    machine, is64, results = parse_exports(path)
    print(f"{path}")
    print(f"machine=0x{machine:04X} 64-bit={is64} total_named_exports={len(results)}")
    hits = [r for r in results if needle.lower() in r[0].lower()]
    print(f"--- {len(hits)} export(s) matching '{needle}' ---")
    for name, rva, ordinal in hits:
        print(f"  RVA 0x{rva:08X}  ord {ordinal:5d}  {name}")


if __name__ == "__main__":
    main()
