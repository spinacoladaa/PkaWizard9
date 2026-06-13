"""
qunc_dump.py - Dump de volledig ontsleutelde Activity-XML uit een draaiende PT9,
door een breakpoint op Qt6Core.dll::qUncompress te zetten.

qUncompress-export (Qt6Core.dll): ?qUncompress@@YA?AVQByteArray@@PEBE_J@Z
  signatuur: QByteArray qUncompress(const uchar* data, qsizetype nbytes)
  x64 entry: RDX = data-ptr ([4-byte BE size][78 9C zlib...]),  R8 = nbytes

ferib's stage 4 IS exact dit qUncompress-formaat. De INPUT-buffer (RDX, R8 bytes) is
dus precies de stage-3-output van de v9-unpack-pipeline. We:
  1. lezen die input-buffer,
  2. zlib-inflaten 'm zelf (= de platte XML) en filteren op de Activity,
  3. bewaren BEIDE: qunc_input.bin (ijkpunt voor de offline-decryptor) en activity.xml.

Geen admin nodig (zelfde gebruiker). Veilig: DebugSetProcessKillOnExit(false),
herstelt de gepatchte byte in finally, detacht (PT draait door).

Gebruik:
  python qunc_dump.py --probe          # read-only: attach, resolveer adres, lees byte
  python qunc_dump.py                  # arm BP en wacht; open daarna een .pka in PT
  python qunc_dump.py --budget 180     # langere wachttijd (s)
"""
import sys
import os
import time
import zlib
import struct
import argparse
import ctypes
from ctypes import wintypes
import pymem
import pymem.process

PROC = "PacketTracer.exe"
QT6CORE = "Qt6Core.dll"
OUT_DIR = os.path.dirname(os.path.abspath(__file__))


def _find_pt_exe():
    """Vind PacketTracer.exe portabel: env PT_EXE > geinstalleerde versies > default."""
    import glob
    env = os.environ.get("PT_EXE")
    if env and os.path.exists(env):
        return env
    cands = []
    for base in (os.environ.get("ProgramFiles", r"C:\Program Files"),
                 os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")):
        cands += sorted(glob.glob(os.path.join(base, "Cisco Packet Tracer*", "bin", "PacketTracer.exe")),
                        reverse=True)
    cands.append(r"C:\Program Files\Cisco Packet Tracer 9.0.0\bin\PacketTracer.exe")
    for c in cands:
        if os.path.exists(c):
            return c
    return cands[-1]


PT_EXE = _find_pt_exe()


def _resolve_quncompress_rva():
    """Bepaal de qUncompress-RVA uit Qt6Core.dll-exports (build-onafhankelijk); fallback constant."""
    try:
        try:
            from .find_export import parse_exports   # gepakketteerd (distro)
        except Exception:
            from find_export import parse_exports    # plat (src/)
        qt = os.path.join(os.path.dirname(PT_EXE), QT6CORE)
        _, _, res = parse_exports(qt)
        for name, rva, _o in res:
            if "qUncompress" in name:
                return rva
    except Exception:
        pass
    return 0x0013D8B0


QUNCOMPRESS_RVA = _resolve_quncompress_rva()
# Strikte hallmark van het activity-bestand (root = PACKETTRACER5_ACTIVITY), ASCII en UTF-16LE.
# (device-library-templates hebben root <PACKETTRACER>, dus die filteren we hiermee weg.)
MARKERS = (b"PACKETTRACER5_ACTIVITY", "PACKETTRACER5_ACTIVITY".encode("utf-16-le"))
DEBUG_ONLY_THIS_PROCESS = 0x00000002

k32 = ctypes.windll.kernel32
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001
EXCEPTION_DEBUG_EVENT = 1
EXIT_PROCESS_DEBUG_EVENT = 5
EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_SINGLE_STEP = 0x80000004
CONTEXT_AMD64 = 0x100000
CONTEXT_CR = CONTEXT_AMD64 | 0x1 | 0x2  # CONTROL | INTEGER
THREAD_ALL = 0x1FFFFF
TRAP_FLAG = 0x100


class EXCEPTION_RECORD(ctypes.Structure):
    _fields_ = [("ExceptionCode", wintypes.DWORD), ("ExceptionFlags", wintypes.DWORD),
                ("ExceptionRecord", ctypes.c_void_p), ("ExceptionAddress", ctypes.c_void_p),
                ("NumberParameters", wintypes.DWORD),
                ("ExceptionInformation", ctypes.c_ulonglong * 15)]


class EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("ExceptionRecord", EXCEPTION_RECORD), ("dwFirstChance", wintypes.DWORD)]


class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [("dwDebugEventCode", wintypes.DWORD), ("dwProcessId", wintypes.DWORD),
                ("dwThreadId", wintypes.DWORD), ("u", EXCEPTION_DEBUG_INFO)]


class CONTEXT(ctypes.Structure):
    _fields_ = [(f, ctypes.c_ulonglong) for f in
                ("P1Home", "P2Home", "P3Home", "P4Home", "P5Home", "P6Home")] + [
        ("ContextFlags", ctypes.c_ulong), ("MxCsr", ctypes.c_ulong),
        ("SegCs", ctypes.c_ushort), ("SegDs", ctypes.c_ushort), ("SegEs", ctypes.c_ushort),
        ("SegFs", ctypes.c_ushort), ("SegGs", ctypes.c_ushort), ("SegSs", ctypes.c_ushort),
        ("EFlags", ctypes.c_ulong)] + [(f, ctypes.c_ulonglong) for f in
        ("Dr0", "Dr1", "Dr2", "Dr3", "Dr6", "Dr7",
         "Rax", "Rcx", "Rdx", "Rbx", "Rsp", "Rbp", "Rsi", "Rdi",
         "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "Rip")] + [
        ("FltSave", ctypes.c_byte * 512), ("VectorRegister", ctypes.c_byte * 416),
        ("VectorControl", ctypes.c_ulonglong), ("DebugControl", ctypes.c_ulonglong),
        ("LastBranchToRip", ctypes.c_ulonglong), ("LastBranchFromRip", ctypes.c_ulonglong),
        ("LastExceptionToRip", ctypes.c_ulonglong), ("LastExceptionFromRip", ctypes.c_ulonglong)]


k32.OpenThread.restype = ctypes.c_void_p
k32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.GetThreadContext.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
k32.SetThreadContext.argtypes = [ctypes.c_void_p, ctypes.c_void_p]


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
                ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
                ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
                ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
                ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
                ("lpReserved2", ctypes.c_void_p), ("hStdInput", ctypes.c_void_p),
                ("hStdOutput", ctypes.c_void_p), ("hStdError", ctypes.c_void_p)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", ctypes.c_void_p), ("hThread", ctypes.c_void_p),
                ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]


k32.CreateProcessW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p,
                               ctypes.c_void_p, wintypes.BOOL, wintypes.DWORD,
                               ctypes.c_void_p, wintypes.LPCWSTR,
                               ctypes.c_void_p, ctypes.c_void_p]


def aligned_context():
    buf = (ctypes.c_byte * (ctypes.sizeof(CONTEXT) + 16))()
    addr = (ctypes.addressof(buf) + 15) & ~15
    return ctypes.cast(addr, ctypes.POINTER(CONTEXT)).contents, buf


def ws(pid):
    h = k32.OpenProcess(0x0400 | 0x0010, False, pid)
    if not h:
        return 0

    class PMC(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("pf", wintypes.DWORD)] + \
                   [(c, ctypes.c_size_t) for c in "abcdefgh"]
    c = PMC(); c.cb = ctypes.sizeof(c)
    ctypes.windll.psapi.GetProcessMemoryInfo(h, ctypes.byref(c), c.cb)
    k32.CloseHandle(h)
    return c.b


def attach():
    pids = [pe.th32ProcessID for pe in pymem.process.list_processes()
            if pe.szExeFile.decode(errors="ignore").lower() == PROC.lower()]
    if not pids:
        print("ERROR: PacketTracer is not running."); sys.exit(1)
    pid = max(pids, key=ws)
    pm = pymem.Pymem(); pm.open_process_from_id(pid)
    qbase = pymem.process.module_from_name(pm.process_handle, QT6CORE).lpBaseOfDll
    addr = qbase + QUNCOMPRESS_RVA
    print(f"Engine-PID {pid}, {QT6CORE} base 0x{qbase:016X}, qUncompress @ 0x{addr:016X}")
    return pm, pid, addr


def try_inflate(buf):
    """Probeer de qUncompress-input te inflaten. Geeft (xml, zlib_offset) of (None, -1)."""
    for off in (4, 0):  # ferib: 4-byte BE size + zlib; fallback: pure zlib
        if len(buf) > off + 2 and buf[off] == 0x78:
            try:
                return zlib.decompress(bytes(buf[off:])), off
            except zlib.error:
                # partiële stream? probeer decompressobj
                try:
                    d = zlib.decompressobj()
                    out = d.decompress(bytes(buf[off:]))
                    if out:
                        return out, off
                except zlib.error:
                    pass
    return None, -1


def probe():
    pm, pid, addr = attach()
    b = pm.read_bytes(addr, 16)
    print(f"qUncompress first 16 bytes: {b.hex(' ')}")
    print("OK: attach + address resolution work." if b[0] != 0xCC
          else "NOTE: byte is 0xCC (breakpoint already set?).")


def capture(budget):
    pm, pid, addr = attach()
    orig = pm.read_bytes(addr, 1)
    if orig == b"\xCC":
        print("ERROR: byte is already 0xCC; is a debugger already attached?"); return

    if not k32.DebugActiveProcess(pid):
        print(f"DebugActiveProcess failed (err {k32.GetLastError()})."); return
    k32.DebugSetProcessKillOnExit(False)
    armed = False
    found = False
    pending_rearm = None
    hits = 0
    try:
        pm.write_bytes(addr, b"\xCC", 1); armed = True
        print(f"BP armed on qUncompress. Open a .pka in Packet Tracer NOW "
              f"(budget {budget}s)...", flush=True)
        evt = DEBUG_EVENT()
        t0 = time.time()
        first_bp = True
        while time.time() - t0 < budget and not found:
            if not k32.WaitForDebugEvent(ctypes.byref(evt), 1000):
                continue
            code = evt.dwDebugEventCode
            status = DBG_CONTINUE
            if code == EXCEPTION_DEBUG_EVENT:
                er = evt.u.ExceptionRecord
                exc = er.ExceptionCode
                exa = er.ExceptionAddress or 0
                if exc == EXCEPTION_BREAKPOINT and exa == addr and armed:
                    hits += 1
                    th = k32.OpenThread(THREAD_ALL, False, evt.dwThreadId)
                    ctx, _buf = aligned_context()
                    ctx.ContextFlags = CONTEXT_CR
                    if k32.GetThreadContext(th, ctypes.byref(ctx)):
                        data_ptr = ctx.Rdx
                        nbytes = ctx.R8 & 0xFFFFFFFFFFFF
                        tag = ""
                        if 0 < nbytes <= 64 * 1024 * 1024 and data_ptr:
                            try:
                                buf = pm.read_bytes(data_ptr, int(nbytes))
                            except Exception:
                                buf = b""
                            xml, off = try_inflate(buf)
                            if xml and any(m in xml for m in MARKERS):
                                with open(os.path.join(OUT_DIR, "qunc_input.bin"), "wb") as f:
                                    f.write(buf)
                                with open(os.path.join(OUT_DIR, "activity.xml"), "wb") as f:
                                    f.write(xml)
                                print(f"  [hit {hits}] nbytes={nbytes} zlib@+{off}  "
                                      f"-> XML {len(xml)} bytes  *** ACTIVITY FOUND ***",
                                      flush=True)
                                print(f"  -> {os.path.join(OUT_DIR, 'qunc_input.bin')}")
                                print(f"  -> {os.path.join(OUT_DIR, 'activity.xml')}")
                                found = True
                            else:
                                tag = f"xml={len(xml) if xml else 0} (no activity marker)"
                        else:
                            tag = f"nbytes={nbytes} (skipped)"
                        if not found:
                            print(f"  [hit {hits}] {tag}", flush=True)
                        # re-arm via single-step: herstel byte, RIP terug, TF aan
                        pm.write_bytes(addr, orig, 1); armed = False
                        ctx.Rip = addr
                        ctx.EFlags |= TRAP_FLAG
                        ctx.ContextFlags = CONTEXT_CR
                        k32.SetThreadContext(th, ctypes.byref(ctx))
                        pending_rearm = addr
                    k32.CloseHandle(th)
                    k32.ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, DBG_CONTINUE)
                    continue
                elif exc == EXCEPTION_SINGLE_STEP and pending_rearm is not None:
                    pm.write_bytes(pending_rearm, b"\xCC", 1); armed = True
                    pending_rearm = None
                    k32.ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, DBG_CONTINUE)
                    continue
                elif exc == EXCEPTION_BREAKPOINT and first_bp:
                    first_bp = False
                else:
                    status = DBG_EXCEPTION_NOT_HANDLED
            elif code == EXIT_PROCESS_DEBUG_EVENT:
                print("PT process exited."); break
            k32.ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, status)
        if not found:
            print(f"No activity qUncompress seen within budget ({hits} hits total). "
                  f"Did you open a .pka while the BP was armed?")
    finally:
        try:
            if pm.read_bytes(addr, 1) == b"\xCC":
                pm.write_bytes(addr, orig, 1)
        except Exception:
            pass
        k32.DebugActiveProcessStop(pid)
        print("Detached (PT keeps running).")


DUMPALL_DIR = None  # gezet door --dumpall: bewaar elke hit i.p.v. te stoppen
CAPTURED_XML = None   # door _try_dump gevuld met de gevonden activity-XML (voor hergebruik als module)
CAPTURED_INPUT = None  # idem: de qUncompress-input (stage-3 output)


def _map_addr(pm, addr):
    """Map een runtime-adres -> (modulenaam, rva) via module-enumeratie."""
    try:
        mods = list(pymem.process.list_modules(pm.process_handle))
    except Exception:
        return None, 0
    for m in mods:
        base = m.lpBaseOfDll
        size = getattr(m, "SizeOfImage", 0) or 0
        if base and base <= addr < base + size:
            name = m.name if isinstance(m.name, str) else m.name.decode(errors="ignore")
            return name, addr - base
    return None, 0


def _try_dump(pm, ctx, hits):
    """Lees qUncompress-input (RDX, R8), inflate, check activity-marker, bewaar. -> found."""
    data_ptr = ctx.Rdx
    nbytes = ctx.R8 & 0xFFFFFFFFFFFF
    if not (0 < nbytes <= 64 * 1024 * 1024 and data_ptr):
        print(f"  [hit {hits}] nbytes={nbytes} (skipped)", flush=True)
        return False
    try:
        buf = pm.read_bytes(data_ptr, int(nbytes))
    except Exception:
        return False
    xml, off = try_inflate(buf)
    if xml and any(m in xml for m in MARKERS) and DUMPALL_DIR is None:
        global CAPTURED_XML, CAPTURED_INPUT
        CAPTURED_XML = xml
        CAPTURED_INPUT = buf
    # caller-returnadres (= binnen de v9-unpack-functie) + module-mapping
    ret = caller = ""
    try:
        ra = struct.unpack("<Q", pm.read_bytes(ctx.Rsp, 8))[0]
        mod, rva = _map_addr(pm, ra)
        caller = f"  caller-ret=0x{ra:016X}  ({mod}+0x{rva:X})" if mod else f"  caller-ret=0x{ra:016X}"
    except Exception:
        pass
    if DUMPALL_DIR is not None:
        os.makedirs(DUMPALL_DIR, exist_ok=True)
        olen = len(xml) if xml else 0
        with open(os.path.join(DUMPALL_DIR, f"hit{hits:02d}_in{nbytes}_out{olen}.bin"), "wb") as f:
            f.write(xml if xml else buf[:65536])
        mark = " <PACKETTRACER>" if (xml and any(m in xml for m in MARKERS)) else ""
        print(f"  [hit {hits}] nbytes={nbytes} -> out {olen}{mark}", flush=True)
        return False
    if xml and any(m in xml for m in MARKERS):
        with open(os.path.join(OUT_DIR, "qunc_input.bin"), "wb") as f:
            f.write(buf)
        with open(os.path.join(OUT_DIR, "activity.xml"), "wb") as f:
            f.write(xml)
        print(f"  [hit {hits}] nbytes={nbytes} zlib@+{off} -> XML {len(xml):,} bytes  "
              f"*** ACTIVITY FOUND ***", flush=True)
        print(f"  -> {os.path.join(OUT_DIR, 'qunc_input.bin')}  (stage-3 output, Phase-2 reference)")
        print(f"  -> {os.path.join(OUT_DIR, 'activity.xml')}")
        # stack-walk: alle PacketTracer.exe return-adressen op de stack = call-keten naar de unpack-fn
        try:
            ptmod = pymem.process.module_from_name(pm.process_handle, "PacketTracer.exe")
            ptbase = ptmod.lpBaseOfDll
            ptsize = ptmod.SizeOfImage
            print(f"  qUncompress-caller-ret in PacketTracer.exe (base 0x{ptbase:016X})", flush=True)
            stk = pm.read_bytes(ctx.Rsp, 0x800)
            print("  STACK (PacketTracer.exe return addresses, stack order):", flush=True)
            seen = set()
            for i in range(0, len(stk) - 8, 8):
                v = struct.unpack_from("<Q", stk, i)[0]
                if ptbase <= v < ptbase + ptsize:
                    rva = v - ptbase
                    if rva not in seen:
                        seen.add(rva)
                        print(f"    PacketTracer.exe+0x{rva:X}", flush=True)
                        if len(seen) >= 30:
                            break
        except Exception as e:
            print(f"  (stack-walk error: {e})", flush=True)
        return True
    print(f"  [hit {hits}] nbytes={nbytes} xml={len(xml) if xml else 0} (no activity)", flush=True)
    return False


def launch(pka, budget):
    pka = os.path.abspath(pka)
    cmd = f'"{PT_EXE}" "{pka}"'
    si = STARTUPINFOW(); si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()
    if not k32.CreateProcessW(PT_EXE, ctypes.create_unicode_buffer(cmd), None, None,
                              False, DEBUG_ONLY_THIS_PROCESS, None, None,
                              ctypes.byref(si), ctypes.byref(pi)):
        print(f"CreateProcessW failed (err {k32.GetLastError()})."); return
    pid = pi.dwProcessId
    print(f"PT launched as debuggee PID {pid}; opening {pka}", flush=True)
    k32.DebugSetProcessKillOnExit(False)

    pm = None; addr = None; orig = None; armed = False
    found = False; pending = None; hits = 0; first_bp = True
    evt = DEBUG_EVENT(); t0 = time.time()
    try:
        while time.time() - t0 < budget and not found:
            if not k32.WaitForDebugEvent(ctypes.byref(evt), 1000):
                continue
            code = evt.dwDebugEventCode
            status = DBG_CONTINUE
            if addr is None:  # arm zodra Qt6Core in de debuggee geladen is
                if pm is None:
                    try:
                        pm = pymem.Pymem(); pm.open_process_from_id(pid)
                    except Exception:
                        pm = None
                if pm is not None:
                    try:
                        qb = pymem.process.module_from_name(pm.process_handle, QT6CORE).lpBaseOfDll
                        addr = qb + QUNCOMPRESS_RVA
                        orig = pm.read_bytes(addr, 1)
                        pm.write_bytes(addr, b"\xCC", 1); armed = True
                        print(f"BP armed @ 0x{addr:016X} (Qt6Core loaded).", flush=True)
                    except Exception:
                        addr = None
            if code == EXCEPTION_DEBUG_EVENT:
                er = evt.u.ExceptionRecord
                exc = er.ExceptionCode; exa = er.ExceptionAddress or 0
                if addr is not None and exc == EXCEPTION_BREAKPOINT and exa == addr and armed:
                    hits += 1
                    th = k32.OpenThread(THREAD_ALL, False, evt.dwThreadId)
                    ctx, _b = aligned_context(); ctx.ContextFlags = CONTEXT_CR
                    if k32.GetThreadContext(th, ctypes.byref(ctx)):
                        found = _try_dump(pm, ctx, hits)
                        pm.write_bytes(addr, orig, 1); armed = False
                        ctx.Rip = addr; ctx.EFlags |= TRAP_FLAG; ctx.ContextFlags = CONTEXT_CR
                        k32.SetThreadContext(th, ctypes.byref(ctx))
                        pending = addr
                    k32.CloseHandle(th)
                    k32.ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, DBG_CONTINUE)
                    continue
                elif exc == EXCEPTION_SINGLE_STEP and pending is not None:
                    pm.write_bytes(pending, b"\xCC", 1); armed = True; pending = None
                    k32.ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, DBG_CONTINUE)
                    continue
                elif exc == EXCEPTION_BREAKPOINT and first_bp:
                    first_bp = False
                else:
                    status = DBG_EXCEPTION_NOT_HANDLED
            elif code == EXIT_PROCESS_DEBUG_EVENT:
                print("Debuggee exited (possibly single-instance-forwarded to an existing PT).",
                      flush=True)
                break
            k32.ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, status)
        if not found:
            print(f"No activity qUncompress seen ({hits} hits total).")
    finally:
        try:
            if pm and armed and pm.read_bytes(addr, 1) == b"\xCC":
                pm.write_bytes(addr, orig, 1)
        except Exception:
            pass
        k32.DebugActiveProcessStop(pid)
        print("Detached (PT keeps running).")
    return CAPTURED_XML


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe", action="store_true", help="read-only attach + adres-check")
    ap.add_argument("--launch", metavar="PKA", help="start PT onder debugger en open dit .pka")
    ap.add_argument("--dumpall", metavar="DIR", help="bewaar ELKE qUncompress-hit in DIR (geen stop)")
    ap.add_argument("--budget", type=int, default=120, help="wachttijd in seconden")
    args = ap.parse_args()
    global DUMPALL_DIR
    if args.dumpall:
        DUMPALL_DIR = args.dumpall
    if args.probe:
        probe()
    elif args.launch:
        launch(args.launch, args.budget)
    else:
        capture(args.budget)


if __name__ == "__main__":
    main()
