"""
xml_source - bemachtig de ontsleutelde activity-XML voor een .pka.

Pluggable backends:
  runtime_dump   - start PT onder debugger, breek op qUncompress, dump de XML (werkt nu).
  offline_decrypt- (later) PkaDecrypt9 met file-Twofish KEY/IV; geen PT nodig.

Caching: de XML wordt naast het bestand bewaard als <stem>.activity.xml, zodat PT maar
één keer per .pka hoeft te draaien. Bestaande dumps (src/activity_<stem>.xml) worden als
seed herkend.
"""
import os
import sys

MARKER = b"PACKETTRACER5_ACTIVITY"
SRC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # ...\src
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)


def cache_path(pka):
    return os.path.splitext(pka)[0] + ".activity.xml"


def _seed_paths(pka):
    """Bestaande handmatige dumps die we als cache mogen hergebruiken."""
    stem = os.path.splitext(os.path.basename(pka))[0]
    return [os.path.join(SRC_DIR, "activity_%s.xml" % stem)]


def _valid(data):
    return bool(data) and MARKER in data


def runtime_dump(pka, budget=150):
    """Start PT onder debugger en vang de activity-XML op. Geeft bytes of None."""
    try:
        from . import qunc_dump          # gepakketteerd (distro)
    except Exception:
        import qunc_dump                 # plat (src/, qunc_dump.py naast het pakket)
    import pymem.process
    others = [p for p in pymem.process.list_processes()
              if p.szExeFile.decode(errors="ignore").lower() == "packettracer.exe"]
    if others:
        print("    WARNING: %d PacketTracer instance(s) already running. Close them for a clean "
              "dump (otherwise the launch may 'forward' to an existing instance and not load the "
              "file itself)." % len(others))
    qunc_dump.CAPTURED_XML = None
    qunc_dump.DUMPALL_DIR = None
    xml = qunc_dump.launch(pka, budget)
    return xml if _valid(xml) else None


def get_activity_xml(pka, refresh=False, budget=150, backend=runtime_dump):
    """Cache-aware: lees cache/seed, anders draai backend en cache het resultaat."""
    cp = cache_path(pka)
    if not refresh:
        if os.path.exists(cp):
            data = open(cp, "rb").read()
            if _valid(data):
                return data, "cache"
        for sp in _seed_paths(pka):
            if os.path.exists(sp):
                data = open(sp, "rb").read()
                if _valid(data):
                    open(cp, "wb").write(data)   # promoveer seed naar cache
                    return data, "seed:" + os.path.basename(sp)
    xml = backend(pka, budget)
    if _valid(xml):
        open(cp, "wb").write(xml)
        return xml, "runtime-dump"
    return None, "FAILED"
