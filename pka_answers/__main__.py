"""
pka_answers - orchestration: find .pka -> XML -> parse answer network -> <pka>.answers.txt.

Usage:
  python -m pka_answers                      # all .pka in the current folder
  python -m pka_answers --folder D:\acts
  python -m pka_answers --file C:\PT9\realtest.pka
  python -m pka_answers --refresh-cache      # ignore cache, dump again via PT
"""
import argparse
import sys

from . import discover, xml_source, parse, render


def process(pka, refresh, budget):
    print("\n[*] %s" % pka, flush=True)
    xml, source = xml_source.get_activity_xml(pka, refresh=refresh, budget=budget)
    if not xml:
        print("    ERROR: could not obtain the activity XML (PT dump failed?).")
        return False
    parsed = parse.parse_activity(xml)
    if not parsed["devices"]:
        print("    ERROR: no devices found in the XML.")
        return False
    target, ncli, nend = render.render_combined(pka, parsed, source)
    print("    XML via %s | answer network #%s (richness %d) | %d CLI + %d end devices"
          % (source, (parsed["answer_index"] or 0) + 1, parsed["score"], ncli, nend))
    print("    -> %s" % target)
    return True


def main():
    ap = argparse.ArgumentParser(prog="pka_answers")
    ap.add_argument("--folder", help="folder to search (default: current working dir)")
    ap.add_argument("--file", help="a specific .pka file")
    ap.add_argument("--refresh-cache", action="store_true", help="ignore cache, dump again")
    ap.add_argument("--budget", type=int, default=150, help="PT dump timeout (s)")
    args = ap.parse_args()

    pkas = [args.file] if args.file else discover.find_pka(args.folder)
    if not pkas:
        print("No .pka files found."); sys.exit(1)
    print("Found: %d .pka file(s)" % len(pkas))
    ok = sum(process(p, args.refresh_cache, args.budget) for p in pkas)
    print("\nDone: %d/%d processed." % (ok, len(pkas)))


if __name__ == "__main__":
    main()
