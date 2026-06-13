"""render - per-device sorted answer config -> a single <pka>.answers.txt."""
import os
import re
import datetime


def _natkey(name):
    """natural sort: R-C-BRANCH2 < R-C-BRANCH10."""
    return [int(t) if t.isdigit() else t.lower() for t in re.split(r"(\d+)", name)]


def render_combined(pka, parsed, source):
    devices = parsed["devices"]
    cli = sorted([d for d in devices if d["kind"] == "cli"], key=lambda d: _natkey(d["name"]))
    end = sorted([d for d in devices if d["kind"] == "end"], key=lambda d: _natkey(d["name"]))

    bar = "=" * 78
    out = [bar,
           " ANSWER CONFIGS  -  %s" % os.path.basename(pka),
           " Source: %s   |   answer network #%s (richness %s)" % (
               source, (parsed["answer_index"] or 0) + 1, parsed["score"]),
           " %d IOS devices (CLI)  +  %d end devices   |   %s" % (
               len(cli), len(end), datetime.datetime.now().strftime("%Y-%m-%d %H:%M")),
           bar, ""]

    for d in cli:
        title = d["name"] + (" / hostname %s" % d["hostname"] if d["hostname"] and d["hostname"] != d["name"] else "")
        out.append("#" * 78)
        out.append("#  %s   (IOS running-config)" % title)
        out.append("#" * 78)
        out.append("\n".join(d["cli"]).rstrip())
        out.append("")
        out.append("")

    if end:
        # disambiguate same-named devices (e.g. several 'PC') by their primary IP or index
        name_counts = {}
        for d in end:
            name_counts[d["name"]] = name_counts.get(d["name"], 0) + 1
        idx = {}
        out.append("#" * 78)
        out.append("#  END DEVICES (PC/server) - IP settings")
        out.append("#" * 78)
        for d in end:
            label = d["name"]
            if name_counts[d["name"]] > 1:
                idx[d["name"]] = idx.get(d["name"], 0) + 1
                tag = d.get("primary_ip") or ("#%d" % idx[d["name"]])
                label = "%s (%s)" % (d["name"], tag)
            out.append("----- %s -----" % label)
            if d["ip"]:
                out.extend("   " + s for s in d["ip"])
            else:
                out.append("   (DHCP / no static IP config found)")
            out.append("")

    text = "\n".join(out).rstrip() + "\n"
    target = os.path.splitext(pka)[0] + ".answers.txt"
    with open(target, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    return target, len(cli), len(end)
