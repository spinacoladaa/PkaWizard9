"""
parse - activity-XML -> answer-netwerk -> per-device config.

De activity-XML bevat meerdere <PACKETTRACER5>-netwerken. Het answer-netwerk = het rijkste
(meeste config-commando's). Per device-block (begrensd door <SYS_NAME>) halen we:
  - IOS-devices: de <RUNNINGCONFIG><LINE>-regels (entity-gedecodeerd) = exacte CLI.
  - eind-devices (PC/server): best-effort IP-instellingen (DHCP/IP/mask/gateway/DNS/VLAN)
    en server-services (DNS A-records).
"""
import re
import html

# config-regels die "rijkdom" van een netwerk aangeven (om answer te kiezen)
RICH = re.compile(r"^\s*(router |ip route|ip nat|access-list|ip access|network |switchport|"
                  r"interface |standby|vlan |ip address|encapsulation|tunnel |crypto |line |"
                  r"username |ip dhcp|spanning-tree |banner |enable )", re.I)

IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
# eind-device IP-velden die we tonen (tagnaam -> label)
END_TAGS = [
    ("DHCP_ENABLED", "DHCP"), ("DHCPV6_ENABLED", "DHCPv6"),
    ("IPADDRESS", "IP"), ("IP", "IP"), ("IPV4ADDRESS", "IPv4"),
    ("SUBNETMASK", "Mask"), ("SUBNET", "Mask"),
    ("GATEWAY", "Gateway"), ("DEFAULTGATEWAY", "Gateway"),
    ("DNSSERVER", "DNS"), ("VLAN", "VLAN"),
]


def sanitize(raw):
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "replace")
    raw = bytes(b if (b >= 0x20 or b in (0x09, 0x0a, 0x0d)) else 0x20 for b in raw)
    return raw.decode("utf-8", "replace")


def _cli_lines(block):
    m = re.search(r"<RUNNINGCONFIG>(.*?)</RUNNINGCONFIG>", block, re.S)
    if not m:
        m = re.search(r"<STARTUPCONFIG>(.*?)</STARTUPCONFIG>", block, re.S)
    if not m:
        return None
    lines = [html.unescape(x.group(1)) for x in re.finditer(r"<LINE>(.*?)</LINE>", m.group(1), re.S)]
    # trailing lege regels weg
    while lines and not lines[-1].strip():
        lines.pop()
    return lines if lines else None


def _hostname(lines):
    for l in lines or []:
        s = l.strip()
        if s.lower().startswith("hostname "):
            return s.split(None, 1)[1].strip()
    return None


def _ip_settings(block):
    """best-effort IP-instellingen + DNS-records uit een eind-device-block.

    Geeft (lines, primary_ip): server-DNS-records worden apart getoond en hun IP's
    tellen niet als host-IP (om ruis te vermijden). primary_ip dient om gelijknamige
    devices (bv. meerdere 'PC') te onderscheiden.
    """
    # DNS A-records (server-services) eerst -> hun IP's uitsluiten als host-IP
    dns_recs, dns_ips = [], set()
    for m in re.finditer(r"<NAME>([^<]+)</NAME>\s*<TTL>[^<]*</TTL>\s*<IPADDRESS>([^<]+)</IPADDRESS>", block):
        nm, ip = html.unescape(m.group(1)), html.unescape(m.group(2))
        dns_recs.append("DNS-record: %s -> %s" % (nm, ip)); dns_ips.add(ip)

    lines, seen, primary = [], set(), None
    for tag, label in END_TAGS:
        for m in re.finditer(r"<%s>([^<]{1,60})</%s>" % (tag, tag), block):
            v = html.unescape(m.group(1)).strip()
            if not v:
                continue
            if label in ("DHCP", "DHCPv6"):
                v = "enabled" if v in ("1", "true", "True") else ("disabled" if v in ("0", "false", "False") else v)
            elif label in ("IP", "IPv4"):
                if not IPV4.match(v) or v in dns_ips:   # sla server-record-IP's over
                    continue
                if primary is None:
                    primary = v
            elif label in ("Mask", "Gateway"):
                if not IPV4.match(v):
                    continue
            key = (label, v)
            if key not in seen:
                seen.add(key); lines.append("%s: %s" % (label, v))
    lines.extend(dns_recs)
    return lines, primary


def _devices_in(seg):
    """Splits een netwerk-segment in device-blokken op <SYS_NAME> en parse elk."""
    names = list(re.finditer(r"<SYS_NAME>([^<]*)</SYS_NAME>", seg))
    devices = []
    for i, m in enumerate(names):
        start = m.start()
        end = names[i + 1].start() if i + 1 < len(names) else len(seg)
        block = seg[start:end]
        name = html.unescape(m.group(1)).strip() or "(naamloos)"
        cli = _cli_lines(block)
        if cli and len(cli) >= 3:
            devices.append({"name": name, "kind": "cli", "cli": cli,
                            "hostname": _hostname(cli), "ip": []})
        else:
            ip, primary = _ip_settings(block)
            devices.append({"name": name, "kind": "end", "cli": None, "hostname": None,
                            "ip": ip, "primary_ip": primary})
    return devices


def _score(devices):
    return sum(1 for d in devices if d["cli"] for l in d["cli"] if RICH.match(l))


def parse_activity(xml_bytes):
    """Geef dict: {networks, answer_index, score, devices:[...]} voor het answer-netwerk."""
    text = sanitize(xml_bytes)
    starts = [m.start() for m in re.finditer(r"<PACKETTRACER5>", text)]
    act = text.find("<ACTIVITY ")
    if act < 0:
        act = len(text)
    bounds = starts + [act]
    nets = []
    for i, s in enumerate(starts):
        devs = _devices_in(text[s:bounds[i + 1]])
        nets.append({"devices": devs, "score": _score(devs)})
    if not nets:
        return {"networks": 0, "answer_index": None, "score": 0, "devices": []}
    # answer = hoogste rijkdom; tie-break = laatste netwerk
    best = max(range(len(nets)), key=lambda i: (nets[i]["score"], i))
    return {"networks": len(nets), "answer_index": best,
            "score": nets[best]["score"], "devices": nets[best]["devices"]}
