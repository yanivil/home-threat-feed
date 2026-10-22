#!/usr/bin/env python3
"""Turn Cyberint IOC exports (.xlsx) into indicator lists for vt_check.py.

    python3 cyberint_xlsx.py ~/Downloads/Cyberint_*_IOCs_2026-10-22.xlsx > iocs.tsv
    python3 vt_check.py --trusted -f iocs.tsv        # the user vouches for the source
    python3 vt_check.py -f iocs.tsv                  # ... or check them on VirusTotal first

An export is one sheet with the columns Type, Created at, Updated at, Value; the group and
export date come from the file name (Cyberint_<Group>_IOCs_<YYYY-MM-DD>.xlsx). Each output
line is `<value>\\t<group>\\tCyberint export <date>`. Values that would block something
legitimate (bare shared-platform hosts) or that a gateway cannot act on (Tor addresses,
anything vt_check.classify rejects) are dropped and listed on stderr. Reads the workbook
with the standard library only, so no spreadsheet package is needed.
"""

import ipaddress
import re
import sys
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlsplit

import vt_check

NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
      "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships"}
NAME_RE = re.compile(r"Cyberint_(?P<group>.+?)_IOCs_(?P<date>\d{4}-\d{2}-\d{2})\.xlsx$", re.IGNORECASE)
# Hosts whose apex is a shared platform: an attacker's page there is one tenant among millions,
# and a bare entry would block the platform. A specific sub-host (x.netlify.app) is kept.
SHARED_PLATFORMS = {
    "github.com", "githubusercontent.com", "gitlab.com", "google.com", "googleapis.com", "drive.google.com",
    "docs.google.com", "dropbox.com", "microsoft.com", "live.com", "onedrive.live.com", "sharepoint.com",
    "amazonaws.com", "cloudfront.net", "azurewebsites.net", "workers.dev", "pages.dev", "netlify.app",
    "vercel.app", "herokuapp.com", "telegram.org", "t.me", "discord.com", "discordapp.com", "ngrok.io",
    "ngrok-free.app", "pastebin.com", "mega.nz", "anydesk.com", "teamviewer.com", "cloudflare.com",
    "bit.ly", "tinyurl.com", "wetransfer.com", "box.com", "icloud.com", "apple.com", "facebook.com",
    "twitter.com", "x.com", "youtube.com", "linkedin.com", "reddit.com", "medium.com", "wordpress.com",
    "blogspot.com", "weebly.com", "wixsite.com", "simplex.im", "proton.me", "protonmail.com", "gmail.com",
    "somee.com", "sendit.sh", "firebaseio.com", "storyblok.com", "onehub.com",
}
# Services whose sub-hosts are shared infrastructure too (relays, API endpoints), not attacker tenants.
SHARED_SUFFIXES = ("simplex.im", "telegram.org", "discord.com", "discordapp.com", "google.com", "microsoft.com",
                   "apple.com", "icloud.com", "whatsapp.com", "whatsapp.net", "signal.org", "proton.me", "t.me")
# Anycast / shared front-end ranges: an address here fronts thousands of unrelated sites.
SHARED_RANGES = [ipaddress.ip_network(n) for n in (
    "104.16.0.0/12", "172.64.0.0/13", "162.158.0.0/15", "188.114.96.0/20", "198.41.128.0/17",  # Cloudflare
    "141.101.64.0/18", "108.162.192.0/18", "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22", "190.93.240.0/20", "197.234.240.0/22",
    "34.117.0.0/16", "34.149.0.0/16", "34.160.0.0/16", "35.186.0.0/16", "35.190.0.0/16",  # Google Cloud LB / GFE
    "142.250.0.0/15", "172.217.0.0/16", "216.58.192.0/19", "74.125.0.0/16", "64.233.160.0/19",  # Google
    "151.101.0.0/16", "199.232.0.0/16",  # Fastly
    "23.192.0.0/11", "104.64.0.0/10", "184.24.0.0/13", "2.16.0.0/13", "95.100.0.0/15",  # Akamai
    "13.107.0.0/16", "52.96.0.0/12", "40.96.0.0/13", "20.190.128.0/18",  # Microsoft 365 front doors
    "13.224.0.0/14", "13.32.0.0/15", "54.230.0.0/16", "54.192.0.0/16", "99.84.0.0/16", "143.204.0.0/16",  # CloudFront
    "205.251.192.0/19", "18.160.0.0/13", "3.160.0.0/14",
)]


def _column(ref):
    return re.match(r"[A-Z]+", ref).group(0)


def _xml(z, name):
    """Parse one workbook part. A downloaded file is untrusted and a real workbook never
    carries a DTD, so any entity declaration (XXE, billion-laughs) is refused before parsing."""
    data = z.read(name)
    if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise ValueError(f"{name}: unexpected DTD or entity declaration in a workbook part")
    return ET.fromstring(data)


def read_rows(path):
    """The first sheet as a list of {header: value} dicts (values as the file stores them, as text)."""
    with zipfile.ZipFile(path) as z:
        shared = []
        if "xl/sharedStrings.xml" in z.namelist():
            for si in _xml(z, "xl/sharedStrings.xml").findall("m:si", NS):
                shared.append("".join(t.text or "" for t in si.iter("{%s}t" % NS["m"])))
        workbook = _xml(z, "xl/workbook.xml")
        rels = {r.get("Id"): r.get("Target") for r in _xml(z, "xl/_rels/workbook.xml.rels")}
        first = workbook.find("m:sheets", NS)[0]
        target = rels[first.get("{%s}id" % NS["r"])]
        target = target if target.startswith("xl/") else "xl/" + target.lstrip("/")
        rows = []
        for row in _xml(z, target).iter("{%s}row" % NS["m"]):
            cells = {}
            for c in row.findall("m:c", NS):
                kind, v = c.get("t"), c.find("m:v", NS)
                if kind == "s":
                    value = shared[int(v.text)]
                elif kind == "inlineStr":
                    value = "".join(t.text or "" for t in c.iter("{%s}t" % NS["m"]))
                else:
                    value = v.text if v is not None else None
                if value is not None:
                    cells[_column(c.get("r"))] = str(value).strip()
            if cells:
                rows.append(cells)
    if not rows:
        return []
    header = rows[0]
    return [{header[col]: val for col, val in r.items() if col in header} for r in rows[1:]]


def group_and_date(path):
    m = NAME_RE.search(Path(path).name)
    if not m:
        raise ValueError(f"{Path(path).name}: expected Cyberint_<Group>_IOCs_<YYYY-MM-DD>.xlsx")
    return m.group("group"), m.group("date")


def _host(value):
    if "://" in value:
        return (urlsplit(value).hostname or "").lower()
    return value.lower().rstrip(".").split("/")[0].split(":")[0]


def drop_reason(value):
    """Why a value must not go into a blocking feed, or None if it may."""
    if any(c in value for c in "{}<>"):
        return "placeholder"
    host = _host(value)
    if host.endswith(".onion"):
        return "Tor address"
    if host in SHARED_PLATFORMS or any(host == s or host.endswith("." + s) for s in SHARED_SUFFIXES):
        return "shared platform"
    try:
        ioc_type, normalised = vt_check.classify(value)
    except ValueError as e:
        return str(e)
    if ioc_type == "IP" and any(ipaddress.ip_address(normalised) in net for net in SHARED_RANGES):
        return "shared CDN address"
    return None


def convert(path):
    """(kept, dropped): kept = [(value, label)], dropped = [(value, reason)]."""
    group, date = group_and_date(path)
    label = f"{group}\tCyberint export {date}"
    kept, dropped, seen = [], [], set()
    for row in read_rows(path):
        value = row.get("Value", "").strip()
        if not value or value.lower() in seen:
            continue
        seen.add(value.lower())
        reason = drop_reason(value)
        if reason:
            dropped.append((value, reason))
        else:
            kept.append((value, label))
    return kept, dropped


def tsv_lines(path):
    return [f"{value}\t{label}" for value, label in convert(path)[0]]


def main(argv=None):
    paths = argv if argv is not None else sys.argv[1:]
    if not paths:
        print(__doc__, file=sys.stderr)
        return 2
    total = 0
    for path in paths:
        kept, dropped = convert(path)
        total += len(kept)
        for value, label in kept:
            print(f"{value}\t{label}")
        print(f"{Path(path).name}: {len(kept)} kept, {len(dropped)} dropped", file=sys.stderr)
        for value, reason in dropped:
            print(f"  dropped {value}  ({reason})", file=sys.stderr)
    print(f"{total} indicators written", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
