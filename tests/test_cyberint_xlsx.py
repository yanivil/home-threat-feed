import tempfile
import unittest
import zipfile
from pathlib import Path

import cyberint_xlsx

SHARED = ["Type", "Created at", "Updated at", "Value", "IPv4 Address", "Domain", "URL", "SHA-256", "MD5",
          "213.145.86.112", "evil-update.com", "https://fileportalshare.netlify.app", "github.com",
          "http://tezwsse5czllksjb7cwp65rvnk4oobmzti2znn42i43xyz.onion/x", "t.me", "Evil.COM.",
          "16db04b632668dae081359fc07c97e5a9b79dad61713642e48b1c2d3e4f5a6b7", "44d88612fea8a8f36de82e1278abb02f"]
ROWS = [  # (type index, value index) into SHARED; a header row comes first
    (4, 9), (5, 10), (6, 11), (5, 12), (6, 13), (5, 14), (5, 15), (7, 16), (8, 17),
]


def make_xlsx(path):
    """A minimal workbook shaped like a Cyberint IOC export: one sheet, Type/Created at/Updated at/Value."""
    ns = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
    sst = f'<sst {ns}>' + "".join(f"<si><t>{s}</t></si>" for s in SHARED) + "</sst>"

    def cell(ref, idx):
        return f'<c r="{ref}" t="s"><v>{idx}</v></c>'

    rows = ['<row r="1">' + cell("A1", 0) + cell("B1", 1) + cell("C1", 2) + cell("D1", 3) + "</row>"]
    for n, (t, v) in enumerate(ROWS, start=2):
        rows.append(f'<row r="{n}">' + cell(f"A{n}", t) + f'<c r="B{n}"><v>45000</v></c>' + cell(f"D{n}", v) + "</row>")
    sheet = f'<worksheet {ns}><sheetData>' + "".join(rows) + "</sheetData></worksheet>"
    wb = (f'<workbook {ns} xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
          '<sheets><sheet name="IOCs" sheetId="1" r:id="rId1"/></sheets></workbook>')
    rels = ('<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="x" Target="worksheets/sheet1.xml"/></Relationships>')
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("xl/workbook.xml", wb)
        z.writestr("xl/_rels/workbook.xml.rels", rels)
        z.writestr("xl/sharedStrings.xml", sst)
        z.writestr("xl/worksheets/sheet1.xml", sheet)


class ReadTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "Cyberint_APT29_IOCs_2026-10-22.xlsx"
        make_xlsx(self.path)

    def test_reads_type_and_value_rows(self):
        rows = cyberint_xlsx.read_rows(self.path)

        self.assertEqual(rows[0], {"Type": "IPv4 Address", "Created at": "45000", "Value": "213.145.86.112"})
        self.assertEqual(len(rows), 9)

    def test_group_and_date_come_from_the_file_name(self):
        self.assertEqual(cyberint_xlsx.group_and_date(self.path), ("APT29", "2026-10-22"))
        self.assertEqual(cyberint_xlsx.group_and_date("Cyberint_Anonymous_Sudan_IOCs_2026-10-22.xlsx"),
                         ("Anonymous Sudan", "2026-10-22"))
        self.assertEqual(cyberint_xlsx.group_and_date("Cyberint_NoName057(16)_IOCs_2026-10-22.xlsx"),
                         ("NoName057(16)", "2026-10-22"))

    def test_refuses_a_workbook_part_that_declares_entities(self):
        """A downloaded file is untrusted: a DTD in any XML part (XXE, billion laughs) is rejected unread."""
        bad = self.path.with_name("Cyberint_Bad_IOCs_2026-10-22.xlsx")
        with zipfile.ZipFile(self.path) as src, zipfile.ZipFile(bad, "w") as dst:
            for item in src.namelist():
                data = src.read(item)
                if item == "xl/sharedStrings.xml":
                    data = b'<!DOCTYPE x [<!ENTITY a "aaaa">]>' + data
                dst.writestr(item, data)

        with self.assertRaises(ValueError):
            cyberint_xlsx.read_rows(bad)


class DropReasonTest(unittest.TestCase):
    def test_placeholders_shared_hosts_and_tor_are_dropped_but_specific_tenants_kept(self):
        cases = [
            ("https://{REDACTED}.firebaseio.com/OutlookStandaloneUpdate/<host-id>.json", "placeholder"),
            ("http://95.181.161.49/index.php?id=<victim>", "placeholder"),
            ("smp10.simplex.im", "shared platform"),  # a relay of a shared messaging service
            ("https://smp10.simplex.im/a#Otp0TGDMNIj", "shared platform"),
            ("somee.com", "shared platform"),  # free web hosting apex
            ("sendit.sh", "shared platform"),
            ("api.telegram.org", "shared platform"),
            ("https://raw.githubusercontent.com/x/y/main/builder.exe", "shared platform"),  # host-level match would hit all of GitHub
            ("https://transfer.sh", "shared platform"),  # public file-transfer services
            ("https://fex.net", "shared platform"),
            ("https://www.sendspace.com", "shared platform"),
            ("https://www.premiumize.com", "shared platform"),
            ("cyberfear.com", "shared platform"),  # encrypted e-mail provider named as a contact channel
            ("tutanota.com", "shared platform"),
            ("https://master-repogen.vercel.app/file/server.scr", None),  # an attacker's own sub-host
            ("tezwsse5czllksjb7cwp65rvnk4oobmzti2znn42i43bjdfd2prqqkad.onion", "Tor address"),
            ("184.168.123.0/24", "not an IP, domain, URL, MD5, SHA1 or SHA256"),
            ("172.67.156.47", "shared CDN address"),  # Cloudflare front-end: blocking it hits thousands of sites
            ("104.86.182.8", "shared CDN address"),  # Akamai
            ("34.117.59.81", "shared CDN address"),  # Google Cloud load-balancer anycast
            ("15.197.240.20", "shared CDN address"),  # AWS Global Accelerator anycast
            ("35.204.181.10", None),  # a Google Cloud VM: one tenant's address
            ("fileportalshare.netlify.app", None),  # an attacker's own sub-host on a platform
            ("elvenforest.s3.us-east-005.backblazeb2.com", None),
            ("accounteam.onmicrosoft.com", None),
            ("213.145.86.112", None),
        ]
        for value, want in cases:
            with self.subTest(value=value):
                self.assertEqual(cyberint_xlsx.drop_reason(value), want)


class ConvertTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "Cyberint_APT29_IOCs_2026-10-22.xlsx"
        make_xlsx(self.path)

    def test_keeps_real_indicators_with_group_label_and_drops_the_rest(self):
        kept, dropped = cyberint_xlsx.convert(self.path)

        self.assertEqual(kept, [
            ("213.145.86.112", "APT29\tCyberint export 2026-10-22"),
            ("evil-update.com", "APT29\tCyberint export 2026-10-22"),
            ("https://fileportalshare.netlify.app", "APT29\tCyberint export 2026-10-22"),
            ("Evil.COM.", "APT29\tCyberint export 2026-10-22"),
            ("16db04b632668dae081359fc07c97e5a9b79dad61713642e48b1c2d3e4f5a6b7", "APT29\tCyberint export 2026-10-22"),
            ("44d88612fea8a8f36de82e1278abb02f", "APT29\tCyberint export 2026-10-22"),
        ])
        self.assertEqual(
            dropped,
            [("github.com", "shared platform"),
             ("http://tezwsse5czllksjb7cwp65rvnk4oobmzti2znn42i43xyz.onion/x", "Tor address"),
             ("t.me", "shared platform")],
        )

    def test_tsv_lines_are_tab_separated_for_vt_check(self):
        lines = cyberint_xlsx.tsv_lines(self.path)

        self.assertEqual(lines[0], "213.145.86.112\tAPT29\tCyberint export 2026-10-22")


if __name__ == "__main__":
    unittest.main()
