# wb-find.py
"""wb-find.py -- build msprcore.bla (PRKF) from the PlayReady DLL alone.

  python wb-find.py discover   once per DLL build -> testdata/offsets.json
  python wb-find.py hwid       -> testdata/hwid.bin              (optional)
  python wb-find.py payload    -> testdata/activation_request.bin
  python wb-find.py activate   -> testdata/activation_response.bin
  python wb-find.py decrypt    -> testdata/msprcore.bla

discover is first because it is the only step that searches: the payload routine
is the heap block whose decrypted code contains 2252 (0x8CC), and the get-HWID
and decrypt routines are then searched in a window around it. Probing is not
spread over the other stages, because a probe with a routine's own argument
block makes a foreign routine dereference a size or a small integer as a pointer
and die -- one dead process per descriptor.

The image itself is decrypted in-process with op=1, where a failure is an
NTSTATUS rather than a crash, and cached per DLL build in testdata/wbtool_img.bin.

hwid is skippable: the Activation service does not validate it. If testdata/hwid.bin
is absent, payload writes a synthetic one and says so.
"""
import base64
import ctypes
import json
import os
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

if os.name != "nt" or ctypes.sizeof(ctypes.c_void_p) != 8:
    raise SystemExit("wb-find.py: Windows x64 only")

import warbird as wb

OFFSETS = {"hwid": 0x0, "payload": 0x0, "decrypt": []}
WINDOW = 24                       # neighbours either side of the payload routine
SYNTH = b"FAKE.PR.ID" + b"\0" * 22

WORK = "testdata"
HWID = os.path.join(WORK, "hwid.bin")
REQ = os.path.join(WORK, "activation_request.bin")
RESP = os.path.join(WORK, "activation_response.bin")
BLA = os.path.join(WORK, "msprcore.bla")
OFF = os.path.join(WORK, "offsets.json")
IMG = os.path.join(WORK, "wbtool_img.bin")
SYN = os.path.join(WORK, "synthetic.bin")

URL = "https://activation.playready.microsoft.com/PlayReady/ACT/Activation.asmx"
ACTION = '"http://schemas.microsoft.com/PlayReady/ActivationService/v1/Activate"'

SOAP = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <Activate xmlns="http://schemas.microsoft.com/PlayReady/ActivationService/v1">
      <challenge>
        <clientSdkVersion>4.6.0.0</clientSdkVersion>
        <clientSdkType>2</clientSdkType>
        <platform>9</platform>
        <tid>1</tid>
        <payload>
          <primaryPayload>{b64}</primaryPayload>
        </payload>
      </challenge>
    </Activate>
  </soap:Body>
</soap:Envelope>"""


def wr(p, b):
    with open(p, "wb") as f:
        f.write(b)


def need(p, how):
    if not os.path.exists(p):
        wb.die("missing %s - run: python wb-find.py %s" % (p, how))
    return p


def load_cache():
    try:
        with open(OFF) as f:
            c = json.load(f)
    except (OSError, ValueError):
        return {}
    return c if c.get("dll_sha256") == wb.dll_sha() else {}


def save_cache(c):
    c["dll_sha256"] = wb.dll_sha()
    with open(OFF, "w") as f:
        json.dump(c, f, indent=2)


def image():
    sha = wb.dll_sha()
    try:
        with open(IMG + ".json") as f:
            m = json.load(f)
        if m.get("dll_sha256") == sha and m.get("size") == os.path.getsize(IMG):
            print("[*] image cached (%d bytes)" % m["size"])
            with open(IMG, "rb") as f:
                return f.read()
    except (OSError, ValueError):
        pass
    print("[*] decrypting the image")
    img = wb.dec_image()
    wr(IMG, img)
    with open(IMG + ".json", "w") as f:
        json.dump({"dll_sha256": sha, "size": len(img)}, f)
    return img


def window(pay):
    ds = sorted(wb.heaps(wb.scan()), key=lambda d: d["desc"])
    ids = [d["desc"] for d in ds]
    if pay not in ids:
        wb.die("payload desc %#x is not a heap descriptor for this build" % pay)
    i = ids.index(pay)
    return ds[max(0, i - WINDOW):i + WINDOW + 1]


def one(c, kind):
    if len(c) == 1:
        return c[0]
    wb.die("%d %s matches%s - raise WINDOW or set OFFSETS" %
           (len(c), kind, "".join(" %#x" % d for d in c)))


def post(payload):
    req = urllib.request.Request(URL, method="POST",
        data=SOAP.format(b64=base64.b64encode(payload).decode()).encode(),
        headers={"Content-Type": "text/xml; charset=utf-8",
                 "SOAPAction": ACTION,
                 "User-Agent": "PlayReady PC SDK v3.0"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            xml = r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        wb.die("HTTP %d: %s" % (e.code, e.read().decode("utf-8", "replace")[:300]))
    for el in ET.fromstring(xml).iter():
        if el.tag.rsplit("}", 1)[-1] == "primaryPayload" and el.text:
            return base64.b64decode(el.text)
    wb.die("no primaryPayload in the response")


# ---------------------------------------------------------------------- discover

def cmd_discover():
    c = load_cache()
    img = image()
    ds = wb.scan()
    cands = wb.pay_candidates(img, ds)
    print("[*] payload candidates (0x8CC in decrypted code): %d" % len(cands))
    if not cands:
        wb.die("no decrypted heap block contains 0x8CC - delete %s and rerun" % IMG)

    rows, _ = wb.probe("payload", cands, hwid=SYNTH.hex())
    pay = one([d["desc"] for d in cands
               if wb.ok(rows.get(d["desc"])) and rows[d["desc"]].get("seeddiff")],
              "build-payload")
    c["payload"] = pay
    print("[+] payload desc=%#x" % pay)

    win = window(pay)
    print("[*] window %d descriptors around payload" % len(win))

    rows, _ = wb.probe("hwid", win)
    hw = [d["desc"] for d in win
          if wb.ok(rows.get(d["desc"])) and rows[d["desc"]].get("stable")
          and rows[d["desc"]]["nz"] and 1 <= rows[d["desc"]]["n"] <= 512]
    c["hwid"] = one(hw, "get-HWID") if hw else 0
    print("[+] hwid    desc=%#x" % c["hwid"] if c["hwid"]
          else "[!] no get-HWID in window - skippable, write hwid.bin by hand")

    wr(SYN, os.urandom(0x100))
    rows, _ = wb.probe("decrypt", win, resp=os.path.abspath(SYN), seed="00" * 16)
    dec = [d["desc"] for d in win
           if wb.ok(rows.get(d["desc"])) and 0 < rows[d["desc"]]["n"] <= 0x1000]
    if not dec:
        wb.die("no decrypt candidate in the window - raise WINDOW and rerun")
    c["decrypt"] = dec
    print("[+] decrypt desc=%s"
          % "".join(" %#x" % d for d in dec))
    save_cache(c)
    print("\nOFFSETS = {\"hwid\": %#x, \"payload\": %#x, \"decrypt\": %s}"
          % (c["hwid"], c["payload"], [hex(d) for d in c["decrypt"]]))


# ------------------------------------------------------------------------ stages

def cmd_hwid():
    d = OFFSETS["hwid"] or load_cache().get("hwid") or 0
    if not d:
        wb.die("no get-HWID offset - run discover, or write %s by hand and skip"
               " this stage (the service does not validate it)" % HWID)
    nt, st, data, n = wb.call_hwid(wb.base(), d)
    if nt or st or not 1 <= n <= 512:
        wb.die("get-HWID nt=%#x status=%#x len=%d - rerun discover" % (nt, st, n))
    wr(HWID, data)
    print("[+] hwid    %d bytes  %s" % (n, data[:16].hex()))


def cmd_payload():
    if os.path.exists(HWID):
        hwid = open(HWID, "rb").read()
    else:
        hwid = SYNTH
        wr(HWID, hwid)
        print("[!] %s absent - wrote a synthetic %d-byte hwid" % (HWID, len(hwid)))
    d = OFFSETS["payload"] or load_cache().get("payload") or 0
    if not d:
        wb.die("no payload offset - run discover")
    nt, st, data, n = wb.call_payload(wb.base(), d, hwid)
    if nt or st or len(data) < 32:
        wb.die("build-payload nt=%#x status=%#x len=%d - rerun discover" % (nt, st, n))
    wr(REQ, data)
    print("[+] payload %d bytes  seed=%s" % (n, data[-16:].hex()))


def cmd_activate():
    p = open(need(REQ, "payload"), "rb").read()
    resp = post(p)
    wr(RESP, resp)
    print("[+] response %d bytes" % len(resp))


def cmd_decrypt():
    req = open(need(REQ, "payload"), "rb").read()
    resp = open(need(RESP, "activate"), "rb").read()
    seed = req[-16:]
    ds = OFFSETS["decrypt"] or load_cache().get("decrypt") or []
    if isinstance(ds, int):
        ds = [ds]
    if not ds:
        wb.die("no decrypt candidates - run discover")
    b = wb.base()
    for d in ds:
        nt, st, data, _ = wb.call_decrypt(b, d, resp, seed)
        k = data.find(b"PRKF")
        if not nt and not st and k >= 0:
            wr(BLA, data[k:])
            print("[+] %s (%d bytes)  desc=%#x" % (BLA, len(data) - k, d))
            c = load_cache()
            c["decrypt"] = [d]
            save_cache(c)
            print("\nOFFSETS = {\"hwid\": %#x, \"payload\": %#x, \"decrypt\": [%#x]}"
                  % (c.get("hwid", 0), c.get("payload", 0), d))
            return
    wb.die("none of %d decrypt candidates produced PRKF - rerun discover"
           % len(ds))


MODES = {"discover": cmd_discover, "hwid": cmd_hwid, "payload": cmd_payload,
         "activate": cmd_activate, "decrypt": cmd_decrypt}


def main():
    if len(sys.argv) != 2 or sys.argv[1].lower() not in MODES:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    os.makedirs(WORK, exist_ok=True)
    MODES[sys.argv[1].lower()]()
    return 0


if __name__ == "__main__":
    sys.exit(main())
# wb-find.py
