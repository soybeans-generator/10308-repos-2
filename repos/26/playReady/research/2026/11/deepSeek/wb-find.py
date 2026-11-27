# wb-find.py
"""wb-find.py -- build msprcore.bla (PRKF) from the PlayReady DLL alone.

  python wb-find.py discover   once per DLL build -> testdata/offsets.json
  python wb-find.py hwid       optional           -> testdata/hwid.bin
  python wb-find.py payload                       -> testdata/activation_request.bin
  python wb-find.py activate                      -> testdata/activation_response.bin
  python wb-find.py decrypt                       -> testdata/msprcore.bla

Four files, same directory: this one is the CLI and the one HTTP call, wbprobe.py
runs probe children and the staged sweep, wbimage.py reads the PE, builds the
decrypted image and the candidate filter, warbird.py makes the syscalls.

hwid sweeps with Go's probe block and accepts a descriptor whose output does not
depend on the key, because a HWID is not keyed. dead.json is honoured, so a rerun
resumes instead of repeating its faults.
"""
import base64
import json
import os
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

import warbird as wb
import wbimage as im
import wbprobe as pr

HWID = os.path.join(pr.WORK, "hwid.bin")
REQ = os.path.join(pr.WORK, "activation_request.bin")
RESP = os.path.join(pr.WORK, "activation_response.bin")
BLA = os.path.join(pr.WORK, "msprcore.bla")

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


def post(payload):
    req = urllib.request.Request(URL, method="POST", data=SOAP.format(
        b64=base64.b64encode(payload).decode()).encode(), headers={
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": ACTION,
            "User-Agent": "PlayReady PC SDK v3.0"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            xml = r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        wb.die("HTTP %d: %s" % (e.code, e.read().decode("utf-8", "replace")[:400]))
    for el in ET.fromstring(xml).iter():
        if el.tag.rsplit("}", 1)[-1] == "primaryPayload" and el.text:
            return base64.b64decode(el.text)
    wb.die("no primaryPayload in the response")


def discover():
    ds = im.scan()
    hs = im.heaps(ds)
    sg = [d for d in ds if d["size"] != 0xF0]
    print("[*] %d descriptors: %d segment, %d heap-exec" % (len(ds), len(sg), len(hs)))
    if not sg:
        wb.die("no segment descriptors - this DLL does not match the known layout")

    img = pr.image(ds, hs)
    cands = im.pay_candidates(img, hs)
    print("[*] payload candidates (constant 2252 in decrypted code): %d" % len(cands))
    if not cands:
        wb.die("no decrypted heap block carries the constant\n"
               "  blocks did not decrypt (watch ok/err above), or it is not inline\n"
               "  in this build - set OFFSETS in wbprobe.py and rerun")

    rows, _ = pr.probe("payload", cands, hwid=pr.SYNTH.hex(), dump=True)
    pr.report(cands, rows)
    good = [d["desc"] for d in cands if rows.get(d["desc"], {}).get("ok")]

    if not good:
        a = cands[0]["desc"]
        near = [x for x in pr.outward(a, pr.NEAR) if x["desc"] != a]
        print("[*] nothing at %#x wrote a payload - trying %d neighbours"
              % (a, len(near)))
        nrows, _ = pr.probe("payload", near, hwid=pr.SYNTH.hex(), dump=True)
        pr.report(near, nrows)
        good = [x["desc"] for x in near if nrows.get(x["desc"], {}).get("ok")]

    if len(good) > 1:
        good.sort(key=lambda d: abs(d - cands[0]["desc"]))
        print("[!] %d descriptors wrote a payload%s - keeping the one nearest the\n"
              "    constant's block; OFFSETS can pin another."
              % (len(good), "".join(" %#x" % d for d in good)))
    pick = good[0] if good else cands[0]["desc"]
    c = pr.load_cache()
    c["payload"] = pick
    c.pop("unconfirmed", None)
    if not good:
        c["unconfirmed"] = True
        print("[!] nothing wrote a payload; recording %#x anyway - the constant is\n"
              "    in a callee, not the routine op=3 enters. payload then activate\n"
              "    is the real test." % pick)
    pr.save_cache(c)
    print("[+] payload desc=%#x%s" % (pick, "" if good else " (unconfirmed)"))


def hwid():
    rows = {}
    d = pr.OFFSETS.get("hwid") or pr.load_cache().get("hwid") or 0
    if not d:
        print("[*] walking outward from anchor %#x  %d workers  %d candidates"
              % (pr.anchor(), pr.WORKERS, len(im.heap_routines())))
        hit, rows = pr.sweep("hwid", lambda r: r.get("stable") and r.get("nz"))
        if not hit:
            wb.die("no descriptor returned a key-independent non-zero blob under\n"
                   "  Go's probe block. get-HWID is not a heap-exec descriptor on\n"
                   "  this build, or it writes its length through +0x1C and dies\n"
                   "  under that block. Skip it - the Activation service does not\n"
                   "  validate the HWID:\n"
                   "  python -c \"open('testdata/hwid.bin','wb').write("
                   "b'FAKE.PR.ID'+b'\\0'*22)\"")
        d = hit["desc"]
        c = pr.load_cache()
        c["hwid"] = d
        pr.save_cache(c)
        print("[+] get-HWID desc=%#x  n=%d" % (d, rows[d]["n"]))

    data = bytes.fromhex(rows.get(d, {}).get("h", ""))
    if not data:
        one = [x for x in im.heap_routines() if x["desc"] == d]
        if not one:
            wb.die("hwid desc=%#x is not a heap routine for this build" % d)
        rr, _ = pr.probe("hwid", one)
        data = bytes.fromhex(rr.get(d, {}).get("h", ""))
    if len(data) < 8:
        wb.die("get-HWID desc=%#x gave %d bytes" % (d, len(data)))
    pr.wr(HWID, data)
    print("[+] hwid    %d bytes  %s" % (len(data), data[:16].hex()))


def payload():
    if os.path.exists(HWID):
        with open(HWID, "rb") as f:
            data = f.read()
    else:
        data = pr.SYNTH
        pr.wr(HWID, data)
        print("[!] %s absent - wrote a synthetic %d-byte hwid" % (HWID, len(data)))
    d = pr.anchor()
    out, src, n, moved, why = wb.payload(wb.base(), d, data)
    if not out:
        wb.die("build-payload desc=%#x failed: %s - rerun discover" % (d, why))
    pr.wr(REQ, out)
    print("[+] payload %d bytes  desc=%#x  src=%s  %s" % (n, d, src, out[:16].hex()))
    print("    seed %s  %s" % (out[-16:].hex(), "moved" if moved else "same"))
    if not moved:
        print("[!] both calls gave the same tail - the key may be per client\n"
              "    instance, not per request. activate is what decides.")


def activate():
    with open(pr.need(REQ, "payload"), "rb") as f:
        p = f.read()
    resp = post(p)
    pr.wr(RESP, resp)
    print("[+] response %d bytes" % len(resp))


def decrypt():
    with open(pr.need(REQ, "payload"), "rb") as f:
        req = f.read()
    pr.need(RESP, "activate")
    seed = req[-16:]
    hit, rows = pr.sweep("decrypt", lambda r: r.get("prkf"), dump=True,
                         resp=os.path.abspath(RESP), seed=seed.hex())
    if not hit:
        wb.die("no decrypt routine in the heap descriptor list")
    d = hit["desc"]
    data = bytes.fromhex(rows[d]["full"])
    k = data.find(b"PRKF")
    pr.wr(BLA, data[k:])
    print("[+] %s (%d bytes)  desc=%#x" % (BLA, len(data) - k, d))
    c = pr.load_cache()
    c["decrypt"] = [d]
    pr.save_cache(c)
    print('\nOFFSETS = {"hwid": %#x, "payload": %#x, "decrypt": [%#x]}'
          % (c.get("hwid", 0), c.get("payload", 0), d))


MODES = {"discover": discover, "hwid": hwid, "payload": payload,
         "activate": activate, "decrypt": decrypt}


def main():
    if pr.child():
        return 0
    if len(sys.argv) != 2 or sys.argv[1].lower() not in MODES:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    os.makedirs(pr.WORK, exist_ok=True)
    MODES[sys.argv[1].lower()]()
    return 0


if __name__ == "__main__":
    sys.exit(main())
# wb-find.py
