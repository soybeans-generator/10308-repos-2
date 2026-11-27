"""wbfind.py -- PlayReady activation pipeline, Windows x64, Python 3.8+.

Four stages, run once each, in this order. Each stage reads only what the
previous stage wrote; no stage runs another. The DLL is re-read per stage.

  python wbfind.py hwid      WB get-HWID call        -> testdata/hwid.bin
  python wbfind.py payload   WB build-payload call   -> testdata/activation_request.bin
  python wbfind.py activate  SOAP POST to Microsoft  -> testdata/activation_response.bin
  python wbfind.py decrypt   WB decrypt call         -> testdata/msprcore.bla

Each stage reports the desc_va it found and records it in testdata/offsets.json;
decrypt prints the ready prkf_gen.py command.
"""

import base64
import ctypes
import hashlib
import json
import os
import struct
import subprocess
import sys
import urllib.request
import xml.etree.ElementTree as ET

if os.name != "nt" or ctypes.sizeof(ctypes.c_void_p) != 8:
    raise SystemExit("wbfind.py: Windows x64 only")

DLL = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32",
                   "Windows.Media.Protection.PlayReady.dll")
WORK = "testdata"
HWID = os.path.join(WORK, "hwid.bin")
REQ = os.path.join(WORK, "activation_request.bin")
RESP = os.path.join(WORK, "activation_response.bin")
BLA = os.path.join(WORK, "msprcore.bla")
OFF = os.path.join(WORK, "offsets.json")

URL = "https://activation.playready.microsoft.com/PlayReady/ACT/Activation.asmx"
ACTION = '"http://schemas.microsoft.com/PlayReady/ActivationService/v1/Activate"'

CHUNK, T_CHUNK, T_ONE = 64, 90, 20

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


# ------------------------------------------------------------------- descriptor
# +0x00 sha256 over [0x20,0xF0), +0x20 size (0xF0 = heap-exec), +0x28 desc_va.

def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def scan():
    """Every digest-validated heap-exec descriptor's desc_va in the DLL."""
    fb = open(DLL, "rb").read()
    lf = u32(fb, 0x3C)
    n = struct.unpack_from("<H", fb, lf + 6)[0]
    p = lf + 24 + struct.unpack_from("<H", fb, lf + 20)[0]
    out = set()
    for i in range(n):
        vs, va, rs, rp = struct.unpack_from("<IIII", fb, p + 40 * i + 8)
        b = fb[rp:rp + rs]
        for off in range(0, len(b) - 0xF0, 4):
            if (u32(b, off + 0x20) == 0xF0
                    and hashlib.sha256(b[off + 0x20:off + 0xF0]).digest() == b[off:off + 32]):
                out.add(u32(b, off + 0x28) & 0x0FFFFFFF)
    return sorted(out)


# ---------------------------------------------------------------------- op=3 ABI

class HwidReq(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("op", ctypes.c_uint64), ("seg", ctypes.c_void_p),
                ("status", ctypes.c_void_p), ("oem", ctypes.c_void_p),
                ("type", ctypes.c_uint32), ("out", ctypes.c_void_p),
                ("out_len", ctypes.c_void_p)]


class PayloadReq(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("op", ctypes.c_uint64), ("seg", ctypes.c_void_p),
                ("status", ctypes.c_void_p), ("nonce", ctypes.c_void_p),
                ("in_len", ctypes.c_uint32), ("inp", ctypes.c_void_p),
                ("out_len", ctypes.c_void_p), ("out", ctypes.c_void_p),
                ("ver", ctypes.c_void_p)]


class DecryptReq(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("op", ctypes.c_uint64), ("seg", ctypes.c_void_p),
                ("status", ctypes.c_void_p), ("inp", ctypes.c_void_p),
                ("in_len", ctypes.c_uint32), ("seed", ctypes.c_void_p),
                ("out", ctypes.c_void_p), ("out_len", ctypes.c_void_p)]


_nt = ctypes.WinDLL("ntdll").NtQuerySystemInformation
_nt.restype = ctypes.c_long
_nt.argtypes = [ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p]


def wb(r):
    return _nt(0xB9, ctypes.byref(r), ctypes.sizeof(r), None) & 0xFFFFFFFF


def base():
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.LoadLibraryW.restype = ctypes.c_void_p
    k.LoadLibraryW.argtypes = [ctypes.c_wchar_p]
    b = k.LoadLibraryW(DLL)
    if not b:
        raise OSError("LoadLibraryW %s: %d" % (DLL, ctypes.get_last_error()))
    return b


def call_hwid(b, d):
    st, n = ctypes.c_uint32(), ctypes.c_uint32(512)
    out = (ctypes.c_ubyte * 512)()
    nt = wb(HwidReq(3, b + d, ctypes.addressof(st), None, 1,
                    ctypes.addressof(out), ctypes.addressof(n)))
    n = min(n.value, 512)
    return nt, st.value, bytes(out[:n]), n


def call_payload(b, d, hwid):
    sz = len(hwid) + 2252
    buf, out = (ctypes.c_ubyte * sz)(*hwid), (ctypes.c_ubyte * sz)()
    nonce = (ctypes.c_ubyte * len(hwid))(*hwid)
    n, ver, st = ctypes.c_uint32(sz), ctypes.c_uint32(), ctypes.c_uint32()
    nt = wb(PayloadReq(3, b + d, ctypes.addressof(st), ctypes.addressof(nonce),
                       len(hwid), ctypes.addressof(buf), ctypes.addressof(n),
                       ctypes.addressof(out), ctypes.addressof(ver)))
    m = n.value
    return nt, st.value, bytes(buf[:m]) if 0 < m <= sz else b"", m


def call_decrypt(b, d, resp, seed):
    sz = len(resp)
    buf, out = (ctypes.c_ubyte * sz)(*resp), (ctypes.c_ubyte * sz)()
    key, st = (ctypes.c_ubyte * 16)(*seed), ctypes.c_uint32()
    n = ctypes.c_uint32(max(sz - 8, 0))
    nt = wb(DecryptReq(3, b + d, ctypes.addressof(st), ctypes.addressof(buf), sz,
                       ctypes.addressof(key), ctypes.addressof(out), ctypes.addressof(n)))
    m = n.value
    return nt, st.value, bytes(out[:m]) if 0 < m <= sz else b"", m


# ------------------------------------------------------------------- child probe
# A wrong descriptor faults, and a fault is a SEH exception that kills the process,
# so probes run in a child; a chunk that dies is retried one descriptor at a time.

def child():
    raw = os.environ.get("WBFIND_CHILD")
    if not raw:
        return False
    s = json.loads(raw)
    b = base()
    hwid = bytes.fromhex(s.get("hwid", ""))
    seed = bytes.fromhex(s.get("seed", ""))
    resp = open(s["resp"], "rb").read() if s.get("resp") else b""

    for d in s["descs"]:
        row = {"d": d}
        try:
            if s["mode"] == "hwid":
                a, c = call_hwid(b, d), call_hwid(b, d)
                row.update(nt=a[0], st=a[1], n=a[3], nz=any(a[2]),
                           stable=a == c, h=a[2].hex())
            elif s["mode"] == "payload":
                a, c = call_payload(b, d, hwid), call_payload(b, d, hwid)
                row.update(nt=a[0], st=a[1], n=a[3], n2=c[3],
                           seeddiff=len(a[2]) > 16 and a[2][-16:] != c[2][-16:])
                if s.get("dump"):
                    row["full"] = a[2].hex()
            else:
                a = call_decrypt(b, d, resp, seed)
                row.update(nt=a[0], st=a[1], n=a[3],
                           prkf=0 <= a[2].find(b"PRKF") < 64)
                if s.get("dump"):
                    row["full"] = a[2].hex()
        except Exception as e:
            row["e"] = repr(e)
        print(json.dumps(row), flush=True)
    return True


def run(mode, descs, timeout=T_CHUNK, **kw):
    env = dict(os.environ, WBFIND_CHILD=json.dumps(dict(mode=mode, descs=descs, **kw)))
    try:
        out = subprocess.run([sys.executable, os.path.abspath(__file__)], env=env,
                             capture_output=True, timeout=timeout).stdout
    except subprocess.TimeoutExpired as e:
        out = e.stdout or b""
    rows = {}
    for ln in out.decode("utf-8", "replace").splitlines():
        try:
            r = json.loads(ln)
            rows[r["d"]] = r
        except (ValueError, KeyError):
            pass
    return rows


def probe(mode, descs, **kw):
    rows = {}
    for i in range(0, len(descs), CHUNK):
        chunk = descs[i:i + CHUNK]
        got = run(mode, chunk, **kw)
        for d in [d for d in chunk if d not in got]:
            got.update(run(mode, [d], timeout=T_ONE, **kw))
        for d in chunk:
            rows[d] = got.get(d, {"d": d, "dead": True})
        print("    %d/%d" % (min(i + CHUNK, len(descs)), len(descs)), flush=True)
    return rows


def dump(mode, d, **kw):
    r = run(mode, [d], timeout=T_ONE, dump=True, **kw).get(d)
    return bytes.fromhex(r["full"]) if r and r.get("full") else None


# ------------------------------------------------------------------------ common

def die(m):
    raise SystemExit("[-] " + m)


def wr(p, b):
    with open(p, "wb") as f:
        f.write(b)


def need(p, how):
    if not os.path.exists(p):
        die("missing %s - run: python wbfind.py %s" % (p, how))
    with open(p, "rb") as f:
        return f.read()


def rec(k, v):
    o = {}
    if os.path.exists(OFF):
        with open(OFF) as f:
            try:
                o = json.load(f)
            except ValueError:
                pass
    o[k] = v
    with open(OFF, "w") as f:
        json.dump(o, f)


def good(r):
    return bool(r) and not r.get("e") and not r.get("dead") \
        and r.get("nt") == 0 and r.get("st") == 0


def pick(mode, descs, test, **kw):
    rows = probe(mode, descs, **kw)
    return [(d, r) for d in descs if good(r := rows.get(d)) and test(r)]


def one(c, what):
    if len(c) != 1:
        die("%d %s descriptors%s" % (len(c), what, "".join(" %#x" % d for d, _ in c)))
    return c[0]


def post(payload):
    req = urllib.request.Request(URL, method="POST",
        data=SOAP.format(b64=base64.b64encode(payload).decode()).encode(),
        headers={"Content-Type": "text/xml; charset=utf-8",
                 "SOAPAction": ACTION,
                 "User-Agent": "PlayReady PC SDK v3.0"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8", "replace")


def primary(xml):
    for el in ET.fromstring(xml).iter():
        if el.tag.rsplit("}", 1)[-1] == "primaryPayload" and el.text:
            return base64.b64decode(el.text)
    raise ValueError("no primaryPayload in the response")


# ------------------------------------------------------------------------ stages

def cmd_hwid():
    d, r = one(pick("hwid", scan(),
                    lambda r: r["stable"] and r["nz"] and 1 <= r["n"] <= 512), "get-HWID")
    wr(HWID, bytes.fromhex(r["h"]))
    rec("hwid", d)
    print("[+] hwid    desc=%#x len=%d" % (d, r["n"]))


def cmd_payload():
    hwid = need(HWID, "hwid")
    lim = len(hwid) + 2252
    d, _ = one(pick("payload", scan(),
                    lambda r: r["n"] == r["n2"] and r["seeddiff"] and 1024 <= r["n"] <= lim,
                    hwid=hwid.hex()), "build-payload")
    p = dump("payload", d, hwid=hwid.hex()) or die("dump failed for desc %#x" % d)
    wr(REQ, p)
    rec("payload", d)
    print("[+] payload desc=%#x len=%d seed=%s" % (d, len(p), p[-16:].hex()))


def cmd_activate():
    p = need(REQ, "payload")
    try:
        resp = primary(post(p))
    except Exception as e:
        die(str(e))
    wr(RESP, resp)
    print("[+] response %d bytes" % len(resp))


def cmd_decrypt():
    req = need(REQ, "payload")
    need(RESP, "activate")
    seed, resp = req[-16:], os.path.abspath(RESP)
    d, _ = one(pick("decrypt", scan(), lambda r: r["prkf"],
                    resp=resp, seed=seed.hex()), "decrypt")
    out = dump("decrypt", d, resp=resp, seed=seed.hex()) or die("dump failed for desc %#x" % d)
    k = out.find(b"PRKF")
    if k < 0:
        die("no PRKF in decrypted output")
    wr(BLA, out[k:])
    rec("decrypt", d)
    print("[+] decrypt desc=%#x -> %s (%d bytes)" % (d, BLA, len(out) - k))

    o = {}
    if os.path.exists(OFF):
        with open(OFF) as f:
            o = json.load(f)
    if {"hwid", "payload", "decrypt"} <= set(o):
        print("\npython prkf_gen.py --hwid-offset %#x --payload-offset %#x "
              "--decrypt-offset %#x" % (o["hwid"], o["payload"], o["decrypt"]))


MODES = {"hwid": cmd_hwid, "payload": cmd_payload,
         "activate": cmd_activate, "decrypt": cmd_decrypt}


def main():
    if child():
        return 0
    if len(sys.argv) != 2 or sys.argv[1].lower() not in MODES:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    os.makedirs(WORK, exist_ok=True)
    MODES[sys.argv[1].lower()]()
    return 0


if __name__ == "__main__":
    sys.exit(main())
