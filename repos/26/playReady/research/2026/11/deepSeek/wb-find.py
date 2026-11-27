# wbfind.py -- locate the three PlayReady activation WB descriptors, then run the
# activation chain and write testdata/msprcore.bla.
#   python wbfind.py scan    list heap descriptors (desc_va, code rva, payload constant)
#   python wbfind.py all     find -> activate -> decrypt -> msprcore.bla
#
# Descriptor (warbird.go): +0x00 sha256 over [0x20,size), +0x20 size (0xF0 = heap-exec),
# +0x28 desc_va (the value op=3 is handed), +0x34/+0x38 code rva/len tagged 0xF0000000.

import base64
import ctypes
import hashlib
import json
import os
import struct
import subprocess
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

DLL = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32",
                   "Windows.Media.Protection.PlayReady.dll")
WORK = "testdata"
HWID = os.path.join(WORK, "hwid.bin")
REQ = os.path.join(WORK, "activation_request.bin")
RESP = os.path.join(WORK, "activation_response.bin")
BLA = os.path.join(WORK, "msprcore.bla")

URL = "https://activation.playready.microsoft.com/PlayReady/ACT/Activation.asmx"
ACTION = '"http://schemas.microsoft.com/PlayReady/ActivationService/v1/Activate"'

CHUNK, T_CHUNK, T_ONE = 64, 90, 20
PAY = (b"\xcc\x08\x00\x00", b"\xbc\x08\x00\x00")  # 2252 / 2236

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


# ------------------------------------------------------------------------- PE

def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def pe(fb):
    lf = u32(fb, 0x3C)
    n, opt = u16(fb, lf + 6), u16(fb, lf + 20)
    size, p, secs = u32(fb, lf + 24 + 56), lf + 24 + opt, []
    for i in range(n):
        q = p + 40 * i
        secs.append((u32(fb, q + 12), u32(fb, q + 8), u32(fb, q + 16), u32(fb, q + 20)))
    return size, secs


def at(secs, rva):
    for va, vs, rs, rp in secs:
        if va <= rva < va + rs:
            return rp + rva - va
    return None


# -------------------------------------------------------------- descriptor scan

def scan():
    fb = open(DLL, "rb").read()
    _, secs = pe(fb)
    found = {}
    for va, vs, rs, rp in secs:
        b = fb[rp:rp + rs]
        for off in range(0, len(b) - 0x40, 4):
            sz = u32(b, off + 0x20)
            if sz != 0xF0 or off + sz > len(b):
                continue
            if hashlib.sha256(b[off + 0x20:off + sz]).digest() != b[off:off + 32]:
                continue
            d = {"desc": u32(b, off + 0x28) & 0x0FFFFFFF,
                 "rva": u32(b, off + 0x34) & 0x0FFFFFFF,
                 "len": u32(b, off + 0x38) & 0x0FFFFFFF}
            fo = at(secs, d["rva"])
            code = fb[fo:fo + min(d["len"], 0x40000)] if fo is not None else b""
            d["pay"] = any(p in code for p in PAY)
            found.setdefault(d["desc"], d)
    return sorted(found.values(), key=lambda d: d["desc"])


# ----------------------------------------------------------------- op=3 ABI

class ReqHwid(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("op", ctypes.c_uint64), ("seg", ctypes.c_void_p),
                ("status", ctypes.c_void_p), ("oem", ctypes.c_void_p),
                ("type", ctypes.c_uint32), ("out", ctypes.c_void_p),
                ("out_len", ctypes.c_void_p)]


class ReqPayload(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("op", ctypes.c_uint64), ("seg", ctypes.c_void_p),
                ("status", ctypes.c_void_p), ("nonce", ctypes.c_void_p),
                ("in_len", ctypes.c_uint32), ("inp", ctypes.c_void_p),
                ("out_len", ctypes.c_void_p), ("out", ctypes.c_void_p),
                ("ver", ctypes.c_void_p)]


class ReqDecrypt(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("op", ctypes.c_uint64), ("seg", ctypes.c_void_p),
                ("status", ctypes.c_void_p), ("inp", ctypes.c_void_p),
                ("in_len", ctypes.c_uint32), ("seed", ctypes.c_void_p),
                ("out", ctypes.c_void_p), ("out_len", ctypes.c_void_p)]


if os.name == "nt":
    _nt = ctypes.WinDLL("ntdll").NtQuerySystemInformation
    _nt.restype = ctypes.c_long
    _nt.argtypes = [ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p]
else:
    _nt = None


def wb(r):
    return _nt(0xB9, ctypes.byref(r), ctypes.sizeof(r), None) & 0xFFFFFFFF


def base():
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.LoadLibraryW.restype = ctypes.c_void_p
    k.LoadLibraryW.argtypes = [ctypes.c_wchar_p]
    b = k.LoadLibraryW(DLL)
    if not b:
        raise OSError("LoadLibraryW(%s) -> %d" % (DLL, ctypes.get_last_error()))
    return b


def call_hwid(b, d):
    st, n = ctypes.c_uint32(0), ctypes.c_uint32(512)
    out = (ctypes.c_ubyte * 512)()
    nt = wb(ReqHwid(3, b + d, ctypes.addressof(st), None, 1,
                    ctypes.addressof(out), ctypes.addressof(n)))
    return nt, st.value, bytes(out[:min(n.value, 512)]), min(n.value, 512)


def call_payload(b, d, hwid):
    sz = len(hwid) + 2252
    inp, out = (ctypes.c_ubyte * sz)(*hwid), (ctypes.c_ubyte * sz)()
    n, nonce, ver = ctypes.c_uint32(sz), (ctypes.c_ubyte * len(hwid))(*hwid), ctypes.c_uint32(0)
    st = ctypes.c_uint32(0)
    nt = wb(ReqPayload(3, b + d, ctypes.addressof(st), ctypes.addressof(nonce), len(hwid),
                       ctypes.addressof(inp), ctypes.addressof(n), ctypes.addressof(out),
                       ctypes.addressof(ver)))
    m = n.value
    return nt, st.value, bytes(inp[:m]) if 0 < m <= sz else b"", m


def call_decrypt(b, d, resp, seed):
    sz = len(resp)
    inp, out = (ctypes.c_ubyte * sz)(*resp), (ctypes.c_ubyte * sz)()
    key, n, st = (ctypes.c_ubyte * 16)(*seed), ctypes.c_uint32(max(sz - 8, 0)), ctypes.c_uint32(0)
    nt = wb(ReqDecrypt(3, b + d, ctypes.addressof(st), ctypes.addressof(inp), sz,
                       ctypes.addressof(key), ctypes.addressof(out), ctypes.addressof(n)))
    m = n.value
    return nt, st.value, bytes(out[:m]) if 0 < m <= sz else b"", m


# ------------------------------------------------------------------ child probe
# Arbitrary descriptors fault, and a fault is a SEH exception that kills the process,
# so every probe runs in a child and a chunk that dies is retried one at a time.

def child():
    raw = os.environ.get("WBFIND_CHILD")
    if not raw:
        return False
    spec = json.loads(raw)
    b, mode = base(), spec["mode"]
    hwid, seed = bytes.fromhex(spec.get("hwid", "")), bytes.fromhex(spec.get("seed", ""))
    resp = open(spec["resp"], "rb").read() if spec.get("resp") else b""

    for d in spec["descs"]:
        row = {"d": d}
        try:
            if mode == "hwid":
                a, c = call_hwid(b, d), call_hwid(b, d)
                row.update(nt=a[0], st=a[1], n=a[3], stable=a == c, h=a[2].hex())
            elif mode == "payload":
                a, c = call_payload(b, d, hwid), call_payload(b, d, hwid)
                row.update(nt=a[0], st=a[1], n=a[3], n2=c[3])
                if a[2] and c[2]:
                    row["diff"] = sum(x != y for x, y in zip(a[2], c[2]))
                    row["dist"] = len(set(a[2][:-16]))
                if spec.get("dump"):
                    row["full"] = a[2].hex()
            elif mode == "decrypt":
                a = call_decrypt(b, d, resp, seed)
                row.update(nt=a[0], st=a[1], n=a[3], prkf=0 <= a[2].find(b"PRKF") < 64)
                if spec.get("dump"):
                    row["full"] = a[2].hex()
            else:
                row["e"] = "bad mode"
        except Exception as e:
            row["e"] = repr(e)
        print(json.dumps(row), flush=True)
    return True


def run(mode, descs, timeout=T_CHUNK, **kw):
    spec = dict(mode=mode, descs=descs, **kw)
    env = dict(os.environ, WBFIND_CHILD=json.dumps(spec))
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
        except Exception:
            pass
    return rows


def probe(mode, descs, **kw):
    rows = {}
    for i in range(0, len(descs), CHUNK):
        chunk = descs[i:i + CHUNK]
        got = run(mode, chunk, **kw)
        for d in chunk:
            if d not in got:
                got.update(run(mode, [d], timeout=T_ONE, **kw))
        rows.update({d: got.get(d, {"d": d, "dead": True}) for d in chunk})
        print("    %d/%d" % (i + len(chunk), len(descs)), flush=True)
    return rows


def dump(mode, desc, **kw):
    r = run(mode, [desc], timeout=T_ONE, dump=True, **kw).get(desc)
    return bytes.fromhex(r["full"]) if r and r.get("full") else None


# -------------------------------------------------------------------- finders

def find_hwid(descs):
    rows = probe("hwid", [d["desc"] for d in descs])
    good = [(d, r) for d in descs
            if (r := rows.get(d["desc"])) and not r.get("e") and not r.get("dead")
            and r.get("nt") == 0 and r.get("st") == 0
            and 1 <= r.get("n", 0) <= 512 and any(bytes.fromhex(r.get("h", "")))]
    return sorted(good, key=lambda x: (not x[1].get("stable"), x[1]["n"]))


def find_payload(descs, hwid):
    lim = len(hwid) + 2252
    for group in ([d for d in descs if d["pay"]], [d for d in descs if not d["pay"]]):
        if not group:
            continue
        rows = probe("payload", [d["desc"] for d in group], hwid=hwid.hex())
        good = [(d, r) for d in group
                if (r := rows.get(d["desc"])) and not r.get("e") and not r.get("dead")
                and r.get("nt") == 0 and r.get("st") == 0
                and r.get("n") == r.get("n2") and 1024 <= r.get("n", 0) <= lim
                and r.get("diff", 0) >= 64 and r.get("dist", 0) >= 200]
        if good:
            return sorted(good, key=lambda x: -x[1]["dist"])
    return []


def find_decrypt(descs, resp, seed):
    rows = probe("decrypt", [d["desc"] for d in descs], resp=resp, seed=seed.hex())
    return [(d, r) for d in descs
            if (r := rows.get(d["desc"])) and not r.get("e") and not r.get("dead")
            and r.get("nt") == 0 and r.get("st") == 0 and r.get("prkf")]


# -------------------------------------------------------------------- network

def post(payload):
    req = urllib.request.Request(URL, data=SOAP.format(
        b64=base64.b64encode(payload).decode()).encode(), method="POST", headers={
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": ACTION,
        "User-Agent": "PlayReady PC SDK v3.0"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8", "replace")


def primary(xml):
    for el in ET.fromstring(xml).iter():
        if el.tag.rsplit("}", 1)[-1] == "primaryPayload" and el.text:
            return base64.b64decode(el.text)
    raise ValueError("no primaryPayload in response")


# -------------------------------------------------------------------- commands

def wr(path, data):
    with open(path, "wb") as f:
        f.write(data)


def cmd_scan():
    descs = scan()
    for d in descs:
        print("%#010x  code %#010x+%#07x  %s" %
              (d["desc"], d["rva"], d["len"], "payload" if d["pay"] else ""))
    print("%d heap descriptors, %d with 0x8cc/0x8bc" %
          (len(descs), sum(d["pay"] for d in descs)))
    return 0


def cmd_all():
    os.makedirs(WORK, exist_ok=True)
    descs = scan()
    print("[*] %d heap descriptors" % len(descs))

    hw = find_hwid(descs)
    if hw:
        hd, hr = hw[0]
        hwid = bytes.fromhex(hr["h"])[:hr["n"]]
        print("[+] hwid    desc=%#x len=%d" % (hd["desc"], len(hwid)))
    else:
        hd, hwid = None, b"FAKE.PR.ID" + b"\0" * 22
        print("[!] no get-hwid match, synthetic hwid (%d bytes)" % len(hwid))
    wr(HWID, hwid)

    pays = find_payload(descs, hwid)
    if not pays:
        print("[-] no build-payload candidate")
        return 1

    payload = resp = pd = None
    for d, _ in pays:
        p = dump("payload", d["desc"], hwid=hwid.hex())
        if not p:
            continue
        print("[*] POST     desc=%#x len=%d seed=%s" % (d["desc"], len(p), p[-16:].hex()))
        try:
            resp = primary(post(p))
        except urllib.error.HTTPError as e:
            print("[!] HTTP %d: %s" % (e.code, e.read()[:200]))
            continue
        except Exception as e:
            print("[!] %s" % e)
            continue
        payload, pd = p, d
        break
    if payload is None:
        print("[-] no payload accepted")
        return 1
    print("[+] response %d bytes" % len(resp))
    wr(REQ, payload)
    wr(RESP, resp)

    seed = payload[-16:]
    dec = find_decrypt(descs, os.path.abspath(RESP), seed)
    if not dec:
        print("[-] no decrypt candidate")
        return 1
    dd = dec[0][0]
    out = dump("decrypt", dd["desc"], resp=os.path.abspath(RESP), seed=seed.hex())
    k = out.find(b"PRKF") if out else -1
    if k < 0:
        print("[-] no PRKF in decrypted output")
        return 1
    wr(BLA, out[k:])
    print("[+] %s (%d bytes)" % (BLA, len(out) - k))

    print("\noffsets (desc_va):")
    if hd:
        print("  --hwid-offset    %#x" % hd["desc"])
    print("  --payload-offset %#x" % pd["desc"])
    print("  --decrypt-offset %#x" % dd["desc"])
    if hd:
        print("\npython prkf_gen.py --hwid-offset %#x --payload-offset %#x "
              "--decrypt-offset %#x" % (hd["desc"], pd["desc"], dd["desc"]))
    return 0


def main():
    if os.name != "nt" or ctypes.sizeof(ctypes.c_void_p) != 8:
        print("Windows x64 only")
        return 1
    if child():
        return 0
    cmd = sys.argv[1].lower() if len(sys.argv) > 1 else "all"
    if cmd == "scan":
        return cmd_scan()
    if cmd == "all":
        return cmd_all()
    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main())
