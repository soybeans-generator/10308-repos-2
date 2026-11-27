# find_offs.py -- discover the three Warbird heap-exec offsets of THIS DLL build
# for make_prkf.py. Census on disk, chunked probe children (missing row = fault,
# retried as a single), oracles:
#   build    status clean twice + payload starts with hwid + payloads differ
#            (random seed) -- then confirmed against the Activation service
#   decrypt  response + seed -> output contains PRKF/CHAI
#   hwid     deterministic non-empty output across two calls
#
# python find_offs.py

import base64
import ctypes
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.request
from ctypes import byref, sizeof, addressof, c_void_p, c_uint32, c_ulonglong, Structure

DLL = r"C:\Windows\System32\Windows.Media.Protection.PlayReady.dll"
URL = "https://test.playready.microsoft.com/Service/Provisioning"

CHUNK, CHILD_T, SINGLE_T = 64, 300, 120
BUILD_SCRATCH, RESPONSE_TRAILER, HWID_BUF = 2252, 8, 512
HTTP_T, SOAP_ACTION = 60.0, "http://schemas.microsoft.com/PlayReady/ActivationService/v1/Activate"

CHALLENGE = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <Activate xmlns="http://schemas.microsoft.com/PlayReady/ActivationService/v1">
      <challenge>
        <clientSdkVersion>4.6.0.0</clientSdkVersion>
        <clientSdkType>2</clientSdkType>
        <platform>9</platform>
        <tid>1</tid>
        <payload>
          <primaryPayload>{}</primaryPayload>
        </payload>
      </challenge>
    </Activate>
  </soap:Body>
</soap:Envelope>"""

FAKE_HWID = bytes.fromhex("2EF1223EB61D59DB01260000000000000001000000000002000000010001000100967D000046414B452E50522E4944")

ntqsi = ctypes.windll.ntdll.NtQuerySystemInformation
LoadLibraryW = ctypes.WinDLL("kernel32").LoadLibraryW
LoadLibraryW.restype = c_void_p


class HwidReq(Structure):     # 1.py
    _pack_ = 1
    _fields_ = [("operation", c_ulonglong), ("segment", c_void_p), ("status", c_void_p),
                ("oem_context", c_void_p), ("type", c_uint32), ("output", c_void_p),
                ("output_len", c_void_p)]


class BuildReq(Structure):    # 2.py
    _pack_ = 1
    _fields_ = [("operation", c_ulonglong), ("segment", c_void_p), ("status", c_void_p),
                ("nonce", c_void_p), ("input_len", c_uint32), ("input", c_void_p),
                ("output_len", c_void_p), ("output", c_void_p), ("version", c_void_p)]


class DecryptReq(Structure):  # 3.py
    _pack_ = 1
    _fields_ = [("operation", c_ulonglong), ("segment", c_void_p), ("status", c_void_p),
                ("input", c_void_p), ("input_len", c_uint32), ("seed", c_void_p),
                ("output", c_void_p), ("output_len", c_void_p)]


# ------------------------------------------------------------------- census
def le16(b, o): return int.from_bytes(b[o:o+2], "little")
def le32(b, o): return int.from_bytes(b[o:o+4], "little")


def scan_descs(fb, secs):
    """Heap-exec descriptors (size 0xF0, SHA-256-covered); va is their own RVA."""
    out = []
    for va, vs, rs, rp in secs:
        b = fb[rp:rp+rs]
        for off in range(0, max(0, len(b) - 0xF0), 4):
            if le32(b, off+0x20) == 0xF0 and \
               hashlib.sha256(b[off+0x20:off+0xF0]).digest() == b[off:off+32]:
                out.append(va + off)
    return sorted(set(out))


# ------------------------------------------------------------------- probes
def probe(base, mode, off, hwid, resp, seed):
    """One descriptor, one or two calls; rows are (ntstatus, status, buffer, len)."""
    rows = []
    if mode == "build":
        n = len(hwid) + BUILD_SCRATCH
        for _ in range(2):
            buf = (ctypes.c_ubyte * n).from_buffer_copy(hwid + bytes(BUILD_SCRATCH))
            dummy = (ctypes.c_ubyte * n)()
            out_len, status = c_uint32(n), c_uint32(0)
            nonce = (ctypes.c_ubyte * len(hwid)).from_buffer_copy(hwid)
            req = BuildReq(3, base+off, addressof(status), addressof(nonce), len(hwid),
                           addressof(buf), addressof(out_len), addressof(dummy), addressof(c_uint32(0)))
            rc = ntqsi(0xB9, byref(req), sizeof(req), None)
            rows.append((rc & 0xFFFFFFFF, status.value & 0xFFFFFFFF, bytes(buf), out_len.value))
    elif mode == "hwid":
        for _ in range(2):
            out, out_len, status = (ctypes.c_ubyte * HWID_BUF)(), c_uint32(HWID_BUF), c_uint32(0)
            req = HwidReq(3, base+off, addressof(status), None, 1,
                          addressof(out), addressof(out_len))
            rc = ntqsi(0xB9, byref(req), sizeof(req), None)
            rows.append((rc & 0xFFFFFFFF, status.value & 0xFFFFFFFF, bytes(out), out_len.value))
    else:  # dec
        out = (ctypes.c_ubyte * len(resp))()
        out_len, status = c_uint32(len(resp) - RESPONSE_TRAILER), c_uint32(0)
        src = (ctypes.c_ubyte * len(resp)).from_buffer_copy(resp)
        key = (ctypes.c_ubyte * 16).from_buffer_copy(seed)
        req = DecryptReq(3, base+off, addressof(status), addressof(src), len(resp),
                         addressof(key), addressof(out), addressof(out_len))
        rc = ntqsi(0xB9, byref(req), sizeof(req), None)
        rows.append((rc & 0xFFFFFFFF, status.value & 0xFFFFFFFF, bytes(out), out_len.value))
    return rows


def child(spec):
    base = LoadLibraryW(DLL)
    hwid = bytes.fromhex(spec["hwid"]) if spec.get("hwid") else None
    resp = bytes.fromhex(spec["resp"]) if spec.get("resp") else None
    seed = bytes.fromhex(spec["seed"]) if spec.get("seed") else None
    if base:
        for va in spec["descs"]:
            try:
                r = probe(base, spec["mode"], va, hwid, resp, seed)
                print(json.dumps({"d": va,
                                   "nt": [c[0] for c in r], "st": [c[1] for c in r],
                                   "b": [c[2].hex() for c in r], "l": [c[3] for c in r]}), flush=True)
            except Exception:
                pass                                    # faulted: child exits with no row
    print(json.dumps({"k": "end"}), flush=True)


# ------------------------------------------------------------------- parent
def run_probe(mode, vas, **spec):
    rows, faults = {}, []

    def spawn(sub, timeout):
        env = dict(os.environ, PRKF_FIND=json.dumps(dict(mode=mode, descs=sub, **spec)))
        try:
            p = subprocess.run([sys.executable, __file__], env=env,
                               capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return {}
        got = {}
        for line in p.stdout.splitlines():
            try:
                r = json.loads(line)
            except Exception:
                continue
            if "d" in r:
                got[r["d"]] = r
        return got

    for lo in range(0, len(vas), CHUNK):
        sub = vas[lo:lo+CHUNK]
        rows.update(spawn(sub, CHILD_T))
        for va in sub:                                  # dead chunk: retry as singles
            if va in rows:
                continue
            one = spawn([va], SINGLE_T)
            if va in one:
                rows.update(one)
            else:
                faults.append(va)                       # dies alone: its verdict is "not it"
        print(f"[*] {mode}: {lo+len(sub)}/{len(vas)}  faults {len(faults)}",
              file=sys.stderr)
    return rows, faults


def activate(payload):
    body = CHALLENGE.format(base64.b64encode(payload).decode()).encode()
    req = urllib.request.Request(URL, data=body, method="POST",
                                 headers={"Content-Type": "text/xml; charset=utf-8",
                                          "SOAPAction": f'"{SOAP_ACTION}"'})
    data = urllib.request.urlopen(req, timeout=HTTP_T).read()
    m = re.search(r"<(?:\w+:)?primaryPayload>(.*?)</(?:\w+:)?primaryPayload>",
                  data.decode("utf-8", "replace"), re.S)
    if not m:
        return None, data[:300]
    return base64.b64decode(re.sub(r"\s", "", m.group(1))), b""


def main():
    fb = open(DLL, "rb").read()
    lf = le32(fb, 0x3C)
    secs = [(le32(fb, p+12), le32(fb, p+8), le32(fb, p+16), le32(fb, p+20))
            for p in [lf + 24 + le16(fb, lf+20) + 40*i for i in range(le16(fb, lf+6))]]
    vas = scan_descs(fb, secs)
    print(f"[*] {DLL}: {len(vas)} heap-exec descriptors")
    if not vas:
        sys.exit("[-] no heap-exec descriptors found")

    hwid = open("hwid.bin", "rb").read() if os.path.exists("hwid.bin") else FAKE_HWID

    # 1) builder: clean status twice, payload starts with hwid, payloads differ
    rows, _ = run_probe("build", vas, hwid=hwid.hex())
    cands = []
    for va, r in rows.items():
        if any(r["nt"]) or any(r["st"]) or len(r["b"]) != 2:
            continue
        p1, p2 = bytes.fromhex(r["b"][0]), bytes.fromhex(r["b"][1])
        m = r["l"][0] if 0 < r["l"][0] <= len(p1) else len(p1)
        if p1[:len(hwid)] == hwid and p2[:len(hwid)] == hwid and p1[:m] != p2[:m]:
            cands.append((va, p1[:m]))
    print(f"[*] builder candidates: {[hex(v) for v, _ in cands]}")
    if not cands:
        sys.exit("[-] no builder candidate (2.py contract mismatch on this build)")

    # 2) the service confirms the builder
    builder = resp = p = None
    for va, pay in cands:
        try:
            blob, why = activate(pay)
        except Exception as e:
            sys.exit(f"[-] activation POST failed ({e}) - fix URL in both scripts")
        if blob:
            builder, resp, p = va, blob, pay
            break
        print(f"[*] 0x{va:x} rejected: {why!r}")
    if builder is None:
        sys.exit("[-] no candidate survived the service")
    print(f"[+] OFF_BUILD  = 0x{builder:x}   response {len(resp)}B  seed {p[-16:].hex()}")

    # 3) decryptor: PRKF/CHAI oracle
    rows, _ = run_probe("dec", vas, resp=resp.hex(), seed=p[-16:].hex())
    decs = [va for va, r in rows.items()
            if not any(r["nt"]) and not any(r["st"])
            and (b"PRKF" in bytes.fromhex(r["b"][0]) or b"CHAI" in bytes.fromhex(r["b"][0]))]
    if not decs:
        sys.exit("[-] nothing decrypted the response to a PRKF")
    print(f"[+] OFF_DECRYPT = 0x{decs[0]:x}"
          + (f"  (also: {[hex(v) for v in decs[1:]]}" if len(decs) > 1 else ""))

    # 4) hwid segment: deterministic non-empty output
    rows, _ = run_probe("hwid", vas)
    hws = [va for va, r in rows.items()
           if not any(r["nt"]) and not any(r["st"]) and 0 < r["l"][0] <= HWID_BUF
           and r["b"][0] == r["b"][1] and any(bytes.fromhex(r["b"][0]))]
    for va in hws:
        print(f"[+] OFF_HWID   = 0x{va:x}")
    extra = f" --off-hwid 0x{hws[0]:x}" if hws else ""

    print(f"\npython make_prkf.py --off-build 0x{builder:x} --off-decrypt 0x{decs[0]:x}{extra}")


if __name__ == "__main__":
    if "PRKF_FIND" in os.environ:
        child(json.loads(os.environ["PRKF_FIND"]))
    else:
        main()
