# make_prkf.py -- PlayReady Activation -> testdata\Cache\msprcore.bla (PRKF)
#
#   python make_prkf.py --off-build 0x... --off-decrypt 0x... --off-hwid 0x...
#
# (1) hwid segment (1.py)  : device hwid -> cached to hwid.bin for next runs
# (2) build segment (2.py) : hwid -> primary payload (AES-CTR; UNENCRYPTED
#                            16-byte seed = last 16 bytes of the payload)
# (3) us                   : POST base64(payload) in the SOAP Activate challenge
# (4) parse <primaryPayload> from the XML response, base64-decode it
# (5) decrypt segment (3.py): response + seed -> plaintext blob
# (6) carve PRKF           -> testdata\Cache\msprcore.bla

import argparse
import base64
import ctypes
import os
import re
import urllib.request
from ctypes import byref, sizeof, addressof, c_void_p, c_uint32, c_ulonglong, Structure

DLL = r"C:\Windows\System32\Windows.Media.Protection.PlayReady.dll"
URL = "https://test.playready.microsoft.com/Service/Provisioning"

BUILD_SCRATCH    = 2252  # 2.py: input buffer tail past the hwid
RESPONSE_TRAILER = 8     # 3.py: wrapper bytes stripped from decrypted output
TIMEOUT          = 60.0
SOAP_ACTION      = "http://schemas.microsoft.com/PlayReady/ActivationService/v1/Activate"

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

ntqsi = ctypes.windll.ntdll.NtQuerySystemInformation
LoadLibraryW = ctypes.WinDLL("kernel32").LoadLibraryW
LoadLibraryW.restype = c_void_p

HR_NAMES = {
    0x80090008: "NTE_BAD_ALGID (invalid algorithm specified)",
    0x8004C3F6: "DRM_E_HWID_ERROR",
    0x8004B823: "MSPR_E_HARDWAREID_MISMATCH",
}


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


def warbird(req):
    st = ntqsi(0xB9, byref(req), sizeof(req), None)
    if st != 0:
        raise OSError(f"NtQuerySystemInformation -> 0x{st & 0xFFFFFFFF:08X}")


def check(status, what):
    if status.value != 0:
        v = status.value & 0xFFFFFFFF
        raise OSError(f"{what} status 0x{v:08X} ({HR_NAMES.get(v, 'unmapped HR')})")


def get_hwid(base, off):
    out = (ctypes.c_ubyte * 512)()
    out_len = c_uint32(512)
    status = c_uint32(0)
    req = HwidReq(3, base + off, addressof(status), None, 1,
                  addressof(out), addressof(out_len))
    warbird(req)
    check(status, "hwid segment")
    n = out_len.value if 0 < out_len.value <= 512 else 512
    return bytes(out[:n])


def build_payload(base, off, hwid):
    n = len(hwid) + BUILD_SCRATCH
    buf = (ctypes.c_ubyte * n).from_buffer_copy(hwid + bytes(BUILD_SCRATCH))
    out = (ctypes.c_ubyte * n)()
    out_len = c_uint32(n)
    nonce = (ctypes.c_ubyte * len(hwid)).from_buffer_copy(hwid)
    ver, status = c_uint32(0), c_uint32(0)
    req = BuildReq(3, base + off, addressof(status), addressof(nonce),
                  len(hwid), addressof(buf), addressof(out_len),
                  addressof(out), addressof(ver))
    warbird(req)
    check(status, "build segment")
    m = out_len.value if 0 < out_len.value <= n else n
    return bytes(buf[:m])      # payload is written back into the input buffer


def decrypt_response(base, off, response, seed):
    if len(seed) != 16:
        raise ValueError("seed must be the last 16 bytes of the payload")
    out_len = c_uint32(len(response) - RESPONSE_TRAILER)
    out = (ctypes.c_ubyte * len(response))()
    src = (ctypes.c_ubyte * len(response)).from_buffer_copy(response)
    key = (ctypes.c_ubyte * 16).from_buffer_copy(seed)
    status = c_uint32(0)
    req = DecryptReq(3, base + off, addressof(status), addressof(src),
                    len(response), addressof(key), addressof(out),
                    addressof(out_len))
    warbird(req)
    check(status, "decrypt segment")
    m = out_len.value if 0 < out_len.value <= len(out) else len(out)
    return bytes(out[:m])


def activate(payload):
    body = CHALLENGE.format(base64.b64encode(payload).decode()).encode()
    req = urllib.request.Request(
        URL, data=body, method="POST",
        headers={"Content-Type": "text/xml; charset=utf-8",
                 "SOAPAction": f'"{SOAP_ACTION}"'})
    data = urllib.request.urlopen(req, timeout=TIMEOUT).read()
    text = data.decode("utf-8", "replace")
    m = re.search(r"<(?:\w+:)?primaryPayload>(.*?)</(?:\w+:)?primaryPayload>",
                  text, re.S)
    if not m:
        raise RuntimeError(f"no primaryPayload in response:\n{text[:500]}")
    return base64.b64decode(re.sub(r"\s", "", m.group(1)))


def main():
    ap = argparse.ArgumentParser(description="PlayReady Activation -> msprcore.bla (PRKF)")
    ap.add_argument("--off-hwid", type=lambda v: int(v, 0), required=True,
                    help="1.py hwid segment RVA")
    ap.add_argument("--off-build", type=lambda v: int(v, 0), required=True,
                    help="2.py build segment RVA")
    ap.add_argument("--off-decrypt", type=lambda v: int(v, 0), required=True,
                    help="3.py decrypt segment RVA")
    args = ap.parse_args()

    base = LoadLibraryW(DLL)
    if not base:
        raise OSError(f"cannot load {DLL}")

    if os.path.exists("hwid.bin"):                # cached: same identity + PRKF pair
        hwid = open("hwid.bin", "rb").read()
        print(f"[*] cached hwid: {len(hwid)} bytes")
    else:
        hwid = get_hwid(base, args.off_hwid)
        open("hwid.bin", "wb").write(hwid)
        print(f"[*] device hwid: {len(hwid)} bytes (cached)")

    payload = build_payload(base, args.off_build, hwid)
    print(f"[*] payload: {len(payload)} bytes, seed {payload[-16:].hex()}")

    response = activate(payload)
    print(f"[*] response blob: {len(response)} bytes")

    blob = decrypt_response(base, args.off_decrypt, response, payload[-16:])
    i = blob.find(b"PRKF")
    if i < 0:
        raise RuntimeError("PRKF magic not found in decrypted response")

    os.makedirs(r"testdata\Cache", exist_ok=True)
    with open(r"testdata\Cache\msprcore.bla", "wb") as f:
        f.write(blob[i:])
    print("[+] wrote testdata\\Cache\\msprcore.bla")


if __name__ == "__main__":
    main()
