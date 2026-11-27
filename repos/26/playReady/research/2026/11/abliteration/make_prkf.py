# make_prkf.py -- PlayReady Activation -> testdata\Cache\msprcore.bla (PRKF)
#
# hwid (hwid.bin) -> [build seg 2.py] primary payload (AES-CTR, unencrypted
# 16-byte seed = last 16 bytes) -> base64 into SOAP Challenge -> POST ->
# SOAP reply -> extract base64 response blob -> [decrypt seg 3.py, seed] -> PRKF
#
# Warbird heap-exec segments via NtQuerySystemInformation(SystemControlFlowTransition
# = 0xB9), operation = 3.

import base64
import ctypes
import os
import re
import urllib.request
from ctypes import byref, sizeof, addressof, c_void_p, c_uint32, c_ulonglong, Structure

DLL = r"C:\Windows\System32\Windows.Media.Protection.PlayReady.dll"
# !!! These three RVAs must be Googler's dumped values for YOUR DLL build.
#     The 0x5ac0/0x5780 defaults below are unverified placeholders.
OFF_HWID    = 0x0          # 1.py: device-hwid segment (0 = use hwid.bin)
OFF_BUILD   = 0x5ac0        # 2.py: primary-payload builder
OFF_DECRYPT = 0x5780        # 3.py: response decryptor
URL         = "https://test.playready.microsoft.com/Service/Provisioning"

HWID_LEN         = 32
BUILD_SCRATCH    = 2252     # 2.py: input buffer size past the hwid
RESPONSE_TRAILER = 8        # 3.py: 8-byte wrapper around the encrypted blob
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

# Security Explorations fake identity (fake_pr_id.zip README) - well-formed
# HW/MF system-id the Activation service is proven to accept end-to-end.
FAKE_HWID = bytes.fromhex(
    "2E"
    "F1223EB61D59DB01"
    "26"
    "00000000000000010000"
    "00000002000000010001"
    "000100967D0000"
    "46414B452E50522E4944"   # "FAKE.PR.ID"
)

ntqsi = ctypes.windll.ntdll.NtQuerySystemInformation
LoadLibraryW = ctypes.WinDLL("kernel32").LoadLibraryW
LoadLibraryW.restype = c_void_p

HR_NAMES = {
    0x80090008: "NTE_BAD_ALGID (invalid algorithm specified)",
    0x8004C3F6: "DRM_E_HWID_ERROR",
    0x8004B823: "MSPR_E_HARDWAREID_MISMATCH",
}


class HwidReq(Structure):     # 1.py layout
    _pack_ = 1
    _fields_ = [("operation", c_ulonglong), ("segment", c_void_p), ("status", c_void_p),
                ("oem_context", c_void_p), ("type", c_uint32), ("output", c_void_p),
                ("output_len", c_void_p)]


class BuildReq(Structure):    # 2.py layout
    _pack_ = 1
    _fields_ = [("operation", c_ulonglong), ("segment", c_void_p), ("status", c_void_p),
                ("nonce", c_void_p), ("input_len", c_uint32), ("input", c_void_p),
                ("output_len", c_void_p), ("output", c_void_p), ("version", c_void_p)]


class DecryptReq(Structure):  # 3.py layout
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


def get_hwid(base):
    out = (ctypes.c_ubyte * 512)()
    out_len = c_uint32(512)
    status = c_uint32(0)
    req = HwidReq(3, base + OFF_HWID, addressof(status), None, 1,
                  addressof(out), addressof(out_len))
    warbird(req)
    check(status, "hwid segment")
    n = out_len.value if 0 < out_len.value <= 512 else 512
    return bytes(out[:n])


def build_payload(base, hwid):
    n = len(hwid) + BUILD_SCRATCH
    buf = (ctypes.c_ubyte * n).from_buffer_copy(hwid + bytes(BUILD_SCRATCH))
    out = (ctypes.c_ubyte * n)()
    out_len = c_uint32(n)
    nonce = (ctypes.c_ubyte * len(hwid)).from_buffer_copy(hwid)
    ver, status = c_uint32(0), c_uint32(0)
    req = BuildReq(3, base + OFF_BUILD, addressof(status), addressof(nonce),
                  len(hwid), addressof(buf), addressof(out_len), addressof(out),
                  addressof(ver))
    warbird(req)
    check(status, "build segment")
    m = out_len.value if 0 < out_len.value <= n else n
    return bytes(buf[:m])      # payload is written back into the input buffer


def decrypt_response(base, response, seed):
    if len(seed) != 16:
        raise ValueError("seed must be the last 16 bytes of the payload")
    out_len = c_uint32(len(response) - RESPONSE_TRAILER)
    out = (ctypes.c_ubyte * len(response))()
    src = (ctypes.c_ubyte * len(response)).from_buffer_copy(response)
    key = (ctypes.c_ubyte * 16).from_buffer_copy(seed)
    status = c_uint32(0)
    req = DecryptReq(3, base + OFF_DECRYPT, addressof(status), addressof(src),
                    len(response), addressof(key), addressof(out), addressof(out_len))
    warbird(req)
    check(status, "decrypt segment")
    m = out_len.value if 0 < out_len.value <= len(out) else len(out)
    return bytes(out[:m])


def activate(payload: bytes) -> bytes:
    body = CHALLENGE.format(base64.b64encode(payload).decode()).encode()
    req = urllib.request.Request(
        URL, data=body, method="POST",
        headers={"Content-Type": "text/xml; charset=utf-8",
                 "SOAPAction": f'"{SOAP_ACTION}"'})
    data = urllib.request.urlopen(req, timeout=TIMEOUT).read()
    if not data.startswith(b"<"):
        return data                                  # already raw binary
    text = data.decode("utf-8", "replace")
    for m in re.finditer(r">([A-Za-z0-9+/=\r\n]{100,})<", text):
        try:
            blob = base64.b64decode(re.sub(r"\s", "", m.group(1)), validate=True)
        except Exception:
            continue
        if len(blob) > 8:
            return blob                              # activate-response binary
    raise RuntimeError("no base64 response data in SOAP reply:\n" + text[:500])


def main():
    base = LoadLibraryW(DLL)
    if not base:
        raise OSError(f"cannot load {DLL}")
    print(f"[*] dll: {DLL} ({os.path.getsize(DLL):,} bytes @ 0x{base:x})")

    if os.path.exists("hwid.bin"):
        hwid = open("hwid.bin", "rb").read()
        print(f"[*] cached hwid: {len(hwid)} bytes")
    elif OFF_HWID:
        hwid = get_hwid(base)
        open("hwid.bin", "wb").write(hwid)
        print(f"[*] device hwid: {len(hwid)} bytes (cached)")
    else:
        hwid = FAKE_HWID
        open("hwid.bin", "wb").write(hwid)
        print(f"[*] fake hwid (FAKE.PR.ID): {len(hwid)} bytes (cached)")

    payload = build_payload(base, hwid)
    print(f"[*] payload: {len(payload)} bytes, seed {payload[-16:].hex()}")

    response = activate(payload)
    print(f"[*] response binary: {len(response)} bytes")

    blob = decrypt_response(base, response, payload[-16:])
    i = blob.find(b"PRKF")
    if i < 0:
        raise RuntimeError("PRKF magic not found in decrypted response")

    os.makedirs(r"testdata\Cache", exist_ok=True)
    with open(r"testdata\Cache\msprcore.bla", "wb") as f:
        f.write(blob[i:])
    print("[+] wrote testdata\\Cache\\msprcore.bla")


if __name__ == "__main__":
    main()
