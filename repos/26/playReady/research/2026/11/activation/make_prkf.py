# make_prkf.py -- PlayReady Activation -> msprcore.bla (PRKF)
#
# hwid (hwid.bin or fake) --[build segment]--> primary payload (AES-CTR, seed =
# unencrypted last 16 bytes) --POST--> response --[decrypt segment, seed]--> PRKF
#
# Warbird segments dispatched via NtQuerySystemInformation(SystemControlFlowTransition
# = 0xB9), operation = 3 (heap exec).

import argparse
import ctypes
import os
import urllib.request
from ctypes import byref, sizeof, c_void_p, c_uint32, c_ulonglong, Structure

OUT              = r"testdata\Cache\msprcore.bla"
HWID_LEN         = 32       # fake hwid size, used only if hwid.bin is missing
BUILD_SCRATCH    = 2252     # scratch past the hwid the build segment wants
RESPONSE_TRAILER = 8
TIMEOUT          = 60.0
SOAP_ACTION      = "http://schemas.microsoft.com/PlayReady/ActivationService/v1/Activate"

ntqsi = ctypes.windll.ntdll.NtQuerySystemInformation
LoadLibraryW = ctypes.WinDLL("kernel32").LoadLibraryW
LoadLibraryW.restype = c_void_p


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


def build_payload(off, base, hwid):
    n = len(hwid) + BUILD_SCRATCH
    buf = (ctypes.c_ubyte * n).from_buffer_copy(hwid + bytes(BUILD_SCRATCH))
    out = (ctypes.c_ubyte * n)()
    out_len, nonce, ver, status = c_uint32(n), (ctypes.c_ubyte * len(hwid)).from_buffer_copy(hwid), c_uint32(0), c_uint32(0)

    req = BuildReq(3, base + off, byref(status), byref(nonce), len(hwid),
                  byref(buf), byref(out_len), byref(out), byref(ver))
    warbird(req)
    if status.value != 0:
        raise OSError(f"build segment status 0x{status.value:08X}")
    m = out_len.value if 0 < out_len.value <= n else n
    return bytes(buf[:m])      # payload is written into the input buffer


def decrypt_response(off, base, response, seed):
    if len(seed) != 16:
        raise ValueError("seed must be the last 16 bytes of the payload")
    out_len = c_uint32(len(response) - RESPONSE_TRAILER)
    out = (ctypes.c_ubyte * len(response))()
    src = (ctypes.c_ubyte * len(response)).from_buffer_copy(response)
    key = (ctypes.c_ubyte * 16).from_buffer_copy(seed)
    status = c_uint32(0)

    req = DecryptReq(3, base + off, byref(status), byref(src), len(response),
                     byref(key), byref(out), byref(out_len))
    warbird(req)
    if status.value != 0:
        raise OSError(f"decrypt segment status 0x{status.value:08X}")
    m = out_len.value if 0 < out_len.value <= len(out) else len(out)
    return bytes(out[:m])


def main():
    ap = argparse.ArgumentParser(description="PlayReady Activation -> msprcore.bla (PRKF)")
    ap.add_argument("--dll", required=True, help="PlayReady library with the Warbird segments")
    ap.add_argument("--off-build", required=True, type=lambda v: int(v, 0), help="RVA: build-activation-payload segment")
    ap.add_argument("--off-decrypt", required=True, type=lambda v: int(v, 0), help="RVA: decrypt-response segment")
    ap.add_argument("--url", required=True, help="PlayReady Activation service endpoint")
    args = ap.parse_args()

    if not os.path.exists("hwid.bin"):                 # fake hwid, service accepts it
        open("hwid.bin", "wb").write(os.urandom(HWID_LEN))
    hwid = open("hwid.bin", "rb").read()
    print(f"[*] hwid: {len(hwid)} bytes ({hwid[:8].hex()}...)")

    base = LoadLibraryW(args.dll)
    if not base:
        raise OSError(f"cannot load {args.dll}")

    payload = build_payload(args.off_build, base, hwid)
    print(f"[*] payload: {len(payload)} bytes, seed {payload[-16:].hex()}")

    response = urllib.request.urlopen(urllib.request.Request(
        args.url, data=payload, method="POST",
        headers={"Content-Type": "application/octet-stream", "SOAPAction": f'"{SOAP_ACTION}"'}),
        timeout=TIMEOUT).read()
    print(f"[*] response: {len(response)} bytes")

    blob = decrypt_response(args.off_decrypt, base, response, payload[-16:])
    i = blob.find(b"PRKF")
    if i < 0:
        print("[!] PRKF magic not found, writing full blob")

    os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
    with open(OUT, "wb") as f:
        f.write(blob[i:] if i >= 0 else blob)
    print(f"[+] wrote {OUT}")


if __name__ == "__main__":
    main()
