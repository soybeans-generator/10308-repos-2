# prkf_gen.py -- generate msprcore.bla (PRKF) via Warbird calls + Activation POST
# usage: python prkf_gen.py --hwid-offset 0x.. --payload-offset 0x.. --decrypt-offset 0x..

import argparse
import base64
import ctypes
import sys
import urllib.request
import xml.etree.ElementTree as ET

URL = "https://activation.playready.microsoft.com/PlayReady/ACT/Activation.asmx"
SOAP_ACTION = '"http://schemas.microsoft.com/PlayReady/ActivationService/v1/Activate"'
DLL_NAME = "Windows.Media.Protection.PlayReady.dll"

SOAP_TEMPLATE = """<?xml version="1.0" encoding="utf-8"?>
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


class GetHwid(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("op", ctypes.c_uint64), ("segment", ctypes.c_void_p),
                ("status", ctypes.c_void_p), ("oem", ctypes.c_void_p),
                ("type", ctypes.c_uint32), ("output", ctypes.c_void_p),
                ("output_len", ctypes.c_void_p)]


class BuildPayload(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("op", ctypes.c_uint64), ("segment", ctypes.c_void_p),
                ("status", ctypes.c_void_p), ("nonce", ctypes.c_void_p),
                ("input_len", ctypes.c_uint32), ("input", ctypes.c_void_p),
                ("output_len", ctypes.c_void_p), ("output", ctypes.c_void_p),
                ("version", ctypes.c_void_p)]


class DecryptResp(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("op", ctypes.c_uint64), ("segment", ctypes.c_void_p),
                ("status", ctypes.c_void_p), ("input", ctypes.c_void_p),
                ("input_len", ctypes.c_uint32), ("seed", ctypes.c_void_p),
                ("output", ctypes.c_void_p), ("output_len", ctypes.c_void_p)]


ntqsi = ctypes.WinDLL("ntdll").NtQuerySystemInformation
ntqsi.restype = ctypes.c_long
ntqsi.argtypes = [ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32,
                  ctypes.POINTER(ctypes.c_uint32)]


def wb(req):
    st = ntqsi(0xB9, ctypes.byref(req), ctypes.sizeof(req), None)
    if st != 0:
        sys.exit(f"WB syscall failed: 0x{st & 0xFFFFFFFF:08X}")


def get_hwid(off, dll):
    status = ctypes.c_uint32(0)
    size = ctypes.c_uint32(512)
    out = (ctypes.c_ubyte * 512)()
    wb(GetHwid(op=3, segment=dll + off, status=ctypes.addressof(status),
               oem=None, type=1, output=ctypes.addressof(out),
               output_len=ctypes.addressof(size)))
    return bytes(out[:size.value])


def build_payload(off, dll, hwid):
    status = ctypes.c_uint32(0)
    n = len(hwid) + 2252
    buf = (ctypes.c_ubyte * n)(*hwid)
    out = (ctypes.c_ubyte * n)()
    outlen = ctypes.c_uint32(n)
    nonce = (ctypes.c_ubyte * len(hwid))(*hwid)
    ver = ctypes.c_uint32(0)
    wb(BuildPayload(op=3, segment=dll + off, status=ctypes.addressof(status),
                    nonce=ctypes.addressof(nonce), input_len=len(hwid),
                    input=ctypes.addressof(buf),
                    output_len=ctypes.addressof(outlen),
                    output=ctypes.addressof(out),
                    version=ctypes.addressof(ver)))
    return bytes(buf[:outlen.value])


def decrypt_resp(off, dll, resp, key):
    status = ctypes.c_uint32(0)
    n = len(resp)
    inp = (ctypes.c_ubyte * n)(*resp)
    k = (ctypes.c_ubyte * 16)(*key)
    out = (ctypes.c_ubyte * n)()
    outlen = ctypes.c_uint32(n - 8)
    wb(DecryptResp(op=3, segment=dll + off, status=ctypes.addressof(status),
                    input=ctypes.addressof(inp), input_len=n,
                    seed=ctypes.addressof(k), output=ctypes.addressof(out),
                    output_len=ctypes.addressof(outlen)))
    return bytes(out[:outlen.value])


def soap_post(payload):
    body = SOAP_TEMPLATE.format(b64=base64.b64encode(payload).decode()).encode()
    req = urllib.request.Request(URL, data=body, method="POST", headers={
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": SOAP_ACTION,
        "User-Agent": "PlayReady PC SDK v3.0"})
    return urllib.request.urlopen(req, timeout=60).read().decode()


def extract_primary_payload(xml_text):
    for el in ET.fromstring(xml_text).iter():
        if el.tag.rsplit("}", 1)[-1] == "primaryPayload":
            return base64.b64decode(el.text)
    sys.exit("primaryPayload not found in response")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hwid-offset", type=lambda s: int(s, 0), required=True)
    ap.add_argument("--payload-offset", type=lambda s: int(s, 0), required=True)
    ap.add_argument("--decrypt-offset", type=lambda s: int(s, 0), required=True)
    a = ap.parse_args()

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.GetModuleHandleW.restype = ctypes.c_void_p
    k32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
    k32.LoadLibraryW.restype = ctypes.c_void_p
    k32.LoadLibraryW.argtypes = [ctypes.c_wchar_p]
    dll = k32.GetModuleHandleW(DLL_NAME) or k32.LoadLibraryW(DLL_NAME)
    if not dll:
        sys.exit(f"{DLL_NAME} not found")

    hwid = get_hwid(a.hwid_offset, dll)
    payload = build_payload(a.payload_offset, dll, hwid)
    seed = payload[-16:]

    resp_xml = soap_post(payload)
    resp = extract_primary_payload(resp_xml)

    prkf = decrypt_resp(a.decrypt_offset, dll, resp, seed)
    with open("msprcore.bla", "wb") as f:
        f.write(prkf)
    print(f"[+] msprcore.bla written ({len(prkf)} bytes)")


if __name__ == "__main__":
    main()
