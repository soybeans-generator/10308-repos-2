# wbcall.py - Warbird call layer, and the child process tool.py spawns.
# One JSON object per line on stdout. No HTTP.
#
#   census                        descriptor census, cached by DLL sha256
#   build RVA JSON                call with 2.py's 0x44 block
#   sweepbuild IDENT IDXCSV       the same over an index list, one row per call
#   dec RVA RESP SEED VAR         call with 3.py's 0x3C block
#   sweepdec RESP SEED VAR IDXCSV the same over an index list
#
# VAR selects how the response and seed are presented:
#   0  input=resp     in_len=len     out_len=len-8
#   1  input=resp     in_len=len-8   out_len=len-8
#   2  input=resp[8:] in_len=len-8   out_len=len-8
#   3  input=resp     in_len=len     out_len=len
#
# Every mode initialises COM and runs the op=1 segment pass first: a fresh
# LoadLibraryW leaves the segment-encrypted .rdata/.data tables as ciphertext,
# and the routines read them.
#
# The only file this writes is testdata/tool-state.json, the census cache.

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys

if sys.platform != "win32":
    sys.exit("wbcall.py: Windows x64 only")
if struct.calcsize("P") != 8:
    sys.exit("wbcall.py: 64-bit Python required")

import ctypes

DLL = r"C:\Windows\SYSTEM32\Windows.Media.Protection.PlayReady.dll"
OUT = "testdata"
STATE = os.path.join(OUT, "tool-state.json")
WB = 0xB9
EXTRA = 2252


def u32(b, o):
    return int.from_bytes(b[o:o + 4], "little")


def u16(b, o):
    return int.from_bytes(b[o:o + 2], "little")


def pe_sections(fb):
    if len(fb) < 0x40:
        return []
    lf = u32(fb, 0x3C)
    if lf + 84 > len(fb):
        return []
    n, opt = u16(fb, lf + 6), u16(fb, lf + 20)
    p = lf + 24 + opt
    if n <= 0 or p + 40 * n > len(fb):
        return []
    out = []
    for _ in range(n):
        out.append((u32(fb, p + 12), u32(fb, p + 16), u32(fb, p + 20)))
        p += 40
    return out


def census(fb, maxsize=0x200000):
    heaps, segs = [], []
    for va, rs, rp in pe_sections(fb):
        hi = min(rp + rs, len(fb))
        if hi - rp < 0x40:
            continue
        b = fb[rp:hi]
        for off in range(0, len(b) - 0x40, 4):
            size = u32(b, off + 0x20)
            if size < 0x40 or size > maxsize or off + size > len(b):
                continue
            if hashlib.sha256(b[off + 0x20:off + size]).digest() != b[off:off + 0x20]:
                continue
            if size == 0xF0:
                if u32(b, off + 0x38) & 0x0FFFFFFF >= 0x20:
                    heaps.append([va + off,
                                  u32(b, off + 0x34) & 0x0FFFFFFF,
                                  u32(b, off + 0x38) & 0x0FFFFFFF])
            else:
                segs.append([va + off, u32(b, off + 0x2C), u32(b, off + 0x30)])

    def dedup(v):
        seen, out = set(), []
        for d in v:
            if d[0] not in seen:
                seen.add(d[0])
                out.append(d)
        out.sort()
        return out

    return dedup(heaps), dedup(segs)


def census_cached(dll):
    with open(dll, "rb") as f:
        fb = f.read()
    sha = hashlib.sha256(fb).hexdigest()
    st = {}
    if os.path.exists(STATE):
        try:
            with open(STATE) as f:
                st = json.load(f)
        except Exception:
            st = {}
    c = st.get("census:" + sha)
    if c:
        return sha, c["heaps"], c["segs"]
    heaps, segs = census(fb)
    st["census:" + sha] = {"heaps": heaps, "segs": segs}
    try:
        os.makedirs(OUT, exist_ok=True)
        with open(STATE, "w") as f:
            json.dump(st, f)
    except OSError:
        pass
    return sha, heaps, segs


class R2(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("operation", ctypes.c_uint64), ("segment", ctypes.c_void_p),
                ("status", ctypes.c_void_p), ("nonce", ctypes.c_void_p),
                ("input_len", ctypes.c_uint32), ("input", ctypes.c_void_p),
                ("output_len", ctypes.c_void_p), ("output", ctypes.c_void_p),
                ("version", ctypes.c_void_p)]


class R3(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("operation", ctypes.c_uint64), ("segment", ctypes.c_void_p),
                ("status", ctypes.c_void_p), ("input", ctypes.c_void_p),
                ("input_len", ctypes.c_uint32), ("seed", ctypes.c_void_p),
                ("output", ctypes.c_void_p), ("output_len", ctypes.c_void_p)]


def load(dll):
    k32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
    k32.SetErrorMode(0x8003)
    k32.LoadLibraryW.argtypes = [ctypes.c_wchar_p]
    k32.LoadLibraryW.restype = ctypes.c_void_p
    base = k32.LoadLibraryW(dll)
    if not base:
        raise OSError(ctypes.get_last_error(), f"LoadLibraryW({dll!r})")
    ntq = ctypes.WinDLL("ntdll.dll").NtQuerySystemInformation
    ntq.argtypes = [ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p]
    ntq.restype = ctypes.c_int32
    return base, ntq


def op1(base, ntq, addr, rel, num):
    a = bytearray(0x30)
    struct.pack_into("<Q", a, 0x00, 1)
    struct.pack_into("<Q", a, 0x08, addr)
    struct.pack_into("<Q", a, 0x10, base)
    struct.pack_into("<Q", a, 0x18, base)
    struct.pack_into("<Q", a, 0x20, (base + rel) & 0xFFFFFFFFFFFFFFFF)
    struct.pack_into("<Q", a, 0x28, num)
    buf = ctypes.create_string_buffer(bytes(a), 0x30)
    return ntq(WB, ctypes.byref(buf), 0x30, None) & 0xFFFFFFFF


def prepare(base, ntq, segs):
    ok, first = 0, None
    for va, rel, num in segs:
        st = op1(base, ntq, base + va, rel, num)
        if st == 0:
            ok += 1
        elif first is None:
            first = f"0x{va:x}:{st:#010x}"
    return ok, len(segs), first


def payload(base, ntq, rva, ident):
    span = len(ident) + EXTRA
    seeded = ident + b"\x00" * (span - len(ident))
    src = (ctypes.c_ubyte * max(len(ident), 1)).from_buffer_copy(ident or b"\x00")
    work = (ctypes.c_ubyte * span).from_buffer_copy(seeded)
    out = (ctypes.c_ubyte * span)()
    n = ctypes.c_uint32(span)
    st = ctypes.c_uint32(0)
    ver = ctypes.c_uint32(0)
    r = R2()
    r.operation = 3
    r.segment = base + rva
    r.status = ctypes.addressof(st)
    r.nonce = ctypes.addressof(src)
    r.input_len = len(ident)
    r.input = ctypes.addressof(work)
    r.output_len = ctypes.addressof(n)
    r.output = ctypes.addressof(out)
    r.version = ctypes.addressof(ver)
    nt = ntq(WB, ctypes.byref(r), ctypes.sizeof(r), None) & 0xFFFFFFFF
    got = int(n.value)
    m = got if 0 < got <= span else span
    body = bytes(work)[:m]
    if not any(body):
        body = bytes(out)[:m]
    return {"st": int(st.value) & 0xFFFFFFFF, "nt": nt, "n": got, "payload": body}


def shape(resp, var):
    n = len(resp)
    return {
        0: (resp, n, max(n - 8, 0)),
        1: (resp, max(n - 8, 0), max(n - 8, 0)),
        2: (resp[8:], max(n - 8, 0), max(n - 8, 0)),
        3: (resp, n, n),
    }.get(var, (resp, n, max(n - 8, 0)))


def decrypt(base, ntq, rva, resp, seed, var=0):
    body, inlen, want = shape(resp, var)
    cap = max(len(resp), want, 0x1000) + 0x40
    inp = (ctypes.c_ubyte * max(len(body), 1)).from_buffer_copy(body or b"\x00")
    sd = (ctypes.c_ubyte * 16).from_buffer_copy(seed)
    out = (ctypes.c_ubyte * cap)()
    n = ctypes.c_uint32(want)
    st = ctypes.c_uint32(0)
    r = R3()
    r.operation = 3
    r.segment = base + rva
    r.status = ctypes.addressof(st)
    r.input = ctypes.addressof(inp)
    r.input_len = inlen
    r.seed = ctypes.addressof(sd)
    r.output = ctypes.addressof(out)
    r.output_len = ctypes.addressof(n)
    nt = ntq(WB, ctypes.byref(r), ctypes.sizeof(r), None) & 0xFFFFFFFF
    got = int(n.value)
    m = got if 0 < got <= cap else want
    return {"st": int(st.value) & 0xFFFFFFFF, "nt": nt, "n": got,
            "out": bytes(out)[:m]}


def emit(o):
    sys.stdout.write(json.dumps(o) + "\n")
    sys.stdout.flush()


def idxs(csv, n):
    for tok in csv.split(","):
        try:
            i = int(tok)
        except ValueError:
            continue
        if 0 <= i < n:
            yield i


def main(argv):
    ap = argparse.ArgumentParser(description="Warbird call layer.")
    ap.add_argument("--dll", default=DLL)
    ap.add_argument("mode", choices=("census", "build", "sweepbuild",
                                     "dec", "sweepdec"))
    ap.add_argument("a", nargs="?", default="0")
    ap.add_argument("b", nargs="?", default="")
    ap.add_argument("c", nargs="?", default="")
    ap.add_argument("d", nargs="?", default="")
    a = ap.parse_args(argv)

    sha, heaps, segs = census_cached(a.dll)
    emit({"census": [len(heaps), len(segs)], "sha": sha})
    if a.mode == "census":
        return 0

    base, ntq = load(a.dll)
    ok, n, err = prepare(base, ntq, segs)
    emit({"prep": [ok, n, err]})

    if a.mode == "build":
        for tag, hx in json.loads(a.b).items():
            p = payload(base, ntq, int(a.a, 16), bytes.fromhex(hx))
            emit({"tag": tag, "st": p["st"], "nt": p["nt"], "n": p["n"],
                  "payload": p["payload"].hex()})
        return 0

    if a.mode == "sweepbuild":
        ident = bytes.fromhex(a.a)
        for i in idxs(a.b, len(heaps)):
            rva = heaps[i][0]
            p = payload(base, ntq, rva, ident)
            emit({"i": i, "d": rva, "st": p["st"], "nt": p["nt"],
                  "n": p["n"], "head": p["payload"][:20].hex()})
        return 0

    if a.mode == "dec":
        r = decrypt(base, ntq, int(a.a, 16), bytes.fromhex(a.b),
                    bytes.fromhex(a.c), int(a.d) if a.d else 0)
        emit({"st": r["st"], "nt": r["nt"], "n": r["n"], "out": r["out"].hex()})
        return 0

    resp, seed, var = bytes.fromhex(a.a), bytes.fromhex(a.b), int(a.c)
    for i in idxs(a.d, len(heaps)):
        rva = heaps[i][0]
        r = decrypt(base, ntq, rva, resp, seed, var)
        o = r["out"]
        emit({"i": i, "v": var, "d": rva, "st": r["st"], "nt": r["nt"],
              "n": r["n"], "len": len(o), "prkf": o.find(b"PRKF"),
              "chai": o.find(b"CHAI"), "head": o[:8].hex()})
    return 0


if __name__ == "__main__":
    code = 0
    try:
        code = main(sys.argv[1:])
    except SystemExit:
        raise
    except BaseException as e:  # noqa: BLE001
        emit({"err": f"{type(e).__name__}: {e}"})
        code = 1
    sys.exit(code)
