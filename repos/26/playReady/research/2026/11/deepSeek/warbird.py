# warbird.py
"""PlayReady Warbird layer. Imported by wb-find.py; executed directly it is the
probe child (WARBIRD_CHILD holds a JSON spec), because a wrong descriptor can
fault and a fault is a SEH exception that kills the process.

op=1  segment decrypt, used to build a decrypted image in this process. One
      fresh LoadLibrary per heap block: the kernel honours only the first such
      decrypt per image. A failure is an NTSTATUS, never a crash, which is why
      the image pass is safe to run over all blocks.
op=3  WbHeapExecuteCall, the three activation routines. Never use these as probe
      blocks: a routine that is not the one you are calling reads those fields
      as its own and dereferences garbage.

STATUS is 0x10 bytes; a 4-byte buffer is overrun by 12 and kills the process on
the NEXT call, which is why blame used to land one descriptor late.
"""
import ctypes
import hashlib
import json
import os
import struct
import subprocess
import sys
import time

if os.name != "nt" or ctypes.sizeof(ctypes.c_void_p) != 8:
    raise SystemExit("warbird.py: Windows x64 only")

DLL = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32",
                   "Windows.Media.Protection.PlayReady.dll")

STATUS = 0x10
SCRATCH = 0x100
T = 600
PAY = b"\xcc\x08\x00\x00"          # 2252, appended to the hwid by the payload call


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def g32(buf):
    return struct.unpack_from("<I", bytes(buf), 0)[0]


def die(m):
    raise SystemExit("[-] " + m)


def sections(fb):
    lf = u32(fb, 0x3C)
    n = struct.unpack_from("<H", fb, lf + 6)[0]
    p = lf + 24 + struct.unpack_from("<H", fb, lf + 20)[0]
    return [struct.unpack_from("<IIII", fb, p + 40 * i + 8) for i in range(n)]


def pe_size(fb):
    return u32(fb, u32(fb, 0x3C) + 24 + 56)


def scan(fb=None):
    """Digest-validated descriptors: +0x00 sha256 over [0x20,size), +0x20 size,
    +0x24 marker 0xFFFFFF00, +0x28 desc_va, +0x2C relocs, +0x30 count,
    +0x34/+0x38 code rva/len (heap-exec only). 0xF0 = heap-exec."""
    fb = fb or open(DLL, "rb").read()
    out = {}
    for va, vs, rs, rp in sections(fb):
        seg = fb[rp:rp + rs]
        pos = 0
        while True:
            i = seg.find(b"\x00\xff\xff\xff", pos)
            if i < 0:
                break
            pos = i + 1
            o = i - 0x24
            if o < 0 or o % 4 or o + 0x28 > len(seg):
                continue
            size = u32(seg, o + 0x20)
            if size < 0x40 or size > 0x200000 or o + size > len(seg):
                continue
            if hashlib.sha256(seg[o + 0x20:o + size]).digest() != seg[o:o + 32]:
                continue
            d = {"va": va + o, "off": rp + o, "size": size,
                 "desc": u32(seg, o + 0x28) & 0x0FFFFFFF,
                 "rel": u32(seg, o + 0x2C), "num": u32(seg, o + 0x30),
                 "rva": u32(seg, o + 0x34) & 0x0FFFFFFF if size == 0xF0 else 0,
                 "ln": u32(seg, o + 0x38) & 0x0FFFFFFF if size == 0xF0 else 0}
            key = ("h", d["desc"]) if size == 0xF0 else ("s", d["va"])
            out.setdefault(key, d)
    return list(out.values())


def heaps(ds):
    return [d for d in ds if d["size"] == 0xF0 and d["desc"] and d["ln"]]


def dll_sha():
    with open(DLL, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.LoadLibraryW.restype = ctypes.c_void_p
_k32.LoadLibraryW.argtypes = [ctypes.c_wchar_p]
_k32.VirtualProtect.restype = ctypes.c_int
_k32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]


def base():
    b = _k32.LoadLibraryW(DLL)
    if not b:
        raise OSError("LoadLibraryW %s: %d" % (DLL, ctypes.get_last_error()))
    return b


def free(b):
    _k32.FreeLibrary(ctypes.c_void_p(b))


def vp(addr, size, prot):
    old = ctypes.c_uint32()
    if not _k32.VirtualProtect(ctypes.c_void_p(addr), size, prot, ctypes.byref(old)):
        return None
    return old.value


_nt = ctypes.WinDLL("ntdll").NtQuerySystemInformation
_nt.restype = ctypes.c_long
_nt.argtypes = [ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p]


def wb(a, n):
    return _nt(0xB9, ctypes.byref(a), n, None) & 0xFFFFFFFF


def di_call(b, sac, rel, num):
    """op=1, 0x30 bytes: op, descriptor, image, image, image+relocs, count."""
    a = (ctypes.c_ubyte * 0x30)()
    struct.pack_into("<6Q", a, 0, 1, sac, b, b, b + rel, num)
    return wb(a, 0x30)


def make_desc(hdr, params, rva, size):
    """Synthetic 1-entry segment descriptor for (rva, size)."""
    b = bytearray(0x100)
    b[0x00:0x40] = hdr
    b[0x40:0xF0] = params
    struct.pack_into("<I", b, 0x20, 0x100)
    struct.pack_into("<I", b, 0xF0, 1)
    struct.pack_into("<I", b, 0xF4, 0x30C)
    struct.pack_into("<I", b, 0xF8, rva)
    struct.pack_into("<I", b, 0xFC, size)
    b[0x00:0x20] = hashlib.sha256(bytes(b[0x20:0x100])).digest()
    return bytes(b)


def dec_image(say=print):
    """Decrypt every segment span and every heap block into one image."""
    fb = open(DLL, "rb").read()
    ds = scan(fb)
    segs = [d for d in ds if d["size"] != 0xF0]
    hs = heaps(ds)
    size = pe_size(fb)
    if not segs:
        die("no segment descriptors in %s" % DLL)

    t0 = time.time()
    b = base()
    for s in segs:
        di_call(b, b + s["va"], s["rel"], s["num"])
    img = bytearray(ctypes.string_at(b, size))
    free(b)
    say("    segments %d  %.1fs" % (len(segs), time.time() - t0))

    slot, rel, num = segs[0]["va"], segs[0]["rel"], segs[0]["num"]
    done = same = bad = 0
    t0 = time.time()
    for n, h in enumerate(hs, 1):
        if h["off"] + 0xF0 > len(fb) or h["rva"] + h["ln"] > size:
            bad += 1
            continue
        lib = base()
        try:
            sac = lib + slot
            hdr = ctypes.string_at(sac, 0x40)
            params = fb[h["off"] + 0x40:h["off"] + 0xF0]
            desc = make_desc(hdr, params, h["rva"], h["ln"])
            old = vp(sac, 0x100, 0x40)
            if old is None:
                bad += 1
                continue
            ctypes.memmove(sac, desc, 0x100)
            vp(sac, 0x100, old)
            rc = di_call(lib, sac, rel, num)
            got = ctypes.string_at(lib + h["rva"], h["ln"])
        finally:
            free(lib)
        if rc:
            bad += 1
        elif got == bytes(img[h["rva"]:h["rva"] + h["ln"]]):
            same += 1
        else:
            img[h["rva"]:h["rva"] + h["ln"]] = got
            done += 1
        if n % 200 == 0:
            say("    blocks %d/%d  changed %d  same %d  err %d  %.1fs"
                % (n, len(hs), done, same, bad, time.time() - t0))
    say("    blocks %d  changed %d  same %d  err %d  %.1fs"
        % (len(hs), done, same, bad, time.time() - t0))
    return bytes(img)


def pay_candidates(img, ds):
    return [h for h in heaps(ds)
            if PAY in img[h["rva"]:h["rva"] + h["ln"]]]


class HwidReq(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("op", ctypes.c_uint64), ("seg", ctypes.c_void_p),
                ("status", ctypes.c_void_p), ("ctx", ctypes.c_void_p),
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


def call_hwid(b, d):
    st = (ctypes.c_ubyte * STATUS)()
    ctx = (ctypes.c_ubyte * SCRATCH)()
    n = (ctypes.c_ubyte * STATUS)()
    struct.pack_into("<I", n, 0, 512)
    out = (ctypes.c_ubyte * 512)()
    nt = wb(HwidReq(3, b + d, ctypes.addressof(st), ctypes.addressof(ctx), 1,
                    ctypes.addressof(out), ctypes.addressof(n)), 0x34)
    m = min(g32(n), 512)
    return nt, g32(st), bytes(out[:m]), m


def call_payload(b, d, hwid):
    sz = len(hwid) + 2252
    st = (ctypes.c_ubyte * STATUS)()
    nonce = (ctypes.c_ubyte * max(len(hwid), 1))()
    ctypes.memmove(nonce, hwid, len(hwid))
    buf = (ctypes.c_ubyte * sz)()
    ctypes.memmove(buf, hwid, len(hwid))
    out = (ctypes.c_ubyte * sz)()
    n, ver = (ctypes.c_ubyte * STATUS)(), (ctypes.c_ubyte * STATUS)()
    struct.pack_into("<I", n, 0, sz)
    nt = wb(PayloadReq(3, b + d, ctypes.addressof(st), ctypes.addressof(nonce),
                       len(hwid), ctypes.addressof(buf), ctypes.addressof(n),
                       ctypes.addressof(out), ctypes.addressof(ver)), 0x44)
    m = g32(n)
    return nt, g32(st), bytes(buf[:m]) if 0 < m <= sz else b"", m


def call_decrypt(b, d, resp, seed):
    sz = len(resp)
    st = (ctypes.c_ubyte * STATUS)()
    buf = (ctypes.c_ubyte * sz)()
    ctypes.memmove(buf, resp, sz)
    out = (ctypes.c_ubyte * sz)()
    key = (ctypes.c_ubyte * 16)()
    ctypes.memmove(key, seed, 16)
    n = (ctypes.c_ubyte * STATUS)()
    struct.pack_into("<I", n, 0, max(sz - 8, 0))
    nt = wb(DecryptReq(3, b + d, ctypes.addressof(st), ctypes.addressof(buf), sz,
                       ctypes.addressof(key), ctypes.addressof(out),
                       ctypes.addressof(n)), 0x3C)
    m = g32(n)
    return nt, g32(st), bytes(out[:m]) if 0 <= m <= sz else b"", m


def child():
    raw = os.environ.get("WARBIRD_CHILD")
    if not raw:
        return False
    s = json.loads(raw)
    try:
        b = base()
    except OSError as e:
        print(json.dumps({"d": 0, "e": str(e)}), flush=True)
        return True
    hwid = bytes.fromhex(s.get("hwid", ""))
    seed = bytes.fromhex(s.get("seed", ""))
    resp = open(s["resp"], "rb").read() if s.get("resp") else b""

    for d in s["descs"]:
        print(json.dumps({"d": d, "b": 1}), flush=True)
        row = {"d": d}
        try:
            if s["mode"] == "hwid":
                nt, st, data, n = call_hwid(b, d)
                row.update(nt=nt, st=st, n=n, nz=bool(any(data)), h=data.hex())
                if not nt and not st and 1 <= n <= 512 and any(data):
                    a = call_hwid(b, d)
                    row["stable"] = (a[0], a[1], a[3], a[2]) == (nt, st, n, data)
            elif s["mode"] == "payload":
                nt, st, data, n = call_payload(b, d, hwid)
                row.update(nt=nt, st=st, n=n)
                if not nt and not st and 1024 <= n <= len(hwid) + 2252:
                    a = call_payload(b, d, hwid)
                    row["n2"] = a[3]
                    row["seeddiff"] = a[3] == n and a[2][-16:] != data[-16:]
            else:
                nt, st, data, n = call_decrypt(b, d, resp, seed)
                row.update(nt=nt, st=st, n=n, prkf=0 <= data.find(b"PRKF") < 64)
        except Exception as e:
            row["e"] = repr(e)
        print(json.dumps(row), flush=True)
    return True


def run(mode, descs, **kw):
    env = dict(os.environ, WARBIRD_CHILD=json.dumps(dict(mode=mode, descs=descs, **kw)))
    try:
        out = subprocess.run([sys.executable, "-S", os.path.abspath(__file__)],
                             env=env, capture_output=True, timeout=T).stdout
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


def probe(mode, group, stop=None, **kw):
    """One child run per fault; a fault is a dead process, not a verdict."""
    ids = [d["desc"] for d in group]
    rows, todo, dead, t0 = {}, list(ids), 0, time.time()
    while todo:
        got = run(mode, todo, **kw)
        e = got.get(0, {}).get("e")
        if e:
            die(e)
        cut = None
        for n, d in enumerate(todo):
            r = got.get(d)
            if r is None or r.get("b"):
                cut = n
                break
            rows[d] = r
            if stop and ok(r) and stop(r):
                print("    hit %#x  %d calls  %.1fs" %
                      (d, len(rows), time.time() - t0), flush=True)
                return rows, dead
        if cut is None:
            break
        rows[todo[cut]] = {"d": todo[cut], "dead": True}
        dead += 1
        print("    %#x faulted  %d/%d  %.1fs" %
              (todo[cut], len(rows), len(ids), time.time() - t0), flush=True)
        todo = todo[cut + 1:]
    print("    %d calls  %d faults  %.1fs"
          % (len(rows), dead, time.time() - t0), flush=True)
    return rows, dead


def ok(r):
    return bool(r) and not r.get("e") and not r.get("dead") \
        and r.get("nt") == 0 and r.get("st") == 0


if __name__ == "__main__":
    if child():
        sys.exit(0)
    print("warbird.py is imported by wb-find.py; run that instead", file=sys.stderr)
    sys.exit(2)
# warbird.py
