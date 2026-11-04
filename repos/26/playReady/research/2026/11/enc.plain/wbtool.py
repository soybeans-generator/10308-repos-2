# wbtool.py — feed OBF as `in`, prv[0x20:0x40] as read-only `out`; then MAP -> pubkey
import ctypes, hashlib, json, os, struct

DLL = r"C:\Windows\SYSTEM32\Windows.Media.Protection.PlayReady.dll"
IMG, LOG = "wbtool_img.bin", "wbtool.txt"
RWX = 0x40

MAP = {int(k): v for k, v in json.load(open("oracle_map.json")).items()}
INV = {v: k for k, v in MAP.items()}
PRV = open("extracted.enc.prv", "rb").read()
PUB = open("extracted.enc.pub", "rb").read()[-64:]
PX = int.from_bytes(PUB[:32], "big"); PY = int.from_bytes(PUB[32:], "big")
NN = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

OBF = bytes.fromhex("69ef7582608af8d0df0fb4b515449be5"
                    "a8d0c903741cbf3353be70eb460521f4")
CODES = [0x4300F0, 0x529250, 0x4A80E0, 0x2B8550, 0x337E30, 0x3B8190]
CL = {"t3": 0x843720, "t4": 0x862ee0, "s1": 0x882920, "s2": 0x8a23f0,
      "s3": 0x8c2470, "s4": 0x8e2210, "s5": 0x902180, "s6": 0x922230}

lf = open(LOG, "w", encoding="utf-8")
def L(s=""):
    lf.write(str(s) + "\n"); lf.flush()

img = open(IMG, "rb").read(); fb = open(DLL, "rb").read()
u32 = lambda b, o: struct.unpack_from("<I", b, o)[0]
e = u32(fb, 0x3C)
nsec = struct.unpack_from("<H", fb, e + 6)[0]
optsz = struct.unpack_from("<H", fb, e + 20)[0]
sizeImg = u32(fb, e + 24 + 56)
p = e + 24 + optsz
secs = []
for _ in range(nsec):
    vs, va, rs, rp = struct.unpack_from("<IIII", fb, p + 8)
    secs.append((va, rs, rp)); p += 40

def foff(rva):
    for va, rs, rp in secs:
        if va <= rva < va + rs:
            return rp + (rva - va)
    return None

seg, desc_of, seen = [], {}, set()
for va, rs, rp in secs:
    b = fb[rp:rp+rs]
    for off in range(0, max(0, len(b) - 0x40), 4):
        size = u32(b, off + 0x20)
        if size < 0x40 or size > 0x200000 or off + size > len(b):
            continue
        if hashlib.sha256(b[off+0x20:off+size]).digest() != b[off:off+32]:
            continue
        if size == 0xF0:                    # heap-exec: stays ciphertext
            desc_of[u32(b, off+0x34) & 0x0FFFFFFF] = va + off
            continue
        for k in range((size - 0xF4) // 0xC):
            o = off + 0xF4 + k*0xC
            rva, sz = u32(b, o+4), u32(b, o+8)
            if rva < 0x1000 or sz < 8 or rva + sz > sizeImg or rva in seen:
                continue
            seen.add(rva); seg.append((rva, sz))

keep = []
for r, s in seg:
    d = foff(r)
    if d is None or img[r:r+s] == fb[d:d+s]:
        continue
    keep.append((r, s))

k32 = ctypes.WinDLL("kernel32")
k32.LoadLibraryW.restype = ctypes.c_void_p
k32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong,
                               ctypes.POINTER(ctypes.c_ulong)]
k32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.ReadProcessMemory.restype = ctypes.c_int
nt = ctypes.WinDLL("ntdll")
Raw = nt.NtQuerySystemInformation
Raw.argtypes = [ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p]
Raw.restype = ctypes.c_long
base = k32.LoadLibraryW(DLL)
DUM = ctypes.c_ulong(0)
ME = ctypes.c_void_p(-1)

def rd(addr, n):
    if not addr or addr < 0x10000 or addr > 0x7FFFFFFFFFFF:
        return b""
    buf = ctypes.create_string_buffer(n)
    got = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(ME, ctypes.c_void_p(addr), buf, n, ctypes.byref(got)):
        return b""
    return buf.raw[:got.value]

def wr(rva, data):
    data = bytes(data)
    addr = ctypes.c_void_p(base + rva)
    span = (len(data) + 0xFFF) & ~0xFFF
    old = ctypes.c_ulong(0)
    if not k32.VirtualProtect(addr, span, RWX, ctypes.byref(old)):
        return False
    ctypes.memmove(addr, data, len(data))
    k32.VirtualProtect(addr, span, old.value, ctypes.byref(DUM))
    return True

nblk = sum(1 for r, s in keep if wr(r, img[r:r+s]))
L(f"base 0x{base:x}  segment blocks patched {nblk}  heap-exec left ciphertext")
L(f"OBF  {OBF.hex()}")
L("")

def onf(ep):
    er = struct.unpack_from("<Q", ctypes.string_at(ep, 8))[0]
    c = struct.unpack_from("<I", ctypes.string_at(er, 4))[0]
    addr = struct.unpack_from("<Q", ctypes.string_at(er + 0x10, 8))[0]
    L(f"FAULT 0x{c:08x} rva 0x{(addr - base) & 0xFFFFFFFF:x}")
    lf.flush(); os._exit(3)

VEH = ctypes.CFUNCTYPE(ctypes.c_long, ctypes.c_void_p)
kv = VEH(onf)
k32.AddVectoredExceptionHandler(1, kv)

def call(code, inb, outb):
    dv = desc_of.get(code)
    if dv is None:
        return None, None, "no descriptor"
    st = ctypes.create_string_buffer(0x40)
    ib = ctypes.create_string_buffer(bytes(inb), 0x40)
    ob = ctypes.create_string_buffer(bytes(outb), 0x40)
    a = ctypes.create_string_buffer(0x40)
    struct.pack_into("<Q", a, 0x00, 3)
    struct.pack_into("<Q", a, 0x08, base + dv)
    struct.pack_into("<Q", a, 0x10, ctypes.addressof(st))
    struct.pack_into("<Q", a, 0x18, ctypes.addressof(ib))
    struct.pack_into("<I", a, 0x20, 0x20)
    struct.pack_into("<Q", a, 0x24, ctypes.addressof(ob))
    struct.pack_into("<I", a, 0x2C, 0x20)
    rc = Raw(0xB9, ctypes.cast(a, ctypes.c_void_p), 0x30, None) & 0xFFFFFFFF
    return bytes(ib.raw)[:0x20], bytes(ob.raw)[:0x20], f"nt=0x{rc:08x} st={bytes(st.raw)[:4].hex()}"

def nibs(b, hi):
    return [(b[i >> 1] >> (4 if (i % 2 == 0) == hi else 0)) & 0xF for i in range(64)]
def pack(ns, hi):
    o = bytearray(32)
    for i in range(0, 64, 2):
        o[i >> 1] = (ns[i] << 4) | ns[i + 1] if hi else (ns[i + 1] << 4) | ns[i]
    return bytes(o)

from cryptography.hazmat.primitives.asymmetric import ec
def ours(b):
    k = int.from_bytes(b, "big")
    if not (0 < k < NN):
        return False
    pn = ec.derive_private_key(k, ec.SECP256R1()).public_key().public_numbers()
    return pn.x == PX and pn.y == PY

found = False
def chain(tag, v):
    global found
    if len(v) != 0x20:
        return
    for cl, cbase in CL.items():
        blk = [img[cbase + i*16: cbase + i*16 + 16] for i in range(64)]
        if any(len(x) != 16 or max(x) > 15 or len(set(x)) != 16 for x in blk):
            continue
        for hi in (True, False):
            n = nibs(v, hi)
            mapped = pack([blk[i][n[i]] for i in range(64)], hi)
            cands = [("raw", v),
                     ("map", pack([MAP[x] for x in nibs(v, hi)], hi)),
                     ("inv", pack([INV[x] for x in nibs(v, hi)], hi)),
                     ("bij", mapped),
                     ("bij>map", pack([MAP[x] for x in nibs(mapped, hi)], hi)),
                     ("bij>inv", pack([INV[x] for x in nibs(mapped, hi)], hi))]
            for cname, c in cands:
                for o2, cc in (("fwd", c), ("rev", c[::-1])):
                    if ours(cc):
                        L(f"*** MATCH {tag} {cl} hi={hi} {cname} {o2} ***")
                        L(f"    input {v.hex()}")
                        L(f"    plain {cc.hex()}")
                        open("extracted.enc.plain", "wb").write(cc)
                        L("    written extracted.enc.plain")
                        found = True

SECOND = PRV[0x20:0x40]
FIRST = PRV[0x00:0x20]
PAIRS = [("in=OBF out=prvS", OBF, SECOND),
         ("in=OBF out=prvF", OBF, FIRST),
         ("in=prvS out=OBF", SECOND, OBF),
         ("in=prvF out=prvS", FIRST, SECOND)]

calls = 0
for code in CODES:
    L(f"=== 0x{code:06x}")
    for tag, ib, ob in PAIRS:
        mut, oback, info = call(code, ib, ob)
        calls += 1
        if mut is None:
            L(f"  {tag}: {info}"); continue
        L(f"  {tag}  {info}")
        L(f"     in-mutated {mut.hex()}   out-unchanged {(oback == ob)}")
        chain(f"0x{code:06x} {tag}", mut)
    L("")

L(f"calls {calls}")
L("*** VALIDATED ***" if found else "no match")
lf.close()
