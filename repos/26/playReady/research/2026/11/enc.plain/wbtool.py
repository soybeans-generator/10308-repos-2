# wbtool.py — 6 deobfuscators x 8 tables x nibble order x permutation, checked against pubkey
import ctypes, hashlib, os, struct, subprocess, sys

DLL = r"C:\Windows\SYSTEM32\Windows.Media.Protection.PlayReady.dll"
IMG = "wbtool_img.bin"
LOG = "wbtool.txt"
RWX = 0x40
CODES = [0x2B7E20, 0x337700, 0x3B3D30, 0x3B7A60, 0x5234E0, 0x528B20]

def build():
    img = open(IMG, "rb").read()
    u32 = lambda b, o: struct.unpack_from("<I", b, o)[0]
    f = open(DLL, "rb").read()
    e = u32(f, 0x3C)
    nsec = struct.unpack_from("<H", f, e + 6)[0]
    optsz = struct.unpack_from("<H", f, e + 20)[0]
    sizeImg = u32(f, e + 24 + 56)
    p = e + 24 + optsz
    secs = []
    for _ in range(nsec):
        nm = f[p:p+8].rstrip(b"\0").decode("latin1")
        vs, va, rs, rp = struct.unpack_from("<IIII", f, p + 8)
        secs.append((nm, va, rs, rp)); p += 40
    def foff(rva):
        for nm, va, rs, rp in secs:
            if va <= rva < va + rs:
                return rp + (rva - va)
        return None
    blocks, seen, desc_of = [], set(), {}
    for nm, va, rs, rp in secs:
        b = f[rp:rp+rs]
        for off in range(0, max(0, len(b) - 0x40), 4):
            size = u32(b, off + 0x20)
            if size < 0x40 or size > 0x200000 or off + size > len(b):
                continue
            if hashlib.sha256(b[off+0x20:off+size]).digest() != b[off:off+32]:
                continue
            if size == 0xF0:
                c = u32(b, off+0x34) & 0x0FFFFFFF
                sz = u32(b, off+0x38) & 0x0FFFFFFF
                desc_of[c] = va + off
                if 0 < sz < 0x100000 and c not in seen:
                    seen.add(c); blocks.append((c, sz))
                continue
            for k in range((size - 0xF4) // 0xC):
                o = off + 0xF4 + k*0xC
                rva, sz = u32(b, o+4), u32(b, o+8)
                if rva < 0x1000 or sz < 8 or rva + sz > sizeImg or rva in seen:
                    continue
                seen.add(rva); blocks.append((rva, sz))
    real = []
    for rva, sz in blocks:
        d = foff(rva)
        if d is None or d + sz > len(f):
            continue
        if img[rva:rva+sz] == f[d:d+sz]:
            continue
        if rva in desc_of:
            continue
        real.append((rva, sz))
    real.sort(key=lambda t: -t[1])
    return img, sizeImg, real, desc_of

def worker(code, in2mode):
    img, sizeImg, real, desc_of = build()
    k32 = ctypes.WinDLL("kernel32")
    k32.LoadLibraryW.restype = ctypes.c_void_p
    k32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong,
                                   ctypes.POINTER(ctypes.c_ulong)]
    nt = ctypes.WinDLL("ntdll")
    NtQ = nt.NtQuerySystemInformation
    NtQ.argtypes = [ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p]
    NtQ.restype = ctypes.c_long
    base = k32.LoadLibraryW(DLL)

    SEEN = [False]
    VEH = ctypes.CFUNCTYPE(ctypes.c_long, ctypes.c_void_p)
    def onfault(ep):
        if SEEN[0]:
            os._exit(0)
        SEEN[0] = True
        er = struct.unpack_from("<Q", ctypes.string_at(ep, 8))[0]
        c = struct.unpack_from("<I", ctypes.string_at(er, 4))[0]
        a = struct.unpack_from("<Q", ctypes.string_at(er + 0x10, 8))[0]
        print(f"FAULT 0x{c:08x} rva 0x{(a - base) & 0xFFFFFFFF:x}", flush=True)
        os._exit(0)
    keep = VEH(onfault)
    k32.AddVectoredExceptionHandler(1, keep)

    def patch(rva, data):
        data = bytes(data)
        addr = base + rva
        span = (len(data) + 0xFFF) & ~0xFFF
        old = ctypes.c_ulong(0); d = ctypes.c_ulong(0)
        if not k32.VirtualProtect(addr, span, RWX, ctypes.byref(old)):
            return False
        ctypes.memmove(addr, data, len(data))
        k32.VirtualProtect(addr, span, old.value, ctypes.byref(d))
        return True

    for rva, sz in real:
        patch(rva, img[rva:rva+sz])

    dv = desc_of.get(code)
    if dv is None:
        print("no descriptor", flush=True); os._exit(0)

    prv = open("extracted.enc.prv", "rb").read()
    in2 = ctypes.create_string_buffer(b"\x00" * 0x40, 0x40)
    st = ctypes.create_string_buffer(0x20)
    ob = ctypes.create_string_buffer(0x100)
    kb = ctypes.create_string_buffer(prv, 0x41)

    a = ctypes.create_string_buffer(0x30)
    struct.pack_into("<Q", a, 0x00, 3)
    struct.pack_into("<Q", a, 0x08, base + dv)
    struct.pack_into("<Q", a, 0x10, ctypes.addressof(st))
    struct.pack_into("<Q", a, 0x18, ctypes.addressof(kb))
    struct.pack_into("<Q", a, 0x20, ctypes.addressof(in2))
    struct.pack_into("<Q", a, 0x28, ctypes.addressof(ob))
    r = NtQ(0xB9, ctypes.cast(a, ctypes.c_void_p), 0x30, None) & 0xFFFFFFFF
    out = bytes(ob.raw)[:0x20]
    print(f"nt=0x{r:08x} st={ctypes.string_at(ctypes.addressof(st),8).hex()} obf={out.hex()}",
          flush=True)
    os._exit(0)

if len(sys.argv) > 1 and sys.argv[1] == "--one":
    worker(int(sys.argv[2], 0), int(sys.argv[3], 0))
    raise SystemExit

# ---- gather the 6 OBFs
obfs = {}
for code in CODES:
    p = subprocess.run([sys.executable, os.path.abspath(__file__), "--one", hex(code), "0"],
                       capture_output=True, text=True, timeout=120)
    line = (p.stdout or "").strip()
    hexpart = ""
    for tok in line.split():
        if tok.startswith("obf="):
            hexpart = tok[4:]
    obfs[code] = bytes.fromhex(hexpart) if len(hexpart) == 64 else None

# ---- table + permutation search against the public key
img = open(IMG, "rb").read()
pub = open("extracted.enc.pub", "rb").read()
X = int.from_bytes(pub[-64:-32], "big")
Y = int.from_bytes(pub[-32:], "big")

from cryptography.hazmat.primitives.asymmetric import ec
CURVE = ec.SECP256R1()
NN = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

TABLES = {0x843720: "t3", 0x862ee0: "t4", 0x882920: "s1", 0x8a23f0: "s2",
          0x8c2470: "s3", 0x8e2210: "s4", 0x902180: "s5", 0x922230: "s6"}
DOCMAP = {0:1,1:0,2:0xA,3:0xC,4:9,5:6,6:8,7:4,8:0xF,9:7,0xA:0xD,0xB:5,0xC:3,0xD:0xB,0xE:2,0xF:0xE}
INV = {v: k for k, v in DOCMAP.items()}

def nibs(b, hi):
    return [(b[i >> 1] >> (4 if (i % 2 == 0) == hi else 0)) & 0xF for i in range(64)]

def pack(ns, hi):
    return bytes((ns[i] << 4) | ns[i+1] if hi else (ns[i+1] << 4) | ns[i]
                 for i in range(0, 64, 2))

def ok(pl):
    k = int.from_bytes(pl, "big")
    if not (0 < k < NN):
        return False
    pn = ec.derive_private_key(k, CURVE).public_key().public_numbers()
    return pn.x == X and pn.y == Y

lines = []
found = None
for code, obf in obfs.items():
    lines.append(f"code 0x{code:06x} obf {obf.hex() if obf else 'FAILED'}")
lines.append("")

for code, obf in obfs.items():
    if not obf:
        continue
    for tbase, tname in TABLES.items():
        blk = [img[tbase + i*16: tbase + i*16 + 16] for i in range(64)]
        if any(len(b) != 16 or max(b) > 15 or len(set(b)) != 16 for b in blk):
            continue
        for hi in (True, False):
            nn = nibs(obf, hi)
            mapped = pack([blk[i][nn[i]] for i in range(64)], hi)
            mn = nibs(mapped, hi)
            for pname, perm in (("doc", DOCMAP), ("docinv", INV),
                               ("id", {i: i for i in range(16)})):
                pl = pack([perm[x] for x in mn], hi)
                for oname, cand in (("fwd", pl), ("rev", pl[::-1])):
                    if ok(cand):
                        found = (code, tname, hi, pname, oname, cand)
                        lines.append(f"*** VALIDATED code 0x{code:06x} table {tname} "
                                     f"hi={hi} perm={pname} order={oname}")
                        lines.append(f"    plain {cand.hex()}")
                        break
                if found:
                    break
            if found:
                break
        if found:
            break
    if found:
        break

if found:
    open("extracted.enc.plain", "wb").write(found[5])
    lines.append("written extracted.enc.plain")
else:
    lines.append("no combination matched")
    lines.append("")
    lines.append("OBFs for manual inspection:")
    for code, obf in obfs.items():
        if obf:
            lines.append(f"  0x{code:06x} {obf.hex()}")

open(LOG, "w", encoding="utf-8").write("\n".join(lines) + "\n")
print("\n".join(lines))
