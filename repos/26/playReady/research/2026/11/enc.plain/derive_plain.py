# derive_plain.py — .enc.prv -> .enc.plain (permanent; writes the file once)
import ctypes, hashlib, json, os, struct, sys

DLL   = r"C:\Windows\SYSTEM32\Windows.Media.Protection.PlayReady.dll"
IMG   = "wbtool_img.bin"
MAPF  = "oracle_map.json"
PRVF  = "extracted.enc.prv"
PUBF  = "extracted.enc.pub"
OUTF  = "extracted.enc.plain"
LOG   = "derive_plain.txt"

CODE_OBF = 0x6C6F00    # stage 1: prv[0x00:0x20] -> OBF
CODE_MAP = 0x529250    # stage 2: in = OBF (mutated in place), out = prv[0x20:0x40]
CLUSTER  = 0x8E2210    # bijection subtables proven live by the nibble oracle
RWX      = 0x40
CURVE_N  = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

# recorded from the WB trace / from the validated run; used only if stage 1 is skipped
KNOWN_OBF = "69ef7582608af8d0df0fb4b515449be5a8d0c903741cbf3353be70eb460521f4"

L = []
def log(s=""):
    L.append(str(s)); print(s, flush=True)

def die(msg):
    log(f"FATAL: {msg}")
    open(LOG, "w", encoding="utf-8").write("\n".join(L) + "\n")
    sys.exit(1)

# ---------------------------------------------------------------- inputs
if not os.path.isfile(MAPF):
    die(f"missing {MAPF} - run the oracle step first")
if not os.path.isfile(IMG):
    die(f"missing {IMG} - run the Warbird decrypt first")

MAP = {int(k): v for k, v in json.load(open(MAPF)).items()}
if sorted(MAP.values()) != list(range(16)):
    die("oracle_map.json is not a 16-entry permutation")

PRV = open(PRVF, "rb").read()
if len(PRV) != 0x41:
    die(f"{PRVF} is {len(PRV)} bytes, expected 0x41 (65)")

PUB = open(PUBF, "rb").read()[-64:]
PX = int.from_bytes(PUB[:32], "big")
PY = int.from_bytes(PUB[32:], "big")

# ---------------------------------------------------------------- PE layout
img = open(IMG, "rb").read()
fb  = open(DLL, "rb").read()
u32 = lambda b, o: struct.unpack_from("<I", b, o)[0]

lf     = u32(fb, 0x3C)
nsec   = struct.unpack_from("<H", fb, lf + 6)[0]
optsz  = struct.unpack_from("<H", fb, lf + 20)[0]
sizeImg = u32(fb, lf + 24 + 56)
p = lf + 24 + optsz
secs = []
for _ in range(nsec):
    vs, va, rs, rp = struct.unpack_from("<IIII", fb, p + 8)
    secs.append((va, rs, rp)); p += 40

def foff(rva):
    for va, rs, rp in secs:
        if va <= rva < va + rs:
            return rp + (rva - va)
    return None

def raw_at(rva, n):
    d = foff(rva)
    if d is None or d + n > len(fb):
        return None
    return fb[d:d + n]

# ------------------------------------------- descriptors: heap-exec + segment
seg, desc_of, seen = [], {}, set()
for va, rs, rp in secs:
    b = fb[rp:rp + rs]
    for off in range(0, max(0, len(b) - 0x40), 4):
        size = u32(b, off + 0x20)
        if size < 0x40 or size > 0x200000 or off + size > len(b):
            continue
        if hashlib.sha256(b[off + 0x20:off + size]).digest() != b[off:off + 32]:
            continue
        if size == 0xF0:                       # heap-exec -> kernel decrypts on op=3
            desc_of[u32(b, off + 0x34) & 0x0FFFFFFF] = va + off
            continue
        for k in range((size - 0xF4) // 0xC):
            o = off + 0xF4 + k * 0xC
            rva, sz = u32(b, o + 4), u32(b, o + 8)
            if rva < 0x1000 or sz < 8 or rva + sz > sizeImg or rva in seen:
                continue
            seen.add(rva); seg.append((rva, sz))

d_obf = desc_of.get(CODE_OBF)
d_map = desc_of.get(CODE_MAP)
if d_obf is None or d_map is None:
    die(f"descriptor missing: 0x{CODE_OBF:06x}->{d_obf}, 0x{CODE_MAP:06x}->{d_map}")

# only blocks this image actually decrypted (differs from the file)
patch_list = []
for r, s in seg:
    rawb = raw_at(r, s)
    if rawb is None:
        continue
    if img[r:r + s] != rawb:
        patch_list.append((r, s))

# ---------------------------------------------------------------- process
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
if not base:
    die("LoadLibraryW failed")
DUM = ctypes.c_ulong(0)
ME  = ctypes.c_void_p(-1)

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

npatched = sum(1 for r, s in patch_list if wr(r, img[r:r + s]))
log(f"base 0x{base:x}   segment blocks patched {npatched}/{len(patch_list)}   "
    f"heap-exec left ciphertext")
if npatched == 0:
    die("nothing patched - is wbtool_img.bin really decrypted?")

def onfault(ep):
    er = struct.unpack_from("<Q", ctypes.string_at(ep, 8))[0]
    code = struct.unpack_from("<I", ctypes.string_at(er, 4))[0]
    addr = struct.unpack_from("<Q", ctypes.string_at(er + 0x10, 8))[0]
    die(f"FAULT 0x{code:08x} at rva 0x{(addr - base) & 0xFFFFFFFF:x}")

VEH = ctypes.CFUNCTYPE(ctypes.c_long, ctypes.c_void_p)
keep_veh = VEH(onfault)
k32.AddVectoredExceptionHandler(1, keep_veh)

def op3(desc_rva, ln, status, key, out, inbuf=None):
    """{+0x10 status, +0x18 key/in, +0x20 size, +0x24 out[, +0x2C size]}"""
    a = ctypes.create_string_buffer(0x40)
    struct.pack_into("<Q", a, 0x00, 3)
    struct.pack_into("<Q", a, 0x08, base + desc_rva)
    struct.pack_into("<Q", a, 0x10, ctypes.addressof(status))
    struct.pack_into("<Q", a, 0x18, ctypes.addressof(key))
    struct.pack_into("<I", a, 0x20, 0x20)
    struct.pack_into("<Q", a, 0x24, ctypes.addressof(out))
    if ln >= 0x30:
        struct.pack_into("<I", a, 0x2C, 0x20)
    rc = Raw(0xB9, ctypes.cast(a, ctypes.c_void_p), ln, None) & 0xFFFFFFFF
    return rc, bytes(status.raw)[:4]

# ---------------------------------------------------------------- stage 1 -> OBF
argv = sys.argv[1:]
if argv[:1] == ["--obf"] and len(argv) > 1:
    OBF = bytes.fromhex(argv[1])
    log(f"OBF       {OBF.hex()}  (from --obf)")
else:
    st = ctypes.create_string_buffer(0x40)
    kb = ctypes.create_string_buffer(PRV[0x00:0x20], 0x40)
    ob = ctypes.create_string_buffer(0x40)
    rc, sd = op3(d_obf, 0x2C, st, kb, ob)
    OBF = bytes(ob.raw)[:0x20]
    log(f"stage 1   0x{CODE_OBF:06x} nt=0x{rc:08x} status={sd.hex()}")
    if rc != 0 or sd != b"\0\0\0\0" or OBF == b"\0" * 0x20:
        OBF = bytes.fromhex(KNOWN_OBF)
        log("          stage 1 unusable, falling back to recorded OBF")
    log(f"OBF       {OBF.hex()}")

# ---------------------------------------------------------------- stage 2 -> mapped
st = ctypes.create_string_buffer(0x40)
ib = ctypes.create_string_buffer(OBF, 0x40)
ob = ctypes.create_string_buffer(PRV[0x20:0x40], 0x40)
rc, sd = op3(d_map, 0x30, st, ib, ob)
mut = bytes(ib.raw)[:0x20]
log(f"stage 2   0x{CODE_MAP:06x} nt=0x{rc:08x} status={sd.hex()}")
if rc != 0 or sd != b"\0\0\0\0":
    die(f"stage 2 rejected (status {sd.hex()})")
log(f"in-mutated {mut.hex()}")

# ---------------------------------------------------------------- bijection + MAP
BLK = [img[CLUSTER + i * 16: CLUSTER + i * 16 + 16] for i in range(64)]
if any(len(b) != 16 or max(b) > 15 or len(set(b)) != 16 for b in BLK):
    die(f"cluster 0x{CLUSTER:06x} is not 64 clean nibble permutations")

def nibs(b):
    return [(b[i >> 1] >> (4 if i % 2 == 0 else 0)) & 0xF for i in range(64)]

def pack(ns):
    return bytes((ns[i] << 4) | ns[i + 1] for i in range(0, 64, 2))

n = nibs(mut)
mapped = pack([BLK[i][n[i]] for i in range(64)])
plain = pack([MAP[x] for x in nibs(mapped)])
log(f"mapped    {mapped.hex()}")
log(f"plain     {plain.hex()}")

# ---------------------------------------------------------------- verify + write
from cryptography.hazmat.primitives.asymmetric import ec

d = int.from_bytes(plain, "big")
if not (0 < d < CURVE_N):
    die("derived scalar out of range")
pn = ec.derive_private_key(d, ec.SECP256R1()).public_key().public_numbers()
if (pn.x, pn.y) != (PX, PY):
    die(f"scalar does not reproduce {PUBF}\n"
        f"  got  X={pn.x:064x}\n       Y={pn.y:064x}\n"
        f"  want X={PX:064x}\n       Y={PY:064x}")

log("pubkey    MATCH")
with open(OUTF, "wb") as fh:
    fh.write(plain)
digest = hashlib.sha256(plain).hexdigest()
log(f"written   {OUTF}  ({len(plain)} bytes)  sha256 {digest}")

open(LOG, "w", encoding="utf-8").write("\n".join(L) + "\n")
