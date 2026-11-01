# wbtool.py
import ctypes, hashlib, os, struct, subprocess, sys

DLL = r"C:\Windows\SYSTEM32\Windows.Media.Protection.PlayReady.dll"
TABLES = [0x8843720, 0x8862ee0, 0x8882920, 0x88a23f0, 0x88c2470, 0x88e2210, 0x8902180, 0x8922230]

def pe_descs():
    d = open(DLL, "rb").read()
    lf = struct.unpack_from("<I", d, 0x3C)[0]
    nsec = struct.unpack_from("<H", d, lf + 6)[0]
    optsz = struct.unpack_from("<H", d, lf + 20)[0]
    p = lf + 24 + optsz
    secs = []
    for _ in range(nsec):
        vs, va, rs, rp = struct.unpack_from("<IIII", d, p + 8)
        secs.append((va, rs, rp))
        p += 40
    out = []
    for va, rs, rp in secs:
        b = d[rp:rp + rs]
        for off in range(0, len(b) - 0x40, 4):
            size = struct.unpack_from("<I", b, off + 0x20)[0]
            if size != 0xF0 or off + size > len(b):
                continue
            if hashlib.sha256(b[off + 0x20:off + size]).digest() != b[off:off + 32]:
                continue
            out.append(va + off)
    return out

# ---------------- worker ----------------
def one(desc, prv):
    KEY = 0x41
    k32 = ctypes.WinDLL("kernel32")
    k32.LoadLibraryW.restype = ctypes.c_void_p
    base = k32.LoadLibraryW(DLL)
    ntdll = ctypes.WinDLL("ntdll")
    NtQ = ntdll.NtQuerySystemInformation
    NtQ.argtypes = [ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p]
    NtQ.restype = ctypes.c_long

    VEH = ctypes.CFUNCTYPE(ctypes.c_long, ctypes.c_void_p)
    handler = VEH(lambda i: (print(f"RESULT {desc:#x} FAULT"), sys.stdout.flush(), os._exit(0))[-1])
    k32.AddVectoredExceptionHandler(1, handler)

    enc = open(prv, "rb").read()
    for layout in ("A", "B"):
        fill = os.urandom(0x20)
        kb = ctypes.create_string_buffer(enc, KEY)
        st = ctypes.create_string_buffer(0x10)
        out = ctypes.create_string_buffer(fill, 0x20)
        a = ctypes.create_string_buffer(0x38)
        struct.pack_into("<Q", a, 0x00, 3)
        struct.pack_into("<Q", a, 0x08, base + desc)
        struct.pack_into("<Q", a, 0x10, ctypes.addressof(st))
        struct.pack_into("<Q", a, 0x18, ctypes.addressof(kb))
        struct.pack_into("<I", a, 0x20, KEY)
        if layout == "A":                      # signing-key style: out at +0x24
            struct.pack_into("<Q", a, 0x24, ctypes.addressof(out))
            ln = 0x2C
        else:                                  # license style: out at +0x28
            struct.pack_into("<Q", a, 0x28, ctypes.addressof(out))
            ln = 0x30
        r = NtQ(0xB9, ctypes.cast(a, ctypes.c_void_p), ln, None) & 0xFFFFFFFF
        if r == 0:
            sd = ctypes.string_at(ctypes.addressof(st), 4)
            res = ctypes.string_at(ctypes.addressof(out), 0x20)
            if sd == b"\0\0\0\0" and res != fill:
                print(f"RESULT {desc:#x} {layout} OK {res.hex()}")
                sys.stdout.flush()
                os._exit(0)
    print(f"RESULT {desc:#x} none")
    sys.stdout.flush()
    os._exit(0)

# ---------------- driver ----------------
if __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1] == "--one":
    one(int(sys.argv[2], 0), sys.argv[3])
    raise SystemExit

prv = sys.argv[1] if len(sys.argv) > 1 else "id.enc.prv"
pub = sys.argv[2] if len(sys.argv) > 2 else "id.enc.pub"

descs = pe_descs()
print(f"{len(descs)} heap-exec descriptors, probing with {prv}", flush=True)

cands = []
me = os.path.abspath(__file__)
for i, dv in enumerate(descs, 1):
    try:
        r = subprocess.run([sys.executable, me, "--one", hex(dv), prv],
                           capture_output=True, text=True, timeout=30)
        line = next((l for l in r.stdout.splitlines() if l.startswith("RESULT")), "")
    except subprocess.TimeoutExpired:
        line = ""
    if " OK " in line:
        cands.append((dv, line.split(" OK ")[1].strip()))
        print("CANDIDATE " + line, flush=True)
    if i % 150 == 0:
        print(f"  {i}/{len(descs)} cands={len(cands)}", flush=True)

print(f"\ncandidates: {len(cands)}")
if not cands:
    print("none - wrong arg layout for this build")
    raise SystemExit

# ---- validate: table chain + nibble map, judged by the public key ----
raw = open(pub, "rb").read()
X = int.from_bytes(raw[-64:-32], "big")
Y = int.from_bytes(raw[-32:], "big")

from cryptography.hazmat.primitives.asymmetric import ec
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

DOC = [1,0,14,12,7,11,5,9,6,4,2,13,3,10,15,8]           # doc W10: deobf -> real
INV = [0]*16
for k, v in enumerate(DOC):
    INV[v] = k
PERMS = {"doc": DOC, "doc_inv": INV, "id": list(range(16))}

img = open("wbtool_img.bin", "rb").read()

def blocks(t):
    return [img[t + i*16: t + i*16 + 16] for i in range(64)]

def nibbles(b):
    return [(b[i >> 1] >> (4 if i % 2 == 0 else 0)) & 0xF for i in range(len(b)*2)]

done = False
for dv, hx in cands:
    obf = bytes.fromhex(hx)
    for t in TABLES:
        bs = blocks(t)
        if any(len(b) != 16 or max(b) > 15 or len(set(b)) != 16 for b in bs):
            continue
        n = nibbles(obf)
        mapped = bytes((bs[i][n[i]] << 4) | bs[i+1][n[i+1]] for i in range(0, 64, 2))
        for pname, perm in PERMS.items():
            mn = nibbles(mapped)
            plain = bytes((perm[mn[i]] << 4) | perm[mn[i+1]] for i in range(0, 64, 2))
            k = int.from_bytes(plain, "big")
            if not (0 < k < N):
                continue
            try:
                pn = ec.derive_private_key(k, ec.SECP256R1()).public_key().public_numbers()
            except Exception:
                continue
            if pn.x == X and pn.y == Y:
                print(f"\n*** VALIDATED ***")
                print(f"  desc    0x{dv:x}")
                print(f"  table   0x{t:x}  perm {pname}")
                print(f"  plain   {plain.hex()}")
                open("enc_plain.bin", "wb").write(plain)
                done = True
if not done:
    print("\nno combination validated - candidates are wrong routines, or")
    print("the map for this build differs from the doc's (oracle then needed)")
