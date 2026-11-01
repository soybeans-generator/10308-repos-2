# wbtool.py
import struct, sys, hashlib, bisect
from collections import Counter

DLL = sys.argv[1] if len(sys.argv) > 1 else r"C:\Windows\System32\Windows.Media.Protection.PlayReady.dll"
OUT = "wbtool.txt"
d = open(DLL, "rb").read()

E = struct.unpack_from("<I", d, 0x3C)[0]
coff = E + 4
nsec, = struct.unpack_from("<H", d, coff + 2)
optsz, = struct.unpack_from("<H", d, coff + 16)
p = coff + 20 + optsz
secs = []
for _ in range(nsec):
    nm = d[p:p + 8].rstrip(b"\0").decode("latin1")
    vs, va, rs, rp = struct.unpack_from("<IIII", d, p + 8)
    secs.append((nm, va, vs, rp, rs))
    p += 40
u32 = lambda b, o: struct.unpack_from("<I", b, o)[0]

def rva_of(off):
    for nm, va, vs, rp, rs in secs:
        if rp <= off < rp + rs:
            return va + (off - rp), nm
    return None, None

spans = []
for nm, va, vs, rp, rs in secs:
    b = d[rp:rp + rs]
    for off in range(0, len(b) - 0x40, 4):
        size = u32(b, off + 0x20)
        if not (0x40 <= size <= 0x2000) or off + size > len(b):
            continue
        dig = b[off:off + 0x20]
        if dig == b"\0" * 0x20 or hashlib.sha256(b[off + 0x20:off + size]).digest() != dig:
            continue
        body = b[off:off + size]
        if size == 0xF0:
            r, s = u32(body, 0x34) & 0x0FFFFFFF, u32(body, 0x38) & 0x0FFFFFFF
            if 0 < s < 0x1000000:
                spans.append((r, r + s))
        else:
            for i in range((size - 0xF4) // 0xC):
                o = 0xF4 + i * 0xC
                r, s = u32(body, o + 4) & 0x0FFFFFFF, u32(body, o + 8)
                if 0 < s < 0x1000000:
                    spans.append((r, r + s))
spans.sort()
merged = []
for a, b2 in spans:
    if merged and a <= merged[-1][1]:
        merged[-1][1] = max(merged[-1][1], b2)
    else:
        merged.append([a, b2])
ms = [a for a, b2 in merged]

def enc(x):
    i = bisect.bisect_right(ms, x) - 1
    return i >= 0 and merged[i][0] <= x < merged[i][1]

L = []
def w(s=""):
    L.append(str(s))

w(f"dll    {DLL}")
w(f"sha256 {hashlib.sha256(d).hexdigest()}")
w("")

NEEDLES = {
    "w11 EK pos0 row0": bytes.fromhex("60d413a78632f541b703c47051e52296"),
    "w11 EK pos1 row0": bytes.fromhex("ec589f2b0abe79cd3b8f48fcdd69ae1a"),
}
w("needle search (whole file, every offset):")
for name, nd in NEEDLES.items():
    hits, i = [], d.find(nd)
    while i != -1:
        hits.append(i)
        i = d.find(nd, i + 1)
    w(f"  {name}: {len(hits)} hit(s)")
    for h in hits[:8]:
        r, s = rva_of(h)
        w(f"    file 0x{h:08x}  rva {r if r is None else hex(r)}  {s}  encr={None if r is None else enc(r)}")
w("")

h256 = [o for o in range(0, len(d) - 256, 16) if len(set(d[o:o + 256])) == 256]
cl = []
for o in h256:
    if cl and o - cl[-1][-1] <= 0x100:
        cl[-1].append(o)
    else:
        cl.append([o])
w(f"256-byte permutation windows: {len(h256)} in {len(cl)} cluster(s)")
for c in cl:
    if len(c) < 8:
        continue
    a, b = c[0], c[-1] + 256
    reg = d[a:b]
    w(f"  file 0x{a:08x}..0x{b:08x}  windows {len(c)}")
    blocks = [reg[i:i + 256] for i in range(0, len(reg) - 255, 256)]
    w(f"    256-aligned blocks {len(blocks)}  distinct {len(set(blocks))}")
    best = []
    for stride in (0x10, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000):
        if stride >= len(reg):
            continue
        eq = sum(1 for i in range(0, min(len(reg) - stride, 65536)) if reg[i] == reg[i + stride])
        best.append((eq / min(len(reg) - stride, 65536), stride))
    best.sort(reverse=True)
    for frac, stride in best[:4]:
        w(f"    repeat rate stride 0x{stride:05x}: {100 * frac:5.1f}%")
    w(f"    first 32 bytes: {reg[:32].hex()}")
w("")

if cl:
    a, b = cl[0][0], cl[0][-1] + 256
    lo, hi = max(0, a - 0x20000), min(len(d) - 4096, b + 0x20000)
    w(f"unaligned 4096-byte hash scan, band 0x{lo:08x}..0x{hi:08x} (step 1):")
    for name, hx in (("w10", "ddc2079bd34d62870119547a565c0ccc35b370951b5b3a4b0ef819d8206572ec"),
                     ("w11", "43504baadd25530974fb17c0c6fd69344059fb1fa91f28abd22e68267b78257d")):
        tgt = bytes.fromhex(hx)
        hit = None
        for o in range(lo, hi):
            if hashlib.sha256(d[o:o + 4096]).digest() == tgt:
                hit = o
                break
        r, s = rva_of(hit) if hit is not None else (None, None)
        w(f"  {name} EK sha256: {'file 0x%08x rva %s %s' % (hit, hex(r), s) if hit is not None else 'none'}")
w("")

open(OUT, "w", encoding="utf-8").write("\n".join(L) + "\n")
print(f"windows {len(h256)}  clusters {len(cl)}  -> {OUT}")
