# =============================================================================
# 3-derive-map.py  (oracle2) -- magic-independent stage 3
#
# Replaces the previous stage 3. Same inputs, same outputs, same JSON schema,
# so 1-make-oracle.py, 2-decrypt-img.py and 4-derive-plain.py are unchanged.
#
# WHY THIS VERSION
#   The previous stage 3 decided HIT/MISS by comparing the 32-byte output to
#   SENT XOR MAGIC, with MAGIC hardcoded to the Windows 10 sequence. On a build
#   using a different sequence every query reads MISS even when the table patch
#   worked. Symptom: no fault, status 0, N misses in a row - indistinguishable
#   from "the set is not live".
#
# DISCRIMINATOR (no magic needed)
#   For set S, forced mapped nibble m, licence NN:
#       O(S,m,NN) = X(C2 - d'(m)*C1) XOR magic
#   with d'(m) the scalar whose every nibble is MAP[m]. Decryption reaches the
#   sentinel iff MAP[m] == NN. Hence
#     - S not live : 16 outputs identical per licence (equal to control), and
#                    different between licences.
#     - S live     : 16 outputs vary, and exactly one is the SAME 32 bytes for
#                    every licence (the sentinel X, which is licence-independent).
#   So |intersection over licences| == 1  <=>  S is live, and the shared value
#   is SENT XOR magic. magic is then recovered rather than assumed.
#
#   If NO set yields a shared value, the sentinel is never produced: the blob /
#   ECC encoding is wrong, not the table.
#
# PHASES
#   1  all discovered sets x licences 01/02/03  -> live set + magic
#   2  live set x licences 01..0f               -> full permutation
#
# OUTPUT  oracle_map.json  {"cluster": rva, "magic": hex, "map": {...}}
#         derive_map.txt
# =============================================================================

import ctypes, hashlib, json, os, re, struct, subprocess, sys

DLL    = r"C:\Windows\SYSTEM32\Windows.Media.Protection.PlayReady.dll"
IMG    = "wbtool_img.bin"
PRVF   = "extracted.enc.prv"
ORACLE = "oracle"
OUTF   = "oracle_map.json"
LOG    = "derive_map.txt"

CBLK, CN, CLEN = 16, 64, 0x400
RWX  = 0x40
PAT  = b"\x83\x79\x14\x41"            # cmp dword ptr [rcx+0x14], 0x41
SENT = b"HELLO MICROSOFT!" + b"\x00" * 16

W10 = bytes.fromhex("a77bece491a87ebcd8a2c62856b165b3"
                    "3ad2572cf88bdae3ddc79be816be3185")
W11 = bytes.fromhex("c3cd57691eff156c95d946d534121dfb"
                    "81738adb5b4bb4223faad89cbb459bec")

u16 = lambda b, o: struct.unpack_from("<H", b, o)[0]
u32 = lambda b, o: struct.unpack_from("<I", b, o)[0]


def pe(fb):
    lf = u32(fb, 0x3C)
    nsec, optsz = u16(fb, lf + 6), u16(fb, lf + 20)
    sizeImg = u32(fb, lf + 24 + 56)
    p, secs = lf + 24 + optsz, []
    for _ in range(nsec):
        vs, va, rs, rp = struct.unpack_from("<IIII", fb, p + 8)
        secs.append((va, rs, rp)); p += 40
    return sizeImg, secs


def census(fb, secs, sizeImg):
    segs, heaps, spans = [], [], []
    for va, rs, rp in secs:
        b = fb[rp:rp + rs]
        for off in range(0, max(0, len(b) - 0x40), 4):
            size = u32(b, off + 0x20)
            if size < 0x40 or size > 0x200000 or off + size > len(b):
                continue
            if hashlib.sha256(b[off + 0x20:off + size]).digest() != b[off:off + 32]:
                continue
            if size == 0xF0:
                heaps.append(dict(desc=va + off, fo=rp + off,
                                  rva=u32(b, off + 0x34) & 0x0FFFFFFF,
                                  size=u32(b, off + 0x38) & 0x0FFFFFFF))
            else:
                segs.append(dict(desc=va + off, fo=rp + off, size=size))
    for s in segs:                       # per descriptor, NOT deduped by RVA
        b = fb[s["fo"]:s["fo"] + s["size"]]
        for k in range((s["size"] - 0xF4) // 0xC):
            o = 0xF4 + k * 0xC
            rva, sz = u32(b, o + 4), u32(b, o + 8)
            if rva >= 0x1000 and sz >= 8 and rva + sz <= sizeImg:
                spans.append((rva, sz))
    return segs, heaps, spans


def raw_at(fb, secs, rva, n):
    for va, rs, rp in secs:
        if va <= rva < va + rs and rp + (rva - va) + n <= len(fb):
            return fb[rp + (rva - va):rp + (rva - va) + n]
    return None


def find_sets(img):
    out = []
    for m in re.finditer(rb"[\x00-\x0f]{%d,}" % CLEN, img):
        lo, hi, o = m.start(), m.end(), m.start()
        while o + CLEN <= hi:
            if len(set(img[o:o + CBLK])) != CBLK:
                o += 1; continue
            if all(len(set(img[o + i * CBLK:o + (i + 1) * CBLK])) == CBLK
                   for i in range(CN)):
                out.append(o); o += CLEN
            else:
                o += 1
    out.sort()
    return [(f"set{i}", rva) for i, rva in enumerate(out)]


def find_consumer(img, heaps):
    sites, i = [], img.find(PAT)
    while i != -1:
        sites.append(i); i = img.find(PAT, i + 1)
    if len(sites) != 1:
        return None, sites
    owner = None
    for h in heaps:
        if h["size"] and h["rva"] <= sites[0] < h["rva"] + h["size"]:
            owner = h["desc"]
    return owner, sites


# ================================ worker =====================================
if len(sys.argv) > 1 and sys.argv[1] == "--sweep":
    SETRVA = int(sys.argv[2], 0)
    DESC   = int(sys.argv[3], 0)
    LICS   = [int(x, 16) for x in sys.argv[4].split(",")]

    fb = open(DLL, "rb").read()
    img = open(IMG, "rb").read()
    PRV = open(PRVF, "rb").read()
    sizeImg, secs = pe(fb)
    segs, heaps, spans = census(fb, secs, sizeImg)

    k32 = ctypes.WinDLL("kernel32")
    k32.LoadLibraryW.restype = ctypes.c_void_p
    k32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong,
                                   ctypes.POINTER(ctypes.c_ulong)]
    k32.K32GetMappedFileNameW.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                          ctypes.c_wchar_p, ctypes.c_ulong]
    nt = ctypes.WinDLL("ntdll")
    Raw = nt.NtQuerySystemInformation
    Raw.argtypes = [ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p]
    Raw.restype = ctypes.c_long

    base = k32.LoadLibraryW(DLL)
    if not base:
        print("LOADFAIL"); sys.stdout.flush(); os._exit(4)

    def wr(rva, data):
        data = bytes(data)
        span = (len(data) + 0xFFF) & ~0xFFF
        old = ctypes.c_ulong(0)
        a = ctypes.c_void_p(base + rva)
        if not k32.VirtualProtect(a, span, RWX, ctypes.byref(old)):
            return False
        ctypes.memmove(a, data, len(data))
        k32.VirtualProtect(a, span, old.value, ctypes.byref(ctypes.c_ulong(0)))
        return True

    # --- prep: patch segment plaintext, but never over a heap-exec block.
    # The kernel decrypts those itself on op=3; pre-filling them causes a
    # double decrypt and the routine executes garbage.
    blocks = sorted((h["rva"], h["rva"] + h["size"]) for h in heaps if h["size"])
    merged = []
    for lo, hi in blocks:
        if merged and lo <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    los = [b[0] for b in merged]

    def carve(r, s):
        """Subtract heap-exec blocks from [r, r+s); return the remaining runs."""
        out, cur, e = [], r, r + s
        i = 0
        for j, lo in enumerate(los):
            if lo <= r:
                i = j
            else:
                break
        for lo, hi in merged[i:]:
            if hi <= cur:
                continue
            if lo >= e:
                break
            if lo > cur:
                out.append((cur, min(lo, e)))
            cur = max(cur, hi)
            if cur >= e:
                break
        if cur < e:
            out.append((cur, e))
        return [(a, b - a) for a, b in out if b > a]

    patched = skipped = 0
    for r, s in spans:
        if r + s > len(img):
            continue
        c = raw_at(fb, secs, r, s)
        if c is None or img[r:r + s] == c:
            continue
        for a, n in carve(r, s):
            if wr(a, img[a:a + n]):
                patched += 1
            else:
                skipped += 1
    print(f"PATCHED {patched} skipped {skipped}", flush=True)
    print(f"VARIANT prv[0x40]=0x{PRV[0x40]:02x} %3={PRV[0x40] % 3}", flush=True)

    def onf(ep):
        er = struct.unpack_from("<Q", ctypes.string_at(ep, 8))[0]
        code = u32(ctypes.string_at(er, 4), 0)
        ad = struct.unpack_from("<Q", ctypes.string_at(er + 0x10, 8))[0]
        nm = ctypes.create_unicode_buffer(512)
        try:
            k32.K32GetMappedFileNameW(ctypes.c_void_p(-1), ctypes.c_void_p(ad), nm, 512)
        except Exception:
            pass
        mod = nm.value.rsplit("\\", 1)[-1] if nm.value else "-"
        print(f"FAULT 0x{code:08x} addr=0x{ad:016x} off={ad - base:+#x} module={mod}",
              flush=True)
        os._exit(3)

    VEH = ctypes.CFUNCTYPE(ctypes.c_long, ctypes.c_void_p)
    keep = VEH(onf)
    k32.AddVectoredExceptionHandler(1, keep)

    orig = ctypes.string_at(base + SETRVA, CLEN)

    def decrypt(blob):
        st = ctypes.create_string_buffer(0x40)
        o  = ctypes.create_string_buffer(0x100)
        kb = ctypes.create_string_buffer(PRV, 0x48)
        cb = ctypes.create_string_buffer(blob, len(blob))
        a  = ctypes.create_string_buffer(0x40)
        struct.pack_into("<Q", a, 0x00, 3)
        struct.pack_into("<Q", a, 0x08, base + DESC)
        struct.pack_into("<Q", a, 0x10, ctypes.addressof(st))
        struct.pack_into("<I", a, 0x18, 0)
        struct.pack_into("<Q", a, 0x1C, ctypes.addressof(kb))
        struct.pack_into("<I", a, 0x24, 0x41)
        struct.pack_into("<Q", a, 0x28, ctypes.addressof(cb))
        struct.pack_into("<Q", a, 0x30, ctypes.addressof(o))
        rc = Raw(0xB9, ctypes.cast(a, ctypes.c_void_p), 0x38, None) & 0xFFFFFFFF
        return rc, bytes(st.raw)[:4], bytes(o.raw)[:0x20]

    for nn in LICS:
        blob = open(os.path.join(ORACLE, f"lic_{nn:02x}.blob"), "rb").read()
        rc, sd, out = decrypt(blob)
        print(f"CTRL {nn:02x} rc=0x{rc:08x} st={sd.hex()} {out.hex()}", flush=True)
        for mm in range(16):
            wr(SETRVA, bytes([mm]) * CLEN)
            try:
                rc, sd, out = decrypt(blob)
            finally:
                wr(SETRVA, orig)
            print(f"OUT {nn:02x} {mm:02x} rc=0x{rc:08x} st={sd.hex()} {out.hex()}",
                  flush=True)
    os._exit(0)


# ================================ driver =====================================
L = []
def log(s=""):
    L.append(str(s)); print(s, flush=True)

def die(msg):
    log(f"FATAL: {msg}")
    open(LOG, "w", encoding="utf-8").write("\n".join(L) + "\n")
    sys.exit(1)

for f in (IMG, PRVF):
    if not os.path.isfile(f):
        die(f"missing {f}")
if not os.path.isdir(ORACLE):
    die(f"missing {ORACLE}\\ - run 1-make-oracle.py first")

fb = open(DLL, "rb").read()
img = open(IMG, "rb").read()
sizeImg, secs = pe(fb)
segs, heaps, spans = census(fb, secs, sizeImg)

log(f"dll      {DLL}")
log(f"sha256   {hashlib.sha256(fb).hexdigest()}")
log(f"size     {len(fb):,}   SizeOfImage 0x{sizeImg:x}")
log(f"image    {IMG}  {len(img):,} bytes")
log(f"segments {len(segs)}  heap-exec {len(heaps)}  spans {len(spans)}")
log("")

SETS = find_sets(img)
log(f"bijection sets: {len(SETS)}")
for n, r in SETS:
    log(f"  {n}  0x{r:06x}  {img[r:r + 16].hex()}")
log("")
if not SETS:
    die("no permutation sets found - is wbtool_img.bin decrypted?")

DESC, sites = find_consumer(img, heaps)
log(f"size-check sites: {[hex(x) for x in sites]}")
if DESC is None:
    die(f"consumer not unique ({len(sites)} sites)")
h = next(x for x in heaps if x["desc"] == DESC)
log(f"consumer descriptor 0x{DESC:06x}  code 0x{h['rva']:06x}+0x{h['size']:x}")
log("")


def sweep(setrva, lics):
    p = subprocess.run([sys.executable, os.path.abspath(__file__),
                        "--sweep", hex(setrva), hex(DESC),
                        ",".join(f"{x:02x}" for x in lics)],
                       capture_output=True, text=True, timeout=1800)
    ctrl, outs, meta, fault = {}, {}, [], None
    for x in (p.stdout or "").splitlines():
        f = x.split()
        if not f:
            continue
        if f[0] in ("PATCHED", "VARIANT"):
            meta.append(x)
        elif f[0] == "CTRL":
            ctrl[int(f[1], 16)] = f[-1]
        elif f[0] == "OUT":
            outs.setdefault(int(f[1], 16), {})[int(f[2], 16)] = f[-1]
        elif f[0] == "FAULT":
            fault = x
    return dict(ctrl=ctrl, outs=outs, meta=meta, fault=fault, rc=p.returncode)


# ---- phase 1: live set + magic, using three licences
P1 = [1, 2, 3]
log(f"phase 1: {len(SETS)} sets x licences {P1}")
log(f"{'set':<6}{'rva':<12}{'distinct':<26}{'shared':<8}verdict")
live, magic_hex, table = None, None, {}
for name, rva in SETS:
    r = sweep(rva, P1)
    if r["fault"]:
        log(f"{name:<6}0x{rva:06x}  {r['fault']}")
        continue
    if any(nn not in r["outs"] for nn in P1):
        log(f"{name:<6}0x{rva:06x}  incomplete (rc {r['rc']})")
        continue
    sets = {nn: set(r["outs"][nn].values()) for nn in P1}
    distinct = {nn: len(sets[nn]) for nn in P1}
    shared = set.intersection(*sets.values())
    verdict = "LIVE" if len(shared) == 1 and min(distinct.values()) > 1 else "not live"
    log(f"{name:<6}0x{rva:06x}  {str(distinct):<26}{len(shared):<8}{verdict}")
    if verdict == "LIVE":
        if live is not None:
            die(f"two live sets: {live[0]} and {name}")
        live, magic_hex, table = (name, rva), next(iter(shared)), r
log("")

if live is None:
    log("no set produced a shared plaintext across licences.")
    log("")
    log("That rules out both wrong-magic and wrong-live-set: if the sentinel were")
    log("ever produced, the shared value would appear. So the sentinel is never")
    log("reached at all, which points at the blob/ECC encoding rather than at the")
    log("tables. Check, in order:")
    log("  1. lic_NN.blob point order - C1||C2 vs C2||C1. The oracle writes")
    log("     C1=(rG) then C2=(M+rQ); a build that reads C2 first never lands on M.")
    log("  2. Whether the consumer really is the 0x41 licence consumer on this")
    log("     build. Compare the 'distinct' column: all-1 means the patch has no")
    log("     effect on the output, so that descriptor is not reading the table.")
    log("  3. Whether prv[0x40]%3 selects a routine family whose table is not among")
    log("     the discovered sets - the VARIANT line above records the value.")
    die("no live set")

MAGIC = bytes(a ^ b for a, b in zip(bytes.fromhex(magic_hex), SENT))

log(f"live set   {live[0]} 0x{live[1]:06x}")
log(f"magic      {MAGIC.hex()}")
if MAGIC == W10:
    log("           == the Windows 10 sequence")
elif MAGIC == W11:
    log("           == the Windows 11 sequence")
else:
    log("           == NEITHER published sequence: this build uses a third one,")
    log("              which is why a hardcoded W10 constant would never match.")
log("")
for m in table["meta"]:
    log(f"  {m}")

# ---- phase 2: full permutation on the live set
log("")
log("phase 2: full permutation on the live set")
r = sweep(live[1], list(range(1, 16)))
if r["fault"]:
    die(r["fault"])
if any(nn not in r["outs"] for nn in range(1, 16)):
    die(f"incomplete sweep (rc {r['rc']})")

TARGET = magic_hex          # the shared sentinel output, as hex
MAP = {}
for nn in range(1, 16):
    hits = [mm for mm, v in r["outs"][nn].items() if v == TARGET]
    if len(hits) != 1:
        die(f"nibble 0x{nn:x}: {len(hits)} hits, expected 1")
    mm = hits[0]
    if mm in MAP:
        die(f"nibble 0x{nn:x}: mapped 0x{mm:x} already used by real 0x{MAP[mm]:x}")
    MAP[mm] = nn
    log(f"  real 0x{nn:x} <- mapped 0x{mm:x}")

left = [m for m in range(16) if m not in MAP]
if len(left) != 1:
    die(f"expected one leftover, got {[hex(x) for x in left]}")
MAP[left[0]] = 0
log(f"  leftover mapped 0x{left[0]:x} -> real 0x0")
log("")

if sorted(MAP.values()) != list(range(16)):
    die("not a bijection")

log("[MAP]  mapped -> real")
for m in range(16):
    log(f"  {m:x} -> {MAP[m]:x}")

json.dump({"cluster": live[1], "magic": MAGIC.hex(),
           "map": {str(k): v for k, v in MAP.items()}},
          open(OUTF, "w"), indent=2)
log("")
log(f"written {OUTF}")
open(LOG, "w", encoding="utf-8").write("\n".join(L) + "\n")
