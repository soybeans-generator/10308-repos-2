# =============================================================================
# 4-derive-plain.py
#
# Stage 4 of the chain: extracted.enc.prv -> extracted.enc.plain
#
# WHAT IT DOES
#   Turns the obfuscated 65-byte private ECC key into the plaintext 32-byte
#   private scalar, in four steps:
#
#     stage 1  prv[0x00:0x20]  --stage-1 routine-->  OBF
#     stage 2  OBF (mutated in place) --0x529250-->  mut
#     stage 3  mut   --64 per-nibble bijection subtables-->  mapped
#     stage 4  mapped --16-entry permutation from oracle_map.json-->  plain
#
#   Then it proves the result: d * G must reproduce extracted.enc.pub. Nothing
#   is written unless that proof succeeds.
#
# WHY EACH STAGE IS IMPLEMENTED WHERE IT IS
#   Stages 1 and 2 are the library's own code, invoked through the kernel's
#   Warbird call mechanism. Reimplementing them in Python would mean
#   reimplementing the obfuscation, so the real routines are called.
#   Stages 3 and 4 are done in Python because the bijection subtables are plain
#   data in the decrypted image and the permutation was measured by
#   3-derive-map.py.
#
#   There is deliberately no fallback and no bypass for stage 1. A substituted
#   OBF would still let stages 2-4 reach pubkey MATCH and would mask a broken
#   stage 1, turning the only acceptance test into a false pass.
#
# STAGE 1 IS DISCOVERED, NOT HARDCODED
#   The stage-1 routine is selected at runtime by the key's variant byte, so its
#   address cannot be assumed. It is found by walking the code graph outward from
#   the 0x41-byte key consumer:
#     - the consumer is located by its own input-size check,
#       `cmp dword ptr [rcx+0x14], 0x41` (83 79 14 41), unique in the image;
#     - from there, rip-relative lea targets and rel32 call/jmp targets are
#       followed up to a few hops, collecting every heap-exec descriptor they
#       reach (descriptor refs land ~7 bytes off, hence the tolerance);
#     - plain segment code is followed too, because the shim that issues the
#       inner WB call lives there rather than in a WB block.
#   That yields a superset of candidates. The public key then decides: each
#   candidate is driven through the full chain and only the one whose scalar
#   reproduces .enc.pub is accepted.
#
#   Candidates are tried in separate processes because a wrong candidate can
#   fault inside the library (the 0x720-family routines take a pointer where the
#   0x4f-family take a size). Isolation keeps one bad candidate from ending the
#   search.
#
# PIPELINE
#   1-make-oracle.py   ->  oracle/key_NN.pub, oracle/lic_NN.blob
#   2-decrypt-img.py   ->  wbtool_img.bin
#   3-derive-map.py    ->  oracle_map.json
#   4-derive-plain.py  ->  extracted.enc.plain                (this script)
#
# INPUTS
#   extracted.enc.prv      from the msprcore.bla extractor. 0x41 = 65 bytes:
#                            [0x00:0x20]  first half   (stage 1 input)
#                            [0x20:0x40]  second half  (stage 2 read-only input)
#                            [0x40]       variant byte (selects the routine pair)
#   extracted.enc.pub      from the same extractor, 64 bytes X||Y. Used ONLY to
#                          verify the derived scalar, and to pick the stage-1
#                          candidate - never as an input to the derivation.
#   wbtool_img.bin         from 2-decrypt-img.py. Supplies (a) the plaintext
#                          segment blocks copied into the live image so stages
#                          1 and 2 can execute, and (b) the live bijection set.
#   oracle_map.json        from 3-derive-map.py. Carries both the build's
#                          16-entry permutation and the RVA of the live bijection
#                          set, so nothing about the table layout is hardcoded.
#   PlayReady.dll          read directly; used to enumerate descriptors, walk the
#                          code graph, and loaded so the routines can be called.
#
# OUTPUT
#   extracted.enc.plain    32-byte plaintext private scalar.
#   derive_plain.txt       log.
#
# ACCEPTANCE CHECK
#   Self-check d*G == .enc.pub, executed before writing. Expected for the
#   recorded build:
#       CODE_OBF 0x6c6f00   (descriptor 0x4abc0)
#       OBF      69ef7582608af8d0df0fb4b515449be5a8d0c903741cbf3353be70eb460521f4
#       plain    cdfb1d858ea5cfe062d0ba877cbe2ea731fdcd196d0c9be64699cf723cbcdcc1
#       pubkey   MATCH
#   A pass here means stages 1 through 4 all ran correctly, because each stage's
#   output feeds the next and the final scalar must land on the exact public
#   point. Independent cross-checks, run only when needed:
#       ECIES-decrypt a real licence XMR with d; the AES-CMAC must match
#       go run ./lictest       Go implementation, same content key
#
# PER-BUILD CONSTANTS
#   CODE_MAP is the one address still hardcoded: it is the stage-2 routine, also
#   selected by the variant byte. Everything else is either discovered at
#   runtime (stage 1, bijection set) or read from oracle_map.json.
#
# HOW THE STAGES ARE CALLED
#   Stages 1 and 2 are heap-exec routines, so they are invoked with the kernel's
#   op=3 call. The argument block, as the routines see it (rcx = args+0x10):
#       +0x00  -> status dword
#       +0x08  -> key / writable input buffer
#       +0x10  u32 size 0x20
#       +0x14  -> output / read-only input buffer
#       +0x1c  u32 size 0x20
#   Stage 2 mutates its +0x08 buffer in place; that mutated value is what feeds
#   the bijection, not the +0x14 buffer.
#
# KNOWN PITFALLS
#   - The stage routines' own blocks must be LEFT CIPHERTEXT. They are heap-exec,
#     so the kernel decrypts each exactly once during the op=3 call; patching
#     them from wbtool_img.bin beforehand causes a double decrypt and the routine
#     executes garbage.
#   - Segment blocks must still be patched to plaintext, otherwise the helper
#     routines the stages call are ciphertext and the call faults.
#   - oracle_map.json must come from the current 3-derive-map.py. An older
#     flat-format file has no cluster entry and is rejected rather than guessed.
#   - A fault is reported with its code and RVA, then hard-exits via os._exit;
#     sys.exit cannot unwind out of a ctypes callback and would recurse.
#
# SECURITY
#   extracted.enc.plain is the identity private encryption key: it decrypts any
#   licence blob addressed to that identity. Keep it in the offline corpus and
#   out of version control.
# =============================================================================

import ctypes, hashlib, json, os, struct, subprocess, sys

# --- inputs / outputs --------------------------------------------------------
DLL   = r"C:\Windows\SYSTEM32\Windows.Media.Protection.PlayReady.dll"  # input (live)
PRVF  = "extracted.enc.prv"      # input: msprcore.bla extractor
PUBF  = "extracted.enc.pub"      # input: msprcore.bla extractor (verification only)
OUTF  = "extracted.enc.plain"    # output
LOG   = "derive_plain.txt"       # output: log

IMG   = "wbtool_img.bin"         # input: from 2-decrypt-img.py
MAPF  = "oracle_map.json"        # input: from 3-derive-map.py (permutation + cluster)

# --- the one remaining per-build address --------------------------------------
# Stage 2 routine. Selected at runtime by the key's variant byte alongside
# stage 1, so it cannot be found by shape; identified by cross-referencing the
# WB call trace on the recorded build.
CODE_MAP = 0x529250    # stage 2: in = OBF (mutated in place), out = prv[0x20:0x40]

RWX      = 0x40
CURVE_N  = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
TIMEOUT  = 300

# --- stage-1 discovery tuning ------------------------------------------------
TOL     = 0x20      # WB delta convention lands a descriptor ref ~7 bytes off
WIN     = 0x400     # window scanned from a non-WB code target
MAXHOPS = 5
MAXBLK  = 400

# ============================== worker =======================================
# One candidate, one process. A wrong candidate can fault inside the library, so
# each trial is isolated and reports its own outcome.
def worker(desc_obf, desc_map):
    img = open(IMG, "rb").read()
    _raw = json.load(open(MAPF))
    MAP = {int(k): v for k, v in _raw["map"].items()}
    CLUSTER = int(_raw["cluster"])
    PRV = open(PRVF, "rb").read()
    PUB = open(PUBF, "rb").read()[-64:]
    PX = int.from_bytes(PUB[:32], "big")
    PY = int.from_bytes(PUB[32:], "big")

    fb = open(DLL, "rb").read()
    u32 = lambda b, o: struct.unpack_from("<I", b, o)[0]
    lf = u32(fb, 0x3C)
    nsec = struct.unpack_from("<H", fb, lf + 6)[0]
    optsz = struct.unpack_from("<H", fb, lf + 20)[0]
    sizeImg = u32(fb, lf + 24 + 56)
    p = lf + 24 + optsz
    secs = []
    for _ in range(nsec):
        vs, va, rs, rp = struct.unpack_from("<IIII", fb, p + 8)
        secs.append((va, rs, rp)); p += 40

    def raw_at(rva, n):
        for va, rs, rp in secs:
            if va <= rva < va + rs:
                if rp + (rva - va) + n > len(fb):
                    return None
                return fb[rp + (rva - va):rp + (rva - va) + n]
        return None

    # segment spans only; heap-exec blocks stay ciphertext for the kernel
    seg, seen = [], set()
    for va, rs, rp in secs:
        b = fb[rp:rp + rs]
        for off in range(0, max(0, len(b) - 0x40), 4):
            size = u32(b, off + 0x20)
            if size < 0x40 or size > 0x200000 or off + size > len(b):
                continue
            if hashlib.sha256(b[off + 0x20:off + size]).digest() != b[off:off + 32]:
                continue
            if size == 0xF0:
                continue
            for k in range((size - 0xF4) // 0xC):
                o = off + 0xF4 + k * 0xC
                rva, sz = u32(b, o + 4), u32(b, o + 8)
                if rva < 0x1000 or sz < 8 or rva + sz > sizeImg or rva in seen:
                    continue
                seen.add(rva); seg.append((rva, sz))

    k32 = ctypes.WinDLL("kernel32")
    k32.LoadLibraryW.restype = ctypes.c_void_p
    k32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong,
                                   ctypes.POINTER(ctypes.c_ulong)]
    nt = ctypes.WinDLL("ntdll")
    Raw = nt.NtQuerySystemInformation
    Raw.argtypes = [ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p]
    Raw.restype = ctypes.c_long

    base = k32.LoadLibraryW(DLL)
    if not base:
        print("RESULT ERR loadlibrary"); sys.stdout.flush(); os._exit(0)
    DUM = ctypes.c_ulong(0)

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

    for r, s in seg:
        rawb = raw_at(r, s)
        if rawb is not None and img[r:r + s] != rawb:
            wr(r, img[r:r + s])

    def onf(ep):
        er = struct.unpack_from("<Q", ctypes.string_at(ep, 8))[0]
        c = struct.unpack_from("<I", ctypes.string_at(er, 4))[0]
        a = struct.unpack_from("<Q", ctypes.string_at(er + 0x10, 8))[0]
        print(f"RESULT FAULT 0x{c:08x} 0x{(a - base) & 0xFFFFFFFF:x}")
        sys.stdout.flush(); os._exit(3)

    VEH = ctypes.CFUNCTYPE(ctypes.c_long, ctypes.c_void_p)
    keep = VEH(onf)
    k32.AddVectoredExceptionHandler(1, keep)

    def op3(desc_rva, ln, status, key, out):
        a = ctypes.create_string_buffer(0x40)
        struct.pack_into("<Q", a, 0x00, 3)
        struct.pack_into("<Q", a, 0x08, base + desc_rva)
        struct.pack_into("<Q", a, 0x10, ctypes.addressof(status))
        struct.pack_into("<Q", a, 0x18, ctypes.addressof(key))
        struct.pack_into("<I", a, 0x20, 0x20)
        struct.pack_into("<Q", a, 0x24, ctypes.addressof(out))
        if ln >= 0x30:
            struct.pack_into("<I", a, 0x2C, 0x20)
        return Raw(0xB9, ctypes.cast(a, ctypes.c_void_p), ln, None) & 0xFFFFFFFF

    # stage 1
    st = ctypes.create_string_buffer(0x40)
    kb = ctypes.create_string_buffer(PRV[0x00:0x20], 0x40)
    ob = ctypes.create_string_buffer(0x40)
    rc = op3(desc_obf, 0x2C, st, kb, ob)
    sd = bytes(st.raw)[:4]
    OBF = bytes(ob.raw)[:0x20]
    if rc != 0 or sd != b"\0\0\0\0" or OBF == b"\0" * 0x20:
        print(f"RESULT REJECT 0x{rc:08x} {sd.hex()}")
        sys.stdout.flush(); os._exit(0)

    # stage 2
    st2 = ctypes.create_string_buffer(0x40)
    ib = ctypes.create_string_buffer(OBF, 0x40)
    ob2 = ctypes.create_string_buffer(PRV[0x20:0x40], 0x40)
    rc2 = op3(desc_map, 0x30, st2, ib, ob2)
    sd2 = bytes(st2.raw)[:4]
    if rc2 != 0 or sd2 != b"\0\0\0\0":
        print(f"RESULT REJECT2 0x{rc2:08x} {sd2.hex()}")
        sys.stdout.flush(); os._exit(0)
    mut = bytes(ib.raw)[:0x20]

    # bijection + permutation
    BLK = [img[CLUSTER + i * 16: CLUSTER + i * 16 + 16] for i in range(64)]
    def nibs(b):
        return [(b[i >> 1] >> (4 if i % 2 == 0 else 0)) & 0xF for i in range(64)]
    def pack(ns):
        return bytes((ns[i] << 4) | ns[i + 1] for i in range(0, 64, 2))
    mapped = pack([BLK[i][nibs(mut)[i]] for i in range(64)])
    plain = pack([MAP[x] for x in nibs(mapped)])

    from cryptography.hazmat.primitives.asymmetric import ec
    d = int.from_bytes(plain, "big")
    ok = False
    if 0 < d < CURVE_N:
        pn = ec.derive_private_key(d, ec.SECP256R1()).public_key().public_numbers()
        ok = (pn.x, pn.y) == (PX, PY)
    print(f"RESULT {'MATCH' if ok else 'NOMATCH'} {OBF.hex()} {mut.hex()} {plain.hex()}")
    sys.stdout.flush(); os._exit(0)


if len(sys.argv) > 1 and sys.argv[1] == "--one":
    worker(int(sys.argv[2], 0), int(sys.argv[3], 0))
    raise SystemExit

# ============================== driver =======================================
L = []
def log(s=""):
    L.append(str(s)); print(s, flush=True)

def die(msg):
    log(f"FATAL: {msg}")
    open(LOG, "w", encoding="utf-8").write("\n".join(L) + "\n")
    sys.exit(1)

# --- inputs
for f in (MAPF, IMG, PRVF, PUBF):
    if not os.path.isfile(f):
        die(f"missing {f}")

_raw = json.load(open(MAPF))
if not (isinstance(_raw, dict) and "map" in _raw and "cluster" in _raw):
    die(f"{MAPF} is in the old flat format (no cluster entry) - "
        f"re-run 3-derive-map.py to regenerate it")
MAP = {int(k): v for k, v in _raw["map"].items()}
CLUSTER = int(_raw["cluster"])
if sorted(MAP.values()) != list(range(16)):
    die("oracle_map.json is not a 16-entry permutation")
if CLUSTER < 0x1000:
    die(f"oracle_map.json cluster RVA 0x{CLUSTER:x} looks invalid")

PRV = open(PRVF, "rb").read()
if len(PRV) != 0x41:
    die(f"{PRVF} is {len(PRV)} bytes, expected 0x41 (65)")
PUB = open(PUBF, "rb").read()[-64:]
PX = int.from_bytes(PUB[:32], "big")
PY = int.from_bytes(PUB[32:], "big")

img = open(IMG, "rb").read()
fb  = open(DLL, "rb").read()
u32 = lambda b, o: struct.unpack_from("<I", b, o)[0]

log(f"dll    {DLL}")
log(f"sha256 {hashlib.sha256(fb).hexdigest()}")
log(f"image  {IMG}  ({len(img):,} bytes)")
log(f"prv    {PRVF}  ({len(PRV)} bytes)")
log(f"cluster 0x{CLUSTER:06x}  (from {MAPF})")
log("")

# --- heap-exec inventory: descriptor RVA -> (code RVA, code len)
lf      = u32(fb, 0x3C)
nsec    = struct.unpack_from("<H", fb, lf + 6)[0]
optsz   = struct.unpack_from("<H", fb, lf + 20)[0]
p = lf + 24 + optsz
secs = []
for _ in range(nsec):
    vs, va, rs, rp = struct.unpack_from("<IIII", fb, p + 8)
    secs.append((va, rs, rp)); p += 40

heap_desc = {}
for va, rs, rp in secs:
    b = fb[rp:rp + rs]
    for off in range(0, max(0, len(b) - 0xF0), 4):
        if u32(b, off + 0x20) != 0xF0 or u32(b, off + 0x24) != 0xFFFFFF00:
            continue
        if hashlib.sha256(b[off + 0x20:off + 0xF0]).digest() != b[off:off + 32]:
            continue
        heap_desc[va + off] = (u32(b, off + 0x34) & 0x0FFFFFFF,
                               u32(b, off + 0x38) & 0x0FFFFFFF)
code2desc = {c: dv for dv, (c, n) in heap_desc.items()}
log(f"heap-exec descriptors {len(heap_desc)}")

if CODE_MAP not in code2desc:
    die(f"CODE_MAP 0x{CODE_MAP:06x} has no heap-exec descriptor")
DESC_MAP = code2desc[CODE_MAP]
log(f"stage 2: code 0x{CODE_MAP:06x}  descriptor 0x{DESC_MAP:06x}")
log("")

# --- stage 1 discovery: walk the code graph from the key consumer
def block_of(rva):
    for dv, (c, n) in heap_desc.items():
        if c <= rva < c + n:
            return dv, c, n
    return None, None, None

def match_desc(t):
    best = None
    for dv in heap_desc:
        d = abs(dv - t)
        if d <= TOL and (best is None or d < abs(best - t)):
            best = dv
    return best

MODRM = {0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D}
def refs(lo, hi):
    """rip-relative lea targets and rel32 call/jmp targets in [lo,hi)."""
    out = []
    hi = min(hi, len(img) - 8)
    for o in range(max(0x1000, lo), hi):
        if img[o] in (0x48, 0x4C) and img[o + 1] == 0x8D and img[o + 2] in MODRM:
            out.append(o + 7 + struct.unpack_from("<i", img, o + 3)[0])
        elif img[o] in (0xE8, 0xE9):
            out.append(o + 5 + struct.unpack_from("<i", img, o + 1)[0])
    return out

PAT = b"\x83\x79\x14\x41"       # cmp dword ptr [rcx+0x14], 0x41
sites, i = [], img.find(PAT)
while i != -1:
    sites.append(i); i = img.find(PAT, i + 1)
log(f"key-consumer size-check sites: {[hex(s) for s in sites]}")
if len(sites) != 1:
    die("expected exactly one 'cmp dword ptr [rcx+0x14], 0x41' in the image")
CHECK = sites[0]

dv0, c0, n0 = block_of(CHECK)
if dv0 is None:
    die("no heap-exec block owns the size check")
log(f"key consumer: descriptor 0x{dv0:06x}  code 0x{c0:06x}+0x{n0:x}")
log("")

CAND, visited, frontier, depth = set(), set(), [(c0, n0)], 0
while frontier and depth < MAXHOPS and len(visited) < MAXBLK:
    depth += 1
    nxt = []
    for lo, ln in frontier:
        if (lo, ln) in visited:
            continue
        visited.add((lo, ln))
        for t in refs(lo, lo + ln):
            m = match_desc(t)
            if m is not None:
                CAND.add(m)
                continue
            dv, c, n = block_of(t)
            if dv is not None:
                nxt.append((c, n))
            elif 0x1000 <= t < len(img) - 0x40:
                # non-WB code: the WB shim that issues the inner call lives here
                nxt.append((t, min(WIN, len(img) - t)))
    log(f"  hop {depth}: blocks {len(frontier)} -> descriptors {len(CAND)}, "
        f"next {len(nxt)}")
    frontier = nxt

CAND = sorted(CAND)
log(f"stage-1 candidates: {[hex(x) for x in CAND]}")
log("")
if not CAND:
    die("no stage-1 candidates - the lea/call idiom differs on this build")

# --- try each candidate in its own process; the public key decides
me = os.path.abspath(__file__)
found = None
for dv in CAND:
    code = heap_desc[dv][0]
    try:
        r = subprocess.run([sys.executable, me, "--one", hex(dv), hex(DESC_MAP)],
                           capture_output=True, text=True, timeout=TIMEOUT)
        line = next((x for x in (r.stdout or "").splitlines()
                     if x.startswith("RESULT")), "")
    except subprocess.TimeoutExpired:
        line = "RESULT TIMEOUT"
    log(f"  cand 0x{dv:06x} code 0x{code:06x}: {line or 'no output'}")
    if " MATCH " in line and found is None:
        f = line.split()
        found = (dv, code, f[2], f[3], f[4])

log("")
if not found:
    die("no candidate reproduced extracted.enc.pub - "
        "is oracle_map.json from the current build?")

dv, code, OBF_H, MUT_H, PLAIN_H = found
OBF = bytes.fromhex(OBF_H)
mut = bytes.fromhex(MUT_H)
plain = bytes.fromhex(PLAIN_H)

# --- report the winning chain
log(f"stage 1   0x{code:06x}  (descriptor 0x{dv:06x})")
log(f"OBF       {OBF.hex()}")
log(f"stage 2   0x{CODE_MAP:06x}  (descriptor 0x{DESC_MAP:06x})")
log(f"in-mutated {mut.hex()}")
BLK = [img[CLUSTER + i * 16: CLUSTER + i * 16 + 16] for i in range(64)]
def nibs(b):
    return [(b[i >> 1] >> (4 if i % 2 == 0 else 0)) & 0xF for i in range(64)]
def pack(ns):
    return bytes((ns[i] << 4) | ns[i + 1] for i in range(0, 64, 2))
mapped = pack([BLK[i][nibs(mut)[i]] for i in range(64)])
log(f"mapped    {mapped.hex()}")
log(f"plain     {plain.hex()}")

# --- final check, then write
from cryptography.hazmat.primitives.asymmetric import ec
d = int.from_bytes(plain, "big")
if not (0 < d < CURVE_N):
    die("derived scalar out of range")
pn = ec.derive_private_key(d, ec.SECP256R1()).public_key().public_numbers()
if (pn.x, pn.y) != (PX, PY):
    die(f"scalar does not reproduce {PUBF}\n"
        f"  got  X={pn.x:064x}\n"
        f"       Y={pn.y:064x}\n"
        f"  want X={PX:064x}\n"
        f"       Y={PY:064x}")

log("pubkey    MATCH")
with open(OUTF, "wb") as fh:
    fh.write(plain)
log(f"written   {OUTF}  ({len(plain)} bytes)  sha256 {hashlib.sha256(plain).hexdigest()}")

open(LOG, "w", encoding="utf-8").write("\n".join(L) + "\n")
