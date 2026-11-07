# 4-derive-plain.py
# =============================================================================
#
# Stage 4: extracted.enc.prv -> extracted.enc.plain
#
#   stage 1  prv[0x00:0x20]  --stage-1 routine-->  OBF
#   stage 2  OBF (mutated in place) --stage-2 routine-->  mut
#   stage 3  mut   --64 per-nibble bijection subtables-->  mapped
#   stage 4  mapped --16-entry permutation from oracle_map.json-->  plain
#
#   Proven by d*G == extracted.enc.pub. Nothing is written unless it holds.
#
# NO ADDRESS IN THIS FILE IS HARDCODED
#   Both stage routines are selected at runtime by the key's variant byte, found
#   by walking the code graph outward from the 0x41-byte key consumer. The public
#   key decides which (stage 1, stage 2) pairing is real.
#
# INPUTS   testdata/extracted.enc.prv, testdata/extracted.enc.pub,
#          testdata/wbtool_img.bin, testdata/oracle_map.json
# OUTPUT   testdata/extracted.enc.plain, testdata/derive_plain.txt
#
# REPORTING
#   Every child prints rc and status for every call, rejects included, so
#   "wrong routine" and "never called" are distinguishable. A child that
#   produces no usable line has its stderr and return code logged. The VEH fault
#   line carries the stage tag - "S1 FAULT" / "S2 FAULT" - which is the prefix
#   the driver filters on, so a fault is never recorded as "no output".
#
# KNOWN PITFALLS
#   - The stage routines' own blocks must be LEFT CIPHERTEXT. They are heap-exec,
#     so the kernel decrypts each exactly once during the op=3 call.
#   - Segment blocks must still be patched, otherwise the helpers the stages call
#     are ciphertext and the call faults. PREP=carve is the correct middle.
#   - PREP is overlap-safe by default: it patches segment spans but subtracts the
#     heap-exec blocks. wbtool_img.bin holds DECRYPTED code at those RVAs, so
#     copying it over a block the kernel will decrypt again yields garbage.
#     PREP=full patches whole spans and PREP=none patches nothing; all three are
#     selectable so they can be compared directly.
#   - A fault is reported with code, absolute address, signed offset, module and
#     bytes, then hard-exits via os._exit; sys.exit cannot unwind out of a ctypes
#     callback.
#   - On failure a localization matrix runs automatically: each candidate with
#     real inputs, then with zeroed inputs, to separate a data-dependent fault
#     from a structural one.
#
# SECURITY
#   extracted.enc.plain decrypts any licence blob addressed to that identity.
#   Keep it out of version control.
# =============================================================================

import bisect, ctypes, hashlib, json, os, struct, subprocess, sys

# --- paths -------------------------------------------------------------------
# Every input and every output lives under testdata/. There is deliberately no
# fallback to the current directory: a stale extracted.enc.prv or .enc.pub
# sitting next to the script can no longer be picked up in place of the
# intended one.
DATA = "testdata"
os.makedirs(DATA, exist_ok=True)


def data(name):
    """testdata/<name> - the only place this pipeline reads or writes."""
    return os.path.join(DATA, name)


DLL   = r"C:\Windows\SYSTEM32\Windows.Media.Protection.PlayReady.dll"
PRVF  = data("extracted.enc.prv")
PUBF  = data("extracted.enc.pub")
OUTF  = data("extracted.enc.plain")
LOG   = data("derive_plain.txt")

IMG   = data("wbtool_img.bin")
MAPF  = data("oracle_map.json")

RWX      = 0x40
CURVE_N  = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
TIMEOUT  = 300
PAT      = b"\x83\x79\x14\x41"          # cmp dword ptr [rcx+0x14], 0x41

# --- discovery tuning --------------------------------------------------------
TOL     = 0x20
WIN     = 0x400
MAXHOPS = 5
MAXBLK  = 400

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


def census(fb, secs, sizeImg, dedup=True):
    """Segment spans and heap-exec blocks from the on-disk file."""
    seg, heaps, seen = [], [], set()
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
                continue
            for k in range((size - 0xF4) // 0xC):
                o = off + 0xF4 + k * 0xC
                rva, sz = u32(b, o + 4), u32(b, o + 8)
                if rva < 0x1000 or sz < 8 or rva + sz > sizeImg:
                    continue
                if dedup and rva in seen:
                    continue
                seen.add(rva); seg.append((rva, sz))
    return seg, heaps


def raw_at(fb, secs, rva, n):
    for va, rs, rp in secs:
        if va <= rva < va + rs and rp + (rva - va) + n <= len(fb):
            return fb[rp + (rva - va):rp + (rva - va) + n]
    return None


def merge_blocks(heaps):
    out = []
    for lo, hi in sorted((h["rva"], h["rva"] + h["size"]) for h in heaps if h["size"]):
        if out and lo <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], hi))
        else:
            out.append((lo, hi))
    return out


def make_carve(merged):
    los = [b[0] for b in merged]

    def carve(r, s):
        """[r, r+s) minus the heap-exec blocks -> list of (start, len)."""
        out, cur, e = [], r, r + s
        i = max(0, bisect.bisect_right(los, r) - 1)
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
    return carve


# ============================== worker =======================================
# One trial, one process.
#   --s1 <desc> [prep]
#   --s2 <desc> <obfhex> [prep] [variant]
# variant 0 real inputs / 1 zero out-buffer / 2 all zero / 3 no second size
def worker(mode, a, b, prep, var):
    TAG = "S1" if mode == "--s1" else "S2"

    def say(s):
        print(f"{TAG} {s}", flush=True)

    try:
        img = open(IMG, "rb").read()
        _raw = json.load(open(MAPF))
        MAP = {int(k): v for k, v in _raw["map"].items()}
        CLUSTER = int(_raw["cluster"])
        PRV = open(PRVF, "rb").read()
        PUB = open(PUBF, "rb").read()[-64:]
        PX = int.from_bytes(PUB[:32], "big")
        PY = int.from_bytes(PUB[32:], "big")

        fb = open(DLL, "rb").read()
        sizeImg, secs = pe(fb)
        seg, heaps = census(fb, secs, sizeImg)
        carve = make_carve(merge_blocks(heaps))

        k32 = ctypes.WinDLL("kernel32")
        k32.LoadLibraryW.restype = ctypes.c_void_p
        k32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                       ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
        k32.K32GetMappedFileNameW.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                              ctypes.c_wchar_p, ctypes.c_ulong]
        nt = ctypes.WinDLL("ntdll")
        Raw = nt.NtQuerySystemInformation
        Raw.argtypes = [ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p]
        Raw.restype = ctypes.c_long

        base = k32.LoadLibraryW(DLL)
        if not base:
            say("ERR loadlibrary"); os._exit(4)

        def wr(rva, buf):
            buf = bytes(buf)
            span = (len(buf) + 0xFFF) & ~0xFFF
            old = ctypes.c_ulong(0)
            p = ctypes.c_void_p(base + rva)
            if not k32.VirtualProtect(p, span, RWX, ctypes.byref(old)):
                return False
            ctypes.memmove(p, buf, len(buf))
            k32.VirtualProtect(p, span, old.value, ctypes.byref(ctypes.c_ulong(0)))
            return True

        # ---- prep ------------------------------------------------------
        patched = skipped = 0
        if prep != "none":
            for r, s in seg:
                if r + s > len(img):
                    continue
                c = raw_at(fb, secs, r, s)
                if c is None or img[r:r + s] == c:
                    continue
                runs = [(r, s)] if prep == "full" else carve(r, s)
                if prep != "full" and not runs:
                    skipped += 1
                for x, n in runs:
                    if wr(x, img[x:x + n]):
                        patched += 1
                    else:
                        skipped += 1
        say(f"PREP {prep} patched {patched} skipped {skipped}")

        def onf(ep):
            er = struct.unpack_from("<Q", ctypes.string_at(ep, 8))[0]
            code = u32(ctypes.string_at(er, 4), 0)
            ad = struct.unpack_from("<Q", ctypes.string_at(er + 0x10, 8))[0]
            nm = ctypes.create_unicode_buffer(512)
            try:
                k32.K32GetMappedFileNameW(ctypes.c_void_p(-1), ctypes.c_void_p(ad),
                                          nm, 512)
            except Exception:
                pass
            mod = nm.value.rsplit("\\", 1)[-1] if nm.value else "-"
            try:
                raw = ctypes.string_at(ad, 16).hex()
            except Exception:
                raw = "-"
            say(f"FAULT 0x{code:08x} addr=0x{ad:016x} off={ad - base:+#x} "
                f"module={mod} bytes={raw}")
            os._exit(3)

        VEH = ctypes.CFUNCTYPE(ctypes.c_long, ctypes.c_void_p)
        keep = VEH(onf)
        k32.AddVectoredExceptionHandler(1, keep)

        def op3(desc_rva, ln, status, key, buf_out, size2=None):
            args = ctypes.create_string_buffer(0x40)
            struct.pack_into("<Q", args, 0x00, 3)
            struct.pack_into("<Q", args, 0x08, base + desc_rva)
            struct.pack_into("<Q", args, 0x10, ctypes.addressof(status))
            struct.pack_into("<Q", args, 0x18, ctypes.addressof(key))
            struct.pack_into("<I", args, 0x20, 0x20)
            struct.pack_into("<Q", args, 0x24, ctypes.addressof(buf_out))
            if size2 is not None:
                struct.pack_into("<I", args, 0x2C, size2)
            return Raw(0xB9, ctypes.cast(args, ctypes.c_void_p), ln, None) & 0xFFFFFFFF

        # ---- stage 1 ---------------------------------------------------
        if mode == "--s1":
            st = ctypes.create_string_buffer(0x40)
            kb = ctypes.create_string_buffer(PRV[0x00:0x20], 0x40)
            ob = ctypes.create_string_buffer(0x40)
            rc = op3(a, 0x2C, st, kb, ob)
            sd = bytes(st.raw)[:4]
            OBF = bytes(ob.raw)[:0x20]
            if rc != 0 or sd != b"\0\0\0\0" or OBF == b"\0" * 0x20:
                say(f"REJECT rc=0x{rc:08x} st={sd.hex()} out={OBF.hex()}")
            else:
                say(f"OK {OBF.hex()}")
            os._exit(0)

        # ---- stage 2 (+ chain) -----------------------------------------
        OBF = bytes.fromhex(b)
        if var == 2:
            OBF_IN, OB2_IN = bytes(0x20), bytes(0x20)
        elif var == 1:
            OBF_IN, OB2_IN = OBF, bytes(0x20)
        else:
            OBF_IN, OB2_IN = OBF, PRV[0x20:0x40]

        ln = 0x2C if var == 3 else 0x30
        st2 = ctypes.create_string_buffer(0x40)
        ib = ctypes.create_string_buffer(OBF_IN, 0x40)
        ob2 = ctypes.create_string_buffer(OB2_IN, 0x40)
        rc2 = op3(a, ln, st2, ib, ob2, None if var == 3 else 0x20)
        sd2 = bytes(st2.raw)[:4]
        if rc2 != 0 or sd2 != b"\0\0\0\0":
            say(f"REJECT var={var} rc=0x{rc2:08x} st={sd2.hex()}")
            os._exit(0)
        mut = bytes(ib.raw)[:0x20]

        BLK = [img[CLUSTER + i * 16: CLUSTER + i * 16 + 16] for i in range(64)]
        def nibs(x):
            return [(x[i >> 1] >> (4 if i % 2 == 0 else 0)) & 0xF for i in range(64)]
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
        say(f"{'MATCH' if ok else 'NOMATCH'} var={var} mut={mut.hex()} "
            f"mapped={mapped.hex()} plain={plain.hex()}")
        os._exit(0)

    except SystemExit:
        raise
    except BaseException as e:
        say(f"ERR {type(e).__name__}: {e}")
        os._exit(5)


if len(sys.argv) > 1 and sys.argv[1] in ("--s1", "--s2"):
    if sys.argv[1] == "--s1":
        worker("--s1", int(sys.argv[2], 0), None,
               sys.argv[3] if len(sys.argv) > 3 else "carve", 0)
    else:
        worker("--s2", int(sys.argv[2], 0), sys.argv[3],
               sys.argv[4] if len(sys.argv) > 4 else "carve",
               int(sys.argv[5]) if len(sys.argv) > 5 else 0)
    raise SystemExit

# ============================== driver =======================================
L = []
def log(s=""):
    L.append(str(s)); print(s, flush=True)

def die(msg):
    log(f"FATAL: {msg}")
    open(LOG, "w", encoding="utf-8").write("\n".join(L) + "\n")
    sys.exit(1)

for f in (MAPF, IMG, PRVF, PUBF):
    if not os.path.isfile(f):
        die(f"missing {f}")

_raw = json.load(open(MAPF))
if not (isinstance(_raw, dict) and "map" in _raw and "cluster" in _raw):
    die(f"{MAPF} is in the old flat format - re-run stage 3")
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
sizeImg, secs = pe(fb)
seg, heaps = census(fb, secs, sizeImg)
carve = make_carve(merge_blocks(heaps))

log(f"dll    {DLL}")
log(f"sha256 {hashlib.sha256(fb).hexdigest()}")
log(f"image  {IMG}  ({len(img):,} bytes, SizeOfImage 0x{sizeImg:x})")
log(f"prv    {PRVF}  ({len(PRV)} bytes, variant 0x{PRV[0x40]:02x} %3={PRV[0x40] % 3})")
log(f"pub    {PUBF}")
log(f"cluster 0x{CLUSTER:06x}  (from {MAPF})")
if _raw.get("magic"):
    log(f"magic  {_raw['magic']}")
log("")

# --- span / heap-exec overlap census: is PREP=carve even needed here?
merged = merge_blocks(heaps)
ov = 0
for r, s in seg:
    if len(carve(r, s)) != 1:
        ov += 1
log(f"spans intersecting heap-exec blocks: {ov} of {len(seg)}")
log("")

# --- heap-exec inventory: descriptor RVA -> (code RVA, code len)
heap_desc = {h["desc"]: (h["rva"], h["size"]) for h in heaps}
log(f"heap-exec descriptors {len(heap_desc)}")
log("")

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
    out = []
    hi = min(hi, len(img) - 8)
    for o in range(max(0x1000, lo), hi):
        if img[o] in (0x48, 0x4C) and img[o + 1] == 0x8D and img[o + 2] in MODRM:
            out.append(o + 7 + struct.unpack_from("<i", img, o + 3)[0])
        elif img[o] in (0xE8, 0xE9):
            out.append(o + 5 + struct.unpack_from("<i", img, o + 1)[0])
    return out

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
                nxt.append((t, min(WIN, len(img) - t)))
    log(f"  hop {depth}: blocks {len(frontier)} -> descriptors {len(CAND)}, "
        f"next {len(nxt)}")
    frontier = nxt

CAND = sorted(CAND)
log(f"stage candidates: {[hex(x) for x in CAND]}")
log("")
if not CAND:
    die("no stage candidates - the lea/call idiom differs on this build")

me = os.path.abspath(__file__)

def run(args, tag):
    """Run one child and return (kind, line, stderr, rc, prep)."""
    try:
        p = subprocess.run([sys.executable, me] + args,
                           capture_output=True, text=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        return "TIMEOUT", "", "", -1, []
    lines = [x for x in (p.stdout or "").splitlines() if x.strip()]
    pre = "--s1" if args[0] == "--s1" else "--s2"
    tagp = "S1" if pre == "--s1" else "S2"
    body = [x for x in lines if x.startswith(tagp + " ")]
    err = (p.stderr or "").strip().splitlines()
    kind = "NONE"
    line = ""
    for x in body:
        w = x.split()
        if len(w) > 1 and w[1] == "FAULT":
            kind, line = "FAULT", x; break
        if len(w) > 1 and w[1] in ("OK", "REJECT", "MATCH", "NOMATCH", "ERR"):
            kind, line = w[1], x
    prep = [x for x in body if " PREP " in x]
    return kind, line, (err[-1] if err else ""), p.returncode, prep

# --- phase 1: which candidates can act as stage 1?
obfs = {}
log("phase 1: stage-1 candidates (PREP=carve)")
for dv in CAND:
    code = heap_desc[dv][0]
    r = run(["--s1", hex(dv), "carve"], dv)
    kind, line, err, rc, prep = r
    log(f"  s1 0x{dv:06x} code 0x{code:06x}: {line or f'<{kind}> rc={rc}'}")
    if err:
        log(f"      stderr: {err}")
    if kind == "OK":
        obfs[dv] = line.split()[2]
log("")
log(f"stage-1 candidates that produced an OBF: {len(obfs)}")
log("")
if not obfs:
    die("no candidate produced an OBF - stage 1 is not in the candidate set")

# --- phase 2: pair each surviving OBF with every candidate
found = None
faults, rejects = [], []
log("phase 2: stage-2 pairing (PREP=carve, variant 0)")
for s1, obf in sorted(obfs.items()):
    for s2 in CAND:
        code2 = heap_desc[s2][0]
        kind, line, err, rc, prep = run(["--s2", hex(s2), obf, "carve", "0"], s2)
        if kind == "MATCH" and found is None:
            f = line.split()
            found = (s1, s2, obf, f[3].split("=")[1], f[4].split("=")[1],
                     f[5].split("=")[1])
        if kind == "FAULT":
            faults.append((s2, line))
        elif kind == "REJECT":
            rejects.append((s2, line))
            continue
        log(f"  s2 0x{s2:06x} code 0x{code2:06x}: {line or f'<{kind}> rc={rc}'}")
        if err:
            log(f"      stderr: {err}")

log("")
log(f"summary: MATCH {int(bool(found))}  FAULT {len(faults)}  "
    f"REJECT {len(rejects)}  of {len(obfs) * len(CAND)} attempts")
log("")

# --- localization matrix when nothing matched
if not found:
    log("no pairing reproduced the public key - localizing")
    log("")
    log("  A: variant 0 (real OBF, real out-buffer, ln 0x30)")
    log("  B: variant 1 (real OBF, ZERO out-buffer)  -> data dependence")
    log("  C: variant 2 (all inputs zero)            -> structural vs data")
    log("  D: variant 3 (ln 0x2C, no second size)    -> arg-length dependence")
    log("")
    log(f"  {'cand':<10}{'code':<10}{'A':<8}{'B':<8}{'C':<8}{'D':<8}note")
    for s2 in CAND:
        obf = sorted(obfs.values())[0]
        row, notes = [], []
        for v in range(4):
            kind, line, err, rc, prep = run(["--s2", hex(s2), obf, "carve", str(v)], s2)
            row.append(kind)
            if err:
                notes.append(f"v{v} stderr {err}")
        log(f"  {hex(s2):<10}{hex(heap_desc[s2][0]):<10}"
            f"{row[0]:<8}{row[1]:<8}{row[2]:<8}{row[3]:<8}{'; '.join(notes)}")
    log("")
    log("  reading the matrix")
    log("    A=FAULT B=FAULT C=FAULT  -> structural: the routine is wrong, or the")
    log("                                image state is wrong (try PREP=full/none)")
    log("    A=FAULT B=MATCH/NOMATCH  -> data-dependent: the OBF or prv[0x20:0x40]")
    log("                                drives a bad index/shift in stage 2")
    log("    A=FAULT D=REJECT         -> arg-length dependent: ln 0x30 is required")
    log("                                and the routine rejects it anyway")
    log("    all REJECT               -> the routine is not stage 2 on this build")
    log("")
    log("  prep sensitivity for the best stage-2-looking candidate")
    cand = next((s2 for s2, _ in rejects), CAND[0])
    obf = sorted(obfs.values())[0]
    for prep in ("full", "carve", "none"):
        kind, line, err, rc, _ = run(["--s2", hex(cand), obf, prep, "0"], cand)
        log(f"    PREP={prep:<6} 0x{cand:06x}: {line or f'<{kind}> rc={rc}'}")
        if err:
            log(f"        stderr: {err}")
    die("no (stage 1, stage 2) pairing reproduced extracted.enc.pub")

s1, s2, OBF_H, MUT_H, MAPPED_H, PLAIN_H = found
OBF = bytes.fromhex(OBF_H)
plain = bytes.fromhex(PLAIN_H)

log(f"stage 1   0x{heap_desc[s1][0]:06x}  (descriptor 0x{s1:06x})")
log(f"OBF       {OBF.hex()}")
log(f"stage 2   0x{heap_desc[s2][0]:06x}  (descriptor 0x{s2:06x})")
log(f"in-mutated {MUT_H}")
log(f"mapped    {MAPPED_H}")
log(f"plain     {PLAIN_H}")

# --- final check, then write
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
log(f"written   {OUTF}  ({len(plain)} bytes)  "
    f"sha256 {hashlib.sha256(plain).hexdigest()}")

open(LOG, "w", encoding="utf-8").write("\n".join(L) + "\n")

# end of 4-derive-plain.py
