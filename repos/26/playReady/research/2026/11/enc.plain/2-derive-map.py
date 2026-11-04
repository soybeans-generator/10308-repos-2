# =============================================================================
# 2-derive-map.py
#
# Stage 2 of the chain: recover this build's 16-entry nibble permutation
# ("[MAP] mapped -> real") by exercising the live license-decrypt path.
#
# WHY THIS SCRIPT EXISTS
#   The private encryption key in *.enc.prv is stored as 64 nibbles that have
#   been passed through per-nibble tables and then through a fixed 16-entry
#   permutation. The tables are in the DLL and can be read statically; the
#   permutation is per-library-build, is NOT published, and brute force is
#   infeasible (16! = 20,922,789,888,000). So it is measured instead, using a
#   chosen-key oracle:
#
#     - For each real nibble value N in 0x01..0x0f, an ECC key is generated
#       whose private scalar is that nibble repeated 64 times, and a licence
#       blob is built for it whose plaintext content key is a known sentinel.
#     - The live bijection subtable the decrypt path uses is overwritten with a
#       constant nibble value MM (forcing every mapped nibble to MM).
#     - The licence for scalar N is decrypted. The sentinel appears in the
#       output exactly when MM maps to N, i.e. MAP[MM] = N.
#     - 15 such queries plus one leftover value (real 0x0, which cannot be
#       expressed as a private scalar) give the whole permutation.
#
#   16 syntactic entries, so 16 forced values x 15 licences = 240 decrypt calls.
#
# PIPELINE
#   1-decrypt-img.py  ->  wbtool_img.bin      (consumed here via IMG)
#   2-derive-map.py   ->  oracle_map.json     (this script)
#   3-derive-plain.py ->  extracted.enc.plain (consumes oracle_map.json)
#   4-verify-plain.py ->  content_key.bin
#
# INPUTS (all produced before this script runs)
#   wbtool_img.bin          from 1-decrypt-img.py. Supplies the plaintext copy of
#                           the eight bijection clusters and the plaintext
#                           segment blocks that the decrypt path walks.
#   extracted.enc.prv       from the msprcore.bla extractor. The target identity's
#                           obfuscated private encryption key (0x41 = 65 bytes).
#   oracle/lic_NN.blob      from oracle.py. 15 licence blobs (0x80 bytes each),
#                           one per real nibble NN = 0x01..0x0f. Each is an
#                           ECIES blob addressed to oracle/key_NN.pub whose
#                           plaintext point X-coordinate is
#                           "HELLO MICROSOFT!" || 0^16.
#   PlayReady.dll           read directly; used only to enumerate descriptors so
#                           the loaded image can be prepared.
#
# OUTPUT
#   oracle_map.json         {"0":14,"1":0,...} mapped nibble -> real nibble.
#                           Reusable for every .enc.prv from the same build.
#   derive_map.txt          log.
#
# VERIFIED BY
#   GOLD below is the permutation recorded for DLL sha 3cc6724d...; this build
#   must reproduce it. Downstream, 3-derive-plain.py must reach
#   pubkey MATCH, and 4-verify-plain.py must reach CMAC ok True.
# =============================================================================

import base64, ctypes, hashlib, json, os, re, struct, subprocess, sys

# --- inputs / outputs --------------------------------------------------------
DLL      = r"C:\Windows\SYSTEM32\Windows.Media.Protection.PlayReady.dll"  # input (live)
PRVF     = "extracted.enc.prv"   # input: from the msprcore.bla extractor
OUTF     = "oracle_map.json"     # output: consumed by 3-derive-plain.py
LOG      = "derive_map.txt"      # output: log

IMG      = "wbtool_img.bin"      # input: from 1-decrypt-img.py
ORACLE   = "oracle"              # input dir: from oracle.py (lic_NN.blob)

DESC     = 0x491C0          # .enc.prv consumer (decrypt license blob)
CLEN     = 0x400            # 64 per-nibble subtables x 16 bytes
RWX      = 0x40
TIMEOUT  = 900

# The decrypted licence output is (signature key || content key) XOR this magic.
# W10 sequence; a W11 library needs the W11 sequence instead. Getting this wrong
# makes every query look like a miss.
MAGIC = bytes.fromhex("a77bece491a87ebcd8a2c62856b165b3"
                     "3ad2572cf88bdae3ddc79be816be3185")   # W10 blob XOR
SENT  = b"HELLO MICROSOFT!" + b"\x00" * 16
WANT  = bytes(a ^ b for a, b in zip(SENT, MAGIC))

# The eight 0x400-byte nibble-permutation clusters in .rdata, as located by
# scanning wbtool_img.bin. Only ONE of them is on the live decrypt path for a
# given key format; phase 1 below determines which, by testing lic_01 against
# each and looking for the sentinel.
CLUSTERS = [("t3", 0x843720), ("t4", 0x862ee0), ("s1", 0x882920), ("s2", 0x8a23f0),
            ("s3", 0x8c2470), ("s4", 0x8e2210), ("s5", 0x902180), ("s6", 0x922230)]

# recorded result for DLL 10.0.19041.4780 — advisory cross-check only
GOLD = {0x0: 0xe, 0x1: 0x0, 0x2: 0xb, 0x3: 0x4, 0x4: 0xa, 0x5: 0x7, 0x6: 0xc, 0x7: 0x3,
        0x8: 0x2, 0x9: 0x8, 0xa: 0x9, 0xb: 0x5, 0xc: 0xf, 0xd: 0x1, 0xe: 0x6, 0xf: 0xd}
GOLD_DLL_SHA = "3cc6724d105e94bb0fb5971cc07ab2967dde2290ecebf4e0d4a910c80732ba7a"


# ---------------------------------------------------------------- worker
# Runs in its own process (see the --sweep entry point at the bottom) so that a
# fault in the decrypt path cannot take down the driver, and so the loaded image
# is discarded after every cluster / nibble.
def sweep(cbase, blobpath):
    PRV = open(PRVF, "rb").read()
    img = open(IMG, "rb").read()     # from 1-decrypt-img.py
    fb = open(DLL, "rb").read()

    # --- enumerate segment spans from the file, so the image can be prepared.
    # Only segment descriptors are used; heap-exec blocks stay ciphertext and
    # the kernel decrypts them itself on the op=3 call below.
    u32 = lambda b, o: struct.unpack_from("<I", b, o)[0]
    lf, nsec = u32(fb, 0x3C), struct.unpack_from("<H", fb, u32(fb, 0x3C) + 6)[0]
    optsz = struct.unpack_from("<H", fb, lf + 20)[0]
    sizeImg = u32(fb, lf + 24 + 56)
    p = lf + 24 + optsz
    secs = []
    for _ in range(nsec):
        vs, va, rs, rp = struct.unpack_from("<IIII", fb, p + 8)
        secs.append((va, rs, rp)); p += 40

    def raw_at(rva, n):
        """Ciphertext from the on-disk file for this RVA, or None if unmapped."""
        for va, rs, rp in secs:
            if va <= rva < va + rs:
                if rp + (rva - va) + n > len(fb):
                    return None
                return fb[rp + (rva - va):rp + (rva - va) + n]
        return None

    seg, seen = [], set()
    for va, rs, rp in secs:
        b = fb[rp:rp + rs]
        for off in range(0, max(0, len(b) - 0x40), 4):
            size = u32(b, off + 0x20)
            # 0x200000 cap, matching 1-decrypt-img.py. A 0x2000 cap silently
            # skips the two large descriptors and breaks the decrypt path.
            if size < 0x40 or size > 0x200000 or off + size > len(b):
                continue
            if hashlib.sha256(b[off + 0x20:off + size]).digest() != b[off:off + 32]:
                continue
            if size == 0xF0:                       # heap-exec: kernel decrypts on op=3
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
    k32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                      ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    k32.ReadProcessMemory.restype = ctypes.c_int
    nt = ctypes.WinDLL("ntdll")
    Raw = nt.NtQuerySystemInformation
    Raw.argtypes = [ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p]
    Raw.restype = ctypes.c_long
    base = k32.LoadLibraryW(DLL)
    DUM, ME = ctypes.c_ulong(0), ctypes.c_void_p(-1)

    def rd(addr, n):
        """Read the caller's own memory without raising on bad pointers."""
        if not addr or addr < 0x10000 or addr > 0x7FFFFFFFFFFF:
            return b""
        buf = ctypes.create_string_buffer(n)
        got = ctypes.c_size_t(0)
        if not k32.ReadProcessMemory(ME, ctypes.c_void_p(addr), buf, n, ctypes.byref(got)):
            return b""
        return buf.raw[:got.value]

    def wr(rva, data):
        """
        Write into the loaded image, RESTORING THE PAGE'S ORIGINAL PROTECTION
        afterwards. Leaving the page writable makes the kernel reject the WB
        descriptor with 0xc000000d, so this restore is mandatory.
        """
        data = bytes(data)
        addr = ctypes.c_void_p(base + rva)
        span = (len(data) + 0xFFF) & ~0xFFF
        old = ctypes.c_ulong(0)
        if not k32.VirtualProtect(addr, span, RWX, ctypes.byref(old)):
            return False
        ctypes.memmove(addr, data, len(data))
        k32.VirtualProtect(addr, span, old.value, ctypes.byref(DUM))
        return True

    # --- prepare the image: copy every decrypted segment span over the live
    # ciphertext, so the decrypt path executes real code rather than noise.
    n = 0
    for r, s in seg:
        rawb = raw_at(r, s)
        if rawb is None or img[r:r + s] == rawb:
            continue                            # unmapped, or nothing was decrypted here
        if wr(r, img[r:r + s]):
            n += 1

    def onf(ep):
        """Report where the decrypt path died, then hard-exit (sys.exit cannot
        unwind out of a ctypes callback)."""
        er = struct.unpack_from("<Q", ctypes.string_at(ep, 8))[0]
        c = struct.unpack_from("<I", ctypes.string_at(er, 4))[0]
        a = struct.unpack_from("<Q", ctypes.string_at(er + 0x10, 8))[0]
        print(f"FAULT 0x{c:08x} rva 0x{(a - base) & 0xFFFFFFFF:x}", flush=True)
        os._exit(3)

    VEH = ctypes.CFUNCTYPE(ctypes.c_long, ctypes.c_void_p)
    kv = VEH(onf)
    k32.AddVectoredExceptionHandler(1, kv)

    blob = open(blobpath, "rb").read()            # oracle/lic_NN.blob

    # --- one decrypt of the given licence blob with the target .enc.prv.
    # Argument block layout for descriptor 0x491C0 (op=3):
    #   rcx+0x00 status ptr   rcx+0x08 mode        rcx+0x0c key ptr (0x41 bytes)
    #   rcx+0x14 size = 0x41  rcx+0x18 blob ptr    rcx+0x20 output ptr
    # The output is (signature key || content key) XOR MAGIC.
    def decrypt():
        st = ctypes.create_string_buffer(0x40)
        o = ctypes.create_string_buffer(0x100)
        kb = ctypes.create_string_buffer(PRV, 0x48)
        cb = ctypes.create_string_buffer(blob, len(blob))
        a = ctypes.create_string_buffer(0x40)
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

    print(f"PATCHED {n}", flush=True)

    # --- control run with the cluster intact. This must NOT produce the
    # sentinel: the target key's scalar is not NN*0x111..1, so if the sentinel
    # appears either the key or the licences are wrong and the whole sweep would
    # be meaningless.
    orig = ctypes.string_at(base + cbase, CLEN)
    rc, sd, out = decrypt()
    print(f"CONTROL nt=0x{rc:08x} st={sd.hex()} sentinel={'YES' if out == WANT else 'no'}",
          flush=True)

    # --- the oracle proper: force every mapped nibble to MM, look for the
    # sentinel. A HIT means MAP[MM] == this licence's real nibble.
    for mm in range(16):
        wr(cbase, bytes([mm]) * CLEN)
        try:
            rc, sd, out = decrypt()
        finally:
            wr(cbase, orig)                     # always restore, even on fault
        hit = (rc == 0 and sd == b"\0\0\0\0" and out == WANT)
        print(f"RESULT {mm:02x} {'HIT' if hit else 'MISS'}", flush=True)
    os._exit(0)


if len(sys.argv) > 1 and sys.argv[1] == "--sweep":
    sweep(int(sys.argv[2], 0), sys.argv[3])
    raise SystemExit


# ---------------------------------------------------------------- driver
L = []
def log(s=""):
    L.append(str(s)); print(s, flush=True)

def die(msg):
    log(f"FATAL: {msg}")
    open(LOG, "w", encoding="utf-8").write("\n".join(L) + "\n")
    sys.exit(1)

# --- preflight: refuse to run with anything missing or stunted, because a
# partial run would still emit a plausible-looking permutation.
for f in (IMG, PRVF):
    if not os.path.isfile(f):
        die(f"missing {f}")
if not os.path.isdir(ORACLE):
    die(f"missing {ORACLE}\\ - run oracle.py first")

blobs = {}
for nib in range(1, 16):
    path = os.path.join(ORACLE, f"lic_{nib:02x}.blob")
    if not os.path.isfile(path):
        die(f"missing {path}")
    if os.path.getsize(path) != 0x80:
        die(f"{path} is not 0x80 bytes")
    blobs[nib] = path

dll_sha = hashlib.sha256(open(DLL, "rb").read()).hexdigest()
log(f"dll    {DLL}")
log(f"sha256 {dll_sha}")
log(f"image  {IMG}  ({os.path.getsize(IMG):,} bytes)")
log(f"prv    {PRVF}  ({os.path.getsize(PRVF)} bytes)")
log("")

def run(cbase, blobpath, tag):
    """Run one sweep in a child process and summarise what it reported."""
    p = subprocess.run([sys.executable, os.path.abspath(__file__),
                        "--sweep", hex(cbase), blobpath],
                       capture_output=True, text=True, timeout=TIMEOUT)
    lines = [x for x in (p.stdout or "").splitlines() if x.strip()]
    info = {"patched": None, "control": None, "hits": [], "fault": None}
    for x in lines:
        if x.startswith("PATCHED "):
            info["patched"] = int(x.split()[1])
        elif x.startswith("CONTROL "):
            info["control"] = x
        elif x.startswith("RESULT "):
            f = x.split()
            if len(f) >= 3 and f[2] == "HIT":
                info["hits"].append(int(f[1], 16))
        elif x.startswith("FAULT "):
            info["fault"] = x
    if info["fault"]:
        log(f"  {tag}: {info['fault']}")
    elif info["patched"] is None:
        log(f"  {tag}: no output (rc {p.returncode})")
        if p.stderr.strip():
            log(f"      {p.stderr.strip().splitlines()[-1]}")
    else:
        log(f"  {tag}: patched {info['patched']}  {info['control'] or ''}"
            f"  hits {[hex(h) for h in info['hits']]}")
    return info

# ---- phase 1: which cluster is live?  (lic_01 -> real nibble 0x1)
# lic_01's scalar is 0x11..11, so if the live cluster is forced to MM and the
# sentinel appears, MAP[MM] = 1. Clusters not on this key format's path produce
# 16 identical outputs (no HIT) because patching them changes nothing.
log("phase 1: locate the live bijection cluster (lic_01 -> real nibble 0x1)")
log("")
live, seed = None, None
for name, cbase in CLUSTERS:
    info = run(cbase, blobs[1], f"{name} 0x{cbase:06x}")
    if info["fault"] or info["patched"] is None:
        continue
    if info["control"] and "sentinel=YES" in info["control"]:
        die(f"{name}: control decrypt returned the sentinel - wrong key or blown oracle")
    if len(info["hits"]) == 1:
        if live is not None:
            die(f"two live clusters: {live[0]} and {name}")   # ambiguity is fatal
        live, seed = (name, cbase), info["hits"][0]
    elif len(info["hits"]) > 1:
        die(f"{name}: {len(info['hits'])} hits for one nibble - table not a clean bijection")
    log("")

if live is None:
    die("no cluster produced the sentinel - wbtool_img.bin or the licences are wrong")

log(f"live cluster: {live[0]} 0x{live[1]:06x}   MAP[0x{seed:x}] = 0x1")
log("")

# ---- phase 2: remaining 14 nibbles on the live cluster
# Every real nibble must resolve to exactly one mapped value, and no two real
# nibbles may claim the same mapped value - that would mean the table is not a
# permutation and the result must not be written.
log("phase 2: resolve the remaining real nibbles")
log("")
MAP = {seed: 1}
for nib in range(2, 16):
    info = run(live[1], blobs[nib], f"nibble 0x{nib:x}")
    if info["fault"] or info["patched"] is None:
        die(f"nibble 0x{nib:x}: sweep failed")
    if len(info["hits"]) != 1:
        die(f"nibble 0x{nib:x}: {len(info['hits'])} hits, expected exactly 1")
    mm = info["hits"][0]
    if mm in MAP:
        die(f"nibble 0x{nib:x}: mapped value 0x{mm:x} already taken by real 0x{MAP[mm]:x}")
    MAP[mm] = nib
    log("")

# ---- leftover -> real 0x0
# Real nibble 0x0 cannot be expressed as a private scalar (zero is not a valid
# key), so it is never queried; it is whatever mapped value remains unused.
# Exactly one must remain - if not, some nibble was mis-resolved.
left = [m for m in range(16) if m not in MAP]
if len(left) != 1:
    die(f"expected exactly one leftover, got {[hex(x) for x in left]}")
MAP[left[0]] = 0
log(f"leftover mapped 0x{left[0]:x} -> real 0x0")
log("")

if sorted(MAP.values()) != list(range(16)):
    die("result is not a 16-entry bijection")

log("[MAP]  mapped -> real")
for m in range(16):
    log(f"  {m:x} -> {MAP[m]:x}")
log("")

# --- advisory cross-check. GOLD is the permutation recorded for this exact DLL
# build; a mismatch on a matching build means one of the two runs is wrong.
if dll_sha == GOLD_DLL_SHA:
    if MAP == GOLD:
        log("cross-check: matches the recorded permutation for this DLL (GOLD match)")
    else:
        log("NOTE: DLL sha matches the recorded build but the permutation differs.")
        log("      one of the two runs is wrong - investigate before trusting this file.")
else:
    log(f"cross-check: DLL differs from the recorded build ({GOLD_DLL_SHA[:16]}...),")
    log("      so a different permutation is expected. GOLD comparison skipped.")

with open(OUTF, "w") as fh:
    json.dump({str(k): v for k, v in MAP.items()}, fh, indent=2)
log("")
log(f"written {OUTF}  (16 entries)")
open(LOG, "w", encoding="utf-8").write("\n".join(L) + "\n")
