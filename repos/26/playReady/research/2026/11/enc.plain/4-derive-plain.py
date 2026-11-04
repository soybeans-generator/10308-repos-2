# =============================================================================
# 4-derive-plain.py
#
# Stage 4 of the chain: extracted.enc.prv -> extracted.enc.plain
#
# WHAT IT DOES
#   Turns the obfuscated 65-byte private ECC key into the plaintext 32-byte
#   private scalar, in four steps:
#
#     stage 1  prv[0x00:0x20]  --0x6c6f00-->  OBF
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
#   reimplementing the obfuscation, so instead the real routines are called.
#   Stages 3 and 4 are done in Python because the bijection subtables are plain
#   data in the decrypted image and the permutation was measured by
#   3-derive-map.py.
#
#   There is deliberately no fallback and no bypass for stage 1. A substituted
#   OBF would still let stages 2-4 reach pubkey MATCH and would mask a broken
#   stage 1, turning the only acceptance test into a false pass.
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
#                          verify the derived scalar, never as an input to the
#                          derivation.
#   wbtool_img.bin         from 2-decrypt-img.py. Supplies (a) the plaintext
#                          segment blocks copied into the live image so stages
#                          1 and 2 can execute, and (b) the s4 bijection
#                          subtables.
#   oracle_map.json        from 3-derive-map.py. The build's 16-entry
#                          permutation, mapped nibble -> real nibble.
#   PlayReady.dll          read directly; used to enumerate descriptors, find the
#                          descriptor owning each stage routine, and loaded so
#                          the routines can be called.
#
# OUTPUT
#   extracted.enc.plain    32-byte plaintext private scalar.
#   derive_plain.txt       log.
#
# ACCEPTANCE CHECK
#   Self-check d*G == .enc.pub, executed before writing. Expected for the
#   recorded build:
#       OBF       69ef7582608af8d0df0fb4b515449be5a8d0c903741cbf3353be70eb460521f4
#       plain     cdfb1d858ea5cfe062d0ba877cbe2ea731fdcd196d0c9be64699cf723cbcdcc1
#       pubkey    MATCH
#   A pass here means stages 1 through 4 all ran correctly, because each stage's
#   output feeds the next and the final scalar must land on the exact public
#   point. Independent cross-checks, run only when needed:
#       ECIES-decrypt a real licence XMR with d; the AES-CMAC must match
#       go run ./lictest       Go implementation, same content key
#
# PER-BUILD CONSTANTS
#   CODE_OBF, CODE_MAP and CLUSTER are RVAs in this build and change with it.
#   CODE_OBF/CODE_MAP were confirmed by the WB call trace; CLUSTER is whatever
#   3-derive-map.py reports as the live cluster, and must be updated here when
#   the map is re-derived for a new build.
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
#     routines the stages call (e.g. 0x335460, 0x521210) are ciphertext and the
#     call faults.
#   - A fault is reported with its code and RVA, then hard-exits via os._exit;
#     sys.exit cannot unwind out of a ctypes callback and would recurse.
#
# SECURITY
#   extracted.enc.plain is the identity private encryption key: it decrypts any
#   licence blob addressed to that identity. Keep it in the offline corpus and
#   out of version control.
# =============================================================================

import ctypes, hashlib, json, os, struct, sys

# --- inputs / outputs --------------------------------------------------------
DLL   = r"C:\Windows\SYSTEM32\Windows.Media.Protection.PlayReady.dll"  # input (live)
PRVF  = "extracted.enc.prv"      # input: msprcore.bla extractor
PUBF  = "extracted.enc.pub"      # input: msprcore.bla extractor (verification only)
OUTF  = "extracted.enc.plain"    # output
LOG   = "derive_plain.txt"       # output: log

IMG   = "wbtool_img.bin"         # input: from 1-decrypt-img.py
MAPF  = "oracle_map.json"        # input: from 2-derive-map.py

# --- the routines / tables, as RVAs within wbtool_img.bin ---------------------
# These are per-build. Identified by cross-referencing the WB call trace; the
# table layout was confirmed against published reference data (the s2 cluster
# reproduces the published OBF->MAP vector), and the nibble oracle then proved
# s4 is the live cluster for this build's key format.
CODE_OBF = 0x6C6F00    # stage 1: prv[0x00:0x20] -> OBF
CODE_MAP = 0x529250    # stage 2: in = OBF (mutated in place), out = prv[0x20:0x40]
CLUSTER  = 0x8E2210    # bijection subtables proven live by the nibble oracle
RWX      = 0x40
CURVE_N  = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

L = []
def log(s=""):
    L.append(str(s)); print(s, flush=True)

def die(msg):
    log(f"FATAL: {msg}")
    open(LOG, "w", encoding="utf-8").write("\n".join(L) + "\n")
    sys.exit(1)

def hard_die(msg):
    """
    Same as die() but exits without unwinding. sys.exit() raises SystemExit,
    which cannot propagate out of a ctypes callback - it re-enters the handler
    and recurses until the interpreter dies. Fault handlers must use this.
    """
    log(f"FATAL: {msg}")
    try:
        open(LOG, "w", encoding="utf-8").write("\n".join(L) + "\n")
    finally:
        os._exit(1)

# ---------------------------------------------------------------- inputs
if not os.path.isfile(MAPF):
    die(f"missing {MAPF} - run 2-derive-map.py first")
if not os.path.isfile(IMG):
    die(f"missing {IMG} - run 1-decrypt-img.py first")

MAP = {int(k): v for k, v in json.load(open(MAPF)).items()}
if sorted(MAP.values()) != list(range(16)):
    die("oracle_map.json is not a 16-entry permutation")

PRV = open(PRVF, "rb").read()
if len(PRV) != 0x41:
    die(f"{PRVF} is {len(PRV)} bytes, expected 0x41 (65)")

# .enc.pub is X||Y; tolerate a prefixed form by taking the last 64 bytes
PUB = open(PUBF, "rb").read()[-64:]
PX = int.from_bytes(PUB[:32], "big")
PY = int.from_bytes(PUB[32:], "big")

# ---------------------------------------------------------------- PE layout
# Descriptors are enumerated from the ON-DISK file, not the image, because each
# descriptor's file offset is needed to read its relocs/num fields.
img = open(IMG, "rb").read()     # from 1-decrypt-img.py
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
    """Ciphertext from the file for this RVA, or None if unmapped/short."""
    d = foff(rva)
    if d is None or d + n > len(fb):
        return None
    return fb[d:d + n]

# ------------------------------------------- descriptors: heap-exec + segment
# desc_of maps a code RVA to the RVA of the descriptor that decrypts it, so the
# two stage routines can be called by descriptor address.
seg, desc_of, seen = [], {}, set()
for va, rs, rp in secs:
    b = fb[rp:rp + rs]
    for off in range(0, max(0, len(b) - 0x40), 4):
        size = u32(b, off + 0x20)
        # 0x200000 cap, matching 1-decrypt-img.py. Lowering it skips the two
        # large descriptors and loses the blocks these stages run from.
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

# only blocks this image actually decrypted (i.e. differ from the file)
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
    """Read the caller's own memory without raising on a bad pointer."""
    if not addr or addr < 0x10000 or addr > 0x7FFFFFFFFFFF:
        return b""
    buf = ctypes.create_string_buffer(n)
    got = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(ME, ctypes.c_void_p(addr), buf, n, ctypes.byref(got)):
        return b""
    return buf.raw[:got.value]

def wr(rva, data):
    """
    Write into the loaded image, RESTORING the page's original protection after.
    A writable descriptor page makes the kernel reject WB calls with
    0xc000000d, so the restore is mandatory.
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

# Copy the decrypted segment spans over the live ciphertext so every routine the
# stages call is real code. The stage routines' OWN blocks are heap-exec and are
# deliberately left ciphertext: the kernel decrypts each exactly once during the
# op=3 call, and pre-patching would double-decrypt them.
npatched = sum(1 for r, s in patch_list if wr(r, img[r:r + s]))
log(f"base 0x{base:x}   segment blocks patched {npatched}/{len(patch_list)}   "
    f"heap-exec left ciphertext")
if npatched == 0:
    die("nothing patched - is wbtool_img.bin really decrypted?")

def onfault(ep):
    er = struct.unpack_from("<Q", ctypes.string_at(ep, 8))[0]
    code = struct.unpack_from("<I", ctypes.string_at(er, 4))[0]
    addr = struct.unpack_from("<Q", ctypes.string_at(er + 0x10, 8))[0]
    # hard_die, not die: sys.exit cannot unwind out of a ctypes callback
    hard_die(f"FAULT 0x{code:08x} at rva 0x{(addr - base) & 0xFFFFFFFF:x}")

VEH = ctypes.CFUNCTYPE(ctypes.c_long, ctypes.c_void_p)
keep_veh = VEH(onfault)
k32.AddVectoredExceptionHandler(1, keep_veh)

def op3(desc_rva, ln, status, key, out):
    """
    Issue op=3 (WbHeapExecuteCall) against a heap-exec descriptor.

    Argument block as the routines see it (rcx = args+0x10):
        +0x00  -> status dword
        +0x08  -> key / writable input buffer
        +0x10  u32 size 0x20
        +0x14  -> output / read-only input buffer
        +0x1c  u32 size 0x20      (only when ln >= 0x30)
    """
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
# 0x6c6f00 takes prv[0x00:0x20] and writes OBF. There is deliberately no
# fallback and no bypass: a substituted OBF would still let the later stages
# reach pubkey MATCH and mask a broken stage 1.
st = ctypes.create_string_buffer(0x40)
kb = ctypes.create_string_buffer(PRV[0x00:0x20], 0x40)
ob = ctypes.create_string_buffer(0x40)
rc, sd = op3(d_obf, 0x2C, st, kb, ob)
OBF = bytes(ob.raw)[:0x20]
log(f"stage 1   0x{CODE_OBF:06x} nt=0x{rc:08x} status={sd.hex()}")
if rc != 0:
    die(f"stage 1: WB call failed (nt=0x{rc:08x})")
if sd != b"\0\0\0\0":
    die(f"stage 1: routine rejected the key (status {sd.hex()})")
if OBF == b"\0" * 0x20:
    die("stage 1: routine returned all zeros")
log(f"OBF       {OBF.hex()}")

# ---------------------------------------------------------------- stage 2 -> mut
# 0x529250 takes OBF as the writable `in` and prv[0x20:0x40] as the read-only
# `out`, and MUTATES `in` in place. The mutated value feeds the bijection; `ob`
# is only there to satisfy the argument contract.
st = ctypes.create_string_buffer(0x40)
ib = ctypes.create_string_buffer(OBF, 0x40)
ob = ctypes.create_string_buffer(PRV[0x20:0x40], 0x40)
rc, sd = op3(d_map, 0x30, st, ib, ob)
mut = bytes(ib.raw)[:0x20]
log(f"stage 2   0x{CODE_MAP:06x} nt=0x{rc:08x} status={sd.hex()}")
if rc != 0:
    die(f"stage 2: WB call failed (nt=0x{rc:08x})")
if sd != b"\0\0\0\0":
    die(f"stage 2: routine rejected the input (status {sd.hex()})")
log(f"in-mutated {mut.hex()}")

# ---------------------------------------------------------------- bijection + MAP
# Stage 3: the cluster is 64 consecutive 16-byte subtables. Nibble i of the
# input indexes subtable i, and the value found there becomes nibble i of the
# output. Stage 4: the 16-entry permutation from oracle_map.json.
BLK = [img[CLUSTER + i * 16: CLUSTER + i * 16 + 16] for i in range(64)]
if any(len(b) != 16 or max(b) > 15 or len(set(b)) != 16 for b in BLK):
    die(f"cluster 0x{CLUSTER:06x} is not 64 clean nibble permutations")

def nibs(b):
    """Split 32 bytes into 64 nibbles, high nibble of each byte first."""
    return [(b[i >> 1] >> (4 if i % 2 == 0 else 0)) & 0xF for i in range(64)]

def pack(ns):
    """Inverse of nibs(): pack 64 nibbles back into 32 bytes."""
    return bytes((ns[i] << 4) | ns[i + 1] for i in range(0, 64, 2))

n = nibs(mut)
mapped = pack([BLK[i][n[i]] for i in range(64)])
plain = pack([MAP[x] for x in nibs(mapped)])
log(f"mapped    {mapped.hex()}")
log(f"plain     {plain.hex()}")

# ---------------------------------------------------------------- verify + write
# The acceptance test: the derived scalar must reproduce .enc.pub. Nothing is
# written unless it does.
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
digest = hashlib.sha256(plain).hexdigest()
log(f"written   {OUTF}  ({len(plain)} bytes)  sha256 {digest}")

open(LOG, "w", encoding="utf-8").write("\n".join(L) + "\n")
