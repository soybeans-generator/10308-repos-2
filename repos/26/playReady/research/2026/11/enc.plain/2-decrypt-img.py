# =============================================================================
# 2-decrypt-img.py
#
# Stage 2 of the chain: decrypt the Warbird-protected code and tables in
# Windows.Media.Protection.PlayReady.dll into a flat, plaintext image.
#
# WHY THIS EXISTS
#   PlayReady keeps the interesting parts of the library — the license blob
#   parser, the ECC key handling, the per-nibble bijection subtables — as
#   Warbird-encrypted blocks. The decryption keys live in the kernel and are
#   never exported, but the kernel will decrypt a block on request for any
#   descriptor whose embedded SHA-256 validates. So the image is decrypted
#   block by descriptor rather than by recovering a key.
#
#   Two different descriptor kinds need two different treatment:
#     - segment descriptors (?g_Encry, sizes other than 0xF0) each list one or
#       more RVA ranges. All of them can be decrypted in a single loaded image.
#     - heap-exec descriptors (size 0xF0) describe a single code block, and the
#       kernel only honours the FIRST such decrypt per loaded image. Each block
#       therefore needs its own fresh LoadLibraryW.
#
# PIPELINE
#   1-make-oracle.py   ->  oracle/key_NN.pub, oracle/lic_NN.blob
#   2-decrypt-img.py   ->  wbtool_img.bin                      (this script)
#   3-derive-map.py    ->  oracle_map.json
#   4-derive-plain.py  ->  extracted.enc.plain
#
# INPUT
#   Windows.Media.Protection.PlayReady.dll, read directly from System32.
#   Nothing about this build is assumed: descriptor locations, counts, sizes,
#   the sacrificial slot and its relocation data are all discovered at runtime.
#
# OUTPUT
#   wbtool_img.bin   SizeOfImage bytes, laid out so RVA == file offset.
#                    Consumed by IMG in 3-derive-map.py and 4-derive-plain.py.
#   decrypt_img.txt  log: descriptor counts, per-block results, sample bytes.
#
# ACCEPTANCE CHECK
#   This stage cannot judge itself, because every address and every count is
#   per-build. What it must report is:
#       descriptors <n>  segments <n>  heap-exec <n>      (informational)
#       slot 0x<...>  relocs 0x<...>/<n>                  (resolved, not hardcoded)
#       segment descriptors <n> ok <n>                    (all must succeed)
#       heap-exec <n>  changed <n>  unchanged <n>  error 0
#   The real proof is 4-derive-plain.py printing pubkey MATCH: that requires the
#   stage routines to be real code, the blocks they call to be decrypted, and the
#   live bijection set to be intact. It is the only version-independent check.
#
# DO NOT COMPARE THE FILE HASH BETWEEN RUNS
#   Every LoadLibraryW bakes the current process load base into IAT slots and
#   relocated fields, so no two decrypted images hash alike even though they are
#   functionally identical. The hash in the log is a per-run identifier only.
#
# KNOWN PITFALLS
#   - Descriptor size cap must stay at 0x200000. The two largest descriptors on
#     the recorded build are 0x829c and 0x3cac; a 0x2000 cap silently skips them,
#     which loses the gap blocks 0x334290..0x3370ef and makes 4-derive-plain.py
#     execute ciphertext.
#   - Segment descriptors must be decrypted per descriptor, not per deduped RVA.
#     Descriptor span lists overlap; deduping by RVA drops later/larger spans
#     (7818 spans instead of 7937) and corrupts the downstream scalar.
#   - The sacrificial descriptor page's original protection must be restored
#     before the WB call, or the kernel rejects the descriptor with 0xc000000d.
# =============================================================================

import ctypes, hashlib, struct, sys

# --- inputs / outputs --------------------------------------------------------
DLL    = r"C:\Windows\SYSTEM32\Windows.Media.Protection.PlayReady.dll"  # input
OUT    = "wbtool_img.bin"        # output: consumed by 3-derive-map.py, 4-derive-plain.py
LOG    = "decrypt_img.txt"       # output: log only

RWX    = 0x40                    # PAGE_EXECUTE_READWRITE

L = []
def log(s=""):
    L.append(str(s)); print(s, flush=True)

def finish(msg, code):
    if msg:
        log(msg)
    open(LOG, "w", encoding="utf-8").write("\n".join(L) + "\n")
    sys.exit(code)

# =============================================================================
# Descriptor discovery, offline from the file.
#
# A Warbird descriptor is a 0x20-byte SHA-256 digest followed by a body; the
# digest covers [0x20, size) where size is the dword at +0x20. This validates
# every candidate structurally, so no external tool is needed to enumerate them.
# =============================================================================
f = open(DLL, "rb").read()
u32 = lambda b, o: struct.unpack_from("<I", b, o)[0]

lf      = u32(f, 0x3C)                                  # e_lfanew
nsec    = struct.unpack_from("<H", f, lf + 6)[0]        # NumberOfSections
optsz   = struct.unpack_from("<H", f, lf + 20)[0]       # SizeOfOptionalHeader
sizeImg = u32(f, lf + 24 + 56)                          # SizeOfImage
sizeHdr = u32(f, lf + 24 + 60)                          # SizeOfHeaders
p = lf + 24 + optsz
secs = []
for _ in range(nsec):
    vs, va, rs, rp = struct.unpack_from("<IIII", f, p + 8)
    secs.append((va, rs, rp)); p += 40

# segs  : (descriptorVa, fileOffset, size)              - ?g_Encry blocks
# heaps : (descriptorVa, fileOffset, codeRva, codeSize) - 0xF0 heap-exec blocks
segs  = []
heaps = []
for va, rs, rp in secs:
    b = f[rp:rp + rs]
    for off in range(0, max(0, len(b) - 0x40), 4):
        size = u32(b, off + 0x20)
        # 0x200000, not 0x2000: the two largest descriptors on the recorded
        # build are 0x829c and 0x3cac bytes. A 0x2000 cap silently skips them,
        # which loses the gap blocks 0x334290..0x3370ef and makes
        # 4-derive-plain.py fault. Do not lower it.
        if size < 0x40 or size > 0x200000 or off + size > len(b):
            continue
        if hashlib.sha256(b[off + 0x20:off + size]).digest() != b[off:off + 32]:
            continue
        if size == 0xF0:
            # heap-exec descriptor: codeRVA at +0x34, codeLen at +0x38, both
            # masked with 0x0FFFFFFF (top nibble is a flag)
            rva = u32(b, off + 0x34) & 0x0FFFFFFF
            sz  = u32(b, off + 0x38) & 0x0FFFFFFF
            heaps.append((va + off, rp + off, rva, sz))
        else:
            segs.append((va + off, rp + off, size))

if not segs:
    finish("FATAL: no segment descriptors found", 1)

# --- Warbird calling convention constants ------------------------------------
# SLOT / RELOCS / NUM all vary between DLL builds, so they are read from a real
# segment descriptor instead of being hardcoded. segs[0] is used as the
# sacrificial slot because a genuine descriptor already carries its own
# self-address at +0x28, which the kernel validates; a fabricated slot elsewhere
# would have to be told its own RVA. On the recorded build this resolves to
# SLOT 0x6d8000, RELOCS 0x943770, NUM 20888.
#
# The heap-exec pass overwrites this slot with a synthetic descriptor so the
# kernel will decrypt an arbitrary RVA; the segment pass has already finished by
# then, so reusing one of its descriptors is safe.
SLOT   = segs[0][0]
RELOCS = u32(f, segs[0][1] + 0x2C)
NUM    = u32(f, segs[0][1] + 0x30)

log(f"dll     {DLL}")
log(f"sha256  {hashlib.sha256(f).hexdigest()}")
log(f"image   0x{sizeImg:x} ({sizeImg:,} bytes)")
log(f"descriptors {len(segs) + len(heaps)}  segments {len(segs)}  heap-exec {len(heaps)}")
log(f"slot    0x{SLOT:x}  relocs 0x{RELOCS:x}/{NUM}")
log("")

# =============================================================================
# Kernel call plumbing.
#
# NtQuerySystemInformation(0xB9) is the Warbird syscall. op=1 is "segment
# decrypt": the kernel decodes the descriptor, validates its digest, and
# decrypts [rva, rva+size) in the loaded image at `base`.
# =============================================================================
k32 = ctypes.WinDLL("kernel32")
k32.LoadLibraryW.restype = ctypes.c_void_p
k32.FreeLibrary.argtypes = [ctypes.c_void_p]
k32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong,
                               ctypes.POINTER(ctypes.c_ulong)]
nt = ctypes.WinDLL("ntdll")
Raw = nt.NtQuerySystemInformation
Raw.argtypes = [ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p]
Raw.restype = ctypes.c_long

def call(base, sac, rel, num):
    """Issue op=1 (segment decrypt) for descriptor at `sac` inside `base`."""
    a = ctypes.create_string_buffer(0x30)
    struct.pack_into("<Q", a, 0x00, 1)          # op = 1, segment decrypt
    struct.pack_into("<Q", a, 0x08, sac)        # descriptor address
    struct.pack_into("<Q", a, 0x10, base)       # image base
    struct.pack_into("<Q", a, 0x18, base)       # image base
    struct.pack_into("<Q", a, 0x20, base + rel) # relocations
    struct.pack_into("<Q", a, 0x28, num)        # relocation count
    return Raw(0xB9, ctypes.cast(a, ctypes.c_void_p), 0x30, None) & 0xFFFFFFFF

def make(hdr, params, rva, size):
    """
    Build a synthetic 1-entry segment descriptor:
        [0x00..0x20)  sha256 over the body
        [0x20]        total size (0x100)
        [0x40..0xF0)  crypto params copied from a real descriptor
        [0xF0]        entry count (1)
        [0xF4]        entry flags
        [0xF8]        entry rva
        [0xFC]        entry size
    hdr is the first 0x40 bytes of the sacrificial slot, reused so the header
    shape matches what the kernel expects for this build.
    """
    buf = bytearray(0x100)
    buf[0x00:0x40] = hdr
    buf[0x40:0x40 + len(params)] = params
    struct.pack_into("<I", buf, 0x20, 0x100)   # descriptor total size
    struct.pack_into("<I", buf, 0xF0, 1)       # 1 entry
    struct.pack_into("<I", buf, 0xF4, 0x30C)   # flags
    struct.pack_into("<I", buf, 0xF8, rva)
    struct.pack_into("<I", buf, 0xFC, size)
    buf[0x00:0x20] = hashlib.sha256(bytes(buf[0x20:0x100])).digest()
    return bytes(buf)

# =============================================================================
# Segment pass: ONE loaded image, op=1 against every real segment descriptor.
#
# Per-descriptor (not per-deduped-RVA) is essential: descriptors overlap, and
# deduping by RVA drops the later/larger spans. That mistake produced 7818
# spans instead of 7937 and a wrong downstream scalar.
# =============================================================================
base = k32.LoadLibraryW(DLL)
if not base:
    finish("FATAL: LoadLibraryW failed", 1)
ok = 0
for descVa, fo, size in segs:
    rel = u32(f, fo + 0x2C)      # this descriptor's own relocations
    num = u32(f, fo + 0x30)
    if call(base, base + descVa, rel, num) == 0:
        ok += 1
log(f"segment descriptors {len(segs)} ok {ok}")
img = bytearray(ctypes.string_at(base, sizeImg))   # harvest the whole image
k32.FreeLibrary(base)
log("")

# =============================================================================
# Heap-exec pass: ONE FRESH IMAGE PER BLOCK.
#
# The kernel only honours the first heap-exec decrypt per loaded image, so the
# library must be reloaded for every block. Each iteration:
#   - build a synthetic descriptor for (rva, size) using this block's crypto
#     params (copied from the block's own descriptor body at +0x40..+0xF0)
#   - write it over the sacrificial slot, then RESTORE THE SLOT'S ORIGINAL PAGE
#     PROTECTION before the syscall (the kernel rejects a descriptor living on a
#     writable page with 0xc000000d)
#   - decrypt, read back, free
# =============================================================================
done = same = err = 0
fails = []
for i, (descVa, fo, rva, size) in enumerate(heaps, 1):
    if rva == 0 or size == 0 or rva + size > sizeImg:
        err += 1
        continue
    before = bytes(img[rva:rva + size])

    base = k32.LoadLibraryW(DLL)
    if not base:
        finish(f"FATAL: LoadLibraryW failed at heap block {i}", 1)
    try:
        sac = base + SLOT
        old = ctypes.c_ulong(0)
        dummy = ctypes.c_ulong(0)
        if not k32.VirtualProtect(sac, 0x1000, RWX, ctypes.byref(old)):
            err += 1
            continue
        hdr = ctypes.string_at(sac, 0x40)
        params = f[fo + 0x40:fo + 0xF0]      # this block's own crypto params
        ctypes.memmove(sac, make(hdr, params, rva, size), 0x100)
        k32.VirtualProtect(sac, 0x1000, old.value, ctypes.byref(dummy))  # restore BEFORE syscall
        rc = call(base, sac, RELOCS, NUM)
        got = ctypes.string_at(base + rva, size)
    finally:
        k32.FreeLibrary(base)

    if rc == 0 and len(got) == size and got != before:
        img[rva:rva + size] = got
        done += 1
    elif rc == 0:
        # was already plaintext (e.g. .data entries) - not an error
        same += 1
        if len(fails) < 12:
            fails.append((rva, size, descVa))
    else:
        err += 1
    if i % 200 == 0:
        log(f"  {i}/{len(heaps)}  changed {done}  same {same}  err {err}")

log("")
log(f"heap-exec {len(heaps)}  changed {done}  unchanged {same}  error {err}")
for rva, size, owner in fails:
    log(f"  unchanged 0x{rva:06x}+0x{size:x} owner 0x{owner:x}")
log("")

open(OUT, "wb").write(bytes(img))

# --- build signature ---------------------------------------------------------
# Deliberately no hardcoded probe addresses: they are per-build. Instead dump
# the first bytes of the first heap-exec block and of the largest segment span,
# both chosen at runtime, so the log is still useful for eyeballing real code.
def dump(tag, rva, n=16):
    log(f"  {tag} 0x{rva:06x} {bytes(img[rva:rva + n]).hex()}")

if heaps:
    dump("first heap-exec", heaps[0][2])
if segs:
    big = max(segs, key=lambda s: s[2])
    dump("largest segment", big[0])

log("")
log(f"written {OUT}  ({len(img):,} bytes)")
log(f"sha256   {hashlib.sha256(bytes(img)).hexdigest()}")
finish("", 0)
