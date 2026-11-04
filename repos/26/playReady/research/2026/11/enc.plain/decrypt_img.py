# decrypt_img.py — full Warbird image decrypt: per-descriptor segments + one fresh image per heap-exec block
import ctypes, hashlib, struct, sys

DLL    = r"C:\Windows\SYSTEM32\Windows.Media.Protection.PlayReady.dll"
OUT    = "wbtool_img.bin"
LOG    = "decrypt_img.txt"
SLOT   = 0x6D8000          # sacrificial descriptor inside ?g_Encry
RELOCS, NUM = 0x943770, 20888
RWX    = 0x40

L = []
def log(s=""):
    L.append(str(s)); print(s, flush=True)

def finish(msg, code):
    if msg:
        log(msg)
    open(LOG, "w", encoding="utf-8").write("\n".join(L) + "\n")
    sys.exit(code)

f = open(DLL, "rb").read()
u32 = lambda b, o: struct.unpack_from("<I", b, o)[0]

lf      = u32(f, 0x3C)
nsec    = struct.unpack_from("<H", f, lf + 6)[0]
optsz   = struct.unpack_from("<H", f, lf + 20)[0]
sizeImg = u32(f, lf + 24 + 56)
sizeHdr = u32(f, lf + 24 + 60)
p = lf + 24 + optsz
secs = []
for _ in range(nsec):
    vs, va, rs, rp = struct.unpack_from("<IIII", f, p + 8)
    secs.append((va, rs, rp)); p += 40

segs  = []   # (descVa, fileOff, size)
heaps = []   # (descVa, fileOff, codeRva, codeSize)
for va, rs, rp in secs:
    b = f[rp:rp + rs]
    for off in range(0, max(0, len(b) - 0x40), 4):
        size = u32(b, off + 0x20)
        if size < 0x40 or size > 0x200000 or off + size > len(b):
            continue
        if hashlib.sha256(b[off + 0x20:off + size]).digest() != b[off:off + 32]:
            continue
        if size == 0xF0:
            rva = u32(b, off + 0x34) & 0x0FFFFFFF
            sz  = u32(b, off + 0x38) & 0x0FFFFFFF
            heaps.append((va + off, rp + off, rva, sz))
        else:
            segs.append((va + off, rp + off, size))

log(f"dll     {DLL}")
log(f"sha256  {hashlib.sha256(f).hexdigest()}")
log(f"image   0x{sizeImg:x} ({sizeImg:,} bytes)")
log(f"descriptors {len(segs) + len(heaps)}  segments {len(segs)}  heap-exec {len(heaps)}")
log("")

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
    a = ctypes.create_string_buffer(0x30)
    struct.pack_into("<Q", a, 0x00, 1)          # op=1  segment decrypt
    struct.pack_into("<Q", a, 0x08, sac)
    struct.pack_into("<Q", a, 0x10, base)
    struct.pack_into("<Q", a, 0x18, base)
    struct.pack_into("<Q", a, 0x20, base + rel)
    struct.pack_into("<Q", a, 0x28, num)
    return Raw(0xB9, ctypes.cast(a, ctypes.c_void_p), 0x30, None) & 0xFFFFFFFF

def make(hdr, params, rva, size):
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

# ---------------------------------------------------------------- segment pass
# one loaded image, op=1 against every real segment descriptor
base = k32.LoadLibraryW(DLL)
if not base:
    finish("FATAL: LoadLibraryW failed", 1)
ok = 0
for descVa, fo, size in segs:
    rel = u32(f, fo + 0x2C)
    num = u32(f, fo + 0x30)
    if call(base, base + descVa, rel, num) == 0:
        ok += 1
log(f"segment descriptors {len(segs)} ok {ok}")
img = bytearray(ctypes.string_at(base, sizeImg))
k32.FreeLibrary(base)
log("")

# ---------------------------------------------------------------- heap-exec pass
# one fresh image per block (the kernel decrypts only the first per image)
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
        params = f[fo + 0x40:fo + 0xF0]
        ctypes.memmove(sac, make(hdr, params, rva, size), 0x100)
        k32.VirtualProtect(sac, 0x1000, old.value, ctypes.byref(dummy))  # restore before syscall
        rc = call(base, sac, RELOCS, NUM)
        got = ctypes.string_at(base + rva, size)
    finally:
        k32.FreeLibrary(base)

    if rc == 0 and len(got) == size and got != before:
        img[rva:rva + size] = got
        done += 1
    elif rc == 0:
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
for rva in (0x335460, 0x337700, 0x6C6F00, 0x2229F0, 0x5234E0, 0x4300F0, 0x8E2210):
    log(f"  probe 0x{rva:06x} {bytes(img[rva:rva + 16]).hex()}")
log("")
log(f"written {OUT}  ({len(img):,} bytes)")
log(f"sha256   {hashlib.sha256(bytes(img)).hexdigest()}")
finish("", 0)
