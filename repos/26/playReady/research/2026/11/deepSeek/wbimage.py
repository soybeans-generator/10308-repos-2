# wbimage.py
"""wbimage.py -- PE sections, Warbird descriptors, decrypted image, patch plan.

Sections: VirtualSize +8, VirtualAddress +12, SizeOfRawData +16, PointerToRawData
+20. Taking +8 as the address makes every descriptor VirtualSize+offset and op=1
rejects every segment with 0xc000000d; the reorder in sections() exists for that.

Descriptor: sha256 at +0x00 over [0x20,size), size +0x20 (0xF0 = heap-exec),
marker +0x24, desc_va +0x28, relocs +0x2C, count +0x30, code rva/len +0x34/+0x38.
The digest is the only test valid for both kinds; the marker is absent on segment
descriptors. size < 0x200000 forces byte +0x23 to 0.

heap_routines() is Go's signingCandidates: a heap descriptor whose code span is
empty or outside every mapped section cannot be a routine, so probing it only buys a
fault. This is a static filter, applied before any child is spawned.

patch_plan/apply are Go's pfImage.apply, used by the image pass only: segment spans
hold decrypted plaintext, heap blocks are carved out because op=3 decrypts those
itself. apply flips protection once per section, not once per range.
"""
import ctypes
import hashlib
import struct
import time

import warbird as wb

PAYS = (b"\xcc\x08\x00\x00", b"\xbc\x08\x00\x00")   # 2252 / 2236
LAYOUTS = ("countf0", "count30", "self")
TRY = 12


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def sections(fb):
    lf = u32(fb, 0x3C)
    n = struct.unpack_from("<H", fb, lf + 6)[0]
    p = lf + 24 + struct.unpack_from("<H", fb, lf + 20)[0]
    out = []
    for i in range(n):
        q = p + 40 * i
        vs, va, rs, rp = struct.unpack_from("<IIII", fb, q + 8)
        out.append((va, vs, rs, rp))
    return out


def section_prots(fb):
    lf = u32(fb, 0x3C)
    n = struct.unpack_from("<H", fb, lf + 6)[0]
    p = lf + 24 + struct.unpack_from("<H", fb, lf + 20)[0]
    out = []
    for i in range(n):
        q = p + 40 * i
        vs, va, rs, _ = struct.unpack_from("<IIII", fb, q + 8)
        ch = u32(fb, q + 36)
        prot = 0x20 if ch & 0x20000000 else (0x04 if ch & 0x80000000 else 0x02)
        out.append((va, max(vs, rs, 1), prot))
    return out


def pe_size(fb):
    return u32(fb, u32(fb, 0x3C) + 24 + 56)


def scan(fb=None):
    fb = fb or open(wb.DLL, "rb").read()
    out = {}
    for va, vs, rs, rp in sections(fb):
        seg = fb[rp:rp + rs]
        idx, pos = seg[3::4], 0
        while True:
            j = idx.find(b"\x00", pos)
            if j < 0:
                break
            pos = j + 1
            o = 4 * j - 0x20
            if o < 0:
                continue
            if o + 0x40 > len(seg):
                break
            size = u32(seg, o + 0x20)
            if not 0x40 <= size <= 0x200000 or o + size > len(seg):
                continue
            if hashlib.sha256(seg[o + 0x20:o + size]).digest() != seg[o:o + 32]:
                continue
            d = {"va": va + o, "off": rp + o, "size": size,
                 "desc": u32(seg, o + 0x28) & 0x0FFFFFFF,
                 "rel": u32(seg, o + 0x2C), "num": u32(seg, o + 0x30),
                 "rva": 0, "ln": 0}
            if size == 0xF0:
                d["rva"] = u32(seg, o + 0x34) & 0x0FFFFFFF
                d["ln"] = u32(seg, o + 0x38) & 0x0FFFFFFF
            out.setdefault(("h", d["desc"]) if size == 0xF0 else ("s", d["va"]), d)
    return list(out.values())


def heaps(ds):
    return [d for d in ds if d["size"] == 0xF0 and d["desc"] and d["ln"]]


_HEAP = None


def heap_routines():
    """Heap descriptors whose code span is non-empty and inside a mapped section."""
    global _HEAP
    if _HEAP is None:
        fb = open(wb.DLL, "rb").read()
        secs = sections(fb)
        _HEAP = [d for d in heaps(scan(fb))
                 if any(va <= d["rva"] < va + max(vs, rs, 1)
                        for va, vs, rs, rp in secs)]
    return _HEAP


def dll_sha():
    with open(wb.DLL, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def seg_spans(fb, d, size):
    b = fb[d["off"]:d["off"] + d["size"]]
    out = []
    for o in range(0xF4, len(b) - 0xB, 0xC):
        rva, ln = u32(b, o + 4), u32(b, o + 8)
        if rva >= 0x1000 and ln >= 8 and rva + ln <= size:
            out.append((rva, ln))
    return out


def _merge(ivs):
    ivs.sort()
    res = []
    for s, l in ivs:
        if res and s <= res[-1][0] + res[-1][1]:
            e = res[-1][0] + res[-1][1]
            res[-1] = (res[-1][0], max(e, s + l) - res[-1][0])
        else:
            res.append((s, l))
    return res


def patch_plan(fb, ds, size):
    hb = _merge([(h["rva"], h["ln"]) for h in heaps(ds) if h["rva"] and h["ln"]])
    cuts = []
    for d in ds:
        if d["size"] == 0xF0:
            continue
        for s, l in seg_spans(fb, d, size):
            cur, end = s, s + l
            for hs, hl in hb:
                if hs + hl <= cur or hs >= end:
                    continue
                if hs > cur:
                    cuts.append((cur, hs - cur))
                cur = max(cur, hs + hl)
                if cur >= end:
                    break
            if cur < end:
                cuts.append((cur, end - cur))
    return _merge(cuts)


def apply(b, img, plan, prots):
    olds = []
    for rva, sz, _ in prots:
        olds.append((rva, sz, wb.vp(b + rva, sz, 0x40)))
    n = 0
    for rva, ln in plan:
        if ln > 0 and rva + ln <= len(img):
            ctypes.memmove(b + rva, img[rva:rva + ln], ln)
            n += 1
    for rva, sz, old in olds:
        if old is not None:
            wb.vp(b + rva, sz, old)
    return n


def build_desc(hdr, params, layout, rva, size):
    b = bytearray(0x100)
    b[0x00:0x40] = hdr
    b[0x40:0xF0] = params
    struct.pack_into("<I", b, 0x20, 0x100)
    if layout == "count30":
        struct.pack_into("<I", b, 0x30, 1)
        struct.pack_into("<III", b, 0xF0, 0x30C, rva, size)
    else:
        struct.pack_into("<I", b, 0xF0, 1)
        struct.pack_into("<III", b, 0xF4, 0x30C, rva, size)
    b[0x00:0x20] = hashlib.sha256(bytes(b[0x20:0x100])).digest()
    return bytes(b)


def one_block(fb, h, slot, rel, num, layout):
    lib = wb.base()
    try:
        if layout == "self":
            rc = wb.di_call(lib, lib + h["desc"], 0, 0)
        else:
            sac = lib + slot
            old = wb.vp(sac, 0x1000, 0x40)
            if old is None:
                return None, 0xC000000D
            ctypes.memmove(sac, build_desc(ctypes.string_at(sac, 0x40),
                                           fb[h["off"] + 0x40:h["off"] + 0xF0],
                                           layout, h["rva"], h["ln"]), 0x100)
            if wb.vp(sac, 0x1000, old) is None:
                return None, 0xC000000D
            rc = wb.di_call(lib, sac, rel, num)
        if rc:
            return None, rc
        return ctypes.string_at(lib + h["rva"], h["ln"]), 0
    finally:
        wb.free(lib)


def pick_layout(fb, hs, slot, rel, num, layouts, say):
    for name in layouts:
        rc, changed = 0, 0
        for h in hs[:TRY]:
            got, rc = one_block(fb, h, slot, rel, num, name)
            if rc:
                break
            if got is not None and got != fb[h["rva"]:h["rva"] + h["ln"]]:
                changed += 1
        if not rc and changed:
            say("    layout %-8s works  %d/%d blocks changed" % (name, changed, TRY))
            return name
        say("    layout %-8s %s" % (name, "rejected rc=%#x" % rc if rc
                                    else "ran but changed nothing"))
    wb.die("no descriptor layout decrypts a block - op=1 does not match this build")


def dec_image(ds=None, say=print):
    fb = open(wb.DLL, "rb").read()
    ds = ds or scan(fb)
    segs = [d for d in ds if d["size"] != 0xF0]
    hs = heaps(ds)
    size = pe_size(fb)
    if not segs:
        wb.die("no segment descriptors (%d found, %d heap-exec)" % (len(ds), len(hs)))

    t0 = time.time()
    b = wb.base()
    good = sum(1 for s in segs if not wb.di_call(b, b + s["va"], s["rel"], s["num"]))
    img = bytearray(ctypes.string_at(b, size))
    wb.free(b)
    say("    segments %d  ok %d  %.1fs" % (len(segs), good, time.time() - t0))
    if not good:
        say("    no segment decrypted; trying the heap descriptor itself")

    slot, rel, num = segs[0]["va"], segs[0]["rel"], segs[0]["num"]
    layout = pick_layout(fb, hs, slot, rel, num, LAYOUTS if good else ("self",), say)

    done = bad = 0
    t0 = time.time()
    for n, h in enumerate(hs, 1):
        if not h["rva"] or h["off"] + 0xF0 > len(fb) or h["rva"] + h["ln"] > size:
            bad += 1
            continue
        got, rc = one_block(fb, h, slot, rel, num, layout)
        if rc or got is None:
            bad += 1
        else:
            img[h["rva"]:h["rva"] + h["ln"]] = got
            done += 1
        if n % 200 == 0:
            say("    blocks %d/%d  ok %d  err %d  %.1fs"
                % (n, len(hs), done, bad, time.time() - t0))
        if got is not None and any(p in got for p in PAYS):
            say("    payload constant in block %#x  (%d/%d, %.1fs)"
                % (h["desc"], n, len(hs), time.time() - t0))
            break
    say("    blocks %d  ok %d  err %d  %.1fs"
        % (len(hs), done, bad, time.time() - t0))
    return bytes(img)


def pay_candidates(img, hs):
    return [h for h in hs if any(p in img[h["rva"]:h["rva"] + h["ln"]] for p in PAYS)]
# wbimage.py
