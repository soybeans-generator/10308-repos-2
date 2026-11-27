# wbprobe.py
"""wbprobe.py -- probe children, staged sweep, dead list, offset cache, image cache.

A descriptor that is not the routine being called dereferences a size or a small
integer, which is a SEH exception: the process dies and Python cannot resume it. So
each probe runs in a child -- wb-find.py re-executed with WARBIRD_CHILD holding a
JSON spec -- that announces every call before making it.

THE PROBE BLOCK IS GO'S, EXACTLY. kernel.go builds op3Call as

    +0x00 op=3    +0x08 desc    +0x10 ->status    +0x18 ->key
    +0x20 u32 key size          +0x24 ->out       +0x2C u32 second size

and signing.go probes with op3(descVA, 0x34, 0x20, status, key32, out32, nil):
block length 0x34, key size 0x20, second size zero. Googler's get-HWID block is NOT
a safe probe: its +0x2C is an 8-byte output-length POINTER where this ABI has a u32,
so a routine that reads +0x14 as a pointer receives `type` = 1 and dies. A sweep
with it kills nearly every descriptor, which is what the last log showed.

FOUR WORKERS, AND THE FLOOR IS THE FAULT RATE. A dead child costs one interpreter
start plus LoadLibrary, about 0.9 s, and roughly 40% of descriptors kill it. 981
descriptors therefore cost ~400 spawns however the chunks are cut: ~6 min serial,
~90 s with four workers. Chunking cannot beat this -- chunk 80 already yields ~0.4
spawns per descriptor, which is the fault rate itself.

THREE SERIAL SAVINGS:
  * distance ordering -- the sweep walks outward from the payload anchor, so a
    routine near it ends the run early for every worker;
  * dead list -- testdata/dead.json, per DLL build and per mode, so a rerun resumes
    instead of repeating its faults; delete the file to re-probe from zero;
  * code-span filter -- wbimage.heap_routines(), Go's signingCandidates, drops
    descriptors whose code is not inside a mapped section before any child starts.

T IS 30 S, NOT 600: a descriptor that neither answers nor faults HANGS, and one hung
child held a worker for ten minutes. The descriptor announced last with no verdict is
recorded dead, so it is never paid for twice. A child killed by T is reported as hung;
one that exited on its own is reported as faulted.
"""
import ctypes
import json
import os
import struct
import subprocess
import sys
import threading
import time

import warbird as wb
import wbimage as im

T = 30
CHUNK = 80
WORKERS = 4
PAR_MIN = 40
RADIUS = 24
NEAR = 8
STEPS = (RADIUS, 96, 384, None)
SYNTH = b"FAKE.PR.ID" + b"\0" * 22
E_INVALIDARG = 0x80070057
FILL = 0xCC
K1 = bytes(range(32))
K2 = bytes(range(32, 64))

OFFSETS = {"hwid": 0x0, "payload": 0x0, "decrypt": 0x0}

WORK = "testdata"
OFF = os.path.join(WORK, "offsets.json")
IMG = os.path.join(WORK, "wbtool_img.bin")
DEAD = os.path.join(WORK, "dead.json")

ENTRY = os.path.abspath(getattr(sys.modules["__main__"], "__file__", sys.argv[0]))
_PRINT = threading.Lock()


def _p(*a):
    with _PRINT:
        print(*a, flush=True)


def wr(p, b):
    with open(p, "wb") as f:
        f.write(b)


def need(p, how):
    if not os.path.exists(p):
        wb.die("missing %s - run: python wb-find.py %s" % (p, how))
    return p


def load_dead(mode):
    try:
        with open(DEAD) as f:
            c = json.load(f)
    except (OSError, ValueError):
        return set()
    return set(c.get(mode, [])) if c.get("dll_sha256") == im.dll_sha() else set()


def save_dead(mode, new):
    try:
        with open(DEAD) as f:
            c = json.load(f)
    except (OSError, ValueError):
        c = {}
    if c.get("dll_sha256") != im.dll_sha():
        c = {}
    c["dll_sha256"] = im.dll_sha()
    c[mode] = sorted(load_dead(mode) | new)
    with open(DEAD, "w") as f:
        json.dump(c, f, indent=2)


def generic(b, d, key):
    """Go -1's probe block: op=3, length 0x34, key size 0x20, no second size."""
    st = (ctypes.c_ubyte * 0x10)()
    kb = (ctypes.c_ubyte * 32)()
    ctypes.memmove(kb, key, 32)
    out = (ctypes.c_ubyte * 0x20)(*([FILL] * 0x20))
    a = (ctypes.c_ubyte * 0x34)()
    struct.pack_into("<Q", a, 0x00, 3)
    struct.pack_into("<Q", a, 0x08, b + d)
    struct.pack_into("<Q", a, 0x10, ctypes.addressof(st))
    struct.pack_into("<Q", a, 0x18, ctypes.addressof(kb))
    struct.pack_into("<I", a, 0x20, 0x20)
    struct.pack_into("<Q", a, 0x24, ctypes.addressof(out))
    return wb.wb(a, 0x34), wb.g32(st), bytes(out)


def probe_row(b, d):
    """Two keys through Go's block. A HWID is key-independent: same bytes twice.

    nz means the routine wrote something other than the fill, so a descriptor that
    only returns E_INVALIDARG is not a candidate.
    """
    a = generic(b, d, K1)
    if a[0] or a[1]:
        return {"nt": a[0], "st": a[1], "n": 0, "nz": False, "stable": False}
    z = generic(b, d, K2)
    fill = bytes([FILL]) * 0x20
    n = 0x20
    while n and a[2][n - 1] in (FILL, 0):
        n -= 1
    return {"nt": 0, "st": 0, "n": n, "h": a[2].hex(),
            "nz": a[2] != fill and n > 0,
            "stable": not z[0] and not z[1] and z[2] == a[2]}


def child():
    raw = os.environ.get("WARBIRD_CHILD")
    if not raw:
        return False
    s = json.loads(raw)
    try:
        b = wb.base()
    except OSError as e:
        print(json.dumps({"d": 0, "e": str(e)}), flush=True)
        return True
    hwid = bytes.fromhex(s.get("hwid", ""))
    seed = bytes.fromhex(s.get("seed", ""))
    resp = open(s["resp"], "rb").read() if s.get("resp") else b""

    for d in s["descs"]:
        print(json.dumps({"d": d, "b": 1}), flush=True)
        row = {"d": d}
        try:
            if s["mode"] == "hwid":
                row.update(probe_row(b, d))
            elif s["mode"] == "payload":
                data, src, n, moved, why = wb.payload(b, d, hwid)
                row.update(ok=bool(data), src=src, n=n, seed=moved, why=why)
                if data and s.get("dump"):
                    row["full"] = data.hex()
            else:
                nt, st, data, n = wb.call_decrypt(b, d, resp, seed)
                row.update(nt=nt, st=st, n=n, prkf=0 <= data.find(b"PRKF") < 64)
                if s.get("dump"):
                    row["full"] = data.hex()
        except Exception as e:
            row["e"] = repr(e)
        print(json.dumps(row), flush=True)
    return True


def run(mode, descs, **kw):
    """One child for up to CHUNK descriptors. Returns (rows, timed_out)."""
    env = dict(os.environ, WARBIRD_CHILD=json.dumps(dict(mode=mode, descs=descs, **kw)))
    timed = False
    try:
        out = subprocess.run([sys.executable, "-S", ENTRY], env=env,
                             capture_output=True, timeout=T).stdout
    except subprocess.TimeoutExpired as e:
        out, timed = e.stdout or b"", True
    rows = {}
    for ln in (out or b"").decode("utf-8", "replace").splitlines():
        try:
            r = json.loads(ln)
            rows[r["d"]] = r
        except (ValueError, KeyError):
            pass
    return rows, timed


def ok(r):
    return bool(r) and not r.get("e") and not r.get("dead") \
        and r.get("nt") == 0 and r.get("st") == 0


def _walk(mode, part, stop, rows, hit, err, ev, lock, tag, total, newdead, **kw):
    todo = list(part)
    while todo and not ev.is_set():
        chunk = todo[:CHUNK]
        got, timed = run(mode, chunk, **kw)
        e = got.get(0, {}).get("e")
        if e:
            with lock:
                err.append(e)
            ev.set()
            return
        cut = None
        for i, d in enumerate(chunk):
            r = got.get(d)
            if r is None or r.get("b"):
                cut = i
                break
            with lock:
                rows[d] = r
            if stop and ok(r) and stop(r):
                with lock:
                    hit.append(d)
                ev.set()
                return
        if cut is None:
            todo = todo[len(chunk):]
            continue
        d = chunk[cut]
        with lock:
            rows[d] = {"d": d, "dead": True}
            newdead.add(d)
            done = len(rows)
        _p("    %s %#x %s  %d/%d"
           % (tag, d, "hung" if timed else "faulted", done, total))
        todo = todo[cut + 1:]


def probe(mode, group, stop=None, **kw):
    """Probe a group; WORKERS children at PAR_MIN descriptors and above, one below."""
    dead = load_dead(mode)
    ids = [d["desc"] for d in group if d["desc"] not in dead]
    skipped = len(group) - len(ids)
    if not ids:
        _p("    all %d descriptors are in the dead list" % len(group))
        return {}, 0

    rows, hit, err, newdead = {}, [], [], set()
    ev, lock = threading.Event(), threading.Lock()
    t0 = time.time()
    n = len(ids)
    if skipped:
        _p("    %d descriptors skipped from %s" % (skipped, DEAD))

    if n >= PAR_MIN:
        parts = [(ids[i::WORKERS], "abcd"[i]) for i in range(WORKERS)]
    else:
        parts = [(ids, " ")]

    ts = [threading.Thread(target=_walk,
                           args=(mode, p, stop, rows, hit, err, ev, lock, tag,
                                 n, newdead),
                           kwargs=kw)
          for p, tag in parts]
    for t in ts:
        t.start()
    for t in ts:
        t.join()

    if newdead:
        save_dead(mode, newdead)
    if err:
        wb.die(err[0])
    if hit:
        _p("    hit %#x  %d called  %d dead  %.1fs  %d worker(s)"
           % (hit[0], len(rows), len(newdead), time.time() - t0, len(parts)))
    else:
        _p("    %d called  %d dead  %.1fs  %d worker(s)"
           % (len(rows), len(newdead), time.time() - t0, len(parts)))
    return rows, len(newdead)


def report(group, rows):
    for d in group:
        r = rows.get(d["desc"], {})
        if r.get("e"):
            print("    desc=%#x  child error: %s" % (d["desc"], r["e"]))
        elif r.get("dead"):
            print("    desc=%#x  faulted or hung" % d["desc"])
        elif r.get("ok"):
            print("    desc=%#x  OK n=%d src=%s seed=%s"
                  % (d["desc"], r["n"], r["src"],
                     "moved" if r.get("seed") else "same"))
        elif r.get("st") == E_INVALIDARG:
            print("    desc=%#x  rejected the argument" % d["desc"])
        else:
            print("    desc=%#x  %s" % (d["desc"], r.get("why", "no verdict")))


def load_cache():
    try:
        with open(OFF) as f:
            c = json.load(f)
    except (OSError, ValueError):
        return {}
    return c if c.get("dll_sha256") == im.dll_sha() else {}


def save_cache(c):
    c["dll_sha256"] = im.dll_sha()
    with open(OFF, "w") as f:
        json.dump(c, f, indent=2)


def anchor():
    p = OFFSETS.get("payload") or load_cache().get("payload") or 0
    if not p:
        wb.die("no payload descriptor - run: python wb-find.py discover")
    return p


def outward(pay, radius=RADIUS):
    ds = sorted(im.heap_routines(), key=lambda d: d["desc"])
    ids = [d["desc"] for d in ds]
    if pay not in ids:
        wb.die("payload %#x is not a heap descriptor for this build" % pay)
    i = ids.index(pay)
    out = [ds[i]]
    for k in range(1, min(radius, len(ds)) + 1):
        out += [ds[j] for j in (i - k, i + k) if 0 <= j < len(ds)]
    return out


def sweep(mode, stop, steps=STEPS, **kw):
    """Walk outward from the payload anchor, widening, until stop matches."""
    a, seen, rows = anchor(), set(), {}
    n = len(im.heap_routines())
    for r in steps:
        r = n if r is None else min(r, n)
        group = [d for d in outward(a, r) if d["desc"] not in seen]
        if not group:
            continue
        print("[*] %d descriptors within %d of anchor %#x" % (len(group), r, a))
        got, _ = probe(mode, group, stop=stop, **kw)
        rows.update(got)
        seen.update(d["desc"] for d in group)
        for d in group:
            if ok(got.get(d["desc"])) and stop(got[d["desc"]]):
                return d, rows
        if len(seen) >= n:
            break
    return None, rows


def image(ds, hs):
    """Decrypted image, cached per DLL build, trusted only when it carries the
    payload constant in a heap block."""
    sha = im.dll_sha()

    def stale(why):
        print("[!] discarding cached image: %s" % why)

    if os.path.exists(IMG):
        try:
            with open(IMG + ".json") as f:
                m = json.load(f)
            if m.get("dll_sha256") != sha:
                stale("different DLL build")
            elif m.get("size") != os.path.getsize(IMG):
                stale("size mismatch")
            else:
                with open(IMG, "rb") as f:
                    img = f.read()
                if im.pay_candidates(img, hs):
                    print("[*] image cached (%d bytes)" % len(img))
                    return img
                stale("no payload constant in any heap block")
        except (OSError, ValueError):
            stale("unreadable sidecar")
        for p in (IMG, IMG + ".json"):
            try:
                os.remove(p)
            except OSError:
                pass

    print("[*] decrypting the image")
    img = im.dec_image(ds)
    wr(IMG, img)
    with open(IMG + ".json", "w") as f:
        json.dump({"dll_sha256": sha, "size": len(img)}, f)
    return img
# wbprobe.py
