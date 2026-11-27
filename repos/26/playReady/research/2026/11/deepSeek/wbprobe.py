"""wbprobe.py -- probe children, staged sweep, image cache.

A block that is not callable faults and kills the child; a block that returns a status
ran and refused the arguments. Survival is the classifier, not the status word.

FIVE WORKERS, NO WATCHDOG. A sixth thread broke the budget, and a worker blocked in
readline() could not be rescued anyway: a hung descriptor parked it with nothing
printed. Each worker polls its child's pipe with PeekNamedPipe, output resets a SILENT
deadline, and the worker that owns a silent child kills it.

Nothing here searches for a HWID. The identity is 32 bytes and its content is not
checked, so ID is what payload sends.

No probe result is cached. offsets.json is written by discover and only read here.
"""
import ctypes
import json
import msvcrt
import os
import subprocess
import sys
import threading
import time

import warbird as wb
import wbimage as im

SILENT = 6.0
WORKERS = 5
CHUNK = 250
PAR_MIN = 12
RADIUS = 24
NEAR = 8
STEPS = (RADIUS, 96, 384, None)

ID = b"FAKE.PR.ID" + b"\0" * 22

WORK = "testdata"
OFF = os.path.join(WORK, "offsets.json")
IMG = os.path.join(WORK, "wbtool_img.bin")
ENTRY = os.path.abspath(getattr(sys.modules["__main__"], "__file__", sys.argv[0]))
_PRINT = threading.Lock()

_k32 = ctypes.WinDLL("kernel32")
_k32.PeekNamedPipe.restype = ctypes.c_int
_k32.PeekNamedPipe.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
                               ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32),
                               ctypes.c_void_p]


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
            if s["mode"] == "payload":
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
            row.pop("e", None)
            row["dead"] = True
            row["why"] = repr(e)
        print(json.dumps(row), flush=True)
    return True


def _stream(mode, chunk, sink, **kw):
    """Run one child, calling sink(row) per line, killing it after SILENT quiet."""
    env = dict(os.environ, WARBIRD_CHILD=json.dumps(dict(mode=mode, descs=chunk, **kw)))
    try:
        p = subprocess.Popen([sys.executable, "-S", ENTRY], env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             bufsize=0)
    except OSError as e:
        sink({"d": 0, "e": str(e)})
        return True
    fd, hp = p.stdout.fileno(), msvcrt.get_osfhandle(p.stdout.fileno())
    buf, deadline = b"", time.time() + SILENT
    try:
        while True:
            avail = ctypes.c_uint32(0)
            if not _k32.PeekNamedPipe(ctypes.c_void_p(hp), None, 0, None,
                                      ctypes.byref(avail), None):
                break
            if avail.value:
                data = os.read(fd, avail.value)
                if not data:
                    break
                buf += data
                deadline = time.time() + SILENT
                while b"\n" in buf:
                    ln, buf = buf.split(b"\n", 1)
                    try:
                        r = json.loads(ln.strip() or b"{}")
                    except ValueError:
                        continue
                    if r and sink(r):
                        return True
                continue
            if p.poll() is not None:
                break
            if time.time() > deadline:
                break
            time.sleep(0.008)
    finally:
        if p.poll() is None:
            try:
                p.kill()
            except OSError:
                pass
        p.wait()
        try:
            p.stdout.close()
        except OSError:
            pass
    return False


def ok(r):
    return bool(r) and not r.get("e") and not r.get("dead") \
        and r.get("nt") == 0 and r.get("st") == 0


def _walk(mode, part, stop, rows, hit, err, ev, lock, tag, total, **kw):
    todo = list(part)
    while todo and not ev.is_set():
        chunk = todo[:CHUNK]
        pend = {"d": None}

        def sink(r):
            d = r.get("d")
            if not d:
                return False
            if r.get("b"):
                pend["d"] = d
                return False
            pend["d"] = None
            if r.get("e"):
                with lock:
                    err.append(r["e"])
                ev.set()
                return True
            with lock:
                rows[d] = r
            if stop and ok(r) and stop(r):
                with lock:
                    hit.append(d)
                ev.set()
                return True
            return False

        _stream(mode, chunk, sink, **kw)
        if ev.is_set():
            return
        d = pend["d"]
        if not d:
            todo = todo[len(chunk):]
            continue
        with lock:
            rows[d] = {"d": d, "dead": True}
            done = len(rows)
        _p("    %s %#x dead  %d/%d" % (tag, d, done, total))
        todo = todo[chunk.index(d) + 1:]


def probe(mode, group, stop=None, **kw):
    """Probe a group; WORKERS children at PAR_MIN descriptors and above, one below."""
    ids = [d["desc"] for d in group]
    if not ids:
        return {}, 0
    rows, hit, err = {}, [], []
    ev, lock = threading.Event(), threading.Lock()
    t0, n = time.time(), len(ids)
    parts = [ids[i::WORKERS] for i in range(WORKERS)] if n >= PAR_MIN else [ids]
    ts = [threading.Thread(target=_walk,
                           args=(mode, p, stop, rows, hit, err, ev, lock,
                                 "abcde"[i] if len(parts) > 1 else " ", n),
                           kwargs=kw)
          for i, p in enumerate(parts)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    ev.set()
    if err:
        wb.die(err[0])
    faults = sum(1 for r in rows.values() if r.get("dead"))
    if hit or n >= PAR_MIN:
        _p("    %s%d called  %d dead  %.1fs  %d worker(s)"
           % ("hit %#x  " % hit[0] if hit else "", len(rows), faults,
              time.time() - t0, len(parts)))
    return rows, faults


def report(group, rows):
    for d in group:
        r = rows.get(d["desc"], {})
        if r.get("dead"):
            print("    desc=%#x  dead  %s" % (d["desc"], r.get("why", "")))
        elif r.get("ok"):
            print("    desc=%#x  OK n=%d src=%s" % (d["desc"], r["n"], r["src"]))
        else:
            print("    desc=%#x  %s" % (d["desc"], r.get("why", "no verdict")))


def load_cache():
    """discover's output: the payload descriptor. Read only, never written here."""
    try:
        with open(OFF) as f:
            c = json.load(f)
    except (OSError, ValueError):
        return {}
    return c if c.get("dll_sha256") == im.dll_sha() else {}


def anchor():
    p = load_cache().get("payload") or 0
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
                return d["desc"], rows
        if len(seen) >= n:
            break
    return None, rows


def image(ds, hs):
    """Decrypted image, cached per DLL build, trusted only when a heap block carries
    the payload constant."""
    sha = im.dll_sha()

    def drop(why):
        print("[!] discarding cached image: %s" % why)
        for p in (IMG, IMG + ".json"):
            try:
                os.remove(p)
            except OSError:
                pass

    if os.path.exists(IMG):
        try:
            with open(IMG + ".json") as f:
                m = json.load(f)
            with open(IMG, "rb") as f:
                img = f.read()
            if m.get("dll_sha256") != sha:
                drop("different DLL build")
            elif m.get("size") != len(img):
                drop("size mismatch")
            elif im.pay_candidates(img, hs):
                print("[*] image cached (%d bytes)" % len(img))
                return img
            else:
                drop("no payload constant in any heap block")
        except (OSError, ValueError):
            drop("unreadable sidecar")

    print("[*] decrypting the image")
    img = im.dec_image(ds)
    wr(IMG, img)
    with open(IMG + ".json", "w") as f:
        json.dump({"dll_sha256": sha, "size": len(img)}, f)
    return img
