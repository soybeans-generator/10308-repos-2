# wbprobe.py
"""wbprobe.py -- probe children, offset cache, decrypted-image cache.

A descriptor that is not the routine being called can dereference a size or a small
integer: that is a SEH exception, the process dies, and Python cannot resume it. So
each probe runs in a child -- wb-find.py re-executed with WARBIRD_CHILD holding a
JSON spec -- that announces every call before making it. The last announcement with
no verdict names the descriptor that died, so a fault costs one respawn, not one
respawn per descriptor.
"""
import json
import os
import subprocess
import sys
import time

import warbird as wb
import wbimage as im

T = 600                       # one probe run
RADIUS = 12                   # descriptors either side of the payload anchor
NEAR = 8                      # neighbours tried when the constant's block fails
SYNTH = b"FAKE.PR.ID" + b"\0" * 22
E_INVALIDARG = 0x80070057

OFFSETS = {"hwid": 0x0, "payload": 0x0, "decrypt": 0x0}

WORK = "testdata"
OFF = os.path.join(WORK, "offsets.json")
IMG = os.path.join(WORK, "wbtool_img.bin")

ENTRY = os.path.abspath(getattr(sys.modules["__main__"], "__file__", sys.argv[0]))


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
            if s["mode"] == "hwid":
                nt, st, data, n = wb.call_hwid(b, d)
                row.update(nt=nt, st=st, n=n, nz=bool(any(data)), h=data.hex())
                if not nt and not st and 1 <= n <= 512 and any(data):
                    a = wb.call_hwid(b, d)
                    row["stable"] = (a[0], a[1], a[3], a[2]) == (nt, st, n, data)
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
    env = dict(os.environ, WARBIRD_CHILD=json.dumps(dict(mode=mode, descs=descs, **kw)))
    try:
        out = subprocess.run([sys.executable, "-S", ENTRY], env=env,
                             capture_output=True, timeout=T).stdout
    except subprocess.TimeoutExpired as e:
        out = e.stdout or b""
    rows = {}
    for ln in out.decode("utf-8", "replace").splitlines():
        try:
            r = json.loads(ln)
            rows[r["d"]] = r
        except (ValueError, KeyError):
            pass
    return rows


def ok(r):
    return bool(r) and not r.get("e") and not r.get("dead") \
        and r.get("nt") == 0 and r.get("st") == 0


def probe(mode, group, stop=None, **kw):
    ids = [d["desc"] for d in group]
    rows, todo, dead, t0 = {}, list(ids), 0, time.time()
    while todo:
        got = run(mode, todo, **kw)
        e = got.get(0, {}).get("e")
        if e:
            wb.die(e)
        cut = None
        for n, d in enumerate(todo):
            r = got.get(d)
            if r is None or r.get("b"):
                cut = n
                break
            rows[d] = r
            if stop and ok(r) and stop(r):
                print("    hit %#x  %d calls  %.1fs" % (d, len(rows), time.time() - t0))
                return rows, dead
        if cut is None:
            break
        rows[todo[cut]] = {"d": todo[cut], "dead": True}
        dead += 1
        print("    %#x faulted  %d/%d  %.1fs"
              % (todo[cut], len(rows), len(ids), time.time() - t0))
        todo = todo[cut + 1:]
    print("    %d calls  %d faults  %.1fs" % (len(rows), dead, time.time() - t0))
    return rows, dead


def report(group, rows):
    for d in group:
        r = rows.get(d["desc"], {})
        if r.get("e"):
            print("    desc=%#x  child error: %s" % (d["desc"], r["e"]))
        elif r.get("dead"):
            print("    desc=%#x  faulted" % d["desc"])
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
    ds = sorted(im.heaps(im.scan()), key=lambda d: d["desc"])
    ids = [d["desc"] for d in ds]
    if pay not in ids:
        wb.die("payload %#x is not a heap descriptor for this build" % pay)
    i = ids.index(pay)
    out = [ds[i]]
    for k in range(1, radius + 1):
        out += [ds[j] for j in (i - k, i + k) if 0 <= j < len(ds)]
    return out


def image(ds, hs):
    """Decrypted image, cached per DLL build.

    Trusted only when it contains the payload constant in a heap block: a run whose
    op=1 calls all failed still writes SizeOfImage bytes of ciphertext and passes a
    sha-and-size check.
    """
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
