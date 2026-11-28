# tool.py
#
#   python tool.py --hwid "MY.ID.TEXT"   request
#   python tool.py --decrypt             decrypt to testdata/msprcore.bla
#
# Writes only testdata/: payload.bin, response.bin, msprcore.bla,
# tool-state.json. The DLL path lives in wbcall.py and every call inherits it.
#
# A fault is free: wbcall.py catches it per descriptor. A death costs one index,
# which is retired and cached; a hang is caught by IDLE and treated the same.
# That cache is why a second run against the same DLL is instant.
#
# The builder is chosen by the service, not by a heuristic: candidates that
# answer with 01000000 and size output to input are POSTed until one is
# accepted. Rejected ones are remembered.
#
# The 49-byte nonce is built locally: 01 | FILETIME | 28 | 27 constants | HWID.

import argparse
import base64
import json
import os
import re
import secrets
import struct
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from xml.etree import ElementTree as ET

OUT = "testdata"
STATE = os.path.join(OUT, "tool-state.json")
PAYLOAD = os.path.join(OUT, "payload.bin")
RESPONSE = os.path.join(OUT, "response.bin")
BLA = os.path.join(OUT, "msprcore.bla")
URL = "https://activation.playready.microsoft.com/PlayReady/ACT/Activation.asmx"
NS = "http://schemas.microsoft.com/PlayReady/ActivationService/v1"
NO_WINDOW = 0x08000000
FAULT = 0xFFFFFFFF

SDK, SDK_TYPE, PLATFORM, TID = "4.3.0.0", "2", "9", "1"
TIMEOUT = 60.0
IDLE = 4.0
HARD = 300.0
EXTRA, TAIL, NVAR = 2252, 12, 4
CHUNK, LANES, CAND = 200, 6, 8
HEAD4 = "01000000"

CONST27 = bytes.fromhex("0000000000000000" "02000000" "00020000"
                        "000100" "010001" "0096" "7d0000")


def batch_run(argv, idle=IDLE, hard=HARD):
    """Run wbcall.py, collecting rows as they arrive.

    stderr is merged into stdout so a traceback cannot fill a pipe, and the
    child is killed when no new row has appeared for idle seconds. Rows already
    received are kept: the caller needs to know how far it got.
    """
    exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wbcall.py")
    try:
        p = subprocess.Popen([sys.executable, exe] + argv,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT,
                             creationflags=NO_WINDOW)
    except Exception as e:
        return [], "%s: %s" % (type(e).__name__, e)

    rows, tail = [], []

    def read():
        for raw in p.stdout:
            line = raw.decode("utf-8", "replace").strip()
            if not line.startswith("{"):
                if line:
                    tail.append(line)
                    del tail[:-4]
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "err" in r and "tag" not in r and "i" not in r:
                tail.append(r["err"])
            else:
                rows.append(r)

    t = threading.Thread(target=read, daemon=True)
    t.start()

    t0 = mark = time.monotonic()
    seen = 0
    while t.is_alive():
        time.sleep(0.05)
        n = len(rows)
        if n != seen:
            seen, mark = n, time.monotonic()
            continue
        now = time.monotonic()
        if now - mark > idle or now - t0 > hard:
            p.kill()
            return rows, "stall"
    try:
        p.wait(timeout=5)
    except Exception:
        p.kill()
    return rows, (tail[-1] if tail and not rows else None)


def wbcall(*args, timeout=120):
    return batch_run(list(args), idle=timeout, hard=timeout * 4)


def state():
    try:
        with open(STATE) as f:
            return json.load(f)
    except Exception:
        return {}


def save(d):
    try:
        os.makedirs(OUT, exist_ok=True)
        with open(STATE, "w") as f:
            json.dump(d, f)
    except OSError:
        pass


def cached(sha, key):
    return state().get("rva:" + sha, {}).get(key)


def remember(sha, **kv):
    d = state()
    d.setdefault("rva:" + sha, {}).update(kv)
    save(d)


def get_list(key):
    return list(state().get(key, []))


def add_list(key, vals):
    if vals:
        d = state()
        d[key] = sorted(set(d.get(key, [])) | set(vals))
        save(d)


def dead(sha, kind):
    return set(state().get("dead:%s:%s" % (kind, sha), []))


def census_info():
    rows, err = wbcall("census")
    if not rows:
        raise RuntimeError(err or "no census row")
    sha = rows[0]["sha"]
    st = state().get("census:" + sha, {})
    return sha, rows[0]["census"][0], [h[0] for h in st.get("heaps") or []]


def sweep(ids, fn, hit, label, sha, kind, maxhits=1):
    """A missing row means the child died there: retire that index, resume after
    it. Each iteration therefore either answers descriptors or eliminates one."""
    known = dead(sha, kind)
    ids = [i for i in ids if i not in known]
    lock = threading.Lock()
    stop = threading.Event()
    box = {"qi": 0, "ok": 0, "fault": 0, "retired": [], "hits": []}
    errs = []
    queue = [ids[i:i + CHUNK] for i in range(0, len(ids), CHUNK)]
    total = len(ids)
    t0 = time.monotonic()

    def one(batch):
        pending = list(batch)
        while pending and not stop.is_set():
            rows, err = fn(pending)
            if err and err not in errs and len(errs) < 6:
                errs.append(err)
            missing = None
            for i in pending:
                r = rows.get(i)
                if r is None:
                    missing = i
                    break
                with lock:
                    if r["st"] == FAULT:
                        box["fault"] += 1
                    else:
                        box["ok"] += 1
                    n = box["ok"] + box["fault"]
                if hit(r):
                    with lock:
                        box["hits"].append(r)
                        full = len(box["hits"]) >= maxhits
                    if full:
                        stop.set()
                        return
                if n % 200 == 0:
                    print("    %d/%d  %.0fs" % (n, total, time.monotonic() - t0),
                          flush=True)
            if missing is None:
                return
            with lock:
                box["retired"].append(missing)
                nr = len(box["retired"])
            if nr % 25 == 0:
                print("    %d retired" % nr, flush=True)
            pending = pending[pending.index(missing) + 1:]

    def lane():
        while not stop.is_set():
            with lock:
                if box["qi"] >= len(queue):
                    return
                b = queue[box["qi"]]
                box["qi"] += 1
            one(b)

    print("[%s] %d probe(s)%s" % (label, len(ids),
                                  ", %d known-dead" % len(known) if known else ""))
    ts = [threading.Thread(target=lane, daemon=True) for _ in range(LANES)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    add_list("dead:%s:%s" % (kind, sha), box["retired"])
    print("[%s] %d answered, %d fault, %d retired in %.0fs"
          % (label, box["ok"], box["fault"], len(box["retired"]),
             time.monotonic() - t0))
    for e in errs:
        print("    " + e)
    return box["hits"]


def near_first(count, vas, anchor):
    if len(vas) == count and anchor:
        return sorted(range(count), key=lambda i: abs(vas[i] - anchor))
    return list(range(count))


def build(rva, ident):
    rows, err = wbcall("build", "%x" % rva, json.dumps({"x": ident.hex()}))
    row = next((r for r in rows if "tag" in r), None) if rows else None
    if row is None:
        raise RuntimeError(err or "no build row")
    if row["st"] == FAULT:
        raise RuntimeError("access violation")
    if row["st"] or row["nt"]:
        raise RuntimeError("call failed %#010x" % row["st"])
    return bytes.fromhex(row["payload"])


def find_builds(sha, count, vas):
    cand = get_list("bcand:" + sha)
    if cand:
        print("[i] builders %d candidate(s)  (cached)" % len(cand))
        return cand

    info = {}

    def fn(batch):
        rows, err = batch_run(["sweepbuild", (b"\x00" * 49).hex(),
                               ",".join(map(str, batch))])
        for r in rows:
            if "prep" in r and "prep" not in info:
                info["prep"] = r["prep"]
        return {r["i"]: r for r in rows if "i" in r}, err

    def hit(r):
        return r["st"] == 0 and r["nt"] == 0 and r["head"].startswith(HEAD4)

    print("\n[find] builder: %d descriptors, header %s" % (count, HEAD4))
    hits = sweep(near_first(count, vas, None), fn, hit, "builder", sha, "b",
                 maxhits=CAND)
    if "prep" in info:
        p = info["prep"]
        print("[i] prep     %d/%d segments%s"
              % (p[0], p[1], "  first err " + str(p[2]) if p[2] else ""))
    if not hits:
        print("[-] no descriptor returned a buffer starting " + HEAD4)
        return []

    good = []
    for r in sorted(hits, key=lambda x: x["d"]):
        try:
            p = build(r["d"], b"\x00" * 33)
        except RuntimeError as e:
            print("    %#x unusable: %s" % (r["d"], e))
            continue
        ok = len(p) == 33 + EXTRA and p[:4].hex() == HEAD4
        print("    %#x sizes-to-input %s (%d B)" % (r["d"], ok, len(p)))
        if ok:
            good.append(r["d"])
    if good:
        add_list("bcand:" + sha, good)
        print("[i] builders %d candidate(s)" % len(good))
    else:
        print("[-] none of them sized output to input")
    return good


def find_dec(sha, count, vas, resp, seed, build_rva):
    rva = cached(sha, "dec")
    if rva is not None:
        var = cached(sha, "decvar") or 0
        print("[i] decrypt  %#x variant %d  (cached)" % (rva, var))
        return rva, var

    order = near_first(count, vas, build_rva)
    info = {}
    for var in range(NVAR):
        def fn(batch, v=var):
            rows, err = batch_run(["sweepdec", resp.hex(), seed.hex(), str(v),
                                   ",".join(map(str, batch))])
            for r in rows:
                if "prep" in r and "prep" not in info:
                    info["prep"] = r["prep"]
            return ({r["i"]: r for r in rows
                     if "i" in r and r.get("v") == v}, err)

        def hit(r):
            return (r["st"] == 0 and r["nt"] == 0
                    and (r["prkf"] >= 0 or r["chai"] >= 0))

        found = sweep(order, fn, hit, "decrypt/v%d" % var, sha, "d%d" % var)
        if found:
            r = found[0]
            remember(sha, dec=r["d"], decvar=r["v"])
            print("[i] decrypt  %#x variant %d  (discovered)" % (r["d"], r["v"]))
            return r["d"], r["v"]
    print("[-] no descriptor decrypted this response, %d block shapes" % NVAR)
    return None, None


def make_nonce(label):
    ft = int((datetime.now(timezone.utc).timestamp() + 11_644_473_600) * 10_000_000)
    return (b"\x01" + struct.pack("<Q", ft) + b"\x28" + CONST27
            + (label + b"\x00" * TAIL)[:TAIL])


def envelope(p):
    return ('<?xml version="1.0" encoding="utf-8"?>'
            '<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
            ' xmlns:xsd="http://www.w3.org/2001/XMLSchema"'
            ' xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
            '<soap:Body><Activate xmlns="%s"><challenge>'
            '<clientSdkVersion>%s</clientSdkVersion>'
            '<clientSdkType>%s</clientSdkType>'
            '<platform>%s</platform><tid>%s</tid>'
            '<payload><primaryPayload>%s</primaryPayload></payload>'
            '</challenge></Activate></soap:Body></soap:Envelope>'
            % (NS, SDK, SDK_TYPE, PLATFORM, TID,
               base64.b64encode(p).decode("ascii"))).encode()


def post(p):
    import requests
    try:
        r = requests.post(URL, data=envelope(p), timeout=TIMEOUT, headers={
            "Accept": "*/*",
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": '"%s/Activate"' % NS,
            "User-Agent": "Microsoft-PlayReady-DRM/1.0",
            "x-playready-info": ("OSVersion=10.0; ClientDllVersion=Windows.Media."
                                 "Protection.PlayReady.dll/10.0.19041.4780 "
                                 "(WinBuild.160101.0800); Session=%s;"
                                 % secrets.token_hex(16)),
            "X-XblCorrelationId": str(secrets.randbits(63))})
    except Exception as e:
        return "err", str(e), {}
    try:
        root = ET.fromstring(r.content)
    except ET.ParseError:
        return str(r.status_code), "not XML", {}
    info = {"fault": None, "status": None, "payload": None, "keyfile": None}
    for el in root.iter():
        tag = el.tag.rsplit("}", 1)[-1].lower()
        txt = "".join(el.itertext()).strip()
        if tag == "faultstring" and not info["fault"]:
            info["fault"] = " ".join(txt.split())
        elif tag == "statuscode" and info["status"] is None:
            info["status"] = txt
        elif tag == "primarypayload" and not info["payload"]:
            info["payload"] = "".join(txt.split())
        elif tag == "keyfile" and not info["keyfile"]:
            info["keyfile"] = "".join(txt.split())
    if info["fault"]:
        return str(r.status_code), info["fault"], info
    if info["status"] is not None:
        return str(r.status_code), "statusCode " + info["status"], info
    if info["payload"] or info["keyfile"]:
        return str(r.status_code), "ACCEPTED", info
    return str(r.status_code), "unexpected", info


def cmd_request(hwid):
    sha, count, vas = census_info()
    print("[i] sha256   %s\n[i] census   %d heap-exec" % (sha, count))

    known = cached(sha, "build")
    if known is not None:
        print("[i] builder  %#x  (cached)" % known)
        cands = [known]
    else:
        cands = find_builds(sha, count, vas)
    if not cands:
        return 1

    bad = set(get_list("bbad:" + sha))
    nonce, label = make_nonce(hwid.encode()), hwid.encode()[:TAIL]
    head = 49 - TAIL
    print("\n[i] nonce    %s\n[i] hwid     %r" % (nonce.hex(), hwid))
    tail = lambda fill: (label + fill * TAIL)[:TAIL]
    todo = [("zero", nonce[:head] + tail(b"\x00")),
            ("dot", nonce[:head] + tail(b"."))]

    for rva in cands:
        if rva in bad:
            continue
        print("\n[post] %d variant(s) via %#x" % (len(todo), rva))
        win = None
        for tag, n in todo:
            try:
                p = build(rva, n)
            except RuntimeError as e:
                print("    %-6s build failed: %s" % (tag, e))
                continue
            http, verdict, info = post(p)
            t = n[head:]
            print("    %-6s %4d B  %-4s %s  tail %s %r"
                  % (tag, len(p), http, verdict, t.hex(),
                     "".join(chr(c) if 32 <= c < 127 else "." for c in t)))
            if verdict == "ACCEPTED" and win is None:
                win = (tag, p, info)
            time.sleep(0.3)

        if win is None:
            print("    %#x rejected" % rva)
            add_list("bbad:" + sha, [rva])
            continue

        tag, p, info = win
        remember(sha, build=rva)
        with open(PAYLOAD, "wb") as f:
            f.write(p)
        print("\n[+] ACCEPTED as '%s' via %#x   saved %s (%d B)"
              % (tag, rva, PAYLOAD, len(p)))
        if info.get("payload"):
            dec = base64.b64decode(info["payload"])
            with open(RESPONSE, "wb") as f:
                f.write(dec)
            print("    saved %s (%d B)\n\nnext: python tool.py --decrypt"
                  % (RESPONSE, len(dec)))
        else:
            print("    no primaryPayload in the reply")
        return 0

    print("\n[-] no builder candidate was accepted")
    return 1


def read_response(path):
    with open(path, "rb") as f:
        raw = f.read()
    if raw[:1] != b"<":
        return raw
    m = re.search(rb"<primaryPayload>([A-Za-z0-9+/=\s]+)</primaryPayload>", raw)
    if m:
        return base64.b64decode(re.sub(rb"\s", b"", m.group(1)))
    return None


def cmd_decrypt():
    if not os.path.exists(RESPONSE) or not os.path.exists(PAYLOAD):
        print("[x] need %s and %s - run a request first" % (RESPONSE, PAYLOAD))
        return 2
    resp = read_response(RESPONSE)
    if not resp:
        print("[x] %s: no primaryPayload" % RESPONSE)
        return 2
    seed = open(PAYLOAD, "rb").read()[-16:]
    if len(seed) != 16:
        print("[x] seed is %d B, expected 16" % len(seed))
        return 2

    sha, count, vas = census_info()
    print("[i] seed     %s\n[i] response %s  %d B\n[i] expect   %d B of PRKF"
          % (seed.hex(), RESPONSE, len(resp), max(len(resp) - 8, 0)))

    rva, var = find_dec(sha, count, vas, resp, seed, cached(sha, "build"))
    if rva is None:
        return 1

    rows, err = wbcall("dec", "%x" % rva, resp.hex(), seed.hex(), str(var))
    row = next((r for r in rows if "out" in r), None) if rows else None
    if row is None or row["st"] or row["nt"]:
        print("[x] dec failed: %s" % (err or "no row"))
        return 1

    plain = bytes.fromhex(row["out"])
    for o in range(0, min(len(plain), 0x60), 16):
        b = plain[o:o + 16]
        print("    %04x  %-47s  %s" % (o, " ".join("%02x" % c for c in b),
                                       "".join(chr(c) if 32 <= c < 127 else "."
                                               for c in b)))
    ok = plain[:4] == b"PRKF"
    print("    PRKF     %s" % ok)
    with open(BLA, "wb") as f:
        f.write(plain)
    print("\n[i] saved    %s  (%d B)" % (BLA, len(plain)))
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(
        epilog='  python tool.py --hwid "MY.ID"   request\n'
               "  python tool.py --decrypt         decrypt")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--hwid", metavar="TEXT",
                      help="request mode; text written into the 12-byte tail")
    mode.add_argument("--decrypt", action="store_true", help="decrypt mode")
    a = ap.parse_args(argv)
    os.makedirs(OUT, exist_ok=True)
    try:
        return cmd_request(a.hwid) if a.hwid is not None else cmd_decrypt()
    except KeyboardInterrupt:
        print("\n[!] interrupted - rerun to resume")
        os._exit(130)


if __name__ == "__main__":
    sys.exit(main())
