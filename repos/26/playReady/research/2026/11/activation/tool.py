# tool.py
#
#   python tool.py --hwid "MY.ID.TEXT"   request
#   python tool.py --decrypt             decrypt to testdata/msprcore.bla
#
# Everything written goes in testdata/: payload.bin, response.bin,
# msprcore.bla, tool-state.json, sweep.log.
#
# One probe = one child process, PROBE_TIMEOUT seconds each. A descriptor that
# hangs in native code is recorded once and never probed again; every verdict
# is appended to testdata/sweep.log as it is known, so an interrupted run
# resumes.
#
# No RVA is hardcoded; both are discovered and cached under the DLL sha256:
#   builder   output length input + 2252 with a constant 20-byte prologue
#   decrypt   returns PRKF or CHAI
#
# No captured file is needed: the 49-byte nonce is built here,
#   01 | FILETIME(8) | 28 | 27 constants | 12-byte HWID tail

from __future__ import annotations

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

DLL = r"C:\Windows\SYSTEM32\Windows.Media.Protection.PlayReady.dll"
OUT = "testdata"
STATE = os.path.join(OUT, "tool-state.json")
LOG = os.path.join(OUT, "sweep.log")
PAYLOAD = os.path.join(OUT, "payload.bin")
RESPONSE = os.path.join(OUT, "response.bin")
BLA = os.path.join(OUT, "msprcore.bla")
URL = "https://activation.playready.microsoft.com/PlayReady/ACT/Activation.asmx"
NS = "http://schemas.microsoft.com/PlayReady/ActivationService/v1"
NO_WINDOW = 0x08000000

SDK, SDK_TYPE, PLATFORM, TID = "4.3.0.0", "2", "9", "1"
TIMEOUT = 60.0
PROBE_TIMEOUT = 15.0
EXTRA, TAIL, NVAR, LANES = 2252, 12, 4, 16

PROLOGUE = bytes.fromhex("010000000c1bfa0084723e622f607a2c5e80f5f7")
CONST27 = bytes.fromhex("0000000000000000" "02000000" "00020000"
                        "000100" "010001" "0096" "7d0000")


def wbcall(*args, timeout=PROBE_TIMEOUT):
    exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wbcall.py")
    try:
        p = subprocess.run([sys.executable, exe, *args], capture_output=True,
                           timeout=timeout, creationflags=NO_WINDOW)
    except subprocess.TimeoutExpired:
        return [], f"timeout {timeout:g}s"
    except Exception as e:
        return [], f"{type(e).__name__}: {e}"
    rows, err = [], None
    for line in p.stdout.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "err" in r:
            err = r["err"]
        else:
            rows.append(r)
    return rows, err


def state():
    try:
        with open(STATE) as f:
            return json.load(f)
    except Exception:
        return {}


def remember(sha, **kv):
    d = state()
    d.setdefault("rva:" + sha, {}).update(kv)
    try:
        os.makedirs(OUT, exist_ok=True)
        with open(STATE, "w") as f:
            json.dump(d, f)
    except OSError:
        pass


def cached(sha, key):
    return state().get("rva:" + sha, {}).get(key)


def log_load():
    s = set()
    try:
        with open(LOG) as f:
            lines = f.readlines()
    except OSError:
        return s
    for line in lines:
        p = line.split()
        if len(p) == 3:
            try:
                s.add((p[0], int(p[1]), int(p[2])))
            except ValueError:
                pass
    return s


def log_add(kind, idx, var):
    try:
        os.makedirs(OUT, exist_ok=True)
        with open(LOG, "a") as f:
            f.write(f"{kind} {idx} {var}\n")
    except OSError:
        pass


def census_info():
    rows, err = wbcall("census", "--dll", DLL, timeout=120)
    if err or not rows:
        raise RuntimeError(err or "no census row")
    sha = rows[0]["sha"]
    st = state().get("census:" + sha, {})
    return sha, rows[0]["census"][0], [h[0] for h in st.get("heaps") or []]


def run(probes, fn, label):
    """probes: [(kind, idx, var)]. fn(kind, idx, var) -> (hit row | None, err)."""
    done = log_load()
    todo = [p for p in probes if p not in done]
    skip = len(probes) - len(todo)
    print(f"[{label}] {len(todo)} probe(s)" + (f", {skip} cached" if skip else ""))
    if not todo:
        return None

    lock = threading.Lock()
    stop = threading.Event()
    box = {"qi": 0, "n": 0, "hit": None}
    errs = []
    t0 = time.monotonic()

    def lane():
        while not stop.is_set():
            with lock:
                if box["qi"] >= len(todo):
                    return
                p = todo[box["qi"]]
                box["qi"] += 1
            r, err = fn(*p)
            log_add(*p)
            with lock:
                box["n"] += 1
                k = box["n"]
                if err and err not in errs and len(errs) < 6:
                    errs.append(err)
                if r is not None:
                    box["hit"] = r
                    stop.set()
                    return
            if k % 100 == 0:
                el = max(time.monotonic() - t0, 1e-9)
                print(f"    {k}/{len(todo)}  {el:.0f}s  {k / el:.0f}/s",
                      flush=True)

    ts = [threading.Thread(target=lane, daemon=True) for _ in range(LANES)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    el = time.monotonic() - t0
    print(f"[{label}] {box['n']}/{len(todo)} in {el:.0f}s")
    for e in errs:
        print(f"    {e}")
    return box["hit"]


def near_first(count, vas, anchor):
    if len(vas) == count and anchor:
        return sorted(range(count), key=lambda i: abs(vas[i] - anchor))
    return list(range(count))


def find_build(sha, count, vas):
    rva = cached(sha, "build")
    if rva is not None:
        print(f"[i] builder  {rva:#x}  (cached)")
        return rva

    ident = b"\x00" * 49
    info = {}

    def fn(_k, i, _v):
        rows, err = wbcall("sweepbuild", ident.hex(), str(i), "--dll", DLL)
        for r in rows:
            if "prep" in r and "prep" not in info:
                info["prep"] = r["prep"]
            if ("i" in r and r["st"] == 0 and r["nt"] == 0
                    and r["n"] == 49 + EXTRA and r["head"] == PROLOGUE.hex()):
                return r, None
        return None, err

    hit = run([("b", i, 0) for i in near_first(count, vas, None)], fn, "builder")
    if "prep" in info:
        p = info["prep"]
        print(f"[i] prep     {p[0]}/{p[1]} segments"
              + (f"  first err {p[2]}" if p[2] else ""))
    if hit is None:
        print(f"[-] no descriptor produced {49 + EXTRA} B with prologue "
              f"{PROLOGUE.hex()}")
        return None
    remember(sha, build=hit["d"])
    print(f"[i] builder  {hit['d']:#x}  (discovered)")
    return hit["d"]


def find_dec(sha, count, vas, resp, seed, build_rva):
    rva = cached(sha, "dec")
    if rva is not None:
        var = cached(sha, "decvar") or 0
        print(f"[i] decrypt  {rva:#x} variant {var}  (cached)")
        return rva, var

    info = {}

    def fn(_k, i, v):
        rows, err = wbcall("sweepdec", resp.hex(), seed.hex(), str(v), str(i),
                           "--dll", DLL)
        for r in rows:
            if "prep" in r and "prep" not in info:
                info["prep"] = r["prep"]
            if ("i" in r and r["v"] == v and r["st"] == 0 and r["nt"] == 0
                    and (r["prkf"] >= 0 or r["chai"] >= 0)):
                return r, None
        return None, err

    order = near_first(count, vas, build_rva)
    hit = run([("d", i, v) for v in range(NVAR) for i in order], fn, "decrypt")
    if "prep" in info:
        p = info["prep"]
        print(f"[i] prep     {p[0]}/{p[1]} segments"
              + (f"  first err {p[2]}" if p[2] else ""))
    if hit is None:
        print(f"[-] no descriptor decrypted this response under any of the "
              f"{NVAR} block shapes")
        return None, None
    remember(sha, dec=hit["d"], decvar=hit["v"])
    print(f"[i] decrypt  {hit['d']:#x} variant {hit['v']}  (discovered)")
    return hit["d"], hit["v"]


def make_nonce(label):
    ft = int((datetime.now(timezone.utc).timestamp() + 11_644_473_600) * 10_000_000)
    return b"\x01" + struct.pack("<Q", ft) + b"\x28" + CONST27 + \
        (label + b"\x00" * TAIL)[:TAIL]


def envelope(p):
    b64 = base64.b64encode(p).decode("ascii")
    return ('<?xml version="1.0" encoding="utf-8"?>'
            '<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
            ' xmlns:xsd="http://www.w3.org/2001/XMLSchema"'
            ' xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
            f'<soap:Body><Activate xmlns="{NS}"><challenge>'
            f'<clientSdkVersion>{SDK}</clientSdkVersion>'
            f'<clientSdkType>{SDK_TYPE}</clientSdkType>'
            f'<platform>{PLATFORM}</platform><tid>{TID}</tid>'
            f'<payload><primaryPayload>{b64}</primaryPayload></payload>'
            '</challenge></Activate></soap:Body></soap:Envelope>').encode()


def headers():
    return {"Accept": "*/*", "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": f'"{NS}/Activate"',
            "User-Agent": "Microsoft-PlayReady-DRM/1.0",
            "x-playready-info": (
                "OSVersion=10.0; ClientDllVersion=Windows.Media.Protection."
                "PlayReady.dll/10.0.19041.4780 (WinBuild.160101.0800); "
                f"Session={secrets.token_hex(16)};"),
            "X-XblCorrelationId": str(secrets.randbits(63))}


def post(p):
    import requests
    try:
        r = requests.post(URL, data=envelope(p), timeout=TIMEOUT, headers=headers())
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
        return str(r.status_code), f"statusCode {info['status']}", info
    if info["payload"] or info["keyfile"]:
        return str(r.status_code), "ACCEPTED", info
    return str(r.status_code), "unexpected", info


def build(rva, ident):
    rows, err = wbcall("build", f"{rva:x}",
                       json.dumps({"x": ident.hex()}), "--dll", DLL)
    if err:
        raise RuntimeError(err)
    row = next((r for r in rows if "tag" in r), None)
    if not row or row["st"] or row["nt"]:
        raise RuntimeError(f"call failed {row and row['st']:#010x}")
    return bytes.fromhex(row["payload"])


def cmd_request(hwid):
    sha, count, vas = census_info()
    print(f"[i] sha256   {sha}\n[i] census   {count} heap-exec")
    rva = find_build(sha, count, vas)
    if rva is None:
        return 1

    nonce, label = make_nonce(hwid.encode()), hwid.encode()[:TAIL]
    head = 49 - TAIL
    print(f"\n[i] nonce    {nonce.hex()}\n[i] hwid     {hwid!r}")

    def tail(fill):
        return (label + fill * TAIL)[:TAIL]

    todo = [("zero", nonce[:head] + tail(b"\x00")),
            ("dot", nonce[:head] + tail(b"."))]
    print(f"\n[post] {len(todo)} variant(s)")
    ok = None
    for tag, n in todo:
        try:
            p = build(rva, n)
        except RuntimeError as e:
            print(f"    {tag:<6} build failed: {e}")
            continue
        http, verdict, info = post(p)
        t = n[head:]
        print(f"    {tag:<6} {len(p):>4} B  {http:<4} {verdict}  tail "
              f"{t.hex()} {''.join(chr(c) if 32 <= c < 127 else '.' for c in t)!r}")
        if verdict == "ACCEPTED" and ok is None:
            ok = (tag, p, info)
        time.sleep(0.3)

    print()
    if not ok:
        print("[-] rejected")
        return 1
    tag, p, info = ok
    with open(PAYLOAD, "wb") as f:
        f.write(p)
    print(f"[+] ACCEPTED as '{tag}'   saved {PAYLOAD} ({len(p)} B)")
    if info.get("payload"):
        dec = base64.b64decode(info["payload"])
        with open(RESPONSE, "wb") as f:
            f.write(dec)
        print(f"    saved {RESPONSE} ({len(dec)} B)"
              f"\n\nnext: python tool.py --decrypt")
    else:
        print("    no primaryPayload in the reply")
    return 0


def read_response(path):
    with open(path, "rb") as f:
        raw = f.read()
    if raw[:1] != b"<":
        return raw
    m = re.search(rb"<primaryPayload>([A-Za-z0-9+/=\s]+)</primaryPayload>", raw)
    if m:
        return base64.b64decode(re.sub(rb"\s", b"", m.group(1)))
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return None
    for el in root.iter():
        if el.tag.rsplit("}", 1)[-1].lower() == "primarypayload":
            txt = "".join(el.itertext()).strip()
            if txt:
                return base64.b64decode(txt)
    return None


def cmd_decrypt():
    if not os.path.exists(RESPONSE) or not os.path.exists(PAYLOAD):
        print(f"[x] need {RESPONSE} and {PAYLOAD} - run a request first")
        return 2
    resp = read_response(RESPONSE)
    if not resp:
        print(f"[x] {RESPONSE}: no primaryPayload")
        return 2
    seed = open(PAYLOAD, "rb").read()[-16:]
    if len(seed) != 16:
        print(f"[x] seed is {len(seed)} B, expected 16")
        return 2

    sha, count, vas = census_info()
    print(f"[i] seed     {seed.hex()}")
    print(f"[i] response {RESPONSE}  {len(resp)} B")
    print(f"[i] expect   {max(len(resp) - 8, 0)} B of PRKF")

    rva, var = find_dec(sha, count, vas, resp, seed, cached(sha, "build"))
    if rva is None:
        return 1

    rows, err = wbcall("dec", f"{rva:x}", resp.hex(), seed.hex(), str(var),
                       "--dll", DLL, timeout=120)
    row = next((r for r in rows if "out" in r), None) if not err else None
    if not row or row["st"] or row["nt"]:
        print(f"[x] dec failed: {err or hex(row and row['st'])}")
        return 1

    plain = bytes.fromhex(row["out"])
    for o in range(0, min(len(plain), 0x60), 16):
        rowb = plain[o:o + 16]
        print(f"    {o:04x}  {' '.join(f'{c:02x}' for c in rowb):<47}  "
              f"{''.join(chr(c) if 32 <= c < 127 else '.' for c in rowb)}")
    ok = plain[:4] == b"PRKF"
    print(f"    PRKF     {ok}")
    with open(BLA, "wb") as f:
        f.write(plain)
    print(f"\n[i] saved    {BLA}  ({len(plain)} B)")
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="  python tool.py --hwid \"MY.ID\"   request\n"
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
        print("\n[!] interrupted - rerun the same command to resume; "
              "verdicts so far are in testdata\\sweep.log")
        os._exit(130)


if __name__ == "__main__":
    sys.exit(main())
