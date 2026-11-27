# tool.py
#
# PlayReady activation, request and response, on a clean machine.
#
#   python tool.py --hwid "MY.ID.TEXT"   request, then save the response
#   python tool.py --rva 0x66280         decrypt that response to msprcore.bla
#
# The request needs NO captured file. The client's 49-byte nonce is
#
#     01 | FILETIME(8) | 28 | 27 constant bytes | 12-byte HWID tail
#
# The 27 bytes are identical across captures, and every 12-byte tail we tried
# was accepted - that is what makes a custom HWID possible. So the nonce is
# built here: constants, the current time, and --hwid in the tail. nonce.bin is
# read if present, --nonce-hex overrides, and neither is required.
#
# The decrypt half is 3.py's block: input is the response, input_len =
# len(response), seed is the last 16 bytes of the request payload, output_len =
# len - 8. 0x66280 on this DLL; without --rva the sweep finds it.
#
# Both RVAs belong to one DLL build. A Windows update moves them, so the sweep
# is the default and --rva is the shortcut. wbcall.py does the DLL side.

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
STATE = "tool-state.json"
NONCE_FILE = "nonce.bin"
PAYLOAD = "payload.bin"
RESPONSE = "response.bin"
BLA = "msprcore.bla"
BUILD_RVA = 0x64BC0
DEC_RVA = 0x66280
URL = "https://activation.playready.microsoft.com/PlayReady/ACT/Activation.asmx"
NS = "http://schemas.microsoft.com/PlayReady/ActivationService/v1"
NO_WINDOW = 0x08000000
TAIL = 12
NVAR = 4
LANES = 16
CHUNK = 40

# the 27 bytes between the inner length and the HWID tail, taken verbatim from
# a client capture; identical in every nonce seen
CONST27 = bytes.fromhex("0000000000000000" "02000000" "00020000"
                        "000100" "010001" "0096" "7d0000")


# ------------------------------------------------------------- wbcall.py bridge

def wbcall(*args, timeout=900):
    exe = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wbcall.py")
    try:
        p = subprocess.run([sys.executable, exe, *args], capture_output=True,
                           timeout=timeout, creationflags=NO_WINDOW)
    except Exception as e:
        return [], str(e)
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


def heap_vas():
    if not os.path.exists(STATE):
        return []
    try:
        with open(STATE) as f:
            st = json.load(f)
    except Exception:
        return []
    for k, v in st.items():
        if k.startswith("census:") and isinstance(v, dict):
            hs = v.get("heaps") or []
            if hs:
                return [h[0] for h in hs]
    return []


def find(p):
    for d in (".", os.path.expanduser("~")):
        q = os.path.join(d, p)
        if os.path.exists(q):
            return q
    return p if os.path.exists(p) else None


# ---------------------------------------------------------------- the nonce

def make_nonce(label: bytes, when=None) -> bytes:
    """01 | FILETIME | 28 | 27 constants | 12-byte tail.  49 bytes."""
    when = when or datetime.now(timezone.utc)
    ft = int((when.timestamp() + 11_644_473_600) * 10_000_000)
    tail = (label + b"\x00" * TAIL)[:TAIL]
    return b"\x01" + struct.pack("<Q", ft) + b"\x28" + CONST27 + tail


def load_nonce(a):
    """(nonce, source).  Built locally when no file and no argument."""
    if a.nonce_hex:
        return bytes.fromhex(a.nonce_hex), "argument"
    p = find(NONCE_FILE)
    if p:
        return open(p, "rb").read(), p
    return make_nonce(a.hwid.encode()), "built here"


# ------------------------------------------------------------------- the request

def envelope(payload, sdk, sdk_type, platform, tid):
    b64 = base64.b64encode(payload).decode("ascii")
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
        ' xmlns:xsd="http://www.w3.org/2001/XMLSchema"'
        ' xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
        '<soap:Body>'
        f'<Activate xmlns="{NS}"><challenge>'
        f'<clientSdkVersion>{sdk}</clientSdkVersion>'
        f'<clientSdkType>{sdk_type}</clientSdkType>'
        f'<platform>{platform}</platform>'
        f'<tid>{tid}</tid>'
        f'<payload><primaryPayload>{b64}</primaryPayload></payload>'
        '</challenge></Activate></soap:Body></soap:Envelope>'
    ).encode("utf-8")


def headers():
    return {
        "Accept": "*/*",
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": f'"{NS}/Activate"',
        "User-Agent": "Microsoft-PlayReady-DRM/1.0",
        "x-playready-info": ("OSVersion=10.0; ClientDllVersion=Windows.Media."
                             "Protection.PlayReady.dll/10.0.19041.4780 "
                             "(WinBuild.160101.0800); Session="
                             + secrets.token_hex(16) + ";"),
        "X-XblCorrelationId": str(secrets.randbits(63)),
    }


def post(payload, a):
    body = envelope(payload, a.sdk, a.sdk_type, a.platform, a.tid)
    if a.dry_run:
        return "dry", "not sent", {}
    import requests
    try:
        r = requests.post(a.url, data=body, timeout=a.timeout, headers=headers())
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


def build(a, ident):
    rows, err = wbcall("build", f"{BUILD_RVA:x}",
                       json.dumps({"x": ident.hex()}), "--dll", a.dll)
    if err:
        raise RuntimeError(err)
    row = next((r for r in rows if "tag" in r), None)
    if not row:
        raise RuntimeError("no build row")
    if row["st"] or row["nt"]:
        raise RuntimeError(f"call failed {row['st']:#010x}")
    return bytes.fromhex(row["payload"])


def cmd_request(a):
    nonce, src = load_nonce(a)
    if len(nonce) != 49:
        print(f"[x] nonce is {len(nonce)} B, expected 49")
        return 2
    label = a.hwid.encode()[:TAIL]
    head = 49 - TAIL

    print(f"[i] nonce    {nonce.hex()}  ({src})")
    print(f"[i] hwid     {a.hwid!r} in the {TAIL}-byte tail")

    def tail(fill):
        return (label + fill * TAIL)[:TAIL]

    cands = [("zero", nonce[:head] + tail(b"\x00")),
             ("dot", nonce[:head] + tail(b"."))]
    seen, todo = set(), []
    for tag, n in cands:
        if n not in seen:
            seen.add(n)
            todo.append((tag, n))

    print(f"\n[post] {len(todo)} variant(s)")
    accepted = None
    for tag, n in todo:
        try:
            payload = build(a, n)
        except RuntimeError as e:
            print(f"    {tag:<8} build failed: {e}")
            continue
        http, verdict, info = post(payload, a)
        t = n[head:]
        asc = "".join(chr(c) if 32 <= c < 127 else "." for c in t)
        print(f"    {tag:<8} {len(payload):>4} B  {http:<4} {verdict}  "
              f"tail {t.hex()} {asc!r}")
        if verdict == "ACCEPTED" and accepted is None:
            accepted = (tag, n, payload, info)
        time.sleep(0.3)

    print()
    if not accepted:
        print("[-] rejected")
        return 1

    tag, n, payload, info = accepted
    with open(PAYLOAD, "wb") as f:
        f.write(payload)
    print(f"[+] ACCEPTED as '{tag}'")
    print(f"    saved    {PAYLOAD}  ({len(payload)} B)")
    if info.get("payload"):
        dec = base64.b64decode(info["payload"], validate=True)
        with open(RESPONSE, "wb") as f:
            f.write(dec)
        print(f"    saved    {RESPONSE}  ({len(dec)} B)")
        print(f"\nnext:  python tool.py --rva {DEC_RVA:#x}")
    else:
        print("    no primaryPayload in the reply - nothing to decrypt")
    return 0


# ------------------------------------------------------------------- decrypt

def read_response(path):
    with open(path, "rb") as f:
        raw = f.read()
    if raw[:5] == b"<?xml" or raw[:1] == b"<":
        m = re.search(rb"<primaryPayload>([A-Za-z0-9+/=\s]+)</primaryPayload>",
                      raw)
        if m:
            return base64.b64decode(re.sub(rb"\s", b"", m.group(1)), validate=True)
        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            return None
        for el in root.iter():
            if el.tag.rsplit("}", 1)[-1].lower() == "primarypayload":
                txt = "".join(el.itertext()).strip()
                if txt:
                    return base64.b64decode(txt, validate=True)
        return None
    return raw


class Sweep:
    def __init__(self, a, resp, seed, order):
        self.a, self.resp, self.seed, self.order = a, resp, seed, order
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.found, self.errs = [], []
        self.done = self.faults = 0
        self.jobs = []
        for var in range(NVAR):
            idx = list(order)
            self.jobs += [(var, idx[i:i + CHUNK])
                          for i in range(0, len(idx), CHUNK)]
        self.qi = 0

    def note(self, e):
        with self.lock:
            if len(self.errs) < 4 and e not in self.errs:
                self.errs.append(e)

    def run(self, var, idxs):
        if not idxs or self.stop.is_set():
            return
        rows, err = wbcall("sweepdec", self.resp.hex(), self.seed.hex(),
                           str(var), ",".join(str(i) for i in idxs),
                           "--dll", self.a.dll)
        if err:
            self.note(err)
        got = {r["i"]: r for r in rows if "i" in r and r.get("v") == var}

        last = -1
        for k, i in enumerate(idxs):
            r = got.get(i)
            if r is None:
                break
            last = k
            with self.lock:
                self.done += 1
            if r["st"] == 0 and r["nt"] == 0 and (r["prkf"] >= 0 or r["chai"] >= 0):
                with self.lock:
                    self.found.append(r)
                self.stop.set()
                return

        rest = idxs[last + 1:]
        if not rest:
            return
        with self.lock:
            self.faults += 1
        if len(rest) == 1:
            return
        mid = len(rest) // 2
        self.run(var, rest[:mid])
        self.run(var, rest[mid:])

    def lane(self):
        while not self.stop.is_set():
            with self.lock:
                if self.qi >= len(self.jobs):
                    return
                var, idxs = self.jobs[self.qi]
                self.qi += 1
            self.run(var, idxs)


def sweep(a, resp, seed, order):
    s = Sweep(a, resp, seed, order)
    total = len(order) * NVAR
    ts = [threading.Thread(target=s.lane, daemon=True) for _ in range(LANES)]
    t0 = time.monotonic()
    for t in ts:
        t.start()
    last = 0.0
    while any(t.is_alive() for t in ts):
        time.sleep(0.4)
        if s.stop.is_set():
            break
        if time.monotonic() - last >= 2.0:
            last = time.monotonic()
            with s.lock:
                n, f = s.done, s.faults
            print(f"    {n}/{total}  faults {f}  ({time.monotonic() - t0:.1f}s)",
                  flush=True)
    for t in ts:
        t.join(timeout=0.5)
    return s.found, s.errs, time.monotonic() - t0, s.done, s.faults


def hexdump(b, limit=0x60):
    for o in range(0, min(len(b), limit), 16):
        row = b[o:o + 16]
        hx = " ".join(f"{c:02x}" for c in row)
        asc = "".join(chr(c) if 32 <= c < 127 else "." for c in row)
        print(f"    {o:04x}  {hx:<47}  {asc}")


def cmd_decrypt(a):
    rp = find(RESPONSE)
    if not rp:
        print(f"[x] no {RESPONSE} - run a request first")
        return 2
    resp = read_response(rp)
    if not resp:
        print(f"[x] {rp}: no primaryPayload in it")
        return 2

    if a.seed:
        seed, src = bytes.fromhex(a.seed), "argument"
    else:
        qp = find(PAYLOAD)
        if not qp:
            print(f"[x] no {PAYLOAD} and no --seed")
            return 2
        seed, src = open(qp, "rb").read()[-16:], qp
    if len(seed) != 16:
        print(f"[x] seed is {len(seed)} B, expected 16")
        return 2

    print(f"[i] seed     {seed.hex()}  ({src})")
    print(f"[i] response {rp}  {len(resp)} B  head {resp[:16].hex()}")
    print(f"[i] expect   {max(len(resp) - 8, 0)} B of PRKF")

    rows, err = wbcall("census", "--dll", a.dll)
    if err:
        print(f"[x] census: {err}")
        return 2
    count, nseg = rows[0]["census"]
    print(f"[i] census   {count} heap-exec, {nseg} segment")

    vas = heap_vas()
    if len(vas) == count:
        order = sorted(range(count), key=lambda i: abs(vas[i] - BUILD_RVA))
        print(f"[i] order    nearest to {BUILD_RVA:#x} first")
    else:
        order = list(range(count))

    rva, var = a.rva, a.var
    if rva is None:
        print(f"\n[sweep] {count} descriptors x {NVAR} variants "
              f"= {count * NVAR} probes")
        found, errs, dt, n, f = sweep(a, resp, seed, order)
        print(f"[sweep] {n}/{count * NVAR} in {dt:.1f}s  faults {f}  "
              f"hits {len(found)}")
        for e in errs:
            print(f"    child: {e}")
        if not found:
            print()
            if n < count * NVAR // 2:
                print(f"[-] only {n} probes returned a row - incomplete, "
                      f"not negative. Paste the counts.")
            else:
                print("[-] complete negative: none of the four block shapes")
                print("    decrypted this response, so the seed does not pair")
                print("    with it, or the layout differs on this build.")
            return 1
        rva, var = found[0]["d"], found[0]["v"]
        print(f"[i] routine  {rva:#x}  variant {var}  ({found[0]['len']} B, "
              f"PRKF at {found[0]['prkf']})")
        print(f"    reuse:   python tool.py --rva {rva:#x} --var {var}")
    else:
        print(f"\n[dec] descriptor {rva:#x}  variant {var}")

    rows, err = wbcall("dec", f"{rva:x}", resp.hex(), seed.hex(), str(var),
                       "--dll", a.dll)
    if err:
        print(f"[x] dec: {err}")
        return 2
    row = next((r for r in rows if "out" in r), None)
    if not row:
        print("[x] no output")
        return 2
    if row["st"] or row["nt"]:
        print(f"[x] call failed: status {row['st']:#010x} nt {row['nt']:#010x}")
        return 1

    plain = bytes.fromhex(row["out"])
    print(f"\n[i] plaintext {len(plain)} B")
    hexdump(plain)
    print(f"    ascii    "
          f"{''.join(chr(c) if 32 <= c < 127 else '.' for c in plain[:0x40])!r}")
    ok = plain[:4] == b"PRKF"
    print(f"    PRKF     {ok}")

    with open(BLA, "wb") as f:
        f.write(plain)
    print(f"\n[i] saved    {BLA}  ({len(plain)} B)")
    if ok:
        print(f"    -4 carves the chain:  corePath = {BLA}")
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="PlayReady activation: request with a custom HWID, or "
                    "decrypt the response.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="  python tool.py --hwid \"MY.ID\"     request\n"
               "  python tool.py --rva 0x66280      decrypt")
    ap.add_argument("--hwid", nargs="?", const="FAKE.PR.ID", metavar="TEXT",
                    help="enter request mode; text written into the 12-byte "
                         "tail (default FAKE.PR.ID)")
    ap.add_argument("--nonce-hex", metavar="HEX",
                    help="49-byte nonce, overriding the built one")
    ap.add_argument("--seed", metavar="HEX",
                    help="16-byte seed, instead of the payload tail")
    ap.add_argument("--rva", type=lambda s: int(s, 0),
                    help="decrypt descriptor; without it the sweep finds it")
    ap.add_argument("--var", type=int, default=0, help="block shape 0..3")
    ap.add_argument("--dll", default=DLL)
    ap.add_argument("--url", default=URL)
    ap.add_argument("--sdk", default="4.3.0.0")
    ap.add_argument("--sdk-type", default="2")
    ap.add_argument("--platform", default="9")
    ap.add_argument("--tid", default="1")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--timeout", type=float, default=60.0)
    a = ap.parse_args(argv)

    return cmd_request(a) if a.hwid is not None else cmd_decrypt(a)


if __name__ == "__main__":
    sys.exit(main())
