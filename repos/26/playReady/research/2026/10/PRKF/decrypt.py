import hashlib, struct

msprcore = open("msprcore.bla", "rb").read()
sigprv   = open("fake.sig.prv", "rb").read()
sigplain = open("fake.sig.prv.plain", "rb").read()
sigpub   = open("fake.sig.pub", "rb").read()

# ---------- NIST P-256, dependency-free ----------
P  = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
A  = P - 3
N  = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
G  = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
      0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)

def padd(p, q):
    if p is None: return q
    if q is None: return p
    (x1, y1), (x2, y2) = p, q
    if x1 == x2 and (y1 + y2) % P == 0: return None
    l = ((3*x1*x1 + A) * pow(2*y1, -1, P) if p == q
         else (y2 - y1) * pow(x2 - x1, -1, P)) % P
    x3 = (l*l - x1 - x2) % P
    return x3, (l*(x1 - x3) - y1) % P

def pmul(k, p):
    r = None
    while k:
        if k & 1: r = padd(r, p)
        p = padd(p, p); k >>= 1
    return r

def pub_matches(priv, pub_xy, endian="big"):
    d = int.from_bytes(priv, endian)
    if not (0 < d < N): return False
    return pmul(d, G) == pub_xy

# ---------- parse the 0x100f records (as in step 2) ----------
def walk(buf, s, e):
    out, off = [], s
    while off + 8 <= e:
        tag, typ, total = struct.unpack_from(">HHI", buf, off)
        if total < 8 or off + total > e: break
        out.append((off, tag, typ, total, off + 8, off + total)); off += total
    return out

km = next(s for s in walk(msprcore, 12, len(msprcore)) if s[2] == 0x1009)
recs = []
for off, tag, typ, total, ps, pe in walk(msprcore, km[4], km[5]):
    if typ != 0x100f: continue
    publen = struct.unpack_from(">I", msprcore, ps + 4)[0]
    pub    = msprcore[ps + 8 : ps + 8 + publen]
    q      = ps + 8 + publen
    privlen = struct.unpack_from(">I", msprcore, q + 8)[0]
    priv    = msprcore[q + 12 : q + 12 + privlen]
    mac     = msprcore[q + 12 + privlen : q + 12 + privlen + 16]
    recs.append(dict(off=off, pub=pub, priv=priv, mac=mac))

def xy(b): return (int.from_bytes(b[:32], "big"), int.from_bytes(b[32:64], "big"))
pub_sig = xy(sigpub)

print("[0] EC code sanity with the known pair")
print(f"    int(fake.sig.prv.plain)*G == fake.sig.pub : "
      f"{pub_matches(sigplain, pub_sig)}")

ks = bytes(a ^ b for a, b in zip(sigprv, sigplain))
print(f"\n[1] keystream = fake.sig.prv XOR fake.sig.prv.plain ({len(ks)} bytes)")
for i in range(0, len(ks), 16):
    print(f"    {i:02x}: {ks[i:i+16].hex(' ')}")
print(f"    16-byte period : {ks[:16] == ks[16:32]}")

print("\n[2] reuse test: does the SAME keystream decode record[0] (encryption key)?")
pub0 = xy(recs[0]["pub"])
cand = bytes(a ^ b for a, b in zip(recs[0]["priv"], ks))
print(f"    record[0] stored  : {recs[0]['priv'].hex()}")
print(f"    candidate plain   : {cand.hex()}")
print(f"    d*G == record[0] pub (big-endian)     : {pub_matches(cand, pub0, 'big')}")
print(f"    d*G == record[0] pub (little-endian)  : {pub_matches(cand, pub0, 'little')}")

print("\n[3] cheap source guesses for the keystream")
for name, data in (("sha256(pub_sig)", sigpub),
                   ("sha256(pubX_sig)", sigpub[:32]),
                   ("sha256(pubY_sig)", sigpub[32:64]),
                   ("sha256(mac_sig)", recs[1]["mac"]),
                   ("sha256(pub_sig||mac_sig)", sigpub + recs[1]["mac"])):
    print(f"    ks == {name:<26}: {hashlib.sha256(data).digest() == ks}")

print()
if pub_matches(cand, pub0, "big") or pub_matches(cand, pub0, "little"):
    print("GLOBAL MASK CONFIRMED - keystream is record-independent")
    print("  rule: plain = stored XOR ks (constant, reusable for every identity)")
    print(f"  exit check: fake.sig.prv XOR ks == fake.sig.prv.plain : "
          f"{bytes(a ^ b for a, b in zip(sigprv, ks)) == sigplain}")
else:
    print("GLOBAL MASK DEAD - keystream is record-dependent (per-record key/nonce)")
    print("  the transform's constants live in the PlayReady library:")
    print("    encrypt path : decrypt-signing-key subroutine, RVA 0x222650 (sample prlib)")
    print("    WRET         : decsignkey / decenckey / xorkey")
    print("  the keystream below is the reference value that constant-recovery must reproduce")
