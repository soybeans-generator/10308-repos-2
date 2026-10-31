import struct

msprcore = open("msprcore.bla", "rb").read()
sigprv   = open("fake.sig.prv", "rb").read()
sigpub   = open("fake.sig.pub", "rb").read()
sigplain = open("fake.sig.prv.plain", "rb").read()

assert msprcore[:4] == b"PRKF", "bad magic"
ver, fsize = struct.unpack_from(">II", msprcore, 4)
print(f"PRKF v{ver}  declared size {fsize}  actual {len(msprcore)}")
print(f"refs: fake.sig.prv={len(sigprv)}B  fake.sig.pub={len(sigpub)}B  "
      f"fake.sig.prv.plain={len(sigplain)}B")

# section walker: u16 tag | u16 type | u32 total_len (incl 8B header) | payload
def walk(buf, start, end):
    out, off = [], start
    while off + 8 <= end:
        tag, typ, total = struct.unpack_from(">HHI", buf, off)
        if total < 8 or off + total > end:
            break
        out.append((off, tag, typ, total, off + 8, off + total))
        off += total
    return out

top = walk(msprcore, 12, len(msprcore))
print("\n[top-level sections]")
print("  offset   tag  type    total  payload")
for off, tag, typ, total, ps, pe in top:
    print(f"  {off:#06x}   {tag:>3}  0x{typ:04x}  {total:>5}  {pe-ps:>5}")

# key record (type 0x100f):
# u16 ver | u16 flags | u32 publen | pub | u32 0 | u32 0 | u32 privlen | priv | 16B MAC | u32
def parse_rec(buf, ps, pe):
    rver, flags, publen = struct.unpack_from(">HHI", buf, ps)
    pub = buf[ps+8 : ps+8+publen]
    q = ps + 8 + publen
    z1, z2, privlen = struct.unpack_from(">III", buf, q)
    priv = buf[q+12 : q+12+privlen]
    mac  = buf[q+12+privlen : q+12+privlen+16]
    tail = buf[q+12+privlen+16 : q+12+privlen+20]
    return dict(ver=rver, flags=flags, publen=publen, pub=pub,
                privlen=privlen, priv=priv, mac=mac, tail=tail)

# key material container = type 0x1009
km = next(s for s in top if s[2] == 0x1009)
km_secs = [s for s in walk(msprcore, km[4], km[5]) if s[2] == 0x100f]
km_offs = [s[0] for s in km_secs]
recs    = [parse_rec(msprcore, s[4], s[5]) for s in km_secs]

print(f"\n[key records] in type-0x1009 section @ {km[0]:#x} -> {len(recs)} records")
for i, (o, r) in enumerate(zip(km_offs, recs)):
    print(f"\n  record[{i}] @ {o:#06x}: ver={r['ver']} flags=0x{r['flags']:04x} "
          f"publen={r['publen']} privlen={r['privlen']}")
    print(f"    pub X = {r['pub'][:32].hex()}")
    print(f"         Y = {r['pub'][32:64].hex()}")
    print(f"    priv  = {r['priv'].hex()}")
    print(f"    mac   = {r['mac'].hex()}   tail={r['tail'].hex()}")

# --- chain (step 1) so we can tie a key to the leaf cert ---
def chain_at(buf, base):
    if buf[base:base+4] != b"CHAI":
        return None
    vv, total, fl, cnt = struct.unpack_from(">IIII", buf, base+4)
    if not (20 <= total <= len(buf)-base):
        return None
    off, crts = base+20, []
    for _ in range(cnt):
        if off+16 > base+total or buf[off:off+4] != b"CERT":
            return None
        t = struct.unpack_from(">I", buf, off+8)[0]
        if t < 16 or off+t > base+total:
            return None
        crts.append((off, t)); off += t
    if off != base+total:
        return None
    return (base, total), crts

ch = None
j = msprcore.find(b"CHAI")
while j != -1:
    r = chain_at(msprcore, j)
    if r:
        ch = r; break
    j = msprcore.find(b"CHAI", j+1)
if not ch:
    raise SystemExit("chain not found")
(cb, cl), crts = ch
leaf_off, leaf_len = crts[0]
leaf = msprcore[leaf_off:leaf_off+leaf_len]
print(f"\n[chain] @ {cb:#x} len {cl}; leaf cert @ {leaf_off:#x} len {leaf_len}")

# --- identify signing key: record whose 64B pubkey lives in the leaf cert ---
in_leaf = [ (r['pub'] in leaf) or
            ((r['pub'][:32] in leaf) and (r['pub'][32:64] in leaf)) for r in recs ]
print("\n[identify signing key]")
for i in range(len(recs)):
    print(f"  record[{i}]: pubkey in leaf cert = {in_leaf[i]}")

if sum(in_leaf) == 1:
    idx = in_leaf.index(True)
    how = "unique pubkey match in leaf cert"
else:
    idx = [i for i, r in enumerate(recs) if r['privlen'] == 32][1]
    how = "order fallback (2nd 32-byte key = signing key)"

sig = recs[idx]
print(f"  -> signing key = record[{idx}] @ {km_offs[idx]:#x}  ({how})")

# --- verify against the reference files ---
print("\n[per-record reference check]")
for i, r in enumerate(recs):
    print(f"  record[{i}]: priv==fake.sig.prv={r['priv']==sigprv}  "
          f"pub==fake.sig.pub={r['pub']==sigpub}  pub_in_leaf={in_leaf[i]}")

print("\n[verify selected]")
print(f"  priv == fake.sig.prv       : {sig['priv'] == sigprv}")
print(f"  pub  == fake.sig.pub       : {sig['pub'] == sigpub}")
print(f"  priv != fake.sig.prv.plain : {sig['priv'] != sigplain}  (PRKF holds obfuscated key)")

if sig['priv'] == sigprv and sig['pub'] == sigpub:
    print("\nEXTRACTION OK")
    print("standalone rule:")
    print("  PRKF -> section type 0x1009 -> records type 0x100f")
    print("  -> record whose 64-byte pubkey is in the leaf cert")
    print("  -> privkey = record_payload + 84, length = u32be at payload+80")
