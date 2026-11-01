# 2-extract-keys.py [prkf] [refstem] [outstem]   defaults: msprcore.bla fake extracted

import os, struct, sys

def walk(buf, start, end):
    out, off = [], start
    while off + 8 <= end:
        tag, typ, total = struct.unpack_from(">HHI", buf, off)
        if total < 8 or off + total > end: break
        out.append((off, tag, typ, total, off + 8, off + total))
        off += total
    return out

def parse_rec(buf, ps, pe):
    if ps + 8 > pe: return None
    ver, flags, publen = struct.unpack_from(">HHI", buf, ps)
    if publen > 0x100 or ps + 8 + publen + 12 > pe: return None
    pub = buf[ps + 8 : ps + 8 + publen]
    q = ps + 8 + publen
    z1, z2, privlen = struct.unpack_from(">III", buf, q)
    if privlen > 0x200 or q + 12 + privlen + 20 > pe: return None
    return dict(off=ps, publen=publen, pub=pub,
                privlen=privlen, priv=buf[q + 12 : q + 12 + privlen])

def rd(p):
    try: return open(p, "rb").read()
    except OSError: return None

def main(src="msprcore.bla", refstem="fake", outstem="extracted"):
    out_names = ("sig.pub", "sig.prv", "enc.pub", "enc.prv")
    outs = {k: f"{outstem}.{k}" for k in out_names}
    refs = {k: f"{refstem}.{k}" for k in ("sig.pub", "sig.prv")}

    for o in outs.values():
        if os.path.abspath(o) == os.path.abspath(src) or \
           os.path.abspath(o) in {os.path.abspath(r) for r in refs.values()}:
            raise SystemExit(f"refusing to overwrite {o} - pick another outstem")

    b = rd(src)
    if b is None or b[:4] != b"PRKF": raise SystemExit(f"{src}: not a PRKF")
    ref = {k: rd(p) for k, p in refs.items()}

    km = next((s for s in walk(b, 12, len(b)) if s[2] == 0x1009), None)
    if km is None: raise SystemExit("no 0x1009 key-material section")
    recs = [r for r in (parse_rec(b, ps, pe)
                        for off, tag, typ, total, ps, pe in walk(b, km[4], km[5])
                        if typ == 0x100f) if r]
    print(f"usable records: {len(recs)}")
    for r in recs:
        print(f"  {r['off']:#8x}  pub={r['publen']:>2}B priv={r['privlen']:>2}B "
              f"{r['pub'][:8].hex()}")

    # --- signing key: identified by the reference pubkey, which is authoritative.
    if ref["sig.pub"] is None:
        raise SystemExit(f"{refs['sig.pub']} is required to identify the signing "
                         f"key among {len(recs)} records")
    hits = [r for r in recs if r["pub"] == ref["sig.pub"]]
    if len(hits) != 1:
        raise SystemExit(f"{len(hits)} records match {refs['sig.pub']} (need 1)")
    sig = hits[0]
    print(f"signing key: {sig['off']:#x}  (pubkey == {refs['sig.pub']})")

    # --- encryption key: the 65-byte private component
    enc_c = [r for r in recs if r["privlen"] == 65 and r is not sig]
    if len(enc_c) != 1:
        raise SystemExit(f"{len(enc_c)} non-signing records have a 65-byte "
                         f"private component (need 1)")
    enc = enc_c[0]
    print(f"encryption key: {enc['off']:#x}  (65-byte private component)")

    if sig["privlen"] != 32:
        raise SystemExit(f"signing priv is {sig['privlen']}B, expected 32")

    data = {"sig.pub": sig["pub"], "sig.prv": sig["priv"],
            "enc.pub": enc["pub"], "enc.prv": enc["priv"]}

    print("\nwritten:")
    for k, v in data.items():
        open(outs[k], "wb").write(v)
        print(f"  {outs[k]}  {len(v):>2} B")

    ok = True
    print(f"\nverified against {refstem}.sig.* :")
    for k in ("sig.pub", "sig.prv"):
        if ref[k] is None:
            print(f"  [ n/a] {refs[k]} not present")
        else:
            same = data[k] == ref[k]
            ok &= same
            print(f"  [{' OK ' if same else 'FAIL'}] {outs[k]} "
                  f"{'==' if same else '!='} {refs[k]}")

    print("\nPASS" if ok else "\nFAIL")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:4]))
