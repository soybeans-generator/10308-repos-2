import struct
import sys
from pathlib import Path

CORE = Path("msprcore.bla")
REF  = Path("fake.cert")      # optional: verification only
OUT  = Path("extracted.cert")

CHAI_HDR = 20   # magic(4) version(4) total_length(4) flags(4) cert_count(4)
CERT_HDR = 16   # magic(4) version(4) total_length(4) certificate_length(4)

def parse_chain(buf, base):
    """Self-validating parse of a CHAI chain at `base`. Returns dict or None."""
    if buf[base:base + 4] != b"CHAI":
        return None
    version, total_length, flags, cert_count = struct.unpack_from(">IIII", buf, base + 4)
    if total_length < CHAI_HDR or total_length > len(buf) - base:
        return None

    end, off, certs, warnings = base + total_length, base + CHAI_HDR, [], []
    for n in range(cert_count):
        if off + CERT_HDR > end or buf[off:off + 4] != b"CERT":
            return None
        c_ver, c_tot, c_len = struct.unpack_from(">III", buf, off + 4)
        if c_tot < CERT_HDR or off + c_tot > end:
            return None
        if c_len != c_tot - CERT_HDR:
            warnings.append(f"cert {n} @ {off:#x}: certificate_length {c_len} "
                            f"!= entry {c_tot} - {CERT_HDR}")
        certs.append((off, c_tot, c_len))
        off += c_tot
    if off != end:                      # entries must tile the chain exactly
        return None

    prefix = None
    if base >= 4:
        prefix = struct.unpack_from(">I", buf, base - 4)[0]

    return dict(base=base, version=version, total_length=total_length,
                flags=flags, cert_count=cert_count, certs=certs,
                warnings=warnings, prefix=prefix,
                prefix_ok=(prefix == total_length))

def main():
    if not CORE.is_file():
        sys.exit(f"missing input: {CORE}")
    buf = CORE.read_bytes()
    print(f"{CORE} : {len(buf)} bytes")

    reference = None
    if REF.is_file():
        reference = REF.read_bytes()
        print(f"{REF} : {len(reference)} bytes")
    else:
        print(f"{REF} : absent -> skipping verification (carve is self-validating)")

    # ---- collect every structurally valid candidate -----------------
    candidates, i = [], buf.find(b"CHAI")
    while i != -1:
        c = parse_chain(buf, i)
        if c:
            candidates.append(c)
        i = buf.find(b"CHAI", i + 1)

    if not candidates:
        sys.exit("no valid CHAI chain found")

    print(f"\n{len(candidates)} valid CHAI candidate(s):")
    for c in candidates:
        tag = "length-prefix confirmed" if c["prefix_ok"] else "no length prefix"
        print(f"  @ {c['base']:#x}  {c['total_length']} bytes  "
              f"{c['cert_count']} certs  flags={c['flags']:#x}  [{tag}]")

    # prefer the length-prefix-confirmed chain; fall back to first valid
    confirmed = [c for c in candidates if c["prefix_ok"]]
    chain = confirmed[0] if confirmed else candidates[0]
    if len(candidates) > 1:
        print(f"\nselected {chain['base']:#x} "
              f"({'length prefix' if confirmed else 'first valid, unconfirmed'})")

    base, total_length = chain["base"], chain["total_length"]
    blob = buf[base:base + total_length]

    # ---- context around the chain -----------------------------------
    lo = max(base - 16, 0)
    print(f"\nbytes {lo:#x}..{base:#x} (before CHAI):")
    print("  " + buf[lo:base].hex(" "))
    if chain["prefix"] is None:
        print("  (chain starts before offset 4 - no length prefix possible)")
    elif chain["prefix_ok"]:
        print(f"u32be at CHAI-4 = {chain['prefix']:#010x} == chain length "
              "-> PRKF length-prefix confirmed")
    else:
        print(f"u32be at CHAI-4 = {chain['prefix']:#010x} != chain length "
              f"({total_length}) -> not a PRKF-length-prefixed span")

    for w in chain["warnings"]:
        print(f"warning: {w}")

    # ---- optional cross-check against fake.cert ----------------------
    verdict = None
    if reference is None:
        print("\nno reference file - writing carved chain unconditionally")
        verdict = "unverified"
    elif reference == blob:
        print("\nEXTRACTION OK - carved chain is byte-identical to fake.cert")
        verdict = "exact"
    elif len(reference) == len(blob) + 1 and reference[1:] == blob:
        lead = reference[0]
        prev = buf[base - 1] if base >= 1 else None
        print(f"\nfake.cert = leading byte {lead:#04x} + chain (chain matches exactly)")
        if lead == prev:
            print(f"leading byte == {CORE}[{base - 1:#x}] ({prev:#04x})")
            print("-> fake.cert is a verbatim span of the core starting one byte before CHAI")
            verdict = "leading-byte"
        else:
            print(f"but {CORE}[{max(base - 1, 0):#x}] = "
                  f"{prev if prev is not None else 'n/a'} - leading byte unexplained")
            verdict = "mismatch"
    else:
        print("\nMISMATCH - neither exact nor 1-leading-byte match")
        n = min(len(blob), len(reference))
        diff = next((j for j in range(n) if blob[j] != reference[j]), None)
        if diff is not None:
            print(f"  first difference at offset {diff:#x}")
            print(f"    carved: {blob[max(diff-8,0):diff+8].hex(' ')}")
            print(f"    ref   : {reference[max(diff-8,0):diff+8].hex(' ')}")
        else:
            print(f"  common prefix identical over {n} bytes "
                  f"(lengths differ: {len(blob)} vs {len(reference)})")
        verdict = "mismatch"

    if verdict == "mismatch":
        sys.exit("not writing output - investigate the mismatch first")

    OUT.write_bytes(blob)
    print(f"\nwrote {OUT} ({len(blob)} bytes, verdict: {verdict})")

if __name__ == "__main__":
    main()
