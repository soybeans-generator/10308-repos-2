import struct

msprcore = open("msprcore.bla", "rb").read()
reference = open("fake.cert", "rb").read()

print(f"msprcore.bla : {len(msprcore)} bytes")
print(f"fake.cert    : {len(reference)} bytes")

# ---- BCert chain (big-endian, self-validating) -------------------
# CHAI | u32be version | u32be total_length | u32be flags | u32be cert_count
# then cert_count entries:
# CERT | u32be version | u32be total_length | u32be certificate_length | attrs

def parse_chain(buf, base):
    if buf[base:base+4] != b"CHAI":
        return None
    version, total_length, flags, cert_count = struct.unpack_from(">IIII", buf, base + 4)
    if not (20 <= total_length <= len(buf) - base):
        return None
    off, certs = base + 20, []
    for _ in range(cert_count):
        if off + 16 > base + total_length or buf[off:off+4] != b"CERT":
            return None
        ctot = struct.unpack_from(">I", buf, off + 8)[0]
        if ctot < 16 or off + ctot > base + total_length:
            return None
        certs.append((off, ctot))
        off += ctot
    if off != base + total_length:
        return None
    return total_length, cert_count, certs

# ---- locate CHAI -------------------------------------------------

res = None
base = None
i = msprcore.find(b"CHAI")
while i != -1:
    res = parse_chain(msprcore, i)
    if res:
        base = i
        break
    i = msprcore.find(b"CHAI", i + 1)

if res is None:
    raise SystemExit("no valid CHAI chain found")

total_length, cert_count, certs = res
blob = msprcore[base : base + total_length]

print(f"\nCHAI at {base:#x}, chain {total_length} bytes, {cert_count} certs")

# ---- what precedes the chain in the PRKF? ------------------------

print(f"\n16 bytes before CHAI ({base-16:#x}..{base:#x}):")
print("  " + msprcore[base-16:base].hex(" "))

v = struct.unpack_from(">I", msprcore, base - 4)[0]
print(f"u32be at CHAI-4 : {v:#010x} ({v})"
      + ("   == chain length -> PRKF length-prefix confirmed" if v == total_length else ""))

# ---- verify against fake.cert ------------------------------------
# accept:
#   (a) exact match, or
#   (b) fake.cert = 1 leading byte + chain, ONLY if that byte equals
#       the byte immediately preceding CHAI in msprcore.bla
#       (proves fake.cert is a verbatim file span starting 1 byte early,
#        i.e. it swallowed the last byte of the length prefix)

if blob == reference:
    print("\nEXTRACTION OK - carved chain is byte-identical to fake.cert")
    open("extracted.cert", "wb").write(blob)
elif len(reference) == len(blob) + 1 and reference[1:] == blob:
    lead, prev = reference[0], msprcore[base - 1]
    print(f"\nfake.cert = leading byte {lead:#04x} + chain (chain matches exactly)")
    if lead == prev:
        print(f"leading byte == msprcore.bla[{base-1:#x}] ({prev:#04x})")
        print("-> proven: fake.cert is a verbatim span of msprcore.bla starting")
        print("   1 byte before CHAI (includes last byte of the length prefix)")
        print("EXTRACTION OK - chain object == fake.cert[1:]")
        open("extracted.cert", "wb").write(blob)
    else:
        print(f"but msprcore.bla[{base-1:#x}] = {prev:#04x} - leading byte NOT")
        print("explained by the file - do not accept, investigate first")
else:
    print("\nMISMATCH - neither exact nor 1-leading-byte match")
    n = min(len(blob), len(reference))
    for j in range(n):
        if blob[j] != reference[j]:
            print(f"  first difference at offset {j:#x}")
            break
