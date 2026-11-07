# 1-make-oracle.py
# =============================================================================
#
# Stage 1 of the chain: build the nibble-oracle inputs used by 3-derive-map.py.
#
# WHY THIS EXISTS
#   3-derive-map.py measures the build's 16-entry nibble permutation by forcing
#   the mapped nibble to a constant value M against a license blob built for a
#   known key, and checking whether a known plaintext appears. That requires,
#   for every key nibble N in 0x0N for N in 0..f (excluding 0x00):
#
#       key_NN.pub    public key whose private scalar is nibble NN
#                     repeated 64 times
#       lic_NN.blob   licence blob addressed to that public key, whose
#                     plaintext content key / signature block contains
#                     the known sentinel "HELLO MICROSOFT!"
#
#   The permutation entry is recovered because decrypting a blob addressed to
#   key_NN with the unknown private key only succeeds if the forced mapped
#   nibble M satisfies MAP[M] = NN.
#
#   Nibble 0x00 is skipped here because scalar 0 is not a valid private key;
#   3-derive-map.py recovers that entry as the leftover permutation value.
#
# PIPELINE
#   1-make-oracle.py   ->  testdata/oracle/key_NN.pub, testdata/oracle/lic_NN.blob
#   2-decrypt-img.py   ->  testdata/wbtool_img.bin
#   3-derive-map.py    ->  testdata/oracle_map.json
#   4-derive-plain.py  ->  testdata/extracted.enc.plain
#
# OUTPUTS   (all under testdata/, which is created on demand)
#   testdata/oracle/key_NN.pub     64 bytes, X||Y (no 0x04 prefix)
#   testdata/oracle/lic_NN.blob    128 bytes, C1.x||C1.y||C2.x||C2.y
#
# PROPERTIES
#   - key_NN.pub is DETERMINISTIC: same bytes on every run, every machine.
#     Byte-identical to the values recorded during development, so a rebuilt
#     oracle is verifiable with a file hash.
#   - lic_NN.blob is NOT reproducible: it uses a random ephemeral scalar, so
#     the bytes differ on every run. Validity is proven instead by
#       3-derive-map.py  reaching GOLD match
#       4-derive-plain.py reaching pubkey MATCH
#
# ORACLE PRIVATE SCALARS (for reference / manual checks)
#   nibble NN  ->  d = 0xNN repeated 64 times
#   For 0x0f that scalar (2^256-1) exceeds the group order N and is reduced
#   mod N for the scalar multiplication; the key *bytes* are still all 0x0f,
#   which is what the oracle needs.
# =============================================================================

import os
import sys
from cryptography.hazmat.primitives.asymmetric import ec

# --- output root -------------------------------------------------------------
# Every artefact this pipeline produces lives under testdata/. Keeping the
# oracle beside the image it feeds means a run can never pick up a stale copy
# from the current directory by accident.
DATA = "testdata"
os.makedirs(DATA, exist_ok=True)

# --- secp256r1 / NIST P-256 ------------------------------------------------
P  = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A  = P - 3
B  = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N  = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G  = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
      0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)

# The licence plaintext: signature key = "HELLO MICROSOFT!", content key = zeros.
# 2-derive-map.py XORs the routine's 32-byte output with the W10 magic sequence
# and looks for exactly these bytes.
SENT = b"HELLO MICROSOFT!" + b"\x00" * 16

# --- output directory --------------------------------------------------------
# Default testdata/oracle. An explicit argument still overrides it, so a fresh
# set can be generated beside the existing one and compared before swapping.
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(DATA, "oracle")

L = []
def log(s=""):
    L.append(str(s)); print(s, flush=True)

def die(msg):
    log(f"FATAL: {msg}")
    sys.exit(1)


def y_from_x(x):
    """Even-square-root Y for x, or None if x is not on the curve."""
    rhs = (pow(x, 3, P) + A * x + B) % P
    y = pow(rhs, (P + 1) // 4, P)          # P = 3 mod 4, so this is the sqrt
    if (y * y - rhs) % P:
        return None                        # no square root: x not on curve
    return y if y % 2 == 0 else P - y      # canonical (even) root


def on_curve(x, y):
    return (0 <= x < P and 0 <= y < P
            and (y * y - (pow(x, 3, P) + A * x + B)) % P == 0)


def add(p, q):
    """Affine point addition on P-256."""
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None                    # p == -q
        lam = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P     # doubling
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P             # addition
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def mul(pt, k):
    """Double-and-add scalar multiplication; k is taken mod N."""
    r = None
    k %= N
    while k:
        if k & 1:
            r = add(r, pt)
        pt = add(pt, pt)
        k >>= 1
    return r


# ---------------------------------------------------------------- sanity
MX = int.from_bytes(SENT, "big")
MY = y_from_x(MX)
if MY is None or not on_curve(MX, MY):
    die("'HELLO MICROSOFT!' || 0^16 is not an x-coordinate on P-256")
M = (MX, MY)

os.makedirs(OUT, exist_ok=True)
log(f"output    {os.path.abspath(OUT)}")
log(f"sentinel  X = {MX:064x}")
log(f"          Y = {MY:064x}")
log("")

keys, blobs = [], []
seen = {}

for nib in range(1, 16):
    # The oracle private scalar: this nibble repeated 64 times.
    raw = int(f"{nib:x}" * 64, 16)
    k   = raw % N
    if k == 0:
        die(f"nibble {nib:02x} reduces to a zero scalar")
    if k in seen:
        die(f"nibble {nib:02x} collides with {seen[k]:02x} after reduction")
    seen[k] = nib

    Q = mul(G, k)
    if Q is None or not on_curve(Q[0], Q[1]):
        die(f"nibble {nib:02x} produced an invalid public point")
    if (Q[0], Q[1]) in [(x, y) for x, y in keys]:
        die(f"nibble {nib:02x} duplicates an earlier public key")
    keys.append((Q[0], Q[1]))

    # --- key file: X||Y, no 0x04 prefix, exactly what -.sig.pub/.enc.pub use
    pub = Q[0].to_bytes(32, "big") + Q[1].to_bytes(32, "big")
    if len(pub) != 0x40:
        die(f"nibble {nib:02x}: pubkey is {len(pub)} bytes")
    with open(os.path.join(OUT, f"key_{nib:02x}.pub"), "wb") as fh:
        fh.write(pub)

    # --- licence blob: ECIES  C1 = r*G,  C2 = M + r*Q
    # Decryption with scalar k gives C2 - k*C1 = M, so the plaintext point's
    # X-coordinate is the sentinel and the routine's output is SENT XOR magic.
    r = 0
    while r == 0:
        r = int.from_bytes(os.urandom(32), "big") % N
    C1 = mul(G, r)
    C2 = add(M, mul(Q, r))
    blob = (C1[0].to_bytes(32, "big") + C1[1].to_bytes(32, "big")
            + C2[0].to_bytes(32, "big") + C2[1].to_bytes(32, "big"))
    if len(blob) != 0x80:
        die(f"nibble {nib:02x}: blob is {len(blob)} bytes")
    with open(os.path.join(OUT, f"lic_{nib:02x}.blob"), "wb") as fh:
        fh.write(blob)
    blobs.append(blob)

    # --- round-trip: decrypt with the oracle scalar and require the sentinel
    rec = add(C2, mul(C1, N - k))
    if rec != M:
        die(f"nibble {nib:02x}: round-trip did not recover the sentinel point")

    note = "  (scalar 2^256-1 > N, reduced; key bytes still all 0f)" if raw >= N else ""
    log(f"{nib:02x}  d = {k:064x}{note}")
    log(f"    X {Q[0]:064x}")
    log(f"    Y {Q[1]:064x}")
    log(f"    key 0x40 bytes  blob 0x80 bytes  round-trip OK")

# --- final invariants, because a bad oracle silently produces a wrong MAP
if len(set(keys)) != 15:
    die(f"only {len(set(keys))} distinct public keys, expected 15")
if len(set(blobs)) != 15:
    die(f"only {len(set(blobs))} distinct blobs, expected 15")

log("")
log(f"generated {len(keys)}/15 key+licence pairs in {OUT}\\")
log("key_NN.pub is deterministic; lic_NN.blob is not (random ephemeral scalar).")

# end of 1-make-oracle.py
