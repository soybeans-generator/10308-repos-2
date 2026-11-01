# oracle_keys.py
import sys, os
from cryptography.hazmat.primitives.asymmetric import ec

CURVE = ec.SECP256R1()
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

GOLD_01 = (
    0x0217E617F0B6443928278F96999E69A23A4F2C152BDF6D6CDF66E5B80282D4ED,
    0x194A7DEBCB97712D2DDA3CA85AA8765A56F45FC758599652F2897C65306E5794,
)

def point(k):
    pn = ec.derive_private_key(k % N, CURVE).public_key().public_numbers()
    return pn.x, pn.y

# --- gold check before emitting anything usable ---
x, y = point(int("1" * 64, 16))
if (x, y) != GOLD_01:
    sys.exit(f"FATAL: nibble 01 mismatch\n got  X={x:064x} Y={y:064x}\n want X={GOLD_01[0]:064x} Y={GOLD_01[1]:064x}")
print("gold check OK (nibble 01)")

os.makedirs("oracle", exist_ok=True)
seen = {}
for nib in range(1, 16):
    k = int(f"{nib:x}" * 64, 16)
    if k % N == 0:
        sys.exit(f"FATAL: nibble {nib:02x} reduces to zero scalar")
    x, y = point(k)
    if (x, y) in seen:
        sys.exit(f"FATAL: nibble {nib:02x} collides with {seen[(x, y)]}")
    seen[(x, y)] = nib
    note = "  <- scalar 2^256-1 > N, reduced mod N (key bytes still all-f)" if k >= N else ""
    print(f"{nib:02x} {x:064x} {y:064x}{note}")
    with open(f"oracle/key_{nib:02x}.pub", "wb") as fh:
        fh.write(x.to_bytes(32, "big") + y.to_bytes(32, "big"))

print(f"wrote {len(seen)} keys to oracle/  (X||Y, 64 bytes each)")
