# verify_plain.py — corrected CMAC body slice (xmr[:-28], not xmr[:-16])
import base64, re
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
SIG_FTLV = 28

def add(p, q):
    if p is None: return q
    if q is None: return p
    x1, y1 = p; x2, y2 = q
    if x1 == x2:
        if (y1 + y2) % P == 0: return None
        lam = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)

def mul(pt, k):
    r = None; k %= N
    while k:
        if k & 1: r = add(r, pt)
        pt = add(pt, pt); k >>= 1
    return r

def pt(b):
    return (int.from_bytes(b[:32], "big"), int.from_bytes(b[32:64], "big"))

def enc(k, b):
    c = Cipher(algorithms.AES(k), modes.ECB()).encryptor()
    return c.update(b) + c.finalize()

def dbl(b):
    n = int.from_bytes(b, "big") << 1
    if n >> 128:
        n = (n & ((1 << 128) - 1)) ^ 0x87
    return n.to_bytes(16, "big")

def cmac(k, msg):
    L = enc(k, b"\x00" * 16)
    K1, K2 = dbl(L), dbl(dbl(L))
    if msg and len(msg) % 16 == 0:
        last, head = bytes(a ^ b for a, b in zip(msg[-16:], K1)), msg[:-16]
    else:
        n = len(msg) % 16
        last = bytes(a ^ b for a, b in zip(msg[len(msg)-n:] + b"\x80" + b"\x00"*(15-n), K2))
        head = msg[:len(msg)-n]
    x = b"\x00" * 16
    for i in range(0, len(head), 16):
        x = enc(k, bytes(a ^ b for a, b in zip(x, head[i:i+16])))
    return enc(k, bytes(a ^ b for a, b in zip(x, last)))

d = int.from_bytes(open("extracted.enc.plain", "rb").read(), "big")
assert 0 < d < N

pub = open("extracted.enc.pub", "rb").read()[-64:]
G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
     0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)
Q = mul(G, d)
assert Q == pt(pub), "scalar does not reproduce .enc.pub"

xml = open("resp.xml", encoding="utf-8", errors="replace").read()
xmr = base64.b64decode("".join(re.search(
    r"<License>([A-Za-z0-9+/=\s]+)</License>", xml).group(1).split()))
C1, C2 = pt(xmr[0x80:0xC0]), pt(xmr[0xC0:0x100])

M = add(C2, mul(C1, N - d))
assert M is not None
mx = M[0].to_bytes(32, "big")
sig, cont = mx[:16], mx[16:]
body, want = xmr[:-SIG_FTLV], xmr[-16:]

print(f"private scalar  {d:064x}")
print(f"pubkey match    True")
print(f"signature key   {sig.hex()}")
print(f"content key     {cont.hex()}")
print(f"cmac body       {len(body)} bytes")
print(f"cmac computed   {cmac(sig, body).hex()}")
print(f"cmac expected   {want.hex()}")
print(f"CMAC ok         {cmac(sig, body) == want}")
print(f"matches request {cont == base64.b64decode('EAtsIJQPd5pFiRUrV9Layw==')}")
