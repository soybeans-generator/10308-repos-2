import os, sys

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
G = (GX, GY)

PLAIN_X = int.from_bytes(b"HELLO MICROSOFT!" + b"\x00" * 16, "big")


def y_from_x(x):
    rhs = (pow(x, 3, P) + A * x + B) % P
    y = pow(rhs, (P + 1) // 4, P)
    if (y * y - rhs) % P:
        return None
    return y if y % 2 == 0 else P - y


def on_curve(x, y):
    if not (0 <= x < P and 0 <= y < P):
        return False
    return (y * y - (pow(x, 3, P) + A * x + B)) % P == 0


def add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        lam = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def mul(pt, k):
    r = None
    k %= N
    while k:
        if k & 1:
            r = add(r, pt)
        pt = add(pt, pt)
        k >>= 1
    return r


def main():
    if not on_curve(PLAIN_X, y_from_x(PLAIN_X) or 0):
        sys.exit("FATAL: 'HELLO MICROSOFT!'||0^16 is not an x-coordinate on P-256")
    m = (PLAIN_X, y_from_x(PLAIN_X))

    verified = False
    for nib in range(1, 16):
        pubf = os.path.join("oracle", "key_%02x.pub" % nib)
        outf = os.path.join("oracle", "lic_key_%02x.blob" % nib)
        raw = open(pubf, "rb").read()
        if len(raw) != 64:
            sys.exit("FATAL: %s is %d bytes, expected 64" % (pubf, len(raw)))
        qx = int.from_bytes(raw[:32], "big")
        qy = int.from_bytes(raw[32:], "big")
        if not on_curve(qx, qy):
            sys.exit("FATAL: %s is not a valid P-256 point" % pubf)

        k = 0
        while k == 0:
            k = int.from_bytes(os.urandom(32), "big") % N
        c1 = mul(G, k)
        c2 = add(m, mul((qx, qy), k))
        blob = b"".join(v.to_bytes(32, "big") for v in (c1[0], c1[1], c2[0], c2[1]))
        open(outf, "wb").write(blob)

        if not verified:
            d = int("1" * 64, 16) % N
            if add(c2, mul(c1, N - d)) != m:
                sys.exit("FATAL: self-check failed (blob layout/arithmetic wrong)")
            verified = True
            print("self-check OK (key_01 round-trip via known scalar)")

        print("%s: %d bytes" % (outf, len(blob)))

    print("all 15 blobs written to oracle\\")


if __name__ == "__main__":
    main()
