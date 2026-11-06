# 4-decrypt.py decrypt a PlayReady signing key
# (extracted.sig.prv -> extracted.sig.plain)
#
# USAGE
#   decrypt.py                      decrypt extracted.sig.prv -> extracted.sig.plain
#   decrypt.py --pub PATH           validate against a specific public key
#                                   (default: extracted.sig.pub)
#
#   No positional arguments. Input and output names are fixed to the ones
#   2-extract-keys.py produces. The output is written only after every
#   available check passes.
#
# VERSION SUPPORT
#   Verified on: Windows.Media.Protection.PlayReady.dll 10.0.19041.4780,
#                10,348,448 bytes,
#                sha256 3cc6724d105e94bb0fb5971cc07ab2967dde2290ecebf4e0d4a910c80732ba7a
#
#   Only ONE value differs between DLL builds: the RVA of the heap descriptor
#   holding the signing-key routine. It comes from prsubs.json, keyed by the
#   DLL sha256 and produced by findprsub.py, which does not use sample keys.
#   This script refuses to run if the cache does not match the DLL.
#
#   Everything else is hardcoded because it cannot drift with the DLL:
#
#   - op=3 and the WarbirdCallArgs layout are a kernel ABI. The DLL and the
#     running kernel must agree on them, so neither can change unilaterally.
#   - The routine's own argument struct is packed (it reads its output
#     pointer unaligned at +0x14), and packed layout is fixed by source and
#     invariant under recompilation.
#   - size == 0x20 is the P-256 private scalar length, and the routine tests
#     it itself with `cmp dword ptr [rcx+10h], 20h`.
#   - 0x34 is the size of the kernel's call-args struct.
#
#   prsubs.json is read from the CURRENT DIRECTORY, so run this from the same
#   directory findprsub.py was run in.
#
# VERIFICATION
#   The check is cryptographic and needs no secret reference: the plaintext d,
#   read big-endian, must satisfy d*G == Q, where Q is the P-256 public key
#   that 2-extract-keys.py wrote next to the ciphertext. A wrong descriptor, a
#   wrong output offset, a wrong argument layout or a wrong input file cannot
#   produce a scalar whose public point lands on Q. Cost: a few milliseconds.
#
#   This single check subsumes scalar-range validation: a d outside [1, n-1]
#   cannot yield Q, so no separate range test is performed.
#
#   Failure is loud, never silent:
#     wrong desc_va     -> NTSTATUS 0xC0000095 (INTEGER_OVERFLOW)
#     wrong arg layout  -> status dword 0x80070057 (E_INVALIDARG) and an
#                          unwritten output buffer; findprsub.py would also
#                          report zero accepted descriptors
#     output == input   -> descriptor for the wrong routine
#     d*G != sig.pub    -> descriptor, argument layout or input is wrong
# ---------------------------------------------------------------------------

import ctypes, hashlib, json, os, struct, sys

DLL = r"C:\Windows\SYSTEM32\Windows.Media.Protection.PlayReady.dll"

SRC = "extracted.sig.prv"          # written by 2-extract-keys.py
PUB = "extracted.sig.pub"          # written by 2-extract-keys.py
DST = "extracted.sig.plain"        # 32-byte plaintext scalar

# 32 bytes: the P-256 private scalar length, and the size the routine accepts.
KEY_LEN = 0x20

# The routine reads its output pointer from args+0x14 - i.e. struct+0x24,
# because the args it sees begin 0x10 into the kernel's WarbirdCallArgs.
# The read is unaligned, so this value cannot be inferred from alignment.
OUT_OFF = 0x24

# ---- P-256 domain parameters ---------------------------------------------
P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
P256_A = P256_P - 3
P256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
P256_G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
          0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)

USAGE = """\
usage: decrypt.py [--pub PATH]

  (no arguments)      decrypt extracted.sig.prv -> extracted.sig.plain,
                      validating d*G against extracted.sig.pub
  --pub PATH          validate against PATH instead of extracted.sig.pub
  -h, --help          this text
"""


def _buf(data):
    """Fixed-size, NUL-free buffer of exactly len(data) bytes.

    create_string_buffer(data, len(data)) is not usable here: the C-string
    helper wants room for a terminator and raises 'byte string too long'.
    """
    return (ctypes.c_ubyte * len(data)).from_buffer_copy(data)


def _prsubs():
    """Load and validate the build-specific descriptor RVA."""
    with open(DLL, "rb") as f:
        sha = hashlib.sha256(f.read()).hexdigest()

    if not os.path.isfile("prsubs.json"):
        raise SystemExit("no prsubs.json in the current directory - "
                         "run findprsub.py here first")

    with open("prsubs.json") as f:
        rec = json.load(f)

    if rec.get("sha256") != sha:
        raise SystemExit(
            "prsubs.json was built for a different DLL\n"
            f"  cache : {rec.get('sha256', '?')[:16]}...\n"
            f"  actual: {sha[:16]}...\n"
            "  re-run findprsub.py")

    if not rec.get("desc_va"):
        raise SystemExit("cache has no desc_va - re-run findprsub.py")

    return rec


# ---- P-256 arithmetic, for validating the plaintext ----------------------
def _ec_add(p1, p2):
    """Affine point addition on P-256; None is the point at infinity."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % P256_P == 0:
            return None                              # P + (-P), and y == 0
        lam = (3 * x1 * x1 + P256_A) * pow(2 * y1, -1, P256_P) % P256_P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P256_P) % P256_P
    x3 = (lam * lam - x1 - x2) % P256_P
    return x3, (lam * (x1 - x3) - y1) % P256_P


def _ec_mul(k, point):
    """Right-to-left double-and-add; ~384 modular inversions for k < 2^256."""
    acc = None
    while k:
        if k & 1:
            acc = _ec_add(acc, point)
        point = _ec_add(point, point)
        k >>= 1
    return acc


def pubkey_of(d):
    return _ec_mul(d, P256_G)


def parse_pubkey(blob):
    """Decode an uncompressed (65B), raw (64B) or compressed (33B) P-256
    point, and verify that it really lies on the curve."""
    if len(blob) == 65 and blob[0] == 0x04:
        x = int.from_bytes(blob[1:33], "big")
        y = int.from_bytes(blob[33:65], "big")
    elif len(blob) == 64:
        x = int.from_bytes(blob[:32], "big")
        y = int.from_bytes(blob[32:], "big")
    elif len(blob) == 33 and blob[0] in (0x02, 0x03):
        x = int.from_bytes(blob[1:], "big")
        rhs = (pow(x, 3, P256_P) + P256_A * x + P256_B) % P256_P
        y = pow(rhs, (P256_P + 1) // 4, P256_P)      # P == 3 (mod 4)
        if (y & 1) != (blob[0] & 1):
            y = P256_P - y
    else:
        raise ValueError(f"{len(blob)} bytes, prefix {blob[:1].hex()} - "
                         "not a P-256 point encoding")

    if not (0 <= x < P256_P and 0 <= y < P256_P):
        raise ValueError("coordinate outside the field")
    if (y * y - (pow(x, 3, P256_P) + P256_A * x + P256_B)) % P256_P:
        raise ValueError("point is not on the P-256 curve")
    if x == 0 and y == 0:
        raise ValueError("point at infinity")
    return x, y


def decrypt_signing_key(prv_path, out_path=None, _rec=None):
    """Decrypt a 32-byte obfuscated PlayReady signing key.

    prv_path : file holding the 32-byte *.sig.prv component
    out_path : optional path for the 32-byte plaintext key
    returns  : 32-byte plaintext private key
    """
    rec = _rec or _prsubs()

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.LoadLibraryW.restype = ctypes.c_void_p
    base = k32.LoadLibraryW(DLL)
    if not base:
        raise RuntimeError(f"LoadLibraryW({DLL}) failed, err "
                           f"{ctypes.get_last_error()}")

    ntdll = ctypes.WinDLL("ntdll")
    NtQ = ntdll.NtQuerySystemInformation
    NtQ.argtypes = [ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p]
    NtQ.restype = ctypes.c_long

    with open(prv_path, "rb") as f:
        enc = f.read()
    if len(enc) != KEY_LEN:
        raise ValueError(f"{prv_path}: expected {KEY_LEN} bytes, got {len(enc)}")

    # A random fill proves the routine actually wrote to the output buffer;
    # a fixed sentinel could collide with real key material.
    fill = os.urandom(KEY_LEN)
    key_buf = _buf(enc)
    status  = ctypes.create_string_buffer(0x10)        # zero-filled
    out     = _buf(fill)

    # Kernel WarbirdCallArgs for op=3 (WbHeapExecuteCall). The arguments the
    # routine itself sees begin at +0x10, which is why its documented +0x14
    # output field lands at +0x24 here:
    #
    #     +0x00  op = 3
    #     +0x08  descriptor address
    #     +0x10  -> status dword   (routine's +0x00)
    #     +0x18  -> 32-byte key    (routine's +0x08)
    #     +0x20  u32 key size      (routine's +0x10)
    #     +0x24  -> output buffer  (routine's +0x14)
    args = ctypes.create_string_buffer(0x34)
    struct.pack_into("<Q", args, 0x00, 3)
    struct.pack_into("<Q", args, 0x08, base + rec["desc_va"])
    struct.pack_into("<Q", args, 0x10, ctypes.addressof(status))
    struct.pack_into("<Q", args, 0x18, ctypes.addressof(key_buf))
    struct.pack_into("<I", args, 0x20, KEY_LEN)
    struct.pack_into("<Q", args, OUT_OFF, ctypes.addressof(out))

    st = NtQ(0xB9, ctypes.cast(args, ctypes.c_void_p), 0x34, None) & 0xFFFFFFFF
    if st != 0:
        raise RuntimeError(
            f"NtQuerySystemInformation -> {st:#010x}"
            + (" (INTEGER_OVERFLOW: desc_va is wrong for this build)"
               if st == 0xC0000095 else ""))

    status_dword = ctypes.string_at(ctypes.addressof(status), 4)
    if status_dword != b"\0\0\0\0":
        raise RuntimeError(
            f"routine returned {status_dword.hex()} - the argument layout no "
            "longer matches this build; re-run findprsub.py")

    res = ctypes.string_at(ctypes.addressof(out), KEY_LEN)
    if res == fill:
        raise RuntimeError("output buffer untouched - out_off is wrong")
    if res == enc:
        raise RuntimeError("output equals input - desc_va is the wrong routine")

    if out_path:
        with open(out_path, "wb") as f:
            f.write(res)
    return res


def main(argv):
    pub_path = PUB

    # ---- arguments: flags only, nothing positional --------------------
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-h", "--help", "/?"):
            print(USAGE)
            return 0
        name, eq, val = a.partition("=")
        if name == "--pub":
            if not eq:
                i += 1
                if i >= len(argv):
                    raise SystemExit(f"--pub needs a value\n\n{USAGE}")
                val = argv[i]
            pub_path = val
        elif a.startswith("-"):
            raise SystemExit(f"unknown option {a}\n\n{USAGE}")
        else:
            raise SystemExit(f"unexpected argument {a!r}: "
                             f"this script takes options only\n\n{USAGE}")
        i += 1

    if os.name != "nt":
        raise SystemExit("this script drives "
                         "Windows.Media.Protection.PlayReady.dll - Windows only")

    if not os.path.isfile(SRC):
        raise SystemExit(f"missing input: {SRC}\n  run 2-extract-keys.py first")

    if not os.path.isfile(pub_path):
        raise SystemExit(f"missing public key: {pub_path}\n"
                         "  run 2-extract-keys.py first, or pass --pub PATH")

    # ---- decrypt ------------------------------------------------------
    got = decrypt_signing_key(SRC, None)
    print(f"{SRC} ({KEY_LEN} bytes)")
    print(f"plaintext {got.hex()}")

    # ---- validation: d*G must equal the published public key ----------
    with open(pub_path, "rb") as f:
        pub_raw = f.read()
    try:
        want = parse_pubkey(pub_raw)
    except ValueError as e:
        raise SystemExit(f"{pub_path}: {e}")

    if pubkey_of(int.from_bytes(got, "big")) != want:
        raise SystemExit(
            f"d*G != {pub_path} - the plaintext is not the private key for\n"
            "that public key. The descriptor, the argument layout or the\n"
            "input file is wrong. Nothing was written.")
    print(f"[ OK ] d*G == {pub_path}")
    print(f"       Q = ({want[0]:064x},\n"
          f"            {want[1]:064x})")

    # ---- write --------------------------------------------------------
    with open(DST, "wb") as f:
        f.write(got)
    print(f"\nwrote {DST} ({len(got)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
