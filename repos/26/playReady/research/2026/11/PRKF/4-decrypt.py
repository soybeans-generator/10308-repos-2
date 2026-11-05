# ---------------------------------------------------------------------------
# decrypt a PlayReady signing key (extracted.sig.prv -> extracted.sig.plain)
#
# USAGE
#   decrypt.py                      decrypt extracted.sig.prv -> extracted.sig.plain
#   decrypt.py --known-good PATH    same, but first compare the plaintext with
#                                   PATH; a mismatch aborts before any write
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
#   Failure is loud, never silent:
#     wrong desc_va     -> NTSTATUS 0xC0000095 (INTEGER_OVERFLOW)
#     wrong arg layout  -> status dword 0x80070057 (E_INVALIDARG) and an
#                          unwritten output buffer; findprsub.py would also
#                          report zero accepted descriptors
#     output == input   -> descriptor for the wrong routine
#     scalar out of range -> plaintext is not a P-256 private key
# ---------------------------------------------------------------------------

import ctypes, hashlib, json, os, struct, sys

DLL = r"C:\Windows\SYSTEM32\Windows.Media.Protection.PlayReady.dll"

SRC = "extracted.sig.prv"          # written by 2-extract-keys.py
DST = "extracted.sig.plain"        # 32-byte plaintext scalar

# 32 bytes: the P-256 private scalar length, and the size the routine accepts.
KEY_LEN = 0x20

# The routine reads its output pointer from args+0x14 - i.e. struct+0x24,
# because the args it sees begin 0x10 into the kernel's WarbirdCallArgs.
# The read is unaligned, so this value cannot be inferred from alignment.
OUT_OFF = 0x24

# Order of the P-256 group. A P-256 private scalar must be in [1, n-1];
# anything else proves we ran the wrong routine, at zero cost.
P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

USAGE = """\
usage: decrypt.py [--known-good PATH]

  (no arguments)    decrypt extracted.sig.prv -> extracted.sig.plain
  --known-good PATH compare the plaintext with PATH; a mismatch aborts
                    before anything is written
  -h, --help        this text
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
    known_good = None

    # ---- arguments: flags only, nothing positional --------------------
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-h", "--help", "/?"):
            print(USAGE)
            return 0
        name, eq, val = a.partition("=")
        if name == "--known-good":
            if not eq:
                i += 1
                if i >= len(argv):
                    raise SystemExit(f"--known-good needs a value\n\n{USAGE}")
                val = argv[i]
            known_good = val
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

    if known_good is not None and not os.path.isfile(known_good):
        raise SystemExit(f"known-good file not found: {known_good}")

    # ---- decrypt ------------------------------------------------------
    got = decrypt_signing_key(SRC, None)
    print(f"{SRC} ({KEY_LEN} bytes)")
    print(f"plaintext {got.hex()}")

    # ---- sanity: a real decrypt must land in the P-256 scalar range ----
    if not 0 < int.from_bytes(got, "big") < P256_N:
        raise SystemExit("plaintext is not a valid P-256 private scalar - "
                         "descriptor or argument layout is wrong")
    print("[ OK ] plaintext is in range for a P-256 private scalar")

    # ---- comparison against a user-supplied known good ----------------
    if known_good is None:
        print("[ n/a] no --known-good given, comparison skipped")
    else:
        with open(known_good, "rb") as f:
            want = f.read()
        if want == got:
            print(f"[ OK ] == {known_good}")
        else:
            n = min(len(got), len(want))
            d = next((j for j in range(n) if got[j] != want[j]), None)
            print(f"[FAIL] != {known_good}")
            if d is not None:
                print(f"       first difference at offset {d:#x}")
                print(f"       got : {got[max(d-8, 0):d+8].hex(' ')}")
                print(f"       want: {want[max(d-8, 0):d+8].hex(' ')}")
            else:
                print(f"       common prefix identical over {n} bytes "
                      f"(lengths {len(got)} vs {len(want)})")
            raise SystemExit("not writing output - the plaintext does not "
                             "match the known good")

    # ---- write --------------------------------------------------------
    with open(DST, "wb") as f:
        f.write(got)
    print(f"\nwrote {DST} ({len(got)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
