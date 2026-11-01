# locate the signing-key routine's descriptor for this DLL build.
#
# This script does NOT use sample key files. Discovery rests entirely on
# properties of the routine itself, read from its disassembly:
#
#   1. accepts exactly 0x20 bytes and succeeds
#        (the routine begins: cmp dword ptr [rcx+10h], 20h)
#   2. writes its output buffer
#        (it copies the input there, then transforms in place)
#   3. different input -> different output
#        (a key transform cannot ignore its input)
#   4. REJECTS a size other than 0x20
#        (property 1's converse; no generic routine enforces this)
#
# IMPORTANT: rejection is reported in the STATUS DWORD, not in NTSTATUS.
# The routine writes 0x80070057 (E_INVALIDARG) to the status pointer and
# returns normally, so NtQuerySystemInformation still returns 0. A check
# written as "NTSTATUS != 0" will never fire.
#
# Property 4 is the discriminating one - it collapses the large set of
# descriptors that merely return success. Verification against a real key is
# decrypt.py's job, not this script's.
#
# The ONLY value that differs between DLL builds is the RVA of the heap
# descriptor holding the routine.
#
# A result of ZERO accepted descriptors, or more than one, is an error to
# investigate - there is no fallback path.
#
# Outputs, in the CURRENT DIRECTORY:
#   prsubs.json     build-specific values, keyed by the DLL sha256
#   findprsub.txt   per-descriptor probe results, for diagnosing a failure

import ctypes, hashlib, json, os, struct, subprocess, sys

DLL = r"C:\Windows\SYSTEM32\Windows.Media.Protection.PlayReady.dll"

# 32 bytes: the P-256 private scalar length, the size this routine accepts,
# and the size it tests for itself with `cmp dword ptr [rcx+10h], 20h`.
KEY_LEN = 0x20

# The routine reads its output pointer from args+0x14 - i.e. struct+0x24,
# because the args it sees begin 0x10 into the kernel's WarbirdCallArgs.
# The read is unaligned, so this value cannot be inferred from alignment.
OUT_OFF = 0x24

# Size of one Warbird heap-exec descriptor, including its 32-byte digest.
# The descriptor's own size field holds this same value, which is what makes
# it usable as a signature.
DESC_TOTAL = 0xF0


def pe_sections(d):
    e = struct.unpack_from("<I", d, 0x3C)[0]
    coff = e + 4
    nsec, = struct.unpack_from("<H", d, coff + 2)
    optsz, = struct.unpack_from("<H", d, coff + 16)
    p, out = coff + 20 + optsz, []
    for _ in range(nsec):
        name = d[p:p + 8].rstrip(b"\0").decode("latin1")
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", d, p + 8)
        out.append((name, vaddr, vsize, rawptr, rawsize))
        p += 40
    return out


def section_ranges(secs):
    return [(va, va + max(vs, rs)) for nm, va, vs, rp, rs in secs]


def inside(rva, length, ranges):
    end = rva + length
    return any(lo <= rva and end <= hi for lo, hi in ranges)


def heap_descs(d, ranges):
    """Collect digest-validated Warbird heap-exec descriptors.

    Descriptor layout, relative to its base:
        +0x00  32-byte SHA-256 over [0x20, 0xF0)
        +0x20  u32 total size (0xF0)
        +0x24  u32 v1 marker (0xFFFFFF00)
        +0x28  u32 desc_va
        +0x34  u32 encr_va   (0xF0000000 | code_rva)
        +0x38  u32 size      (0xF0000000 | code_len)

    Only descriptors whose code segment lies entirely inside a mapped section
    are returned, as sorted [(desc_va, code_rva, code_len)].
    """
    found = set()
    for _name, _vaddr, _vsize, rawptr, rawsize in pe_sections(d):
        if rawsize < DESC_TOTAL:
            continue
        blob = d[rawptr:rawptr + rawsize]
        for off in range(0, len(blob) - DESC_TOTAL + 1, 4):
            if struct.unpack_from("<I", blob, off + 0x20)[0] != DESC_TOTAL:
                continue
            if struct.unpack_from("<I", blob, off + 0x24)[0] != 0xFFFFFF00:
                continue
            body = blob[off + 0x20:off + DESC_TOTAL]
            if hashlib.sha256(body).digest() != blob[off:off + 0x20]:
                continue
            desc_va = struct.unpack_from("<I", blob, off + 0x28)[0]
            encr_va = struct.unpack_from("<I", blob, off + 0x34)[0]
            code_sz = struct.unpack_from("<I", blob, off + 0x38)[0]
            # top nibble of both fields is a flag; the rest is an RVA
            code_rva = encr_va & 0x0FFFFFFF
            code_len = code_sz & 0x0FFFFFFF
            if code_len and inside(code_rva, code_len, ranges):
                found.add((desc_va & 0x0FFFFFFF, code_rva, code_len))
    return sorted(found, key=lambda x: x[1])


# ---------------- worker: run the probes on one descriptor ----------------
if len(sys.argv) >= 3 and sys.argv[1] == "--one":
    dv = int(sys.argv[2], 0)

    # Two distinct 32-byte inputs: the routine must map them to distinct
    # outputs, which is what distinguishes a transform from a copy.
    INPUT_A = bytes(range(0x00, 0x20))
    INPUT_B = bytes(range(0x20, 0x40))

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.LoadLibraryW.restype = ctypes.c_void_p
    base = k32.LoadLibraryW(DLL)
    ntdll = ctypes.WinDLL("ntdll")
    NtQ = ntdll.NtQuerySystemInformation
    NtQ.argtypes = [ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p]
    NtQ.restype = ctypes.c_long

    results = {}
    current = [0]

    def saw_success(entry):
        """Success is NTSTATUS 0 AND a zero status dword - not NTSTATUS alone."""
        st, sv, _out, _fill = entry
        return st == 0 and sv == b"\0\0\0\0"

    def emit(tag):
        a, b, c = results.get("A"), results.get("B"), results.get("C")
        if not (a and b and c):
            print(f"RESULT {dv:#x} REJECT {tag} (probe {current[0]})")
            sys.stdout.flush()
            os._exit(0)

        st1, sv1, out1, fill1 = a
        st2, sv2, out2, fill2 = b

        ok_accept  = saw_success(a) and out1 != fill1 and out1 != INPUT_A
        ok_accept2 = saw_success(b) and out2 != fill2 and out2 != INPUT_B
        ok_input   = out1 != out2
        ok_reject  = not saw_success(c)

        verdict = "ACCEPT" if (ok_accept and ok_accept2 and ok_input
                               and ok_reject) else "REJECT"
        print(f"RESULT {dv:#x} {verdict} "
              f"A(st={st1:#010x},sv={sv1.hex()}) "
              f"B(st={st2:#010x},sv={sv2.hex()}) "
              f"C(st={c[0]:#010x},sv={c[1].hex()}) "
              f"input_dep={ok_input} size_enforced={ok_reject} "
              f"out={out1.hex()}")
        sys.stdout.flush()
        os._exit(0)

    VEH = ctypes.CFUNCTYPE(ctypes.c_long, ctypes.c_void_p)

    def onexc(i):
        emit("FAULT")

    _v = VEH(onexc)
    k32.AddVectoredExceptionHandler(1, _v)

    def probe(tag, data, size):
        """Perform one WB heap-exec call.

        Arg block for the kernel's WarbirdCallArgs with op=3. The arguments
        the routine itself sees begin at +0x10, which is why the routine's
        documented +0x14 output field lands at +0x24 here:

            +0x00  op = 3 (WbHeapExecuteCall)
            +0x08  descriptor address
            +0x10  -> status dword
            +0x18  -> 32-byte key
            +0x20  u32 key size
            +0x24  -> output buffer
        """
        current[0] = tag
        fill = os.urandom(KEY_LEN)
        key_buf = ctypes.create_string_buffer(data, KEY_LEN)
        status  = ctypes.create_string_buffer(0x10)
        out     = ctypes.create_string_buffer(fill, KEY_LEN)

        args = ctypes.create_string_buffer(0x34)
        struct.pack_into("<Q", args, 0x00, 3)
        struct.pack_into("<Q", args, 0x08, base + dv)
        struct.pack_into("<Q", args, 0x10, ctypes.addressof(status))
        struct.pack_into("<Q", args, 0x18, ctypes.addressof(key_buf))
        struct.pack_into("<I", args, 0x20, size)
        struct.pack_into("<Q", args, OUT_OFF, ctypes.addressof(out))

        st = NtQ(0xB9, ctypes.cast(args, ctypes.c_void_p), 0x34, None) & 0xFFFFFFFF
        results[tag] = (st,
                        ctypes.string_at(ctypes.addressof(status), 4),
                        ctypes.string_at(ctypes.addressof(out), KEY_LEN),
                        fill)

    probe("A", INPUT_A, KEY_LEN)
    probe("B", INPUT_B, KEY_LEN)
    probe("C", INPUT_A, 0x1F)      # one byte short - must be rejected
    emit("OK")


# ---------------- driver ----------------
d    = open(DLL, "rb").read()
sha  = hashlib.sha256(d).hexdigest()
rngs = section_ranges(pe_sections(d))

log = open("findprsub.txt", "w", encoding="utf-8")

def w(s=""):
    log.write(str(s) + "\n")
    log.flush()

w(f"dll    {DLL}")
w(f"sha256 {sha}")
w(f"size   {len(d):,}")
w("")

descs = heap_descs(d, rngs)
w(f"heap descriptors: {len(descs)}")
print(f"heap descriptors: {len(descs)}", flush=True)

script = os.path.abspath(__file__)
acc, n = [], 0

for dv, cv, ln in descs:
    n += 1
    try:
        r = subprocess.run([sys.executable, script, "--one", hex(dv)],
                           capture_output=True, text=True, timeout=40)
        line = next((l for l in (r.stdout or "").splitlines()
                     if l.startswith("RESULT")), None)
    except subprocess.TimeoutExpired:
        line = None
    # every probe result goes to the log so a zero-accept run is diagnosable
    w(line or f"RESULT {dv:#x} NO_OUTPUT")
    if line and " ACCEPT " in line:
        acc.append((dv, cv, ln))
        print("ACCEPT " + line, flush=True)
    if n % 100 == 0:
        print(f"  {n}/{len(descs)}  accepted={len(acc)}", flush=True)

w("")
w(f"accepted: {len(acc)}")
for dv, cv, ln in acc:
    w(f"  desc {dv:#09x} code {cv:#09x}+{ln:#07x}")

if not acc:
    log.close()
    raise SystemExit(
        "no descriptor satisfied the signing-key routine's properties.\n"
        "  See the per-descriptor probe results in findprsub.txt\n"
        "  Either the hardcoded argument layout no longer matches this build,\n"
        "  or this library does not contain the routine.")

if len(acc) > 1:
    log.close()
    raise SystemExit(
        f"{len(acc)} descriptors satisfied every property - genuinely "
        "ambiguous; investigate before trusting either.")

dv, cv, ln = acc[0]
rec = {"sha256": sha, "dll_size": len(d),
       "desc_va": dv, "code_rva": cv, "seg_len": ln}

with open("prsubs.json", "w") as f:
    json.dump(rec, f, indent=2)

w("")
w(f"cache: {json.dumps(rec)}")
log.close()
print("written findprsub.txt")
print(f"cache: {json.dumps(rec)}")
