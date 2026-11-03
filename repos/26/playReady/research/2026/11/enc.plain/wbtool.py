# wbtool.py — scan live mfpmp for the prv buffer and the decrypted 0x2229f0 block
import ctypes, struct, time

k32 = ctypes.WinDLL("kernel32")
k32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
k32.CreateToolhelp32Snapshot.argtypes = [ctypes.c_ulong, ctypes.c_ulong]
k32.Process32First.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
k32.Process32Next.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
k32.OpenProcess.restype = ctypes.c_void_p
k32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
k32.CloseHandle.argtypes = [ctypes.c_void_p]
k32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]

class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", ctypes.c_ulong), ("PartitionId", ctypes.c_ushort),
                ("pad", ctypes.c_ushort), ("RegionSize", ctypes.c_size_t),
                ("State", ctypes.c_ulong), ("Protect", ctypes.c_ulong),
                ("Type", ctypes.c_ulong)]

def pids(name="mfpmp.exe"):
    snap = k32.CreateToolhelp32Snapshot(0x2, 0)
    if not snap or snap == ctypes.c_void_p(-1).value:
        return []
    buf = ctypes.create_string_buffer(0x400)
    struct.pack_into("<I", buf, 0, 0x400)
    out = []
    if k32.Process32First(snap, buf):
        while True:
            pid = struct.unpack_from("<I", buf, 8)[0]
            exe = buf[0x2C:0x2C + 520].decode("utf-16-le", "ignore").split("\x00")[0]
            if exe.lower() == name:
                out.append(pid)
            struct.pack_into("<I", buf, 0, 0x400)
            if not k32.Process32Next(snap, buf):
                break
    k32.CloseHandle(snap)
    return out

def regions(h):
    out, addr, mbi = [], 0, MBI()
    while addr < 0x7FFFFFFF0000:
        if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi),
                                  ctypes.sizeof(MBI)):
            break
        base = mbi.BaseAddress or 0
        if mbi.State == 0x1000 and (mbi.Protect & 0xCC) and 0 < mbi.RegionSize <= 0x4000000:
            out.append((base, mbi.RegionSize))
        nxt = base + mbi.RegionSize
        if nxt <= addr:
            break
        addr = nxt
    return out

def scan(h, needle, regs, limit=3):
    hits = []
    for base, size in regs:
        buf = ctypes.create_string_buffer(size)
        got = ctypes.c_size_t(0)
        if not k32.ReadProcessMemory(h, ctypes.c_void_p(base), buf, size, ctypes.byref(got)):
            continue
        data = buf.raw[:got.value]
        i = data.find(needle)
        while i != -1 and len(hits) < limit:
            hits.append((base + i, data[max(0, i - 0x20):i + 0x60]))
            i = data.find(needle, i + 1)
        if len(hits) >= limit:
            break
    return hits

prv = open("extracted.enc.prv", "rb").read()
needles = [("prv16", prv[:16]),
           ("block2229f0", bytes.fromhex("41bab9000000488d558f41b830000000"))]

seen = set()
t0 = time.time()
print("polling; start playback now", flush=True)
while time.time() - t0 < 90:
    found = pids()
    for pid in found:
        if pid in seen:
            continue
        seen.add(pid)
        h = k32.OpenProcess(0x0410, 0, pid)
        if not h:
            print(f"pid {pid}: open failed", flush=True)
            continue
        print(f"=== pid {pid}", flush=True)
        regs = regions(h)
        print(f"  regions {len(regs)}", flush=True)
        for name, needle in needles:
            hits = scan(h, needle, regs)
            print(f"  {name}: {len(hits)} hit(s)", flush=True)
            for addr, ctx in hits:
                print(f"    @0x{addr:x} {ctx.hex()}", flush=True)
        k32.CloseHandle(h)
    time.sleep(0.4)
print("done")
