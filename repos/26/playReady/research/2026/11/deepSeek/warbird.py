# warbird.py
"""warbird.py -- Warbird syscalls.

op=1, 0x30 bytes: op, descriptor, image, image, image+relocs, count
op=3, WbHeapExecuteCall, 0x34 get-HWID / 0x44 payload / 0x3C decrypt.
status is 0x10 bytes: at 4 the process dies on the NEXT call. E_INVALIDARG in
status with NTSTATUS 0 is a refusal by a live process, not a fault.
"""
import ctypes
import os
import struct

if os.name != "nt" or ctypes.sizeof(ctypes.c_void_p) != 8:
    raise SystemExit("warbird.py: Windows x64 only")

DLL = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32",
                   "Windows.Media.Protection.PlayReady.dll")
ST = 0x10
STATIC = 2252


def g32(b):
    return struct.unpack_from("<I", bytes(b), 0)[0]


def die(m):
    raise SystemExit("[-] " + m)


def _buf(n, data=b""):
    a = (ctypes.c_ubyte * n)()
    if data:
        ctypes.memmove(a, data, min(len(data), n))
    return a


def _u32(v):
    a = (ctypes.c_ubyte * ST)()
    struct.pack_into("<I", a, 0, v)
    return a


_k = ctypes.WinDLL("kernel32", use_last_error=True)
_k.LoadLibraryW.restype = ctypes.c_void_p
_k.LoadLibraryW.argtypes = [ctypes.c_wchar_p]
_k.FreeLibrary.restype = ctypes.c_int
_k.FreeLibrary.argtypes = [ctypes.c_void_p]
_k.VirtualProtect.restype = ctypes.c_int
_k.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32,
                              ctypes.POINTER(ctypes.c_uint32)]


def base():
    b = _k.LoadLibraryW(DLL)
    if not b:
        raise OSError("LoadLibraryW %s: %d" % (DLL, ctypes.get_last_error()))
    return b


def free(b):
    _k.FreeLibrary(ctypes.c_void_p(b))


def vp(addr, n, prot):
    old = ctypes.c_uint32()
    if not _k.VirtualProtect(ctypes.c_void_p(addr), n, prot, ctypes.byref(old)):
        return None
    return old.value


_nt = ctypes.WinDLL("ntdll").NtQuerySystemInformation
_nt.restype = ctypes.c_long
_nt.argtypes = [ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p]


def wb(a, n):
    return _nt(0xB9, ctypes.byref(a), n, None) & 0xFFFFFFFF


def di_call(b, sac, rel, num):
    a = (ctypes.c_ubyte * 0x30)()
    struct.pack_into("<6Q", a, 0, 1, sac, b, b, b + rel, num)
    return wb(a, 0x30)


class Hwid(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("op", ctypes.c_uint64), ("seg", ctypes.c_void_p),
                ("status", ctypes.c_void_p), ("ctx", ctypes.c_void_p),
                ("type", ctypes.c_uint32), ("out", ctypes.c_void_p),
                ("out_len", ctypes.c_void_p)]


class Payload(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("op", ctypes.c_uint64), ("seg", ctypes.c_void_p),
                ("status", ctypes.c_void_p), ("nonce", ctypes.c_void_p),
                ("in_len", ctypes.c_uint32), ("inp", ctypes.c_void_p),
                ("out_len", ctypes.c_void_p), ("out", ctypes.c_void_p),
                ("ver", ctypes.c_void_p)]


class Decrypt(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("op", ctypes.c_uint64), ("seg", ctypes.c_void_p),
                ("status", ctypes.c_void_p), ("inp", ctypes.c_void_p),
                ("in_len", ctypes.c_uint32), ("seed", ctypes.c_void_p),
                ("out", ctypes.c_void_p), ("out_len", ctypes.c_void_p)]


def call_hwid(b, d):
    st, ctx = _buf(ST), _buf(0x100)
    n, out = _u32(512), _buf(512)
    nt = wb(Hwid(3, b + d, ctypes.addressof(st), ctypes.addressof(ctx), 1,
                 ctypes.addressof(out), ctypes.addressof(n)), 0x34)
    m = min(g32(n), 512)
    return nt, g32(st), bytes(out[:m]), m


def _payload(b, d, hwid, mode):
    sz = len(hwid) + STATIC
    st, nonce = _buf(ST), _buf(len(hwid), hwid)
    inp, out = _buf(sz, hwid), _buf(sz)
    n, ver = _u32(sz), _buf(ST)
    nt = wb(Payload(3, b + d, ctypes.addressof(st), ctypes.addressof(nonce),
                    sz if mode else len(hwid), ctypes.addressof(inp),
                    ctypes.addressof(n), ctypes.addressof(out),
                    ctypes.addressof(ver)), 0x44)
    return nt, g32(st), bytes(inp), bytes(out), g32(n)


def payload(b, d, hwid):
    """(bytes, src, n, moved, why); bytes is None when no shape worked.

    mode 0 passes len(hwid) as in_len, as Googler's block does; mode 1 passes the
    whole buffer. The payload may land in the input buffer or the output buffer,
    so both are compared against what they held before the call.
    """
    sz, why = len(hwid) + STATIC, "no shape tried"
    for m in (0, 1):
        nt, st, inp, out, n = _payload(b, d, hwid, m)
        if nt or st:
            why = "mode %d: nt=%#x st=%#x" % (m, nt, st)
            continue
        if not 16 <= n <= sz:
            why = "mode %d: n=%d outside 16..%d" % (m, n, sz)
            continue
        z = _payload(b, d, hwid, m)
        moved = not (z[0] or z[1]) and z[4] == n and (
            inp[:n][-16:] != z[2][:n][-16:] or out[:n][-16:] != z[3][:n][-16:])
        for tag, got, was in (("in", inp, _buf(sz, hwid)), ("out", out, _buf(sz))):
            if got[:n] != was[:n]:
                return got[:n], tag, n, moved, ""
        why = "mode %d: n=%d, neither buffer changed" % (m, n)
    return None, "-", 0, False, why


def call_decrypt(b, d, resp, seed):
    sz = len(resp)
    st, inp = _buf(ST), _buf(sz, resp)
    key, out = _buf(16, seed), _buf(sz)
    n = _u32(max(sz - 8, 0))
    nt = wb(Decrypt(3, b + d, ctypes.addressof(st), ctypes.addressof(inp), sz,
                    ctypes.addressof(key), ctypes.addressof(out),
                    ctypes.addressof(n)), 0x3C)
    m = g32(n)
    return nt, g32(st), bytes(out[:m]) if 0 <= m <= sz else b"", m
# warbird.py
