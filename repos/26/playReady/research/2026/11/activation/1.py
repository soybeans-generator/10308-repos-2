class WarbirdRequest(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("operation", ULONG64),
        ("segment", PVOID),
        ("status", PVOID),
        ("oem_context", ctypes.c_void_p),
        ("type", ctypes.c_uint32),
        ("output", ctypes.c_void_p),
        ("output_len", ctypes.c_void_p),
    ]


def untag(v: int) -> int:
    return v & 0x0FFFFFFF if (v & 0xF0000000) == 0xF0000000 else v


def call_heap_exec(offset: int, dll: int):
    offset = dll + offset
    seg_ptr = ctypes.cast(offset, PVOID)

    status_obj = ctypes.c_uint32(0)
    status_ptr = ctypes.addressof(status_obj)

    size_val = ctypes.c_uint32(512)
    size_ptr = ctypes.c_void_p(ctypes.addressof(size_val))

    output = (ctypes.c_ubyte * 512)()
    output_ptr = ctypes.c_void_p(ctypes.addressof(output))

    request = WarbirdRequest()
    request.operation = 3
    request.segment = seg_ptr
    request.status = status_ptr
    request.oem_context = None
    request.type = 1
    request.output = output_ptr
    request.output_len = size_ptr

    nt_status = NtQuerySystemInformation(
        ULONG(SystemControlFlowTransition), ctypes.byref(request), ULONG(ctypes.sizeof(request)), None
    )

    if nt_status != 0:
        name = NTSTATUS_MAP.get(nt_status, "UNKNOWN")
        raise Exception(f"[-] Syscall failed: {name} (0x{nt_status:X})")

    return ctypes.string_at(output_ptr, size_val.value)
