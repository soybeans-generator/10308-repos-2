class WarbirdRequest(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("operation", ULONG64),
        ("segment", PVOID),
        ("status", PVOID),
        ("nonce", ctypes.c_void_p),
        ("input_len", ctypes.c_uint32),
        ("input", ctypes.c_void_p),
        ("output_len", ctypes.c_void_p),
        ("output", ctypes.c_void_p),
        ("version", ctypes.c_void_p),
    ]


def call_heap_exec(offset: int, dll: int, hwid: bytes) -> bytes:
    offset = dll + offset
    seg_ptr = ctypes.cast(offset, PVOID)

    status_obj = ctypes.c_uint32(0)
    status_ptr = ctypes.addressof(status_obj)

    input_size_val = len(hwid) + 2252
    input_data = (ctypes.c_ubyte * input_size_val)(*hwid)

    output_obj = (ctypes.c_ubyte * input_size_val)(*bytes(input_size_val))
    output_len_obj = ctypes.c_uint32(input_size_val)

    nonce_obj = (ctypes.c_ubyte * len(hwid))(*hwid)

    ver_val = ctypes.c_uint32(0)

    first_request_obj = ctypes.string_at(addressof(input_data), output_len_obj.value)
    first_request_ptr = (ctypes.c_ubyte * input_size_val)(*first_request_obj)

    request = WarbirdRequest()
    request.operation = 3
    request.segment = seg_ptr
    request.status = status_ptr
    request.nonce = addressof(nonce_obj)
    request.input_len = len(hwid)
    request.input = addressof(first_request_ptr)
    request.output_len = addressof(output_len_obj)
    request.output = addressof(output_obj)
    request.version = addressof(ver_val)

    nt_status = NtQuerySystemInformation(
        ULONG(SystemControlFlowTransition), ctypes.byref(request), ULONG(ctypes.sizeof(request)), None
    )

    if nt_status != 0:
        name = NTSTATUS_MAP.get(nt_status, "UNKNOWN")
        raise Exception(f"[-] Syscall failed: {name} (0x{nt_status:X})")

    return ctypes.string_at(request.input, output_len_obj.value)
