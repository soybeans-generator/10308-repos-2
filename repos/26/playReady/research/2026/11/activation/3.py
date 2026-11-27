class WarbirdRequest(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("operation", ULONG64),
        ("segment", PVOID),
        ("status", PVOID),
        ("input", ctypes.c_void_p),
        ("input_len", ctypes.c_uint32),
        ("seed", ctypes.c_void_p),
        ("output", ctypes.c_void_p),
        ("output_len", ctypes.c_void_p),
    ]


def call_heap_exec(offset: int, dll: int, response: bytes, key: bytes):
    offset = dll + offset
    seg_ptr = ctypes.cast(offset, PVOID)

    status_obj = ctypes.c_uint32(0)
    status_ptr = ctypes.addressof(status_obj)

    input_len = len(response)
    input_obj = (ctypes.c_ubyte * input_len)(*response)

    decrypted_output_size = len(response) - 8

    decryption_key = (ctypes.c_ubyte * 16)(*key)

    output_size_val = ctypes.c_uint32(decrypted_output_size)
    output_size_ptr = ctypes.cast(ctypes.addressof(output_size_val), ctypes.c_void_p)

    decrypted_output_obj = (ctypes.c_ubyte * input_len)(*bytes(decrypted_output_size))
    output_ptr = ctypes.cast(ctypes.addressof(decrypted_output_obj), ctypes.c_void_p)

    request = WarbirdRequest()
    request.operation = 3
    request.segment = seg_ptr
    request.status = status_ptr
    request.input = ctypes.addressof(input_obj)
    request.input_len = input_len
    request.seed = ctypes.addressof(decryption_key)
    request.output = output_ptr
    request.output_len = output_size_ptr

    nt_status = NtQuerySystemInformation(
        ULONG(SystemControlFlowTransition), ctypes.byref(request), ULONG(ctypes.sizeof(request)), None
    )

    if nt_status != 0:
        name = NTSTATUS_MAP.get(nt_status, "UNKNOWN")
        raise Exception(f"[-] Syscall failed: {name} (0x{nt_status:X})")

    return ctypes.string_at(output_ptr, input_len)
