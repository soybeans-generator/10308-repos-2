# PlayReady Activation — Working Notes

Scope: only what the final implementation depends on. Private material is attributed to an
anonymous source and paraphrased, not reproduced. Our own findings are stated directly. Adam
Gowdiak's Warbird/PMP research is public, cited only where it corroborates — the system-ID
structure format, the `PRKF`/`CHAI` container layout, and that the activation service does not
validate HWID authenticity.

## Usage

`wbcall.py` and `tool.py` in one directory:

```powershell
python tool.py --hwid "MY.ID.TEXT"
python tool.py --decrypt
```

The first builds a 49-byte nonce from that HWID, has the library's builder produce the payload,
posts the challenge, writes `testdata\payload.bin` + `testdata\response.bin`. The second
decrypts that response using the payload's seed, writes `testdata\msprcore.bla` (the `prkf`
tool's `corePath`). `testdata\tool-state.json` holds the census and discovered RVAs. No
captured file, no hardcoded address.

## From an anonymous source (private)

- **Stateless per request**: a static blob plus the device HWID, AES-CTR keyed from a seed
  stored in the clear in the last 16 bytes.
- **The response reuses the request's key** — what makes the seed the decrypt key.
- **Three call blocks**: HWID retrieval (skippable), payload build, response decrypt, with
  their field orders and the decryptor's `output_len = len(response) - 8`.
- **`input_size = len(hwid) + 2252`** — the only invariant for identifying the builder.
- **The SOAP envelope and endpoint**, including `activation2` as the host the client uses.
- **Two operating conditions**: decrypt the non-Warbird sections first, initialise `ole32`.

Not used: the higher-level wrappers, and the base64-to-XML wrapping advice.

## Our own findings (not public)

### Nonce layout

```
01 | FILETIME(8) | 28 | 27 constant bytes | 12-byte HWID tail
```

- 49 bytes; `2301 - 2252 = 49`.
- Byte `+0` is **`0x01`**, not `0x30` — the public structure starts with total-minus-one, and
  every shape built that way was rejected; this byte blocked eleven candidates. `+9` is the
  inner length `0x28` = 1 + 27 + 12. The 27 middle bytes are constant across captures.
- **The 12-byte tail is free**: any bytes, including ASCII, are accepted — what makes a custom
  HWID possible. Three payloads differing only there all returned `ACCEPTED`.

### Builder

Identified by invariants, not address: output length `input + 2252` and the constant 20-byte
prologue `010000000c1bfa0084723e622f607a2c5e80f5f7` shared with the real client.
**Re-randomises its whole body every call** — two calls with identical identity and input
differ in all 2252 body bytes. No search, replay, or offline input recovery is possible; the
seed is generated, not read.

### Decryptor

`input = whole response`, `input_len = len`, `output_len = len - 8`: 5117 bytes of `PRKF` from
a 5125-byte response, feeding the existing `prkf` tool unmodified (`CHAI` at 749).

### Three Warbird prerequisites

Each silently produced wrong results when missing:

- **op=1 segment pass first.** A fresh `LoadLibraryW` leaves segment-encrypted `.rdata`/`.data`
  as ciphertext and routines read them, so a cold call returns a DRM error that looks like
  "wrong routine". All 37 segment descriptors must be decrypted before any op=3 call.
- **`CoInitializeEx(COINIT_MULTITHREADED)` before `LoadLibrary`** — without an apartment the
  library returns success but not usable output.
- **`rcx`-relative argument serialisation**: `rcx` points at `block + 0x10`, pointer fields are
  unaligned (`+0x14`, `+0x24`), so naturally-aligned structs misplace them.

### Locating a routine without its layout

Every heap-exec is `op = 3`, so one run holds hundreds of different subroutines; guessing two
layouts found one buffer in 714 calls. But **`block + 0x08` is the descriptor address**, naming
the routine regardless of layout, and subtracting census VAs from observed descriptors recovers
the module base exactly with no PEB walk. That is what made the nonce visible.

### Identity is per-build

Types 0, 1, 2 of the HWID routine return **three different 32-byte values** — none 49 bytes, so
the nonce is not a padded one of these. Descriptor RVAs move every build; discovery by property
costs ~10–40 s and is cached by SHA-256. Hardcoding was wrong.

### Negative results, so they are not retried

- **Version is not validated**: one captured payload accepted at `clientSdkVersion` 4.3.0.0 and
  4.6.0.0; fifteen versions against a built payload all failed.
- **Offline AES-CTR with the seed as key fails** across seven derivations (raw, as IV, MD5,
  SHA-256, counter offset) — the seed is not the key alone.
- **The identity is not recoverable by search** (see Builder).

### Method notes

One DLL load per chunk, results streamed per call so a fault costs one entry, binary-split
recovery rather than one-descriptor-at-a-time: the sweep went from timing out at 1744/3924 to
completing in 74 s. And a sweep reporting `probed 0/N` is a script bug, not a verdict — three
batching faults hid real results this way, each printing as a confident negative.
