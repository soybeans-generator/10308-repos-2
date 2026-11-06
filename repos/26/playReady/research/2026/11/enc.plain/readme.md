# Warbird / PlayReady — Findings Beyond the Original Document

Anything in here was established empirically during this work. It is either (a) absent from the published technical document, or (b) present there but for a *different* library build, so the values had to be re-derived.

Save as `FINDINGS.md`.

---

## 1. Provenance

| item | value |
|---|---|
| Target library | `C:\Windows\System32\Windows.Media.Protection.PlayReady.dll` |
| Version | `10.0.19041.4780` (WinBuild.160101.0800) |
| SHA-256 | `3cc6724d105e94bb0fb5971cc07ab2967dde2290ecebf4e0d4a910c80732ba7a` |
| Size / SizeOfImage | 10,348,448 bytes / `0x9d4000` |
| Decrypted image size | 10,305,536 bytes |
| Certificate | Microsoft Windows, valid 2022-09-03 → 2025-09-02 |

The document's reference build is a W10 22H2 Oct-2024 DLL (and a W11 Oct-24 variant). Ours is the Win10 2004/20H2 family, so **every RVA in the document drifts** and every per-build constant had to be re-derived.

## 2. Warbird descriptor format (established empirically)

A descriptor is a **0x20-byte SHA-256 followed by a body**. The digest covers `[0x20, size)` where `size` is the dword at `+0x20`. This makes descriptor discovery fully offline and self-validating — no external tool needed.

| offset | field |
|---|---|
| `+0x00` | SHA-256 over `[0x20, size)` |
| `+0x20` | u32 total descriptor size |
| `+0x24` | `0xFFFFFF00` marker (heap-exec only) |
| `+0x28` | descriptor RVA |
| `+0x2C` | relocations RVA |
| `0x30` | relocation entry count |
| `+0x34` | `0xF0000000 \| code_rva` (heap-exec) |
| `+0x38` | `0xF0000000 \| code_len` (heap-exec) |
| `+0xF4` | segment entry list start, 12-byte stride |

**Segment entry entries are `{flags, rva, size}` — flags first**, rva at `+4`, size at `+8`. This ordering is a common trap; reading rva from `+0` yields `0x30C` for every entry.

Two descriptor kinds on this build:

| kind | size field | count | block size |
|---|---|---|---|
| segment (`?g_Encry`) | `0x100`, `0x10C`, `0x7C0`, `0x7C4`, `0xc4a8`, `0x829c`, `0x3cac`, … | 37 | lists many RVA spans |
| heap-exec | `0xF0` | 981 | one code block each |

Total: **1018 descriptors, 8946 decryptable blocks (7965 segment spans + 981 heap-exec)**.

> **Caveat on the span count.** Measured on this build: **7947** spans without RVA dedup, and **7947** with it — no duplicate RVAs exist here, so dedup is inert. An earlier note in `2-decrypt-img.py`'s header quotes `7818` (deduped) vs `7937` (not deduped); those figures do not reproduce and should not be quoted unless re-measured on a build where duplicates actually exist. Because dedup can only lose spans and can never add them, discovery code should default to **no dedup**, matching the documented per-descriptor rule.

**Size cap must be `0x200000`.** The two largest descriptors are `0x829c` and `0x3cac`; a `0x2000` cap silently skips them, losing the `0x334290`–`0x3370ef` gap blocks (including `0x335460`) and causing the stage routines to execute ciphertext.

## 3. Warbird kernel ABI (`NtQuerySystemInformation`, class `0xB9`)

### Argument block

| off | value |
|---|---|
| `+0x00` | op |
| `+0x08` | descriptor address (absolute) |
| `+0x10` | image base |
| `+0x18` | image base |
| `+0x20` | relocations address |
| `+0x28` | relocation count |
| length | `0x30` |

### Op codes observed

| op | meaning |
|---|---|
| `1` | segment decrypt (`WbSegmentDecrypt`) |
| `2` | segment reencrypt |
| `3` | heap-exec call (`WbHeapExecuteCall`) |
| `9` | `WbProcessModuleUnload` — issued during licence decrypt; returns `0` and is safe to swallow |

### Constraints discovered (none of these are in the document)

1. **A descriptor living on a writable page is rejected** with `STATUS_INVALID_PARAMETER` (`0xc000000d`). The page's original protection must be restored *immediately before* the syscall, not after.

2. **Decrypt state is keyed by the descriptor address, not by the loaded image.** A descriptor already decrypted at a given address is not decrypted again: the call returns `res 0` and leaves the code unchanged. Because `2-decrypt-img.py` drove every block through *one* sacrificial slot (`segs[0]`), every block after the first reused an already-decrypted address and silently no-opped — which is where the earlier "one heap-exec decrypt per loaded image" reading came from.

   The reference implementation avoids this by rewriting each heap-exec descriptor **at its own address** (`0x3080`, `0x33c0`, …), so all 981 decrypts use distinct addresses and succeed in a single loaded image. The primary document's own `wbsetup` trace confirms it:

   ```
   - scanning for heap exec descriptors
     found: 981
   - decrypting heapexec descriptors
   ...
   - patching self LEAs
     total: 981
   ```

   as does `wbop`, which decrypts `0x5a1b60` and then `0x6bacf0` in one session.

   A distinct descriptor address per block is what is required; a fresh `LoadLibraryW` is not. This is a strong inference from the reference implementation's behaviour rather than a directly instrumented result — a two-block/two-slot discrimination test settles it — and it matters practically: if correct, the per-block reload can be dropped for a roughly 981× speedup.

3. **Both descriptor kinds are decrypted with the same call.** The sacrificial-slot technique and `wbsetup` both rewrite a descriptor into segment shape before issuing `op=1`, so the kernel never sees a heap-exec decrypt. The two code paths exist because a segment descriptor carries a *list* of spans while a heap-exec descriptor carries one code block — not because the kernel treats them differently. What actually limits throughput is reusing a single descriptor address (constraint 2).

4. **Heap-exec blocks must be left ciphertext** when earlier blocks are patched. Pre-patching a heap-exec block that the kernel will decrypt causes a double decrypt and executes garbage. Segment blocks, by contrast, must be patched to plaintext.

   **Check this per build rather than assuming it.** The hazard only triggers where a segment span overlaps a heap-exec block. Measured on `10.0.19041.4780`: **0 of 7947 spans overlap**, so span patching and overlap-safe patching are equivalent there — which is why a prep that ignores the hazard works on this build. A build where the count is non-zero will corrupt the image silently. Prep should subtract heap-exec ranges and report the census rather than trust that it is zero.

5. **Nested WB calls inside heap-exec code use an inline `syscall` instruction**, bypassing any `NtQuerySystemInformation` IAT hook. This is why IAT hooking shows zero counters while the code clearly makes WB calls.

6. **`hModule` from `LoadLibraryW` is not an image base** for the WB calls on this build; the address space base and image base are the same, and `LoadLibraryW`'s return value works directly.

### Sacrificial descriptor technique

A heap-exec block can be decrypted at an arbitrary RVA by overwriting a spare `?g_Encry` descriptor slot. Slot `0x6D8000` was used (mapped `R-X`, restorable byte-for-byte):

- `[0x00:0x40)` ← the slot's own first 0x40 bytes (header shape must match the build)
- `[0x40:0xF0)` ← crypto params copied from the target block's descriptor body at `+0x40..+0xF0`
- `+0x20` = `0x100` (total size), `+0xF0` = `1` (entry count), `+0xF4` = `0x30C` (flags), `+0xF8` = rva, `+0xFC` = size
- `[0x00:0x20)` ← SHA-256 over `[0x20,0x100)`

This build's relocation pair used for synthetic descriptors: `RELOCS = 0x943770`, `NUM = 20888`.

**Reusing one slot across many blocks is subject to constraint 2.** Each block needs either its own descriptor address or an `op=2` reencrypt of the slot in between; otherwise every call after the first no-ops.

## 4. WB subroutine conventions (decrypted code)

Every Warbird subroutine in a heap-exec block begins with the same preamble:

```
4C 8B DC              mov  r11, rsp
49 89 5B 20           mov  [r11+0x20], rbx
55 56 57 41 54 …      push rbp/rbx/rsi/rdi/r12/r13/r14/r15
48 8D AC 24 78 FB FF FF   lea rbp, [rsp-0x488]
48 81 EC 88 05 00 00  sub  rsp, 0x588
```

Segment-block routines instead begin `48 8D 15 F9 FF FF FF` (`lea rdx, [rip-7]`) + `48 8B 0C 24` (`mov rcx, [rsp]`).

Key consequences:

- **`rcx` at entry is `[rsp]`**, i.e. the *caller's* args pointer is passed on the stack, not in `rcx`. A normal `call` places a return address there instead — this mismatch silently produces garbage arguments.
- **The kernel's args block is `rcx = args + 0x10`.** A routine reading `[rcx+0x10]` is reading `args+0x20`.
- **The 16 bytes before a routine (`[code-0x10]`, `[code-0x8]`) are a per-block delta**, `0xCC`-filled in the file and written by the kernel at decrypt time. The prologue does `mov rdi,[rax-0x10]; add rax,rdi` before indirect calls. Pre-patched code that skips this jumps to `0xCCCC…`.
- **Heap-exec routines return via `movabs r10,0xb9; xor rdx,rdx; xor r8,r8; xor r9,r9; syscall; ret`** — not a plain `ret`. A real `call` into such a routine never returns to its caller.
- `.pdata` treats each heap-exec block as **one function** (verified: `0x4300f0..0x435049`, size `0x4f59`, 12,335 sane entries). Block ≠ function-count.

## 5. Address map for build `10.0.19041.4780`

### Document's `pkdata` routines vs ours — constant `+0x150` drift

| document | ours |
|---|---|
| `2b7cd0` | `2b7e20` |
| `3375b0` | `337700` |
| `3b3be0` | `3b3d30` |
| `3b7910` | `3b7a60` |
| `523390` | `5234e0` |
| `5289d0` | `528b20` |

These six are **stage ② (bijection)**, not stage ①: each loads its own table set with `lea r14, [rip+…]` and then walks it.

### Bijection table clusters

| set | RVA | companion table |
|---|---|---|
| t3 | `0x843720` | `0x844150` (0x48) |
| t4 | `0x862ee0` | `0x863910` (0x48) |
| s1 | `0x882920` | `0x883350` (0x48) |
| **s2** | `0x8a23f0` | `0x8a2e48` (0x20) |
| s3 | `0x8c2470` | `0x8c2ce8` (0x20) |
| **s4** | `0x8e2210` | `0x8e2c10` (0x48) |
| s5 | `0x902180` | `0x902bd8` (0x20) |
| s6 | `0x922230` | `0x922c58` (0x20) |

Each is 64 consecutive 16-byte subtable blocks in a `0x400` span. Document's addresses (`8828a0, 8a2620, 8c1ff0, 8e2190, 9023b0, 922430`) are within ~`0x500` but the drift is **not constant**, so they must be located by pattern.

**Only `s4` is live** for this build's key format. Patching the other seven produces *sixteen identical outputs* — the signal used to rule them out. This is confirmed independently by the `distinct` diagnostic in §10: the seven non-live sets report `distinct = 1` per licence, the live one reports `16`.

### Table-list descriptors in `?g_Encry`

`0x6dd350, 0x6de550, 0x6df774, 0x6e0944, 0x6e1bbc, 0x6e2e64, 0x6e40f4, 0x6e53b4` — anchor addresses spaced `0xC0` apart, 12-byte entries pointing at the tables. These are the code-visible handles on each table set.

### Stage ① and ② routines (confirmed by WB trace)

| role | code RVA | descriptor RVA |
|---|---|---|
| **stage ①** (`enc.prv[0:0x20] → OBF`) | `0x6c6f00` | `0x4abc0` |
| **stage ②** (our variant, `%3 == 1`) | `0x337e30` ≡ `0x529250` | `0x7d840` ≡ `0x8fcc0` |
| licence-blob consumer (`declicense`) | `0x2229f0` | `0x491c0` |

The dispatch inside `0x2229f0` selects the routine pair from `prv[0x40] % 3`:

| `%3` | stage ① family | stage ② family |
|---|---|---|
| 0 | `0x4a80e0` / `0x3b8190` | `0x3b3d30` / `0x2b7e20` |
| 1 | `0x6c6f00` (only this one produced an OBF under the stage ① layout; `0x4300f0` and `0x2b8550` return `E_INVALIDARG` there) | **`0x529250` ≡ `0x337e30`** |
| 2 | `0x4300f0` / `0x2b8550` | `0x5234e0` / `0x3b7a60` |

All three documented equivalence pairs are now **confirmed by measurement**, not inference — driving each member with identical inputs gives byte-identical output:

| pair | observed |
|---|---|
| `0x2b8550 ≡ 0x4300f0` | both `REJECT st=57000780` |
| `0x3b8190 ≡ 0x4a80e0` | both `NOMATCH`, same `mut` |
| `0x529250 ≡ 0x337e30` | both `MATCH`, same `mut`/`mapped`/`plain` |

Because discovery iterates candidates in address order, the lower descriptor wins and stage ② reports as `0x337e30` (descriptor `0x07d840`) rather than the `0x529250` named in §12. Both are correct.

### Gap blocks (`0x334290`–`0x3376ef`)

Listed only in the *large* descriptor `0x6eb000`'s entry table (at `0x6f0d80`), which a `0x2000` size cap skips:

```
0x334290+0x4c3   0x334760+0x4af   0x334c20+0x454
0x335080+0x3d1   0x335460+0x1c56  0x3370c0+0x62f
```

These contain the helper routines the stage routines call (`0x335460`, `0x521210`), which is why losing them makes everything fault.

Large descriptors: `0x6da000` (0xc4a8, 4175 entries), `0x6eb000` (0x829c, 2766), `0x6f44d8` (0x3cac, 1274), `0x6e70c4` (0x7c0, 145).

### Section encryption (this build)

| section | encrypted |
|---|---|
| `.text` | 62% |
| `.rdata` | 2.8% (`0x125eb` of `0x291400`) — the document's build was 45% |

Low `.rdata` encryption is why the bijection tables are readable without decryption.

## 6. The `.enc.prv` / `.sig.prv` file format

`0x41 = 65` bytes:

| range | role |
|---|---|
| `[0x00:0x20]` | stage ① input (32 bytes) |
| `[0x20:0x40]` | stage ② read-only second input (32 bytes) |
| `[0x40]` | variant byte → selects the routine pair by `% 3` |

This split is not documented. It was inferred from the routine ABI and then confirmed by the chain reproducing the public key.

## 7. Stage ABI (established by disassembly + behaviour)

### Stage ① — `0x6c6f00`, layout `{status, in, size, out}`

Body contains exactly two checks: `cmp dword ptr [rsp+0x28], 0x20` and `cmp dword ptr [rsp+0x20], 0x20`.

| arg off | routine sees | field |
|---|---|---|
| `+0x10` | `+0x00` | status pointer |
| `+0x18` | `+0x08` | input (0x20) |
| `+0x20` | `+0x10` | u32 size = 0x20 |
| `+0x24` | `+0x14` | output (0x20) |

Call length `0x2C`. **`+0x00` is a status pointer, not an output buffer** — `0x80070057` landing there was the diagnostic that revealed the layout.

### Stage ② — `0x337e30` / `0x529250`, layout `{status, in, size, out}`

Same shape, call length `0x30`, but behaviour differs critically:

- **`in` is mutated in place**; the mutated bytes are the result.
- **`out` is read-only input** (`out_ptr[0] & 7` becomes a shift amount, `out_ptr[0x1f]` another input).
- Body: no `call` instructions in 3,955 instructions — fully inlined.

### Licence consumer — `0x2229f0`

| `rcx+` | args off | field |
|---|---|---|
| `+0x00` | `+0x10` | status output |
| `+0x08` | `+0x18` | mode dword |
| `+0x0c` | `+0x1c` | key pointer (checked size `0x41` at `rcx+0x14`) |
| `+0x14` | `+0x24` | size = `0x41` |
| `+0x18` | `+0x28` | licence blob |
| `+0x20` | `+0x30` | real output |

Guards: `[rcx+0x0c] != 0`, `[rcx+0x18] != 0`, `[rcx+0x14] == 0x41`. The size check sits at `0x222a64` (bytes `83 79 14 41`), unique in the decrypted image; the owning block is `0x2229f0 + 0x434`.

**Output is `(signature_key ‖ content_key) XOR magic`** — 32 bytes, not a private key. It *consumes* `.enc.prv`; it never emits plaintext.

## 8. Licence blob / XMR (this response)

360-byte XMR, magic `XMR\0`, nonce echo at `+0x08`.

| structure | offset | content |
|---|---|---|
| `ContentKeyObject` | `0x62` | KID `bb6a67eb34cb965ebbcf616630f1a3da`, symmetric cipher `0x0001`, key-enc cipher `0x0003` (**plain ECC256 / ElGamal, not `ECC256ViaSymmetric`**), `CBEncryptedKey 0x0080`, buffer `0x80..0x100` |
| `EccDeviceKeyObject` | `0x100` | curve `0x0001`, `CBKeyData 0x40`, key = the identity's `.enc.pub` |
| `SignatureObject` | `0x150` | `00 00 00 1c 00 01 00 10` then 16-byte CMAC at `0x158` |

**The signature FTLV is 28 bytes total**: 8-byte FTLV header + 4-byte signature-object header + 16-byte MAC. So the CMAC covers `xmr[:-28]`, and the expected value is `xmr[-16:]`. Using `xmr[:-16]` as the body yields a false negative — a real trap, since the MAC is the only offline verifier available.

Because the cipher is plain `0x0003`, decryption is a single operation: $M = C_2 - d\cdot C_1$ over P-256, then $M_x$ splits into signature key ‖ content key.

## 9. The nibble permutation — derived value

**Our build's `[MAP]` (mapped → real):**

```
0→e  1→0  2→b  3→4  4→a  5→7  6→c  7→3
8→2  9→8  a→9  b→5  c→f  d→1  e→6  f→d
```

**Document's build, as mapped → real** (the inverse of the table it prints):

```
0→1  1→0  2→a  3→c  4→9  5→6  6→8  7→4
8→f  9→7  a→d  b→5  c→3  d→b  e→2  f→e
```

They differ — only `b→5` coincides. Re-deriving was unavoidable. The difference is a build difference, not a variant difference: `prv[0x40] % 3` selects which routine family and table set is used, and the document's map was derived on a different DLL, so it is not evidence of variant-dependent permutations either way (see §17).

**Only 3 standalone 16-byte permutations exist in the entire image, and none is the map.** It is computed, not stored. The 1,617-window cluster at `0x73f680` is a farm of 256-byte permutations (1598 distinct), not the 64-subtable structure.

## 10. Oracle method — how to re-derive for another build

This is the document's own approach, but the concrete constraints are new:

1. **15 licences only.** Scalar $d = \underbrace{NN\ldots NN}_{64}$, i.e. `int("NN"*64, 16)`. Nibble `00` is impossible (zero scalar) and is recovered as the **single leftover** permutation slot. `0x0f` reduces mod $N$ ($2^{256}-1 > N$, giving `00000000ffffffff…039cdaae`) but the key bytes are still all `0f`.
2. **Each licence's plaintext point** is $X = $ `"HELLO MICROSOFT!" ‖ 0¹⁶`. Expect the even-Y root to be used.
3. **Blob generation is plain ECIES**: $C_1 = rG$, $C_2 = M + rQ$. No toolkit needed.
4. **Force a constant mapped nibble** by overwriting the live `0x400` subtable region with `bytes([MM]) * 0x400`.
5. **Detect via the XOR-masked sentinel**: expected output is `("HELLO MICROSOFT!" ‖ 0¹⁶) XOR magic`. Both halves must match; one alone can collide.
6. **Control run required.** With the table intact the sentinel must *not* appear — if it does, the key or licences are wrong and every result is garbage. The control also supplies the "not live" baseline: on a non-live set all sixteen outputs equal it, which is what makes `distinct = 1` meaningful.
7. **Clusters not on the live path return 16 identical outputs**, which is how phase 1 identifies the live one (exactly one hit for `lic_01`).
8. **Every patched page must have its protection restored** or the call returns `0xc000000d`.
9. **Derive the magic; do not assume it.** The published W10/W11 sequences were taken from specific builds. A build from a different family may use a third sequence, and the symptom is indistinguishable from a wrong live set: every query misses, no fault, status `0`. For set $S$, forced mapped nibble $m$, licence $NN$:

   $$O(S,m,NN) = X\!\left(C_2 - d'(m)\cdot C_1\right) \oplus \text{magic}$$

   where $d'(m)$ is the scalar with every nibble forced to $\mathrm{MAP}[m]$. Decryption reaches the sentinel iff $\mathrm{MAP}[m] = NN$, so on a **live** set exactly one of the sixteen outputs is byte-identical across *all* licences — the sentinel X-coordinate, which is licence-independent. Hence

   $$\left|\bigcap_{NN}\{\,O(S,m,NN) : m = 0..15\,\}\right| = 1 \iff S \text{ is live}$$

   and the shared value is $\text{SENT} \oplus \text{magic}$. Magic is recovered, not supplied.

   Validated on `10.0.19041.4780`: eight sets found, exactly one live (`0x8e2210`), `distinct = 16` per licence, `shared = 1`, derived magic equal to the Windows 10 sequence.

10. **The per-set `distinct` count separates three failures.** Report $\left|\{O(S,m,NN) : m = 0..15\}\right|$ per set per licence:

    | `distinct` | `shared` | reading |
    |---|---|---|
    | all `1` | `0` | set not on this key's path — the patch has no effect on the output |
    | `16` | `1` | **live** — magic recovered, permutation derivable |
    | `16` | `0` | set is read, sentinel never reached → blob/ECC encoding is wrong |

    If **every** set reports `distinct = 1`, the consumer descriptor is wrong for that build (the routine returns `0` but never reads the table) — a different fix from a wrong magic. Without this column the two are indistinguishable, and a run of N misses with no fault cannot be triaged at all.

11. Result must be a bijection with exactly one leftover, or the derivation is invalid.

Total cost: ≤ 240 decrypt calls. **Reusable for keys of the same variant within a build**; cross-variant reuse is untested (see §17).

The `magic` sequences are per OS family (W10 vs W11); item 9 makes that irrelevant, but they are worth recording for cross-checking a derived value:

```
W10  a77bece491a87ebcd8a2c62856b165b3 3ad2572cf88bdae3ddc79be816be3185
W11  c3cd57691eff156c95d946d534121dfb 81738adb5b4bb4223faad89cbb459bec
```

## 11. Validation anchors — what matched the published document

These confirmed the *understanding* was right even when the derived values differed:

| anchor | result |
|---|---|
| `s2` bijection applied to doc's `OBF` | reproduces doc's `MAP` **64/64** |
| doc's `MAP` + doc's permutation | reproduces doc's plaintext exactly |
| XOR split of the doc's worked example | `24 5a 65 ef…` XOR magic → `e7 97 32 86…` = doc's signature key |
| signature FTLV length | 28 bytes, consistent with the doc's example |

So the document's tables and map *are* correct — for its build. Our build differs only in stage ① output and in the permutation.

## 12. Verified chain (regression values)

```
extracted.enc.prv          6dcd ecc5 f297 38be …  (65 bytes, [0x40] = 0x0a)
stage ①  0x6c6f00(prv[0:0x20])  ->  69ef7582 608af8d0 df0fb4b5 15449be5
                                     a8d0c903 741cbf33 53be70eb 460521f4   (= OBF)
stage ②  0x337e30 in=OBF, out=prv[0x20:0x40]
         in-mutated            ->  b5295b2c 77fb4cc5 399ff4ca 295cd46a
                                     70baf34d 9310893b 833cab54 906f6388
stage ③  bijection(s4)         ->  6fc2df9b 904b6c01 e8f12495 56208045
                                     7dcf6fda ef16a20e 3eaa6c58 7626f66d
stage ④  MAP                   ->  cdfb1d85 8ea5cfe0 62d0ba87 7cbe2ea7
                                     31fdcd19 6d0c9be6 4699cf72 3cbcdcc1   (= .enc.plain)

extracted.enc.plain  sha256  075cdae2b17f6fa1c72ef30ad4805fdc20d6926a6f2b73f4ff3f60490634aa98
```

Verified by `d·G == extracted.enc.pub`, and independently by ECIES-decrypting a real Microsoft licence: AES-CMAC matched, content key `100b6c20940f779a4589152b57d2dacb` = `EAtsIJQPd5pFiRUrV9Layw==`.

Chain re-verified end to end after the stage-3 rewrite: all four intermediate values reproduce this table exactly, `d·G` matches, and stage 3's `[MAP]` reproduces §9 all sixteen entries with a derived magic equal to the Windows 10 sequence. Three independent derivations of the map now agree — the original single-hit sweep, the intersection method, and the recorded `GOLD` constant.

## 13. Negative results — do not retry

| attempt | outcome |
|---|---|
| `genfixedkey`, `genzlicense`, `msprcp` | not publicly available (confirmed by download) |
| WRET / `wbsetup` / `pkdata` / `declicense` | not publicly available; exit codes / formats unverifiable |
| 34 windows of `prv` through `0x6c6f00` | all distinct; none matched a candidate |
| 3,840 table × order × perm × byte-order combinations | no match |
| 20,736 combinations (6 routines × 4 in-windows × 18 out-candidates) | no match |
| `in2` = `prv[0x20:0x40]` against all six `pkdata` routines | none produced `DOC_OBF`; **`in2` is not a caller argument at all** |
| iterating stage ① 128 times | no fixed point, no cycle |
| searching for the map as standalone data | only 3 permutations exist in the image; none is the map |
| EK table by published SHA-256 | absent — not stored contiguously, or built at load time |
| W11 EK literal-byte needle | absent on a W10-family build (expected, uninformative) |
| INT3 hooks on heap-exec entries | fail by construction: those blocks must stay ciphertext |
| IAT hook on `NtQuerySystemInformation` | blind to nested calls (inline `syscall`) |
| stage ① against the doc's published pair | **unresolved** — see open items |
| one sacrificial slot reused for every heap-exec block | no-ops after the first (see §3 constraint 2); not a kernel per-image limit |

## 14. Tooling substitutions

| document tool | replacement used |
|---|---|
| `genfixedkey` | P-256 scalar multiplication in Python (deterministic, hash-verifiable) |
| `genzlicense` | ECIES blob builder in Python |
| `wbsetup -r` | `LoadLibraryW` + op=1 per descriptor; **distinct descriptor address per heap-exec block** (the reference rewrites each block's own descriptor; reusing one slot no-ops after the first) |
| `declicense` | op=3 against descriptor `0x491c0` with the 6-field arg block |
| `pkdata -k` | direct overwrite of the live `0x400` subtable region |
| `PrvKeyExtractor` | oracle sweep: 16 forced values × 15 licences |

Also learned: identifying a signing-key routine by **size discrimination** (accepts `0x20`, rejects other sizes, distinct outputs for distinct inputs) works without any sample keys, provided the rejection is read from the *status dword* rather than from `NTSTATUS`.

## 15. Fault triage

A Warbird fault is only interpretable if three fields survive: the NTSTATUS, the **signed** offset from the image base, and the module that owns the faulting address.

**`(addr - base) & 0xFFFFFFFF` destroys the answer.** A fault 108 MB *below* the base becomes `0x9859CCA7`, which reads like a plausible RVA inside a 10 MB image. Report the signed offset:

```python
off = ad - base          # keep the sign
```

and resolve the owner:

```python
buf = ctypes.create_unicode_buffer(512)
k32.K32GetMappedFileNameW(ctypes.c_void_p(-1), ctypes.c_void_p(ad), buf, 512)
```

Measured taxonomy on `10.0.19041.4780`, driving candidates with the stage ①/② argument layout:

| signature | meaning |
|---|---|
| `module` = the DLL, `off` inside the image, `bytes` = `8b411c4c8bc1…` (`mov eax,[rcx+0x1c]; mov rax,rcx`) | executed code reached a routine that dereferences `rcx` as a pointer. The candidate takes a pointer where this layout supplies a size — wrong calling convention, image otherwise sound |
| `module=-`, `off` large negative, `addr` in no module | jumped into a kernel-allocated Warbird block, i.e. double-decrypted garbage |
| no fault, `st=57000780` | routine ran and returned `E_INVALIDARG` — the layout is wrong for that candidate, not the image |

The third row is the one that matters most for triage: **a reject and a crash look identical if the reject path prints nothing.** Every call must log `rc` and the status dword, including rejects.

Corollary for harnesses: a child process that reports faults under a different prefix than the driver filters on will log every fault as "no output" and discard the code, address, module and bytes. Filter on the mode-aware prefix, and surface the child's `stderr` and return code whenever no usable line appears.

## 16. `mfpmp.exe` findings (abandoned route, recorded for completeness)

- `OpenProcess(PROCESS_VM_READ)` succeeded on this build — the process is **not** protected by default here.
- Setting `NoProtectedProcess=1` breaks DRM playback (`SOURCE_STREAM_TYPE_NOT_SUPPORTED`); removing it did not restore playback without also clearing stale Edge processes.
- `LoadLibraryW` returns `GetLastError = 5` (access denied) inside the PMP container **even for a signed Microsoft DLL**, with correct ACLs and no Code Integrity events. Raw shellcode in `VirtualAllocEx`/`CreateRemoteThread` did run.
- No log file written by an injected DLL ever appeared, consistent with the load being refused rather than the DLL failing to initialise.
- The route was abandoned because the decryptor object needed is built only during a signature-verified decrypt, which the in-process op=3 path reaches without any injection.

## 17. Open items

1. **Stage ① is not cross-validated against the document.** `0x6c6f00` applied to the doc's published `.enc.prv` does not reproduce the doc's `OBF`, and none of the six `pkdata` routines with any tested input did either. Either the doc's build has a different stage ①, or the doc's operand selection differs. Our chain is nonetheless self-consistent: it reproduces the public key and decrypts a real Microsoft licence.
2. **`%3` dispatch table is inferred, not traced.** The *duplication structure* is now measured: all three equivalence pairs reproduce byte-identically (see §5), and for `prv[0x40] = 0x0a` (`%3 = 1`) only `0x6c6f00` acts as stage ① while `0x337e30`/`0x529250` act as stage ②. What remains inferred is the assignment of the other two variants' pairs. Tracing a live call per variant would settle it.
3. **`in2` for the six `pkdata` routines is still unknown.** They require a `0x40`-byte struct that is decryptor state, not key material. Not needed for the working chain, but unexplained.
4. **Only one build tested.** The permutation, live cluster, and routine RVAs are all per-build; the oracle is the only build-independent part of the method.
5. **Discovery generator for `oracle/` is `1-make-oracle.py`** — 15 fixed-scalar keys and ECIES licences, fully reproducible, keys hash-verifiable.
6. **`oracle_map.json` reusability is unproven.** §10 says the map is reusable for keys of the same variant within a build. Nothing in the green run tests that, and if the permutation is variant-dependent the claim is false. Cheap to settle: run stage 3 against a second identity with `prv[0x40] % 3 ≠ 1` and diff the maps. Until then treat the map as belonging to the key it was derived with.

## 18. Additional constants worth recording

| item | value |
|---|---|
| live bijection cluster (this build, this key format) | `0x8e2210` |
| `MAP[0xd] = 1` (first oracle result) | confirms `lic_01` → mapped `0x0d` |
| leftover mapped nibble | `0x1` → real `0x0` |
| `.reloc` RVA / count used for synthetic descriptors | `0x943770` / `20888` |
| sacrificial descriptor slot | `0x6D8000` |
| `?g_Encry` sections | `0x6d8000, 0x6d9000, 0x6da000, 0x6e9000, 0x6ea000, 0x6eb000, 0x6f9000, 0x6fa000` |
| `.pdata` sane entries | 12,335 |
| heap-exec block prologues sampled | `0x6bae40, 0x0ce940, 0x1a16c0, 0x11a3f0, 0x14bb50, 0x179ff0` |
| consumer size-check site | `0x222a64` (`83 79 14 41`) |
| spans overlapping heap-exec blocks | 0 of 7947 on this build |

---

Two notes on using this: the *values* in §5, §9 and §18 are this-build-only and will fail on any other DLL, so treat them as a worked example rather than a specification. And §12 is the only section that should ever be used as a pass/fail test — everything else is descriptive.
