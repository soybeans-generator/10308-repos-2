# findbij.py
import struct, sys

path = sys.argv[1] if len(sys.argv) > 1 else r"C:\Windows\System32\Windows.Media.Protection.PlayReady.dll"
d = open(path, "rb").read()

pe = struct.unpack_from("<I", d, 0x3C)[0]
nsec = struct.unpack_from("<H", d, pe + 6)[0]
optsz = struct.unpack_from("<H", d, pe + 20)[0]
base = struct.unpack_from("<Q", d, pe + 24 + 24)[0]
secs = []
for i in range(nsec):
    o = pe + 24 + optsz + i * 40
    name = d[o:o + 8].rstrip(b"\x00").decode("ascii", "replace")
    vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", d, o + 8)
    secs.append((name, vaddr, vsize, rawptr, rawsize))

print(f"{path}\n  image base {base:#x}  sections {nsec}")
def rva(off):
    for name, vaddr, vsize, rawptr, rawsize in secs:
        if rawptr <= off < rawptr + rawsize:
            return vaddr + (off - rawptr), name
    return None, None

hits = [o for o in range(0, len(d) - 16, 16) if bytes(sorted(d[o:o+16])) == bytes(range(16))]
clusters = []
for o in hits:
    if clusters and o - clusters[-1][-1] <= 0x400:
        clusters[-1].append(o)
    else:
        clusters.append([o])

print(f"  {len(hits)} permutation blocks, {len(clusters)} clusters\n")
for c in clusters:
    if len(c) >= 16:
        r, s = rva(c[0])
        print(f"  cluster blocks={len(c):5d} span={c[-1]-c[0]+16:#07x} "
              f"rva={r:#x} ({s})" if r else f"  cluster blocks={len(c):5d} (unmapped)")
