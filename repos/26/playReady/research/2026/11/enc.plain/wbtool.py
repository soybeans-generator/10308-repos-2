# wbtool.py — find the function that builds the decryptor object (contains 0x215c71)
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

IMG, LOG = "wbtool_img.bin", "wbtool.txt"
ANCHOR = 0x215C71

d = open(IMG, "rb").read()
md = Cs(CS_ARCH_X86, CS_MODE_64)

L = []
def W(s=""):
    L.append(str(s))

st = ANCHOR
while st > ANCHOR - 0x2000:
    if d[st-2] == 0xCC and d[st-1] == 0xCC:
        break
    st -= 1
st += 1

W(f"anchor 0x{ANCHOR:06x}  function start 0x{st:06x}  span 0x{ANCHOR-st:x}")
W(f"prologue {d[st:st+12].hex()}")
W("")
for ins in md.disasm(d[st:st + 0x120], st):
    W(f"  0x{ins.address:06x}  {ins.bytes.hex():<22s} {ins.mnemonic:<8s} {ins.op_str}")
    if ins.mnemonic == "ret":
        break

W("")
W("immediate 0x41 / size checks in first 0x600 bytes:")
for ins in md.disasm(d[st:st + 0x600], st):
    if ins.mnemonic in ("cmp", "mov") and "0x41" in ins.op_str:
        W(f"  0x{ins.address:06x}  {ins.mnemonic} {ins.op_str}")

open(LOG, "w", encoding="utf-8").write("\n".join(L) + "\n")
print("\n".join(L))
