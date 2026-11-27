// emu.go begin
// A small x86-64 interpreter for the Warbird heap-exec blocks.
//
// -2 leaves every heap-exec block in plaintext, so the routines in wbtool_img.bin are the
// code itself. What a caller outside Windows lacks is not the code but the ability to call
// it: the blocks are written for the Warbird ABI, and the kernel is what normally supplies
// that. The instruction set they use is small and contains no vector instruction at all,
// which is what makes an interpreter of this size viable.
//
// THE ABI, from the disassembly of the -6 block:
//
//   lea rdx,[rip-7]        rdx = the block's own address
//   mov rdi,[rdx-8]        the WB syscall number, 0x36
//   mov r14,[rdx-0x10]     the relocation delta
//   mov rcx,[rsp]          the argument pointer
//
// and the argument pointer is the caller's WB buffer plus 0x10. A block that has finished
// issues syscall with rdx == 0; any other syscall is a nested WB operation, and op 3 is
// performed by recursing into the block the census names.
//
// SIGNED CONDITIONS NEED OF. jg, jge, jl and jle are decided by SF and OF together, and an
// interpreter that tracks only SF makes all four false - the fall-through branch is taken
// every time, silently, and the routine returns a plausible-looking wrong answer. So OF is
// computed by add, adc, sub, sbb, cmp, inc, dec, neg and the shifts.
//
// THE HIGH-BYTE RULE IS APPLIED IN EXACTLY ONE PLACE. Byte registers 4-7 are ah, ch, dh, bh
// when there is no REX prefix, and spl, bpl, sil, dil when there is. modrm returns the raw
// register-field number and never adjusts it; the caller builds the operand with regOp.
// Adjusting in both places turns `mov [x], ah` into `mov [x], al`, which is silent.
//
// A BLOCK ALWAYS RUNS FROM A SCRATCH COPY, AND THE CAPTURE CHANGES WHAT IT READS. The sixteen
// bytes before a block hold the WB syscall number and the relocation delta, and the kernel
// writes those into its own per-call copy - the mapped module never holds them. So the copy
// is where the prefix is fabricated, and the delta is measured against e.imgBase, which is
// the captured module base when there is a capture.
//
// THE TEB EXISTS ONLY AS FAR AS THESE ROUTINES LOOK AT IT. A helper reading
// `mov rax, qword ptr gs:[0x58]` is reading ThreadLocalStoragePointer, indexing it with the
// module's TLS index and comparing one dword of the resulting block against a table of build
// thresholds. Dropping the gs: prefix turns that into an absolute read of address 0x58.
//
// GROUP 2 IS THE SHIFT FAMILY AND THERE ARE SIX OPCODES FOR IT. c0/c1 take an imm8 count,
// d0/d1 shift by one, d2/d3 shift by cl, and the first of each pair is the byte form.
//
// THE ALU NUMBERING IS THE ARCHITECTURAL ONE. For the opcode pairs, the GROUP is in bits
// 5:3, the DIRECTION is bit 1 and the SIZE is bit 0.
//
// GROUP 3 IS f6 AND f7 WITH ONE BODY. /0 test, /2 not, /3 neg.
package main

import (
   "encoding/binary"
   "fmt"
   "math/bits"
   "sort"
)

const (
   emuImgBase   = 0x0000_0001_0000_0000
   emuStackBase = 0x0000_0002_0000_0000
   emuStackSize = 0x0040_0000
   emuCopyBase  = 0x0000_0003_0000_0000
   emuCopySize  = 0x0100_0000
   emuTebBase   = 0x0000_0004_0000_0000
   emuTebSize   = 0x0000_0000_0001_0000

   wbSyscallNo = 0x36

   // tebTlsValue is the dword a helper compares against its build thresholds. The compare
   // is `cmp [global], eax / jg`, so a value above every threshold takes the fall-through
   // branch, which is the newest-build implementation.
   tebTlsValue = 0x7FFFFFFF

   // tebSlotCount covers any TLS index the image can hold; every slot aliases one block,
   // so the index never matters.
   tebSlotCount = 64

   rRAX = 0
   rRCX = 1
   rRDX = 2
   rRBX = 3
   rRSP = 4
   rRBP = 5
   rRSI = 6
   rRDI = 7
   rR8  = 8
   rR9  = 9
   rR10 = 10
   rR11 = 11
   rR12 = 12
   rR13 = 13
   rR14 = 14
   rR15 = 15
)

// The ALU numbering, matching the group-1 /digit field and the opcode-pair group bits.
const (
   aluAdd = 0
   aluOr  = 1
   aluAdc = 2
   aluSbb = 3
   aluAnd = 4
   aluSub = 5
   aluXor = 6
   aluCmp = 7
)

// ---------------------------------------------------------------- registers

func emuMask(size int) uint64 {
   switch size {
   case 1:
      return 0xff
   case 2:
      return 0xffff
   case 4:
      return 0xffffffff
   }
   return ^uint64(0)
}

// imm reads one immediate: 1 byte when wide is false, 4 bytes otherwise.
func imm(code []byte, pc *int, wide bool) (uint64, error) {
   if !wide {
      if *pc >= len(code) {
         return 0, fmt.Errorf("truncated imm8")
      }
      v := uint64(int64(int8(code[*pc])))
      *pc = *pc + 1
      return v, nil
   }
   if *pc+4 > len(code) {
      return 0, fmt.Errorf("truncated imm32")
   }
   v := uint64(int64(int32(binary.LittleEndian.Uint32(code[*pc:]))))
   *pc += 4
   return v, nil
}

// ---------------------------------------------------------------- the interpreter

// prefixes consumes operand-size, REX and segment/repeat prefixes.
func prefixes(code []byte, pc int) (int, byte, byte, bool) {
   rex := byte(0)
   seg := byte(0)
   opsz := false
   for pc < len(code) {
      c := code[pc]
      switch {
      case c == 0x66:
         opsz = true
         pc++
      case c >= 0x40 && c <= 0x4f:
         rex = c
         pc++
      case c == 0x2e || c == 0x3e || c == 0x26 || c == 0x36 ||
         c == 0x64 || c == 0x65 || c == 0xf0 || c == 0xf2 ||
         c == 0xf3 || c == 0x67:
         if c == 0x64 || c == 0x65 {
            seg = c
         }
         pc++
      default:
         return pc, rex, seg, opsz
      }
   }
   return pc, rex, seg, opsz
}

// ---------------------------------------------------------------- flags and alu

// signBit is the mask of the sign bit for an operand of this size.
func signBit(size int) uint64 { return 1 << (uint(size*8) - 1) }

// emuRange is one heap-exec block: where its code sits in the image.
type emuRange struct {
   rva, ln uint32
}

// emuResult is one emulated call: the status dword and both buffers as the routine left them.
type emuResult struct {
   status []byte
   key    []byte
   out    []byte
}

// memMapFile is mem.json, written by prkf -4.
type memMapFile struct {
   ImageBase uint64      `json:"image_base"`
   DLLSHA256 string      `json:"dll_sha256"`
   Regions   []memRegion `json:"regions"`
   Total     uint64      `json:"total"`
}

// memRegion is one captured memory region: where it lives and where its bytes start in the
// capture file. Blank counts the bytes ReadProcessMemory could not read; they are zero in the
// file, and the region's size is unchanged so every later offset still lines up.
//
// prkf -4 writes this file on Windows and -6/-7 read it everywhere, so the type lives in this
// untagged file rather than beside the writer.
type memRegion struct {
   Addr  uint64 `json:"addr"`
   Size  uint64 `json:"size"`
   Off   uint64 `json:"off"`
   Blank uint64 `json:"blank,omitempty"`
}

type operand struct {
   isReg bool
   hi    bool // ah/ch/dh/bh: byte 1 of a legacy register
   reg   int
   addr  uint64
   size  int
}

// region is one captured region with its bytes resolved.
type region struct {
   addr uint64
   data []byte
}

type wbEmu struct {
   img        []byte
   imgBase    uint64
   stk        []byte
   cpy        []byte
   teb        []byte
   gsBase     uint64
   blocks     map[uint32]emuRange
   copies     map[uint32]uint64
   regions    []region
   lastRegion *region
   captured   bool
   cpyTop     int
   dataTop    int
   frameTop   int
   reg        [16]uint64
   zf         bool
   cf         bool
   sf         bool
   of         bool
   pf         bool
   depth      int
}

func newWBEmu(img []byte, blocks map[uint32]emuRange) *wbEmu {
   e := &wbEmu{
      img:     img,
      imgBase: emuImgBase,
      stk:     make([]byte, emuStackSize),
      cpy:     make([]byte, emuCopySize),
      teb:     make([]byte, emuTebSize),
      blocks:  blocks,
      copies:  map[uint32]uint64{},
   }
   e.setupTeb()
   return e
}

// alloc hands out a buffer in the data area at the bottom of the stack region.
func (e *wbEmu) alloc(n int) uint64 {
   e.dataTop = (e.dataTop + 15) &^ 15
   a := emuStackBase + uint64(e.dataTop)
   e.dataTop += n
   return a
}

// alu performs one group-1 operation, numbered as the architecture numbers them.
//
// OF IS NOT OPTIONAL. add, adc, sub, sbb and cmp all set it, and the signed conditions read
// it; without it jg/jge/jl/jle silently answer false and every threshold dispatch takes the
// fall-through branch.
func (e *wbEmu) alu(kind int, dst operand, src uint64, store bool) error {
   a, err := e.readOp(dst)
   if err != nil {
      return err
   }
   size := dst.size
   m := emuMask(size)
   sb := signBit(size)
   a &= m
   src &= m
   carry := uint64(0)
   if e.cf {
      carry = 1
   }

   var r uint64
   switch kind {
   case aluAdd, aluAdc:
      cin := uint64(0)
      if kind == aluAdc {
         cin = carry
      }
      sum, c := bits.Add64(a, src, cin)
      r = sum & m
      e.cf = c != 0
      e.of = (^(a ^ src) & (a ^ r) & sb) != 0
   case aluSub, aluSbb, aluCmp:
      cin := uint64(0)
      if kind == aluSbb {
         cin = carry
      }
      d, b := bits.Sub64(a, src, cin)
      r = d & m
      e.cf = b != 0
      e.of = ((a ^ src) & (a ^ r) & sb) != 0
   case aluOr:
      r = a | src
      e.cf, e.of = false, false
   case aluAnd:
      r = a & src
      e.cf, e.of = false, false
   case aluXor:
      r = a ^ src
      e.cf, e.of = false, false
   default:
      return fmt.Errorf("alu kind %d", kind)
   }
   e.setSZP(r, size)
   if !store {
      return nil
   }
   return e.writeOp(dst, r)
}

// blockCopy places one block in scratch with the 16-byte prefix the ABI reads.
//
// THE DELTA IS MEASURED AGAINST e.imgBase, which is the synthetic base without a capture and
// the captured module base with one. Either way `add rax, r14` inside a block lands on the
// image the block came from, which is what makes a call out of the copy reach real code.
func (e *wbEmu) blockCopy(va uint32, code []byte) (uint64, error) {
   if a, ok := e.copies[va]; ok {
      return a, nil
   }
   need := 0x10 + len(code)
   e.cpyTop = (e.cpyTop + 15) &^ 15
   if e.cpyTop+need > len(e.cpy) {
      return 0, fmt.Errorf("emulator scratch is full at block 0x%06x", va)
   }
   off := e.cpyTop
   a := emuCopyBase + uint64(off+0x10)
   imgAddr := e.imgBase + uint64(e.blocks[va].rva)

   copy(e.cpy[off+0x10:], code)
   binary.LittleEndian.PutUint64(e.cpy[off:], imgAddr-a)
   binary.LittleEndian.PutUint64(e.cpy[off+8:], wbSyscallNo)

   e.cpyTop += need
   e.copies[va] = a
   return a, nil
}

// ---------------------------------------------------------------- the block call

// call runs one block with the argument block the native op3Call would build.
func (e *wbEmu) call(descVA uint32, keySize uint32, key, out []byte, size2 *uint32) (res *emuResult, err error) {
   defer func() {
      if r := recover(); r != nil {
         res, err = nil, fmt.Errorf("emulator panic: %v", r)
      }
   }()

   e.dataTop, e.frameTop = 0, 0

   P := e.alloc(0x40)
   stP := e.alloc(0x10)
   keyP := e.alloc(0x40)
   outP := e.alloc(0x40)

   kb := make([]byte, 0x40)
   copy(kb, key)
   ob := make([]byte, 0x40)
   copy(ob, out)
   if err := e.copyIn(keyP, kb); err != nil {
      return nil, err
   }
   if err := e.copyIn(outP, ob); err != nil {
      return nil, err
   }

   a := make([]byte, 0x40)
   binary.LittleEndian.PutUint64(a[0x00:], 3)
   binary.LittleEndian.PutUint64(a[0x08:], e.imgBase+uint64(descVA))
   binary.LittleEndian.PutUint64(a[0x10:], stP)
   binary.LittleEndian.PutUint64(a[0x18:], keyP)
   binary.LittleEndian.PutUint32(a[0x20:], keySize)
   binary.LittleEndian.PutUint64(a[0x24:], outP)
   if size2 != nil {
      binary.LittleEndian.PutUint32(a[0x2c:], *size2)
   }
   if err := e.copyIn(P, a); err != nil {
      return nil, err
   }

   if err := e.runBlock(descVA, P); err != nil {
      return nil, err
   }
   return &emuResult{
      status: e.copyOut(stP, 4),
      key:    e.copyOut(keyP, 0x40),
      out:    e.copyOut(outP, 0x40),
   }, nil
}

// cond answers one condition code.
//
// 0 jo, 1 jno, 2 jb, 3 jae, 4 je, 5 jne, 6 jbe, 7 ja, 8 js, 9 jns, 10 jp, 11 jnp,
// 12 jl, 13 jge, 14 jle, 15 jg.
func (e *wbEmu) cond(c byte) bool {
   switch c {
   case 0x0:
      return e.of
   case 0x1:
      return !e.of
   case 0x2:
      return e.cf
   case 0x3:
      return !e.cf
   case 0x4:
      return e.zf
   case 0x5:
      return !e.zf
   case 0x6:
      return e.cf || e.zf
   case 0x7:
      return !e.cf && !e.zf
   case 0x8:
      return e.sf
   case 0x9:
      return !e.sf
   case 0xa:
      return e.pf
   case 0xb:
      return !e.pf
   case 0xc:
      return e.sf != e.of
   case 0xd:
      return e.sf == e.of
   case 0xe:
      return e.zf || e.sf != e.of
   case 0xf:
      return !e.zf && e.sf == e.of
   }
   return false
}

func (e *wbEmu) copyIn(addr uint64, b []byte) error {
   p, err := e.memRange(addr, len(b))
   if err != nil {
      return err
   }
   copy(p, b)
   return nil
}

func (e *wbEmu) copyOut(addr uint64, n int) []byte {
   p, err := e.memRange(addr, n)
   if err != nil {
      return make([]byte, n)
   }
   out := make([]byte, n)
   copy(out, p)
   return out
}

// fetch returns the bytes an instruction can occupy at addr.
func (e *wbEmu) fetch(addr uint64) ([]byte, error) {
   for n := 16; n > 0; n-- {
      if b, err := e.memRange(addr, n); err == nil {
         return b, nil
      }
   }
   return nil, fmt.Errorf("no readable code at %#x", addr)
}

// frame hands out one block's private stack, growing down from the top.
func (e *wbEmu) frame() uint64 {
   e.frameTop += 0x10000
   return emuStackBase + uint64(len(e.stk)-e.frameTop)
}

// group3 handles f6 and f7 with one body.
func (e *wbEmu) group3(op byte, win []byte, n *int, at uint64, rex, seg byte, sz int) error {
   size := sz
   if op == 0xf6 {
      size = 1
   }
   rm, ext, err := e.modrm(win, n, at, rex, seg, size)
   if err != nil {
      return err
   }
   switch ext {
   case 0: // test r/m, imm
      v, err := imm(win, n, size != 1)
      if err != nil {
         return err
      }
      return e.alu(aluAnd, rm, v, false)

   case 2: // not: no flags at all
      v, err := e.readOp(rm)
      if err != nil {
         return err
      }
      return e.writeOp(rm, ^v&emuMask(size))

   case 3: // neg
      v, err := e.readOp(rm)
      if err != nil {
         return err
      }
      m := emuMask(size)
      r := (0 - v) & m
      e.cf = v&m != 0
      e.of = v&m == signBit(size)
      e.setSZP(r, size)
      return e.writeOp(rm, r)
   }
   return fmt.Errorf("%02x /%d (mul, div) is not supported", op, ext)
}

// incdec is not alu: inc and dec leave CF alone, but they do set OF, and a signed compare
// against the result reads it.
func (e *wbEmu) incdec(o operand, dec bool) error {
   v, err := e.readOp(o)
   if err != nil {
      return err
   }
   size := o.size
   m := emuMask(size)
   sb := signBit(size)
   v &= m
   var r uint64
   if dec {
      r = (v - 1) & m
      e.of = v == sb
   } else {
      r = (v + 1) & m
      e.of = r == sb
   }
   e.setSZP(r, size)
   return e.writeOp(o, r)
}

func (e *wbEmu) load(addr uint64, n int) (uint64, error) {
   b, err := e.memRange(addr, n)
   if err != nil {
      return 0, err
   }
   switch n {
   case 1:
      return uint64(b[0]), nil
   case 2:
      return uint64(binary.LittleEndian.Uint16(b)), nil
   case 4:
      return uint64(binary.LittleEndian.Uint32(b)), nil
   case 8:
      return binary.LittleEndian.Uint64(b), nil
   }
   return 0, fmt.Errorf("load size %d", n)
}

// loadCapture maps the memory prkf -4 dumped. Blocks still run from the scratch copy; what the
// capture changes is everything the block READS.
//
// That split is deliberate. A block reads two qwords at [rdx-8] and [rdx-0x10] - the WB
// syscall number and the relocation delta - and the kernel writes those into its own per-call
// copy of the block, so the mapped module never holds them. Writing them into the capture was
// tried and is wrong: sixteen bytes back from a block is sometimes the previous block's tail,
// and clobbering it leaves 0x36 where a pointer belongs. The copy path already fabricates the
// prefix correctly, so the capture is used only as the address space the copy points into.
func (e *wbEmu) loadCapture(mm *memMapFile, data []byte) error {
   if mm.ImageBase == 0 {
      return fmt.Errorf("capture has no image base")
   }
   if len(mm.Regions) == 0 {
      return fmt.Errorf("capture has no regions")
   }

   own := [][2]uint64{
      {emuStackBase, emuStackSize},
      {emuCopyBase, emuCopySize},
      {emuTebBase, emuTebSize},
   }

   out := make([]region, 0, len(mm.Regions))
   for _, r := range mm.Regions {
      if r.Size == 0 {
         continue
      }
      if r.Off+r.Size > uint64(len(data)) {
         return fmt.Errorf("region %#x+%#x is outside a %d-byte capture", r.Addr, r.Size, len(data))
      }
      for _, o := range own {
         if r.Addr < o[0]+o[1] && r.Addr+r.Size > o[0] {
            return fmt.Errorf("captured region %#x+%#x overlaps the emulator's own range %#x+%#x",
               r.Addr, r.Size, o[0], o[1])
         }
      }
      out = append(out, region{addr: r.Addr, data: data[r.Off : r.Off+r.Size]})
   }
   sort.Slice(out, func(i, j int) bool { return out[i].addr < out[j].addr })

   e.regions = out
   e.lastRegion = nil
   e.captured = true
   e.imgBase = mm.ImageBase
   return nil
}

// ---------------------------------------------------------------- memory

func (e *wbEmu) memRange(addr uint64, n int) ([]byte, error) {
   if e.captured {
      if r := e.regionAt(addr); r != nil {
         if o := addr - r.addr; o+uint64(n) <= uint64(len(r.data)) {
            return r.data[o : o+uint64(n)], nil
         }
      }
   } else if addr >= emuImgBase {
      if o := addr - emuImgBase; o+uint64(n) <= uint64(len(e.img)) {
         return e.img[o : o+uint64(n)], nil
      }
   }
   if addr >= emuStackBase {
      if o := addr - emuStackBase; o+uint64(n) <= uint64(len(e.stk)) {
         return e.stk[o : o+uint64(n)], nil
      }
   }
   if addr >= emuCopyBase {
      if o := addr - emuCopyBase; o+uint64(n) <= uint64(len(e.cpy)) {
         return e.cpy[o : o+uint64(n)], nil
      }
   }
   if addr >= emuTebBase {
      if o := addr - emuTebBase; o+uint64(n) <= uint64(len(e.teb)) {
         return e.teb[o : o+uint64(n)], nil
      }
   }
   return nil, fmt.Errorf("unmapped address %#x + %d", addr, n)
}

// modrm decodes one ModRM byte plus any SIB and displacement. at is the address of the first
// byte of the instruction, and seg applies its segment base to the final address.
//
// THE REGISTER FIELD IS RETURNED RAW. The high-byte rule for byte registers 4-7 is the
// caller's job, through regOp, and it must be applied exactly once: applying it here as well
// turns `mov [x], ah` into `mov [x], al`.
func (e *wbEmu) modrm(code []byte, pc *int, at uint64, rex, seg byte, size int) (operand, int, error) {
   if *pc >= len(code) {
      return operand{}, 0, fmt.Errorf("truncated modrm")
   }
   b := code[*pc]
   *pc = *pc + 1

   mod := b >> 6
   regf := int(b>>3&7) | int(rex>>2&1)<<3
   rawrm := int(b & 7)
   rm := rawrm | int(rex&1)<<3

   if mod == 3 {
      op := operand{isReg: true, reg: rm, size: size}
      if size == 1 && rex == 0 && rawrm >= 4 {
         op.hi = true
         op.reg = rawrm - 4
      }
      return op, regf, nil
   }

   var addr uint64
   switch {
   case rawrm == 4:
      if *pc >= len(code) {
         return operand{}, 0, fmt.Errorf("truncated sib")
      }
      sib := code[*pc]
      *pc = *pc + 1

      scale := uint64(1) << (sib >> 6)
      if rawIdx := int(sib >> 3 & 7); rawIdx != 4 || rex&2 != 0 {
         idx := rawIdx | int(rex>>1&1)<<3
         addr += e.reg[idx] * scale
      }
      if rawBase := int(sib & 7); rawBase == 5 && mod == 0 {
         if *pc+4 > len(code) {
            return operand{}, 0, fmt.Errorf("truncated disp32")
         }
         addr += uint64(int64(int32(binary.LittleEndian.Uint32(code[*pc:]))))
         *pc += 4
      } else {
         addr += e.reg[rawBase|int(rex&1)<<3]
      }

   case rawrm == 5 && mod == 0:
      if *pc+4 > len(code) {
         return operand{}, 0, fmt.Errorf("truncated disp32")
      }
      d := uint64(int64(int32(binary.LittleEndian.Uint32(code[*pc:]))))
      *pc += 4
      addr = at + uint64(*pc) + d

   default:
      addr = e.reg[rm]
   }

   switch mod {
   case 0:
   case 1:
      if *pc >= len(code) {
         return operand{}, 0, fmt.Errorf("truncated disp8")
      }
      addr += uint64(int64(int8(code[*pc])))
      *pc = *pc + 1
   case 2:
      if *pc+4 > len(code) {
         return operand{}, 0, fmt.Errorf("truncated disp32")
      }
      addr += uint64(int64(int32(binary.LittleEndian.Uint32(code[*pc:]))))
      *pc += 4
   }

   if seg == 0x65 {
      addr += e.gsBase
   }
   return operand{addr: addr, size: size}, regf, nil
}

// nested performs one WB operation issued by a syscall inside a block.
func (e *wbEmu) nested(p uint64) error {
   op, err := e.load(p, 8)
   if err != nil {
      return err
   }
   switch op {
   case 1, 2:
      return nil
   case 3:
      desc, err := e.load(p+8, 8)
      if err != nil {
         return err
      }
      if desc < e.imgBase || desc >= e.imgBase+uint64(len(e.img)) {
         return fmt.Errorf("nested descriptor %#x is outside the image", desc)
      }
      save := e.reg
      if err := e.runBlock(uint32(desc-e.imgBase), p); err != nil {
         return err
      }
      e.reg = save
      return nil
   case 4:
      return nil
   }
   return fmt.Errorf("WB op %d is not handled", op)
}

func (e *wbEmu) readOp(o operand) (uint64, error) {
   if o.isReg {
      return e.regGet(o), nil
   }
   return e.load(o.addr, o.size)
}

func (e *wbEmu) regGet(o operand) uint64 {
   if o.hi {
      return (e.reg[o.reg] >> 8) & 0xff
   }
   return e.reg[o.reg] & emuMask(o.size)
}

func (e *wbEmu) regPut(o operand, v uint64) {
   if o.hi {
      e.reg[o.reg] = e.reg[o.reg]&^0xff00 | (v&0xff)<<8
      return
   }
   switch o.size {
   case 1:
      e.reg[o.reg] = e.reg[o.reg]&^0xff | v&0xff
   case 2:
      e.reg[o.reg] = e.reg[o.reg]&^0xffff | v&0xffff
   case 4:
      e.reg[o.reg] = v & 0xffffffff
   default:
      e.reg[o.reg] = v
   }
}

// regionAt returns the captured region containing addr. The last hit is remembered because
// instruction fetch walks forward through one region at a time.
func (e *wbEmu) regionAt(addr uint64) *region {
   if r := e.lastRegion; r != nil && addr >= r.addr && addr-r.addr < uint64(len(r.data)) {
      return r
   }
   lo, hi := 0, len(e.regions)
   for lo < hi {
      mid := int(uint(lo+hi) >> 1)
      r := &e.regions[mid]
      switch {
      case addr < r.addr:
         hi = mid
      case addr-r.addr >= uint64(len(r.data)):
         lo = mid + 1
      default:
         e.lastRegion = r
         return r
      }
   }
   return nil
}

// run executes from start until a WB return syscall, or until a ret with no call frame.
func (e *wbEmu) run(start uint64) error {
   pc := start
   depth := 0

   for steps := 0; ; steps++ {
      if steps > 200_000_000 {
         return fmt.Errorf("no termination after 200M instructions, stopped at %#x", pc)
      }

      at := pc
      win, err := e.fetch(at)
      if err != nil {
         return err
      }

      n, rex, seg, opsz := prefixes(win, 0)
      if n >= len(win) {
         return fmt.Errorf("%#x: instruction is past the readable window", at)
      }
      op := win[n]
      n++

      sz := 4
      if rex&8 != 0 {
         sz = 8
      } else if opsz {
         sz = 2
      }
      moved := false

      set := func(target uint64) {
         pc = target
         moved = true
      }

      // regOp builds a register operand from a ModRM register field, applying the high-byte
      // rule in the one place it belongs.
      regOp := func(idx, size int) operand {
         o := operand{isReg: true, reg: idx, size: size}
         if size == 1 && rex == 0 && idx >= 4 {
            o.hi = true
            o.reg = idx - 4
         }
         return o
      }

      switch {
      // --- mov ---------------------------------------------------------
      case op == 0x88 || op == 0x89 || op == 0x8a || op == 0x8b:
         size := sz
         if op&1 == 0 {
            size = 1
         }
         rm, regf, err := e.modrm(win, &n, at, rex, seg, size)
         if err != nil {
            return fmt.Errorf("%#x: %w", at, err)
         }
         if op >= 0x88 && op <= 0x89 {
            if err := e.writeOp(rm, e.regGet(regOp(regf, size))); err != nil {
               return fmt.Errorf("%#x: %w", at, err)
            }
         } else {
            v, err := e.readOp(rm)
            if err != nil {
               return fmt.Errorf("%#x: %w", at, err)
            }
            e.regPut(regOp(regf, size), v)
         }

      case op == 0x8d: // lea
         rm, regf, err := e.modrm(win, &n, at, rex, seg, sz)
         if err != nil {
            return fmt.Errorf("%#x: %w", at, err)
         }
         if rm.isReg {
            return fmt.Errorf("%#x: lea with a register operand", at)
         }
         e.regPut(regOp(regf, sz), rm.addr)

      case op >= 0xb8 && op <= 0xbf: // mov reg, imm
         r := int(op&7) | int(rex&1)<<3
         switch {
         case rex&8 != 0:
            if n+8 > len(win) {
               return fmt.Errorf("%#x: truncated imm64", at)
            }
            e.regPut(regOp(r, 8), binary.LittleEndian.Uint64(win[n:]))
            n += 8
         case opsz:
            if n+2 > len(win) {
               return fmt.Errorf("%#x: truncated imm16", at)
            }
            e.regPut(regOp(r, 2), uint64(binary.LittleEndian.Uint16(win[n:])))
            n += 2
         default:
            if n+4 > len(win) {
               return fmt.Errorf("%#x: truncated imm32", at)
            }
            e.regPut(regOp(r, 4), uint64(binary.LittleEndian.Uint32(win[n:])))
            n += 4
         }

      case op == 0xc6 || op == 0xc7: // mov r/m, imm
         size := sz
         if op == 0xc6 {
            size = 1
         }
         rm, ext, err := e.modrm(win, &n, at, rex, seg, size)
         if err != nil {
            return fmt.Errorf("%#x: %w", at, err)
         }
         if ext != 0 {
            return fmt.Errorf("%#x: c6/c7 ext %d", at, ext)
         }
         var v uint64
         switch size {
         case 1:
            if n+1 > len(win) {
               return fmt.Errorf("%#x: truncated imm8", at)
            }
            v = uint64(win[n])
            n++
         case 2:
            if n+2 > len(win) {
               return fmt.Errorf("%#x: truncated imm16", at)
            }
            v = uint64(binary.LittleEndian.Uint16(win[n:]))
            n += 2
         default:
            if n+4 > len(win) {
               return fmt.Errorf("%#x: truncated imm32", at)
            }
            v = uint64(int64(int32(binary.LittleEndian.Uint32(win[n:]))))
            n += 4
         }
         if err := e.writeOp(rm, v); err != nil {
            return fmt.Errorf("%#x: %w", at, err)
         }

      // --- accumulator and immediate ------------------------------------
      case op <= 0x3d && op&7 >= 4 && op&7 <= 5:
         kind := int(op >> 3)
         size := 1
         if op&1 == 1 {
            size = sz
         }
         v, err := imm(win, &n, op&1 == 1)
         if err != nil {
            return fmt.Errorf("%#x: %w", at, err)
         }
         if err := e.alu(kind, operand{isReg: true, reg: rRAX, size: size}, v, kind != aluCmp); err != nil {
            return fmt.Errorf("%#x: %w", at, err)
         }

      // --- the opcode pairs --------------------------------------------
      case op <= 0x3b && op&7 < 4:
         kind := int(op >> 3)
         size := sz
         if op&1 == 0 {
            size = 1
         }
         rm, regf, err := e.modrm(win, &n, at, rex, seg, size)
         if err != nil {
            return fmt.Errorf("%#x: %w", at, err)
         }
         dst := rm
         src := regOp(regf, size)
         if op&2 != 0 {
            dst, src = src, rm
         }
         v, err := e.readOp(src)
         if err != nil {
            return fmt.Errorf("%#x: %w", at, err)
         }
         if err := e.alu(kind, dst, v, kind != aluCmp); err != nil {
            return fmt.Errorf("%#x: %w", at, err)
         }

      case op == 0x80 || op == 0x81 || op == 0x83: // group 1 with an immediate
         size := sz
         if op == 0x80 {
            size = 1
         }
         rm, ext, err := e.modrm(win, &n, at, rex, seg, size)
         if err != nil {
            return fmt.Errorf("%#x: %w", at, err)
         }
         v, err := imm(win, &n, op == 0x81)
         if err != nil {
            return fmt.Errorf("%#x: %w", at, err)
         }
         if err := e.alu(ext, rm, v, ext != aluCmp); err != nil {
            return fmt.Errorf("%#x: %w", at, err)
         }

      case op == 0x84 || op == 0x85: // test r/m, r
         size := sz
         if op == 0x84 {
            size = 1
         }
         rm, regf, err := e.modrm(win, &n, at, rex, seg, size)
         if err != nil {
            return fmt.Errorf("%#x: %w", at, err)
         }
         if err := e.alu(aluAnd, rm, e.regGet(regOp(regf, size)), false); err != nil {
            return fmt.Errorf("%#x: %w", at, err)
         }

      // --- group 4 and 5: inc, dec, call, jmp, push ---------------------
      case op == 0xfe || op == 0xff:
         rm, ext, err := e.modrm(win, &n, at, rex, seg, 8)
         if err != nil {
            return fmt.Errorf("%#x: %w", at, err)
         }
         switch ext {
         case 0, 1:
            rm.size = sz
            if op == 0xfe {
               rm.size = 1
            }
            if err := e.incdec(rm, ext == 1); err != nil {
               return fmt.Errorf("%#x: %w", at, err)
            }

         case 2: // call r/m
            rm.size = 8
            target, err := e.readOp(rm)
            if err != nil {
               return fmt.Errorf("%#x: %w", at, err)
            }
            ret := at + uint64(n)
            e.reg[rRSP] -= 8
            if err := e.store(e.reg[rRSP], 8, ret); err != nil {
               return fmt.Errorf("%#x: call stack: %w", at, err)
            }
            depth++
            set(target)

         case 4: // jmp r/m
            rm.size = 8
            target, err := e.readOp(rm)
            if err != nil {
               return fmt.Errorf("%#x: %w", at, err)
            }
            set(target)

         case 6: // push r/m
            rm.size = sz
            v, err := e.readOp(rm)
            if err != nil {
               return fmt.Errorf("%#x: %w", at, err)
            }
            e.reg[rRSP] -= 8
            if err := e.store(e.reg[rRSP], 8, v); err != nil {
               return fmt.Errorf("%#x: %w", at, err)
            }

         default:
            return fmt.Errorf("%#x: ff /%d is not supported", at, ext)
         }

      case op == 0xf6 || op == 0xf7: // group 3
         if err := e.group3(op, win, &n, at, rex, seg, sz); err != nil {
            return fmt.Errorf("%#x: %w", at, err)
         }

      // --- group 2: shifts and rotates ----------------------------------
      case op == 0xc0 || op == 0xc1 || op == 0xd0 || op == 0xd1 ||
         op == 0xd2 || op == 0xd3:
         size := sz
         switch op {
         case 0xc0, 0xd0, 0xd2:
            size = 1
         }
         rm, ext, err := e.modrm(win, &n, at, rex, seg, size)
         if err != nil {
            return fmt.Errorf("%#x: %w", at, err)
         }
         var cnt uint
         switch op {
         case 0xc0, 0xc1:
            if n >= len(win) {
               return fmt.Errorf("%#x: truncated shift count", at)
            }
            cnt = uint(win[n])
            n++
         case 0xd0, 0xd1:
            cnt = 1
         case 0xd2, 0xd3:
            cnt = uint(e.reg[rRCX] & 0xff)
         }
         if err := e.shift(ext, rm, cnt, size); err != nil {
            return fmt.Errorf("%#x: %w", at, err)
         }

      // --- sign-extending moves -----------------------------------------
      case op == 0x63: // movsxd r64, r/m32
         rm, regf, err := e.modrm(win, &n, at, rex, seg, 4)
         if err != nil {
            return fmt.Errorf("%#x: %w", at, err)
         }
         v, err := e.readOp(rm)
         if err != nil {
            return fmt.Errorf("%#x: %w", at, err)
         }
         e.regPut(regOp(regf, 8), uint64(int64(int32(v))))

      case op == 0x98: // cwde / cdqe
         if rex&8 != 0 {
            e.reg[rRAX] = uint64(int64(int32(e.reg[rRAX])))
         } else {
            e.reg[rRAX] = uint64(uint32(int32(int16(e.reg[rRAX]))))
         }

      case op == 0x99: // cdq / cqo
         e.reg[rRDX] = ^uint64(0)
         if rex&8 != 0 {
            if int64(e.reg[rRAX]) >= 0 {
               e.reg[rRDX] = 0
            }
         } else if int32(e.reg[rRAX]) >= 0 {
            e.reg[rRDX] = 0
         }

      // --- imul ---------------------------------------------------------
      case op == 0x69 || op == 0x6b:
         rm, regf, err := e.modrm(win, &n, at, rex, seg, sz)
         if err != nil {
            return fmt.Errorf("%#x: %w", at, err)
         }
         v, err := imm(win, &n, op == 0x69)
         if err != nil {
            return fmt.Errorf("%#x: %w", at, err)
         }
         a, err := e.readOp(rm)
         if err != nil {
            return fmt.Errorf("%#x: %w", at, err)
         }
         m := emuMask(sz)
         e.regPut(regOp(regf, sz), (a&m)*(v&m)&m)

      // --- push / pop ---------------------------------------------------
      case op >= 0x50 && op <= 0x57:
         r := int(op&7) | int(rex&1)<<3
         e.reg[rRSP] -= 8
         if err := e.store(e.reg[rRSP], 8, e.reg[r]); err != nil {
            return fmt.Errorf("%#x: %w", at, err)
         }

      case op >= 0x58 && op <= 0x5f:
         r := int(op&7) | int(rex&1)<<3
         v, err := e.load(e.reg[rRSP], 8)
         if err != nil {
            return fmt.Errorf("%#x: %w", at, err)
         }
         e.reg[rRSP] += 8
         e.reg[r] = v

      // --- jumps and calls ----------------------------------------------
      case op == 0xe8: // call rel32
         if n+4 > len(win) {
            return fmt.Errorf("%#x: truncated call", at)
         }
         d := int64(int32(binary.LittleEndian.Uint32(win[n:])))
         n += 4
         ret := at + uint64(n)
         e.reg[rRSP] -= 8
         if err := e.store(e.reg[rRSP], 8, ret); err != nil {
            return fmt.Errorf("%#x: call stack: %w", at, err)
         }
         depth++
         set(uint64(int64(at) + int64(n) + d))

      case op == 0xe9: // jmp rel32
         if n+4 > len(win) {
            return fmt.Errorf("%#x: truncated jmp", at)
         }
         d := int64(int32(binary.LittleEndian.Uint32(win[n:])))
         n += 4
         set(uint64(int64(at) + int64(n) + d))

      case op == 0xeb: // jmp rel8
         if n >= len(win) {
            return fmt.Errorf("%#x: truncated jmp", at)
         }
         d := int64(int8(win[n]))
         n++
         set(uint64(int64(at) + int64(n) + d))

      case op >= 0x70 && op <= 0x7f: // jcc rel8
         if n >= len(win) {
            return fmt.Errorf("%#x: truncated jcc", at)
         }
         d := int64(int8(win[n]))
         n++
         if e.cond(op & 0xf) {
            set(uint64(int64(at) + int64(n) + d))
         }

      case op == 0x90: // nop

      case op == 0xc3: // ret
         if depth == 0 {
            return nil
         }
         v, err := e.load(e.reg[rRSP], 8)
         if err != nil {
            return fmt.Errorf("%#x: ret: %w", at, err)
         }
         e.reg[rRSP] += 8
         depth--
         set(v)

      case op == 0xc2: // ret imm16
         if depth == 0 {
            return nil
         }
         if n+2 > len(win) {
            return fmt.Errorf("%#x: truncated ret", at)
         }
         pop := uint64(binary.LittleEndian.Uint16(win[n:]))
         v, err := e.load(e.reg[rRSP], 8)
         if err != nil {
            return fmt.Errorf("%#x: ret: %w", at, err)
         }
         e.reg[rRSP] += 8 + pop
         depth--
         set(v)

      case op == 0xc9: // leave
         e.reg[rRSP] = e.reg[rRBP]
         v, err := e.load(e.reg[rRSP], 8)
         if err != nil {
            return fmt.Errorf("%#x: leave: %w", at, err)
         }
         e.reg[rRSP] += 8
         e.reg[rRBP] = v

      case op == 0x0f:
         if n >= len(win) {
            return fmt.Errorf("%#x: truncated 0f", at)
         }
         op2 := win[n]
         n++
         switch {
         case op2 == 0x05: // syscall
            if e.reg[rRDX] == 0 {
               return nil
            }
            if err := e.nested(e.reg[rRDX]); err != nil {
               return fmt.Errorf("%#x: %w", at, err)
            }
            e.reg[rRAX] = 0
            e.reg[rRCX] = 0
            e.reg[rR11] = 0

         case op2 == 0xb6 || op2 == 0xb7: // movzx
            src := 1
            if op2 == 0xb7 {
               src = 2
            }
            dst := 4
            if rex&8 != 0 {
               dst = 8
            }
            rm, regf, err := e.modrm(win, &n, at, rex, seg, src)
            if err != nil {
               return fmt.Errorf("%#x: %w", at, err)
            }
            v, err := e.readOp(rm)
            if err != nil {
               return fmt.Errorf("%#x: %w", at, err)
            }
            e.regPut(regOp(regf, dst), v)

         case op2 == 0xbe || op2 == 0xbf: // movsx
            src := 1
            if op2 == 0xbf {
               src = 2
            }
            dst := 4
            if rex&8 != 0 {
               dst = 8
            }
            rm, regf, err := e.modrm(win, &n, at, rex, seg, src)
            if err != nil {
               return fmt.Errorf("%#x: %w", at, err)
            }
            v, err := e.readOp(rm)
            if err != nil {
               return fmt.Errorf("%#x: %w", at, err)
            }
            var ext64 uint64
            if src == 1 {
               ext64 = uint64(int64(int8(v)))
            } else {
               ext64 = uint64(int64(int16(v)))
            }
            e.regPut(regOp(regf, dst), ext64)

         case op2 == 0xaf: // imul r, r/m
            rm, regf, err := e.modrm(win, &n, at, rex, seg, sz)
            if err != nil {
               return fmt.Errorf("%#x: %w", at, err)
            }
            v, err := e.readOp(rm)
            if err != nil {
               return fmt.Errorf("%#x: %w", at, err)
            }
            m := emuMask(sz)
            dst := regOp(regf, sz)
            e.regPut(dst, (e.regGet(dst)*v)&m)

         case op2 >= 0x40 && op2 <= 0x4f: // cmovcc
            rm, regf, err := e.modrm(win, &n, at, rex, seg, sz)
            if err != nil {
               return fmt.Errorf("%#x: %w", at, err)
            }
            v, err := e.readOp(rm)
            if err != nil {
               return fmt.Errorf("%#x: %w", at, err)
            }
            if e.cond(op2 & 0xf) {
               e.regPut(regOp(regf, sz), v)
            }

         case op2 == 0x1e || op2 == 0x1f: // nop r/m
            if _, _, err := e.modrm(win, &n, at, rex, seg, sz); err != nil {
               return fmt.Errorf("%#x: %w", at, err)
            }

         case op2 >= 0x80 && op2 <= 0x8f: // jcc rel32
            if n+4 > len(win) {
               return fmt.Errorf("%#x: truncated jcc", at)
            }
            d := int64(int32(binary.LittleEndian.Uint32(win[n:])))
            n += 4
            if e.cond(op2 & 0xf) {
               set(uint64(int64(at) + int64(n) + d))
            }

         default:
            return fmt.Errorf("%#x: opcode 0f %02x is not supported", at, op2)
         }

      default:
         return fmt.Errorf("%#x: opcode %02x is not supported", at, op)
      }

      if !moved {
         pc = at + uint64(n)
      }
   }
}

func (e *wbEmu) runBlock(va uint32, argP uint64) error {
   b, ok := e.blocks[va]
   if !ok {
      return fmt.Errorf("block 0x%06x is not a heap-exec descriptor in the census", va)
   }
   if b.ln == 0 || uint64(b.rva)+uint64(b.ln) > uint64(len(e.img)) {
      return fmt.Errorf("block 0x%06x has no usable code range", va)
   }
   if e.depth >= 12 {
      return fmt.Errorf("nested WB calls deeper than 12 at 0x%06x", va)
   }
   code := e.img[b.rva : b.rva+b.ln]

   at, err := e.blockCopy(va, code)
   if err != nil {
      return err
   }

   e.depth++
   defer func() { e.depth-- }()

   frame := e.frame()
   e.reg = [16]uint64{}
   e.reg[rRSP] = frame
   if err := e.store(frame, 8, argP+0x10); err != nil {
      return err
   }
   return e.run(at)
}

func (e *wbEmu) setSZP(r uint64, size int) {
   r &= emuMask(size)
   e.zf = r == 0
   e.sf = r&signBit(size) != 0
   e.pf = bits.OnesCount8(byte(r))&1 == 0
}

// setupTeb builds the only three things a helper reads from the thread environment.
func (e *wbEmu) setupTeb() {
   e.gsBase = emuTebBase
   binary.LittleEndian.PutUint64(e.teb[0x58:], emuTebBase+0x1000)
   for i := 0; i < tebSlotCount; i++ {
      binary.LittleEndian.PutUint64(e.teb[0x1000+i*8:], emuTebBase+0x2000)
   }
   binary.LittleEndian.PutUint32(e.teb[0x2000+4:], tebTlsValue)
}

// shift is group 2. The /digit field selects the operation: 0 rol, 1 ror, 4 shl, 5 shr,
// 7 sar. A count of zero changes nothing, not even the flags.
func (e *wbEmu) shift(ext int, o operand, cnt uint, size int) error {
   v, err := e.readOp(o)
   if err != nil {
      return err
   }
   m := emuMask(size)
   sb := signBit(size)
   width := uint(size * 8)
   cnt &= width - 1
   if cnt == 0 {
      return nil
   }

   var r uint64
   switch ext {
   case 0: // rol
      r = ((v << cnt) | (v >> (width - cnt))) & m
      e.cf = r&1 != 0
      e.of = (r&sb != 0) != e.cf
   case 1: // ror
      r = ((v >> cnt) | (v << (width - cnt))) & m
      e.cf = r&sb != 0
      e.of = (r&sb != 0) != (r&(sb>>1) != 0)
   case 4, 6: // shl, sal
      r = (v << cnt) & m
      e.cf = (v>>(width-cnt))&1 != 0
      e.of = (r&sb != 0) != e.cf
   case 5: // shr
      r = (v & m) >> cnt
      e.cf = (v>>(cnt-1))&1 != 0
      e.of = v&sb != 0
   case 7: // sar
      switch size {
      case 1:
         r = uint64(uint8(int8(v) >> cnt))
      case 2:
         r = uint64(uint16(int16(v) >> cnt))
      case 4:
         r = uint64(uint32(int32(v) >> cnt))
      default:
         r = uint64(int64(v) >> cnt)
      }
      e.cf = (v>>(cnt-1))&1 != 0
      e.of = false
   default:
      return fmt.Errorf("shift /%d (rcl, rcr) is not supported", ext)
   }
   r &= m
   e.setSZP(r, size)
   return e.writeOp(o, r)
}

func (e *wbEmu) store(addr uint64, n int, v uint64) error {
   b, err := e.memRange(addr, n)
   if err != nil {
      return err
   }
   switch n {
   case 1:
      b[0] = byte(v)
   case 2:
      binary.LittleEndian.PutUint16(b, uint16(v))
   case 4:
      binary.LittleEndian.PutUint32(b, uint32(v))
   case 8:
      binary.LittleEndian.PutUint64(b, v)
   default:
      return fmt.Errorf("store size %d", n)
   }
   return nil
}

func (e *wbEmu) writeOp(o operand, v uint64) error {
   if o.isReg {
      e.regPut(o, v)
      return nil
   }
   return e.store(o.addr, o.size, v)
}

// emu.go end
