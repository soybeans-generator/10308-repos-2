// box.go marker preserve
package sofia

import (
   "encoding/binary"
   "errors"
)

// boxEnd returns the offset just past the box described by h, clamped to
// the available data. A declared size of 0 means "to the end".
func boxEnd(data []byte, h *BoxHeader) int {
   end := int(h.Size)
   if end == 0 || end > len(data) {
      end = len(data)
   }
   if end < 8 {
      end = 8
   }
   return end
}

// boxPayload returns the child-box area of data: everything after the
// 8-byte header.
func boxPayload(data []byte, h *BoxHeader) []byte {
   return boxPayloadFrom(data, h, 8)
}

// boxPayloadFrom returns the box body starting at from, bounded by the
// box's declared size.
func boxPayloadFrom(data []byte, h *BoxHeader, from int) []byte {
   end := boxEnd(data, h)
   if end < from {
      end = from
   }
   return data[from:end]
}

// encodeBox assembles a container box: the 8-byte header, then prefix,
// then children. The header size is set to the total length.
func encodeBox(h *BoxHeader, prefix []byte, children [][]byte) []byte {
   size := 8 + len(prefix)
   for _, child := range children {
      size += len(child)
   }
   buffer := make([]byte, 8, size)
   buffer = append(buffer, prefix...)
   for _, child := range children {
      buffer = append(buffer, child...)
   }
   h.Size = uint32(len(buffer))
   h.Put(buffer)
   return buffer
}

// removeChildren returns raw without any child box of the given type.
func removeChildren(raw [][]byte, typ string) [][]byte {
   kept := make([][]byte, 0, len(raw))
   for _, child := range raw {
      if len(child) >= 8 && string(child[4:8]) == typ {
         continue
      }
      kept = append(kept, child)
   }
   return kept
}

// walkBoxes iterates the child boxes of data, calling fn with each
// child's type and its complete bytes, header included. A header that
// cannot be read ends the walk; an impossible size is an error.
func walkBoxes(data []byte, fn func(typ [4]byte, content []byte) error) error {
   for offset := 0; offset < len(data); {
      h, err := DecodeBoxHeader(data[offset:])
      if err != nil {
         return nil
      }
      size := int(h.Size)
      if size == 0 {
         size = len(data) - offset
      }
      if size < 8 || offset+size > len(data) {
         return errors.New("invalid child box size")
      }
      if err := fn(h.Type, data[offset:offset+size]); err != nil {
         return err
      }
      offset += size
   }
   return nil
}

// FindMoov returns the first moov of a decoded box list.
func FindMoov(boxes []Box) (*MoovBox, bool) {
   for _, box := range boxes {
      if box.Moov != nil {
         return box.Moov, true
      }
   }
   return nil, false
}

// --- Box ---
type Box struct {
   Moov *MoovBox
   Moof *MoofBox
   Mdat *MdatBox
   Raw  []byte
}

func DecodeBoxes(data []byte) ([]Box, error) {
   var boxes []Box
   err := walkBoxes(data, func(typ [4]byte, content []byte) error {
      switch string(typ[:]) {
      case "moov":
         moov, err := DecodeMoovBox(content)
         if err != nil {
            return err
         }
         boxes = append(boxes, Box{Moov: moov})
      case "moof":
         moof, err := DecodeMoofBox(content)
         if err != nil {
            return err
         }
         boxes = append(boxes, Box{Moof: moof})
      case "mdat":
         mdat, err := DecodeMdatBox(content)
         if err != nil {
            return err
         }
         boxes = append(boxes, Box{Mdat: mdat})
      default:
         boxes = append(boxes, Box{Raw: content})
      }
      return nil
   })
   if err != nil {
      return nil, err
   }
   return boxes, nil
}

// --- BoxHeader ---
type BoxHeader struct {
   Size uint32
   Type [4]byte
}

func DecodeBoxHeader(data []byte) (*BoxHeader, error) {
   if len(data) < 8 {
      return nil, errors.New("not enough data for box header")
   }
   h := &BoxHeader{Size: binary.BigEndian.Uint32(data[:4])}
   copy(h.Type[:], data[4:8])
   return h, nil
}

func (h *BoxHeader) Put(buffer []byte) {
   binary.BigEndian.PutUint32(buffer[:4], h.Size)
   copy(buffer[4:8], h.Type[:])
}

// --- MDAT ---
type MdatBox struct {
   Header  *BoxHeader
   Payload []byte
}

func DecodeMdatBox(data []byte) (*MdatBox, error) {
   h, err := DecodeBoxHeader(data)
   if err != nil {
      return nil, err
   }
   return &MdatBox{Header: h, Payload: boxPayload(data, h)}, nil
}

// --- READING HELPER ---
type parser struct {
   data   []byte
   offset int
}

func (p *parser) Byte() byte {
   val := p.data[p.offset]
   p.offset++
   return val
}

func (p *parser) Bytes(n int) []byte {
   val := p.data[p.offset : p.offset+n]
   p.offset += n
   return val
}

func (p *parser) Int32() int32 {
   val := int32(binary.BigEndian.Uint32(p.data[p.offset:]))
   p.offset += 4
   return val
}

func (p *parser) Uint16() uint16 {
   val := binary.BigEndian.Uint16(p.data[p.offset:])
   p.offset += 2
   return val
}

func (p *parser) Uint32() uint32 {
   val := binary.BigEndian.Uint32(p.data[p.offset:])
   p.offset += 4
   return val
}

func (p *parser) Uint64() uint64 {
   val := binary.BigEndian.Uint64(p.data[p.offset:])
   p.offset += 8
   return val
}

// --- WRITING HELPER ---
type writer struct {
   buf    []byte
   offset int
}

func (w *writer) PutByte(data byte) {
   w.buf[w.offset] = data
   w.offset++
}

func (w *writer) PutBytes(data []byte) {
   copy(w.buf[w.offset:], data)
   w.offset += len(data)
}

func (w *writer) PutUint32(val uint32) {
   binary.BigEndian.PutUint32(w.buf[w.offset:], val)
   w.offset += 4
}

func (w *writer) PutUint64(val uint64) {
   binary.BigEndian.PutUint64(w.buf[w.offset:], val)
   w.offset += 8
}

// box.go marker preserve
