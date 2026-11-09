// movie.go marker preserve
package sofia

import (
   "bytes"
   "errors"
)

// decodeTimes reads the time fields shared by mvhd and mdhd, whose layout
// differs only by FullBox version.
func decodeTimes(p *parser, version byte) (creation, modification uint64, timescale uint32, duration uint64) {
   if version == 1 {
      creation = p.Uint64()
      modification = p.Uint64()
      timescale = p.Uint32()
      duration = p.Uint64()
   } else {
      creation = uint64(p.Uint32())
      modification = uint64(p.Uint32())
      timescale = p.Uint32()
      duration = uint64(p.Uint32())
   }
   return
}

// encodeTimes is decodeTimes in the other direction.
func encodeTimes(w *writer, version byte, creation, modification uint64, timescale uint32, duration uint64) {
   if version == 1 {
      w.PutUint64(creation)
      w.PutUint64(modification)
      w.PutUint32(timescale)
      w.PutUint64(duration)
   } else {
      w.PutUint32(uint32(creation))
      w.PutUint32(uint32(modification))
      w.PutUint32(timescale)
      w.PutUint32(uint32(duration))
   }
}

// --- MOOV ---
type MoovBox struct {
   Header      *BoxHeader
   Mvhd        *MvhdBox
   Trak        []*TrakBox
   Pssh        []*PsshBox
   RawChildren [][]byte
}

func DecodeMoovBox(data []byte) (*MoovBox, error) {
   b := &MoovBox{}
   var err error
   if b.Header, err = DecodeBoxHeader(data); err != nil {
      return nil, err
   }
   err = walkBoxes(boxPayload(data, b.Header), func(typ [4]byte, content []byte) error {
      var decErr error
      switch string(typ[:]) {
      case "mvhd":
         b.Mvhd, decErr = DecodeMvhdBox(content)
      case "trak":
         var trak *TrakBox
         if trak, decErr = DecodeTrakBox(content); decErr == nil {
            b.Trak = append(b.Trak, trak)
         }
      case "pssh":
         var pssh *PsshBox
         if pssh, decErr = DecodePsshBox(content); decErr == nil {
            b.Pssh = append(b.Pssh, pssh)
         }
      default:
         b.RawChildren = append(b.RawChildren, content)
      }
      return decErr
   })
   if err != nil {
      return nil, err
   }
   return b, nil
}

func (b *MoovBox) Encode() []byte {
   children := make([][]byte, 0, 1+len(b.Trak)+len(b.RawChildren))
   if b.Mvhd != nil {
      children = append(children, b.Mvhd.Encode())
   }
   for _, trak := range b.Trak {
      children = append(children, trak.Encode())
   }
   // pssh is skipped on encode
   children = append(children, b.RawChildren...)
   return encodeBox(b.Header, nil, children)
}

// FindDefaultKID walks the first track's sample entries and returns the first
// non-zero default KID declared by a 'tenc' box, following
// trak > mdia > minf > stbl > stsd > enc > sinf > schi > tenc.
// An all-zero KID means no key is declared by that box, so it is skipped.
// Returns nil if no KID is found.
func (b *MoovBox) FindDefaultKID() []byte {
   if len(b.Trak) == 0 {
      return nil
   }
   trak := b.Trak[0]
   if trak.Mdia == nil || trak.Mdia.Minf == nil || trak.Mdia.Minf.Stbl == nil || trak.Mdia.Minf.Stbl.Stsd == nil {
      return nil
   }
   for _, enc := range trak.Mdia.Minf.Stbl.Stsd.EncChildren {
      if enc.Sinf == nil || enc.Sinf.Schi == nil || enc.Sinf.Schi.Tenc == nil {
         continue
      }
      kid := enc.Sinf.Schi.Tenc.DefaultKID
      if kid != ([16]byte{}) {
         return kid[:]
      }
   }
   return nil
}

func (b *MoovBox) FindPssh(systemID []byte) (*PsshBox, bool) {
   for _, pssh := range b.Pssh {
      if bytes.Equal(pssh.SystemID[:], systemID) {
         return pssh, true
      }
   }
   return nil, false
}

func (b *MoovBox) RemoveMvex() {
   b.RawChildren = removeChildren(b.RawChildren, "mvex")
}

// --- MVHD ---
type MvhdBox struct {
   Header           *BoxHeader
   Version          byte
   Flags            [3]byte
   CreationTime     uint64
   ModificationTime uint64
   Timescale        uint32
   Duration         uint64
   RemainingData    []byte
}

func DecodeMvhdBox(data []byte) (*MvhdBox, error) {
   b := &MvhdBox{}
   var err error
   if b.Header, err = DecodeBoxHeader(data); err != nil {
      return nil, err
   }
   if len(data) < 12 {
      return nil, errors.New("mvhd box too small")
   }

   p := parser{data: data, offset: 8}
   versionAndFlags := p.Bytes(4)
   b.Version = versionAndFlags[0]
   copy(b.Flags[:], versionAndFlags[1:])

   if b.Version == 1 {
      if len(data) < 40 { // 8 header + 4 version/flags + 28 v1 body
         return nil, errors.New("mvhd v1 too short")
      }
   } else if len(data) < 28 { // 8 header + 4 version/flags + 16 v0 body
      return nil, errors.New("mvhd v0 too short")
   }
   b.CreationTime, b.ModificationTime, b.Timescale, b.Duration = decodeTimes(&p, b.Version)

   b.RemainingData = boxPayloadFrom(data, b.Header, p.offset)
   return b, nil
}

func (b *MvhdBox) Encode() []byte {
   bodySize := 20 // 4 version/flags + 16 v0 body
   if b.Version == 1 {
      bodySize = 32 // 4 version/flags + 28 v1 body
   }
   body := make([]byte, bodySize+len(b.RemainingData))
   w := writer{buf: body}
   w.PutByte(b.Version)
   w.PutBytes(b.Flags[:])
   encodeTimes(&w, b.Version, b.CreationTime, b.ModificationTime, b.Timescale, b.Duration)
   w.PutBytes(b.RemainingData)
   return encodeBox(b.Header, body, nil)
}

func (b *MvhdBox) SetDuration(duration uint64) {
   b.Duration = duration
   if b.Duration > 0xFFFFFFFF {
      b.Version = 1
   }
}

// movie.go marker preserve
