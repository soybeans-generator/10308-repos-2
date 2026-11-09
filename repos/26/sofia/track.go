// track.go marker preserve
package sofia

import (
   "errors"
   "fmt"
)

// --- ENC (Encrypted Sample Entry) ---
type EncBox struct {
   Header      *BoxHeader
   EntryHeader []byte
   Sinf        *SinfBox
   RawChildren [][]byte
}

func DecodeEncBox(data []byte) (*EncBox, error) {
   b := &EncBox{}
   var err error
   if b.Header, err = DecodeBoxHeader(data); err != nil {
      return nil, err
   }

   var entrySize int
   switch string(b.Header.Type[:]) {
   case "enca":
      entrySize = 28
   case "encv":
      entrySize = 78
   default:
      return nil, fmt.Errorf("unknown encryption box type %q", b.Header.Type[:])
   }
   if end := boxEnd(data, b.Header); end < 8+entrySize {
      return nil, fmt.Errorf("enc box too small for sample entry header: need %d bytes, have %d", 8+entrySize, end)
   }
   b.EntryHeader = data[8 : 8+entrySize]

   err = walkBoxes(boxPayloadFrom(data, b.Header, 8+entrySize), func(typ [4]byte, content []byte) error {
      if string(typ[:]) != "sinf" {
         b.RawChildren = append(b.RawChildren, content)
         return nil
      }
      sinf, decErr := DecodeSinfBox(content)
      if decErr != nil {
         return decErr
      }
      b.Sinf = sinf
      return nil
   })
   if err != nil {
      return nil, err
   }
   return b, nil
}

func (b *EncBox) Encode() []byte {
   children := make([][]byte, 0, 1+len(b.RawChildren))
   if b.Sinf != nil {
      children = append(children, b.Sinf.Encode())
   }
   children = append(children, b.RawChildren...)
   return encodeBox(b.Header, b.EntryHeader, children)
}

// --- FRMA ---
type FrmaBox struct {
   Header     *BoxHeader
   DataFormat [4]byte
}

func DecodeFrmaBox(data []byte) (*FrmaBox, error) {
   b := &FrmaBox{}
   var err error
   if b.Header, err = DecodeBoxHeader(data); err != nil {
      return nil, err
   }
   if len(data) < 12 {
      return nil, errors.New("frma box is too small")
   }
   copy(b.DataFormat[:], data[8:12])
   return b, nil
}

func (b *FrmaBox) Encode() []byte {
   return encodeBox(b.Header, b.DataFormat[:], nil)
}

// --- MDHD ---
type MdhdBox struct {
   Header           *BoxHeader
   Version          byte
   Flags            [3]byte
   CreationTime     uint64
   ModificationTime uint64
   Timescale        uint32
   Duration         uint64
   Language         [2]byte
   Quality          [2]byte
}

func DecodeMdhdBox(data []byte) (*MdhdBox, error) {
   b := &MdhdBox{}
   var err error
   if b.Header, err = DecodeBoxHeader(data); err != nil {
      return nil, err
   }
   if len(data) < 12 {
      return nil, errors.New("mdhd box too small")
   }

   p := parser{data: data, offset: 8}
   versionAndFlags := p.Bytes(4)
   b.Version = versionAndFlags[0]
   copy(b.Flags[:], versionAndFlags[1:])

   if b.Version == 1 {
      if len(data) < 44 {
         return nil, errors.New("mdhd v1 too short")
      }
   } else if len(data) < 32 {
      return nil, errors.New("mdhd v0 too short")
   }
   b.CreationTime, b.ModificationTime, b.Timescale, b.Duration = decodeTimes(&p, b.Version)

   if len(data) < p.offset+4 {
      return nil, errors.New("mdhd truncated at language/quality")
   }
   copy(b.Language[:], p.Bytes(2))
   copy(b.Quality[:], p.Bytes(2))
   return b, nil
}

func (b *MdhdBox) Encode() []byte {
   bodySize := 24 // 4 version/flags + 16 v0 body + 4 language/quality
   if b.Version == 1 {
      bodySize = 36 // 4 version/flags + 28 v1 body + 4 language/quality
   }
   body := make([]byte, bodySize)
   w := writer{buf: body}
   w.PutByte(b.Version)
   w.PutBytes(b.Flags[:])
   encodeTimes(&w, b.Version, b.CreationTime, b.ModificationTime, b.Timescale, b.Duration)
   w.PutBytes(b.Language[:])
   w.PutBytes(b.Quality[:])
   return encodeBox(b.Header, body, nil)
}

func (b *MdhdBox) SetDuration(duration uint64) {
   b.Duration = duration
   if b.Duration > 0xFFFFFFFF {
      b.Version = 1
   }
}

// --- MDIA ---
type MdiaBox struct {
   Header      *BoxHeader
   Mdhd        *MdhdBox
   Minf        *MinfBox
   RawChildren [][]byte
}

func DecodeMdiaBox(data []byte) (*MdiaBox, error) {
   b := &MdiaBox{}
   var err error
   if b.Header, err = DecodeBoxHeader(data); err != nil {
      return nil, err
   }
   err = walkBoxes(boxPayload(data, b.Header), func(typ [4]byte, content []byte) error {
      var decErr error
      switch string(typ[:]) {
      case "mdhd":
         b.Mdhd, decErr = DecodeMdhdBox(content)
      case "minf":
         b.Minf, decErr = DecodeMinfBox(content)
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

func (b *MdiaBox) Encode() []byte {
   var children [][]byte
   if b.Mdhd != nil {
      children = append(children, b.Mdhd.Encode())
   }
   if b.Minf != nil {
      children = append(children, b.Minf.Encode())
   }
   children = append(children, b.RawChildren...)
   return encodeBox(b.Header, nil, children)
}

// --- MINF ---
type MinfBox struct {
   Header      *BoxHeader
   Stbl        *StblBox
   RawChildren [][]byte
}

func DecodeMinfBox(data []byte) (*MinfBox, error) {
   b := &MinfBox{}
   var err error
   if b.Header, err = DecodeBoxHeader(data); err != nil {
      return nil, err
   }
   err = walkBoxes(boxPayload(data, b.Header), func(typ [4]byte, content []byte) error {
      if string(typ[:]) != "stbl" {
         b.RawChildren = append(b.RawChildren, content)
         return nil
      }
      stbl, decErr := DecodeStblBox(content)
      if decErr != nil {
         return decErr
      }
      b.Stbl = stbl
      return nil
   })
   if err != nil {
      return nil, err
   }
   return b, nil
}

func (b *MinfBox) Encode() []byte {
   var children [][]byte
   if b.Stbl != nil {
      children = append(children, b.Stbl.Encode())
   }
   children = append(children, b.RawChildren...)
   return encodeBox(b.Header, nil, children)
}

// --- SCHI (Scheme Information) ---
type SchiBox struct {
   Header      *BoxHeader
   Tenc        *TencBox
   RawChildren [][]byte
}

func DecodeSchiBox(data []byte) (*SchiBox, error) {
   b := &SchiBox{}
   var err error
   if b.Header, err = DecodeBoxHeader(data); err != nil {
      return nil, err
   }
   err = walkBoxes(boxPayload(data, b.Header), func(typ [4]byte, content []byte) error {
      if string(typ[:]) != "tenc" {
         b.RawChildren = append(b.RawChildren, content)
         return nil
      }
      tenc, decErr := DecodeTencBox(content)
      if decErr != nil {
         return decErr
      }
      b.Tenc = tenc
      return nil
   })
   if err != nil {
      return nil, err
   }
   return b, nil
}

func (b *SchiBox) Encode() []byte {
   var children [][]byte
   if b.Tenc != nil {
      children = append(children, b.Tenc.Encode())
   }
   children = append(children, b.RawChildren...)
   return encodeBox(b.Header, nil, children)
}

// --- SINF ---
type SinfBox struct {
   Header      *BoxHeader
   Frma        *FrmaBox
   Schi        *SchiBox
   RawChildren [][]byte
}

func DecodeSinfBox(data []byte) (*SinfBox, error) {
   b := &SinfBox{}
   var err error
   if b.Header, err = DecodeBoxHeader(data); err != nil {
      return nil, err
   }
   err = walkBoxes(boxPayload(data, b.Header), func(typ [4]byte, content []byte) error {
      var decErr error
      switch string(typ[:]) {
      case "frma":
         b.Frma, decErr = DecodeFrmaBox(content)
      case "schi":
         b.Schi, decErr = DecodeSchiBox(content)
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

func (b *SinfBox) Encode() []byte {
   var children [][]byte
   if b.Frma != nil {
      children = append(children, b.Frma.Encode())
   }
   if b.Schi != nil {
      children = append(children, b.Schi.Encode())
   }
   children = append(children, b.RawChildren...)
   return encodeBox(b.Header, nil, children)
}

// --- STSD ---
type StsdBox struct {
   Header       *BoxHeader
   HeaderFields [8]byte // Ver(1)+Flags(3)+EntryCount(4)
   EncChildren  []*EncBox
   RawChildren  [][]byte
}

func DecodeStsdBox(data []byte) (*StsdBox, error) {
   b := &StsdBox{}
   var err error
   if b.Header, err = DecodeBoxHeader(data); err != nil {
      return nil, err
   }
   if len(data) < 16 {
      return nil, errors.New("stsd box too short")
   }
   copy(b.HeaderFields[:], data[8:16])

   err = walkBoxes(boxPayloadFrom(data, b.Header, 16), func(typ [4]byte, content []byte) error {
      switch string(typ[:]) {
      case "encv", "enca":
         enc, decErr := DecodeEncBox(content)
         if decErr != nil {
            return decErr
         }
         b.EncChildren = append(b.EncChildren, enc)
      default:
         b.RawChildren = append(b.RawChildren, content)
      }
      return nil
   })
   if err != nil {
      return nil, err
   }
   return b, nil
}

func (b *StsdBox) Encode() []byte {
   children := make([][]byte, 0, len(b.EncChildren)+len(b.RawChildren))
   for _, child := range b.EncChildren {
      children = append(children, child.Encode())
   }
   children = append(children, b.RawChildren...)
   return encodeBox(b.Header, b.HeaderFields[:], children)
}

// RemoveSinf turns each encrypted sample entry into its plain form: the
// entry type becomes the original format from frma and the sinf box is
// dropped.
func (b *StsdBox) RemoveSinf() {
   for _, child := range b.EncChildren {
      if child.Sinf == nil || child.Sinf.Frma == nil {
         continue
      }
      child.Header.Type = child.Sinf.Frma.DataFormat
      child.Sinf = nil
   }
}

// --- TRAK ---
type TrakBox struct {
   Header      *BoxHeader
   Mdia        *MdiaBox
   RawChildren [][]byte
}

func DecodeTrakBox(data []byte) (*TrakBox, error) {
   b := &TrakBox{}
   var err error
   if b.Header, err = DecodeBoxHeader(data); err != nil {
      return nil, err
   }
   err = walkBoxes(boxPayload(data, b.Header), func(typ [4]byte, content []byte) error {
      if string(typ[:]) != "mdia" {
         b.RawChildren = append(b.RawChildren, content)
         return nil
      }
      mdia, decErr := DecodeMdiaBox(content)
      if decErr != nil {
         return decErr
      }
      b.Mdia = mdia
      return nil
   })
   if err != nil {
      return nil, err
   }
   return b, nil
}

func (b *TrakBox) Encode() []byte {
   var children [][]byte
   if b.Mdia != nil {
      children = append(children, b.Mdia.Encode())
   }
   children = append(children, b.RawChildren...)
   return encodeBox(b.Header, nil, children)
}

func (b *TrakBox) RemoveEdts() {
   b.RawChildren = removeChildren(b.RawChildren, "edts")
}

// track.go marker preserve
