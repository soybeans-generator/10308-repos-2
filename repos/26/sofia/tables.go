// tables.go marker preserve
package sofia

import (
   "encoding/binary"
   "errors"
)

// The sample tables of a progressive MP4. stbl is the container; its child
// boxes map to RemuxSample fields (stts durations, ctts composition time
// offsets, stsz sizes, stss sync flags) and to chunk locations (stsc
// counts, stco/co64 offsets). The table boxes store only their entries:
// headers exist only in encoded bytes and are rebuilt by the encoders.
// The build functions turn remuxer state into the table boxes Finish
// appends to the file.

// buildChunkOffsetBox decides whether to use stco or co64.
func buildChunkOffsetBox(offsets []uint64) []byte {
   for _, offset := range offsets {
      if offset > 0xFFFFFFFF {
         return encodeTable64("co64", offsets)
      }
   }
   entries := make([]uint32, len(offsets))
   for i, offset := range offsets {
      entries[i] = uint32(offset)
   }
   return encodeTable("stco", 0, len(entries), entries)
}

func buildCtts(samples []*RemuxSample) []byte {
   counts, values := runLength(len(samples), func(i int) int32 {
      return samples[i].CompositionTimeOffset
   })
   // buildCtts synthesises the box from samples rather than round-tripping a
   // decoded one, so there is no source version to carry over: version 1 is
   // required as soon as any offset is negative, version 0 otherwise.
   hasCTO := false
   version := byte(0)
   for _, value := range values {
      if value != 0 {
         hasCTO = true
      }
      if value < 0 {
         version = 1
      }
   }
   if !hasCTO {
      return nil // no ctts box needed if all offsets are 0
   }
   raw := make([]uint32, 0, 2*len(counts))
   for i := range counts {
      raw = append(raw, counts[i], uint32(values[i]))
   }
   return encodeTable("ctts", version, len(counts), raw)
}

func buildStsc(counts []uint32) []byte {
   runs, values := runLength(len(counts), func(i int) uint32 { return counts[i] })
   entries := make([]StscEntry, len(runs))
   firstChunk := uint32(1)
   for i := range runs {
      entries[i] = StscEntry{FirstChunk: firstChunk, SamplesPerChunk: values[i], SampleDescriptionIndex: 1}
      firstChunk += runs[i]
   }
   return StscBox{Entries: entries}.Encode()
}

func buildStss(samples []*RemuxSample) []byte {
   var indices []uint32
   for i, sample := range samples {
      if sample.IsSync {
         indices = append(indices, uint32(i+1))
      }
   }
   if len(indices) == len(samples) {
      return nil
   }
   return StssBox{Indices: indices}.Encode()
}

func buildStsz(samples []*RemuxSample) []byte {
   entries := make([]uint32, len(samples))
   for i, sample := range samples {
      entries[i] = sample.Size
   }
   return StszBox{SampleCount: uint32(len(samples)), EntrySizes: entries}.Encode()
}

func buildStts(samples []*RemuxSample) []byte {
   if len(samples) == 0 {
      return nil
   }
   counts, values := runLength(len(samples), func(i int) uint32 { return samples[i].Duration })
   raw := make([]uint32, 0, 2*len(counts))
   for i := range counts {
      raw = append(raw, counts[i], values[i])
   }
   return encodeTable("stts", 0, len(counts), raw)
}

// encodeTable builds a table box: version/flags, entry count, then the
// 4-byte entries.
func encodeTable(name string, version byte, count int, entries []uint32) []byte {
   buffer := make([]byte, 16+len(entries)*4)
   w := writer{buf: buffer, offset: 8}
   w.PutUint32(uint32(version) << 24)
   w.PutUint32(uint32(count))
   for _, entry := range entries {
      w.PutUint32(entry)
   }
   header := &BoxHeader{Size: uint32(len(buffer))}
   copy(header.Type[:], name)
   header.Put(buffer)
   return buffer
}

// encodeTable64 is encodeTable with 8-byte entries.
func encodeTable64(name string, entries []uint64) []byte {
   buffer := make([]byte, 16+len(entries)*8)
   w := writer{buf: buffer, offset: 8}
   w.PutUint32(0) // version and flags
   w.PutUint32(uint32(len(entries)))
   for _, entry := range entries {
      w.PutUint64(entry)
   }
   header := &BoxHeader{Size: uint32(len(buffer))}
   copy(header.Type[:], name)
   header.Put(buffer)
   return buffer
}

// runLength groups consecutive equal values into (count, value) runs.
func runLength[T comparable](n int, valueAt func(int) T) ([]uint32, []T) {
   var counts []uint32
   var values []T
   for i := 0; i < n; i++ {
      value := valueAt(i)
      if k := len(values); k > 0 && values[k-1] == value {
         counts[k-1]++
         continue
      }
      counts = append(counts, 1)
      values = append(values, value)
   }
   return counts, values
}

// tableEntries decodes the common table shape — version/flags, entry
// count, then count entries — and returns the raw entries. T is uint32
// for 4-byte entries and uint64 for 8-byte entries (co64).
func tableEntries[T uint32 | uint64](data []byte) ([]T, error) {
   if len(data) < 16 {
      return nil, errors.New("box too short")
   }
   p := parser{data: data, offset: 8}
   _ = p.Uint32() // version and flags
   count := p.Uint32()
   width := binary.Size(T(0))
   if int(count) > (len(data)-p.offset)/width {
      return nil, errors.New("box too short for declared entries")
   }
   entries := make([]T, count)
   for i := range entries {
      if width == 8 {
         entries[i] = T(p.Uint64())
      } else {
         entries[i] = T(p.Uint32())
      }
   }
   return entries, nil
}

// --- CO64 ---
type Co64Box struct {
   Offsets []uint64
}

func DecodeCo64Box(data []byte) (*Co64Box, error) {
   offsets, err := tableEntries[uint64](data)
   if err != nil {
      return nil, err
   }
   return &Co64Box{Offsets: offsets}, nil
}

func (b Co64Box) Encode() []byte {
   return encodeTable64("co64", b.Offsets)
}

// --- CTTS ---
// CttsBox is the CompositionOffsetBox ('ctts'), ISO/IEC 14496-12 §8.7.2.
//
//   aligned(8) class CompositionOffsetBox extends FullBox('ctts', version, 0) {
//       unsigned int(32) entry_count;
//       int i;
//       if (version == 0) {
//           for (i = 0; i < entry_count; i++) {
//               unsigned int(32) sample_count;
//               unsigned int(32) sample_offset;
//           }
//       } else if (version == 1) {
//           for (i = 0; i < entry_count; i++) {
//               unsigned int(32) sample_count;
//               signed int(32) sample_offset;
//           }
//       }
//   }
//
// The entry layout is identical in both versions; the version decides only
// whether sample_offset is read as unsigned (0) or signed (1). Version 1 is
// required whenever any offset is negative.
type CttsBox struct {
   Version byte
   Entries []CttsEntry
}

func DecodeCttsBox(data []byte) (*CttsBox, error) {
   if len(data) < 16 {
      return nil, errors.New("box too short")
   }
   p := parser{data: data, offset: 8}
   version := byte(p.Uint32() >> 24) // version and flags
   if version > 1 {
      return nil, errors.New("unsupported ctts version")
   }
   count := p.Uint32() // entry count: each entry is 8 bytes
   if int(count) > (len(data)-p.offset)/8 {
      return nil, errors.New("ctts box too short for declared entries")
   }
   b := &CttsBox{Version: version, Entries: make([]CttsEntry, count)}
   for i := range b.Entries {
      b.Entries[i].SampleCount = p.Uint32()
      b.Entries[i].SampleOffset = int32(p.Uint32())
   }
   return b, nil
}

func (b CttsBox) Encode() []byte {
   raw := make([]uint32, 2*len(b.Entries))
   for i, entry := range b.Entries {
      raw[2*i], raw[2*i+1] = entry.SampleCount, uint32(entry.SampleOffset)
   }
   return encodeTable("ctts", b.Version, len(b.Entries), raw)
}

type CttsEntry struct {
   SampleCount  uint32
   SampleOffset int32
}

// --- STBL ---
type StblBox struct {
   Header      *BoxHeader
   Stsd        *StsdBox
   Stts        *SttsBox
   Ctts        *CttsBox
   Stsz        *StszBox
   Stsc        *StscBox
   Stco        *StcoBox
   Co64        *Co64Box
   Stss        *StssBox
   RawChildren [][]byte
}

func DecodeStblBox(data []byte) (*StblBox, error) {
   b := &StblBox{}
   var err error
   if b.Header, err = DecodeBoxHeader(data); err != nil {
      return nil, err
   }
   err = walkBoxes(boxPayload(data, b.Header), func(typ [4]byte, content []byte) error {
      var decErr error
      switch string(typ[:]) {
      case "stsd":
         b.Stsd, decErr = DecodeStsdBox(content)
      case "stts":
         b.Stts, decErr = DecodeSttsBox(content)
      case "ctts":
         b.Ctts, decErr = DecodeCttsBox(content)
      case "stsz":
         b.Stsz, decErr = DecodeStszBox(content)
      case "stsc":
         b.Stsc, decErr = DecodeStscBox(content)
      case "stco":
         b.Stco, decErr = DecodeStcoBox(content)
      case "co64":
         b.Co64, decErr = DecodeCo64Box(content)
      case "stss":
         b.Stss, decErr = DecodeStssBox(content)
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

func (b *StblBox) Encode() []byte {
   var children [][]byte
   if b.Stsd != nil {
      children = append(children, b.Stsd.Encode())
   }
   children = append(children, b.RawChildren...)
   return encodeBox(b.Header, nil, children)
}

// --- STCO ---
type StcoBox struct {
   Offsets []uint32
}

func DecodeStcoBox(data []byte) (*StcoBox, error) {
   offsets, err := tableEntries[uint32](data)
   if err != nil {
      return nil, err
   }
   return &StcoBox{Offsets: offsets}, nil
}

func (b StcoBox) Encode() []byte {
   return encodeTable("stco", 0, len(b.Offsets), b.Offsets)
}

// --- STSC ---
type StscBox struct {
   Entries []StscEntry
}

func DecodeStscBox(data []byte) (*StscBox, error) {
   if len(data) < 16 {
      return nil, errors.New("box too short")
   }
   p := parser{data: data, offset: 8}
   _ = p.Uint32() // version and flags
   count := p.Uint32()
   if int(count) > (len(data)-p.offset)/12 {
      return nil, errors.New("stsc box too short for declared entries")
   }
   b := &StscBox{Entries: make([]StscEntry, count)}
   for i := range b.Entries {
      b.Entries[i].FirstChunk = p.Uint32()
      b.Entries[i].SamplesPerChunk = p.Uint32()
      b.Entries[i].SampleDescriptionIndex = p.Uint32()
   }
   return b, nil
}

func (b StscBox) Encode() []byte {
   raw := make([]uint32, 3*len(b.Entries))
   for i, entry := range b.Entries {
      raw[3*i], raw[3*i+1], raw[3*i+2] = entry.FirstChunk, entry.SamplesPerChunk, entry.SampleDescriptionIndex
   }
   return encodeTable("stsc", 0, len(b.Entries), raw)
}

type StscEntry struct {
   FirstChunk             uint32
   SamplesPerChunk        uint32
   SampleDescriptionIndex uint32
}

// --- STSS ---
type StssBox struct {
   Indices []uint32
}

func DecodeStssBox(data []byte) (*StssBox, error) {
   indices, err := tableEntries[uint32](data)
   if err != nil {
      return nil, err
   }
   return &StssBox{Indices: indices}, nil
}

func (b StssBox) Encode() []byte {
   return encodeTable("stss", 0, len(b.Indices), b.Indices)
}

// --- STSZ ---
type StszBox struct {
   SampleSize  uint32
   SampleCount uint32
   EntrySizes  []uint32
}

func DecodeStszBox(data []byte) (*StszBox, error) {
   if len(data) < 20 {
      return nil, errors.New("stsz box too short")
   }
   p := parser{data: data, offset: 8}
   _ = p.Uint32() // version and flags
   b := &StszBox{}
   b.SampleSize = p.Uint32()
   b.SampleCount = p.Uint32()
   if b.SampleSize != 0 {
      return b, nil // constant sample size: no per-sample entries
   }
   if int(b.SampleCount) > (len(data)-p.offset)/4 {
      return nil, errors.New("stsz box too short for declared entries")
   }
   b.EntrySizes = make([]uint32, b.SampleCount)
   for i := range b.EntrySizes {
      b.EntrySizes[i] = p.Uint32()
   }
   return b, nil
}

func (b StszBox) Encode() []byte {
   buffer := make([]byte, 20+len(b.EntrySizes)*4)
   w := writer{buf: buffer, offset: 8}
   w.PutUint32(0) // version and flags
   w.PutUint32(b.SampleSize)
   w.PutUint32(b.SampleCount)
   for _, size := range b.EntrySizes {
      w.PutUint32(size)
   }
   header := &BoxHeader{Size: uint32(len(buffer))}
   copy(header.Type[:], "stsz")
   header.Put(buffer)
   return buffer
}

// --- STTS ---
type SttsBox struct {
   Entries []SttsEntry
}

func DecodeSttsBox(data []byte) (*SttsBox, error) {
   if len(data) < 16 {
      return nil, errors.New("box too short")
   }
   p := parser{data: data, offset: 8}
   _ = p.Uint32()      // version and flags
   count := p.Uint32() // entry count: each entry is 8 bytes
   if int(count) > (len(data)-p.offset)/8 {
      return nil, errors.New("stts box too short for declared entries")
   }
   b := &SttsBox{Entries: make([]SttsEntry, count)}
   for i := range b.Entries {
      b.Entries[i].SampleCount = p.Uint32()
      b.Entries[i].SampleDuration = p.Uint32()
   }
   return b, nil
}

func (b SttsBox) Encode() []byte {
   raw := make([]uint32, 2*len(b.Entries))
   for i, entry := range b.Entries {
      raw[2*i], raw[2*i+1] = entry.SampleCount, entry.SampleDuration
   }
   return encodeTable("stts", 0, len(b.Entries), raw)
}

type SttsEntry struct {
   SampleCount    uint32
   SampleDuration uint32
}

// tables.go marker preserve
