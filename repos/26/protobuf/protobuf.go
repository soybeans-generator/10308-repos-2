// Package protobuf is a schema-less Protocol Buffer decoder.
//
// Decode turns wire bytes into a flat list of field occurrences; Values returns
// every occurrence of a given field number, First returns just the first.
// Encode is the inverse of Decode. NewVarint, NewBytes and NewMessage build
// values by hand; NewMessage takes child values, so messages nest to any depth.
//
// A Value is either a leaf or a container:
//
//   WireVarint, WireI64 -> Uint
//   WireI32             -> Uint (zero-extended; use uint32(v.Uint))
//   WireBytes           -> Bytes (decoded) or Children (constructed)
//
// Construction never fails; Encode validates the whole tree. The package
// depends only on the standard library.
package protobuf

import (
   "encoding/binary"
   "fmt"
)

// maxFieldNumber is the largest legal protobuf field number, 2^29-1.
const maxFieldNumber = 1<<29 - 1

// appendTag writes a field tag.
func appendTag(b []byte, field int, wireType WireType) []byte {
   return appendVarint(b, uint64(field)<<3|uint64(wireType))
}

// appendVarint writes x in base-128 form.
func appendVarint(b []byte, x uint64) []byte {
   for x >= 0x80 {
      b = append(b, byte(x)|0x80)
      x >>= 7
   }
   return append(b, byte(x))
}

// consumeVarint decodes a base-128 varint and reports its encoded length.
func consumeVarint(b []byte) (uint64, int, error) {
   var x uint64

   for i := 0; i < len(b); i++ {
      c := b[i]
      if i == 9 && c > 1 {
         return 0, 0, fmt.Errorf("varint overflows 64 bits")
      }
      x |= uint64(c&0x7f) << (7 * uint(i))
      if c < 0x80 {
         return x, i + 1, nil
      }
   }

   return 0, 0, fmt.Errorf("unexpected end of buffer")
}

// Message is a payload: an ordered list of fields.
type Message []*Value

// Decode parses wire-format bytes. Field order and duplicates are preserved.
func Decode(b []byte) (Message, error) {
   orig := b
   m := make(Message, 0, 8)

   for len(b) > 0 {
      offset := len(orig) - len(b)

      v, n, err := consume(b)
      if err != nil {
         return nil, fmt.Errorf("protobuf: offset %d: %w", offset, err)
      }
      b = b[n:]
      m = append(m, v)
   }
   return m, nil
}

// Encode writes m in wire format, the inverse of Decode: decoding the result
// yields an equivalent Message. Fields are emitted in slice order and children
// are encoded recursively.
func (m Message) Encode() ([]byte, error) {
   out := make([]byte, 0, 64)

   for i, v := range m {
      if v == nil {
         return nil, fmt.Errorf("protobuf: index %d: nil value", i)
      }
      if v.Field < 1 || v.Field > maxFieldNumber {
         return nil, fmt.Errorf("protobuf: index %d: invalid field number %d", i, v.Field)
      }

      out = appendTag(out, v.Field, v.Type)

      switch v.Type {
      case WireVarint:
         out = appendVarint(out, v.Uint)
      case WireI64:
         out = binary.LittleEndian.AppendUint64(out, v.Uint)
      case WireI32:
         out = binary.LittleEndian.AppendUint32(out, uint32(v.Uint))
      case WireBytes:
         payload := v.Bytes
         if v.Children != nil {
            p, err := v.Children.Encode()
            if err != nil {
               return nil, fmt.Errorf("protobuf: field %d: %w", v.Field, err)
            }
            payload = p
         }
         out = appendVarint(out, uint64(len(payload)))
         out = append(out, payload...)
      default:
         return nil, fmt.Errorf("protobuf: field %d: unsupported wire type %d", v.Field, v.Type)
      }
   }

   return out, nil
}

// First returns the first occurrence of the given field number. The pointer is
// nil and ok is false if the field does not occur.
func (m Message) First(field int) (*Value, bool) {
   for _, v := range m {
      if v.Field == field {
         return v, true
      }
   }
   return nil, false
}

// Values returns every occurrence of the given field number, in wire order.
func (m Message) Values(field int) []*Value {
   var out []*Value
   for _, v := range m {
      if v.Field == field {
         out = append(out, v)
      }
   }
   return out
}

// Value is one field: a leaf payload or a container of child values.
type Value struct {
   Field    int      // field number
   Type     WireType // wire type
   Uint     uint64   // numeric payload; WireI32 uses the low 32 bits
   Bytes    []byte   // payload of a decoded value; aliases the source buffer
   Children Message  // payload of a constructed value; takes precedence over Bytes
}

// NewBytes returns a length-delimited value for the given field. The slice is
// not copied, so it must stay valid until the value is encoded.
func NewBytes(field int, b []byte) *Value {
   return &Value{Field: field, Type: WireBytes, Bytes: b}
}

// NewMessage returns a length-delimited value for the given field holding the
// given children as an embedded message. Children are encoded by Encode, so
// this cannot fail and calls nest freely.
func NewMessage(field int, children ...*Value) *Value {
   return &Value{Field: field, Type: WireBytes, Children: children}
}

// NewVarint returns a varint value for the given field.
func NewVarint(field int, n uint64) *Value {
   return &Value{Field: field, Type: WireVarint, Uint: n}
}

// consume decodes one field from the front of b and reports how many bytes it
// occupied, tag included.
func consume(b []byte) (*Value, int, error) {
   field, wireType, tagLen, err := consumeTag(b)
   if err != nil {
      return nil, 0, err
   }

   rest := b[tagLen:]
   v := &Value{Field: field, Type: wireType}
   total := tagLen

   switch wireType {
   case WireVarint:
      x, n, err := consumeVarint(rest)
      if err != nil {
         return nil, 0, fmt.Errorf("field %d: %w", field, err)
      }
      v.Uint, total = x, total+n

   case WireI64:
      if len(rest) < 8 {
         return nil, 0, fmt.Errorf("field %d: unexpected end of buffer", field)
      }
      v.Uint, total = binary.LittleEndian.Uint64(rest), total+8

   case WireI32:
      if len(rest) < 4 {
         return nil, 0, fmt.Errorf("field %d: unexpected end of buffer", field)
      }
      v.Uint, total = uint64(binary.LittleEndian.Uint32(rest)), total+4

   case WireBytes:
      length, n, err := consumeVarint(rest)
      if err != nil {
         return nil, 0, fmt.Errorf("field %d: length: %w", field, err)
      }
      if length > uint64(len(rest)-n) {
         return nil, 0, fmt.Errorf("field %d: length %d exceeds %d remaining bytes", field, length, len(rest)-n)
      }
      v.Bytes = rest[n : n+int(length)]
      total += n + int(length)
   }

   return v, total, nil
}

// Message returns the value's payload as an embedded message: the children of a
// constructed value, or the decoded payload of a length-delimited one.
func (v *Value) Message() (Message, error) {
   if v == nil {
      return nil, fmt.Errorf("protobuf: nil value")
   }
   if v.Children != nil {
      return v.Children, nil
   }
   if v.Type != WireBytes {
      return nil, fmt.Errorf("protobuf: field %d: wire type %d is not an embedded message", v.Field, v.Type)
   }
   return Decode(v.Bytes)
}

// WireType is the encoding of a field's payload on the wire.
type WireType uint8

const (
   WireVarint WireType = 0 // base-128 varint
   WireI64    WireType = 1 // 8 bytes, little-endian
   WireBytes  WireType = 2 // varint length, then that many bytes
   WireI32    WireType = 5 // 4 bytes, little-endian
)

// consumeTag decodes a field tag.
func consumeTag(b []byte) (int, WireType, int, error) {
   x, n, err := consumeVarint(b)
   if err != nil {
      return 0, 0, 0, fmt.Errorf("tag: %w", err)
   }

   field := x >> 3
   if field < 1 || field > maxFieldNumber {
      return 0, 0, 0, fmt.Errorf("tag: invalid field number %d", field)
   }

   wireType := WireType(x & 7)
   switch wireType {
   case WireVarint, WireI64, WireBytes, WireI32:
   default:
      return 0, 0, 0, fmt.Errorf("tag: unsupported wire type %d", wireType)
   }

   return int(field), wireType, n, nil
}
