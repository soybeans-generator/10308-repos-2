package protobuf

import (
   "bytes"
   "encoding/binary"
   "errors"
   "fmt"
)

var (
   // errOutOfBounds is returned when attempting to read past the end of the buffer.
   errOutOfBounds = errors.New("data is out of bounds")

   // errMalformedVarint is returned when a varint is unterminated or overflows.
   errMalformedVarint = errors.New("malformed varint")

   // errBufferTooSmall is returned when a buffer does not contain enough bytes for a fixed-size value.
   errBufferTooSmall = errors.New("buffer is too small")

   // errInvalidWireType is returned when an unknown or unsupported wire type is encountered.
   errInvalidWireType = errors.New("invalid wire type")

   // errInvalidFieldNumber is returned when a tag has field number 0, which is invalid per the protobuf spec.
   errInvalidFieldNumber = errors.New("invalid field number")
)

// decodeFixed32 decodes a 32-bit little-endian integer from the buffer.
func decodeFixed32(buffer []byte) (uint32, int, error) {
   if len(buffer) < 4 {
      return 0, 0, errBufferTooSmall
   }
   return binary.LittleEndian.Uint32(buffer), 4, nil
}

// decodeFixed64 decodes a 64-bit little-endian integer from the buffer.
func decodeFixed64(buffer []byte) (uint64, int, error) {
   if len(buffer) < 8 {
      return 0, 0, errBufferTooSmall
   }
   return binary.LittleEndian.Uint64(buffer), 8, nil
}

// decodeLengthPrefixed decodes a length-prefixed field from the buffer.
// It returns the length of the data, the number of bytes read for the length header, and an error if any.
func decodeLengthPrefixed(buffer []byte) (uint64, int, error) {
   length, bytesRead := binary.Uvarint(buffer)
   if bytesRead <= 0 {
      return 0, 0, errMalformedVarint
   }
   if uint64(len(buffer)-bytesRead) < length {
      return 0, 0, errOutOfBounds
   }
   return length, bytesRead, nil
}

// Field represents a single, decoded field in a protobuf message.
//
// The tag stays unexported: nothing outside this package inspects it, and
// fields are only ever built through the constructors below or DecodeMessage.
type Field struct {
   tag     *tag
   Numeric uint64
   Bytes   []byte
   Message Message
}

// Bytes creates a new length-delimited field holding raw bytes.
func Bytes(fieldNum uint32, value []byte) *Field {
   return &Field{
      tag:   &tag{number: fieldNum, wireType: wireBytes},
      Bytes: value,
   }
}

// Embed creates a new embedded message field from the provided sub-fields.
func Embed(fieldNum uint32, value ...*Field) *Field {
   return &Field{
      tag:     &tag{number: fieldNum, wireType: wireBytes},
      Message: Message(value),
   }
}

// Varint creates a new Varint field and returns a pointer to it.
func Varint(fieldNum uint32, value uint64) *Field {
   return &Field{
      tag:     &tag{number: fieldNum, wireType: wireVarint},
      Numeric: value,
   }
}

// Message is a named type for a slice of field pointers, representing a
// decoded protobuf message.
type Message []*Field

// DecodeMessage populates a message by decoding the protobuf wire format data.
func DecodeMessage(data []byte) (Message, error) {
   var (
      fields Message
      offset int
   )
   for offset < len(data) {
      t, bytesRead, err := decodeTag(data[offset:])
      if err != nil {
         return nil, fmt.Errorf("failed to decode tag at offset %d: %w", offset, err)
      }
      offset += bytesRead

      field := Field{tag: t}
      var dataLength int

      switch t.wireType {
      case wireVarint:
         val, bytesRead := binary.Uvarint(data[offset:])
         if bytesRead <= 0 {
            return nil, fmt.Errorf("failed to decode varint for field %d at offset %d: %w", t.number, offset, errMalformedVarint)
         }
         field.Numeric = val
         dataLength = bytesRead

      case wireFixed32:
         val, bytesRead, err := decodeFixed32(data[offset:])
         if err != nil {
            return nil, fmt.Errorf("failed to decode fixed32 for field %d: %w", t.number, err)
         }
         field.Numeric = uint64(val)
         dataLength = bytesRead

      case wireFixed64:
         val, bytesRead, err := decodeFixed64(data[offset:])
         if err != nil {
            return nil, fmt.Errorf("failed to decode fixed64 for field %d: %w", t.number, err)
         }
         field.Numeric = val
         dataLength = bytesRead

      case wireBytes:
         length, bytesRead, err := decodeLengthPrefixed(data[offset:])
         if err != nil {
            return nil, fmt.Errorf("failed to decode length for field %d: %w", t.number, err)
         }
         offset += bytesRead
         dataLength = int(length)

         // Copy rather than aliasing data[offset:offset+dataLength]: a
         // sub-slice would pin the entire parent buffer for as long as
         // this one field is retained.
         field.Bytes = make([]byte, dataLength)
         copy(field.Bytes, data[offset:offset+dataLength])

      default:
         return nil, fmt.Errorf("%w %d for field %d at offset %d", errInvalidWireType, t.wireType, t.number, offset)
      }

      offset += dataLength
      fields = append(fields, &field)
   }

   return fields, nil
}

// Encode serializes the message into the protobuf wire format.
//
// For wireBytes fields, Bytes takes precedence: if it is non-nil, it is
// written verbatim. Message is only encoded when Bytes is nil (i.e.,
// fields built via Embed). An empty-but-non-nil Bytes ([]byte{} or
// []byte("")) encodes as a zero-length field, same as an empty Message.
func (m Message) Encode() ([]byte, error) {
   var buffer bytes.Buffer
   // Allocate a small buffer on the stack to prevent heap allocations inside the loop
   var scratch [binary.MaxVarintLen64]byte

   for _, field := range m {
      if field == nil || field.tag == nil {
         return nil, fmt.Errorf("cannot encode field: nil field or nil tag")
      }

      // Validate the field number before writing anything, mirroring
      // decodeTag. Valid field numbers are 1 through 2^29-1 per the
      // protobuf spec; emitting anything else would produce output that
      // this package's own decoder rejects with errInvalidFieldNumber.
      if num := field.tag.number; num == 0 || num > 536_870_911 {
         return nil, fmt.Errorf("%w %d for encoding", errInvalidFieldNumber, num)
      }

      var valueBytes []byte

      if field.tag.wireType == wireBytes {
         if field.Bytes == nil {
            // No raw bytes: treat the field as an embedded message.
            // Note: Encode on a nil Message is safe and yields no bytes,
            // so Embed(1) with no sub-fields encodes as a zero-length field.
            encoded, err := field.Message.Encode()
            if err != nil {
               return nil, fmt.Errorf("failed to encode embedded message for field %d: %w", field.tag.number, err)
            }
            valueBytes = encoded
         } else {
            valueBytes = field.Bytes
         }
      }

      // Create tag: (Field Number << 3) | Wire Type
      tagValue := uint64(field.tag.number)<<3 | uint64(field.tag.wireType)
      n := binary.PutUvarint(scratch[:], tagValue)
      buffer.Write(scratch[:n])

      switch field.tag.wireType {
      case wireVarint:
         n := binary.PutUvarint(scratch[:], field.Numeric)
         buffer.Write(scratch[:n])
      case wireFixed32:
         binary.LittleEndian.PutUint32(scratch[:4], uint32(field.Numeric))
         buffer.Write(scratch[:4])
      case wireFixed64:
         binary.LittleEndian.PutUint64(scratch[:8], field.Numeric)
         buffer.Write(scratch[:8])
      case wireBytes:
         n := binary.PutUvarint(scratch[:], uint64(len(valueBytes)))
         buffer.Write(scratch[:n])
         buffer.Write(valueBytes)
      default:
         return nil, fmt.Errorf("%w %d for encoding field %d", errInvalidWireType, field.tag.wireType, field.tag.number)
      }
   }
   return buffer.Bytes(), nil
}

// Field finds and returns the first field matching the given field number.
// The boolean return value is false if no matching field is found.
func (m Message) Field(fieldNum uint32) (*Field, bool) {
   iterator := m.Iterator(fieldNum)
   if iterator.Next() {
      return iterator.Field(), true
   }
   return nil, false
}

// Iterator creates a new iterator to loop over all fields with the given number.
func (m Message) Iterator(fieldNum uint32) *iterator {
   return &iterator{
      message:  m,
      fieldNum: fieldNum,
      cursor:   -1,
   }
}

// iterator provides a stateful, memory-efficient way to loop over
// all occurrences of a specific field number within a message.
type iterator struct {
   message  Message // The message being iterated over
   fieldNum uint32
   cursor   int // The current index in the message slice
}

// Field returns a pointer to the current field the iterator is pointing to.
func (it *iterator) Field() *Field {
   if it.cursor >= 0 && it.cursor < len(it.message) {
      return it.message[it.cursor]
   }
   return nil
}

// Next advances the iterator to the next matching field. It returns false
// when there are no more matching fields.
func (it *iterator) Next() bool {
   for i := it.cursor + 1; i < len(it.message); i++ {
      field := it.message[i]
      if field == nil || field.tag == nil {
         continue
      }
      if field.tag.number == it.fieldNum {
         it.cursor = i
         return true
      }
   }
   return false
}

// tag represents a field's tag (field number + wire type).
type tag struct {
   number   uint32
   wireType wireType
}

// decodeTag decodes a varint from the input buffer and returns it as a pointer to a tag struct
func decodeTag(buffer []byte) (*tag, int, error) {
   tagValue, bytesRead := binary.Uvarint(buffer)
   if bytesRead <= 0 {
      return nil, 0, errMalformedVarint
   }

   // Keep tagValue as uint64 until validated so the range check is exact.
   // Valid field numbers are 1 through 2^29-1 (536870911) per the protobuf
   // spec; anything larger would be silently truncated by the uint32 cast.
   fieldNum := tagValue >> 3
   if fieldNum == 0 || fieldNum > 536_870_911 {
      return nil, 0, errInvalidFieldNumber
   }

   return &tag{
      number:   uint32(fieldNum),
      wireType: wireType(tagValue & 0x7),
   }, bytesRead, nil
}

// wireType represents the type of data encoding on the wire.
type wireType uint8

const (
   wireVarint  wireType = 0
   wireFixed64 wireType = 1
   wireBytes   wireType = 2
   wireFixed32 wireType = 5
)
