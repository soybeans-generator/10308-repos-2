// protobuf.go marker preserve
package widevine

import (
   "41.neocities.org/protobuf"
   "crypto/aes"
   "crypto/cipher"
   "crypto/rsa"
   "crypto/sha1"
   "encoding/binary"
   "errors"
   "fmt"
   "github.com/emmansun/gmsm/cbcmac"
   "github.com/emmansun/gmsm/padding"
)

const (
   kWrappingKeyLabel    = "ENCRYPTION"
   kWrappingKeySizeBits = 128
)

// EncodeSignedMessage envelopes the request with an RSA signature.
func EncodeSignedMessage(requestData []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
   signature, err := signMessage(requestData, privateKey)
   if err != nil {
      return nil, err
   }
   message := protobuf.Message{
      protobuf.Varint(1, 1), // LICENSE_REQUEST
      protobuf.Bytes(2, requestData),
      protobuf.Bytes(3, signature),
   }
   return message.Encode()
}

func decodeErrorFromMessage(message protobuf.Message) error {
   errorCode, ok := message.Field(1)
   if !ok || errorCode == nil {
      return errors.New("widevine license error: unknown code")
   }
   return fmt.Errorf("widevine license error: code %v", errorCode.Numeric)
}

func DecodeLicenseResponse(responseData []byte, requestData []byte, privateKey *rsa.PrivateKey) ([]*KeyContainer, error) {
   message, err := protobuf.DecodeMessage(responseData)
   if err != nil {
      return nil, fmt.Errorf("failed to parse SignedMessage: %w", err)
   }

   typeField, ok := message.Field(1)
   if !ok {
      return nil, errors.New("missing message type")
   }

   msgField, ok := message.Field(2)
   if !ok || msgField.Message == nil {
      return nil, errors.New("missing message payload")
   }

   switch typeField.Numeric {
   case 2: // LICENSE
      sessionKeyField, ok := message.Field(4)
      if !ok {
         return nil, errors.New("missing session_key")
      }
      decKey, err := rsa.DecryptOAEP(sha1.New(), nil, privateKey, sessionKeyField.Bytes, nil)
      if err != nil {
         return nil, err
      }
      return decodeLicenseFromMessage(msgField.Message, requestData, decKey)
   case 3: // ERROR_RESPONSE
      return nil, decodeErrorFromMessage(msgField.Message)
   }
   return nil, fmt.Errorf("unsupported message type: %d", typeField.Numeric)
}

func decodeLicenseFromMessage(message protobuf.Message, requestData []byte, sessionKey []byte) ([]*KeyContainer, error) {
   cmacCipher, err := aes.NewCipher(sessionKey)
   if err != nil {
      return nil, fmt.Errorf("failed to create AES cipher for CMAC: %w", err)
   }

   kdfInput := append([]byte{0x01}, []byte(kWrappingKeyLabel)...)
   kdfInput = append(kdfInput, 0x00)
   kdfInput = append(kdfInput, requestData...)
   sizeBytes := make([]byte, 4)
   binary.BigEndian.PutUint32(sizeBytes, kWrappingKeySizeBits)
   kdfInput = append(kdfInput, sizeBytes...)

   derivedKey := cbcmac.NewCMAC(cmacCipher, 16).MAC(kdfInput)
   ckCipher, err := aes.NewCipher(derivedKey)
   if err != nil {
      return nil, fmt.Errorf("failed to create AES cipher for content key: %w", err)
   }

   var keys []*KeyContainer
   it := message.Iterator(3)
   for it.Next() {
      if it.Field().Message == nil {
         continue
      }
      kc := &KeyContainer{}
      m := it.Field().Message
      if f, ok := m.Field(1); ok {
         kc.Id = f.Bytes
      }
      if f, ok := m.Field(2); ok {
         kc.Iv = f.Bytes
      }
      if f, ok := m.Field(3); ok {
         dec := cipher.NewCBCDecrypter(ckCipher, kc.Iv)
         plain := make([]byte, len(f.Bytes))
         dec.CryptBlocks(plain, f.Bytes)
         unpadded, err := padding.NewPKCS7Padding(aes.BlockSize).Unpad(plain)
         if err != nil {
            return nil, fmt.Errorf("failed to unpad key: %w", err)
         }
         kc.Key = unpadded
      }
      keys = append(keys, kc)
   }
   return keys, nil
}

// PsshData represents the Widevine-specific protobuf message.
type PsshData struct {
   KeyIds    [][]byte
   ContentId []byte
}

// DecodePsshData parses the protobuf wire format into a PsshData struct.
func DecodePsshData(data []byte) (*PsshData, error) {
   message, err := protobuf.DecodeMessage(data)
   if err != nil {
      return nil, err
   }

   p := &PsshData{}
   it := message.Iterator(2)
   for it.Next() {
      if field := it.Field(); field != nil {
         p.KeyIds = append(p.KeyIds, field.Bytes)
      }
   }
   if field, ok := message.Field(4); ok {
      p.ContentId = field.Bytes
   }
   return p, nil
}

// Encode serializes the PsshData struct into the protobuf wire format.
func (p *PsshData) Encode() ([]byte, error) {
   var message protobuf.Message
   for _, keyId := range p.KeyIds {
      if len(keyId) > 0 {
         message = append(message, protobuf.Bytes(2, keyId))
      }
   }
   if len(p.ContentId) > 0 {
      message = append(message, protobuf.Bytes(4, p.ContentId))
   }
   return message.Encode()
}

// EncodeLicenseRequest creates and serializes a LicenseRequest protobuf message.
func (p *PsshData) EncodeLicenseRequest(clientId []byte) ([]byte, error) {
   psshBytes, err := p.Encode()
   if err != nil {
      return nil, err
   }
   psshDataField := protobuf.Bytes(1, psshBytes)
   widevinePsshData := protobuf.Embed(1, psshDataField)
   contentIdentification := protobuf.Embed(2, widevinePsshData)

   message := protobuf.Message{
      protobuf.Bytes(1, clientId),
      contentIdentification,
      protobuf.Varint(3, 1), // NEW
   }
   return message.Encode()
}

// protobuf.go marker preserve
