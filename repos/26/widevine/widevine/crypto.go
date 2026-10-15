// crypto.go marker preserve
package widevine

import (
   "bytes"
   "crypto/rsa"
   "crypto/x509"
   "encoding/pem"
   "errors"
   "fmt"
)

func DecodePrivateKey(pemData []byte) (*rsa.PrivateKey, error) {
   block, _ := pem.Decode(pemData)
   if block == nil {
      return nil, errors.New("failed to decode PEM block containing private key")
   }
   key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
   if err == nil {
      rsaKey, ok := key.(*rsa.PrivateKey)
      if !ok {
         return nil, errors.New("key in PEM block is not an RSA private key")
      }
      return rsaKey, nil
   }
   rsaKey, errPkcs1 := x509.ParsePKCS1PrivateKey(block.Bytes)
   if errPkcs1 != nil {
      return nil, fmt.Errorf("failed to parse private key: PKCS#8 (%v), PKCS#1 (%v)", err, errPkcs1)
   }
   return rsaKey, nil
}

// GetKey searches for a key by its ID in a slice of KeyContainers.
// If the key is found, it returns the key and a nil error.
// If the key is not found, it returns nil and an error.
func GetKey(keys []*KeyContainer, id []byte) ([]byte, error) {
   for _, key := range keys {
      if bytes.Equal(key.Id, id) {
         return key.Key, nil
      }
   }
   return nil, errors.New("key not found")
}

// crypto.go marker preserve
