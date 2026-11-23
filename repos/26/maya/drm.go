// drm.go KEEP THIS LINE
package maya

import (
   "bytes"
   "encoding/hex"
   "errors"
   "fmt"
   "log"
   "os"
   "path/filepath"
   "strings"

   "41.neocities.org/luna/dash"
   "41.neocities.org/playReady"
   "41.neocities.org/sofia"
   "41.neocities.org/widevine"
)

const (
   playReadySystemID = "9a04f07998404286ab92e65be0885f95"
   widevineSystemID  = "edef8ba979d64acea3c827dcd51d21ed"

   widevinePsshURN = "urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed"
)

var (
   playReadyId = decodeSystemId(playReadySystemID)
   widevineId  = decodeSystemId(widevineSystemID)
)

// decodeSystemId decodes a hex DRM system ID. The inputs are constants, so a
// failure is a programming error rather than something a caller can handle.
func decodeSystemId(hexId string) []byte {
   id, err := hex.DecodeString(hexId)
   if err != nil {
      panic(err)
   }
   return id
}

// getKeyForStream fetches the key for a stream, preferring the content ID
// from the manifest and the key ID from the initialization segment.
func getKeyForStream(fetchKey keyFetcher, manifestProtection, initProtection *protectionInfo) ([]byte, error) {
   var contentId []byte
   switch {
   case manifestProtection != nil && len(manifestProtection.ContentId) > 0:
      contentId = manifestProtection.ContentId
      log.Printf("content ID from manifest: %x", contentId)
   case initProtection != nil && len(initProtection.ContentId) > 0:
      contentId = initProtection.ContentId
      log.Printf("content ID from MP4: %x", contentId)
   }

   var keyId []byte
   if initProtection != nil && initProtection.KeyId != nil {
      keyId = initProtection.KeyId
      log.Printf("key ID from MP4 tenc: %x", keyId)
   }
   if keyId == nil {
      log.Println("no key ID found in MP4 'tenc' box; assuming stream is not encrypted")
      return nil, nil
   }

   key, err := fetchKey(keyId, contentId)
   if err != nil {
      return nil, fmt.Errorf("fetch decryption key: %w", err)
   }
   return key, nil
}

func playReadyKey(device string, keyId []byte, contentId string, fetchLicense func([]byte) ([]byte, error)) ([]byte, error) {
   certData, err := os.ReadFile(filepath.Join(device, "bdevcert.dat"))
   if err != nil {
      return nil, err
   }
   chain, err := playReady.ParseChain(certData)
   if err != nil {
      return nil, err
   }

   signingData, err := os.ReadFile(filepath.Join(device, "zprivsig.dat"))
   if err != nil {
      return nil, err
   }
   signingKey, err := playReady.ParseRawPrivateKey(signingData)
   if err != nil {
      return nil, err
   }

   encryptData, err := os.ReadFile(filepath.Join(device, "zprivencr.dat"))
   if err != nil {
      return nil, err
   }
   encryptKey, err := playReady.ParseRawPrivateKey(encryptData)
   if err != nil {
      return nil, err
   }

   playReady.UuidOrGuid(keyId)
   request, err := chain.LicenseRequestBytes(signingKey, keyId, contentId)
   if err != nil {
      return nil, err
   }
   response, err := fetchLicense(request)
   if err != nil {
      return nil, err
   }
   license, err := playReady.ParseLicense(response)
   if err != nil {
      return nil, err
   }
   if !bytes.Equal(license.ContainerOuter.ContainerKeys.ContentKey.GuidKeyID, keyId) {
      return nil, errors.New("key ID mismatch")
   }

   key, err := license.Decrypt(encryptKey)
   if err != nil {
      return nil, err
   }
   log.Printf("key: %x", key)
   return key, nil
}

func widevineKey(device string, keyId, contentId []byte, fetchLicense func([]byte) ([]byte, error)) ([]byte, error) {
   clientId, err := os.ReadFile(filepath.Join(device, "device_client_id_blob"))
   if err != nil {
      return nil, err
   }
   pemData, err := os.ReadFile(filepath.Join(device, "device_private_key"))
   if err != nil {
      return nil, err
   }

   pssh := widevine.PsshData{
      ContentId: contentId,
      KeyIds:    [][]byte{keyId},
   }
   requestData, err := pssh.EncodeLicenseRequest(clientId)
   if err != nil {
      return nil, err
   }
   privateKey, err := widevine.DecodePrivateKey(pemData)
   if err != nil {
      return nil, err
   }
   signedData, err := widevine.EncodeSignedMessage(requestData, privateKey)
   if err != nil {
      return nil, err
   }
   responseData, err := fetchLicense(signedData)
   if err != nil {
      return nil, err
   }

   keys, err := widevine.DecodeLicenseResponse(responseData, requestData, privateKey)
   if err != nil {
      return nil, err
   }
   key, err := widevine.GetKey(keys, keyId)
   if err != nil {
      return nil, err
   }
   var zero [16]byte
   if bytes.Equal(key, zero[:]) {
      return nil, errors.New("zero key received")
   }

   log.Printf("key: %x", key)
   return key, nil
}

// keyFetcher returns the content key for a key ID and content ID.
type keyFetcher func(keyId, contentId []byte) ([]byte, error)

// protectionInfo holds the identifiers needed to request a license.
type protectionInfo struct {
   ContentId []byte
   KeyId     []byte
}

// getDashProtection extracts the Widevine content ID from a representation.
func getDashProtection(rep *dash.Representation) (*protectionInfo, error) {
   var psshData []byte
   for _, contentProtection := range rep.GetContentProtection() {
      if !strings.EqualFold(contentProtection.SchemeIdUri, widevinePsshURN) {
         continue
      }
      pssh, err := contentProtection.GetPssh()
      if err != nil {
         return nil, fmt.Errorf("parse widevine pssh from manifest: %w", err)
      }
      if pssh != nil {
         psshData = pssh
         break
      }
   }
   if psshData == nil {
      return nil, nil
   }

   psshData, err := sofia.ExtractPsshData(psshData)
   if err != nil {
      return nil, fmt.Errorf("extract pssh data: %w", err)
   }
   widevineData, err := widevine.DecodePsshData(psshData)
   if err != nil {
      return nil, fmt.Errorf("decode widevine pssh data: %w", err)
   }
   return &protectionInfo{ContentId: widevineData.ContentId}, nil
}

// keyFetcher returns the key fetcher selected by the DRM options, or nil
// when no DRM is configured. A nil Options means no DRM.
func (options *Options) keyFetcher() (keyFetcher, error) {
   if options == nil || options.Drm == DrmNone {
      return nil, nil
   }
   if options.License == nil {
      return nil, errors.New("a License function is required when DRM is specified")
   }
   if options.Device == "" {
      return nil, errors.New("a Device path is required when DRM is specified")
   }

   switch options.Drm {
   case DrmWidevine:
      return func(keyId, contentId []byte) ([]byte, error) {
         return widevineKey(options.Device, keyId, contentId, options.License)
      }, nil
   case DrmPlayReady:
      return func(keyId, contentId []byte) ([]byte, error) {
         return playReadyKey(options.Device, keyId, string(contentId), options.License)
      }, nil
   default:
      return nil, fmt.Errorf("unsupported DRM system: %v", options.Drm)
   }
}

// drm.go KEEP THIS LINE
