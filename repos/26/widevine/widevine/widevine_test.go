package widevine

import (
   "bytes"
   "encoding/base64"
   "encoding/json"
   "fmt"
   "net/http"
   "net/url"
   "os"
   "testing"
)

func TestLicense(t *testing.T) {
   // read private key
   pemData, err := os.ReadFile(`C:\Users\Steven\AppData\Local\L3\private_key.pem`)
   if err != nil {
      t.Fatal(err)
   }
   privateKey, err := DecodePrivateKey(pemData)
   if err != nil {
      t.Fatal(err)
   }

   // read client ID
   clientId, err := os.ReadFile(`C:\Users\Steven\AppData\Local\L3\client_id.bin`)
   if err != nil {
      t.Fatal(err)
   }

   // decode PSSH data
   psshRaw, err := base64.StdEncoding.DecodeString(
      "CAESENlROAqEW0/uqlhMioe8fWMaBmFtYXpvbiI1Y2lkOjB4YUQ4bzJPUm9XYTluZHFSVjlqRGc9PSwyVkU0Q29SYlQrNnFXRXlLaDd4OVl3PT0qAlNEMgA=",
   )
   if err != nil {
      t.Fatal(err)
   }
   pssh, err := DecodePsshData(psshRaw)
   if err != nil {
      t.Fatal(err)
   }

   // build license request
   requestData, err := pssh.EncodeLicenseRequest(clientId)
   if err != nil {
      t.Fatal(err)
   }

   // sign the request
   signedData, err := EncodeSignedMessage(requestData, privateKey)
   if err != nil {
      t.Fatal(err)
   }

   // build the HTTP request
   challenge := base64.StdEncoding.EncodeToString(signedData)
   body := map[string]any{
      "includeHdcpTestKey": true,
      "licenseChallenge":   challenge,
   }
   bodyData, err := json.Marshal(body)
   if err != nil {
      t.Fatal(err)
   }

   reqURL := &url.URL{
      Scheme: "https",
      Host:   "ab8mt4dd97et.na.api.amazonvideo.com",
      Path:   "/playback/drm-vod/GetWidevineLicense",
   }
   q := url.Values{}
   q.Set("deviceID", "uuidcbb2f9705f13437e9e515622dce02106")
   q.Set("deviceTypeID", "A2SNKIF736WF4T")
   q.Set("gascEnabled", "false")
   q.Set("marketplaceID", "ATVPDKIKX0DER")
   q.Set("uxLocale", "en-US")
   q.Set("firmware", "1")
   q.Set("titleId", "amzn1.dv.gti.28b85d90-1338-720b-4be7-3247683a7624")
   reqURL.RawQuery = q.Encode()

   req, err := http.NewRequest("POST", reqURL.String(), bytes.NewReader(bodyData))
   if err != nil {
      t.Fatal(err)
   }
   req.Header.Set("Accept", "*/*")
   req.Header.Set("Authorization", "Bearer Atna|EwMDIODjqerb1s19VY8TleIkKR1BEOKexzrLTQXgCGXp0J6itgvkzWwku0_bpHh98e4DXYIDwzGDHgMa2gKlxn5vZsCbc8gJX5f4KgyRzEE-P1hJhKD7t__EQ5WkD-RDOkZ85U9i8JFlv1OyNFF8R67eRToH6e67S1Jv5TmzHo3_JeF3B6iR4KUPj4-Lv1qeSJvmb_xAzuWxjLu0kXdVh934lbGNbdj_dmo7S6ZfiIbGfxJ9_2QnW3_tyC7ONmRUuX8RkPyYvunUcFY8Bxpon-ZjXE2ju5xL1O_weRRku2ehOHBiuLt73sPfqpOSKUK4mO3EsK2BXYUT0qruoZAePhhIrA_iezaUA-M7Dq5nO9ivoIb6pCQFRO0dfKQXjKQmcdplXXFTw1WtyXmGk8dJ28kDmZejh5Muxf4o-Uvp1f_tBKrbuYoXt0MHUjLwtXLIXV1MGZU")
   req.Header.Set("Content-Type", "text/plain")
   req.Header.Set("User-Agent", "Android/google/sdk_gphone_x86/generic_x86_arm:11/RSR1.240422.006/12134477:userdebug/dev-keys, Ignition X/15.5.2026042820-android, Google")

   // send request
   resp, err := http.DefaultClient.Do(req)
   if err != nil {
      t.Fatal(err)
   }
   defer resp.Body.Close()

   fmt.Println("Status:", resp.Status)
   if resp.StatusCode != http.StatusOK {
      t.Fatal("expected 200 OK, got", resp.Status)
   }
}
