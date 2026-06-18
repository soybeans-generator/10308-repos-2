package playReady

import (
   "bytes"
   "encoding/base64"
   "encoding/json"
   "io"
   "net/http"
   "net/url"
   "os"
   "testing"
)

func TestPrimeVideoLicense(t *testing.T) {
   // Read your Chain and Private Key from disk
   // You will need to provide these to generate a valid licenseChallenge
   chainData, err := os.ReadFile(
      `C:\Users\Steven\AppData\Local\SL3000\bdevcert.dat`,
   )
   if err != nil {
      t.Fatal("chain.bin not found, skipping test...")
   }
   signKeyData, err := os.ReadFile(
      `C:\Users\Steven\AppData\Local\SL3000\zprivsig.dat`,
   )
   if err != nil {
      t.Fatal("sign.key not found, skipping test...")
   }
   chain, err := ParseChain(chainData)
   if err != nil {
      t.Fatalf("failed to parse chain: %v", err)
   }
   signKey, err := ParseRawPrivateKey(signKeyData)
   if err != nil {
      t.Fatalf("failed to parse sign key: %v", err)
   }
   kid, _ := base64.StdEncoding.DecodeString("fNnoFS0I40ao394Qc/5yfg==")
   // Generate the license challenge bytes using the loaded chain and key
   challengeBytes, err := chain.LicenseRequestBytes(signKey, kid, "")
   if err != nil {
      t.Fatalf("failed to generate license request: %v", err)
   }
   // Base64 encode the generated XML challenge
   licenseChallenge := base64.StdEncoding.EncodeToString(challengeBytes)
   client := &http.Client{}
   reqURL := &url.URL{
      Scheme: "https",
      Host:   "atv-ps.primevideo.com",
      Path:   "/playback/drm-vod/GetPlayReadyLicense",
   }
   q := url.Values{}
   q.Add("deviceID", "uuidcbb2f9705f13437e9e515622dce02106")
   q.Add("deviceTypeID", "A2SNKIF736WF4T")
   reqURL.RawQuery = q.Encode()
   // Construct the JSON body payload
   payload := map[string]string{
      "licenseChallenge": licenseChallenge,
      "playbackEnvelope": playback_envelope,
   }
   bodyBytes, err := json.Marshal(payload)
   if err != nil {
      t.Fatalf("failed to marshal json payload: %v", err)
   }
   req, err := http.NewRequest("POST", reqURL.String(), bytes.NewReader(bodyBytes))
   if err != nil {
      t.Fatalf("failed to create http request: %v", err)
   }
   // Set the required headers
   req.Header.Set("Authorization", authorization)
   req.Header.Set("Content-Type", "application/json")
   // Execute the request
   resp, err := client.Do(req)
   if err != nil {
      t.Fatalf("http request failed: %v", err)
   }
   defer resp.Body.Close()
   respBody, _ := io.ReadAll(resp.Body)
   // Validate the 200 OK status as requested
   if resp.StatusCode != 200 {
      t.Fatalf("expected 200 OK, got %d:\n%s", resp.StatusCode, string(respBody))
   }
   t.Logf("Success! Got 200 OK.\nResponse: %s", string(respBody))
}

const (
   authorization     = "Bearer Atna|EwMDIB0AunR2jTXUjuExekfZQ2mdUyKc5o-CmnWKUmYc5hUYBpA-l2xhYuHmf6h5KILfGF9fPdPA6_LuVHNh755h8om-iYbjm3IJqVtUkZGlCQU0ZwAtvs9dzhznpln07L_JlHWtbSuSVEHuj9-hr8P0QvTZXJq9hvFjoL1WTha2zhCNVlrZuf4grh4c9_wqpG60zG5cHwY_W6iTOfj0oa7AgjNb23MiJ5AQH_IHifrTMzqnijUGIo5RQKNtXT8-3vI_9kvfKU1TjqKqaXZc4xdAujfMqYAUbvIKUR1DJs7wok8RLuQc06w4L23Z0Hg_vjoz0DNG_B2_AIynm15VmoJbGH_MmGV7DnhQyywz3hm-7wkgrs3ePykp5r_rhBtoY1OYsHAgUBl68aPGV89eapNF836r93CKBCFs1DCDRH8dAF5KBAP6lAMozZpkbf3ztvRQHyc"
   playback_envelope = "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"
)
