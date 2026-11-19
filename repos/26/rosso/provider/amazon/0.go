// 0.go marker preserve
package amazon

import (
   "bytes"
   "encoding/json"
   "errors"
   "fmt"
   "net/http"
   "net/url"
   "strings"
)

// the wrong DTID will fail the license request. if you change the DTID you
// need to relog. also if you get a failed license request try provision again.
// this might be UHD also
// > amazon-device -dtid A3GTP8TAF8V3YG
// manufacturer name: Hisense TV
// model number: HU43K3110FW
var Devices = []Device{
   {
      Manufacturer:  "Hisense",
      Model:         "HE55A7000EUWTS",
      SecurityLevel: 3000,
      DeviceTypeID:  "A3REWRVYBYPKUM",
   },
   {
      Manufacturer:  "Hisense",
      Model:         "HU50A6100UW",
      SecurityLevel: 3000,
      DeviceTypeID:  "AAJ692ZPT1X85",
   },
   {
      Manufacturer:  "Hisense",
      Model:         "HU32E5600FHWV",
      SecurityLevel: 3000,
      DeviceTypeID:  "A2RGJ95OVLR12U",
   },
   {
      Manufacturer:  "EXPRESS LUCK TECHNOLOGY LIMITED",
      Model:         "LE-*",
      SecurityLevel: 3000,
      DeviceTypeID:  "A3NM0WFSU3DLT5",
   },
}

func trimURLPath(rawUrl string) (*url.URL, error) {
   parsedURL, err := url.Parse(rawUrl)
   if err != nil {
      return nil, err
   }

   parts := strings.Split(parsedURL.Path, "/")

   // Handle "/dm/3$..." structure
   if len(parts) > 4 && parts[1] == "dm" && strings.HasPrefix(parts[2], "3$") {
      parsedURL.Path = "/" + strings.Join(parts[4:], "/")
      // Handle "/3$..." structure
   } else if len(parts) > 3 && strings.HasPrefix(parts[1], "3$") {
      parsedURL.Path = "/" + strings.Join(parts[3:], "/")
   }

   return parsedURL, nil
}

// PollRegister attempts to register the device. This should typically be called in a loop
// until it returns success (after the user links the device on the web).
func PollRegister(codes *CodePair, deviceTypeID string) (*TokenPair, error) {
   payload := map[string]any{
      "auth_data": map[string]any{
         "code_pair": map[string]string{
            "public_code":  codes.PublicCode,
            "private_code": codes.PrivateCode,
         },
      },
      "registration_data": map[string]string{
         "domain":           DeviceDomain,
         "device_name":      deviceName(),
         "app_name":         AppName,
         "app_version":      AppVersion,
         "device_model":     DeviceModel,
         "os_version":       OSVersion,
         "device_type":      deviceTypeID,
         "device_serial":    DeviceID,
         "software_version": SoftwareVersion,
      },
      "requested_token_type": []string{"bearer"},
   }
   body, err := json.Marshal(payload)
   if err != nil {
      return nil, err
   }
   req, err := http.NewRequest(
      "POST", HostAmazonAPI+"/auth/register", bytes.NewBuffer(body),
   )
   if err != nil {
      return nil, err
   }
   req.Header.Set("content-type", "application/json")

   resp, err := doRequest(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()
   var result struct {
      Response struct {
         Success struct {
            Tokens struct {
               Bearer TokenPair `json:"bearer"`
            } `json:"tokens"`
         } `json:"success"`
         Error struct {
            Code    string `json:"code"`
            Message string `json:"message"`
         } `json:"error"`
      } `json:"response"`
   }
   if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
      return nil, err
   }
   if result.Response.Error.Code != "" {
      return nil, fmt.Errorf("amazon API error: %s - %s", result.Response.Error.Code, result.Response.Error.Message)
   }
   if resp.StatusCode != http.StatusOK {
      return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
   }
   bearer := result.Response.Success.Tokens.Bearer
   return &bearer, nil
}

// CodePair represents the public and private codes used for device linking.
type CodePair struct {
   PublicCode  string `json:"public_code"`
   PrivateCode string `json:"private_code"`
}

// CreateCodePair requests a public and private code pair for device linking.
func CreateCodePair(deviceTypeID string) (*CodePair, error) {
   if deviceTypeID == "" {
      return nil, errors.New("deviceTypeID cannot be empty")
   }

   payload := map[string]any{
      "code_data": map[string]string{
         "domain":           DeviceDomain,
         "device_name":      deviceName(),
         "app_name":         AppName,
         "app_version":      AppVersion,
         "device_model":     DeviceModel,
         "os_version":       OSVersion,
         "device_type":      deviceTypeID,
         "device_serial":    DeviceID,
         "software_version": SoftwareVersion,
      },
   }
   body, err := json.MarshalIndent(payload, "", " ")
   if err != nil {
      return nil, err
   }
   req, err := http.NewRequest(
      "POST", HostAmazonAPI+"/auth/create/codepair",
      bytes.NewBuffer(body),
   )
   if err != nil {
      return nil, err
   }
   req.Header.Set("content-type", "application/json")

   resp, err := doRequest(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()

   if resp.StatusCode != http.StatusOK {
      return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
   }

   // Decode directly into our new struct type
   var result CodePair
   if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
      return nil, err
   }

   return &result, nil
}

func (*CodePair) CachePath() string {
   return "rosso/amazon/CodePair"
}

func (c *CodePair) String() string {
   var data strings.Builder
   data.WriteString("Please navigate to https://amazon.com/gp/ontv\n")
   data.WriteString("Enter the following code: ")
   data.WriteString(c.PublicCode)
   return data.String()
}

// Device represents the metadata for a supported hardware device.
type Device struct {
   Manufacturer  string
   Model         string
   SecurityLevel int
   DeviceTypeID  string
}

func (*TokenPair) CachePath() string {
   return "rosso/amazon/TokenPair"
}

// Refresh exchanges the existing refresh token for a new access token
// using the /auth/token endpoint, mutating the TokenPair in-place.
func (t *TokenPair) Refresh() error {
   if t == nil || t.RefreshToken == "" {
      return fmt.Errorf("invalid token pair or missing refresh token")
   }

   payload := map[string]string{
      "app_name":             "AIV",
      "requested_token_type": "access_token",
      "source_token":         t.RefreshToken,
      "source_token_type":    "refresh_token",
   }
   body, err := json.Marshal(payload)
   if err != nil {
      return err
   }
   req, err := http.NewRequest(
      "POST", HostAmazonAPI+"/auth/token", bytes.NewBuffer(body),
   )
   if err != nil {
      return err
   }
   req.Header.Set("content-type", "application/json")

   resp, err := doRequest(req)
   if err != nil {
      return err
   }
   defer resp.Body.Close()

   // Decode into an anonymous struct handling the expected Python response keys
   var result struct {
      AccessToken string `json:"access_token"`
      TokenType   string `json:"token_type"`
      Error       string `json:"error"`
      ErrorDesc   string `json:"error_description"`
   }

   if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
      return err
   }

   // Handle API errors as seen in the Python code
   if result.Error != "" {
      return fmt.Errorf("failed to refresh device token: %s [%s]", result.ErrorDesc, result.Error)
   }

   if result.TokenType != "bearer" {
      return fmt.Errorf("unexpected returned refreshed token type: %s", result.TokenType)
   }

   // Mutate the struct in-place with the new access token
   t.AccessToken = result.AccessToken

   return nil
}

// GetPlaybackExperienceMetadata returns the first playback envelope found in the
// resource: the legacy "actions" list first, then the modern "primaryActions"
// list.
func (r *Resource) GetPlaybackExperienceMetadata() (*PlaybackExperienceMetadata, error) {
   for _, action := range r.Actions {
      pem := action.Metadata.PlaybackExperienceMetadata
      if pem.PlaybackEnvelope != "" {
         return &pem, nil
      }
   }
   for _, action := range r.PrimaryActions {
      pem := action.NavigationAction.PlaybackMetadata.PlaybackExperienceMetadata
      if pem.PlaybackEnvelope != "" {
         return &pem, nil
      }
   }
   return nil, fmt.Errorf("playbackExperienceMetadata not found in actions or primaryActions")
}

func (r *Resource) String() string {
   var data strings.Builder
   if r.ApplyHdr {
      data.WriteString("HDR: true")
   } else {
      data.WriteString("HDR: false")
   }
   data.WriteByte('\n')
   if r.ApplyUhd {
      data.WriteString("UHD: true")
   } else {
      data.WriteString("UHD: false")
   }

   for _, pa := range r.PrimaryActions {
      for _, oc := range pa.OfferCards {
         details := oc.OfferCardDecoration.TransactionDetail
         if len(details) == 0 {
            continue
         }
         data.WriteByte('\n')
         data.WriteString("offer card: ")
         for j, td := range details {
            if j > 0 {
               data.WriteByte(' ')
            }
            data.WriteString(td.Text)
         }
      }
   }

   if r.EntitlementMessaging.EntitlementMessageSlotDetail.Message != "" {
      data.WriteByte('\n')
      data.WriteString("entitlement message: ")
      data.WriteString(r.EntitlementMessaging.EntitlementMessageSlotDetail.Message)
   }

   return data.String()
}

// Clean extracts the Akamai MPD URL from the main playlist and sanitizes its path.
// Returns an error if the Main playlist or Akamai CDN is not found.
func (p *PlaybackUrls) Clean() (*url.URL, error) {
   for _, playlist := range p.IntraTitlePlaylist {
      if playlist.Type == "Main" {
         if len(playlist.Urls) == 0 {
            return nil, fmt.Errorf("no urls found in main playlist")
         }

         // Require Akamai to avoid the 30MB Cloudfront/Amazon MPD bloat
         for _, u := range playlist.Urls {
            if u.Cdn == "akamai" {
               return trimURLPath(u.Url)
            }
         }

         return nil, fmt.Errorf("akamai cdn not found in main playlist")
      }
   }

   return nil, fmt.Errorf("main playlist not found in response")
}

func (*ActorToken) CachePath() string {
   return "rosso/amazon/ActorToken"
}

func (*PlaybackExperienceMetadata) CachePath() string {
   return "rosso/amazon/PlaybackExperienceMetadata"
}

// 0.go marker preserve
