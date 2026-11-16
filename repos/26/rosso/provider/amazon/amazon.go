package amazon

import (
   "bytes"
   "encoding/json"
   "fmt"
   "io"
   "net/http"
   "net/url"
   "strings"
   "time"
)

const HostATVPS = "https://atv-ps.amazon.com"

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

// types.go marker preserve
// GetPlayReadyLicense fetches the PlayReady DRM license for the given title.
func GetPlayReadyLicense(actorToken *ActorToken, metadata *PlaybackExperienceMetadata, licenseChallenge []byte, deviceTypeID string) ([]byte, error) {
   return fetchDRMLicense("/playback/drm-vod/GetPlayReadyLicense", actorToken, metadata, licenseChallenge, deviceTypeID)
}

// GetWidevineLicense requests a Widevine DRM license from the Amazon endpoint.
func GetWidevineLicense(actorToken *ActorToken, metadata *PlaybackExperienceMetadata, licenseChallenge []byte, deviceTypeID string) ([]byte, error) {
   return fetchDRMLicense("/playback/drm-vod/GetWidevineLicense", actorToken, metadata, licenseChallenge, deviceTypeID)
}

// fetchDRMLicense is the shared base function for making DRM requests
func fetchDRMLicense(path string, actorToken *ActorToken, metadata *PlaybackExperienceMetadata, licenseChallenge []byte, deviceTypeID string) ([]byte, error) {
   payload := map[string]any{
      "playbackEnvelope": metadata.PlaybackEnvelope,
      "licenseChallenge": licenseChallenge,
   }

   body, err := json.Marshal(payload)
   if err != nil {
      return nil, fmt.Errorf("failed to marshal payload: %w", err)
   }

   req, err := http.NewRequest(http.MethodPost, HostATVPS+path, bytes.NewReader(body))
   if err != nil {
      return nil, fmt.Errorf("failed to create request: %w", err)
   }

   query := url.Values{}
   query.Set("deviceTypeID", deviceTypeID)
   query.Set("deviceID", DeviceID)

   req.URL.RawQuery = query.Encode()
   req.Header.Set("Authorization", "Bearer "+actorToken.Token)

   resp, err := doRequest(req)
   if err != nil {
      return nil, fmt.Errorf("request failed: %w", err)
   }
   defer resp.Body.Close()

   // Read the body once so we can attempt multiple unmarshals
   respBytes, err := io.ReadAll(resp.Body)
   if err != nil {
      return nil, fmt.Errorf("failed to read response: %w", err)
   }

   // 1. Try the standard response format (contains licenses or a nested error object)
   var standardResp struct {
      WidevineLicense *struct {
         License []byte `json:"license"`
      } `json:"widevineLicense"`
      PlayReadyLicense *struct {
         License []byte `json:"license"`
      } `json:"playReadyLicense"`
      Message *struct {
         Body *struct {
            Code    string `json:"code"`
            Message string `json:"message"`
         } `json:"body"`
      } `json:"message"`
   }

   if err := json.Unmarshal(respBytes, &standardResp); err == nil {
      if standardResp.Message != nil && standardResp.Message.Body != nil {
         return nil, fmt.Errorf("API error [%s]: %s", standardResp.Message.Body.Code, standardResp.Message.Body.Message)
      }
      if standardResp.WidevineLicense != nil && len(standardResp.WidevineLicense.License) > 0 {
         return standardResp.WidevineLicense.License, nil
      }
      if standardResp.PlayReadyLicense != nil && len(standardResp.PlayReadyLicense.License) > 0 {
         return standardResp.PlayReadyLicense.License, nil
      }
   }

   // 2. If the first unmarshal fails (e.g., "message" is a string causing a type error), try the flat error format
   var flatErrorResp struct {
      Code    string `json:"code"`
      ID      string `json:"id"`
      Message string `json:"message"`
   }

   if err := json.Unmarshal(respBytes, &flatErrorResp); err == nil && flatErrorResp.Message != "" {
      return nil, fmt.Errorf("code: %s, message: %s, id: %s", flatErrorResp.Code, flatErrorResp.Message, flatErrorResp.ID)
   }

   // 3. Check for standard HTTP errors if no JSON error message was extracted
   if resp.StatusCode != http.StatusOK {
      return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
   }

   return nil, fmt.Errorf("license not found in response")
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

// ActorToken represents an actor-specific access token.
type ActorToken struct {
   Token string `json:"token"`
}

// playback.go marker preserve
// GetActorToken exchanges the account refresh token and actor ID for an actor-specific access token.
func GetActorToken(tokens *TokenPair, profile *Profile, deviceTypeID string) (*ActorToken, error) {
   payload := map[string]any{
      "actor_id":             profile.ProfileID,
      "app_name":             "AIV",
      "requested_token_type": "actor_access_token",
      "source_token_type":    "refresh_token",
      "source_device_tokens": []any{
         map[string]any{
            "device_type": deviceTypeID,
            "account_refresh_token": map[string]string{
               "token": tokens.RefreshToken,
            },
         },
      },
   }
   body, err := json.Marshal(payload)
   if err != nil {
      return nil, err
   }
   req, err := http.NewRequest(
      "POST", HostAmazonAPI+"/auth/token", bytes.NewBuffer(body),
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

   // Embed our new ActorToken struct into the anonymous decoder struct
   var result struct {
      DeviceTokens []struct {
         ActorAccessToken ActorToken `json:"actor_access_token"`
      } `json:"device_tokens"`
   }

   if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
      return nil, err
   }

   if len(result.DeviceTokens) == 0 {
      return nil, fmt.Errorf("no device tokens returned")
   }

   token := result.DeviceTokens[0].ActorAccessToken
   return &token, nil
}

func (*ActorToken) CachePath() string {
   return "rosso/amazon/ActorToken"
}

// Device represents the metadata for a supported hardware device.
type Device struct {
   Manufacturer  string
   Model         string
   SecurityLevel int
   DeviceTypeID  string
}

// EntitlementMessaging holds the "entitlementMessaging" object from the resource.
type EntitlementMessaging struct {
   EntitlementMessageSlotDetail struct {
      Message string `json:"message"`
   } `json:"ENTITLEMENT_MESSAGE_SLOT_DETAIL"`
}

// PlaybackExperienceMetadata contains the envelope and related data needed for playback requests.
type PlaybackExperienceMetadata struct {
   PlaybackEnvelope string `json:"playbackEnvelope"`
   ExpiryTime       int64  `json:"expiryTime"`
   CorrelationId    string `json:"correlationId"`
}

func (*PlaybackExperienceMetadata) CachePath() string {
   return "rosso/amazon/PlaybackExperienceMetadata"
}

// PlaybackUrls is the parent holding the intra-title playlists.
type PlaybackUrls struct {
   IntraTitlePlaylist []struct {
      Type string `json:"type"`
      Urls []struct {
         Url string `json:"url"`
         Cdn string `json:"cdn"` // Used to identify Akamai vs Cloudfront
      } `json:"urls"`
   } `json:"intraTitlePlaylist"`
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

// Profile represents an Amazon actor profile.
type Profile struct {
   ProfileID        string `json:"profileId"`
   IsDefaultProfile bool   `json:"isDefaultProfile"`
}

// GetPrimaryProfile uses the account access token to fetch available profiles and returns the primary profile.
func GetPrimaryProfile(tokens *TokenPair, deviceTypeID string) (*Profile, error) {
   req, err := http.NewRequest(
      "GET",
      HostATVPS+"/lrcedge/getDataByJavaTransform/v1/lr/profiles/profileSelection",
      nil,
   )
   if err != nil {
      return nil, err
   }
   query := url.Values{}
   query.Set("deviceTypeID", deviceTypeID)
   query.Set("deviceID", DeviceID)
   req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
   req.URL.RawQuery = query.Encode()

   resp, err := doRequest(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()

   // Embed our new Profile struct alongside the error Message struct
   var result struct {
      Resource struct {
         Profiles []Profile `json:"profiles"`
      } `json:"resource"`
      Message *struct {
         Body *struct {
            Code    string `json:"code"`
            Message string `json:"message"`
         } `json:"body"`
      } `json:"message"`
   }

   if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
      return nil, fmt.Errorf("failed to decode response (status %d): %w", resp.StatusCode, err)
   }

   // 1. Check for the structured JSON API error
   if result.Message != nil && result.Message.Body != nil {
      return nil, fmt.Errorf("API error [%s]: %s", result.Message.Body.Code, result.Message.Body.Message)
   }

   // 2. Check for standard HTTP errors if no JSON error message was provided
   if resp.StatusCode != http.StatusOK {
      return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
   }

   // 3. Extract and return the primary profile
   for _, profile := range result.Resource.Profiles {
      if profile.IsDefaultProfile {
         return &profile, nil
      }
   }

   return nil, fmt.Errorf("default profile not found")
}

// Resource represents the "resource" object returned from the detailsPageATF endpoint.
type Resource struct {
   Actions []struct {
      Metadata struct {
         PlaybackExperienceMetadata PlaybackExperienceMetadata `json:"playbackExperienceMetadata"`
      } `json:"metadata"`
   } `json:"actions"`
   ApplyHdr       bool `json:"applyHdr"`
   ApplyUhd       bool `json:"applyUhd"`
   PrimaryActions []struct {
      OfferCards []struct {
         OfferCardDecoration struct {
            TransactionDetail []struct {
               Text string
            }
         }
      }
   }
   EntitlementMessaging EntitlementMessaging `json:"entitlementMessaging"`
}

// GetItemDetails uses the actor access token to get metadata for a specific title.
// It explicitly passes UI schema flags to ensure the server returns the PlaybackEnvelope.
func GetItemDetails(token *ActorToken, titleId, deviceTypeID string) (*Resource, error) {
   req, err := http.NewRequest(
      "GET",
      HostATVPS+"/lrcedge/getDataByJavaTransform/v1/lr/detailsPage/detailsPageATF",
      nil,
   )
   if err != nil {
      return nil, err
   }
   query := url.Values{}
   query.Set("itemId", titleId)
   query.Set("presentationScheme", "android-tv-react")
   // Device parameters
   query.Set("deviceTypeID", deviceTypeID)
   query.Set("deviceID", DeviceID)

   if token != nil {
      // Critical UI and Feature flags to force the V2/V3 BuyBox response with
      // PlaybackEnvelope
      query.Set("roles", "playback-envelope-supported")
      // you can get the envelope without this, but it will be trailer:
      // resource.secondaryActions[0].presentation.label = "Watch trailer"
      req.Header.Set("authorization", "Bearer "+token.Token)
   } else {
      query.Add("firmware", "")
      query.Add("roles", "prime-offer-supported,svod-supported,tvod-supported")
      query.Add("clientFeatures", "EnableBuyBoxV2")
   }

   req.URL.RawQuery = query.Encode()

   resp, err := doRequest(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()

   if resp.StatusCode != http.StatusOK {
      return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
   }

   // Embed our new Resource struct into the anonymous decoder struct
   var result struct {
      Resource Resource `json:"resource"`
   }
   if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
      return nil, err
   }
   return &result.Resource, nil
}

// GetPlaybackExperienceMetadata searches the Actions array and returns the first valid PlaybackExperienceMetadata.
func (r *Resource) GetPlaybackExperienceMetadata() (*PlaybackExperienceMetadata, error) {
   for _, action := range r.Actions {
      pem := action.Metadata.PlaybackExperienceMetadata
      if pem.PlaybackEnvelope != "" {
         return &pem, nil
      }
   }
   return nil, fmt.Errorf("playbackExperienceMetadata not found in actions")
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

// TokenPair represents the access and refresh tokens returned upon successful
// registration
type TokenPair struct {
   AccessToken  string `json:"access_token"`
   RefreshToken string `json:"refresh_token"`
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
         "app_name":      "AIV",
         "app_version":   "9",
         "device_model":  "device_model",
         "device_serial": DeviceID,
         "device_type":   deviceTypeID,
         "os_version":    "Android",
         // if you change deviceID this is required
         "device_name": fmt.Sprint(time.Now().Unix()),
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

// VodPlaybackParams holds the configuration for fetching playback resources.
type VodPlaybackParams struct {
   ActorToken                 *ActorToken
   TitleId                    string
   PlaybackExperienceMetadata *PlaybackExperienceMetadata
   DeviceTypeID               string
   VideoCodec                 string // e.g., "H264" or "H265"
   DRMType                    string // e.g., "Widevine" or "PlayReady"
   BitrateAdaptation          string // e.g., "CBR" or "CVBR"
   DynamicRangeFormat         string // e.g., "None", "DolbyVision", or "HDR10"
   MaxVideoResolution         string // e.g., "576p" or "2160p"
}

// Fetch requests the final MPD resources for playback from Amazon's API.
func (p *VodPlaybackParams) Fetch() (*PlaybackUrls, error) {
   if p == nil {
      return nil, fmt.Errorf("VodPlaybackParams cannot be nil")
   }
   payload := map[string]any{
      "vodPlaylistedPlaybackUrlsRequest": map[string]any{
         "playbackSettingsRequest": map[string]any{
            "firmware": "", // required but can be empty
            "titleId":  p.TitleId,
         },
         "device": map[string]any{
            "hdcpLevel":          "2.3", // at least 2.2 is needed for UHD with hev1
            "maxVideoResolution": p.MaxVideoResolution,
            "streamingTechnologies": map[string]any{
               "DASH": map[string]any{
                  "bitrateAdaptations":  []string{p.BitrateAdaptation},
                  "codecs":              []string{p.VideoCodec},
                  "drmType":             p.DRMType,
                  "dynamicRangeFormats": []string{p.DynamicRangeFormat},
               },
            },
            "supportedStreamingTechnologies": []string{"DASH"},
         },
      },
      "globalParameters": map[string]any{
         "playbackEnvelope":       p.PlaybackExperienceMetadata.PlaybackEnvelope,
         "deviceCapabilityFamily": "LivingRoomPlayer",
      },
   }
   body, err := json.Marshal(payload)
   if err != nil {
      return nil, err
   }

   urlStr := HostATVPS + "/playback/prs/GetVodPlaybackResources"
   req, err := http.NewRequest("POST", urlStr, bytes.NewReader(body))
   if err != nil {
      return nil, err
   }
   query := url.Values{}
   query.Set("deviceID", DeviceID)
   query.Set("deviceTypeID", p.DeviceTypeID)
   req.URL.RawQuery = query.Encode()
   req.Header.Set("Authorization", "Bearer "+p.ActorToken.Token)

   resp, err := doRequest(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()

   if resp.StatusCode != http.StatusOK {
      return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
   }

   var result struct {
      GlobalError struct {
         Code    string `json:"code"`
         Message string `json:"message"`
      } `json:"globalError"`
      VodPlaylistedPlaybackUrls struct {
         Result struct {
            PlaybackUrls PlaybackUrls `json:"playbackUrls"`
         } `json:"result"`
         Error struct {
            Message string `json:"message"`
         } `json:"error"`
      } `json:"vodPlaylistedPlaybackUrls"`
   }

   if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
      return nil, err
   }

   if result.GlobalError.Code != "" {
      return nil, fmt.Errorf("global API error: [%s] %s", result.GlobalError.Code, result.GlobalError.Message)
   }

   if result.VodPlaylistedPlaybackUrls.Error.Message != "" {
      return nil, fmt.Errorf("API error: %s", result.VodPlaylistedPlaybackUrls.Error.Message)
   }

   // Return the parent struct holding the playlists
   return &result.VodPlaylistedPlaybackUrls.Result.PlaybackUrls, nil
}

func (*CodePair) CachePath() string {
   return "rosso/amazon/CodePair"
}

func (c *CodePair) String() string {
   var data strings.Builder
   data.WriteString("Please navigate to https://amazon.com/gp/video/ontv\n")
   data.WriteString("Enter the following code: ")
   data.WriteString(c.PublicCode)
   return data.String()
}
