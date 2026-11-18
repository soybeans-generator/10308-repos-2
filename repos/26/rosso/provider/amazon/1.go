// 1.go marker preserve
package amazon

import (
   "bytes"
   "encoding/json"
   "fmt"
   "io"
   "log"
   "net/http"
   "net/url"
)

const (
   AppName         = "AIV"
   AppVersion      = "3.12.0"
   DeviceModel     = "sdk_gphone_x86"
   OSVersion       = "Android"
   SoftwareVersion = "999"
   DeviceDomain    = "Device"
)

const DeviceID = "deviceID"

const HostATVPS = "https://atv-ps.amazon.com"

const HostAmazonAPI = "https://api.amazon.com"

// GetPlayReadyLicense fetches the PlayReady DRM license for the given title.
func GetPlayReadyLicense(actorToken *ActorToken, metadata *PlaybackExperienceMetadata, licenseChallenge []byte, deviceTypeID string) ([]byte, error) {
   return fetchDRMLicense("/playback/drm-vod/GetPlayReadyLicense", actorToken, metadata, licenseChallenge, deviceTypeID)
}

// GetWidevineLicense requests a Widevine DRM license from the Amazon endpoint.
func GetWidevineLicense(actorToken *ActorToken, metadata *PlaybackExperienceMetadata, licenseChallenge []byte, deviceTypeID string) ([]byte, error) {
   return fetchDRMLicense("/playback/drm-vod/GetWidevineLicense", actorToken, metadata, licenseChallenge, deviceTypeID)
}

func deviceName() string {
   return fmt.Sprintf("%%FIRST_NAME%%'s%%DUPE_STRATEGY_1st%% %s", DeviceModel)
}

// doRequest wraps the http.Client Do method to log every outgoing request.
func doRequest(req *http.Request) (*http.Response, error) {
   log.Println(req.Method, req.URL)
   client := &http.Client{}
   return client.Do(req)
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

// ActorToken represents an actor-specific access token.
type ActorToken struct {
   Token string `json:"token"`
}

// GetActorToken exchanges the account refresh token and actor ID for an actor-specific access token.
func GetActorToken(tokens *TokenPair, profile *Profile, deviceTypeID string) (*ActorToken, error) {
   payload := map[string]any{
      "actor_id":             profile.ProfileID,
      "domain":               DeviceDomain,
      "device_name":          deviceName(),
      "app_name":             AppName,
      "app_version":          AppVersion,
      "device_model":         DeviceModel,
      "os_version":           OSVersion,
      "device_type":          deviceTypeID,
      "device_serial":        DeviceID,
      "software_version":     SoftwareVersion,
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

// Profile represents an Amazon actor profile.
type Profile struct {
   ProfileID        string `json:"profileId"`
   IsDefaultProfile bool   `json:"isDefaultProfile"`
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
      NavigationAction struct {
         PlaybackMetadata struct {
            PlaybackExperienceMetadata PlaybackExperienceMetadata `json:"playbackExperienceMetadata"`
         } `json:"playbackMetadata"`
      } `json:"navigationAction"`
      OfferCards []struct {
         OfferCardDecoration struct {
            TransactionDetail []struct {
               Text string
            }
         }
      } `json:"offerCards"`
   } `json:"primaryActions"`
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

// TokenPair represents the access and refresh tokens returned upon successful
// registration
type TokenPair struct {
   AccessToken  string `json:"access_token"`
   RefreshToken string `json:"refresh_token"`
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
   playbackUrls := result.VodPlaylistedPlaybackUrls.Result.PlaybackUrls
   return &playbackUrls, nil
}

// 1.go marker preserve
