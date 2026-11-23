// playback.go KEEP THIS LINE
package amazon

import (
   "bytes"
   "encoding/json"
   "fmt"
   "io"
   "net/http"
   "net/url"
   "strings"
)

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

   req, err := http.NewRequest(http.MethodPost, hostATVPS+path, bytes.NewReader(body))
   if err != nil {
      return nil, fmt.Errorf("failed to create request: %w", err)
   }

   query := url.Values{}
   query.Set("deviceTypeID", deviceTypeID)
   query.Set("deviceID", deviceID)
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

// trimURLPath removes the Amazon routing prefix from an MPD location.
func trimURLPath(rawUrl string) (string, error) {
   parsedURL, err := url.Parse(rawUrl)
   if err != nil {
      return "", err
   }

   parts := strings.Split(parsedURL.Path, "/")

   // Handle "/dm/3$..." structure
   if len(parts) > 4 && parts[1] == "dm" && strings.HasPrefix(parts[2], "3$") {
      parsedURL.Path = "/" + strings.Join(parts[4:], "/")
      // Handle "/3$..." structure
   } else if len(parts) > 3 && strings.HasPrefix(parts[1], "3$") {
      parsedURL.Path = "/" + strings.Join(parts[3:], "/")
   }

   return parsedURL.String(), nil
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

// PlaybackResources is the GetVodPlaybackResources response, trimmed to the
// fields we use.
type PlaybackResources struct {
   GlobalError struct {
      Code    string `json:"code"`
      Message string `json:"message"`
   } `json:"globalError"`
   TimedTextUrls struct {
      Result struct {
         SubtitleUrls []SubtitleUrl `json:"subtitleUrls"`
      } `json:"result"`
   } `json:"timedTextUrls"`
   VodPlaylistedPlaybackUrls struct {
      Result struct {
         PlaybackUrls struct {
            IntraTitlePlaylist []struct {
               Type string `json:"type"`
               Urls []struct {
                  Url string `json:"url"`
                  Cdn string `json:"cdn"` // Used to identify Akamai vs Cloudfront
               } `json:"urls"`
            } `json:"intraTitlePlaylist"`
         } `json:"playbackUrls"`
      } `json:"result"`
      Error struct {
         Message string `json:"message"`
      } `json:"error"`
   } `json:"vodPlaylistedPlaybackUrls"`
}

// PlaybackUrl extracts the Akamai MPD URL from the main playlist and sanitizes
// its path. Returns an error if the Main playlist or Akamai CDN is not found.
func (p *PlaybackResources) PlaybackUrl() (string, error) {
   for _, playlist := range p.VodPlaylistedPlaybackUrls.Result.PlaybackUrls.IntraTitlePlaylist {
      if playlist.Type == "Main" {
         // Require Akamai to avoid the 30MB Cloudfront/Amazon MPD bloat
         for _, u := range playlist.Urls {
            if u.Cdn == "akamai" {
               return trimURLPath(u.Url)
            }
         }

         return "", fmt.Errorf("akamai cdn not found in main playlist")
      }
   }

   return "", fmt.Errorf("main playlist not found in response")
}

// SubtitleUrls returns every subtitle track with ".ttml2" rewritten to ".vtt".
// An empty slice means "no subtitles".
func (p *PlaybackResources) SubtitleUrls() []SubtitleUrl {
   out := make([]SubtitleUrl, 0, len(p.TimedTextUrls.Result.SubtitleUrls))
   for _, subtitle := range p.TimedTextUrls.Result.SubtitleUrls {
      subtitle.Url = strings.Replace(subtitle.Url, ".ttml2", ".vtt", 1)
      out = append(out, subtitle)
   }
   return out
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
func GetItemDetails(token *ActorToken, itemId, deviceTypeID string) (*Resource, error) {
   req, err := http.NewRequest(
      "GET",
      hostATVPS+"/lrcedge/getDataByJavaTransform/v1/lr/detailsPage/detailsPageATF",
      nil,
   )
   if err != nil {
      return nil, err
   }
   query := url.Values{}
   query.Set("itemId", itemId)
   query.Set("presentationScheme", "android-tv-react")
   // Device parameters
   query.Set("deviceTypeID", deviceTypeID)
   query.Set("deviceID", deviceID)

   if token != nil {
      // Critical UI and Feature flags to force the V2/V3 BuyBox response with
      // PlaybackEnvelope
      query.Set("roles", "playback-envelope-supported")
      // you can get the envelope without this, but it will be trailer:
      // resource.secondaryActions[0].presentation.label = "Watch trailer"
      req.Header.Set("authorization", "Bearer "+token.Token)
   } else {
      query.Add("roles", "prime-offer-supported,svod-supported,tvod-supported")
      query.Add("clientFeatures", "EnableBuyBoxV2")
      query.Add("firmware", "firmware")
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

// SubtitleUrl is a single timed-text track from the GetVodPlaybackResources
// response.
type SubtitleUrl struct {
   LanguageCode string `json:"languageCode"`
   Url          string `json:"url"`
}

// String returns the track as key: value lines, language first.
func (s *SubtitleUrl) String() string {
   return fmt.Sprintf("languageCode: %s\nurl: %s", s.LanguageCode, s.Url)
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
func (p *VodPlaybackParams) Fetch() (*PlaybackResources, error) {
   if p == nil {
      return nil, fmt.Errorf("VodPlaybackParams cannot be nil")
   }
   payload := map[string]any{
      "vodPlaylistedPlaybackUrlsRequest": map[string]any{
         "playbackSettingsRequest": map[string]any{
            "titleId":  p.TitleId,
            "firmware": "firmware",
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
      "timedTextUrlsRequest": map[string]any{
         "supportedTimedTextFormats": []string{"TTMLv2"},
      },
      "globalParameters": map[string]any{
         "playbackEnvelope":       p.PlaybackExperienceMetadata.PlaybackEnvelope,
         "deviceCapabilityFamily": "LivingRoomPlayer",
      },
   }
   body, err := json.MarshalIndent(payload, "", " ")
   if err != nil {
      return nil, err
   }
   urlStr := hostATVPS + "/playback/prs/GetVodPlaybackResources"
   req, err := http.NewRequest("POST", urlStr, bytes.NewReader(body))
   if err != nil {
      return nil, err
   }
   query := url.Values{}
   query.Set("deviceID", deviceID)
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

   var result PlaybackResources
   if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
      return nil, err
   }

   if result.GlobalError.Code != "" {
      return nil, fmt.Errorf("global API error: [%s] %s", result.GlobalError.Code, result.GlobalError.Message)
   }

   if result.VodPlaylistedPlaybackUrls.Error.Message != "" {
      return nil, fmt.Errorf("API error: %s", result.VodPlaylistedPlaybackUrls.Error.Message)
   }

   return &result, nil
}

// playback.go KEEP THIS LINE
