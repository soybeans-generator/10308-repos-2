// rakuten.go KEEP THIS LINE
package rakuten

import (
   "bytes"
   "encoding/json"
   "errors"
   "fmt"
   "io"
   "log"
   "net/http"
   "net/url"
   "strings"
)

func do(req *http.Request) (*http.Response, error) {
   log.Println(req.Method, req.URL)
   return http.DefaultClient.Do(req)
}

func formatPlayableDetails(identifier string, title string, playbackStreams []Stream) string {
   seenLanguages := make(map[string]bool)
   var availableLanguages []string
   for _, currentStream := range playbackStreams {
      for _, audioLanguage := range currentStream.AudioLanguages {
         if !seenLanguages[audioLanguage.Id] {
            seenLanguages[audioLanguage.Id] = true
            availableLanguages = append(availableLanguages, audioLanguage.Id)
         }
      }
   }
   formattedAudio := strings.Join(availableLanguages, ", ")
   return fmt.Sprintf("%s (%s) - Audio: %s", title, identifier, formattedAudio)
}

type Classification struct {
   NumericalId int `json:"numerical_id"`
}

type DeviceMetadata struct {
   AppVersion   string `json:"app_version"`
   Brand        string `json:"brand"`
   Model        string `json:"model"`
   Os           string `json:"os"`
   SerialNumber string `json:"serial_number"`
   Uid          string `json:"uid"`
   Year         int    `json:"year"`
}

type Error struct {
   Code    string `json:"code"`
   Message string `json:"message"`
}

type Errors []Error

func (e Errors) Error() string {
   var data strings.Builder
   for i, item := range e {
      if i >= 1 {
         data.WriteByte('\n')
      }
      if item.Code != "" {
         fmt.Fprintf(&data, "code: %s\n", item.Code)
      }
      fmt.Fprintf(&data, "message: %s", item.Message)
   }
   return data.String()
}

type Language struct {
   Id string `json:"id"`
}

type Market struct {
   Code string `json:"code"`
}

type Private struct {
   Streams []Stream `json:"streams"`
}

type Profile struct {
   Classification Classification `json:"classification"`
   AudioLanguage  Language       `json:"audio_language"`
}

type Start struct {
   Profile Profile
   Market  Market
}

func FetchStart(marketCode string) (*Start, error) {
   target := &url.URL{
      Scheme: "https",
      Host:   "gizmo.rakuten.tv",
      Path:   "/v3/me/start",
   }

   query := url.Values{}
   query.Set("market_code", marketCode)
   target.RawQuery = query.Encode()

   payload := StartRequest{
      DeviceIdentifier: "web",
      DeviceMetadata: DeviceMetadata{
         AppVersion:   "app_version",
         Brand:        "brand",
         Model:        "model",
         Os:           "os",
         SerialNumber: "serial_number",
         Uid:          "uid",
         Year:         0,
      },
   }

   body, err := json.Marshal(payload)
   if err != nil {
      return nil, err
   }

   req, err := http.NewRequest("POST", target.String(), bytes.NewReader(body))
   if err != nil {
      return nil, err
   }
   req.Header.Set("content-type", "application/json")

   resp, err := do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()

   var apiResp struct {
      Data   Start  `json:"data"`
      Errors Errors `json:"errors"`
   }

   if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
      return nil, err
   }

   if len(apiResp.Errors) > 0 {
      return nil, apiResp.Errors
   }

   return &apiResp.Data, nil
}

func (*Start) CachePath() string {
   return "rosso/rakuten/Start"
}

type StartRequest struct {
   DeviceIdentifier string         `json:"device_identifier"`
   DeviceMetadata   DeviceMetadata `json:"device_metadata"`
}

type Stream struct {
   AudioLanguages []Language `json:"audio_languages"`
}

type StreamInfo struct {
   LicenseUrl string `json:"license_url"`
   Url        string // MPD
}

func FetchEpisodeStreaming(contentId string, userClassification Classification, audioLanguage string) (*StreamInfo, error) {
   return fetchStreaming(contentId, "episodes", userClassification, audioLanguage)
}

func FetchMovieStreaming(contentId string, userClassification Classification, audioLanguage string) (*StreamInfo, error) {
   return fetchStreaming(contentId, "movies", userClassification, audioLanguage)
}

func fetchStreaming(contentId string, contentType string, userClassification Classification, audioLanguage string) (*StreamInfo, error) {
   target := &url.URL{
      Scheme: "https",
      Host:   "gizmo.rakuten.tv",
      Path:   "/v3/avod/streamings",
   }

   payload := StreamingRequest{
      AudioLanguage:            audioLanguage,
      AudioQuality:             "2.0",
      ClassificationId:         userClassification.NumericalId,
      ContentId:                contentId,
      ContentType:              contentType,
      DeviceIdentifier:         "atvui40",
      DeviceSerial:             "not implemented",
      DeviceStreamVideoQuality: "UHD",
      Player:                   "atvui40:DASH-CENC:PR",
      SubtitleLanguage:         "MIS",
      VideoType:                "stream",
   }

   body, err := json.Marshal(payload)
   if err != nil {
      return nil, err
   }

   req, err := http.NewRequest("POST", target.String(), bytes.NewReader(body))
   if err != nil {
      return nil, err
   }
   req.Header.Set("content-type", "application/json")

   resp, err := do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()

   var apiResp struct {
      Data struct {
         StreamInfos []StreamInfo `json:"stream_infos"`
      } `json:"data"`
      Errors Errors `json:"errors"`
   }

   if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
      return nil, err
   }

   if len(apiResp.Errors) > 0 {
      return nil, apiResp.Errors
   }

   for _, info := range apiResp.Data.StreamInfos {
      return &info, nil
   }

   return nil, errors.New("no stream infos found")
}

func (*StreamInfo) CachePath() string {
   return "rosso/rakuten/StreamInfo"
}

func (s *StreamInfo) FetchLicense(challenge []byte) ([]byte, error) {
   req, err := http.NewRequest("POST", s.LicenseUrl, bytes.NewReader(challenge))
   if err != nil {
      return nil, err
   }

   resp, err := do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()
   return io.ReadAll(resp.Body)
}

type StreamingRequest struct {
   AudioLanguage            string `json:"audio_language"`
   AudioQuality             string `json:"audio_quality"`
   ClassificationId         int    `json:"classification_id"`
   ContentId                string `json:"content_id"`
   ContentType              string `json:"content_type"`
   DeviceIdentifier         string `json:"device_identifier"`
   DeviceSerial             string `json:"device_serial"`
   DeviceStreamVideoQuality string `json:"device_stream_video_quality"`
   Player                   string `json:"player"`
   SubtitleLanguage         string `json:"subtitle_language"`
   VideoType                string `json:"video_type"`
}

type ViewOptions struct {
   Private Private `json:"private"`
}

// rakuten.go KEEP THIS LINE
