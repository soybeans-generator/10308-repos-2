// youtube.go KEEP THIS LINE
package main

import (
   "bytes"
   "encoding/json"
   "errors"
   "fmt"
   "io"
   "net/http"
   "net/url"
   "strings"
   "time"
)

var errVisitorExpired = errors.New("visitor ID expired")

func audioExt(mimeType string) string {
   if mainMime(mimeType) == "audio/webm" {
      return ".opus"
   }
   return ".m4a"
}

func checkPlayable(p *playerData) error {
   s := p.PlayabilityStatus
   if s.Status == "OK" {
      return nil
   }
   if s.Status == "LOGIN_REQUIRED" && strings.Contains(s.Reason, "not a bot") {
      return fmt.Errorf("%w: %s: %s", errVisitorExpired, s.Status, s.Reason)
   }
   if s.Status == "UNPLAYABLE" && s.Reason == "This content isn't available, try again later." {
      return fmt.Errorf("%w: %s: %s", errVisitorExpired, s.Status, s.Reason)
   }
   return fmt.Errorf("playability %s: %s", s.Status, s.Reason)
}

func containerRank(mimeType string) (int, bool) {
   switch mainMime(mimeType) {
   case "audio/webm":
      return 0, true
   case "audio/mp4":
      return 1, true
   }
   return 0, false
}

func downloadYouTube(r *Record, title, visitorID, outputDir string, threads int, maxETA time.Duration) error {
   stream, err := youtubeStream(r.URL, visitorID)
   if err != nil {
      return err
   }
   return saveTrack(stream.URL, r, title, audioExt(stream.MimeType), outputDir, func(streamURL, path string) error {
      return downloadFile(streamURL, path, threads, maxETA)
   })
}

func fetchVisitorID() (string, error) {
   resp, err := http.Get("https://www.youtube.com/")
   if err != nil {
      return "", err
   }
   defer resp.Body.Close()
   if resp.StatusCode != http.StatusOK {
      return "", fmt.Errorf("homepage: %s", resp.Status)
   }
   body, err := io.ReadAll(resp.Body)
   if err != nil {
      return "", err
   }

   _, rest, ok := bytes.Cut(body, []byte("\nytcfg.set("))
   if !ok {
      return "", errors.New("ytcfg block not found")
   }
   var cfg ytConfig
   if err := json.NewDecoder(bytes.NewReader(rest)).Decode(&cfg); err != nil {
      return "", fmt.Errorf("decode ytcfg: %w", err)
   }
   raw := cfg.Context.Client.VisitorData
   if raw == "" {
      return "", errors.New("no visitor data in ytcfg")
   }
   visitor, err := url.PathUnescape(raw)
   if err != nil {
      return "", fmt.Errorf("unescape visitor data: %w", err)
   }
   return visitor, nil
}

func mainMime(mimeType string) string {
   main, _, _ := strings.Cut(mimeType, ";")
   return strings.TrimSpace(main)
}

func videoID(rawURL string) (string, error) {
   u, err := url.Parse(rawURL)
   if err != nil {
      return "", fmt.Errorf("parse url: %w", err)
   }
   if id := u.Query().Get("v"); id != "" {
      return id, nil
   }
   return "", fmt.Errorf("no video ID in %q", rawURL)
}

type audioFormat struct {
   Bitrate      int    `json:"bitrate"`
   AudioQuality string `json:"audioQuality"`
   URL          string `json:"url"`
   MimeType     string `json:"mimeType"`
}

// mediumStream picks the medium-quality audio stream, preferring webm over
// mp4 and keeping response order among equals.
func mediumStream(formats []*audioFormat) (*audioFormat, error) {
   var best *audioFormat
   bestRank := 0
   for _, f := range formats {
      if f == nil || f.AudioQuality != "AUDIO_QUALITY_MEDIUM" || f.URL == "" {
         continue
      }
      rank, ok := containerRank(f.MimeType)
      if !ok {
         continue
      }
      if best == nil || rank < bestRank {
         best, bestRank = f, rank
      }
   }
   if best == nil {
      return nil, errors.New("no medium-quality audio/webm or audio/mp4 stream")
   }
   return best, nil
}

func youtubeStream(watchURL, visitorID string) (*audioFormat, error) {
   id, err := videoID(watchURL)
   if err != nil {
      return nil, err
   }
   player, err := playerResponse(id, visitorID)
   if err != nil {
      return nil, err
   }
   if err := checkPlayable(player); err != nil {
      return nil, err
   }
   return mediumStream(player.StreamingData.AdaptiveFormats)
}

type playerData struct {
   PlayabilityStatus struct {
      Status string `json:"status"`
      Reason string `json:"reason"`
   } `json:"playabilityStatus"`
   StreamingData struct {
      AdaptiveFormats []*audioFormat `json:"adaptiveFormats"`
   } `json:"streamingData"`
}

// playerResponse sends the minimal VISIONOS player request: the context
// carries only the client name and version, and the visitor ID is the only
// extra header.
func playerResponse(id, visitorID string) (*playerData, error) {
   payload, err := json.Marshal(map[string]any{
      "context": map[string]any{
         "client": map[string]any{
            "clientName":    "VISIONOS",
            "clientVersion": "1.02",
         },
      },
      "videoId": id,
   })
   if err != nil {
      return nil, err
   }

   endpoint := "https://www.youtube.com/youtubei/v1/player?prettyPrint=false"
   req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
   if err != nil {
      return nil, err
   }
   req.Header.Set("X-Goog-Visitor-Id", visitorID)

   resp, err := http.DefaultClient.Do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()
   if resp.StatusCode == http.StatusTooManyRequests {
      return nil, fmt.Errorf("rate limited: HTTP %d", resp.StatusCode)
   }
   if resp.StatusCode != http.StatusOK {
      return nil, fmt.Errorf("player endpoint: %s", resp.Status)
   }

   body, err := io.ReadAll(resp.Body)
   if err != nil {
      return nil, err
   }
   var p playerData
   if err := json.Unmarshal(body, &p); err != nil {
      return nil, fmt.Errorf("decode player response: %w", err)
   }
   return &p, nil
}

type ytConfig struct {
   Context struct {
      Client struct {
         VisitorData string `json:"visitorData"`
      } `json:"client"`
   } `json:"INNERTUBE_CONTEXT"`
}

// youtube.go KEEP THIS LINE
