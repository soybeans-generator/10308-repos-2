// youtube.go KEEP THIS LINE
package main

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
   "time"
)

var errVisitorExpired = errors.New("visitor ID expired")

// thumbnailNames is a probe order: the earliest file YouTube serves wins, so
// the indices are the algorithm. Index 0 is the auto-generated image every
// upload has — a hit there means "no artwork" and the record gets no image.
var thumbnailNames = [...]string{
   0:  "sddefault.webp",
   1:  "sddefault.jpg",
   2:  "sd1.webp",
   3:  "sd2.webp",
   4:  "sd3.webp",
   5:  "sd1.jpg",
   6:  "sd2.jpg",
   7:  "sd3.jpg",
   8:  "hqdefault.webp",
   9:  "hqdefault.jpg",
   10: "hq1.webp",
   11: "hq2.webp",
   12: "hq3.webp",
   13: "0.webp",
   14: "0.jpg",
   15: "hq1.jpg",
   16: "hq2.jpg",
   17: "hq3.jpg",
   18: "mqdefault.webp",
   19: "mqdefault.jpg",
   20: "mq1.webp",
   21: "mq2.webp",
   22: "mq3.webp",
   23: "mq1.jpg",
   24: "mq2.jpg",
   25: "mq3.jpg",
   26: "default.webp",
   27: "default.jpg",
   28: "1.webp",
   29: "2.webp",
   30: "3.webp",
   31: "1.jpg",
   32: "2.jpg",
   33: "3.jpg",
}

func addYouTube(videoID, songsPath, visitorID string) error {
   watchURL := "https://youtube.com/watch?v=" + videoID

   songs, err := loadSongs(songsPath)
   if err != nil {
      return err
   }
   if hasAddress(songs, watchURL) {
      return fmt.Errorf("%s is already listed in %s", watchURL, songsPath)
   }

   info, err := fetchPlayer(videoID, visitorID)
   if err != nil {
      return err
   }
   fmt.Println(info.VideoDetails.ShortDescription)
   if info.VideoDetails.Title == "" {
      return fmt.Errorf("%s: player response carries no title", watchURL)
   }

   thumb, err := findThumbnail(videoID)
   if err != nil {
      return err
   }

   songs = append(songs, newSong(songFields{
      artist:  info.VideoDetails.Author,
      title:   info.VideoDetails.Title,
      address: watchURL,
      image:   thumb,
      year:    info.Microformat.PlayerMicroformatRenderer.PublishDate.Year(),
   }))
   sortNewestFirst(songs)
   return saveSongs(songsPath, songs)
}

func fetchVisitorID() (string, error) {
   log.Print("fetching a visitor ID")
   resp, err := http.Get("https://www.youtube.com/")
   if err != nil {
      return "", err
   }
   defer resp.Body.Close()

   page, err := io.ReadAll(resp.Body)
   if err != nil {
      return "", err
   }
   payload, err := objectAfter(page, []byte("\nytcfg.set("))
   if err != nil {
      return "", fmt.Errorf("locate ytcfg: %w", err)
   }

   var cfg struct {
      Context struct {
         Client struct {
            VisitorData string `json:"visitorData"`
         }
      } `json:"INNERTUBE_CONTEXT"`
   }
   if err := json.Unmarshal(payload, &cfg); err != nil {
      return "", fmt.Errorf("decode ytcfg: %w", err)
   }
   return url.PathUnescape(cfg.Context.Client.VisitorData)
}

// findThumbnail returns the first candidate YouTube actually serves, or "" for
// a video with no artwork of its own.
func findThumbnail(videoID string) (string, error) {
   for i, name := range thumbnailNames {
      link := "https://i.ytimg.com/vi/" + videoID + "/" + name
      if strings.HasSuffix(name, ".webp") {
         link = "https://i.ytimg.com/vi_webp/" + videoID + "/" + name
      }
      fmt.Println(link)

      resp, err := http.Head(link)
      if err != nil {
         return "", err
      }
      _ = resp.Body.Close()
      if resp.StatusCode != http.StatusOK {
         continue
      }
      if i == 0 {
         return "", nil
      }
      return link, nil
   }
   return "", nil
}

// objectAfter returns the JSON object that starts right after marker, finding
// its end by counting braces on the raw bytes while skipping string literals.
func objectAfter(data, marker []byte) ([]byte, error) {
   at := bytes.Index(data, marker)
   if at < 0 {
      return nil, fmt.Errorf("marker %q is missing", marker)
   }
   start := at + len(marker)
   if start == len(data) {
      return nil, errors.New("input ends after the marker")
   }
   if data[start] != '{' {
      return nil, fmt.Errorf("object expected, found %q", data[start])
   }

   var depth int
   var inStr, escaped bool
   for i := start; i < len(data); i++ {
      switch c := data[i]; {
      case escaped:
         escaped = false
      case inStr && c == '\\':
         escaped = true
      case c == '"':
         inStr = !inStr
      case inStr:
      case c == '{':
         depth++
      case c == '}':
         if depth--; depth == 0 {
            return data[start : i+1], nil
         }
      }
   }
   return nil, errors.New("no closing brace for the object")
}

type playerResponse struct {
   Microformat struct {
      PlayerMicroformatRenderer struct {
         PublishDate time.Time
      }
   }
   PlayabilityStatus struct {
      Status string
      Reason string
   }
   VideoDetails struct {
      Author           string
      ShortDescription string
      Title            string
   }
}

func fetchPlayer(videoID, visitorID string) (*playerResponse, error) {
   body, err := json.Marshal(map[string]any{
      "contentCheckOk": true,
      "racyCheckOk":    true,
      "videoId":        videoID,
      "context": map[string]any{
         "client": map[string]string{
            "clientName":    "WEB",
            "clientVersion": "2.20231219.04.00",
         },
      },
   })
   if err != nil {
      return nil, err
   }

   req, err := http.NewRequest(http.MethodPost, "https://www.youtube.com/youtubei/v1/player", bytes.NewReader(body))
   if err != nil {
      return nil, err
   }
   req.Header.Set("X-Goog-Visitor-Id", visitorID)

   resp, err := http.DefaultClient.Do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()
   if resp.StatusCode != http.StatusOK {
      return nil, fmt.Errorf("player request: %s", resp.Status)
   }

   var info playerResponse
   if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
      return nil, fmt.Errorf("decode player response: %w", err)
   }
   if st := info.PlayabilityStatus; st.Status == "LOGIN_REQUIRED" &&
      strings.Contains(st.Reason, "not a bot") {
      return nil, fmt.Errorf("%w (%s: %s)", errVisitorExpired, st.Status, st.Reason)
   }
   return &info, nil
}

// youtube.go KEEP THIS LINE
