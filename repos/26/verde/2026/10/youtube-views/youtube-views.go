package main

import (
   "bytes"
   "encoding/json"
   "flag"
   "fmt"
   "log"
   "net/http"
   "strconv"
   "strings"
   "time"
)

const (
   // The Android-flavoured user agent plus osVersion is deliberate: without it
   // a paid video answers with "This video can only be played on newer versions
   // of Android or other supported devices" instead of the correct
   // "This video requires payment to watch".
   clientName    = "WEB"
   clientVersion = "2.20231219.04.00"
   userAgent     = "com.google.android.youtube/" + clientVersion

   androidSdkVersion = 32
   osVersion         = "12"

   playerURL = "https://www.youtube.com/youtubei/v1/player"

   viewLimit = 10_000_000
)

// groupThousands inserts commas as thousands separators: 1234567 -> "1,234,567".
func groupThousands(n int) string {
   s := strconv.Itoa(n)
   if len(s) <= 3 {
      return s
   }

   head := len(s) % 3
   if head == 0 {
      head = 3
   }

   var b strings.Builder
   b.Grow(len(s) + len(s)/3)
   b.WriteString(s[:head])
   for i := head; i < len(s); i += 3 {
      b.WriteByte(',')
      b.WriteString(s[i : i+3])
   }
   return b.String()
}

func main() {
   log.SetFlags(log.Ltime)

   videoID := flag.String("v", "", "video ID")
   flag.Parse()
   if *videoID == "" {
      flag.Usage()
      return
   }

   var tube innerTube
   tube.Context.Client.ClientName = clientName
   tube.VideoID = *videoID

   if err := tube.do(); err != nil {
      log.Fatal(err)
   }
}

func viewsPerYear(views int, published time.Time) int {
   log.Println("publish", published)
   years := time.Since(published).Hours() / 24 / 365
   return int(float64(views) / years)
}

// innerTube is the request body of a /youtubei/v1/player call.
type innerTube struct {
   ContentCheckOk bool   `json:"contentCheckOk,omitempty"`
   RacyCheckOk    bool   `json:"racyCheckOk,omitempty"`
   VideoID        string `json:"videoId"`
   Context        struct {
      Client struct {
         AndroidSdkVersion int    `json:"androidSdkVersion"`
         ClientName        string `json:"clientName"`
         ClientVersion     string `json:"clientVersion"`
         OsVersion         string `json:"osVersion"`
      } `json:"client"`
   } `json:"context"`
}

// do fetches the player response and reports the video's yearly view rate.
func (t *innerTube) do() error {
   p, err := t.player()
   if err != nil {
      return err
   }

   published, err := time.Parse(time.RFC3339, p.Microformat.PlayerMicroformatRenderer.PublishDate)
   if err != nil {
      return fmt.Errorf("publish date: %w", err)
   }

   details := p.VideoDetails
   views := viewsPerYear(details.ViewCount, published)

   log.Println("video ID", details.VideoID)
   log.Println("limit", groupThousands(viewLimit))
   log.Println("views", groupThousands(views))
   return nil
}

// player fills in the client fields, posts the request and decodes the reply.
func (t *innerTube) player() (*player, error) {
   t.Context.Client.AndroidSdkVersion = androidSdkVersion
   t.Context.Client.ClientVersion = clientVersion
   t.Context.Client.OsVersion = osVersion

   body, err := json.Marshal(t)
   if err != nil {
      return nil, err
   }

   req, err := http.NewRequest(http.MethodPost, playerURL, bytes.NewReader(body))
   if err != nil {
      return nil, err
   }
   req.Header.Set("User-Agent", userAgent)

   resp, err := http.DefaultClient.Do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()

   var p player
   if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
      return nil, err
   }
   return &p, nil
}

// player is the slice of the InnerTube response we actually read.
type player struct {
   Microformat struct {
      PlayerMicroformatRenderer struct {
         PublishDate string
      }
   }
   VideoDetails struct {
      VideoID   string `json:"videoId"`
      ViewCount int    `json:",string"`
   }
}
