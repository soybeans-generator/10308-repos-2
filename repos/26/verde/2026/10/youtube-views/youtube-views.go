package main

import (
   "bytes"
   "encoding/json"
   "flag"
   "fmt"
   "log"
   "net/http"
   "net/url"
   "strconv"
   "strings"
   "time"
)

const (
   // The Android-flavoured user agent plus osVersion is deliberate: without it
   // a paid video answers with "This video can only be played on newer versions
   // of Android or other supported devices" instead of the correct
   // "This video requires payment to watch".
   clientName        = "WEB"
   clientVersion     = "2.20231219.04.00"
   userAgent         = "com.google.android.youtube/" + clientVersion
   androidSdkVersion = 32
   osVersion         = "12"

   playerURL = "https://www.youtube.com/youtubei/v1/player"

   viewLimit = 10_000_000

   watchExample = "https://www.youtube.com/watch?v=9bZkp7q19f0"
)

// groupThousands inserts commas as thousands separators: 1234567 -> "1,234,567".
func groupThousands(number int) string {
   digits := strconv.Itoa(number)
   if len(digits) <= 3 {
      return digits
   }

   head := len(digits) % 3
   if head == 0 {
      head = 3
   }

   var grouped strings.Builder
   grouped.Grow(len(digits) + len(digits)/3)
   grouped.WriteString(digits[:head])
   for i := head; i < len(digits); i += 3 {
      grouped.WriteByte(',')
      grouped.WriteString(digits[i : i+3])
   }
   return grouped.String()
}

func main() {
   log.SetFlags(log.Ltime)

   videoURL := flag.String("u", "", "video URL, e.g. "+watchExample)
   flag.Parse()
   if *videoURL == "" {
      flag.Usage()
      return
   }

   if err := reportViews(*videoURL); err != nil {
      log.Fatal(err)
   }
}

// reportViews resolves rawURL to a video ID, fetches that video's player
// response, and logs its yearly view rate.
func reportViews(rawURL string) error {
   videoID, err := videoIDFromURL(rawURL)
   if err != nil {
      return err
   }

   player, err := fetchPlayer(videoID)
   if err != nil {
      return err
   }

   // The response carries both of these as strings, so both get converted here.
   published, err := time.Parse(time.RFC3339, player.Microformat.PlayerMicroformatRenderer.PublishDate)
   if err != nil {
      return fmt.Errorf("publish date: %w", err)
   }

   viewCount, err := strconv.Atoi(player.VideoDetails.ViewCount)
   if err != nil {
      return fmt.Errorf("view count: %w", err)
   }
   log.Println("publish", published)

   views := viewsPerYear(viewCount, published, time.Now())

   log.Println("video ID", player.VideoDetails.VideoID)
   log.Println("limit", groupThousands(viewLimit))
   log.Println("views", groupThousands(views))
   return nil
}

// videoIDFromURL extracts the "v" query parameter from a watch URL. A missing
// "v" and an empty "v" both yield an error.
func videoIDFromURL(rawURL string) (string, error) {
   parsed, err := url.Parse(rawURL)
   if err != nil {
      return "", fmt.Errorf("parse URL %q: %w", rawURL, err)
   }

   videoID := parsed.Query().Get("v")
   if videoID == "" {
      return "", fmt.Errorf("no video ID in %q: \"v\" parameter missing or empty", rawURL)
   }
   return videoID, nil
}

// viewsPerYear divides views by the video's age in years, measured from
// published to now.
func viewsPerYear(views int, published, now time.Time) int {
   years := now.Sub(published).Hours() / 24 / 365
   return int(float64(views) / years)
}

type clientInfo struct {
   AndroidSdkVersion int    `json:"androidSdkVersion"`
   ClientName        string `json:"clientName"`
   ClientVersion     string `json:"clientVersion"`
   OsVersion         string `json:"osVersion"`
}

type playerContext struct {
   Client clientInfo `json:"client"`
}

// playerRequest is the body of a /youtubei/v1/player call. The inner types are
// named rather than anonymous so the body can be built as one composite literal.
type playerRequest struct {
   VideoID string        `json:"videoId"`
   Context playerContext `json:"context"`
}

func newPlayerRequest(videoID string) *playerRequest {
   return &playerRequest{
      VideoID: videoID,
      Context: playerContext{
         Client: clientInfo{
            AndroidSdkVersion: androidSdkVersion,
            ClientName:        clientName,
            ClientVersion:     clientVersion,
            OsVersion:         osVersion,
         },
      },
   }
}

// playerResponse is the slice of the InnerTube reply we actually read. Fields
// stay raw strings exactly as InnerTube sends them, and reportViews does the
// converting. Only read, never constructed, so the nesting stays anonymous.
type playerResponse struct {
   Microformat struct {
      PlayerMicroformatRenderer struct {
         PublishDate string
      }
   }
   VideoDetails struct {
      VideoID   string `json:"videoId"`
      ViewCount string
   }
}

// fetchPlayer posts a /youtubei/v1/player request and decodes the reply.
func fetchPlayer(videoID string) (*playerResponse, error) {
   body, err := json.Marshal(newPlayerRequest(videoID))
   if err != nil {
      return nil, err
   }

   request, err := http.NewRequest(http.MethodPost, playerURL, bytes.NewReader(body))
   if err != nil {
      return nil, err
   }
   request.Header.Set("User-Agent", userAgent)

   response, err := http.DefaultClient.Do(request)
   if err != nil {
      return nil, err
   }
   defer response.Body.Close()

   decoded := &playerResponse{}
   if err := json.NewDecoder(response.Body).Decode(decoded); err != nil {
      return nil, err
   }
   return decoded, nil
}
