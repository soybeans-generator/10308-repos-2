package amazon

import (
   "fmt"
   "net/url"
   "strings"
)

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

// PlaybackResources is the GetVodPlaybackResources response, trimmed to the
// fields we use.
type PlaybackResources struct {
   GlobalError struct {
      Code    string `json:"code"`
      Message string `json:"message"`
   } `json:"globalError"`
   TimedTextUrls struct {
      Result struct {
         SubtitleUrls []struct {
            Format string `json:"format"` // e.g., "TTMLv2"
            Url    string `json:"url"`
         } `json:"subtitleUrls"`
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

// extracts the Akamai MPD URL from the main playlist and sanitizes its path.
// Returns an error if the Main playlist or Akamai CDN is not found.
func (p *PlaybackResources) PlaybackUrl() (string, error) {
   for _, playlist := range p.VodPlaylistedPlaybackUrls.Result.PlaybackUrls.IntraTitlePlaylist {
      if playlist.Type == "Main" {
         if len(playlist.Urls) == 0 {
            return "", fmt.Errorf("no urls found in main playlist")
         }

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

// returns the first TTML2 subtitle URL with its extension changed to ".vtt".
// Returns an error if no TTML2 subtitle is found.
func (p *PlaybackResources) SubtitleUrl() (string, error) {
   for _, subtitle := range p.TimedTextUrls.Result.SubtitleUrls {
      if !strings.EqualFold(subtitle.Format, "TTMLv2") {
         continue
      }
      parsedURL, err := url.Parse(subtitle.Url)
      if err != nil {
         return "", err
      }
      parsedURL.Path = strings.TrimSuffix(parsedURL.Path, ".ttml2") + ".vtt"
      return parsedURL.String(), nil
   }

   return "", fmt.Errorf("ttml2 subtitle not found in response")
}
