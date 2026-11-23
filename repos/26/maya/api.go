// api.go KEEP THIS LINE
package maya

import (
   "errors"
   "fmt"
   "io"
   "log"
   "net/http"
   "net/url"

   "41.neocities.org/luna/dash"
   "41.neocities.org/luna/hls"
)

// DashDownload downloads streamId from a DASH manifest. A nil Options means
// no DRM.
func DashDownload(streamId string, m *Manifest, options *Options) error {
   base, err := url.Parse(m.Url)
   if err != nil {
      return fmt.Errorf("invalid manifest URL %q: %w", m.Url, err)
   }
   mpd, err := dash.Parse(m.Body, base)
   if err != nil {
      return err
   }
   fetchKey, err := options.keyFetcher()
   if err != nil {
      return err
   }
   return downloadDash(mpd, streamId, fetchKey)
}

// HlsDownload downloads streamId from an HLS master playlist. A nil Options
// means no DRM.
func HlsDownload(streamId int, m *Manifest, options *Options) error {
   base, err := url.Parse(m.Url)
   if err != nil {
      return fmt.Errorf("invalid manifest URL %q: %w", m.Url, err)
   }
   playlist, err := hls.DecodeMaster(string(m.Body), base)
   if err != nil {
      return err
   }
   fetchKey, err := options.keyFetcher()
   if err != nil {
      return err
   }
   return downloadHls(playlist, streamId, fetchKey)
}

// fetchData performs a GET and returns the body with the URL that actually
// served it. After a redirect the returned URL differs from target, and any
// relative URL found in the body must be resolved against it.
func fetchData(target *url.URL, headers map[string]string, logRequest bool) ([]byte, *url.URL, error) {
   req, err := http.NewRequest(http.MethodGet, target.String(), nil)
   if err != nil {
      return nil, nil, err
   }
   for key, value := range headers {
      req.Header.Set(key, value)
   }
   if logRequest {
      log.Println(req.Method, req.URL)
   }

   resp, err := http.DefaultClient.Do(req)
   if err != nil {
      return nil, nil, err
   }
   defer resp.Body.Close()

   if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
      return nil, nil, errors.New(resp.Status)
   }
   body, err := io.ReadAll(resp.Body)
   if err != nil {
      return nil, nil, err
   }
   return body, resp.Request.URL, nil
}

// fetchManifest parses the manifest location given on the command line and
// fetches it. This is the one place a manifest URL enters the package as a
// string; everything below it works with url.URL.
func fetchManifest(manifestUrl string) ([]byte, *url.URL, error) {
   target, err := url.Parse(manifestUrl)
   if err != nil {
      return nil, nil, fmt.Errorf("invalid manifest URL %q: %w", manifestUrl, err)
   }
   return fetchData(target, nil, true)
}

// printStreams prints each stream, separating them with a blank line.
func printStreams[T any](streams []T) {
   for i, stream := range streams {
      if i > 0 {
         fmt.Println()
      }
      fmt.Println(stream)
   }
}

// DrmSystem identifies the DRM scheme used to obtain decryption keys.
type DrmSystem int

const (
   DrmNone DrmSystem = iota
   DrmPlayReady
   DrmWidevine
)

// Manifest is a downloaded manifest together with the URL that served it.
//
// Url is a string because a Manifest is a CacheValue stored with
// encoding/xml, and url.URL has no XML form of its own: reflecting over its
// exported fields loses User and RawPath, and a lost RawPath can re-escape
// the path into a different URL.
type Manifest struct {
   Url  string
   Body []byte
}

// DashList downloads a DASH manifest and prints the streams it offers.
func DashList(manifestUrl string) (*Manifest, error) {
   body, effective, err := fetchManifest(manifestUrl)
   if err != nil {
      return nil, err
   }
   // Parse against the URL that actually served the manifest: after a
   // redirect, relative BaseURLs resolve against the final URL.
   mpd, err := dash.Parse(body, effective)
   if err != nil {
      return nil, err
   }
   if err := listStreamsDash(mpd); err != nil {
      return nil, err
   }
   return &Manifest{Url: effective.String(), Body: body}, nil
}

// HlsList downloads an HLS master playlist and prints the streams it offers.
func HlsList(manifestUrl string) (*Manifest, error) {
   body, effective, err := fetchManifest(manifestUrl)
   if err != nil {
      return nil, err
   }
   playlist, err := hls.DecodeMaster(string(body), effective)
   if err != nil {
      return nil, err
   }
   if err := listStreamsHls(playlist); err != nil {
      return nil, err
   }
   return &Manifest{Url: effective.String(), Body: body}, nil
}

func (*Manifest) CachePath() string {
   return "maya/Manifest"
}

// Options configures a download.
type Options struct {
   Drm     DrmSystem
   Device  string
   License func([]byte) ([]byte, error)
}

// api.go KEEP THIS LINE
