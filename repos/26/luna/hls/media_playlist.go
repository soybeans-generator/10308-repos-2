// media_playlist.go marker preserve
package hls

import (
   "errors"
   "fmt"
   "net/url"
   "strconv"
   "strings"
)

type MediaPlaylist struct {
   TargetDuration int
   MediaSequence  int
   Version        int
   PlaylistType   string
   Segments       []*Segment
   Keys           []*Key   // A slice of all keys found in the playlist
   Map            *url.URL // The playlist's initialization map
   EndList        bool
}

// DecodeMedia parses a Media Playlist.
func DecodeMedia(content string) (*MediaPlaylist, error) {
   lines := splitLines(content)
   return parseMedia(lines)
}

func parseMedia(lines []string) (*MediaPlaylist, error) {
   mediaPlaylist := &MediaPlaylist{}

   for i := 0; i < len(lines); i++ {
      line := lines[i]
      switch {
      case strings.HasPrefix(line, "#EXT-X-VERSION:"):
         version, err := strconv.Atoi(strings.TrimPrefix(line, "#EXT-X-VERSION:"))
         if err != nil {
            return nil, fmt.Errorf("invalid EXT-X-VERSION: %w", err)
         }
         mediaPlaylist.Version = version
      case strings.HasPrefix(line, "#EXT-X-TARGETDURATION:"):
         duration, err := strconv.Atoi(strings.TrimPrefix(line, "#EXT-X-TARGETDURATION:"))
         if err != nil {
            return nil, fmt.Errorf("invalid EXT-X-TARGETDURATION: %w", err)
         }
         mediaPlaylist.TargetDuration = duration
      case strings.HasPrefix(line, "#EXT-X-MEDIA-SEQUENCE:"):
         sequence, err := strconv.Atoi(strings.TrimPrefix(line, "#EXT-X-MEDIA-SEQUENCE:"))
         if err != nil {
            return nil, fmt.Errorf("invalid EXT-X-MEDIA-SEQUENCE: %w", err)
         }
         mediaPlaylist.MediaSequence = sequence
      case strings.HasPrefix(line, "#EXT-X-PLAYLIST-TYPE:"):
         mediaPlaylist.PlaylistType = strings.TrimPrefix(line, "#EXT-X-PLAYLIST-TYPE:")
      case strings.HasPrefix(line, "#EXT-X-ENDLIST"):
         mediaPlaylist.EndList = true
      case strings.HasPrefix(line, "#EXT-X-KEY:"):
         newKey, err := parseKey(line)
         if err != nil {
            return nil, err
         }
         mediaPlaylist.Keys = append(mediaPlaylist.Keys, newKey)
      case strings.HasPrefix(line, "#EXT-X-MAP:"):
         attrs := parseAttributes(line, "#EXT-X-MAP:")
         if value, ok := attrs["URI"]; ok && value != "" {
            parsedUrl, err := url.Parse(value)
            if err != nil {
               return nil, fmt.Errorf("invalid URI in EXT-X-MAP: %w", err)
            }
            mediaPlaylist.Map = parsedUrl
         }
      case strings.HasPrefix(line, "#EXTINF:"):
         // Parse duration and title
         // Format: #EXTINF:duration,[title]
         raw := strings.TrimPrefix(line, "#EXTINF:")
         durationStr, title, _ := strings.Cut(raw, ",")
         duration, err := strconv.ParseFloat(durationStr, 64)
         if err != nil {
            return nil, fmt.Errorf("invalid EXTINF duration: %w", err)
         }
         newSegment := &Segment{
            Duration: duration,
            Title:    strings.TrimSpace(title),
         }
         // The URI may not be on the immediately following line; intermediate
         // tags such as #EXT-X-BYTERANGE are allowed between #EXTINF and the
         // segment URI. Scan forward for the URI, but stop at the start of the
         // next entry so a URI-less #EXTINF cannot consume another entry's URI.
         var uri string
         for j := i + 1; j < len(lines); j++ {
            nextLine := lines[j]
            if nextLine == "" {
               continue
            }
            if strings.HasPrefix(nextLine, "#EXTINF:") ||
               strings.HasPrefix(nextLine, "#EXT-X-ENDLIST") {
               break // next entry begins here; this EXTINF has no URI
            }
            if strings.HasPrefix(nextLine, "#") {
               continue // comments, BYTERANGE, and similar tags
            }
            uri = nextLine
            i = j // advance outer loop past consumed lines
            break
         }
         if uri == "" {
            return nil, errors.New("malformed EXTINF: missing segment URI")
         }
         parsedUrl, err := url.Parse(uri)
         if err != nil {
            return nil, fmt.Errorf("invalid segment URI: %w", err)
         }
         newSegment.Uri = parsedUrl
         mediaPlaylist.Segments = append(mediaPlaylist.Segments, newSegment)
      }
   }
   return mediaPlaylist, nil
}

func (mp *MediaPlaylist) ResolveUris(base *url.URL) {
   for _, keyItem := range mp.Keys {
      keyItem.resolve(base)
   }
   for _, segmentItem := range mp.Segments {
      segmentItem.resolve(base)
   }
   if mp.Map != nil {
      mp.Map = base.ResolveReference(mp.Map)
   }
}

type Segment struct {
   Uri      *url.URL
   Duration float64
   Title    string
}

// resolve updates the Segment's URI to be absolute.
func (s *Segment) resolve(base *url.URL) {
   if s.Uri != nil {
      s.Uri = base.ResolveReference(s.Uri)
   }
}

// media_playlist.go marker preserve
