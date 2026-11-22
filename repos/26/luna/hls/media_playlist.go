// media_playlist.go KEEP THIS LINE

package hls

import (
   "errors"
   "fmt"
   "net/url"
   "strconv"
   "strings"
)

// segmentUri finds the URI belonging to the #EXTINF at index i. Tags such as
// #EXT-X-BYTERANGE may sit in between, but the search stops at the next entry so
// a URI-less #EXTINF cannot consume its neighbour's URI.
func segmentUri(lines []string, i int) (string, int, error) {
   for j := i + 1; j < len(lines); j++ {
      line := lines[j]
      if !strings.HasPrefix(line, "#") {
         return line, j, nil
      }
      if strings.HasPrefix(line, extInfTag) || strings.HasPrefix(line, "#EXT-X-ENDLIST") {
         break
      }
   }
   return "", i, errors.New("malformed EXTINF: missing segment URI")
}

// MediaPlaylist is a playlist of media segments.
type MediaPlaylist struct {
   targetDuration int
   mediaSequence  int
   version        int
   playlistType   string
   Segments       []*Segment
   keys           []*key
   Map            *url.URL
   endList        bool
}

// DecodeMedia parses a media playlist. Use ResolveUris to make its URIs absolute.
func DecodeMedia(content string) (*MediaPlaylist, error) {
   lines := splitLines(content)
   if err := checkHeader(lines); err != nil {
      return nil, err
   }
   return parseMedia(lines)
}

func parseMedia(lines []string) (*MediaPlaylist, error) {
   playlist := &MediaPlaylist{}
   // Integer tags map directly onto a field, so they share one parse path.
   intTags := map[string]*int{
      "#EXT-X-VERSION:":        &playlist.version,
      "#EXT-X-TARGETDURATION:": &playlist.targetDuration,
      "#EXT-X-MEDIA-SEQUENCE:": &playlist.mediaSequence,
   }

   for i := 0; i < len(lines); i++ {
      line := lines[i]
      if tag, value, found := strings.Cut(line, ":"); found {
         if target, ok := intTags[tag+":"]; ok {
            n, err := strconv.Atoi(value)
            if err != nil {
               return nil, fmt.Errorf("invalid %s tag: %w", tag, err)
            }
            *target = n
            continue
         }
      }

      switch {
      case strings.HasPrefix(line, "#EXT-X-PLAYLIST-TYPE:"):
         playlist.playlistType = strings.TrimPrefix(line, "#EXT-X-PLAYLIST-TYPE:")

      case strings.HasPrefix(line, "#EXT-X-ENDLIST"):
         playlist.endList = true

      case strings.HasPrefix(line, keyTag):
         k, err := parseKey(line)
         if err != nil {
            return nil, err
         }
         playlist.keys = append(playlist.keys, k)

      case strings.HasPrefix(line, mapTag):
         attrs, err := parseAttributes(line, mapTag)
         if err != nil {
            return nil, fmt.Errorf("invalid EXT-X-MAP: %w", err)
         }
         if uri := attrs["URI"]; uri != "" {
            if playlist.Map, err = url.Parse(uri); err != nil {
               return nil, fmt.Errorf("invalid URI in EXT-X-MAP: %w", err)
            }
         }

      case strings.HasPrefix(line, extInfTag):
         segment, uriLine, err := parseSegment(lines, i)
         if err != nil {
            return nil, err
         }
         i = uriLine
         playlist.Segments = append(playlist.Segments, segment)
      }
   }
   return playlist, nil
}

// ResolveUris makes every URI absolute. A nil base leaves URIs as written.
func (mp *MediaPlaylist) ResolveUris(base *url.URL) {
   for _, k := range mp.keys {
      k.uri = resolveReference(base, k.uri)
   }
   for _, segment := range mp.Segments {
      segment.Uri = resolveReference(base, segment.Uri)
   }
   mp.Map = resolveReference(base, mp.Map)
}

// Segment is one media segment of a media playlist.
type Segment struct {
   Uri      *url.URL
   Duration float64
   title    string
}

// parseSegment parses the #EXTINF at index i and the URI that follows it,
// returning the segment and the index of the URI line.
func parseSegment(lines []string, i int) (*Segment, int, error) {
   durationStr, title, _ := strings.Cut(strings.TrimPrefix(lines[i], extInfTag), ",")
   duration, err := strconv.ParseFloat(durationStr, 64)
   if err != nil {
      return nil, i, fmt.Errorf("invalid EXTINF duration: %w", err)
   }

   uri, uriLine, err := segmentUri(lines, i)
   if err != nil {
      return nil, i, err
   }
   parsed, err := url.Parse(uri)
   if err != nil {
      return nil, i, fmt.Errorf("invalid segment URI: %w", err)
   }

   segment := &Segment{Uri: parsed, Duration: duration, title: strings.TrimSpace(title)}
   return segment, uriLine, nil
}

// media_playlist.go KEEP THIS LINE
