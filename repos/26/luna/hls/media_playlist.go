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
   TargetDuration int
   MediaSequence  int
   Version        int
   PlaylistType   string
   Segments       []*Segment
   Keys           []*Key
   Map            *url.URL
   EndList        bool
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
      "#EXT-X-VERSION:":        &playlist.Version,
      "#EXT-X-TARGETDURATION:": &playlist.TargetDuration,
      "#EXT-X-MEDIA-SEQUENCE:": &playlist.MediaSequence,
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
         playlist.PlaylistType = strings.TrimPrefix(line, "#EXT-X-PLAYLIST-TYPE:")

      case strings.HasPrefix(line, "#EXT-X-ENDLIST"):
         playlist.EndList = true

      case strings.HasPrefix(line, keyTag):
         key, err := parseKey(line)
         if err != nil {
            return nil, err
         }
         playlist.Keys = append(playlist.Keys, key)

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

// ResolveUris makes every URI absolute. An unparsable base is an error and leaves
// the playlist untouched; an empty base leaves URIs as written.
func (mp *MediaPlaylist) ResolveUris(base string) error {
   baseUrl, err := parseBase(base)
   if err != nil {
      return err
   }
   for _, key := range mp.Keys {
      key.Uri = resolveReference(baseUrl, key.Uri)
   }
   for _, segment := range mp.Segments {
      segment.Uri = resolveReference(baseUrl, segment.Uri)
   }
   mp.Map = resolveReference(baseUrl, mp.Map)
   return nil
}

// Segment is one media segment of a media playlist.
type Segment struct {
   Uri      *url.URL
   Duration float64
   Title    string
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

   segment := &Segment{Uri: parsed, Duration: duration, Title: strings.TrimSpace(title)}
   return segment, uriLine, nil
}

// media_playlist.go KEEP THIS LINE
