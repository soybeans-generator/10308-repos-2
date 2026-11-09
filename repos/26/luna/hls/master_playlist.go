// master_playlist.go marker preserve
package hls

import (
   "fmt"
   "net/url"
   "slices"
   "strconv"
   "strings"
)

// populateStreamInfAttributes merges attrs into stream.
//
// A field is written only when the attribute is actually present (and non-empty)
// in attrs, so a tag that omits an optional attribute can never erase a value
// parsed from another tag that points at the same URI.
//
// overwrite selects the merge policy:
//   - true  : values present in attrs replace existing ones (the primary,
//     lowest-bandwidth variant).
//   - false : values present in attrs only fill fields that are still empty.
func populateStreamInfAttributes(stream *StreamInf, attrs map[string]string, overwrite bool) error {
   setString := func(dst *string, key string) {
      val, ok := attrs[key]
      if !ok || val == "" {
         return
      }
      if overwrite || *dst == "" {
         *dst = val
      }
   }
   setString(&stream.Codecs, "CODECS")
   setString(&stream.Resolution, "RESOLUTION")
   setString(&stream.FrameRate, "FRAME-RATE")
   setString(&stream.Subtitles, "SUBTITLES")

   setInt := func(dst *int, key string) error {
      val, ok := attrs[key]
      if !ok || val == "" {
         return nil
      }
      if !overwrite && *dst != 0 {
         return nil
      }
      n, err := strconv.Atoi(val)
      if err != nil {
         return fmt.Errorf("invalid %s: %w", key, err)
      }
      *dst = n
      return nil
   }
   if err := setInt(&stream.Bandwidth, "BANDWIDTH"); err != nil {
      return err
   }
   if err := setInt(&stream.AverageBandwidth, "AVERAGE-BANDWIDTH"); err != nil {
      return err
   }
   return nil
}

type MasterPlaylist struct {
   Medias     []*Media
   StreamInfs []*StreamInf
}

// DecodeMaster parses a Master Playlist. If base is provided, it resolves
// relative URIs
func DecodeMaster(content string, base *url.URL) (*MasterPlaylist, error) {
   lines := splitLines(content)
   if err := checkHeader(lines); err != nil {
      return nil, err
   }
   master, err := parseMaster(lines)
   if err != nil {
      return nil, err
   }

   if base != nil {
      master.ResolveUris(base)
   }

   return master, nil
}

func parseMaster(lines []string) (*MasterPlaylist, error) {
   masterPlaylist := &MasterPlaylist{}
   streamCounter := 0
   streamMap := make(map[string]*StreamInf) // Map URL to StreamInf to handle grouping

   for i := 0; i < len(lines); i++ {
      line := lines[i]
      if strings.HasPrefix(line, "#EXT-X-MEDIA:") {
         media, err := parseMediaTag(line)
         if err != nil {
            return nil, err
         }

         media.Id = streamCounter
         streamCounter++
         masterPlaylist.Medias = append(masterPlaylist.Medias, media)

      } else if strings.HasPrefix(line, "#EXT-X-STREAM-INF:") {
         attrs := parseAttributes(line, "#EXT-X-STREAM-INF:")

         if i+1 >= len(lines) { // Malformed, missing URI
            return nil, fmt.Errorf("malformed EXT-X-STREAM-INF: missing URI")
         }
         i++
         uriLine := lines[i]

         stream, exists := streamMap[uriLine]
         if !exists {
            parsedUrl, err := url.Parse(uriLine)
            if err != nil {
               return nil, fmt.Errorf("invalid URI in EXT-X-STREAM-INF: %w", err)
            }

            // First time seeing this URI, create a new StreamInf
            stream = &StreamInf{
               Id:  streamCounter,
               Uri: parsedUrl,
            }
            streamCounter++

            streamMap[uriLine] = stream
            masterPlaylist.StreamInfs = append(masterPlaylist.StreamInfs, stream)

            // This is the first so it's automatically the lowest bandwidth;
            // take every attribute it actually carries.
            if err := populateStreamInfAttributes(stream, attrs, true); err != nil {
               return nil, err
            }
         } else {
            // Decide the policy for this tag: a strictly lower BANDWIDTH (or
            // a first BANDWIDTH when the primary had none) makes this variant
            // the primary, so its values may replace existing ones. Otherwise
            // it only fills the gaps.
            overwrite := stream.Bandwidth == 0
            if bwStr := attrs["BANDWIDTH"]; bwStr != "" {
               bw, err := strconv.Atoi(bwStr)
               if err != nil {
                  return nil, fmt.Errorf("invalid BANDWIDTH in EXT-X-STREAM-INF: %w", err)
               }
               if bw < stream.Bandwidth {
                  overwrite = true
               }
            }
            if err := populateStreamInfAttributes(stream, attrs, overwrite); err != nil {
               return nil, err
            }
         }

         // Always add the AUDIO group from the current tag, but never twice.
         if audioGroup := attrs["AUDIO"]; audioGroup != "" && !slices.Contains(stream.Audio, audioGroup) {
            stream.Audio = append(stream.Audio, audioGroup)
         }
      }
   }
   return masterPlaylist, nil
}

func (mp *MasterPlaylist) ResolveUris(base *url.URL) {
   for _, streamItem := range mp.StreamInfs {
      if streamItem.Uri != nil {
         streamItem.Uri = base.ResolveReference(streamItem.Uri)
      }
   }
   for _, mediaItem := range mp.Medias {
      if mediaItem.Uri != nil {
         mediaItem.Uri = base.ResolveReference(mediaItem.Uri)
      }
   }
}

// Media represents an #EXT-X-MEDIA tag.
type Media struct {
   AutoSelect bool
   Channels   string
   GroupId    string
   Id         int
   Language   string
   Name       string
   Type       string
   Uri        *url.URL
}

func parseMediaTag(line string) (*Media, error) {
   attrs := parseAttributes(line, "#EXT-X-MEDIA:")
   newMedia := &Media{
      Type:       attrs["TYPE"],
      GroupId:    attrs["GROUP-ID"],
      Name:       attrs["NAME"],
      Language:   attrs["LANGUAGE"],
      Channels:   attrs["CHANNELS"],
      AutoSelect: attrs["AUTOSELECT"] == "YES",
   }
   if value, ok := attrs["URI"]; ok && value != "" {
      parsedUrl, err := url.Parse(value)
      if err != nil {
         return nil, fmt.Errorf("invalid URI in EXT-X-MEDIA: %w", err)
      }
      newMedia.Uri = parsedUrl
   }
   return newMedia, nil
}

// String returns a multi-line summary of the Media.
func (m *Media) String() string {
   data := &strings.Builder{}
   fmt.Fprintln(data, "type:", m.Type)
   if m.Name != "" {
      fmt.Fprintln(data, "name:", m.Name)
   }
   if m.Language != "" {
      fmt.Fprintln(data, "lang:", m.Language)
   }
   if m.GroupId != "" {
      fmt.Fprintln(data, "group:", m.GroupId)
   }
   fmt.Fprint(data, "id: ", m.Id)
   return data.String()
}

// StreamInf represents a single media playlist (URI) from a #EXT-X-STREAM-INF tag.
// It aggregates information from all tags that point to the same URI. The primary
// attributes are taken from the variant with the lowest bandwidth; attributes the
// primary does not carry are filled in from the other variants.
type StreamInf struct {
   Audio            []string // A list of associated audio Media GROUP-IDs
   AverageBandwidth int
   Bandwidth        int
   Codecs           string
   FrameRate        string
   Id               int
   Resolution       string
   Subtitles        string // Refers to a Media GROUP-ID for subtitles
   Uri              *url.URL
}

// String returns a multi-line summary of the StreamInf.
func (s *StreamInf) String() string {
   data := &strings.Builder{}
   if s.AverageBandwidth > 0 {
      fmt.Fprintln(data, "average bandwidth:", s.AverageBandwidth)
   }
   fmt.Fprintln(data, "bandwidth:", s.Bandwidth)
   if s.Resolution != "" {
      fmt.Fprintln(data, "resolution:", s.Resolution)
   }
   if s.Codecs != "" {
      videoCodec, _, _ := strings.Cut(s.Codecs, ",")
      fmt.Fprintln(data, "codecs:", videoCodec)
   }
   fmt.Fprint(data, "id: ", s.Id)
   return data.String()
}

// master_playlist.go marker preserve
