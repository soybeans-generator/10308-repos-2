// master_playlist.go KEEP THIS LINE

package hls

import (
   "errors"
   "fmt"
   "net/url"
   "slices"
   "strings"
)

// MasterPlaylist is a playlist that points at other playlists.
type MasterPlaylist struct {
   Medias     []*Media
   StreamInfs []*StreamInf
}

// DecodeMaster parses a master playlist. base is the location it was loaded from
// and may be empty; every relative URI is resolved against it.
func DecodeMaster(content, base string) (*MasterPlaylist, error) {
   lines := splitLines(content)
   if err := checkHeader(lines); err != nil {
      return nil, err
   }
   master, err := parseMaster(lines)
   if err != nil {
      return nil, err
   }
   if err := master.ResolveUris(base); err != nil {
      return nil, err
   }
   return master, nil
}

func parseMaster(lines []string) (*MasterPlaylist, error) {
   master := &MasterPlaylist{}
   streams := make(map[string]*StreamInf)
   nextId := 0

   for i := 0; i < len(lines); i++ {
      line := lines[i]

      switch {
      case strings.HasPrefix(line, mediaTag):
         media, err := parseMediaTag(line)
         if err != nil {
            return nil, err
         }
         media.Id = nextId
         nextId++
         master.Medias = append(master.Medias, media)

      case strings.HasPrefix(line, streamInfTag):
         attrs, err := parseAttributes(line, streamInfTag)
         if err != nil {
            return nil, fmt.Errorf("invalid EXT-X-STREAM-INF: %w", err)
         }
         // The variant URI is the next line. A tag there means the URI this
         // tag promised is missing; url.Parse would otherwise turn the tag
         // into a fragment-only URL and swallow the real entry.
         if i+1 >= len(lines) {
            return nil, errors.New("malformed EXT-X-STREAM-INF: missing URI")
         }
         i++
         uri := lines[i]
         if strings.HasPrefix(uri, "#") {
            return nil, fmt.Errorf("malformed EXT-X-STREAM-INF: expected URI, got %q", uri)
         }
         bandwidth, err := atoiAttr(attrs, "BANDWIDTH")
         if err != nil {
            return nil, err
         }
         stream, ok := streams[uri]
         if !ok {
            parsed, err := url.Parse(uri)
            if err != nil {
               return nil, fmt.Errorf("invalid URI in EXT-X-STREAM-INF: %w", err)
            }
            stream = &StreamInf{Id: nextId, Uri: parsed}
            nextId++
            streams[uri] = stream
            master.StreamInfs = append(master.StreamInfs, stream)
         }
         // The lowest bandwidth tag is the primary description of the URI
         // and may overwrite what an earlier tag set.
         primary := stream.Bandwidth == 0 || bandwidth < stream.Bandwidth
         if primary && bandwidth > 0 {
            stream.Bandwidth = bandwidth
         }
         if err := stream.applyAttributes(attrs, primary); err != nil {
            return nil, err
         }
         if audio := attrs["AUDIO"]; audio != "" && !slices.Contains(stream.Audio, audio) {
            stream.Audio = append(stream.Audio, audio)
         }
      }
   }
   return master, nil
}

// ResolveUris makes every URI absolute. An unparsable base is an error and leaves
// the playlist untouched; an empty base leaves URIs as written.
func (mp *MasterPlaylist) ResolveUris(base string) error {
   baseUrl, err := parseBase(base)
   if err != nil {
      return err
   }
   for _, stream := range mp.StreamInfs {
      stream.Uri = resolveReference(baseUrl, stream.Uri)
   }
   for _, media := range mp.Medias {
      media.Uri = resolveReference(baseUrl, media.Uri)
   }
   return nil
}

// Media is an #EXT-X-MEDIA tag.
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
   attrs, err := parseAttributes(line, mediaTag)
   if err != nil {
      return nil, fmt.Errorf("invalid EXT-X-MEDIA: %w", err)
   }

   media := &Media{
      Type:       attrs["TYPE"],
      GroupId:    attrs["GROUP-ID"],
      Name:       attrs["NAME"],
      Language:   attrs["LANGUAGE"],
      Channels:   attrs["CHANNELS"],
      AutoSelect: attrs["AUTOSELECT"] == "YES",
   }
   if uri := attrs["URI"]; uri != "" {
      if media.Uri, err = url.Parse(uri); err != nil {
         return nil, fmt.Errorf("invalid URI in EXT-X-MEDIA: %w", err)
      }
   }
   return media, nil
}

// String returns a multi-line summary of the Media.
func (m *Media) String() string {
   var b strings.Builder
   fmt.Fprintln(&b, "type:", m.Type)
   if m.Name != "" {
      fmt.Fprintln(&b, "name:", m.Name)
   }
   if m.Language != "" {
      fmt.Fprintln(&b, "lang:", m.Language)
   }
   if m.GroupId != "" {
      fmt.Fprintln(&b, "group:", m.GroupId)
   }
   fmt.Fprint(&b, "id: ", m.Id)
   return b.String()
}

// StreamInf aggregates the attributes of every #EXT-X-STREAM-INF tag pointing at
// the same URI. Values come from the variant with the lowest bandwidth; whatever
// that variant omits is filled in from the others.
type StreamInf struct {
   Audio            []string
   AverageBandwidth int
   Bandwidth        int
   Codecs           string
   FrameRate        string
   Id               int
   Resolution       string
   Subtitles        string
   Uri              *url.URL
}

// String returns a multi-line summary of the StreamInf.
func (s *StreamInf) String() string {
   var b strings.Builder
   if s.AverageBandwidth > 0 {
      fmt.Fprintln(&b, "average bandwidth:", s.AverageBandwidth)
   }
   fmt.Fprintln(&b, "bandwidth:", s.Bandwidth)
   if s.Resolution != "" {
      fmt.Fprintln(&b, "resolution:", s.Resolution)
   }
   if s.Codecs != "" {
      videoCodec, _, _ := strings.Cut(s.Codecs, ",")
      fmt.Fprintln(&b, "codecs:", videoCodec)
   }
   fmt.Fprint(&b, "id: ", s.Id)
   return b.String()
}

// applyAttributes fills the string fields present in attrs. A value already set
// is only replaced when primary is true, so an incomplete tag cannot erase what a
// primary variant declared.
func (s *StreamInf) applyAttributes(attrs map[string]string, primary bool) error {
   fields := map[string]*string{
      "CODECS":     &s.Codecs,
      "RESOLUTION": &s.Resolution,
      "FRAME-RATE": &s.FrameRate,
      "SUBTITLES":  &s.Subtitles,
   }
   for key, target := range fields {
      if value := attrs[key]; value != "" && (primary || *target == "") {
         *target = value
      }
   }

   average, err := atoiAttr(attrs, "AVERAGE-BANDWIDTH")
   if err != nil {
      return err
   }
   if average > 0 && (primary || s.AverageBandwidth == 0) {
      s.AverageBandwidth = average
   }
   return nil
}

// master_playlist.go KEEP THIS LINE
