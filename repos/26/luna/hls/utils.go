// utils.go KEEP THIS LINE

package hls

import (
   "encoding/base64"
   "errors"
   "fmt"
   "net/url"
   "strconv"
   "strings"
)

const (
   keyTag       = "#EXT-X-KEY:"
   mapTag       = "#EXT-X-MAP:"
   extInfTag    = "#EXTINF:"
   mediaTag     = "#EXT-X-MEDIA:"
   streamInfTag = "#EXT-X-STREAM-INF:"
)

// atoiAttr parses an integer attribute, returning 0 when it is absent.
func atoiAttr(attrs map[string]string, key string) (int, error) {
   raw := attrs[key]
   if raw == "" {
      return 0, nil
   }
   n, err := strconv.Atoi(raw)
   if err != nil {
      return 0, fmt.Errorf("invalid %s: %w", key, err)
   }
   return n, nil
}

// checkHeader verifies the mandatory #EXTM3U prologue.
func checkHeader(lines []string) error {
   if len(lines) == 0 || lines[0] != "#EXTM3U" {
      return errors.New("not an HLS playlist: missing #EXTM3U")
   }
   return nil
}

// parseAttributes parses an attribute list such as METHOD=AES-128,URI="k.bin".
// Quoted values may contain commas and the quotes themselves are stripped.
func parseAttributes(line, prefix string) (map[string]string, error) {
   attrs := make(map[string]string)
   var key, value strings.Builder
   inValue, quoted := false, false

   flush := func() error {
      if key.Len() == 0 {
         return nil
      }
      if !inValue {
         return fmt.Errorf("invalid attribute %q: missing '='", key.String())
      }
      attrs[strings.TrimSpace(key.String())] = strings.Trim(value.String(), `"`)
      key.Reset()
      value.Reset()
      inValue = false
      return nil
   }

   for _, r := range strings.TrimPrefix(line, prefix) {
      switch {
      case r == '"':
         quoted = !quoted
      case quoted:
         value.WriteRune(r)
      case r == ',':
         if err := flush(); err != nil {
            return nil, err
         }
      case r == '=' && !inValue:
         inValue = true
      case inValue:
         value.WriteRune(r)
      default:
         key.WriteRune(r)
      }
   }
   return attrs, flush()
}

// parseBase parses the playlist location. An empty location yields a nil base,
// which leaves URIs as written; a malformed one is an error.
func parseBase(base string) (*url.URL, error) {
   if base == "" {
      return nil, nil
   }
   parsed, err := url.Parse(base)
   if err != nil {
      return nil, fmt.Errorf("invalid base URL %q: %w", base, err)
   }
   return parsed, nil
}

// resolveReference resolves ref against base; a nil on either side returns ref.
func resolveReference(base, ref *url.URL) *url.URL {
   if base == nil || ref == nil {
      return ref
   }
   return base.ResolveReference(ref)
}

// splitLines splits a playlist into non-empty lines, preserving spaces.
func splitLines(content string) []string {
   return strings.FieldsFunc(content, func(r rune) bool { return r == '\n' || r == '\r' })
}

// Key is the encryption information of an #EXT-X-KEY tag.
type Key struct {
   Method            string
   Uri               *url.URL
   KeyFormat         string
   KeyFormatVersions string
   Characteristics   string
}

func parseKey(line string) (*Key, error) {
   attrs, err := parseAttributes(line, keyTag)
   if err != nil {
      return nil, fmt.Errorf("invalid EXT-X-KEY: %w", err)
   }

   key := &Key{
      Method:            attrs["METHOD"],
      KeyFormat:         attrs["KEYFORMAT"],
      KeyFormatVersions: attrs["KEYFORMATVERSIONS"],
      Characteristics:   attrs["CHARACTERISTICS"],
   }
   if uri := attrs["URI"]; uri != "" {
      if key.Uri, err = url.Parse(uri); err != nil {
         return nil, fmt.Errorf("invalid URI in EXT-X-KEY: %w", err)
      }
   }
   return key, nil
}

// DecodeData returns the key bytes carried by a data URI.
func (k *Key) DecodeData() ([]byte, error) {
   switch {
   case k.Uri == nil:
      return nil, errors.New("URI is nil")
   case k.Uri.Scheme != "data":
      return nil, errors.New("URI is not a data URI")
   }
   // net/url keeps the payload of a data URI in Opaque: [<mediatype>][;base64],<data>.
   meta, payload, found := strings.Cut(k.Uri.Opaque, ",")
   if !found {
      return nil, errors.New("invalid data URI: missing comma separator")
   }
   if !strings.Contains(meta, ";base64") {
      return nil, errors.New("data URI does not contain base64 indicator")
   }
   decoded, err := base64.StdEncoding.DecodeString(payload)
   if err != nil {
      return nil, fmt.Errorf("invalid base64 payload in data URI: %w", err)
   }
   return decoded, nil
}

// utils.go KEEP THIS LINE
