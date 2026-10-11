// utils.go marker preserve
package hls

import (
   "encoding/base64"
   "errors"
   "fmt"
   "net/url"
   "strings"
)

// parseAttributes parses HLS attribute lists (e.g., KEY="VAL",KEY2=VAL).
// It handles quoted strings containing commas.
func parseAttributes(line string, tagPrefix string) map[string]string {
   line = strings.TrimPrefix(line, tagPrefix)
   attributes := make(map[string]string)

   var keyBuilder, valueBuilder strings.Builder
   inKey := true
   inQuote := false

   for i := 0; i < len(line); i++ {
      char := line[i]

      if inKey {
         if char == '=' {
            inKey = false
         } else {
            keyBuilder.WriteByte(char)
         }
      } else {
         // Inside the value part
         if char == '"' {
            inQuote = !inQuote
            continue // Skip the actual quote character
         }

         // If we hit a comma and we are NOT in a quote, it's the end of the pair
         if char == ',' && !inQuote {
            keyString := strings.TrimSpace(keyBuilder.String())
            valueString := valueBuilder.String()
            attributes[keyString] = valueString

            // Reset
            keyBuilder.Reset()
            valueBuilder.Reset()
            inKey = true
         } else {
            valueBuilder.WriteByte(char)
         }
      }
   }

   // Flush the final pair
   if keyBuilder.Len() > 0 {
      keyString := strings.TrimSpace(keyBuilder.String())
      valueString := valueBuilder.String()
      attributes[keyString] = valueString
   }

   return attributes
}

// Helper to split lines, ignoring empty lines and carriage returns,
// but preserving leading/trailing spaces.
func splitLines(content string) []string {
   return strings.FieldsFunc(content, func(r rune) bool {
      return r == '\n' || r == '\r'
   })
}

// Key represents encryption info from a #EXT-X-KEY tag.
type Key struct {
   Method            string
   Uri               *url.URL
   KeyFormat         string
   KeyFormatVersions string
   Characteristics   string
}

func parseKey(line string) (*Key, error) {
   prefix := "#EXT-X-KEY:"
   attrs := parseAttributes(line, prefix)
   newKey := &Key{
      Method:            attrs["METHOD"],
      KeyFormat:         attrs["KEYFORMAT"],
      KeyFormatVersions: attrs["KEYFORMATVERSIONS"],
      Characteristics:   attrs["CHARACTERISTICS"],
   }
   if value, ok := attrs["URI"]; ok && value != "" {
      parsedUrl, err := url.Parse(value)
      if err != nil {
         return nil, fmt.Errorf("invalid URI in EXT-X-KEY: %w", err)
      }
      newKey.Uri = parsedUrl
   }
   return newKey, nil
}

// DecodeData extracts and decodes the Base64 data directly from the URL Opaque field.
func (k *Key) DecodeData() ([]byte, error) {
   if k.Uri == nil {
      return nil, errors.New("URI is nil")
   }
   if k.Uri.Scheme != "data" {
      return nil, errors.New("URI is not a data URI")
   }
   // For data URIs, net/url stores the content (mime+encoding+data) in Opaque.
   // Format: [<mediatype>][;base64],<data>
   meta, dataString, found := strings.Cut(k.Uri.Opaque, ",")
   if !found {
      return nil, errors.New("invalid data URI: missing comma separator")
   }
   // Verify base64 encoding is specified in the metadata (before the comma)
   if !strings.Contains(meta, ";base64") {
      return nil, errors.New("data URI does not contain base64 indicator")
   }
   return base64.StdEncoding.DecodeString(dataString)
}

func (k *Key) resolve(base *url.URL) {
   if k.Uri != nil {
      k.Uri = base.ResolveReference(k.Uri)
   }
}

// utils.go marker preserve
