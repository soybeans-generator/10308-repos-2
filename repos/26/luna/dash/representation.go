// representation.go KEEP THIS LINE

package dash

import (
   "encoding/base64"
   "fmt"
   "net/url"
   "strings"
)

// ContentProtection describes a DRM scheme applied to a Representation.
type ContentProtection struct {
   SchemeIdUri string `xml:"schemeIdUri,attr"`
   DefaultKid  string `xml:"default_KID,attr"`
   Pssh        string `xml:"pssh"`
}

// GetPssh decodes the base64 encoded PSSH box.
func (cp *ContentProtection) GetPssh() ([]byte, error) {
   if cp.Pssh == "" {
      return nil, nil
   }
   return base64.StdEncoding.DecodeString(cp.Pssh)
}

// Representation is one encoding of a media stream.
type Representation struct {
   Bandwidth         int                  `xml:"bandwidth,attr"`
   BaseUrl           string               `xml:"BaseURL"`
   Codecs            string               `xml:"codecs,attr"`
   ContentProtection []*ContentProtection `xml:"ContentProtection"`
   Height            int                  `xml:"height,attr"`
   Id                string               `xml:"id,attr"`
   MimeType          string               `xml:"mimeType,attr"`
   SegmentBase       *SegmentBase         `xml:"SegmentBase"`
   SegmentList       *SegmentList         `xml:"SegmentList"`
   SegmentTemplate   *SegmentTemplate     `xml:"SegmentTemplate"`
   Width             int                  `xml:"width,attr"`

   Parent *AdaptationSet `xml:"-"`
}

func (r *Representation) GetCodecs() string {
   if r.Codecs == "" && r.Parent != nil {
      return r.Parent.Codecs
   }
   return r.Codecs
}

func (r *Representation) GetContentProtection() []*ContentProtection {
   if len(r.ContentProtection) > 0 {
      return r.ContentProtection
   }
   if r.Parent != nil {
      return r.Parent.ContentProtection
   }
   return nil
}

func (r *Representation) GetHeight() int {
   if r.Height == 0 && r.Parent != nil {
      return r.Parent.Height
   }
   return r.Height
}

func (r *Representation) GetMimeType() string {
   if r.MimeType == "" && r.Parent != nil {
      return r.Parent.MimeType
   }
   return r.MimeType
}

// GetSegmentTemplate returns the representation's own template, falling back to
// the one declared on its AdaptationSet.
func (r *Representation) GetSegmentTemplate() *SegmentTemplate {
   if r.SegmentTemplate != nil {
      return r.SegmentTemplate
   }
   if r.Parent != nil {
      return r.Parent.SegmentTemplate
   }
   return nil
}

func (r *Representation) ResolveBaseUrl() (*url.URL, error) {
   if r.Parent == nil {
      return resolveRef(nil, r.BaseUrl)
   }
   base, err := r.Parent.resolveBaseUrl()
   if err != nil {
      return nil, err
   }
   return resolveRef(base, r.BaseUrl)
}

// String returns a multi-line summary of the Representation.
func (r *Representation) String() string {
   var b strings.Builder

   fmt.Fprintln(&b, "bandwidth:", r.Bandwidth)
   if width := r.getWidth(); width != 0 {
      fmt.Fprintln(&b, "width:", width)
   }
   if height := r.GetHeight(); height != 0 {
      fmt.Fprintln(&b, "height:", height)
   }
   if codecs := r.GetCodecs(); codecs != "" {
      fmt.Fprintln(&b, "codecs:", codecs)
   }
   fmt.Fprintln(&b, "mimeType:", r.GetMimeType())
   if label := r.getLabel(); label != "" {
      fmt.Fprintln(&b, "label:", label)
   } else if lang := r.getLang(); lang != "" {
      fmt.Fprintln(&b, "lang:", lang)
   }
   if role := r.getRole(); role != "" {
      fmt.Fprintln(&b, "role:", role)
   }
   if duration := r.getPeriodDuration(); duration != "" {
      fmt.Fprintln(&b, "period duration:", duration)
   }
   b.WriteString("id: ")
   b.WriteString(r.Id)

   return b.String()
}

func (r *Representation) getLabel() string {
   if r.Parent == nil {
      return ""
   }
   return r.Parent.Label
}

func (r *Representation) getLang() string {
   if r.Parent == nil {
      return ""
   }
   return r.Parent.Lang
}

func (r *Representation) getPeriodDuration() string {
   if r.Parent == nil || r.Parent.Parent == nil {
      return ""
   }
   return r.Parent.Parent.Duration
}

func (r *Representation) getRole() string {
   if r.Parent == nil || r.Parent.Role == nil {
      return ""
   }
   return r.Parent.Role.Value
}

func (r *Representation) getWidth() int {
   if r.Width == 0 && r.Parent != nil {
      return r.Parent.Width
   }
   return r.Width
}

func (r *Representation) link() {
   if r.SegmentTemplate != nil {
      r.SegmentTemplate.parentRepresentation = r
   }
   if r.SegmentList != nil {
      r.SegmentList.parent = r
      r.SegmentList.link()
   }
}

// requiresOriginalId reports whether the media template references the ID and
// therefore cannot have it rewritten.
func (r *Representation) requiresOriginalId() bool {
   tmpl := r.GetSegmentTemplate()
   if tmpl == nil {
      return true
   }
   return strings.Contains(tmpl.Media, "$RepresentationID$")
}

// representation.go KEEP THIS LINE
