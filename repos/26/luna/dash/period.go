// period.go KEEP THIS LINE

package dash

import (
   "errors"
   "net/url"
   "strings"
   "time"
)

// AdaptationSet groups interchangeable Representations.
type AdaptationSet struct {
   Codecs            string               `xml:"codecs,attr"`
   ContentProtection []*ContentProtection `xml:"ContentProtection"`
   Height            int                  `xml:"height,attr"`
   Label             string               `xml:"Label"`
   Lang              string               `xml:"lang,attr"`
   MimeType          string               `xml:"mimeType,attr"`
   Representations   []*Representation    `xml:"Representation"`
   Role              *Role                `xml:"Role"`
   SegmentTemplate   *SegmentTemplate     `xml:"SegmentTemplate"`
   Width             int                  `xml:"width,attr"`

   Parent *Period `xml:"-"`
}

func (as *AdaptationSet) link() {
   as.Label = strings.TrimSpace(as.Label)
   if as.SegmentTemplate != nil {
      as.SegmentTemplate.ParentAdaptationSet = as
   }
   for _, rep := range as.Representations {
      rep.Parent = as
      rep.link()
   }
}

func (as *AdaptationSet) resolveBaseUrl() (*url.URL, error) {
   if as.Parent == nil {
      return nil, errors.New("dash: adaptation set has no parent period")
   }
   return as.Parent.ResolveBaseUrl()
}

// Period is a temporal section of the presentation.
type Period struct {
   Duration       string           `xml:"duration,attr"`
   Id             string           `xml:"id,attr"`
   BaseUrl        string           `xml:"BaseURL"`
   AdaptationSets []*AdaptationSet `xml:"AdaptationSet"`

   Parent *Mpd `xml:"-"`
}

// GetDuration returns the period duration, falling back to the presentation
// duration.
func (p *Period) GetDuration() (time.Duration, error) {
   raw := p.Duration
   if raw == "" && p.Parent != nil {
      raw = p.Parent.MediaPresentationDuration
   }
   if raw == "" {
      return 0, nil
   }
   return time.ParseDuration(strings.ToLower(strings.TrimPrefix(raw, "PT")))
}

func (p *Period) ResolveBaseUrl() (*url.URL, error) {
   if p.Parent == nil {
      return resolveRef(nil, p.BaseUrl)
   }
   base, err := p.Parent.ResolveBaseUrl()
   if err != nil {
      return nil, err
   }
   return resolveRef(base, p.BaseUrl)
}

func (p *Period) link() {
   for _, set := range p.AdaptationSets {
      set.Parent = p
      set.link()
   }
}

// Role states the purpose of an AdaptationSet's content.
type Role struct {
   Value string `xml:"value,attr"`
}

// period.go KEEP THIS LINE
