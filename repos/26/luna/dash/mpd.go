// mpd.go KEEP THIS LINE

package dash

import (
   "encoding/xml"
   "net/url"
   "strconv"
)

// resolveRef resolves ref against base; an empty ref keeps base, a nil base
// keeps ref.
func resolveRef(base *url.URL, ref string) (*url.URL, error) {
   if ref == "" {
      return base, nil
   }
   u, err := url.Parse(ref)
   if err != nil || base == nil {
      return u, err
   }
   return base.ResolveReference(u), nil
}

// Mpd is the root element of a DASH media presentation description.
type Mpd struct {
   MediaPresentationDuration string    `xml:"mediaPresentationDuration,attr"`
   BaseUrl                   string    `xml:"BaseURL"`
   Periods                   []*Period `xml:"Period"`

   mpdUrl *url.URL
}

// Parse decodes an MPD document, links its tree and normalizes representation
// IDs. mpdUrl is the manifest location and may be nil.
func Parse(data []byte, mpdUrl *url.URL) (*Mpd, error) {
   m := &Mpd{mpdUrl: mpdUrl}
   if err := xml.Unmarshal(data, m); err != nil {
      return nil, err
   }
   m.link()
   m.normalizeIds()
   return m, nil
}

// GetRepresentations groups all Representations by ID, one entry per Period.
func (m *Mpd) GetRepresentations() map[string][]*Representation {
   grouped := make(map[string][]*Representation)
   for _, p := range m.Periods {
      for _, set := range p.AdaptationSets {
         for _, rep := range set.Representations {
            reps := grouped[rep.Id]
            if len(reps) > 0 && reps[len(reps)-1].Parent.Parent == p {
               continue
            }
            grouped[rep.Id] = append(reps, rep)
         }
      }
   }
   return grouped
}

func (m *Mpd) eachRep(fn func(*Representation)) {
   for _, p := range m.Periods {
      for _, set := range p.AdaptationSets {
         for _, rep := range set.Representations {
            fn(rep)
         }
      }
   }
}

func (m *Mpd) link() {
   for _, p := range m.Periods {
      p.parent = m
      p.link()
   }
}

// normalizeIds rewrites representation IDs as sequential integers, except where
// the media template references the ID. Representations sharing a media
// template share one ID.
func (m *Mpd) normalizeIds() {
   reserved := make(map[string]bool)
   m.eachRep(func(r *Representation) {
      if r.requiresOriginalId() {
         reserved[r.Id] = true
      }
   })
   shared := make(map[string]string)
   next := 0
   m.eachRep(func(r *Representation) {
      tmpl := r.GetSegmentTemplate()
      if r.requiresOriginalId() || tmpl == nil {
         return
      }
      id, ok := shared[tmpl.Media]
      if !ok {
         for reserved[strconv.Itoa(next)] {
            next++
         }
         id = strconv.Itoa(next)
         next++
         shared[tmpl.Media] = id
      }
      r.Id = id
   })
}

func (m *Mpd) resolveBaseUrl() (*url.URL, error) {
   return resolveRef(m.mpdUrl, m.BaseUrl)
}

// mpd.go KEEP THIS LINE
