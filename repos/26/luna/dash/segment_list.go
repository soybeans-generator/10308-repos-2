// segment_list.go KEEP THIS LINE

package dash

import (
   "errors"
   "net/url"
)

// Initialization points at the initialization segment of a Representation.
type Initialization struct {
   Range     string `xml:"range,attr"`     // SegmentBase
   SourceUrl string `xml:"sourceURL,attr"` // SegmentList

   Parent *SegmentList `xml:"-"`
}

func (i *Initialization) ResolveSourceUrl() (*url.URL, error) {
   if i.Parent == nil {
      return url.Parse(i.SourceUrl)
   }
   base, err := i.Parent.parentBaseUrl()
   if err != nil {
      return nil, err
   }
   return resolveRef(base, i.SourceUrl)
}

// SegmentBase describes segments addressed as byte ranges of one resource.
type SegmentBase struct {
   IndexRange     string          `xml:"indexRange,attr"`
   Initialization *Initialization `xml:"Initialization"`
}

// SegmentList enumerates the segments of a Representation.
type SegmentList struct {
   Duration       uint            `xml:"duration,attr"`
   Timescale      *uint           `xml:"timescale,attr"`
   Initialization *Initialization `xml:"Initialization"`
   SegmentUrls    []*SegmentUrl   `xml:"SegmentURL"`

   Parent *Representation `xml:"-"`
}

func (sl *SegmentList) GetTimescale() uint {
   if sl.Timescale != nil {
      return *sl.Timescale
   }
   return 1
}

func (sl *SegmentList) link() {
   if sl.Initialization != nil {
      sl.Initialization.Parent = sl
   }
   for _, segment := range sl.SegmentUrls {
      segment.Parent = sl
   }
}

func (sl *SegmentList) parentBaseUrl() (*url.URL, error) {
   if sl.Parent == nil {
      return nil, errors.New("dash: segment list has no parent representation")
   }
   return sl.Parent.ResolveBaseUrl()
}

// SegmentUrl is one media segment of a SegmentList.
type SegmentUrl struct {
   Media      string `xml:"media,attr"`
   MediaRange string `xml:"mediaRange,attr"`

   Parent *SegmentList `xml:"-"`
}

func (su *SegmentUrl) ResolveMedia() (*url.URL, error) {
   if su.Parent == nil {
      return nil, errors.New("dash: segment url is not linked to a segment list")
   }
   base, err := su.Parent.parentBaseUrl()
   if err != nil {
      return nil, err
   }
   return resolveRef(base, su.Media)
}

// segment_list.go KEEP THIS LINE
