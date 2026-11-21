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

   parent *SegmentList
}

func (i *Initialization) ResolveSourceUrl() (*url.URL, error) {
   if i.parent == nil {
      return url.Parse(i.SourceUrl)
   }
   base, err := i.parent.parentBaseUrl()
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

   parent *Representation
}

func (sl *SegmentList) GetTimescale() uint {
   if sl.Timescale != nil {
      return *sl.Timescale
   }
   return 1
}

func (sl *SegmentList) link() {
   if sl.Initialization != nil {
      sl.Initialization.parent = sl
   }
   for _, segment := range sl.SegmentUrls {
      segment.parent = sl
   }
}

func (sl *SegmentList) parentBaseUrl() (*url.URL, error) {
   if sl.parent == nil {
      return nil, errors.New("dash: segment list has no parent representation")
   }
   return sl.parent.ResolveBaseUrl()
}

// SegmentUrl is one media segment of a SegmentList.
type SegmentUrl struct {
   Media      string `xml:"media,attr"`
   MediaRange string `xml:"mediaRange,attr"`

   parent *SegmentList
}

func (su *SegmentUrl) ResolveMedia() (*url.URL, error) {
   if su.parent == nil {
      return nil, errors.New("dash: segment url is not linked to a segment list")
   }
   base, err := su.parent.parentBaseUrl()
   if err != nil {
      return nil, err
   }
   return resolveRef(base, su.Media)
}

// segment_list.go KEEP THIS LINE
