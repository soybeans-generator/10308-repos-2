// segment_template.go KEEP THIS LINE

package dash

import (
   "errors"
   "fmt"
   "math"
   "net/url"
   "strconv"
   "strings"
)

// S is one SegmentTimeline entry.
type S struct {
   D uint `xml:"d,attr"` // duration in timescale units
   R int  `xml:"r,attr"` // repeat count
}

// SegmentTemplate generates media URLs from a template plus a numbering or
// timing scheme.
type SegmentTemplate struct {
   Duration               uint             `xml:"duration,attr"`
   EndNumber              uint             `xml:"endNumber,attr"`
   Initialization         string           `xml:"initialization,attr"`
   Media                  string           `xml:"media,attr"`
   PresentationTimeOffset uint             `xml:"presentationTimeOffset,attr"`
   StartNumber            *uint            `xml:"startNumber,attr"`
   Timescale              *uint            `xml:"timescale,attr"`
   SegmentTimeline        *SegmentTimeline `xml:"SegmentTimeline"`

   ParentAdaptationSet  *AdaptationSet  `xml:"-"`
   ParentRepresentation *Representation `xml:"-"`
}

// GetDurationBasedNumbers expands the fixed duration across the period.
func (st *SegmentTemplate) GetDurationBasedNumbers() ([]uint, error) {
   period := st.period()
   if period == nil {
      return nil, errors.New("dash: segment template is not linked to a period")
   }
   if st.Duration == 0 {
      return nil, errors.New("dash: segment template duration is zero")
   }
   total, err := period.GetDuration()
   if err != nil {
      return nil, err
   }
   if total == 0 {
      return nil, errors.New("dash: period duration is zero or missing")
   }
   segment := float64(st.Duration) / float64(st.GetTimescale())
   count := uint(math.Ceil(total.Seconds() / segment))
   start := st.GetStartNumber()
   numbers := make([]uint, count)
   for i := range numbers {
      numbers[i] = start + uint(i)
   }
   return numbers, nil
}

func (st *SegmentTemplate) GetNumberRange() []uint {
   start := st.GetStartNumber()
   if st.EndNumber < start {
      return nil
   }
   numbers := make([]uint, st.EndNumber-start+1)
   for i := range numbers {
      numbers[i] = start + uint(i)
   }
   return numbers
}

// GetSegmentUrls returns the media URLs produced by the template.
func (st *SegmentTemplate) GetSegmentUrls(rep *Representation) ([]*url.URL, error) {
   if st.Media == "" {
      return nil, nil
   }
   if strings.Contains(st.Media, "$Time$") {
      times := st.GetTimelineTimes()
      if len(times) == 0 {
         return nil, errors.New("dash: $Time$ media template without a SegmentTimeline")
      }
      return st.resolveAll(rep, times, st.ResolveMediaTime)
   }
   numbers, err := st.segmentNumbers()
   if err != nil {
      return nil, err
   }
   return st.resolveAll(rep, numbers, st.ResolveMedia)
}

func (st *SegmentTemplate) GetStartNumber() uint {
   if st.StartNumber != nil {
      return *st.StartNumber
   }
   return 1
}

// GetTimelineNumbers returns the segment numbers described by the timeline.
func (st *SegmentTemplate) GetTimelineNumbers() []uint {
   numbers, _ := st.timeline()
   return numbers
}

// GetTimelineTimes returns the presentation times described by the timeline.
func (st *SegmentTemplate) GetTimelineTimes() []uint {
   _, times := st.timeline()
   return times
}

func (st *SegmentTemplate) GetTimescale() uint {
   if st.Timescale != nil {
      return *st.Timescale
   }
   return 1
}

func (st *SegmentTemplate) ResolveInitialization(rep *Representation) (*url.URL, error) {
   base, tmpl, err := st.prepare(rep, st.Initialization)
   if err != nil {
      return nil, err
   }
   return resolveRef(base, tmpl)
}

func (st *SegmentTemplate) ResolveMedia(rep *Representation, number int) (*url.URL, error) {
   base, tmpl, err := st.prepare(rep, st.Media)
   if err != nil {
      return nil, err
   }
   for width := 2; width <= 9; width++ {
      tmpl = strings.ReplaceAll(tmpl, fmt.Sprintf("$Number%%0%dd$", width), fmt.Sprintf("%0*d", width, number))
   }
   return resolveRef(base, strings.ReplaceAll(tmpl, "$Number$", strconv.Itoa(number)))
}

func (st *SegmentTemplate) ResolveMediaTime(rep *Representation, timestamp int) (*url.URL, error) {
   base, tmpl, err := st.prepare(rep, st.Media)
   if err != nil {
      return nil, err
   }
   return resolveRef(base, strings.ReplaceAll(tmpl, "$Time$", strconv.Itoa(timestamp)))
}

func (st *SegmentTemplate) parentBaseUrl() (*url.URL, error) {
   switch {
   case st.ParentRepresentation != nil:
      return st.ParentRepresentation.ResolveBaseUrl()
   case st.ParentAdaptationSet != nil:
      return st.ParentAdaptationSet.resolveBaseUrl()
   default:
      return nil, errors.New("dash: segment template has no parent")
   }
}

func (st *SegmentTemplate) period() *Period {
   if st.ParentRepresentation != nil && st.ParentRepresentation.Parent != nil {
      return st.ParentRepresentation.Parent.Parent
   }
   if st.ParentAdaptationSet != nil {
      return st.ParentAdaptationSet.Parent
   }
   return nil
}

// prepare resolves the base URL and expands $RepresentationID$.
func (st *SegmentTemplate) prepare(rep *Representation, tmpl string) (*url.URL, string, error) {
   base, err := st.parentBaseUrl()
   if err != nil {
      return nil, "", err
   }
   id := ""
   if rep != nil {
      id = rep.Id
   } else if st.ParentRepresentation != nil {
      id = st.ParentRepresentation.Id
   }
   if id != "" {
      tmpl = strings.ReplaceAll(tmpl, "$RepresentationID$", id)
   }
   return base, tmpl, nil
}

func (st *SegmentTemplate) resolveAll(rep *Representation, values []uint, resolve func(*Representation, int) (*url.URL, error)) ([]*url.URL, error) {
   var urls []*url.URL
   for _, v := range values {
      u, err := resolve(rep, int(v))
      if err != nil {
         return nil, err
      }
      urls = append(urls, u)
   }
   return urls, nil
}

func (st *SegmentTemplate) segmentNumbers() ([]uint, error) {
   if nums := st.GetTimelineNumbers(); len(nums) > 0 {
      return nums, nil
   }
   if st.EndNumber > 0 {
      if nums := st.GetNumberRange(); len(nums) > 0 {
         return nums, nil
      }
   }
   if st.Duration == 0 {
      return nil, nil
   }
   return st.GetDurationBasedNumbers()
}

func (st *SegmentTemplate) timeline() (numbers, times []uint) {
   if st.SegmentTimeline == nil {
      return nil, nil
   }
   number, time := st.GetStartNumber(), st.PresentationTimeOffset
   for _, s := range st.SegmentTimeline.S {
      for repeat := max(s.R, 0) + 1; repeat > 0; repeat-- {
         numbers = append(numbers, number)
         times = append(times, time)
         number++
         time += s.D
      }
   }
   return numbers, times
}

// SegmentTimeline lists segment durations explicitly.
type SegmentTimeline struct {
   S []*S `xml:"S"`
}

// segment_template.go KEEP THIS LINE
