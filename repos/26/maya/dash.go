// dash.go KEEP THIS LINE
package maya

import (
   "cmp"
   "errors"
   "fmt"
   "slices"

   "41.neocities.org/luna/dash"
)

// downloadDash downloads streamId from a parsed MPD.
func downloadDash(mpd *dash.Mpd, streamId string, fetchKey keyFetcher) error {
   group, ok := mpd.GetRepresentations()[streamId]
   if !ok {
      return fmt.Errorf("representation group not found: %v", streamId)
   }
   if len(group) == 0 {
      return errors.New("representation group is empty")
   }

   rep := group[0]
   info, err := detectDashType(rep)
   if err != nil {
      return err
   }
   protection, err := getDashProtection(rep)
   if err != nil {
      return err
   }
   job := &downloadJob{
      outputFileNameBase: rep.Id,
      info:               info,
      manifestProtection: protection,
      fetchKey:           fetchKey,
   }

   // SegmentBase is one URL whose moov is read straight from the stream;
   // the init segment is only needed when resuming past it.
   if rep.SegmentBase != nil {
      baseUrl, err := rep.ResolveBaseUrl()
      if err != nil {
         return err
      }
      job.single = &segment{url: baseUrl.String()}
      job.fetchInit = func() ([]byte, error) {
         return getDashInitSegment(rep, info)
      }
      return orchestrateDownload(job)
   }

   job.initSegmentData, err = getDashInitSegment(rep, info)
   if err != nil {
      return err
   }
   job.allRequests, err = getDashMediaRequests(group)
   if err != nil {
      return err
   }
   return orchestrateDownload(job)
}

// getDashInitSegment locates and fetches the initialization segment of a
// DASH representation.
func getDashInitSegment(rep *dash.Representation, info *typeInfo) ([]byte, error) {
   if !info.IsFmp4 {
      return nil, nil
   }

   if rep.SegmentBase != nil && rep.SegmentBase.Initialization != nil {
      baseUrl, err := rep.ResolveBaseUrl()
      if err != nil {
         return nil, err
      }
      headers := map[string]string{"Range": "bytes=" + rep.SegmentBase.Initialization.Range}
      data, _, err := fetchData(baseUrl.String(), headers, true)
      return data, err
   }

   if template := rep.GetSegmentTemplate(); template != nil && template.Initialization != "" {
      initUrl, err := template.ResolveInitialization(rep)
      if err != nil {
         return nil, fmt.Errorf("resolve DASH SegmentTemplate initialization URL: %w", err)
      }
      data, _, err := fetchData(initUrl.String(), nil, true)
      return data, err
   }

   if list := rep.SegmentList; list != nil && list.Initialization != nil {
      initUrl, err := list.Initialization.ResolveSourceUrl()
      if err != nil {
         return nil, fmt.Errorf("resolve DASH SegmentList initialization URL: %w", err)
      }
      var headers map[string]string
      if list.Initialization.Range != "" {
         headers = map[string]string{"Range": "bytes=" + list.Initialization.Range}
      }
      data, _, err := fetchData(initUrl.String(), headers, true)
      return data, err
   }

   return nil, nil
}

// listStreamsDash prints one representative per representation group,
// ordered by height then bandwidth.
func listStreamsDash(mpd *dash.Mpd) error {
   var reps []*dash.Representation
   for _, group := range mpd.GetRepresentations() {
      reps = append(reps, group[len(group)/2])
   }
   slices.SortFunc(reps, func(a, b *dash.Representation) int {
      return cmp.Or(
         cmp.Compare(a.GetHeight(), b.GetHeight()),
         cmp.Compare(a.Bandwidth, b.Bandwidth),
      )
   })
   printStreams(reps)
   return nil
}

// detectDashType derives the file extension and container type from a
// representation's metadata.
func detectDashType(rep *dash.Representation) (*typeInfo, error) {
   switch rep.GetMimeType() {
   case "video/mp4":
      return &typeInfo{Extension: ".mp4", IsFmp4: true}, nil
   case "audio/mp4":
      return &typeInfo{Extension: ".m4a", IsFmp4: true}, nil
   case "text/vtt":
      return &typeInfo{Extension: ".vtt", IsFmp4: false}, nil
   default:
      return nil, fmt.Errorf("unsupported mime type for stream %s: %s", rep.Id, rep.GetMimeType())
   }
}

// generateSegments builds the segment list of one representation.
func generateSegments(rep *dash.Representation) ([]segment, error) {
   baseUrl, err := rep.ResolveBaseUrl()
   if err != nil {
      return nil, err
   }

   if template := rep.GetSegmentTemplate(); template != nil {
      urls, err := template.GetSegmentUrls(rep)
      if err != nil {
         return nil, err
      }
      segments := make([]segment, len(urls))
      timescale := float64(template.GetTimescale())

      if timeline := template.SegmentTimeline; timeline != nil {
         index := 0
         for _, entry := range timeline.S {
            repeat := max(1, entry.R+1)
            duration := float64(entry.D) / timescale
            for n := 0; n < repeat && index < len(segments); n++ {
               segments[index] = segment{url: urls[index].String(), duration: duration}
               index++
            }
         }
         return segments, nil
      }

      duration := float64(template.Duration) / timescale
      for i := range segments {
         segments[i] = segment{url: urls[i].String(), duration: duration}
      }
      return segments, nil
   }

   if list := rep.SegmentList; list != nil {
      segments := make([]segment, 0, len(list.SegmentUrls))
      duration := float64(list.Duration) / float64(list.GetTimescale())
      for _, entry := range list.SegmentUrls {
         mediaUrl, err := entry.ResolveMedia()
         if err != nil {
            return nil, err
         }
         var headers map[string]string
         if entry.MediaRange != "" {
            headers = map[string]string{"Range": "bytes=" + entry.MediaRange}
         }
         segments = append(segments, segment{
            url:      mediaUrl.String(),
            headers:  headers,
            duration: duration,
         })
      }
      return segments, nil
   }

   var duration float64
   if rep.Parent != nil && rep.Parent.Parent != nil {
      if periodDuration, err := rep.Parent.Parent.GetDuration(); err == nil {
         duration = periodDuration.Seconds()
      }
   }
   return []segment{{url: baseUrl.String(), duration: duration}}, nil
}

// getDashMediaRequests lists the media segments of a representation group.
func getDashMediaRequests(group []*dash.Representation) ([]segment, error) {
   var requests []segment
   for _, rep := range group {
      segments, err := generateSegments(rep)
      if err != nil {
         return nil, err
      }
      requests = append(requests, segments...)
   }
   return requests, nil
}

// dash.go KEEP THIS LINE
