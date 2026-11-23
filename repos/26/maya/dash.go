// dash.go KEEP THIS LINE
package maya

import (
   "cmp"
   "errors"
   "fmt"
   "net/url"
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
      job.single = &segment{url: baseUrl}
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
// DASH representation. Each form names it differently but fetches it the
// same way: one URL and an optional byte range.
func getDashInitSegment(rep *dash.Representation, info *typeInfo) ([]byte, error) {
   if !info.IsFmp4 {
      return nil, nil
   }

   var target *url.URL
   var rangeSpec string
   template := rep.GetSegmentTemplate()
   list := rep.SegmentList

   switch {
   case rep.SegmentBase != nil && rep.SegmentBase.Initialization != nil:
      var err error
      if target, err = rep.ResolveBaseUrl(); err != nil {
         return nil, err
      }
      rangeSpec = rep.SegmentBase.Initialization.Range
   case template != nil && template.Initialization != "":
      var err error
      if target, err = template.ResolveInitialization(rep); err != nil {
         return nil, fmt.Errorf("resolve DASH SegmentTemplate initialization URL: %w", err)
      }
   case list != nil && list.Initialization != nil:
      var err error
      if target, err = list.Initialization.ResolveSourceUrl(); err != nil {
         return nil, fmt.Errorf("resolve DASH SegmentList initialization URL: %w", err)
      }
      rangeSpec = list.Initialization.Range
   default:
      return nil, nil
   }

   data, _, err := fetchData(target, rangeHeader(rangeSpec), true)
   return data, err
}

// listStreamsDash prints one representative per representation group,
// ordered by mime type then bandwidth.
func listStreamsDash(mpd *dash.Mpd) error {
   var reps []*dash.Representation
   for _, group := range mpd.GetRepresentations() {
      reps = append(reps, group[len(group)/2])
   }
   slices.SortFunc(reps, func(a, b *dash.Representation) int {
      return cmp.Or(
         cmp.Compare(a.GetMimeType(), b.GetMimeType()),
         cmp.Compare(a.Bandwidth, b.Bandwidth),
      )
   })
   printStreams(reps)
   return nil
}

// rangeHeader asks a server for one byte range, or returns nil for the whole
// resource. An absent range must not become a "bytes=" header.
func rangeHeader(spec string) map[string]string {
   if spec == "" {
      return nil
   }
   return map[string]string{"Range": "bytes=" + spec}
}

// detectDashType derives the file extension and container type from a
// representation's metadata.
func detectDashType(rep *dash.Representation) (*typeInfo, error) {
   mimeType := rep.GetMimeType()
   switch {
   case mimeType == "video/mp4":
      return &typeInfo{Extension: ".mp4", IsFmp4: true}, nil
   case mimeType == "audio/mp4":
      return &typeInfo{Extension: ".m4a", IsFmp4: true}, nil
   case mimeType == "text/vtt":
      return &typeInfo{Extension: ".vtt"}, nil
   default:
      return nil, fmt.Errorf("unsupported mime type for stream %s: %s", rep.Id, mimeType)
   }
}

// generateSegments builds the segment list of one representation.
func generateSegments(rep *dash.Representation) ([]segment, error) {
   if template := rep.GetSegmentTemplate(); template != nil {
      urls, err := template.GetSegmentUrls(rep)
      if err != nil {
         return nil, err
      }
      segments := make([]segment, len(urls))
      for i, mediaUrl := range urls {
         segments[i] = segment{url: mediaUrl}
      }
      return segments, nil
   }

   if list := rep.SegmentList; list != nil {
      segments := make([]segment, 0, len(list.SegmentUrls))
      for _, entry := range list.SegmentUrls {
         mediaUrl, err := entry.ResolveMedia()
         if err != nil {
            return nil, err
         }
         segments = append(segments, segment{
            url:     mediaUrl,
            headers: rangeHeader(entry.MediaRange),
         })
      }
      return segments, nil
   }

   baseUrl, err := rep.ResolveBaseUrl()
   if err != nil {
      return nil, err
   }
   return []segment{{url: baseUrl}}, nil
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
