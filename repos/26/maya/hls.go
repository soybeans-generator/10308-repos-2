// hls.go KEEP THIS LINE
package maya

import (
   "errors"
   "fmt"
   "net/url"
   "path"
   "strconv"

   "41.neocities.org/luna/hls"
)

// downloadHls downloads streamId from an HLS master playlist.
func downloadHls(playlist *hls.MasterPlaylist, streamId int, fetchKey keyFetcher) error {
   mediaUrl, err := hlsStreamUrl(playlist, streamId)
   if err != nil {
      return err
   }
   media, err := fetchMediaPlaylist(mediaUrl)
   if err != nil {
      return err
   }
   info, err := detectHlsType(media)
   if err != nil {
      return err
   }

   segments := make([]segment, len(media.Segments))
   for i, entry := range media.Segments {
      segments[i] = segment{url: entry.Uri, duration: entry.Duration}
   }

   var initData []byte
   if info.IsFmp4 && media.Map != nil {
      initData, _, err = fetchData(media.Map, nil, true)
      if err != nil {
         return fmt.Errorf("fetch HLS initialization segment: %w", err)
      }
   }

   return orchestrateDownload(&downloadJob{
      outputFileNameBase: strconv.Itoa(streamId),
      info:               info,
      allRequests:        segments,
      initSegmentData:    initData,
      fetchKey:           fetchKey,
   })
}

// fetchMediaPlaylist fetches and parses an HLS media playlist.
func fetchMediaPlaylist(mediaUrl *url.URL) (*hls.MediaPlaylist, error) {
   data, effective, err := fetchData(mediaUrl, nil, true)
   if err != nil {
      return nil, err
   }
   media, err := hls.DecodeMedia(string(data))
   if err != nil {
      return nil, err
   }
   media.ResolveUris(effective)
   return media, nil
}

// hlsStreamUrl returns the URI of the variant or rendition with streamId.
func hlsStreamUrl(playlist *hls.MasterPlaylist, streamId int) (*url.URL, error) {
   for _, variant := range playlist.StreamInfs {
      if variant.Id == streamId {
         return variant.Uri, nil
      }
   }
   for _, rendition := range playlist.Medias {
      if rendition.Id == streamId {
         return rendition.Uri, nil
      }
   }
   return nil, fmt.Errorf("stream with ID not found: %d", streamId)
}

// listStreamsHls prints the renditions, then the variants, in manifest order.
func listStreamsHls(playlist *hls.MasterPlaylist) error {
   streams := make([]any, 0, len(playlist.Medias)+len(playlist.StreamInfs))
   for _, rendition := range playlist.Medias {
      streams = append(streams, rendition)
   }
   for _, variant := range playlist.StreamInfs {
      streams = append(streams, variant)
   }
   printStreams(streams)
   return nil
}

// detectHlsType derives the extension and container type from the first
// segment URL.
func detectHlsType(media *hls.MediaPlaylist) (*typeInfo, error) {
   if len(media.Segments) == 0 {
      return nil, errors.New("empty media playlist")
   }
   firstUrl := media.Segments[0].Uri
   extension := path.Ext(firstUrl.Path)
   if extension == "" {
      return nil, fmt.Errorf("no file extension found in segment URL: %s", firstUrl)
   }
   if extension == ".mp4a" {
      extension = ".m4a"
   }
   isFmp4 := media.Map != nil || extension == ".mp4" || extension == ".m4s" || extension == ".m4a"
   return &typeInfo{Extension: extension, IsFmp4: isFmp4}, nil
}

// hls.go KEEP THIS LINE
