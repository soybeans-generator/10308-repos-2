package criterion

import "testing"

var videos = []struct {
   segment string
   url     string
}{
   {
      segment: "SegmentList",
      url:     "https://criterionchannel.com/films/cnStYoEF/wildcat",
   },
   {
      segment: "SegmentTemplate",
      url:     "https://criterionchannel.com/films/0mKhMtOJ/my-dinner-with-andre",
   },
   {
      url: "https://criterionchannel.com/films/INRFb1nI/121280-ritual",
   },
}

func TestVideo(t *testing.T) {
   t.Log(videos)
}
