package paramount

import "testing"

var videos = []struct {
   justWatch string
   paramount string
   cookie    bool
   height    int
}{
   {
      //1080 pass
      //1440 fail
      cookie:    true,
      height:    2160,
      justWatch: "https://justwatch.com/us/movie/zodiac",
      paramount: "https://paramountplus.com/movies/video/wjQ4RChi6BHHu4MVTncppVuCwu44uq2Q",
   },
   {
      cookie:    false,
      height:    2160,
      justWatch: "https://justwatch.com/us/tv-show/dexter-original-sin",
      paramount: "https://paramountplus.com/shows/video/6z6Nn5LjJqCraw_6dSSL1dY_j__kv0EH",
   },
   {
      cookie:    false,
      height:    1080,
      justWatch: "https://justwatch.com/us/tv-show/60-minutes",
      paramount: "https://cbs.com/shows/video/ALVE01M37SHC34E1FBDZBEMTB4R6JQ",
      
   },
   {
      cookie:    true,
      height:    1080,
      justWatch: "https://justwatch.com/us/tv-show/the-price-is-right",
      paramount: "https://paramountplus.com/shows/video/ALVE01M46GTPGKEY1TQKSW4347HN48",
      
   },
}

func TestVideos(t *testing.T) {
   t.Log(videos)
}
