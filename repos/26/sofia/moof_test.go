package sofia

import (
   "fmt"
   "os"
   "testing"
)

func Test_Moof(t *testing.T) {
   f, err := os.Open("index_video_5_0_1.mp4")
   if err != nil {
      t.Fatal(err)
   }
   defer f.Close()
   var moof MovieFragment
   if err := moof.Decode(f); err != nil {
      t.Fatal(err)
   }
   for _, b := range moof {
      fmt.Println(b.Type())
   }
}
