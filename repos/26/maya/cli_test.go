// cli_test.go marker preserve
package maya

import (
   "os"
   "testing"
)

func TestUsage(t *testing.T) {
   app := FlagString("com.cbs.app")
   folder := FlagString(`D:\DRM\SL3000 EXPRESS LUCK TECHNOLOGY LIMITED LE`)
   var username FlagString
   var password FlagString
   contentID := FlagString("wjQ4RChi6BHHu4MVTncppVuCwu44uq2Q")
   useCookie := FlagBool(false)
   var dashID FlagString

   set := FlagSet{
      {Name: "app", Usage: "com.cbs.app com.cbs.tve com.cbs.ca", Value: &app},
      {Name: "playReady-folder", Value: &folder},
      {Name: "username", Value: &username, Needs: []string{"password"}},
      {Name: "password", Value: &password, Needs: []string{"username"}},
      {Name: "content-id", Value: &contentID},
      {Name: "use-cookie", Value: &useCookie, Needs: []string{"content-id", "dash-id"}},
      {Name: "dash-id", Value: &dashID},
   }

   if err := set.Usage(os.Stdout, "paramount"); err != nil {
      t.Fatal(err)
   }
}

// cli_test.go marker preserve
