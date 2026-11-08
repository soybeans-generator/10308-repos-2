package main

import (
   _ "embed"
   "fmt"
   "net/http"
   "net/url"
   "os"
   "strings"
)

//go:embed page.gql
var queryPage string

func main() {
   client := &http.Client{}
   reqURL := &url.URL{
      Scheme: "https",
      Host:   "friendship.nbc.com",
      Path:   "/v3/graphql",
   }

   body := fmt.Sprintf(`
   {
   "query": %q,
   "variables": {
      "userId": "-7936757034022170749",
      "device": "web",
      "platform": "web",
      "language": "en",
      "authorized": false,
      "isDayZero": true,
      "name": "saturday-night-live/video/november-7-druski/9000484434",
      "type": "VIDEO",
      "subType": "home",
      "timeZone": "America/Chicago",
      "app": "nbc",
      "appVersion": 1255002,
      "queryName": "page"
   }
}
   `, queryPage)

   req, err := http.NewRequest("POST", reqURL.String(), strings.NewReader(body))

   if err != nil {
      panic(err)
   }

   req.Header.Add("accept", "application/json")
   req.Header.Add("accept-encoding", "identity")
   req.Header.Add("accept-language", "en-US,en;q=0.5")
   req.Header.Add("content-length", "23594")
   req.Header.Add("content-type", "application/json")
   req.Header.Add("origin", "https://www.nbc.com")
   req.Header.Add("priority", "u=4")
   req.Header.Add("referer", "https://www.nbc.com/")
   req.Header.Add("sec-fetch-dest", "empty")
   req.Header.Add("sec-fetch-mode", "cors")
   req.Header.Add("sec-fetch-site", "same-site")
   req.Header.Add("te", "trailers")
   req.Header.Add("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:158.0) Gecko/20100101 Firefox/158.0")
   req.Header.Add("x-tve-platform", "web")

   resp, err := client.Do(req)
   if err != nil {
      panic(err)
   }
   if err := resp.Write(os.Stdout); err != nil {
      panic(err)
   }
}
