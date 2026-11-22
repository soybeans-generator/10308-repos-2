// main.go KEEP THIS LINE
package main

import (
   "bytes"
   "cmp"
   _ "embed"
   "encoding/base64"
   "encoding/json"
   "errors"
   "flag"
   "fmt"
   "io"
   "log"
   "maps"
   "net/http"
   "net/url"
   "os"
   "path"
   "slices"
   "strings"
   "time"
)

const apiBase = "https://apis.justwatch.com"

//go:embed BackendConstantsFetcherQuery.gql
var backendConstantsFetcherQuery string

// deviceID is 16 zero bytes, raw-std base64 encoded. The API wants one.
var deviceID = base64.RawStdEncoding.EncodeToString(make([]byte, 16))

// queryParamsToStrip are tracking parameters that never change which title a
// URL points at.
var queryParamsToStrip = []struct {
   key   string
   value string
}{
   {"searchReferral", ""},
   {"referrer", "JustWatch"},
   {"subId3", "justappsvod"},
   {"autoplay", "1"},
   {"searchReferral", "publisher"},
   {"source", "bing"},
   {"source", "search-feeds"},
   {"utm_campaign", "vod_feed"},
   {"utm_content", ""},
   {"utm_medium", "deeplink"},
   {"utm_medium", "partner"},
   {"utm_source", "justWatch-v2-catalog"},
   {"utm_source", "justwatch"},
   {"utm_source", "universal_search"},
   {"utm_term", ""},
}

// GetPath returns the path of rawURL, e.g. /us/movie/goodfellas.
func GetPath(rawURL string) (string, error) {
   u, err := url.Parse(rawURL)
   if err != nil {
      return "", err
   }
   if u.Scheme == "" {
      return "", errors.New("invalid URL: scheme is missing")
   }
   return u.Path, nil
}

// GroupAndSortByUrl groups offers by stripped URL, sorts each group by country
// and returns the keys ordered by length.
func GroupAndSortByUrl(offers []*EnrichedOffer) ([]string, map[string][]*EnrichedOffer) {
   groups := make(map[string][]*EnrichedOffer, len(offers))
   for _, offer := range offers {
      key := getUrlGroupingKey(offer.Offer.StandardWebUrl)
      groups[key] = append(groups[key], offer)
   }
   for _, group := range groups {
      slices.SortFunc(group, func(a, b *EnrichedOffer) int {
         return cmp.Compare(a.Locale.Country, b.Locale.Country)
      })
   }
   // This works for Go 1.21 and older.
   keys := slices.SortedFunc(maps.Keys(groups), func(a, b string) int {
      return cmp.Compare(len(a), len(b))
   })
   return keys, groups
}

// get fetches apiBase+path with query.
func get(path string, query url.Values) ([]byte, error) {
   u, err := url.Parse(apiBase + path)
   if err != nil {
      return nil, err
   }
   u.RawQuery = query.Encode()
   return send(http.MethodGet, u.String(), nil)
}

func getUrlGroupingKey(rawURL string) string {
   trimmed := strings.TrimSuffix(rawURL, "\n")
   u, err := url.Parse(trimmed)
   if err != nil {
      return trimmed
   }
   query := u.Query()
   for _, rule := range queryParamsToStrip {
      // Get returns the first value, or "" when absent, which covers the
      // "assume a single value" rule either way.
      if query.Get(rule.key) == rule.value {
         delete(query, rule.key)
      }
   }
   u.RawQuery = query.Encode()
   return u.String()
}

// graphql posts a query and returns the data field of the reply.
func graphql(query string, variables map[string]string) (json.RawMessage, error) {
   payload, err := json.Marshal(map[string]any{
      "query":     query,
      "variables": variables,
   })
   if err != nil {
      return nil, err
   }
   body, err := send(http.MethodPost, apiBase+"/graphql", payload)
   if err != nil {
      return nil, err
   }
   var envelope struct {
      Data json.RawMessage
   }
   if err := json.Unmarshal(body, &envelope); err != nil {
      return nil, err
   }
   return envelope.Data, nil
}

func main() {
   log.SetFlags(log.Ltime)
   if err := new(client).do(); err != nil {
      log.Fatal(err)
   }
}

// send runs one request and returns the body of a 200 reply.
func send(method, target string, payload []byte) ([]byte, error) {
   req, err := http.NewRequest(method, target, bytes.NewReader(payload))
   if err != nil {
      return nil, err
   }
   req.Header.Set("accept", "application/json")
   req.Header.Set("device-id", deviceID)
   if payload != nil {
      req.Header.Set("content-type", "application/json")
   }
   resp, err := http.DefaultClient.Do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()
   body, err := io.ReadAll(resp.Body)
   if err != nil {
      return nil, err
   }
   if resp.StatusCode != http.StatusOK {
      return nil, fmt.Errorf("%s %s: %s: %s", method, req.URL.Path, resp.Status, body)
   }
   return body, nil
}

func FetchLocales(language string) (Locales, error) {
   data, err := graphql(backendConstantsFetcherQuery, map[string]string{
      "language": language,
   })
   if err != nil {
      return nil, err
   }
   var reply struct {
      Locales Locales
   }
   if err := json.Unmarshal(data, &reply); err != nil {
      return nil, err
   }
   return reply.Locales, nil
}

// Deduplicate removes true duplicates where both the Offer and Locale are identical.
func Deduplicate(offers []*EnrichedOffer) []*EnrichedOffer {
   // Sorting brings identical entries next to each other; this compares the
   // underlying values, which is what we want.
   slices.SortFunc(offers, func(a, b *EnrichedOffer) int {
      return cmp.Or(
         cmp.Compare(a.Offer.StandardWebUrl, b.Offer.StandardWebUrl),
         cmp.Compare(a.Offer.MonetizationType, b.Offer.MonetizationType),
         a.Offer.ElementCount-b.Offer.ElementCount,
         cmp.Compare(a.Locale.FullLocale, b.Locale.FullLocale),
      )
   })
   return slices.CompactFunc(offers, func(a, b *EnrichedOffer) bool {
      return a.Offer.StandardWebUrl == b.Offer.StandardWebUrl &&
         a.Offer.MonetizationType == b.Offer.MonetizationType &&
         a.Offer.ElementCount == b.Offer.ElementCount &&
         a.Locale.FullLocale == b.Locale.FullLocale
   })
}

// FilterOffers removes offers with unwanted monetization types.
// If no unwantedTypes are provided, all offers are returned unfiltered.
func FilterOffers(offers []*EnrichedOffer, unwantedTypes ...string) []*EnrichedOffer {
   unwanted := make(map[string]struct{}, len(unwantedTypes))
   for _, monetization := range unwantedTypes {
      if monetization != "" {
         unwanted[monetization] = struct{}{}
      }
   }
   var kept []*EnrichedOffer
   for _, offer := range offers {
      if _, drop := unwanted[offer.Offer.MonetizationType]; !drop {
         kept = append(kept, offer)
      }
   }
   return kept
}

type client struct {
   address string
   filters string
   sleep   time.Duration
}

func (c *client) do() error {
   flag.StringVar(&c.address, "a", "", "address")
   flag.DurationVar(&c.sleep, "s", 99*time.Millisecond, "sleep")
   flag.StringVar(&c.filters, "f", "BUY,CINEMA,FAST,RENT", "filters (use -f= for none)")
   flag.Parse()

   if c.address != "" {
      return c.do_address()
   }
   flag.Usage()
   return nil
}

func (c *client) do_address() error {
   urlPath, err := GetPath(c.address)
   if err != nil {
      return err
   }
   var content Content
   if err := content.Fetch(urlPath); err != nil {
      return err
   }
   var all []*EnrichedOffer
   for _, tag := range content.HrefLangTags {
      locale, ok := EnUs.Locale(&tag)
      if !ok {
         return errors.New("Locale")
      }
      log.Print(locale)
      offers, err := tag.Offers(locale)
      if err != nil {
         return err
      }
      for _, offer := range offers {
         all = append(all, &EnrichedOffer{Locale: locale, Offer: &offer})
      }
      time.Sleep(c.sleep)
   }
   offers := Deduplicate(all)
   // An empty filter string means no filtering: keep every offer.
   var filters []string
   if c.filters != "" {
      filters = strings.Split(c.filters, ",")
   }
   offers = FilterOffers(offers, filters...)
   keys, groups := GroupAndSortByUrl(offers)
   data := &bytes.Buffer{}
   for i, key := range keys {
      if i >= 1 {
         data.WriteString("\n\n")
      }
      data.WriteString("## ")
      data.WriteString(key)
      for _, enriched := range groups[key] {
         data.WriteByte('\n')
         data.WriteString("\ncountry: ")
         data.WriteString(enriched.Locale.Country)
         data.WriteString("\nname: ")
         data.WriteString(enriched.Locale.CountryName)
         data.WriteString("\nmonetization: ")
         data.WriteString(enriched.Offer.MonetizationType)
         if enriched.Offer.ElementCount >= 1 {
            data.WriteString("\ncount: ")
            fmt.Fprint(data, enriched.Offer.ElementCount)
         }
      }
   }
   name := path.Base(urlPath) + ".md"
   log.Println("WriteFile", name)
   return os.WriteFile(name, data.Bytes(), os.ModePerm)
}

// main.go KEEP THIS LINE
