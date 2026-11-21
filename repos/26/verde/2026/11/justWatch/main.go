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

// api is the only thing here that speaks HTTP.
var api = &apiClient{http: &http.Client{Timeout: 30 * time.Second}}

//go:embed BackendConstantsFetcherQuery.gql
var backendConstantsFetcherQuery string

// deviceID is 16 zero bytes, raw-std base64 encoded. The API wants one.
var deviceID = base64.RawStdEncoding.EncodeToString(make([]byte, 16))

// queryParamsToStrip are tracking parameters that never change which title a
// URL points at.
var queryParamsToStrip = []struct {
   date  string
   key   string
   value string
}{
   {"2026-03-08", "searchReferral", ""},
   {"2026-03-07", "referrer", "JustWatch"},
   {"2026-03-04", "subId3", "justappsvod"},
   {"2026-02-26", "autoplay", "1"},
   {"2026-02-26", "searchReferral", "publisher"},
   {"2026-02-26", "source", "bing"},
   {"2026-02-26", "source", "search-feeds"},
   {"2026-02-26", "utm_campaign", "vod_feed"},
   {"2026-02-26", "utm_content", ""},
   {"2026-02-26", "utm_medium", "deeplink"},
   {"2026-02-26", "utm_medium", "partner"},
   {"2026-02-26", "utm_source", "justWatch-v2-catalog"},
   {"2026-02-26", "utm_source", "justwatch"},
   {"2026-02-26", "utm_source", "universal_search"},
   {"2026-02-26", "utm_term", ""},
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

func getUrlGroupingKey(rawURL string) string {
   trimmed := strings.TrimSuffix(rawURL, "\n")
   u, err := url.Parse(trimmed)
   if err != nil {
      return trimmed
   }
   if u.RawQuery == "" {
      return u.String()
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

func main() {
   log.SetFlags(log.Ltime)
   if err := new(client).do(); err != nil {
      log.Fatal(err)
   }
}

func FetchLocales(language string) (Locales, error) {
   data, err := api.graphql(backendConstantsFetcherQuery, map[string]string{
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

type apiClient struct {
   http *http.Client
}

// do runs req, closes the body and returns it when the status is 200.
func (c *apiClient) do(req *http.Request) ([]byte, error) {
   req.Header.Set("accept", "application/json")
   req.Header.Set("device-id", deviceID)
   resp, err := c.http.Do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()
   body, err := io.ReadAll(resp.Body)
   if err != nil {
      return nil, err
   }
   if resp.StatusCode != http.StatusOK {
      return nil, fmt.Errorf("%s %s: %s: %s", req.Method, req.URL.Path,
         resp.Status, strings.TrimSpace(string(body)))
   }
   return body, nil
}

// get fetches apiBase+path and returns the raw body.
func (c *apiClient) get(path string) ([]byte, error) {
   req, err := http.NewRequest("GET", apiBase+path, nil)
   if err != nil {
      return nil, err
   }
   return c.do(req)
}

// graphql runs a query and returns the data field of the reply.
func (c *apiClient) graphql(query string, variables map[string]string) (json.RawMessage, error) {
   payload, err := json.Marshal(graphQLRequest{Query: query, Variables: variables})
   if err != nil {
      return nil, err
   }
   req, err := http.NewRequest("POST", apiBase+"/graphql", bytes.NewReader(payload))
   if err != nil {
      return nil, err
   }
   req.Header.Set("content-type", "application/json")
   body, err := c.do(req)
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

type graphQLRequest struct {
   Query     string            `json:"query"`
   Variables map[string]string `json:"variables"`
}

// main.go KEEP THIS LINE
