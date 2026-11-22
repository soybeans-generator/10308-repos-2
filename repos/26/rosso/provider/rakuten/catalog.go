// catalog.go KEEP THIS LINE
package rakuten

import (
   "encoding/json"
   "errors"
   "net/http"
   "net/url"
   "strconv"
   "strings"
)

type Address struct {
   MarketCode  string
   ContentType string
   ContentId   string
}

func ParseAddress(targetUrl string) (*Address, error) {
   target, err := url.Parse(targetUrl)
   if err != nil {
      return nil, err
   }

   if !strings.HasSuffix(target.Host, "rakuten.tv") {
      return nil, errors.New("invalid host")
   }

   segments := strings.Split(strings.Trim(target.Path, "/"), "/")
   if len(segments) == 0 || segments[0] == "" {
      return nil, errors.New("missing market code in path")
   }

   parsed := &Address{
      MarketCode: segments[0],
   }

   if len(segments) == 3 {
      parsed.ContentType = segments[1]
      parsed.ContentId = segments[2]
   } else if len(segments) >= 5 && segments[1] == "player" {
      parsed.ContentType = segments[2]
      parsed.ContentId = segments[4]
   }

   query := target.Query()
   if parsed.ContentType == "" {
      parsed.ContentType = query.Get("content_type")
   }

   if parsed.ContentId == "" {
      if id := query.Get("content_id"); id != "" {
         parsed.ContentId = id
      } else if id := query.Get("tv_show_id"); id != "" {
         parsed.ContentId = id
         if parsed.ContentType == "" {
            parsed.ContentType = "tv_shows"
         }
      } else if id := query.Get("movie_id"); id != "" {
         parsed.ContentId = id
         if parsed.ContentType == "" {
            parsed.ContentType = "movies"
         }
      }
   }

   if parsed.MarketCode == "" || parsed.ContentType == "" || parsed.ContentId == "" {
      return nil, errors.New("could not extract all required components from url")
   }

   return parsed, nil
}

func (*Address) CachePath() string {
   return "rosso/rakuten/Address"
}

func (a *Address) IsMovie() bool {
   return a.ContentType == "movies"
}

func (a *Address) IsTvShow() bool {
   return a.ContentType == "tv_shows"
}

type Episode struct {
   Id          string      `json:"id"`
   Title       string      `json:"title"`
   ViewOptions ViewOptions `json:"view_options"`
}

func (e *Episode) String() string {
   return formatPlayableDetails(e.Id, e.Title, e.ViewOptions.Private.Streams)
}

type Movie struct {
   Id          string      `json:"id"`
   Title       string      `json:"title"`
   ViewOptions ViewOptions `json:"view_options"`
}

func FetchMovie(movieId string, userClassification Classification, targetMarket Market) (*Movie, error) {
   target := &url.URL{
      Scheme: "https",
      Host:   "gizmo.rakuten.tv",
      Path:   "/v3/movies/" + movieId,
   }

   query := url.Values{}
   query.Set("classification_id", strconv.Itoa(userClassification.NumericalId))
   query.Set("device_identifier", "atvui40")
   query.Set("market_code", targetMarket.Code)
   target.RawQuery = query.Encode()

   req, err := http.NewRequest("GET", target.String(), nil)
   if err != nil {
      return nil, err
   }

   resp, err := do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()

   var apiResp struct {
      Data Movie `json:"data"`
   }

   if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
      return nil, err
   }

   return &apiResp.Data, nil
}

func (targetMovie *Movie) String() string {
   return formatPlayableDetails(targetMovie.Id, targetMovie.Title, targetMovie.ViewOptions.Private.Streams)
}

type Season struct {
   Id       string    `json:"id"`
   Title    string    `json:"title"`
   Episodes []Episode `json:"episodes"`
}

func FetchSeason(id string, userClassification Classification, targetMarket Market) (*Season, error) {
   target := &url.URL{
      Scheme: "https",
      Host:   "gizmo.rakuten.tv",
      Path:   "/v3/seasons/" + id,
   }

   query := url.Values{}
   query.Set("classification_id", strconv.Itoa(userClassification.NumericalId))
   query.Set("device_identifier", "atvui40")
   query.Set("market_code", targetMarket.Code)
   target.RawQuery = query.Encode()

   req, err := http.NewRequest("GET", target.String(), nil)
   if err != nil {
      return nil, err
   }

   resp, err := do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()

   var apiResp struct {
      Data Season `json:"data"`
   }

   if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
      return nil, err
   }

   return &apiResp.Data, nil
}

type TvShow struct {
   Id      string   `json:"id"`
   Title   string   `json:"title"`
   Seasons []Season `json:"seasons"`
}

func FetchTvShow(tvShowId string, userClassification Classification, targetMarket Market) (*TvShow, error) {
   target := &url.URL{
      Scheme: "https",
      Host:   "gizmo.rakuten.tv",
      Path:   "/v3/tv_shows/" + tvShowId,
   }

   query := url.Values{}
   query.Set("classification_id", strconv.Itoa(userClassification.NumericalId))
   query.Set("device_identifier", "atvui40")
   query.Set("market_code", targetMarket.Code)
   target.RawQuery = query.Encode()

   req, err := http.NewRequest("GET", target.String(), nil)
   if err != nil {
      return nil, err
   }

   resp, err := do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()

   var apiResp struct {
      Data TvShow `json:"data"`
   }

   if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
      return nil, err
   }

   return &apiResp.Data, nil
}

func (show *TvShow) String() string {
   var data strings.Builder
   for i, currentSeason := range show.Seasons {
      if i >= 1 {
         data.WriteByte('\n')
      }
      data.WriteString("season id: ")
      data.WriteString(currentSeason.Id)
   }
   return data.String()
}

// catalog.go KEEP THIS LINE
