package draken

import (
   "bytes"
   _ "embed"
   "encoding/json"
   "errors"
   "io"
   "log"
   "net/http"
   "net/url"
   "strings"
)

//go:embed GetCustomIdFullMovie.gql
var get_custom_id_full_movie string

func FetchPlayableId(customId string) (string, error) {
   body, err := json.Marshal(map[string]any{
      "query": get_custom_id_full_movie,
      "variables": map[string]string{
         "customId": customId,
      },
   })
   if err != nil {
      return "", err
   }

   req, err := http.NewRequest(http.MethodPost,
      "https://client-api.magine.com/api/apiql/v2",
      bytes.NewReader(body),
   )
   if err != nil {
      return "", err
   }
   req.Header.Set("content-type", "application/json")
   // this value is important, with the wrong value you get random failures
   req.Header.Set("x-forwarded-for", "95.192.0.0")
   setBaseHeaders(req.Header, "") // No login token for this request

   resp, err := do(req)
   if err != nil {
      return "", err
   }
   defer resp.Body.Close()
   var result struct {
      Data struct {
         Viewer struct {
            ViewableCustomId *struct {
               DefaultPlayable struct {
                  Id string
               }
            }
         }
      }
   }
   err = json.NewDecoder(resp.Body).Decode(&result)
   if err != nil {
      return "", err
   }
   if result.Data.Viewer.ViewableCustomId == nil {
      return "", errors.New("ViewableCustomId")
   }
   return result.Data.Viewer.ViewableCustomId.DefaultPlayable.Id, nil
}

func do(req *http.Request) (*http.Response, error) {
   log.Println(req.Method, req.URL)
   return http.DefaultClient.Do(req)
}

// setBaseHeaders adds the common authentication and access tokens to a request.
func setBaseHeaders(header http.Header, loginToken string) {
   header.Set("magine-accesstoken", "22cc71a2-8b77-4819-95b0-8c90f4cf5663")
   if loginToken != "" {
      header.Set("authorization", "Bearer "+loginToken)
   }
}

// setPlaybackHeaders adds the headers specific to playback functionality.
func setPlaybackHeaders(header http.Header) {
   header.Set("magine-play-deviceid", "!")
   header.Set("magine-play-devicemodel", "firefox 111.0 / windows 10")
   header.Set("magine-play-deviceplatform", "firefox")
   header.Set("magine-play-devicetype", "web")
   header.Set("magine-play-drm", "widevine")
   header.Set("magine-play-protocol", "dashs")
}

type Entitlement struct {
   Error *Error
   Token string
}

func FetchEntitlement(loginToken, playableId string) (*Entitlement, error) {
   req, err := http.NewRequest(http.MethodPost,
      "https://client-api.magine.com/api/entitlement/v2/asset/"+playableId,
      nil,
   )
   if err != nil {
      return nil, err
   }
   setBaseHeaders(req.Header, loginToken)

   resp, err := do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()
   var result Entitlement
   err = json.NewDecoder(resp.Body).Decode(&result)
   if err != nil {
      return nil, err
   }
   if result.Error != nil {
      return nil, result.Error
   }
   return &result, nil
}

type Error struct {
   Message     string
   UserMessage string `json:"user_message"`
}

func (e *Error) Error() string {
   var data strings.Builder
   data.WriteString("message = ")
   data.WriteString(e.Message)
   data.WriteString("\nuser message = ")
   data.WriteString(e.UserMessage)
   return data.String()
}

type Login struct {
   Message string
   Token   string
}

func FetchLogin(identity, accessKey string) (*Login, error) {
   body, err := json.Marshal(map[string]string{
      "accessKey": accessKey,
      "identity":  identity,
   })
   if err != nil {
      return nil, err
   }

   req, err := http.NewRequest(http.MethodPost,
      "https://client-api.magine.com/api/login/v2/auth/email",
      bytes.NewReader(body),
   )
   if err != nil {
      return nil, err
   }
   req.Header.Set("content-type", "application/json")
   setBaseHeaders(req.Header, "") // No login token for this request

   resp, err := do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()
   var result Login
   err = json.NewDecoder(resp.Body).Decode(&result)
   if err != nil {
      return nil, err
   }
   if result.Message != "" {
      return nil, errors.New(result.Message)
   }
   return &result, nil
}

type Playback struct {
   Headers struct {
      MaginePlayEntitlementId string `json:"Magine-Play-EntitlementId"`
      MaginePlaySession       string `json:"Magine-Play-Session"`
   }
   Playlist string // MPD
}

func FetchPlayback(loginToken, playableId, entitlementId string) (*Playback, error) {
   req, err := http.NewRequest(http.MethodPost,
      "https://client-api.magine.com/api/playback/v1/preflight/asset/"+playableId,
      nil,
   )
   if err != nil {
      return nil, err
   }
   req.Header.Set("content-type", "application/json")
   req.Header.Set("magine-play-entitlementid", entitlementId)
   // this value is important, with the wrong value you get random failures
   req.Header.Set("x-forwarded-for", "95.192.0.0")
   setBaseHeaders(req.Header, loginToken)
   setPlaybackHeaders(req.Header)

   resp, err := do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()
   result := &Playback{}
   err = json.NewDecoder(resp.Body).Decode(result)
   if err != nil {
      return nil, err
   }
   return result, nil
}

func (p *Playback) FetchWidevine(loginToken string, body []byte) ([]byte, error) {
   req, err := http.NewRequest(http.MethodPost,
      "https://client-api.magine.com/api/playback/v1/widevine/license",
      bytes.NewReader(body),
   )
   if err != nil {
      return nil, err
   }
   req.Header.Set("magine-play-session", p.Headers.MaginePlaySession)
   req.Header.Set("magine-play-entitlementId", p.Headers.MaginePlayEntitlementId)
   setBaseHeaders(req.Header, loginToken)
   setPlaybackHeaders(req.Header)

   resp, err := do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()
   return io.ReadAll(resp.Body)
}
