package crave

import (
   "bytes"
   "encoding/json"
   "net/http"
   "net/url"
   "strings"
)

type AccountToken struct {
   AccessToken  string `json:"access_token"`
   RefreshToken string `json:"refresh_token"`
   AccountId    string `json:"account_id"`
   Jti          string `json:"jti"`
}

func PerformLogin(username string, password string) (*AccountToken, error) {
   values := url.Values{}
   values.Set("grant_type", "password")
   values.Set("password", password)
   values.Set("username", username)

   body := []byte(values.Encode())

   req, err := http.NewRequest(http.MethodPost, "https://account.bellmedia.ca/api/login/v2.1", bytes.NewReader(body))
   if err != nil {
      return nil, err
   }

   // crave-web:default
   req.Header.Set("authorization", "Basic Y3JhdmUtd2ViOmRlZmF1bHQ=")
   req.Header.Set("content-type", "application/x-www-form-urlencoded")

   resp, err := doRequest(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()

   account := &AccountToken{}
   if err := json.NewDecoder(resp.Body).Decode(account); err != nil {
      return nil, err
   }

   return account, nil
}

func (*AccountToken) CachePath() string {
   return "rosso/crave/AccountToken"
}

type Profile struct {
   Id                string   `json:"id"`
   AccountId         string   `json:"accountId"`
   Nickname          string   `json:"nickname"`
   HasPin            bool     `json:"hasPin"`
   Master            bool     `json:"master"`
   Maturity          string   `json:"maturity"`
   Onboarded         bool     `json:"onboarded"`
   UiLanguage        string   `json:"uiLanguage"`
   PlaybackLanguages []string `json:"playbackLanguages"`
   LastModifiedDate  string   `json:"lastModifiedDate"`
   AvatarUrl         string   `json:"avatarUrl"`
}

func GetProfiles(account *AccountToken) ([]Profile, error) {
   endpoint := "https://account.bellmedia.ca/api/profile/v2/account/" + account.AccountId

   req, err := http.NewRequest(http.MethodGet, endpoint, nil)
   if err != nil {
      return nil, err
   }
   req.Header.Set("authorization", "Bearer "+account.AccessToken)

   resp, err := doRequest(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()

   var activeProfiles []Profile
   if err := json.NewDecoder(resp.Body).Decode(&activeProfiles); err != nil {
      return nil, err
   }

   return activeProfiles, nil
}

func (p *Profile) String() string {
   var data strings.Builder
   data.WriteString("nickname: ")
   data.WriteString(p.Nickname)
   if p.HasPin {
      data.WriteString("\nhas pin: true")
   } else {
      data.WriteString("\nhas pin: false")
   }
   if p.Master {
      data.WriteString("\nmaster: true")
   } else {
      data.WriteString("\nmaster: false")
   }
   data.WriteString("\nmaturity: ")
   data.WriteString(p.Maturity)
   data.WriteString("\nid: ")
   data.WriteString(p.Id)
   return data.String()
}

type ProfileToken struct {
   AccessToken  string `json:"access_token"`
   RefreshToken string `json:"refresh_token"`
   Scope        string `json:"scope"`
   TokenType    string `json:"token_type"`
   ExpiresIn    int    `json:"expires_in"`
}

func SwitchProfile(account *AccountToken, profileId string) (*ProfileToken, error) {
   values := url.Values{}
   values.Set("grant_type", "refresh_token")
   values.Set("profile_id", profileId)
   values.Set("refresh_token", account.RefreshToken)

   body := []byte(values.Encode())

   req, err := http.NewRequest(http.MethodPost, "https://account.bellmedia.ca/api/login/v2.2", bytes.NewReader(body))
   if err != nil {
      return nil, err
   }

   // crave-web:default
   req.Header.Set("authorization", "Basic Y3JhdmUtd2ViOmRlZmF1bHQ=")
   req.Header.Set("content-type", "application/x-www-form-urlencoded")

   resp, err := doRequest(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()

   token := &ProfileToken{}
   if err := json.NewDecoder(resp.Body).Decode(token); err != nil {
      return nil, err
   }

   return token, nil
}

func (*ProfileToken) CachePath() string {
   return "rosso/crave/ProfileToken"
}

type Subscription struct {
   Type              string     `json:"type"`
   Experience        Experience `json:"experience"`
   SubscriptionState string     `json:"subscriptionState"`
   StoreName         string     `json:"storeName"`
   ExpirationDate    string     `json:"expirationDate"`
   AutoRenewStatus   bool       `json:"autoRenewStatus"`
}

func GetSubscriptions(token *ProfileToken) ([]Subscription, error) {
   req, err := http.NewRequest(http.MethodGet, "https://account.bellmedia.ca/api/subscription/v5", nil)
   if err != nil {
      return nil, err
   }
   req.Header.Set("authorization", "Bearer "+token.AccessToken)

   resp, err := doRequest(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()

   var wrapper struct {
      Subscriptions []Subscription `json:"subscriptions"`
   }
   if err := json.NewDecoder(resp.Body).Decode(&wrapper); err != nil {
      return nil, err
   }

   return wrapper.Subscriptions, nil
}

func (s *Subscription) String() string {
   var data strings.Builder
   data.WriteString("display name: ")
   data.WriteString(s.Experience.DisplayName)
   data.WriteString("\nexpiration date: ")
   data.WriteString(s.ExpirationDate)
   return data.String()
}
