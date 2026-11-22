// account.go KEEP THIS LINE
package disney

import (
   "bytes"
   _ "embed"
   "encoding/json"
   "net/http"
   "strings"
)

// ZGlzbmV5JmJyb3dzZXImMS4wLjA
// disney&browser&1.0.0
const client_api_key = "ZGlzbmV5JmJyb3dzZXImMS4wLjA.Cu56AgSfBTDag5NiRA81oLHkDZfu5L3CKadnefEAY84"

//go:embed authenticateWithOtp.gql
var mutation_authenticate_with_otp string

//go:embed login.gql
var mutation_login string

//go:embed loginWithActionGrant.gql
var mutation_login_with_action_grant string

//go:embed refreshToken.gql
var mutation_refresh_token string

//go:embed registerDevice.gql
var mutation_register_device string

//go:embed requestOtp.gql
var mutation_request_otp string

//go:embed switchProfile.gql
var mutation_switch_profile string

// Response: Device
func RegisterDevice() (*Token, error) {
   body, err := json.Marshal(map[string]any{
      "query": mutation_register_device,
      "variables": map[string]any{
         "input": map[string]any{
            "deviceProfile":      "!",
            "deviceFamily":       "!",
            "applicationRuntime": "!",
            "attributes": map[string]string{
               "operatingSystem":        "",
               "operatingSystemVersion": "",
            },
         },
      },
   })
   if err != nil {
      return nil, err
   }
   req, err := http.NewRequest(
      "POST",
      "https://disney.api.edge.bamgrid.com/graph/v1/device/graphql",
      bytes.NewReader(body),
   )
   if err != nil {
      return nil, err
   }
   req.Header.Set("authorization", "Bearer "+client_api_key)
   resp, err := do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()
   var result struct {
      Data struct {
         RegisterDevice struct {
            Token Token
         }
      }
   }
   err = json.NewDecoder(resp.Body).Decode(&result)
   if err != nil {
      return nil, err
   }
   return &result.Data.RegisterDevice.Token, nil
}

type AuthenticateWithOtp struct {
   ActionGrant string
}

type Login struct {
   Account struct {
      Profiles []Profile
   }
}

type LoginWithActionGrant struct {
   Account struct {
      Profiles []Profile
   }
}

type Profile struct {
   Name string
   Id   string
}

func (p *Profile) String() string {
   var data strings.Builder
   data.WriteString("name: ")
   data.WriteString(p.Name)
   data.WriteString("\nid: ")
   data.WriteString(p.Id)
   return data.String()
}

type RequestOtp struct {
   Accepted bool
}

func (r *RequestOtp) String() string {
   if r.Accepted {
      return "accepted = true"
   }
   return "accepted = false"
}

// request: Device
func (t *Token) AuthenticateWithOtp(email, passcode string) (*AuthenticateWithOtp, error) {
   if err := t.assert("Device"); err != nil {
      return nil, err
   }
   body, err := json.Marshal(map[string]any{
      "query": mutation_authenticate_with_otp,
      "variables": map[string]any{
         "input": map[string]string{
            "email":    email,
            "passcode": passcode,
         },
      },
   })
   if err != nil {
      return nil, err
   }
   req, err := http.NewRequest(
      "POST",
      "https://disney.api.edge.bamgrid.com/v1/public/graphql",
      bytes.NewReader(body),
   )
   if err != nil {
      return nil, err
   }
   req.Header.Set("authorization", "Bearer "+t.AccessToken)
   resp, err := do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()
   var result struct {
      Data struct {
         AuthenticateWithOtp AuthenticateWithOtp
      }
   }
   err = json.NewDecoder(resp.Body).Decode(&result)
   if err != nil {
      return nil, err
   }
   return &result.Data.AuthenticateWithOtp, nil
}

// request: Device
// response: AccountWithoutActiveProfile
func (t *Token) FetchLogin(email, password string) (*Login, error) {
   if err := t.assert("Device"); err != nil {
      return nil, err
   }
   body, err := json.Marshal(map[string]any{
      "query": mutation_login,
      "variables": map[string]any{
         "input": map[string]string{
            "email":    email,
            "password": password,
         },
      },
   })
   if err != nil {
      return nil, err
   }
   req, err := http.NewRequest(
      "POST",
      "https://disney.api.edge.bamgrid.com/v1/public/graphql",
      bytes.NewReader(body),
   )
   if err != nil {
      return nil, err
   }
   req.Header.Set("authorization", "Bearer "+t.AccessToken)
   resp, err := do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()
   var result struct {
      Data struct {
         Login Login
      }
      Extensions struct {
         Sdk struct {
            Token Token
         }
      }
   }
   err = json.NewDecoder(resp.Body).Decode(&result)
   if err != nil {
      return nil, err
   }
   *t = result.Extensions.Sdk.Token
   return &result.Data.Login, nil
}

// request: Device
// response: AccountWithoutActiveProfile
func (t *Token) LoginWithActionGrant(actionGrant string) (*LoginWithActionGrant, error) {
   if err := t.assert("Device"); err != nil {
      return nil, err
   }
   body, err := json.Marshal(map[string]any{
      "query": mutation_login_with_action_grant,
      "variables": map[string]any{
         "input": map[string]string{
            "actionGrant": actionGrant,
         },
      },
   })
   if err != nil {
      return nil, err
   }
   req, err := http.NewRequest(
      "POST",
      "https://disney.api.edge.bamgrid.com/v1/public/graphql",
      bytes.NewReader(body),
   )
   if err != nil {
      return nil, err
   }
   req.Header.Set("authorization", "Bearer "+t.AccessToken)
   resp, err := do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()
   var result struct {
      Data struct {
         LoginWithActionGrant LoginWithActionGrant
      }
      Extensions struct {
         Sdk struct {
            Token Token
         }
      }
   }
   err = json.NewDecoder(resp.Body).Decode(&result)
   if err != nil {
      return nil, err
   }
   *t = result.Extensions.Sdk.Token
   return &result.Data.LoginWithActionGrant, nil
}

// expires: 4 hours
// request: Account
func (t *Token) Refresh() error {
   if err := t.assert("Account"); err != nil {
      return err
   }
   body, err := json.Marshal(map[string]any{
      "query": mutation_refresh_token,
      "variables": map[string]any{
         "input": map[string]string{
            "refreshToken": t.RefreshToken,
         },
      },
   })
   if err != nil {
      return err
   }
   req, err := http.NewRequest(
      "POST",
      "https://disney.api.edge.bamgrid.com/graph/v1/device/graphql",
      bytes.NewReader(body),
   )
   if err != nil {
      return err
   }
   req.Header.Set("authorization", "Bearer "+client_api_key)
   resp, err := do(req)
   if err != nil {
      return err
   }
   defer resp.Body.Close()
   var result struct {
      Extensions struct {
         Sdk struct {
            Token Token
         }
      }
   }
   err = json.NewDecoder(resp.Body).Decode(&result)
   if err != nil {
      return err
   }
   *t = result.Extensions.Sdk.Token
   return nil
}

// request: Device
func (t *Token) RequestOtp(email string) (*RequestOtp, error) {
   if err := t.assert("Device"); err != nil {
      return nil, err
   }
   body, err := json.Marshal(map[string]any{
      "query": mutation_request_otp,
      "variables": map[string]any{
         "input": map[string]string{
            "email":  email,
            "reason": "Login",
         },
      },
   })
   if err != nil {
      return nil, err
   }
   req, err := http.NewRequest(
      "POST",
      "https://disney.api.edge.bamgrid.com/v1/public/graphql",
      bytes.NewReader(body),
   )
   if err != nil {
      return nil, err
   }
   req.Header.Set("authorization", "Bearer "+t.AccessToken)
   resp, err := do(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()
   var result struct {
      Data struct {
         RequestOtp RequestOtp
      }
   }
   err = json.NewDecoder(resp.Body).Decode(&result)
   if err != nil {
      return nil, err
   }
   return &result.Data.RequestOtp, nil
}

// THIS REQUEST SETS THE LOCATION BASED ON YOUR IP
// request: AccountWithoutActiveProfile
// response: Account
func (t *Token) SwitchProfile(profileId string) error {
   if err := t.assert("AccountWithoutActiveProfile"); err != nil {
      return err
   }
   body, err := json.Marshal(map[string]any{
      "query": mutation_switch_profile,
      "variables": map[string]any{
         "input": map[string]string{
            "profileId": profileId,
         },
      },
   })
   if err != nil {
      return err
   }
   req, err := http.NewRequest(
      "POST",
      "https://disney.api.edge.bamgrid.com/v1/public/graphql",
      bytes.NewReader(body),
   )
   if err != nil {
      return err
   }
   req.Header.Set("authorization", "Bearer "+t.AccessToken)
   resp, err := do(req)
   if err != nil {
      return err
   }
   defer resp.Body.Close()
   var result struct {
      Extensions struct {
         Sdk struct {
            Token Token
         }
      }
   }
   err = json.NewDecoder(resp.Body).Decode(&result)
   if err != nil {
      return err
   }
   *t = result.Extensions.Sdk.Token
   return nil
}

// account.go KEEP THIS LINE
