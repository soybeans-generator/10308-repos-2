package amazon

import (
   "bytes"
   "encoding/json"
   "errors"
   "fmt"
   "log"
   "net/http"
)

const DeviceID = "deviceID"

const HostAmazonAPI = "https://api.amazon.com"

// doRequest wraps the http.Client Do method to log every outgoing request.
func doRequest(req *http.Request) (*http.Response, error) {
   log.Println(req.Method, req.URL)
   client := &http.Client{}
   return client.Do(req)
}

// CodePair represents the public and private codes used for device linking.
type CodePair struct {
   PublicCode  string `json:"public_code"`
   PrivateCode string `json:"private_code"`
}

// CreateCodePair requests a public and private code pair for device linking.
func CreateCodePair(deviceTypeID string) (*CodePair, error) {
   if deviceTypeID == "" {
      return nil, errors.New("deviceTypeID cannot be empty")
   }

   payload := map[string]any{
      "code_data": map[string]string{
         "domain":        "Device",
         "device_type":   deviceTypeID,
         "device_serial": DeviceID,
      },
   }
   body, err := json.MarshalIndent(payload, "", " ")
   if err != nil {
      return nil, err
   }
   req, err := http.NewRequest(
      "POST", HostAmazonAPI+"/auth/create_codepair",
      bytes.NewBuffer(body),
   )
   if err != nil {
      return nil, err
   }

   resp, err := doRequest(req)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()

   if resp.StatusCode != http.StatusOK {
      return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
   }

   // Decode directly into our new struct type
   var result CodePair
   if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
      return nil, err
   }

   return &result, nil
}
