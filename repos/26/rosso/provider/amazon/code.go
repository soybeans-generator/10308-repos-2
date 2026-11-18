// code.go marker preserve
package amazon

import (
   "bytes"
   "encoding/json"
   "errors"
   "fmt"
   "log"
   "net/http"
)

const (
   AppName         = "AIV"
   AppVersion      = "3.12.0"
   DeviceModel     = "sdk_gphone_x86"
   OSVersion       = "Android"
   SoftwareVersion = "999"
   DeviceDomain    = "Device"
)

const DeviceID = "deviceID"

const HostAmazonAPI = "https://api.amazon.com"

func deviceName() string {
   return fmt.Sprintf("%%FIRST_NAME%%'s%%DUPE_STRATEGY_1st%% %s", DeviceModel)
}

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
         "domain":           DeviceDomain,
         "device_name":      deviceName(),
         "app_name":         AppName,
         "app_version":      AppVersion,
         "device_model":     DeviceModel,
         "os_version":       OSVersion,
         "device_type":      deviceTypeID,
         "device_serial":    DeviceID,
         "software_version": SoftwareVersion,
      },
   }
   body, err := json.MarshalIndent(payload, "", " ")
   if err != nil {
      return nil, err
   }
   req, err := http.NewRequest(
      "POST", HostAmazonAPI+"/auth/create/codepair",
      bytes.NewBuffer(body),
   )
   if err != nil {
      return nil, err
   }
   req.Header.Set("content-type", "application/json")

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

// code.go marker preserve
