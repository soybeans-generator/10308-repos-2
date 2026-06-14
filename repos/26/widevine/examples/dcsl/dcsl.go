package main

import (
   "bytes"
   "cmp"
   "encoding/json"
   "flag"
   "fmt"
   "log"
   "net/http"
   "os"
   "slices"

   "41.neocities.org/diana/widevine"
)

func main() {
   log.SetFlags(log.Ltime)
   var client_id struct {
      data []byte
      name string
   }
   var private_key struct {
      data []byte
      name string
   }
   flag.StringVar(&client_id.name, "c", "", "client ID")
   flag.StringVar(&private_key.name, "p", "", "private key")
   flag.Parse()
   if client_id.name != "" {
      var err error
      client_id.data, err = os.ReadFile(client_id.name)
      if err != nil {
         panic(err)
      }
      private_key.data, err = os.ReadFile(private_key.name)
      if err != nil {
         panic(err)
      }
      var license get_license
      err = license.New(private_key.data, client_id.data)
      if err != nil {
         panic(err)
      }
      fmt.Println(&license)
   } else {
      flag.Usage()
   }
}

// demo.unified-streaming.com/k8s/features
const content_id = "fkj3ljaSdfalkr3j"

func (g *get_license) New(pem_bytes, client_id []byte) error {
   var pssh widevine.PsshData
   pssh.ContentId = []byte(content_id)

   payload, err := pssh.EncodeLicenseRequest(client_id)
   if err != nil {
      return err
   }

   private_key, err := widevine.DecodePrivateKey(pem_bytes)
   if err != nil {
      return err
   }

   payload, err = widevine.EncodeSignedMessage(payload, private_key)
   if err != nil {
      return err
   }

   payload, err = json.Marshal(map[string][]byte{
      "payload": payload,
   })
   if err != nil {
      return err
   }
   payload, err = json.Marshal(map[string]any{
      "request": payload,
      "signer":  "widevine_test",
   })
   if err != nil {
      return err
   }

   resp, err := http.Post(
      "https://license.uat.widevine.com/cenc/getlicense", "",
      bytes.NewReader(payload),
   )
   if err != nil {
      return err
   }
   defer resp.Body.Close()
   return json.NewDecoder(resp.Body).Decode(g)
}

func (g *get_license) String() string {
   var b []byte
   if len(g.ClientInfo) > 0 {
      b = fmt.Append(b, "client_info:\n")
      // Sort the slice of pointers alphabetically by Name
      slices.SortFunc(g.ClientInfo, func(a, b *client_info) int {
         return cmp.Compare(a.Name, b.Name)
      })
      for _, info := range g.ClientInfo {
         b = fmt.Appendf(b, "\t%s: %s\n", info.Name, info.Value)
      }
   }
   b = fmt.Appendf(b, "client_max_hdcp_version: %s\n", g.ClientMaxHdcpVersion)
   b = fmt.Appendf(b, "drm_cert_serial_number: %s\n", g.DrmCertSerialNumber)
   b = fmt.Appendf(b, "internal_status: %d\n", g.InternalStatus)
   b = fmt.Appendf(b, "make: %s\n", g.Make)
   b = fmt.Appendf(b, "model: %s\n", g.Model)
   b = fmt.Appendf(b, "oem_crypto_api_version: %d\n", g.OemCryptoApiVersion)
   b = fmt.Appendf(b, "platform: %s\n", g.Platform)
   b = fmt.Appendf(b, "security_level: %d\n", g.SecurityLevel)
   b = fmt.Appendf(b, "soc: %s\n", g.Soc)
   b = fmt.Appendf(b, "status: %s\n", g.Status)
   if g.StatusMessage != "" {
      b = fmt.Appendf(b, "status_message: %s\n", g.StatusMessage)
   }
   b = fmt.Appendf(b, "system_id: %d\n", g.SystemId)

   return string(bytes.TrimRight(b, "\n"))
}

type client_info struct {
   Name  string `json:"name"`
   Value string `json:"value"`
}

type get_license struct {
   ClientInfo           []*client_info `json:"client_info"`
   ClientMaxHdcpVersion string         `json:"client_max_hdcp_version"`
   DrmCertSerialNumber  []byte         `json:"drm_cert_serial_number"`
   InternalStatus       int            `json:"internal_status"`
   Make                 string
   Model                string
   OemCryptoApiVersion  int `json:"oem_crypto_api_version"`
   Platform             string
   SecurityLevel        int `json:"security_level"`
   Soc                  string
   Status               string
   StatusMessage        string `json:"status_message"`
   SystemId             int    `json:"system_id"`
}
