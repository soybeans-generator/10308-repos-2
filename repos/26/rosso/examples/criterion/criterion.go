// criterion.go
package main

import (
   "41.neocities.org/maya"
   "41.neocities.org/rosso/criterion"
   "fmt"
   "log"
   "net/url"
   "os"
   "strings"
)

func main() {
   log.SetFlags(log.Ltime)
   err := new(client).do()
   if err != nil {
      log.Fatal(err)
   }
}

// mediaID pulls the id out of a deeplink such as
// https://www.criterionchannel.com/films/rst2RGdS/les-3-boutons, or accepts a
// bare id.
func mediaID(address string) (string, error) {
   parsed, err := url.Parse(address)
   if err != nil {
      return "", err
   }
   parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
   if len(parts) == 1 && parts[0] != "" {
      return parts[0], nil
   }
   if len(parts) < 2 {
      return "", fmt.Errorf("%q has no media id", address)
   }
   return parts[1], nil
}

type client struct {
   Widevine    maya.FlagString
   address     maya.FlagString
   cache       maya.Cache
   dash_id     maya.FlagString
   device_code maya.FlagBool
   token       maya.FlagBool
}

func (*client) CachePath() string {
   return "rosso/examples/criterion/client"
}

func (c *client) do() error {
   if err := c.cache.Setup(); err != nil {
      return err
   }
   if err := c.cache.Decode(c); err != nil {
      return c.cache.Encode(c)
   }
   flags := maya.FlagSet{
      {Name: "widevine-folder", Value: &c.Widevine},
      {Name: "device-code", Value: &c.device_code},
      {Name: "token", Value: &c.token},
      {Name: "address", Value: &c.address},
      {Name: "dash-id", Value: &c.dash_id},
   }
   if err := flags.Parse(os.Args[1:]); err != nil {
      return err
   }
   if flags.IsSet(&c.Widevine) {
      return c.cache.Encode(c)
   }
   if c.device_code {
      return c.do_device_code()
   }
   if c.token {
      return c.do_token()
   }
   if c.address != "" {
      return c.do_address()
   }
   if c.dash_id != "" {
      return c.do_dash_id()
   }
   return flags.Usage(os.Stderr, "criterion")
}

// do_address goes from a deeplink to a parsed manifest: media for the record,
// playback for the signed MPD, then maya reads the manifest.
func (c *client) do_address() error {
   media_id, err := mediaID(string(c.address))
   if err != nil {
      return err
   }
   var token criterion.TokenSet
   if err := c.cache.Decode(&token); err != nil {
      return err
   }
   session := criterion.Session{Token: token.AccessToken}
   media, err := session.FetchMedia(media_id)
   if err != nil {
      return err
   }
   log.Println(media.Title)
   playback, err := session.FetchPlayback(media_id)
   if err != nil {
      return err
   }
   source, err := playback.GetDash()
   if err != nil {
      return err
   }
   address, err := url.Parse(source.File)
   if err != nil {
      return err
   }
   manifest, err := maya.DashList(address)
   if err != nil {
      return err
   }
   return c.cache.Encode(source, manifest)
}

func (c *client) do_dash_id() error {
   var (
      source   criterion.Source
      manifest maya.Manifest
   )
   err := c.cache.Decode(&source, &manifest)
   if err != nil {
      return err
   }
   return maya.DashDownload(string(c.dash_id), &manifest, &maya.Options{
      Device:  string(c.Widevine),
      Drm:     maya.DrmWidevine,
      License: source.FetchWidevine,
   })
}

// do_device_code is step one of the login: it asks login.criterion.com for a
// code pair, shows it, and caches the DeviceCode so do_token can pick it up.
func (c *client) do_device_code() error {
   code, err := criterion.RequestDeviceCode()
   if err != nil {
      return err
   }
   fmt.Fprintf(os.Stderr, "open %v\n", code.VerificationURIComplete)
   fmt.Fprintf(os.Stderr, "or open %v and enter %v\n", code.VerificationURI, code.UserCode)
   fmt.Fprintf(os.Stderr, "then run -token, code expires in %v seconds\n", code.ExpiresIn)
   return c.cache.Encode(code)
}

// do_token is step two: one POST with the cached device code, once the request
// has been approved.
func (c *client) do_token() error {
   var code criterion.DeviceCode
   if err := c.cache.Decode(&code); err != nil {
      return err
   }
   token, err := criterion.RequestToken(code.DeviceCode)
   if err != nil {
      return err
   }
   return c.cache.Encode(token)
}

// criterion.go
