// criterion.go
package main

import (
   "41.neocities.org/maya"
   "41.neocities.org/rosso/criterion"
   "fmt"
   "log"
   "net/url"
   "os"
)

func main() {
   log.SetFlags(log.Ltime)
   err := new(client).do()
   if err != nil {
      log.Fatal(err)
   }
}

type client struct {
   Widevine    maya.FlagString
   cache       maya.Cache
   dash_id     maya.FlagString
   device_code maya.FlagBool
   media_id    maya.FlagString
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
      {Name: "media-id", Value: &c.media_id},
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
   if c.media_id != "" {
      return c.do_media_id()
   }
   if c.dash_id != "" {
      return c.do_dash_id()
   }
   return flags.Usage(os.Stderr, "criterion")
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

// do_media_id goes from a media id to a parsed manifest: refresh for a live
// access token, playback for the signed MPD, then maya reads the manifest.
//
// The refresh is unconditional because the access token only lasts about an
// hour and TokenSet.Expiry is measured from the moment it is called, so a cached
// set cannot report whether it has already gone stale.
func (c *client) do_media_id() error {
   var token criterion.TokenSet
   if err := c.cache.Decode(&token); err != nil {
      return err
   }
   next, err := criterion.RequestRefresh(token.RefreshToken)
   if err != nil {
      return fmt.Errorf("%w (run -device-code then -token)", err)
   }
   // Persist before the network calls: the refresh token rotates on every
   // exchange, so the old one is already spent by the time this returns.
   if err := c.cache.Encode(next); err != nil {
      return err
   }
   session := criterion.Session{Token: next.AccessToken}
   playback, err := session.FetchPlayback(string(c.media_id))
   if err != nil {
      return err
   }
   for _, item := range playback.Playlist {
      log.Println(item.Title)
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
