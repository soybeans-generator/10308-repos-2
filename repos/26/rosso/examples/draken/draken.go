package main

import (
   "41.neocities.org/maya"
   "41.neocities.org/rosso/provider/draken"
   "log"
   "path"
)

func main() {
   log.SetFlags(log.Ltime)
   err := new(client).do()
   if err != nil {
      log.Fatal(err)
   }
}

type client struct {
   Widevine maya.FlagString
   address maya.FlagString
   cache maya.Cache
   dash_id maya.FlagString
   email maya.FlagString
   password maya.FlagString
}

func (c *client) do() error {
   if err := c.cache.Setup(); err != nil {
      return err
   }
   if err := c.cache.Decode(c); err != nil {
      if !os.IsNotExist(err) {
         return err
      }
   }
   flags := maya.FlagSet{
      {Name: "widevine-folder", Value: &c.Widevine},
      {Name: "email", Value: &c.email, Needs: []string{"password"}},
      {Name: "password", Value: &c.password, Needs: []string{"email"}},
      {Name: "address", Value: &c.address},
      {Name: "dash-id", Value: &c.dash_id},
   }
   if err := flags.Parse(os.Args[1:]); err != nil {
      return err
   }
   if flags.IsSet(&c.Widevine) {
      return c.cache.Write(c)
   }
   if c.email != "" {
      if c.password != "" {
         return c.do_email_password()
      }
   }
   if c.address != "" {
      return c.do_address()
   }
   if c.dash_id != "" {
      return c.do_dash_id()
   }
   return flags.Usage(os.Stderr, "draken")
}

///

func (c *client) do_email_password() error {
   var err error
   c.Login, err = draken.FetchLogin(c.email, c.password)
   if err != nil {
      return err
   }
   return c.cache.Write(c)
}

func (c *client) do_address() error {
   playable_id, err := draken.FetchPlayableId(path.Base(c.address))
   if err != nil {
      return err
   }
   entitlement, err := draken.FetchEntitlement(c.Login.Token, playable_id)
   if err != nil {
      return err
   }
   playback, err := draken.FetchPlayback(
      c.Login.Token, playable_id, entitlement.Token,
   )
   if err != nil {
      return err
   }
   dash, err := maya.DashList(playback.Playlist)
   if err != nil {
      return err
   }
   return c.cache.Write(dash, playback)
}

func (c *client) do_dash() error {
   return c.Dash.Download(&c.Job,
      func(data []byte) ([]byte, error) {
         return c.Playback.FetchWidevine(c.Login.Token, data)
      },
   )
}
