package main

import (
   "bytes"
   "encoding/hex"
   "encoding/xml"
   "flag"
   "os"
)

func main() {
   in := flag.String("i", "", "input")
   out := flag.String("o", "keybox.bin", "output")
   flag.Parse()
   if *in != "" {
      data, err := os.ReadFile(*in)
      if err != nil {
         panic(err)
      }
      var secure widevine
      err = xml.Unmarshal(data, &secure)
      if err != nil {
         panic(err)
      }
      os.WriteFile(*out, secure.marshal(), os.ModePerm)
   } else {
      flag.Usage()
   }
}

type device_id [32]byte

func (d *device_id) UnmarshalText(data []byte) error {
   copy(d[:], data)
   return nil
}

type hex_data []byte

func (h *hex_data) UnmarshalText(data []byte) error {
   var err error
   *h, err = hex.AppendDecode(nil, data)
   if err != nil {
      return err
   }
   return nil
}

type widevine struct {
   Keybox struct {
      DeviceId device_id `xml:"DeviceID,attr"`
      Key      hex_data
      Id       hex_data `xml:"ID"`
      Magic    hex_data
      Crc      hex_data `xml:"CRC"`
   }
}

func (w *widevine) marshal() []byte {
   var data bytes.Buffer
   data.Write(w.Keybox.DeviceId[:])
   data.Write(w.Keybox.Key)
   data.Write(w.Keybox.Id)
   data.Write(w.Keybox.Magic)
   data.Write(w.Keybox.Crc)
   return data.Bytes()
}
