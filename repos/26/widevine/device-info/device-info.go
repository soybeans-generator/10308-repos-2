// Dumps a Widevine ClientIdentification protobuf read from a binary file.
//
//   go run . client_id.bin
package main

import (
   "fmt"
   "os"
   "strings"

   "41.neocities.org/protobuf"
)

var tokenTypes = []string{"KEYBOX", "DRM_DEVICE_CERTIFICATE", "REMOTE_ATTESTATION_CERTIFICATE", "OEM_DEVICE_CERTIFICATE", "BOOT_CERTIFICATE_CHAIN"}

func main() {
   if len(os.Args) != 2 {
      fmt.Fprintf(os.Stderr, "usage: %s <client_id file>\n", os.Args[0])
      os.Exit(2)
   }

   blob, err := os.ReadFile(os.Args[1])
   if err != nil {
      fmt.Fprintln(os.Stderr, err)
      os.Exit(1)
   }

   m, err := protobuf.Decode(blob)
   if err != nil {
      fmt.Fprintln(os.Stderr, "not a protobuf:", err)
      os.Exit(1)
   }

   p(0, "ClientIdentification (%d bytes)", len(blob))

   t := u(m, 1)
   p(1, "type: %d (%s)", t, name(tokenTypes, t))

   if tok := raw(m, 2); tok != nil {
      p(1, "token: %d bytes", len(tok))
   }

   for _, v := range m.Values(3) {
      nv, err := v.Message()
      if err != nil {
         continue
      }
      p(1, "info: %s = %s", str(nv, 1), str(nv, 2))
   }

   if v := raw(m, 4); v != nil {
      p(1, "provider_client_token: %d bytes", len(v))
   }
   if v, ok := m.First(5); ok {
      p(1, "license_counter: %d", v.Uint)
   }
   if v := raw(m, 7); v != nil {
      p(1, "vmp_data: %d bytes", len(v))
   }
}

func name(list []string, v uint64) string {
   if v < uint64(len(list)) {
      return list[v]
   }
   return fmt.Sprintf("UNKNOWN(%d)", v)
}

func p(depth int, format string, a ...any) {
   fmt.Printf("%s%s\n", strings.Repeat("  ", depth), fmt.Sprintf(format, a...))
}

func raw(m protobuf.Message, f int) []byte {
   if v, ok := m.First(f); ok {
      return v.Bytes
   }
   return nil
}

func str(m protobuf.Message, f int) string { return string(raw(m, f)) }

func u(m protobuf.Message, f int) uint64 {
   if v, ok := m.First(f); ok {
      return v.Uint
   }
   return 0
}
