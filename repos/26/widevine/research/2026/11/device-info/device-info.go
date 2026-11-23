// Dumps a Widevine ClientIdentification protobuf read from a binary file.
//
//   go run . client_id.bin
package main

import (
   "crypto/x509"
   "fmt"
   "os"
   "strings"
   "time"

   "41.neocities.org/protobuf"
)

var (
   tokenTypes = []string{"KEYBOX", "DRM_DEVICE_CERTIFICATE", "REMOTE_ATTESTATION_CERTIFICATE", "OEM_DEVICE_CERTIFICATE", "BOOT_CERTIFICATE_CHAIN"}
   certTypes  = []string{"ROOT", "DEVICE_MODEL", "DEVICE", "SERVICE", "PROVISIONER"}
   algorithms = []string{"UNKNOWN_ALGORITHM", "RSA", "ECC_SECP256R1", "ECC_SECP384R1", "ECC_SECP521R1"}
   keyTypes   = []string{"RSA_2048", "RSA_3072", "ECC_SECP256R1", "ECC_SECP384R1", "ECC_SECP521R1"}
   hdcp       = []string{"HDCP_NONE", "HDCP_V1", "HDCP_V2", "HDCP_V2_1", "HDCP_V2_2", "HDCP_V2_3"}
)

func dumpCert(b []byte, depth int) {
   m, err := protobuf.Decode(b)
   if err != nil {
      p(depth, "drm_certificate: %d bytes, undecodable", len(b))
      return
   }
   p(depth, "DrmCertificate (%d bytes)", len(b))

   p(depth+1, "type: %s", name(certTypes, u(m, 1)))
   if sn := raw(m, 2); sn != nil {
      p(depth+1, "serial_number: %x", sn)
   }
   if v, ok := m.First(3); ok {
      p(depth+1, "creation_time: %s", ts(v.Uint))
   }
   if v, ok := m.First(12); ok {
      p(depth+1, "expiration_time: %s", ts(v.Uint))
   }
   if pk := raw(m, 4); pk != nil {
      p(depth+1, "public_key: %d bytes, %s", len(pk), keyDesc(pk))
   }
   if v, ok := m.First(5); ok {
      p(depth+1, "system_id: %d", v.Uint)
   }
   if pid := str(m, 7); pid != "" {
      p(depth+1, "provider_id: %s", pid)
   }
   p(depth+1, "algorithm: %s", name(algorithms, u(m, 9)))
   if rot := raw(m, 10); rot != nil {
      p(depth+1, "rot_id: %d bytes", len(rot))
   }
}

func dumpSigned(b []byte, depth int) {
   m, err := protobuf.Decode(b)
   if err != nil {
      p(depth, "token: %d bytes, undecodable", len(b))
      return
   }
   p(depth, "token: SignedDrmCertificate (%d bytes)", len(b))

   if cert := raw(m, 1); cert != nil {
      dumpCert(cert, depth+1)
   }
   if sig := raw(m, 2); sig != nil {
      p(depth+1, "signature: %d bytes", len(sig))
   }
   if s := raw(m, 3); s != nil {
      dumpSigned(s, depth+1)
   }
}

func keyDesc(der []byte) string {
   if k, err := x509.ParsePKCS1PublicKey(der); err == nil {
      return fmt.Sprintf("RSA %d-bit", k.N.BitLen())
   }
   if k, err := x509.ParsePKIXPublicKey(der); err == nil {
      return fmt.Sprintf("%T", k)
   }
   return "unparsed DER"
}

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
      if t == 0 {
         p(1, "token: keybox, %d bytes", len(tok))
      } else {
         dumpSigned(tok, 1)
      }
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
   if c := sub(m, 6); c != nil {
      p(1, "client_capabilities:")
      p(2, "client_token: %t", u(c, 1) != 0)
      p(2, "session_token: %t", u(c, 2) != 0)
      p(2, "max_hdcp_version: %s", name(hdcp, u(c, 4)))
      p(2, "oem_crypto_api_version: %d", u(c, 5))
      p(2, "anti_rollback_usage_table: %t", u(c, 6) != 0)
      p(2, "can_update_srm: %t", u(c, 8) != 0)
      for _, k := range m.Values(9) {
         p(2, "supported_certificate_key_type: %s", name(keyTypes, k.Uint))
      }
      p(2, "analog_output_capabilities: %d", u(c, 10))
      p(2, "can_disable_analog_output: %t", u(c, 11) != 0)
      p(2, "resource_rating_tier: %d", u(c, 12))
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

func sub(m protobuf.Message, f int) protobuf.Message {
   v, ok := m.First(f)
   if !ok {
      return nil
   }
   c, err := v.Message()
   if err != nil {
      return nil
   }
   return c
}

func ts(sec uint64) string {
   if sec == 0 {
      return "unset"
   }
   return time.Unix(int64(sec), 0).UTC().Format(time.RFC3339)
}

func u(m protobuf.Message, f int) uint64 {
   if v, ok := m.First(f); ok {
      return v.Uint
   }
   return 0
}
