// profile.go begin
// The shapes of the files on disk, and the helpers both halves need.
//
// NOTHING HERE TOUCHES THE DLL OR THE SAMPLE. These types are what -1..-4 write and what
// -5..-7 read, so they must exist on every platform; keeping them in one place is what stops
// the writer and the reader from drifting apart.
package main

import (
   "bytes"
   "crypto/ecdh"
   "encoding/binary"
   "os"
   "strconv"
)

// keyLen is 32: the P-256 scalar length and the size both stage routines accept.
const keyLen = 0x20

// dpPattern is the key consumer's size check: `cmp dword ptr [rcx+0x14], 0x41`. It is the
// anchor for -3's census and for the candidate walks in -4 and -7.
var dpPattern = []byte{0x83, 0x79, 0x14, 0x41}

func isFile(p string) bool {
   fi, err := os.Stat(p)
   return err == nil && fi.Mode().IsRegular()
}

func le16(b []byte, o int) uint16 { return binary.LittleEndian.Uint16(b[o:]) }
func le32(b []byte, o int) uint32 { return binary.LittleEndian.Uint32(b[o:]) }

// pubBytes normalizes a stored public key to the 65-byte SEC 1 form. nil means the point is
// off the curve or at infinity.
func pubBytes(raw []byte) []byte {
   if len(raw) == 64 {
      raw = append([]byte{4}, raw...)
   }
   k, err := ecdh.P256().NewPublicKey(raw)
   if err != nil {
      return nil
   }
   return k.Bytes()
}

// pubFor returns d*G as 0x04||X||Y, or nil when d is not a valid P-256 scalar.
func pubFor(d []byte) []byte {
   priv, err := ecdh.P256().NewPrivateKey(d)
   if err != nil {
      return nil
   }
   return priv.PublicKey().Bytes()
}

// pubMatches reports whether d*G is the public key in raw, in either form. The nils are
// checked first: bytes.Equal treats two empty slices as equal.
func pubMatches(d, raw []byte) bool {
   got, want := pubFor(d), pubBytes(raw)
   return got != nil && want != nil && bytes.Equal(got, want)
}

// vkey is the profile's key for one routine family. JSON object keys are strings, and every
// writer and reader goes through this one function.
func vkey(v int) string { return strconv.Itoa(v) }

// dllProfile is everything derived from one DLL build, keyed by its SHA-256. Never keyed by
// the image: LoadLibraryW bakes the load base into IAT slots and relocated fields, so two
// decrypted images of one DLL never hash alike.
type dllProfile struct {
   DLLSHA256   string                    `json:"dll_sha256"`
   SizeOfImage uint32                    `json:"size_of_image"`
   Census      *profileCensus            `json:"census,omitempty"`
   Map         map[string]*profileMap    `json:"map,omitempty"`
   Stages      map[string]*profileStages `json:"stages,omitempty"`
}

// famTab is one family's stage 3/4 tables. The cluster and the permutation travel together
// because stage 4 needs both and a profile can only be valid when both came from one family.
type famTab struct {
   cluster uint32
   perm    [16]int
}

// imgDesc is one digest-validated descriptor. va is its own address and identifies a
// candidate; descVA is +0x28 and is what a call inside the image targets; rva and ln are the
// code block, meaningful only for heap-exec descriptors; off and size are its file position.
type imgDesc struct {
   va     uint32
   off    uint32
   size   uint32
   descVA uint32
   rva    uint32
   ln     uint32
}

// profileCensus is the descriptor census, flattened. Spans are the segment ranges to patch;
// Heaps are {va, descVA, codeRVA, codeLen}.
type profileCensus struct {
   Spans [][2]uint32 `json:"spans"`
   Heaps [][4]uint32 `json:"heaps"`
}

// profileMap is -3's result for one family. Map is an ARRAY because stage 4 indexes a table
// with it.
type profileMap struct {
   Cluster  uint32  `json:"cluster"`
   Magic    string  `json:"magic"`
   Map      [16]int `json:"map"` // mapped nibble -> real nibble
   Consumer uint32  `json:"consumer_desc_va"`
}

// profileStages is -7's result for one family: the whole chain, not just the two descriptors.
type profileStages struct {
   S1 uint32 `json:"s1_desc_va"`
   S2 uint32 `json:"s2_desc_va"`
   K1 int    `json:"s1_key_half"`
   O1 int    `json:"s1_out_buf"`
   K2 int    `json:"s2_key_half"`
   O2 int    `json:"s2_out_buf"`
}

// subRecord is prsubs.json: -1's result.
type subRecord struct {
   SHA256  string `json:"sha256"`
   DescVA  uint32 `json:"desc_va"`
   CodeRVA uint32 `json:"code_rva"`
   SegLen  uint32 `json:"seg_len"`
}

// profile.go end
