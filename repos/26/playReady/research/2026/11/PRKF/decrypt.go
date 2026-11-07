// decrypt.go begin
//go:build windows

// decrypt.go is prkf -3: decrypt the signing key.
//
// Decrypts a PlayReady signing key (testdata/extracted.sig.prv ->
// testdata/extracted.sig.plain).
//
// The names are fixed: input, output and public key are the ones prkf -1
// produces, inside testdata/. The output is written only after every
// available check passes.
//
// # VERSION SUPPORT
//
// Only ONE value differs between DLL builds: the RVA of the heap descriptor
// holding the signing-key routine. It comes from testdata/prsubs.json, keyed
// by the DLL sha256 and produced by prkf -2, which does not use sample keys.
// This program refuses to run if the cache does not match the DLL.
//
// Everything else is hardcoded because it cannot drift with the DLL:
//
//   - op=3 and the WarbirdCallArgs layout are a kernel ABI. The DLL and the
//     running kernel must agree on them, so neither can change unilaterally.
//     The block, the call and the module load are all in warbird.go, shared
//     with prkf -2.
//   - The routine's own argument struct is packed (it reads its output
//     pointer unaligned at +0x14), and packed layout is fixed by source and
//     invariant under recompilation.
//   - size == 0x20 is the P-256 private scalar length, and the routine tests
//     it itself with `cmp dword ptr [rcx+10h], 20h`.
//
// prsubs.json is read from testdata/, so run prkf -2 first; both steps agree
// on the directory because both go through outFile.
//
// # VERIFICATION
//
// The check is cryptographic and needs no secret reference: the plaintext d
// must satisfy d*G == Q, where Q is the P-256 public key that prkf -1 wrote
// next to the ciphertext. A wrong descriptor, a wrong output offset, a wrong
// argument layout or a wrong input file cannot produce a scalar whose public
// point lands on Q. Cost: a few milliseconds.
//
// crypto/ecdh covers both directions: NewPublicKey rejects a published point
// that is off the curve or at infinity, and NewPrivateKey rejects a scalar
// outside [1, n-1] before the base-point multiply is reached. That range
// rejection is why no separate range test appears below.
//
// Failure is loud, never silent:
//
//   wrong desc_va     -> NTSTATUS 0xC0000095 (INTEGER_OVERFLOW)
//   wrong arg layout  -> status dword 0x80070057 (E_INVALIDARG) and an
//                        unwritten output buffer; prkf -2 would also
//                        report zero accepted descriptors
//   output == input   -> descriptor for the wrong routine
//   d*G != sig.pub    -> descriptor, argument layout or input is wrong
//
// NOTE: dllPath is declared in findsub.go; keyLen, argsLen, statusOK, wbArgs,
// newWbArgs, loadWarbird and callWarbird are in warbird.go. This file declares
// no package-wide value of its own except the three paths below, and it
// imports neither unsafe nor syscall: the one pointer conversion and the one
// module load are both inside warbird.go.
package main

import (
   "bytes"
   "crypto/ecdh"
   "crypto/rand"
   "crypto/sha256"
   "encoding/hex"
   "encoding/json"
   "errors"
   "fmt"
   "os"
)

// File names this step reads and writes. They are vars, not consts, only
// because outFile resolves outDir; outDir is itself a constant, so the values
// are fixed for the life of the process.
var (
   srcName = outFile("extracted.sig.prv")   // written by prkf -1
   pubName = outFile("extracted.sig.pub")   // written by prkf -1
   dstName = outFile("extracted.sig.plain") // 32-byte plaintext scalar
)

func cmdDecrypt() error {
   if !isFile(srcName) {
      return fmt.Errorf("missing input: %s\n  run prkf -1 first", srcName)
   }
   if !isFile(pubName) {
      return fmt.Errorf("missing public key: %s\n  run prkf -1 first", pubName)
   }

   // ---- decrypt ------------------------------------------------------
   got, err := decryptSigningKey(srcName)
   if err != nil {
      return err
   }
   fmt.Printf("%s (%d bytes)\n", srcName, len(got))
   fmt.Printf("plaintext %s\n", hex.EncodeToString(got))

   // ---- validation: d*G must equal the published public key ----------
   raw, err := os.ReadFile(pubName)
   if err != nil {
      return err
   }
   // Normalize to the uncompressed 65-byte SEC 1 form. NewPublicKey accepts
   // the uncompressed and compressed encodings and rejects anything off the
   // curve or at infinity, so the on-curve check is not repeated here.
   if len(raw) == 64 { // raw x||y: add the uncompressed prefix
      raw = append([]byte{0x04}, raw...)
   }
   k, err := ecdh.P256().NewPublicKey(raw)
   if err != nil {
      return fmt.Errorf("%s: P-256 point: %v", pubName, err)
   }
   want := k.Bytes()

   // An out-of-range d makes NewPrivateKey fail, leaving gotPub nil, which
   // falls through to the same verdict as a mismatched point.
   var gotPub []byte
   if priv, err := ecdh.P256().NewPrivateKey(got); err == nil {
      gotPub = priv.PublicKey().Bytes()
   }
   if !bytes.Equal(gotPub, want) {
      return fmt.Errorf("d*G != %s - the plaintext is not the private key for\n"+
         "that public key; the descriptor, the argument layout or the\n"+
         "input file is wrong; nothing was written", pubName)
   }
   fmt.Printf("[ OK ] d*G == %s\n", pubName)
   fmt.Printf("       Q = (%s,\n            %s)\n",
      hex.EncodeToString(want[1:33]), hex.EncodeToString(want[33:65]))

   // ---- write --------------------------------------------------------
   if err := os.WriteFile(dstName, got, 0o666); err != nil {
      return err
   }
   fmt.Printf("\nwrote %s (%d bytes)\n", dstName, len(got))
   return nil
}

// ---- the kernel call -----------------------------------------------------

// decryptSigningKey decrypts a 32-byte obfuscated PlayReady signing key,
// reading the *.sig.prv component from prvPath and returning the 32-byte
// plaintext. Nothing is written; cmdDecrypt writes after validating.
func decryptSigningKey(prvPath string) ([]byte, error) {
   rec, err := loadPrsubs()
   if err != nil {
      return nil, err
   }

   // The module has to be mapped in this process before the call: rec.DescVA
   // is an RVA relative to its image base, not a file offset.
   base, ntq, err := loadWarbird()
   if err != nil {
      return nil, err
   }

   enc, err := os.ReadFile(prvPath)
   if err != nil {
      return nil, err
   }
   if len(enc) != keyLen {
      return nil, fmt.Errorf("%s: expected %d bytes, got %d", prvPath, keyLen, len(enc))
   }

   // A random fill proves the routine actually wrote to the output buffer;
   // a fixed sentinel could collide with real key material.
   fill := make([]byte, keyLen)
   if _, err := rand.Read(fill); err != nil {
      return nil, err
   }
   keyBuf := append(make([]byte, 0, keyLen), enc...) // the routine gets its own copy
   status := make([]byte, 0x10)                      // zero-filled
   out := append(make([]byte, 0, keyLen), fill...)

   // The block, the call and the lifetime handling are in warbird.go, so this
   // step and prkf -2 cannot disagree about the ABI. out must stay live until
   // the result is read - its address is stored as a uintptr - and it is, by
   // the comparison below.
   args := newWbArgs(uint64(base)+rec.DescVA, status, keyBuf, out, keyLen)
   st, _, _ := callWarbird(ntq, args)

   if st32 := uint32(st); st32 != 0 {
      msg := fmt.Sprintf("NtQuerySystemInformation -> %#010x", st32)
      if st32 == 0xC0000095 {
         msg += " (INTEGER_OVERFLOW: desc_va is wrong for this build)"
      }
      return nil, errors.New(msg)
   }

   if !statusOK(status) {
      return nil, fmt.Errorf("routine returned %s - the argument layout no "+
         "longer matches this build; re-run prkf -2",
         hex.EncodeToString(status[:4]))
   }

   if bytes.Equal(out, fill) {
      return nil, errors.New("output buffer untouched - out_off is wrong")
   }
   if bytes.Equal(out, enc) {
      return nil, errors.New("output equals input - desc_va is the wrong routine")
   }

   return out, nil
}

func isFile(p string) bool {
   fi, err := os.Stat(p)
   return err == nil && fi.Mode().IsRegular()
}

// ---- prsubs.json ---------------------------------------------------------

type prsubsRecord struct {
   SHA256 string `json:"sha256"`
   DescVA uint64 `json:"desc_va"`
}

// loadPrsubs loads and validates the build-specific descriptor RVA.
func loadPrsubs() (*prsubsRecord, error) {
   dll, err := os.ReadFile(dllPath)
   if err != nil {
      return nil, err
   }
   sum := sha256.Sum256(dll)
   sha := hex.EncodeToString(sum[:])

   cache := outFile("prsubs.json")
   if !isFile(cache) {
      return nil, fmt.Errorf("no %s - run prkf -2 first", cache)
   }
   raw, err := os.ReadFile(cache)
   if err != nil {
      return nil, err
   }
   var rec prsubsRecord
   if err := json.Unmarshal(raw, &rec); err != nil {
      return nil, fmt.Errorf("%s: %v", cache, err)
   }

   if rec.SHA256 != sha {
      return nil, fmt.Errorf("%s was built for a different DLL\n"+
         "  cache : %s\n"+
         "  actual: %s\n"+
         "  re-run prkf -2", cache, rec.SHA256, sha)
   }
   if rec.DescVA == 0 {
      return nil, fmt.Errorf("%s has no desc_va - re-run prkf -2", cache)
   }
   return &rec, nil
}

// decrypt.go end
