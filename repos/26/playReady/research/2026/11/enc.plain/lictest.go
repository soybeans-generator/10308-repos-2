package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	pr "41.neocities.org/playReady"
)

const want = "100b6c20940f779a4589152b57d2dacb"

var out []string

func logf(format string, a ...any) {
	s := fmt.Sprintf(format, a...)
	out = append(out, s)
	fmt.Println(s)
}

func main() {
	resp, err := os.ReadFile("resp.xml")
	if err != nil {
		fmt.Println("read resp.xml:", err)
		return
	}
	lic, err := pr.ParseLicense(resp)
	if err != nil {
		fmt.Println("ParseLicense:", err)
		return
	}

	ck := lic.ContainerOuter.ContainerKeys.ContentKey
	ek := lic.ContainerOuter.ContainerKeys.ECCKey
	logf("xmr            %d bytes", lic.CBXMRLic)
	logf("kid            %x", ck.GuidKeyID)
	logf("key enc cipher 0x%04x", ck.KeyEncryptionCipherType)
	logf("CBEncryptedKey 0x%04x", ck.CBEncryptedKey)
	logf("ecc curve      0x%04x  keydata %d bytes", ek.EccCurveType, len(ek.KeyData))
	logf("ecc keydata    %x", ek.KeyData)
	logf("")

	raw, err := os.ReadFile("extracted.enc.plain")
	if err != nil {
		logf("FAIL  cannot read extracted.enc.plain: %v", err)
		os.Exit(1)
	}
	if len(raw) < 32 {
		logf("FAIL  extracted.enc.plain is %d bytes, expected 32", len(raw))
		os.Exit(1)
	}
	key, err := pr.ParseRawPrivateKey(raw[:32])
	if err != nil {
		logf("FAIL  invalid scalar: %v", err)
		os.Exit(1)
	}
	got, err := lic.Decrypt(key)
	if err != nil {
		logf("FAIL  decrypt: %v", err)
		os.Exit(1)
	}
	h := hex.EncodeToString(got)
	if h != want {
		logf("FAIL  content key %s, expected %s", h, want)
		os.Exit(1)
	}

	logf("ok    content key %s", h)
	logf("*** VALIDATED ***")
	os.WriteFile("lictest.txt", []byte(strings.Join(out, "\n")+"\n"), 0o644)
}
