//go:build libfido2 && cgo

package main

import (
	"os"
	"testing"
)

// TestLibfido2Hardware runs against a real dongle that already holds an
// ssh:p3sig-policy key (`p3sig dongle add`). P3SIG_HW_TEST=1 P3SIG_DONGLE_PIN=…
// CC=gcc go test -tags libfido2 -run Libfido2 — asks for one touch.
func TestLibfido2Hardware(t *testing.T) {
	if os.Getenv("P3SIG_HW_TEST") == "" {
		t.Skip("set P3SIG_HW_TEST=1 with a dongle plugged in")
	}
	d, err := findDongle()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("dongle %+v", d.Info())
	s, err := loadDongleSigner("")
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("p3sig libfido2 hardware test")
	sig, err := s.Sign(nil, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PublicKey().Verify(msg, sig); err != nil {
		t.Fatalf("sk-ecdsa signature from the dongle does not verify: %v", err)
	}
}
