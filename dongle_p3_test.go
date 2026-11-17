package main

// Runs the CLI's dongle client against the firmware's own proto.c (task #2628):
//   make -C ../p3sig/firmware/dongle/tests/host dongle_sim
//   P3SIG_DONGLE_SIM=../p3sig/firmware/dongle/tests/host/dongle_sim go test -run DongleP3

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"os/exec"
	"testing"

	"golang.org/x/crypto/curve25519"
)

type simDongle struct {
	in  io.WriteCloser
	out io.Reader
	cmd *exec.Cmd
}

func startSim(t *testing.T) *simDongle {
	p := os.Getenv("P3SIG_DONGLE_SIM")
	if p == "" {
		t.Skip("P3SIG_DONGLE_SIM not set (build p3sig firmware/dongle/tests/host/dongle_sim)")
	}
	c := exec.Command(p)
	in, _ := c.StdinPipe()
	out, _ := c.StdoutPipe()
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { in.Close(); c.Wait() })
	return &simDongle{in, out, c}
}

func (d *simDongle) do(kind byte, msg []byte) (byte, []byte, error) {
	h := []byte{kind, byte(len(msg) >> 8), byte(len(msg))}
	if _, err := d.in.Write(append(h, msg...)); err != nil {
		return 0, nil, err
	}
	var r [3]byte
	if _, err := io.ReadFull(d.out, r[:]); err != nil {
		return 0, nil, err
	}
	b := make([]byte, int(r[1])<<8|int(r[2]))
	_, err := io.ReadFull(d.out, b)
	return r[0], b, err
}

type simLink struct {
	d    *simDongle
	kind byte
}

func (l simLink) Exchange(m []byte) ([]byte, error) {
	res, b, err := l.d.do(l.kind, m)
	if err == nil && res == 1 {
		err = ErrDongleDropped
	}
	return b, err
}

func rand32(t *testing.T) (k [32]byte) {
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	return
}

func TestDongleP3EndToEnd(t *testing.T) {
	d := startSim(t)
	usb, ble := simLink{d, 'U'}, simLink{d, 'B'}
	hostSK, unlock, seed := rand32(t), rand32(t), rand32(t)

	// Import the existing vault key: delegations made to it stay valid.
	p, err := DonglePair(usb, hostSK, unlock, &seed)
	if err != nil {
		t.Fatal(err)
	}
	want := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	if !bytes.Equal(p.VaultEd, want) {
		t.Fatal("imported vault key: public key differs")
	}
	if _, err := DonglePair(usb, hostSK, unlock, nil); err == nil {
		t.Fatal("second PAIR accepted while paired")
	}

	// The flash record holds neither the seed nor the unlock key.
	_, dump, _ := d.do('F', nil)
	if len(dump) == 0 || bytes.Contains(dump, seed[:]) || bytes.Contains(dump, unlock[:]) || bytes.Contains(dump, hostSK[:]) {
		t.Fatal("flash dump leaks a secret (or is empty)")
	}

	d.do('C', nil)
	s, err := OpenDongleSession(ble, hostSK, p.DongleStatic)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sign([]byte("x")); err == nil {
		t.Fatal("signed while locked")
	}
	if err := s.Unlock(unlock); err != nil {
		t.Fatal(err)
	}
	ed, x, err := s.PubKeys()
	if err != nil || !bytes.Equal(ed, want) || x != p.VaultX {
		t.Fatalf("PUBKEYS: %v", err)
	}

	// A policy-sized message, sent in pieces, verifies like an ssh-ed25519 signature.
	policy := bytes.Repeat([]byte("p3sig policy line\n"), 200)
	sig, err := s.Sign(policy)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(want, policy, sig) {
		t.Fatal("dongle signature does not verify")
	}

	// Unseal gives the sender's per-item secret only.
	eph := rand32(t)
	ephPub, _ := curve25519.X25519(eph[:], curve25519.Basepoint)
	senderShared, _ := curve25519.X25519(eph[:], p.VaultX[:])
	var ep [32]byte
	copy(ep[:], ephPub)
	got, err := s.Unseal(ep)
	if err != nil || !bytes.Equal(got[:], senderShared) {
		t.Fatalf("UNSEAL: %v", err)
	}

	// Lock, then disconnect: the next session must unlock again.
	if err := s.Lock(); err != nil {
		t.Fatal(err)
	}
	d.do('D', nil)
	d.do('C', nil)
	s, err = OpenDongleSession(ble, hostSK, p.DongleStatic)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sign([]byte("x")); err == nil {
		t.Fatal("signed after lock + reconnect without unlocking")
	}
	if err := s.Unlock(rand32(t)); err == nil {
		t.Fatal("wrong unlock key accepted")
	}

	// A host that was not paired cannot complete the handshake.
	d.do('D', nil)
	d.do('C', nil)
	if _, err := OpenDongleSession(ble, rand32(t), p.DongleStatic); err == nil {
		t.Fatal("unpaired host completed the handshake")
	}

	// A tampered message wipes the session and drops the link.
	d.do('D', nil)
	d.do('C', nil)
	s, err = OpenDongleSession(ble, hostSK, p.DongleStatic)
	if err != nil {
		t.Fatal(err)
	}
	m := s.noise.tx.seal(nil, []byte{p3OpLock})
	m[0] ^= 1
	if _, err := ble.Exchange(m); !errors.Is(err, ErrDongleDropped) {
		t.Fatalf("tampered message: want dropped link, got %v", err)
	}

	// UNPAIR needs a button press.
	if err := DongleUnpair(usb); err == nil {
		t.Fatal("UNPAIR without a press")
	}
	d.do('P', nil)
	if err := DongleUnpair(usb); err != nil {
		t.Fatal(err)
	}
}
