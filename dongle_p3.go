// dongle_p3.go — host side of our own dongle firmware (task #2628, p3sig
// firmware/dongle, design §6 and §9.1). It replaces the OpenSK/FIDO2 dongle.
//
// USB first pairing hands the dongle this host's static Noise key and the
// 256-bit unlock key (which the dongle uses once to seal the vault seed, then
// wipes: 2-of-2). Over BLE every GATT write is one Noise_KK_25519_ChaChaPoly_BLAKE2b
// message with both static keys pinned at pairing; the dongle answers by notify.
// Wire format: firmware/dongle/src/proto.h. The physical links (USB CDC, BLE
// GATT) only have to implement DongleLink; the protocol is tested against the
// firmware's own proto.c through firmware/dongle/tests/host/dongle_sim.
package main

import (
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// DongleLink is one request out, one reply back: a USB CDC frame, or a BLE
// GATT write answered by a notify. ErrDongleDropped means the dongle wiped the
// session and dropped the link.
type DongleLink interface {
	Exchange(msg []byte) ([]byte, error)
}

var ErrDongleDropped = errors.New("dongle: session wiped and link dropped (wrong key or tampered message)")

const (
	p3Prologue = "p3sig-dongle/1"
	p3MaxMsg   = 244 // one BLE write at ATT MTU 247
	p3MaxPlain = p3MaxMsg - 32 - 16
	p3SignMax  = 8192

	p3OpPair, p3OpInfo, p3OpUnpair                          = 0x01, 0x02, 0x03
	p3OpUnlock, p3OpLock, p3OpPubkeys, p3OpSign, p3OpUnseal = 0x10, 0x11, 0x12, 0x13, 0x14
	p3OpRekey                                               = 0x15
	p3StAuth, p3StConfirm                                   = 2, 7
	p3SignFirst, p3SignLast                                 = 0x01, 0x02
)

var p3Status = []string{"ok", "locked", "wrong unlock key or tampered record", "malformed request",
	"too big", "not paired", "already paired (unpair first)", "press the dongle button first",
	"low-order key refused", "flash or RNG failure"}

// p3StatusError is a refusal the dongle answered with (its status byte).
type p3StatusError struct{ st byte }

func (e *p3StatusError) Error() string {
	if int(e.st) < len(p3Status) {
		return "dongle: " + p3Status[e.st]
	}
	return fmt.Sprintf("dongle: status %d", e.st)
}

func p3Err(st byte) error { return &p3StatusError{st} }

// p3IsStatus: err is the dongle refusing with status st.
func p3IsStatus(err error, st byte) bool {
	var se *p3StatusError
	return errors.As(err, &se) && se.st == st
}

// ---- Noise_KK_25519_ChaChaPoly_BLAKE2b, initiator side ----

type noiseCipher struct {
	k   [32]byte
	n   uint64
	has bool
}

func (c *noiseCipher) aead() cipher.AEAD { a, _ := chacha20poly1305.New(c.k[:]); return a }

func (c *noiseCipher) nonce() []byte {
	var n [12]byte
	binary.LittleEndian.PutUint64(n[4:], c.n)
	return n[:]
}

func (c *noiseCipher) seal(ad, p []byte) []byte {
	if !c.has {
		return append([]byte(nil), p...)
	}
	out := c.aead().Seal(nil, c.nonce(), p, ad)
	c.n++
	return out
}

func (c *noiseCipher) open(ad, m []byte) ([]byte, error) {
	if !c.has {
		return append([]byte(nil), m...), nil
	}
	p, err := c.aead().Open(nil, c.nonce(), m, ad)
	if err != nil {
		return nil, errors.New("noise: decrypt failed")
	}
	c.n++
	return p, nil
}

type noiseKK struct {
	ck, h  [64]byte
	cs     noiseCipher
	s, e   [32]byte // our static and ephemeral private keys
	rs     [32]byte // pinned dongle static
	tx, rx noiseCipher
}

func b2() hash.Hash { h, _ := blake2b.New512(nil); return h }

func hkdf2(ck, ikm []byte) (a, b [64]byte) {
	m := hmac.New(b2, ck)
	m.Write(ikm)
	tk := m.Sum(nil)
	m = hmac.New(b2, tk)
	m.Write([]byte{1})
	copy(a[:], m.Sum(nil))
	m = hmac.New(b2, tk)
	m.Write(a[:])
	m.Write([]byte{2})
	copy(b[:], m.Sum(nil))
	return
}

func (n *noiseKK) mixHash(d []byte) {
	h := b2()
	h.Write(n.h[:])
	h.Write(d)
	copy(n.h[:], h.Sum(nil))
}

func (n *noiseKK) mixKey(ikm []byte) {
	ck, k := hkdf2(n.ck[:], ikm)
	n.ck = ck
	copy(n.cs.k[:], k[:32])
	n.cs.n, n.cs.has = 0, true
}

func pubOf(sk [32]byte) []byte { p, _ := curve25519.X25519(sk[:], curve25519.Basepoint); return p }

func newNoiseKK(hostSK, donglePub [32]byte) *noiseKK {
	n := &noiseKK{s: hostSK, rs: donglePub}
	copy(n.h[:], "Noise_KK_25519_ChaChaPoly_BLAKE2b")
	n.ck = n.h
	n.mixHash([]byte(p3Prologue))
	n.mixHash(pubOf(hostSK))
	n.mixHash(donglePub[:])
	return n
}

// msg1: -> e, es, ss (empty payload)
func (n *noiseKK) writeMsg1() ([]byte, error) {
	if _, err := rand.Read(n.e[:]); err != nil {
		return nil, err
	}
	epub := pubOf(n.e)
	n.mixHash(epub)
	es, err := curve25519.X25519(n.e[:], n.rs[:])
	if err != nil {
		return nil, err
	}
	n.mixKey(es)
	ss, err := curve25519.X25519(n.s[:], n.rs[:])
	if err != nil {
		return nil, err
	}
	n.mixKey(ss)
	c := n.cs.seal(n.h[:], nil)
	n.mixHash(c)
	return append(epub, c...), nil
}

// msg2: <- e, ee, se; then split.
func (n *noiseKK) readMsg2(m []byte) error {
	if len(m) < 32+16 {
		return errors.New("noise: short handshake reply")
	}
	re := m[:32]
	n.mixHash(re)
	ee, err := curve25519.X25519(n.e[:], re)
	if err != nil {
		return err
	}
	n.mixKey(ee)
	se, err := curve25519.X25519(n.s[:], re)
	if err != nil {
		return err
	}
	n.mixKey(se)
	if _, err := n.cs.open(n.h[:], m[32:]); err != nil {
		return errors.New("noise: handshake reply did not authenticate — not the paired dongle")
	}
	n.mixHash(m[32:])
	k1, k2 := hkdf2(n.ck[:], nil)
	copy(n.tx.k[:], k1[:32])
	copy(n.rx.k[:], k2[:32])
	n.tx.has, n.rx.has = true, true
	n.e, n.ck, n.cs = [32]byte{}, [64]byte{}, noiseCipher{}
	return nil
}

// ---- USB pairing ----

// DonglePairing is what the host keeps after USB pairing (the unlock key is
// kept apart, by the phone or the vault, never on the dongle).
type DonglePairing struct {
	DongleStatic [32]byte          // pinned Noise static of the dongle
	VaultEd      ed25519.PublicKey // the vault signing key (delegate this)
	VaultX       [32]byte          // the vault X25519 key (secrets seal to it)
	BLE          string            // the address it advertises on (p3Pair fills it)
}

// DongleP3Info asks over USB whether the dongle is paired and, from firmware that
// reports it, the BLE address it advertises on ("AA:BB:CC:DD:EE:FF/random").
func DongleP3Info(usb DongleLink) (paired bool, ble string, err error) {
	r, err := usb.Exchange([]byte{p3OpInfo})
	if err != nil {
		return false, "", err
	}
	if len(r) < 2 || r[0] != 0 {
		if len(r) < 1 {
			return false, "", errors.New("dongle: empty reply")
		}
		return false, "", p3Err(r[0])
	}
	paired = r[1] == 1
	base := 2
	if paired {
		base = 66
	}
	switch len(r) {
	case base:
	case base + 7:
		a := r[base : base+6] // bt_addr_t: little-endian
		ble = fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", a[5], a[4], a[3], a[2], a[1], a[0])
		if r[base+6] == 0 {
			ble += "/public"
		} else {
			ble += "/random"
		}
	default:
		return false, "", fmt.Errorf("dongle: INFO reply is %d bytes", len(r))
	}
	return paired, ble, nil
}

// DonglePair: seed nil = the dongle generates the vault key; otherwise it
// imports that Ed25519 seed (existing delegations and sealed items stay valid).
func DonglePair(usb DongleLink, hostSK, unlock [32]byte, seed *[32]byte) (*DonglePairing, error) {
	req := append([]byte{p3OpPair}, pubOf(hostSK)...)
	req = append(req, unlock[:]...)
	if seed == nil {
		req = append(req, 0)
	} else {
		req = append(append(req, 1), seed[:]...)
	}
	r, err := usb.Exchange(req)
	if err != nil {
		return nil, err
	}
	if len(r) < 1 || r[0] != 0 {
		if len(r) < 1 {
			return nil, errors.New("dongle: empty reply")
		}
		return nil, p3Err(r[0])
	}
	if len(r) != 97 {
		return nil, fmt.Errorf("dongle: PAIR reply is %d bytes, want 97", len(r))
	}
	p := &DonglePairing{VaultEd: ed25519.PublicKey(append([]byte(nil), r[33:65]...))}
	copy(p.DongleStatic[:], r[1:33])
	copy(p.VaultX[:], r[65:97])
	return p, nil
}

// DongleUnpair erases the pairing; the dongle refuses unless its button was
// pressed in the last 10 s.
func DongleUnpair(usb DongleLink) error {
	r, err := usb.Exchange([]byte{p3OpUnpair})
	if err != nil {
		return err
	}
	if len(r) < 1 || r[0] != 0 {
		return p3Err(append(r, 3)[0])
	}
	return nil
}

// ---- BLE session ----

type DongleSession struct {
	link  DongleLink
	noise *noiseKK
}

// OpenDongleSession runs the KK handshake; a dongle that is not the pinned one
// (or a host it was not paired with) fails here.
func OpenDongleSession(ble DongleLink, hostSK, donglePub [32]byte) (*DongleSession, error) {
	n := newNoiseKK(hostSK, donglePub)
	m1, err := n.writeMsg1()
	if err != nil {
		return nil, err
	}
	m2, err := ble.Exchange(m1)
	if err != nil {
		return nil, err
	}
	if err := n.readMsg2(m2); err != nil {
		return nil, err
	}
	return &DongleSession{link: ble, noise: n}, nil
}

func (s *DongleSession) call(req []byte) ([]byte, error) {
	if len(req) > p3MaxPlain {
		return nil, errors.New("dongle: request too big for one message")
	}
	r, err := s.link.Exchange(s.noise.tx.seal(nil, req))
	if err != nil {
		return nil, err
	}
	p, err := s.noise.rx.open(nil, r)
	if err != nil {
		return nil, err
	}
	if len(p) < 1 {
		return nil, errors.New("dongle: empty reply")
	}
	if p[0] != 0 {
		return nil, p3Err(p[0])
	}
	return p[1:], nil
}

func (s *DongleSession) Unlock(key [32]byte) error {
	_, err := s.call(append([]byte{p3OpUnlock}, key[:]...))
	return err
}

func (s *DongleSession) Lock() error { _, err := s.call([]byte{p3OpLock}); return err }

func (s *DongleSession) PubKeys() (ed25519.PublicKey, [32]byte, error) {
	var x [32]byte
	r, err := s.call([]byte{p3OpPubkeys})
	if err != nil {
		return nil, x, err
	}
	if len(r) != 64 {
		return nil, x, errors.New("dongle: malformed PUBKEYS reply")
	}
	copy(x[:], r[32:])
	return ed25519.PublicKey(append([]byte(nil), r[:32]...)), x, nil
}

// Sign is a plain Ed25519 signature over msg (sent in pieces; the dongle
// buffers up to 8 KiB), so it is exactly what an ssh-ed25519 Signer returns.
func (s *DongleSession) Sign(msg []byte) ([]byte, error) {
	if len(msg) > p3SignMax {
		return nil, fmt.Errorf("dongle: %d bytes to sign, the dongle takes at most %d", len(msg), p3SignMax)
	}
	piece := p3MaxPlain - 2
	for off := 0; ; off += piece {
		end := min(off+piece, len(msg))
		var fl byte
		if off == 0 {
			fl |= p3SignFirst
		}
		if end == len(msg) {
			fl |= p3SignLast
		}
		r, err := s.call(append([]byte{p3OpSign, fl}, msg[off:end]...))
		if err != nil {
			return nil, err
		}
		if fl&p3SignLast != 0 {
			if len(r) != ed25519.SignatureSize {
				return nil, errors.New("dongle: malformed signature")
			}
			return r, nil
		}
	}
}

// Rekey (task #2829) re-seals the SAME vault key under newKey and, when
// newHostPub is set, re-pins this host's Noise static key. The dongle needs the
// session UNLOCKed with the current key and a button press in the last 10 s;
// while it answers "press the button", wait(i) is asked whether to try again
// (it prompts and sleeps). The dongle locks itself afterwards: confirm with a
// fresh session + UNLOCK under the new key.
func (s *DongleSession) Rekey(newKey [32]byte, newHostPub []byte, wait func(attempt int) bool) error {
	if newHostPub != nil && len(newHostPub) != 32 {
		return errors.New("dongle: new host key must be 32 bytes")
	}
	req := append(append([]byte{p3OpRekey}, newKey[:]...), newHostPub...)
	defer wipeBytes(req)
	for i := 0; ; i++ {
		_, err := s.call(req)
		if p3IsStatus(err, p3StConfirm) && wait != nil && wait(i) {
			continue
		}
		return err
	}
}

// Unseal returns X25519(vault, item ephemeral): the per-item secret only.
func (s *DongleSession) Unseal(ephPub [32]byte) ([32]byte, error) {
	var out [32]byte
	r, err := s.call(append([]byte{p3OpUnseal}, ephPub[:]...))
	if err != nil {
		return out, err
	}
	if len(r) != 32 {
		return out, errors.New("dongle: malformed UNSEAL reply")
	}
	copy(out[:], r)
	return out, nil
}
