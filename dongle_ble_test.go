package main

// The BLE GATT DongleLink (task #2628) against a fake GATT server laid out like
// the firmware's BT_GATT_SERVICE_DEFINE (a GAP service first, then the p3sig
// service: decl, rx decl, rx value, tx decl, tx value, CCCD). The always-run
// tests use an echo backend; with P3SIG_DONGLE_SIM set the backend is the
// firmware's own proto.c, so pairing (USB) → Noise_KK session → sign/unseal all
// travel over real ATT PDUs.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
)

type pipeATT struct {
	in, out chan []byte
	closed  chan struct{}
}

func (p *pipeATT) Send(b []byte) error {
	select {
	case p.out <- append([]byte(nil), b...):
		return nil
	case <-p.closed:
		return io.EOF
	}
}

func (p *pipeATT) Recv() ([]byte, error) {
	select {
	case b := <-p.in:
		return b, nil
	case <-p.closed:
		return nil, io.EOF
	}
}

func (p *pipeATT) Close() error {
	select {
	case <-p.closed:
	default:
		close(p.closed)
	}
	return nil
}

// fakeGATT serves the firmware's attribute table; backend answers rx writes.
// notifyFirst sends the notification before the write response (allowed by
// ATT ordering on a real link because the firmware replies from a work queue).
func fakeGATT(t *testing.T, backend DongleLink, notifyFirst bool) attConn {
	closed := make(chan struct{})
	cli := &pipeATT{in: make(chan []byte, 8), out: make(chan []byte, 8), closed: closed}
	srv := &pipeATT{in: cli.out, out: cli.in, closed: closed}
	const svc, rxDecl, rxVal, txDecl, txVal, cccd, end = 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x15
	errRsp := func(op byte, h uint16) []byte { return []byte{attErrorRsp, op, byte(h), byte(h >> 8), attErrNotFound} }
	chr := func(decl uint16, props byte, val uint16, n byte) []byte {
		e := append(le16(decl), props)
		e = append(e, le16(val)...)
		return append(e, p3UUID(n)...)
	}
	go func() {
		defer srv.Close()
		subscribed := false
		for {
			p, err := srv.Recv()
			if err != nil {
				return
			}
			switch p[0] {
			case attMTUReq:
				srv.Send([]byte{attMTURsp, 247, 0})
			case attFindByTypeReq:
				if binary.LittleEndian.Uint16(p[1:]) <= svc && bytes.Equal(p[7:], p3UUID(1)) {
					srv.Send(append(append([]byte{attFindByTypeRsp}, le16(svc)...), le16(end)...))
				} else {
					srv.Send(errRsp(p[0], 1))
				}
			case attReadByTypeReq:
				s := binary.LittleEndian.Uint16(p[1:])
				var r []byte
				if s <= rxDecl {
					r = append(r, chr(rxDecl, 0x0c, rxVal, 2)...)
				}
				if s <= txDecl {
					r = append(r, chr(txDecl, 0x10, txVal, 3)...)
				}
				if r == nil {
					srv.Send(errRsp(p[0], s))
				} else {
					srv.Send(append([]byte{attReadByTypeRsp, 21}, r...))
				}
			case attFindInfoReq:
				s := binary.LittleEndian.Uint16(p[1:])
				if s <= cccd {
					srv.Send(append(append([]byte{attFindInfoRsp, 1}, le16(cccd)...), 0x02, 0x29))
				} else {
					srv.Send(errRsp(p[0], s))
				}
			case attWriteReq:
				h := binary.LittleEndian.Uint16(p[1:])
				switch {
				case h == cccd:
					subscribed = p[3] == 1
					srv.Send([]byte{attWriteRsp})
				case h == rxVal && subscribed:
					reply, err := backend.Exchange(p[3:])
					if errors.Is(err, ErrDongleDropped) {
						return // the dongle drops the link
					}
					if err != nil {
						t.Errorf("backend: %v", err)
						return
					}
					n := append(append([]byte{attNotify}, le16(txVal)...), reply...)
					if notifyFirst {
						srv.Send(n)
						srv.Send([]byte{attWriteRsp})
					} else {
						srv.Send([]byte{attWriteRsp})
						srv.Send(n)
					}
				default:
					srv.Send([]byte{attErrorRsp, p[0], p[1], p[2], 0x03})
				}
			}
		}
	}()
	return cli
}

type echoLink struct{ drop bool }

func (e echoLink) Exchange(m []byte) ([]byte, error) {
	if e.drop {
		return nil, ErrDongleDropped
	}
	return append([]byte("re:"), m...), nil
}

func TestDongleBLEDiscoveryAndExchange(t *testing.T) {
	for _, nf := range []bool{false, true} {
		l, err := newBLELink(fakeGATT(t, echoLink{}, nf), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if l.rx != 0x12 || l.tx != 0x14 || l.cccd != 0x15 || l.mtu != 247 {
			t.Fatalf("discovery: rx %x tx %x cccd %x mtu %d", l.rx, l.tx, l.cccd, l.mtu)
		}
		msg := bytes.Repeat([]byte{7}, p3MaxMsg)
		r, err := l.Exchange(msg)
		if err != nil || !bytes.Equal(r, append([]byte("re:"), msg...)) {
			t.Fatalf("exchange (notifyFirst=%v): %v", nf, err)
		}
		if _, err := l.Exchange(make([]byte, p3MaxMsg+1)); err == nil {
			t.Fatal("over-MTU write accepted")
		}
		l.Close()
	}
}

func TestDongleBLEDropped(t *testing.T) {
	l, err := newBLELink(fakeGATT(t, echoLink{drop: true}, false), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Exchange([]byte{1}); !errors.Is(err, ErrDongleDropped) {
		t.Fatalf("want ErrDongleDropped, got %v", err)
	}
}

func TestParseBLEAddr(t *testing.T) {
	a, r, err := parseBLEAddr("c0:01:02:03:04:0f")
	if err != nil || !r || a != [6]byte{0xc0, 1, 2, 3, 4, 0x0f} {
		t.Fatal(a, r, err)
	}
	if _, r, err := parseBLEAddr("C0:01:02:03:04:0F/public"); err != nil || r {
		t.Fatal(r, err)
	}
	for _, bad := range []string{"", "C0:01:02:03:04", "C0:01:02:03:04:0F/x", "zz:01:02:03:04:0F"} {
		if _, _, err := parseBLEAddr(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

// The firmware's proto.c behind real ATT PDUs: pair over USB, then the whole
// Noise_KK session over GATT.
func TestDongleBLEWithFirmwareProto(t *testing.T) {
	d := startSim(t)
	usb := simLink{d, 'U'}
	hostSK, unlock := rand32(t), rand32(t)
	p, err := DonglePair(usb, hostSK, unlock, nil)
	if err != nil {
		t.Fatal(err)
	}
	d.do('C', nil)
	l, err := newBLELink(fakeGATT(t, simLink{d, 'B'}, true), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	s, err := OpenDongleSession(l, hostSK, p.DongleStatic)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Unlock(unlock); err != nil {
		t.Fatal(err)
	}
	policy := bytes.Repeat([]byte("p3sig policy over BLE\n"), 150)
	sig, err := s.Sign(policy)
	if err != nil || !ed25519.Verify(p.VaultEd, policy, sig) {
		t.Fatalf("sign over GATT: %v", err)
	}
	eph := rand32(t)
	ephPub, _ := curve25519.X25519(eph[:], curve25519.Basepoint)
	want, _ := curve25519.X25519(eph[:], p.VaultX[:])
	var ep [32]byte
	copy(ep[:], ephPub)
	got, err := s.Unseal(ep)
	if err != nil || !bytes.Equal(got[:], want) {
		t.Fatalf("unseal over GATT: %v", err)
	}
	l.Close()
}
