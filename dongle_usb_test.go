package main

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// fakeCDC plays the firmware's side of the frame protocol (main.c cdc_isr +
// usb_work_fn): read [len2][payload], answer one [len2][payload] frame.
func fakeCDC(t *testing.T, c net.Conn, reply func([]byte) []byte) {
	go func() {
		for {
			var h [2]byte
			if _, err := io.ReadFull(c, h[:]); err != nil {
				return
			}
			b := make([]byte, int(h[0])<<8|int(h[1]))
			if _, err := io.ReadFull(c, b); err != nil {
				return
			}
			r := reply(b)
			if r == nil {
				return // never answers
			}
			c.Write(append([]byte{byte(len(r) >> 8), byte(len(r))}, r...))
		}
	}()
}

func TestCDCLinkFrames(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	fakeCDC(t, b, func(req []byte) []byte {
		if req[0] == 0x02 { // INFO
			return append([]byte{0}, bytes.Repeat([]byte{7}, 200)...)
		}
		return []byte{} // malformed: firmware answers with an empty frame
	})
	l := &cdcLink{rw: a, timeout: 2 * time.Second}
	r, err := l.Exchange([]byte{0x02})
	if err != nil || len(r) != 201 || r[0] != 0 || r[200] != 7 {
		t.Fatalf("INFO: %v len=%d", err, len(r))
	}
	if _, err := l.Exchange([]byte{0x7f}); !errors.Is(err, ErrDongleNoReply) {
		t.Fatalf("empty reply: %v", err)
	}
	if _, err := l.Exchange(make([]byte, cdcFrameMax+1)); err == nil {
		t.Fatal("oversize frame accepted")
	}
	if _, err := l.Exchange(nil); err == nil {
		t.Fatal("empty frame accepted")
	}
}

func TestCDCLinkTimeout(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	fakeCDC(t, b, func([]byte) []byte { return nil })
	l := &cdcLink{rw: a, timeout: 200 * time.Millisecond}
	if _, err := l.Exchange([]byte{0x03}); err == nil {
		t.Fatal("no reply should time out")
	}
}

func TestFindDongleSerialExplicit(t *testing.T) {
	if p, err := findDongleSerial("/dev/ttyACM9"); err != nil || p != "/dev/ttyACM9" {
		t.Fatal(p, err)
	}
}
