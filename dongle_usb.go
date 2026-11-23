// dongle_usb.go — the USB CDC ACM DongleLink for our own dongle firmware
// (task #2628). The firmware (p3sig firmware/dongle/src/main.c) reads frames
// [len 2, big-endian][payload] from its CDC ACM port, hands each one to
// p3p_usb_rx, and always answers with exactly one frame in the same shape.
// A zero-length reply means the dongle refused to parse the request.
//
// Only pairing, INFO and UNPAIR travel over USB; every vault operation goes
// over BLE behind Noise_KK (dongle_p3.go).
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const cdcFrameMax = 256 // USB_FRAME_MAX in the firmware

var ErrDongleNoReply = errors.New("dongle: empty USB reply (request not understood)")

// cdcLink speaks the firmware's length-prefixed frames over any byte stream.
type cdcLink struct {
	rw      io.ReadWriter
	timeout time.Duration
}

func (l *cdcLink) Exchange(msg []byte) ([]byte, error) {
	if len(msg) == 0 || len(msg) > cdcFrameMax {
		return nil, fmt.Errorf("dongle: USB frame of %d bytes (1..%d)", len(msg), cdcFrameMax)
	}
	f := make([]byte, 2+len(msg))
	f[0], f[1] = byte(len(msg)>>8), byte(len(msg))
	copy(f[2:], msg)
	_, err := l.rw.Write(f)
	wipeBytes(f) // PAIR carries the unlock key
	if err != nil {
		return nil, fmt.Errorf("dongle: USB write: %w", err)
	}
	type res struct {
		b   []byte
		err error
	}
	ch := make(chan res, 1)
	go func() {
		var h [2]byte
		if _, err := io.ReadFull(l.rw, h[:]); err != nil {
			ch <- res{nil, err}
			return
		}
		n := int(h[0])<<8 | int(h[1])
		if n > cdcFrameMax {
			ch <- res{nil, fmt.Errorf("dongle: USB reply claims %d bytes", n)}
			return
		}
		b := make([]byte, n)
		_, err := io.ReadFull(l.rw, b)
		ch <- res{b, err}
	}()
	t := l.timeout
	if t == 0 {
		t = 30 * time.Second // UNPAIR waits for a button press
	}
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, fmt.Errorf("dongle: USB read: %w", r.err)
		}
		if len(r.b) == 0 {
			return nil, ErrDongleNoReply
		}
		return r.b, nil
	case <-time.After(t):
		return nil, errors.New("dongle: no USB reply (unplugged, or the button was not pressed in time)")
	}
}

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// findDongleSerial picks the dongle's CDC ACM device. An explicit path wins;
// otherwise the one /dev/serial/by-id entry naming p3sig (our firmware's USB
// product string) or the Makerdiary dongle's serial F43CF22D2ADC.
func findDongleSerial(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	hits := dongleSerialCandidates()
	switch len(hits) {
	case 0:
		return "", errors.New("dongle: no p3sig dongle on USB (plug it in, or pass --usb PATH)")
	case 1:
		return hits[0], nil
	}
	return "", fmt.Errorf("dongle: %d candidate USB devices %v; pass --usb PATH", len(hits), hits)
}

func dongleSerialCandidates() []string {
	var hits []string
	ents, _ := filepath.Glob("/dev/serial/by-id/*")
	for _, e := range ents {
		n := strings.ToLower(filepath.Base(e))
		if strings.Contains(n, "p3sig") || strings.Contains(n, "f43cf22d2adc") {
			hits = append(hits, e)
		}
	}
	if mac, _ := filepath.Glob("/dev/cu.usbmodem*"); len(hits) == 0 && len(mac) == 1 {
		hits = mac
	}
	return hits
}

// udevRuleTTY is shipped in the deb/rpm too (packaging/70-p3sig-fido.rules).
const udevRuleTTY = `SUBSYSTEM=="tty", ATTRS{idVendor}=="2fe3", ATTRS{idProduct}=="0100", ATTRS{product}=="p3sig dongle", GROUP="plugdev", MODE="0660"`

func ttyHint(p string, err error) error {
	if runtime.GOOS != "linux" || !errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("dongle: open %s: %w", p, err)
	}
	return fmt.Errorf("dongle: open %s: %w\n\nThe dongle's USB port is not writable by you. Fix (once, as root):\n"+
		"  echo '%s' >> /etc/udev/rules.d/70-p3sig-fido.rules\n"+
		"  udevadm control --reload && udevadm trigger\n"+
		"  usermod -aG plugdev $USER   # then log in again", p, err, udevRuleTTY)
}

// openCDC opens one port in raw mode.
func openCDC(p string, timeout time.Duration) (*cdcLink, *os.File, error) {
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		return nil, nil, ttyHint(p, err)
	}
	if err := serialRaw(f); err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("dongle: raw mode on %s: %w", p, err)
	}
	return &cdcLink{rw: f, timeout: timeout}, f, nil
}

// probeCDC: the port answers an INFO frame the way our firmware does. The
// first image on the hardware (2026-11-23) also enumerated the board's console
// port (if00 beside the pairing port if02); that one never answers.
func probeCDC(p string) bool {
	l, f, err := openCDC(p, 1500*time.Millisecond)
	if err != nil {
		return false
	}
	defer f.Close()
	r, err := l.Exchange([]byte{p3OpInfo})
	return err == nil && len(r) >= 2 && r[0] == 0
}

// OpenDongleUSB opens the dongle's CDC ACM port in raw mode. With several
// candidate ports (a dongle exposing more than one), the one that answers
// INFO is the pairing port.
func OpenDongleUSB(path string) (DongleLink, io.Closer, error) {
	p, err := findDongleSerial(path)
	if err != nil && path == "" {
		var answering []string
		for _, c := range dongleSerialCandidates() {
			if probeCDC(c) {
				answering = append(answering, c)
			}
		}
		if len(answering) != 1 {
			return nil, nil, err
		}
		p, err = answering[0], nil
	}
	if err != nil {
		return nil, nil, err
	}
	l, f, err := openCDC(p, 0)
	if err != nil {
		return nil, nil, err
	}
	return l, f, nil
}
