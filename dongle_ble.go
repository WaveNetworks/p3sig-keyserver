// dongle_ble.go — the BLE GATT DongleLink for our own dongle firmware (task
// #2628). The firmware (p3sig firmware/dongle/src/main.c) exposes one primary
// service 7033fa00-5367-4e44-8f6e-676c65000001 with
//
//	…0002  rx: write — each write is ONE Noise message (≤ 244 bytes, ATT MTU 247)
//	…0003  tx: notify — the dongle's reply to that write
//
// and drops the link when it wipes the session (wrong key, tampered message).
//
// This is a minimal ATT client (Bluetooth Core Vol 3 Part F) over the LE
// fixed ATT channel, so it needs no bluetoothd, D-Bus or extra module: MTU
// exchange, service and characteristic discovery, CCCD subscribe, then
// Write Request → Handle Value Notification per Exchange. The transport is a
// packet conn (one ATT PDU per Send/Recv); on Linux that is an L2CAP
// SOCK_SEQPACKET socket on CID 4 (dongle_ble_linux.go). The protocol is tested
// in-process against a fake GATT server that wraps the firmware's own proto.c
// (dongle_ble_test.go), because no CI box has a radio.
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// ATT opcodes used here.
const (
	attErrorRsp      = 0x01
	attMTUReq        = 0x02
	attMTURsp        = 0x03
	attFindInfoReq   = 0x04
	attFindInfoRsp   = 0x05
	attFindByTypeReq = 0x06
	attFindByTypeRsp = 0x07
	attReadByTypeReq = 0x08
	attReadByTypeRsp = 0x09
	attWriteReq      = 0x12
	attWriteRsp      = 0x13
	attNotify        = 0x1B
	attIndicate      = 0x1D
	attConfirm       = 0x1E

	attErrNotFound = 0x0A
	attWantMTU     = 247 // the firmware's CONFIG_BT_L2CAP_TX_MTU; 244-byte writes fit
)

// p3UUID returns the firmware's 128-bit UUID 7033fa00-5367-4e44-8f6e-676c6500000n
// in ATT's little-endian byte order.
func p3UUID(n byte) []byte {
	be := []byte{0x70, 0x33, 0xfa, 0x00, 0x53, 0x67, 0x4e, 0x44, 0x8f, 0x6e, 0x67, 0x6c, 0x65, 0x00, 0x00, n}
	le := make([]byte, 16)
	for i := range be {
		le[i] = be[15-i]
	}
	return le
}

// attConn carries whole ATT PDUs. Recv returns io.EOF (or any error) once the
// link is gone.
type attConn interface {
	Send(pdu []byte) error
	Recv() ([]byte, error)
	Close() error
}

type attErr struct {
	op     byte
	handle uint16
	code   byte
}

func (e *attErr) Error() string {
	return fmt.Sprintf("dongle: ATT error 0x%02x on request 0x%02x (handle 0x%04x)", e.code, e.op, e.handle)
}

// bleLink is a DongleLink over GATT.
type bleLink struct {
	c        attConn
	pdus     chan []byte
	dead     chan struct{}
	deadErr  error
	mtu      int
	rx, tx   uint16 // value handles
	cccd     uint16
	timeout  time.Duration
	notified [][]byte // notifications that arrived before their write's response
}

// newBLELink runs discovery on an open ATT connection and subscribes to tx.
func newBLELink(c attConn, timeout time.Duration) (*bleLink, error) {
	l := &bleLink{c: c, pdus: make(chan []byte, 16), dead: make(chan struct{}), mtu: 23, timeout: timeout}
	go l.reader()
	if err := l.discover(); err != nil {
		c.Close()
		return nil, err
	}
	return l, nil
}

func (l *bleLink) reader() {
	for {
		p, err := l.c.Recv()
		if err != nil {
			l.deadErr = err
			close(l.dead)
			return
		}
		if len(p) == 0 {
			continue
		}
		switch p[0] {
		case attMTUReq: // the dongle may open its own MTU exchange
			_ = l.c.Send([]byte{attMTURsp, attWantMTU & 0xff, attWantMTU >> 8})
			continue
		case attIndicate:
			_ = l.c.Send([]byte{attConfirm})
		}
		l.pdus <- p
	}
}

// next waits for the next PDU that is not an unrelated notification.
func (l *bleLink) next() ([]byte, error) {
	t := time.NewTimer(l.timeout)
	defer t.Stop()
	select {
	case p := <-l.pdus:
		return p, nil
	case <-l.dead:
		select { // drain what arrived before the link went
		case p := <-l.pdus:
			return p, nil
		default:
		}
		return nil, ErrDongleDropped
	case <-t.C:
		return nil, errors.New("dongle: no BLE reply in time")
	}
}

// request sends a request and returns its response (or the ATT error).
// Notifications that arrive meanwhile are kept for Exchange.
func (l *bleLink) request(req []byte, rspOp byte) ([]byte, error) {
	if err := l.c.Send(req); err != nil {
		return nil, fmt.Errorf("dongle: BLE send: %w", err)
	}
	for {
		p, err := l.next()
		if err != nil {
			return nil, err
		}
		switch {
		case p[0] == rspOp:
			return p[1:], nil
		case p[0] == attErrorRsp && len(p) >= 5 && p[1] == req[0]:
			return nil, &attErr{p[1], binary.LittleEndian.Uint16(p[2:4]), p[4]}
		case (p[0] == attNotify || p[0] == attIndicate) && len(p) >= 3:
			l.notified = append(l.notified, p)
		}
	}
}

func le16(v uint16) []byte { return []byte{byte(v), byte(v >> 8)} }

func (l *bleLink) discover() error {
	// MTU: a 244-byte Noise message needs ATT MTU 247.
	r, err := l.request([]byte{attMTUReq, attWantMTU & 0xff, attWantMTU >> 8}, attMTURsp)
	if err != nil {
		return err
	}
	if len(r) < 2 {
		return errors.New("dongle: short MTU response")
	}
	l.mtu = min(int(binary.LittleEndian.Uint16(r)), attWantMTU)
	if l.mtu < p3MaxMsg+3 {
		return fmt.Errorf("dongle: ATT MTU %d is below the %d a Noise message needs", l.mtu, p3MaxMsg+3)
	}

	// The p3sig service's handle range.
	req := append([]byte{attFindByTypeReq}, le16(1)...)
	req = append(req, le16(0xffff)...)
	req = append(req, le16(0x2800)...)
	req = append(req, p3UUID(1)...)
	r, err = l.request(req, attFindByTypeRsp)
	if err != nil {
		var ae *attErr
		if errors.As(err, &ae) && ae.code == attErrNotFound {
			return errors.New("dongle: no p3sig dongle service on that device (wrong address, or not our firmware)")
		}
		return err
	}
	if len(r) < 4 {
		return errors.New("dongle: short service response")
	}
	start, end := binary.LittleEndian.Uint16(r[0:2]), binary.LittleEndian.Uint16(r[2:4])

	// Characteristic declarations in that range: [handle 2][props 1][value handle 2][uuid].
	for h := start; h <= end && h != 0; {
		req := append([]byte{attReadByTypeReq}, le16(h)...)
		req = append(req, le16(end)...)
		req = append(req, le16(0x2803)...)
		r, err := l.request(req, attReadByTypeRsp)
		if err != nil {
			var ae *attErr
			if errors.As(err, &ae) && ae.code == attErrNotFound {
				break
			}
			return err
		}
		if len(r) < 1 || r[0] < 7 {
			return errors.New("dongle: bad characteristic list")
		}
		n := int(r[0])
		last := h
		for i := 1; i+n <= len(r); i += n {
			e := r[i : i+n]
			last = binary.LittleEndian.Uint16(e[0:2])
			vh := binary.LittleEndian.Uint16(e[3:5])
			if n == 21 && bytes.Equal(e[5:21], p3UUID(2)) {
				l.rx = vh
			} else if n == 21 && bytes.Equal(e[5:21], p3UUID(3)) {
				l.tx = vh
			}
		}
		if last >= end {
			break
		}
		h = last + 1
	}
	if l.rx == 0 || l.tx == 0 {
		return errors.New("dongle: p3sig service is missing its rx/tx characteristics")
	}

	// The tx CCCD (0x2902) among the descriptors after the tx value.
	for h := l.tx + 1; h <= end && l.cccd == 0; {
		req := append([]byte{attFindInfoReq}, le16(h)...)
		req = append(req, le16(end)...)
		r, err := l.request(req, attFindInfoRsp)
		if err != nil {
			break
		}
		if len(r) < 1 || r[0] != 1 { // 16-bit UUIDs only; the CCCD is one
			break
		}
		last := h
		for i := 1; i+4 <= len(r); i += 4 {
			last = binary.LittleEndian.Uint16(r[i:])
			if binary.LittleEndian.Uint16(r[i+2:]) == 0x2902 {
				l.cccd = last
				break
			}
			if binary.LittleEndian.Uint16(r[i+2:]) == 0x2803 {
				h = end + 1 // next characteristic: no CCCD for tx
				break
			}
		}
		if last >= end {
			break
		}
		h = max(h, last+1)
	}
	if l.cccd == 0 {
		return errors.New("dongle: tx characteristic has no notify descriptor")
	}
	req = append([]byte{attWriteReq}, le16(l.cccd)...)
	_, err = l.request(append(req, 0x01, 0x00), attWriteRsp)
	return err
}

// Exchange writes one Noise message and returns the notified reply.
func (l *bleLink) Exchange(msg []byte) ([]byte, error) {
	if len(msg) == 0 || len(msg) > l.mtu-3 {
		return nil, fmt.Errorf("dongle: BLE message of %d bytes (1..%d)", len(msg), l.mtu-3)
	}
	l.notified = nil
	req := append([]byte{attWriteReq}, le16(l.rx)...)
	if _, err := l.request(append(req, msg...), attWriteRsp); err != nil {
		return nil, err
	}
	for {
		var p []byte
		if len(l.notified) > 0 {
			p, l.notified = l.notified[0], l.notified[1:]
		} else {
			var err error
			if p, err = l.next(); err != nil {
				return nil, err
			}
		}
		if (p[0] == attNotify || p[0] == attIndicate) && len(p) >= 3 && binary.LittleEndian.Uint16(p[1:3]) == l.tx {
			return append([]byte(nil), p[3:]...), nil
		}
	}
}

func (l *bleLink) Close() error { return l.c.Close() }

// parseBLEAddr reads "AA:BB:CC:DD:EE:FF" with an optional "/public" or
// "/random" suffix (Zephyr's default identity is a static random address).
func parseBLEAddr(s string) (addr [6]byte, random bool, err error) {
	random = true
	if i := strings.IndexByte(s, '/'); i >= 0 {
		switch strings.ToLower(s[i+1:]) {
		case "public":
			random = false
		case "random":
		default:
			return addr, false, fmt.Errorf("dongle: address type %q (public|random)", s[i+1:])
		}
		s = s[:i]
	}
	var b [6]int
	if n, e := fmt.Sscanf(strings.ToUpper(s), "%02X:%02X:%02X:%02X:%02X:%02X", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]); e != nil || n != 6 {
		return addr, false, fmt.Errorf("dongle: BLE address %q (want AA:BB:CC:DD:EE:FF[/public|/random])", s)
	}
	for i := range b {
		addr[i] = byte(b[i])
	}
	return addr, random, nil
}

// OpenDongleBLE connects to the dongle at addr (see parseBLEAddr) and returns
// a DongleLink whose Exchange is one GATT write answered by one notify.
func OpenDongleBLE(addr string) (DongleLink, io.Closer, error) {
	a, random, err := parseBLEAddr(addr)
	if err != nil {
		return nil, nil, err
	}
	c, err := dialATT(a, random, 15*time.Second)
	if err != nil {
		return nil, nil, err
	}
	l, err := newBLELink(c, 30*time.Second)
	if err != nil {
		return nil, nil, err
	}
	return l, l, nil
}
