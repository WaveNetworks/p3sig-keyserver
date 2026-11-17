//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/sys/unix"
)

const (
	btprotoL2CAP   = 0
	l2capCIDATT    = 4
	bdaddrLEPublic = 1
	bdaddrLERandom = 2
)

// l2capATT is the LE fixed ATT channel as a SOCK_SEQPACKET socket: one read is
// one ATT PDU. The kernel does the LE connection; no bluetoothd involved.
type l2capATT struct{ fd int }

func (c *l2capATT) Send(p []byte) error { _, err := unix.Write(c.fd, p); return err }

func (c *l2capATT) Recv() ([]byte, error) {
	b := make([]byte, 512)
	n, err := unix.Read(c.fd, b)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, io.EOF
	}
	return b[:n], nil
}

func (c *l2capATT) Close() error { return unix.Close(c.fd) }

func dialATT(addr [6]byte, random bool, timeout time.Duration) (attConn, error) {
	fd, err := unix.Socket(unix.AF_BLUETOOTH, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, btprotoL2CAP)
	if err != nil {
		return nil, fmt.Errorf("dongle: no Bluetooth socket (%v) — is there an adapter and the bluetooth kernel module?", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrL2{CID: l2capCIDATT, AddrType: bdaddrLEPublic}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("dongle: bind ATT channel: %w", err)
	}
	t := uint8(bdaddrLERandom)
	if !random {
		t = bdaddrLEPublic
	}
	done := make(chan error, 1)
	go func() { done <- unix.Connect(fd, &unix.SockaddrL2{CID: l2capCIDATT, Addr: addr, AddrType: t}) }()
	select {
	case err = <-done:
	case <-time.After(timeout):
		unix.Shutdown(fd, unix.SHUT_RDWR)
		unix.Close(fd)
		return nil, errors.New("dongle: BLE connect timed out — is the dongle paired, powered and advertising?")
	}
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("dongle: BLE connect %X: %w", addr, err)
	}
	return &l2capATT{fd}, nil
}
