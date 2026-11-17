//go:build !linux

package main

import (
	"errors"
	"time"
)

func dialATT(addr [6]byte, random bool, timeout time.Duration) (attConn, error) {
	return nil, errors.New("dongle: BLE transport is Linux-only in this build (macOS CoreBluetooth / Windows WinRT not written yet)")
}
