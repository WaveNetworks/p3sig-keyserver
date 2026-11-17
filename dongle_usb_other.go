//go:build !linux && !darwin

package main

import (
	"errors"
	"os"
)

// serialRaw: Windows COM ports need SetCommState; not wired yet (task #2628).
func serialRaw(f *os.File) error {
	return errors.New("USB pairing of the p3sig dongle is supported on Linux and macOS for now")
}
