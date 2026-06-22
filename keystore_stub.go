//go:build !darwin && !windows

package main

import "fmt"

// openKeystore is unimplemented on platforms without a supported secure chip
// backend. The darwin/windows builds replace this with a real implementation.
func openKeystore() (Keystore, error) {
	return nil, fmt.Errorf("chip-backed keystore not implemented on this platform (see docs/TODO-macos.md, docs/TODO-windows.md)")
}
