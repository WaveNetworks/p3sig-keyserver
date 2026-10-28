//go:build windows

package main

import "golang.org/x/sys/windows"

// removableMounts: drive letters Windows reports as removable.
func removableMounts() []string {
	var out []string
	for c := 'D'; c <= 'Z'; c++ {
		root := string(c) + `:\`
		p, err := windows.UTF16PtrFromString(root)
		if err == nil && windows.GetDriveType(p) == windows.DRIVE_REMOVABLE {
			out = append(out, root)
		}
	}
	return out
}
