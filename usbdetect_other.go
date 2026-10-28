//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// removableMounts: mounted removable drives. Linux: /proc/mounts entries on a
// block device whose /sys entry is removable or sits on USB. macOS: /Volumes/*
// except the boot volume.
func removableMounts() []string {
	var out []string
	if runtime.GOOS == "darwin" {
		ents, _ := os.ReadDir("/Volumes")
		for _, e := range ents {
			p := filepath.Join("/Volumes", e.Name())
			if t, err := filepath.EvalSymlinks(p); err == nil && t == "/" {
				continue
			}
			out = append(out, p)
		}
		return out
	}
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || !strings.HasPrefix(f[0], "/dev/sd") {
			continue
		}
		disk := strings.TrimRight(strings.TrimPrefix(f[0], "/dev/"), "0123456789")
		rem, _ := os.ReadFile("/sys/block/" + disk + "/removable")
		link, _ := filepath.EvalSymlinks("/sys/block/" + disk)
		if strings.TrimSpace(string(rem)) == "1" || strings.Contains(link, "/usb") {
			out = append(out, strings.ReplaceAll(f[1], `\040`, " "))
		}
	}
	return out
}
