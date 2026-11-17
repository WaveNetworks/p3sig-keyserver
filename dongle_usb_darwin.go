//go:build darwin

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// serialRaw puts a CDC ACM tty in raw 8N1 mode (no echo, no line discipline);
// the baud rate is meaningless on USB CDC.
func serialRaw(f *os.File) error {
	fd := int(f.Fd())
	t, err := unix.IoctlGetTermios(fd, unix.TIOCGETA)
	if err != nil {
		return err
	}
	t.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	t.Oflag &^= unix.OPOST
	t.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	t.Cflag &^= unix.CSIZE | unix.PARENB
	t.Cflag |= unix.CS8 | unix.CLOCAL | unix.CREAD
	t.Cc[unix.VMIN], t.Cc[unix.VTIME] = 1, 0
	return unix.IoctlSetTermios(fd, unix.TIOCSETA, t)
}
