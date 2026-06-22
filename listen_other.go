//go:build !windows

package main

// Non-Windows: serve the agent over a unix-domain socket, as OpenSSH expects on
// macOS/Linux. (openKeystore is only implemented on darwin/windows; on other
// platforms `ssh-agent` will fail at openKeystore with "unsupported platform".)

import (
	"fmt"
	"net"
	"os"
)

func listenAgent(bind string) (net.Listener, func(), error) {
	if bind == "" {
		return nil, nil, fmt.Errorf("--bind PATH is required (path for the agent's unix socket)")
	}
	_ = os.Remove(bind) // clear a stale socket from a previous run
	ln, err := net.Listen("unix", bind)
	if err != nil {
		return nil, nil, err
	}
	return ln, func() { ln.Close(); os.Remove(bind) }, nil
}

func agentHint(bind string) string {
	return "point ssh at it:  export SSH_AUTH_SOCK=" + bind
}
