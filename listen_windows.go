//go:build windows

package main

// Windows OpenSSH talks to its agent over a named pipe, not a unix socket.
// ssh.exe connects to \\.\pipe\openssh-ssh-agent by default; bind that exact
// pipe (after stopping the built-in ssh-agent service) so `ssh` "just works",
// or bind a custom pipe and point SSH_AUTH_SOCK at it.

import (
	"fmt"
	"net"

	"github.com/Microsoft/go-winio"
)

const defaultAgentPipe = `\\.\pipe\openssh-ssh-agent`

func listenAgent(bind string) (net.Listener, func(), error) {
	if bind == "" {
		bind = defaultAgentPipe
	}
	ln, err := winio.ListenPipe(bind, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("listen on named pipe %s: %w (is the Windows ssh-agent service holding it? `Stop-Service ssh-agent`)", bind, err)
	}
	return ln, func() { ln.Close() }, nil
}

func agentHint(bind string) string {
	if bind == "" || bind == defaultAgentPipe {
		return "ssh.exe uses this pipe by default — just run ssh (stop the ssh-agent service first if it owns the pipe)"
	}
	return "point ssh at it:  $env:SSH_AUTH_SOCK = '" + bind + "'"
}
