# p3sig agent — context (read this first)

You are working on `p3sig`, the Go agent for [p3sig.com](https://p3sig.com), a
**zero-knowledge** SSH/secret vault. This doc is the shared brief for the
platform-specific TODOs (`TODO-macos.md`, `TODO-windows.md`). Read it, then your
platform's TODO.

## The product in one paragraph

p3sig holds **only public keys** — never a private key. Servers you SSH *to* trust
a **certificate authority** whose private half lives on your USB/token; you log in
with a short-lived **certificate** the CA signs. The login key on each client machine
should live in that machine's **security chip** (Apple Secure Enclave / a TPM),
unlocked by **Touch ID / Windows Hello**, and never leave it. That chip-backed client
key is **what these TODOs build** — it does not exist yet.

## What already works (don't rebuild it)

- **Protocol & server-agent role** — `main.go`. Auth is a stateless signed request:
  `ed25519.Sign(privKey, []byte("<machine_id>|<unix_ts>"))`, base64, posted as
  `machine_id`,`ts`,`signature`. Wire-compatible with the PHP verifier. Commands:
  `keygen`, `agent pull|run|install` (writes `TrustedUserCAKeys` /
  `AuthorizedPrincipalsFile/<user>` / `RevokedKeys`), `secrets pull`, `exec -- CMD`.
- The whole server side is **proven end-to-end** against a live p3sig: a CA cert
  authenticates against real `sshd`; a KRL re-pull makes `sshd` reject the revoked key.
- The zero-knowledge crypto (`openSealedBox`, ed25519→x25519) is done and kept.

## What you are adding: a chip-backed SSH **client** key

A new client surface, on top of a small platform interface. The **only** platform-specific
code is creating and signing with the chip key; everything else (the ssh-agent, the
`setup` command, OpenSSH encoding) is shared and OS-agnostic — put shared code in files
with no build tag, platform code behind `//go:build darwin` / `//go:build windows`.

### The interface to implement (shared contract)

```go
// keystore.go (no build tag) — interface both platforms satisfy.
package main

// Keystore is a chip-backed SSH client identity: a non-extractable key in the
// platform secure hardware, gated by the platform biometric.
type Keystore interface {
	// Create makes a new non-extractable key gated by biometric and returns its
	// OpenSSH public key line ("ecdsa-sha2-nistp256 AAAA... label").
	Create(label string) (sshPublicKey string, err error)
	// PublicKey returns the OpenSSH public key line for an existing key.
	PublicKey(label string) (sshPublicKey string, err error)
	// Sign signs data with the chip key, prompting the biometric. Used by the
	// ssh-agent to answer SSH authentication challenges.
	Sign(label string, data []byte) (signature []byte, err error)
	// Delete removes the key.
	Delete(label string) error
}

// openKeystore returns the platform implementation (build-tag-selected).
func openKeystore() (Keystore, error) // darwin → secureEnclave{}, windows → winHello{}
```

Secure Enclave and most TPM/Hello keys are **ECDSA P-256** (`ecdsa-sha2-nistp256`) —
not Ed25519. That's fine; OpenSSH supports it. Encode the public key and the signature
in OpenSSH ecdsa wire format (`golang.org/x/crypto/ssh` has helpers:
`ssh.NewPublicKey` on a `*ecdsa.PublicKey`, and the agent below handles signature
formatting if you return a raw ECDSA signature — see the TODO for the exact shape).

### The shared glue you also add (no build tag)

1. **`p3sig setup --label NAME`** — `openKeystore().Create(NAME)`, print the OpenSSH
   public key with instructions to register it in p3sig (Machines / SSH Access) or have
   the CA sign it.
2. **`p3sig ssh-agent --bind PATH`** — run an ssh-agent (implement
   `golang.org/x/crypto/ssh/agent.Agent`) backed by the keystore: `List` returns the
   chip public key; `Sign` calls `keystore.Sign` (biometric prompt). The user points
   `SSH_AUTH_SOCK` at PATH and `ssh` "just works", tapping the sensor per connection.
   On Windows, bind a named pipe instead of a unix socket (see TODO-windows).

This keeps `ssh` itself unmodified — the chip key is served through the agent protocol.

## How to test WITHOUT p3sig (fully local)

You don't need a live p3sig to finish your platform work — prove the chip key end to end
against a loopback `sshd`:

```sh
p3sig setup --label test                       # creates the chip key, prints its pubkey
p3sig ssh-agent --bind /tmp/p3sig.sock &        # serve it
export SSH_AUTH_SOCK=/tmp/p3sig.sock

# trust the chip pubkey directly (direct model), then connect:
mkdir -p ~/.ssh-test && p3sig setup --label test | awk '/ecdsa-/{ $1=$1; print }' > ~/.ssh-test/authorized_keys
# (run a throwaway sshd with AuthorizedKeysFile ~/.ssh-test/authorized_keys, or add to a test host)
ssh -o IdentitiesOnly=no test@localhost true    # should prompt Touch ID / Hello, then succeed
```

**Acceptance:** `ssh` authenticates using the chip key, the biometric prompts on each
sign, and the private key is provably non-extractable (no key file on disk; only a handle).
Bonus: it also works through a CA cert — sign the chip pubkey with a test CA
(`ssh-keygen -s ca -I id -n $USER -V +1h chip.pub`) and connect to an sshd with
`TrustedUserCAKeys ca.pub`.

## Conventions

- Pure-Go core stays cgo-free; only your platform file uses cgo / syscalls.
- Build tags: `//go:build darwin` and `//go:build windows`. A `keystore_stub.go` with
  `//go:build !darwin && !windows` should return "unsupported platform" so `go build`
  works everywhere.
- Don't change the wire protocol or the existing commands.
- Commit small, keep `go vet ./...` clean. Update `README.md` command table when done.
