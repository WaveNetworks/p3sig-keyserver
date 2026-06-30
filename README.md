# p3sig agent

One Go binary, two roles, for [p3sig.com](https://p3sig.com) (zero-knowledge vault + SSH certificate authority).

**Inspect this code.** It handles private keys and decrypts secrets locally — verify it does exactly what it says before running it on your servers.

- **On a server** you SSH *to* / that needs secrets: materialize the sshd trust files
  (`TrustedUserCAKeys`, `AuthorizedPrincipalsFile`, `RevokedKeys`) and inject sealed secrets.
- **Identity:** every machine has an Ed25519 keypair; p3sig holds only the public half.
  Auth is a stateless **signed request** — an Ed25519 signature over `"<machine_id>|<unix_ts>"`.
  No challenge round-trip, no token. Everything pulled is either public (CA keys, principals,
  KRL) or sealed ciphertext opened locally, so the transport carries nothing secret.

## Install

**macOS** (Homebrew — signed, notarized Secure Enclave build):
```sh
brew install --cask WaveNetworks/tap/p3sig
```

**Linux** (one-liner, or apt/dnf packages from the [release](../../releases/latest)):
```sh
curl -fsSL https://raw.githubusercontent.com/WaveNetworks/p3sig-keyserver/main/install.sh | sh
```

**Windows**:
```powershell
scoop bucket add p3sig https://github.com/WaveNetworks/scoop-bucket; scoop install p3sig
# or
winget install WaveNetworks.p3sig
```

**Arch:** `yay -S p3sig-bin`

Or grab the binary for your platform from the [latest release](../../releases/latest) and put it on your PATH manually. Release automation (GoReleaser + signed macOS CI) is documented in [docs/PACKAGING.md](docs/PACKAGING.md).

## Quick start (a server that trusts p3sig-issued certificates)

```sh
# 1. give this machine an identity, register the printed PUBLIC key in p3sig (Machines)
p3sig keygen --out /etc/p3sig/machine.key

# 2. pull the trust files
p3sig agent pull --url https://p3sig.com/p3sig/api/index.php \
                 --machine <machine-id> --key /etc/p3sig/machine.key --out /etc/p3sig/ssh

# 3. wire sshd (prints the lines), then reload sshd
p3sig agent install --out /etc/p3sig/ssh
```

Keep the files fresh with `p3sig agent run … --interval 300` (a systemd service/timer).

## Commands

| Command | Purpose |
|---|---|
| `p3sig keygen [--out FILE]` | Generate the machine identity; print the public key to register |
| `p3sig agent pull --url --machine --key [--out]` | Write `TrustedUserCAKeys` / `AuthorizedPrincipalsFile/<user>` / `RevokedKeys` |
| `p3sig agent run … [--interval SEC]` | Loop `pull` (default 300s) |
| `p3sig agent install [--out]` | Print the `sshd_config` lines |
| `p3sig secrets pull --url --machine --key [--bundle]` | Unseal granted secrets → `KEY=VALUE` |
| `p3sig exec … -- CMD [args]` | Inject those secrets into `CMD`'s environment and run it |
| `p3sig setup [--label NAME] [--show] [--delete]` | Create/show/delete a chip-backed SSH **client** key; print its OpenSSH public key |
| `p3sig ssh-agent [--label NAME] [--bind PATH]` | Run an ssh-agent serving the chip key (biometric prompt per signature) |

`--out` defaults to `/etc/p3sig/ssh`. KRL compilation shells out to `ssh-keygen` (already
present wherever OpenSSH is).

### Chip-backed client key (Secure Enclave / TPM)

`setup` and `ssh-agent` give this machine a **non-extractable** SSH client identity: an
ECDSA P-256 key in the platform secure hardware (Apple Secure Enclave / a TPM), gated by
the platform biometric (Touch ID / Windows Hello). The private key never leaves the chip —
`ssh` authenticates by asking the agent to sign, which prompts the biometric each time.

```sh
p3sig setup --label work                 # creates the chip key, prints its ecdsa pubkey
# register that pubkey in p3sig (Machines / SSH Access) or have your CA sign it, then:
p3sig ssh-agent --label work             # serve it
```

- **macOS/Linux:** `--bind /tmp/p3sig.sock`, then `export SSH_AUTH_SOCK=/tmp/p3sig.sock`.
- **Windows:** binds the named pipe `\\.\pipe\openssh-ssh-agent` by default (stop the
  built-in `ssh-agent` service first, or `--bind \\.\pipe\NAME` and set `$env:SSH_AUTH_SOCK`).
  The key is TPM-resident via the Microsoft Platform Crypto Provider (software-KSP fallback,
  with a warning, if no usable TPM).

Implemented today: **Windows** (CNG/TPM + Windows Hello). macOS Secure Enclave is the
remaining platform (`docs/TODO-macos.md`); the agent already normalizes its DER signatures.

## Build

```sh
go build -o p3sig .
# cross-compile, e.g. macOS arm64 / Windows:
CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -o p3sig-darwin-arm64 .
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o p3sig-windows-amd64.exe .
```

Pure Go (no cgo): the server role is cgo-free, and the Windows chip key reaches CNG/TPM
through `golang.org/x/sys/windows` lazy-loaded `ncrypt.dll` procs — so all targets build
without a C toolchain. The macOS Secure Enclave backend (when added) will need cgo and a
`darwin` build. Platform code is behind `//go:build darwin` / `//go:build windows`;
`keystore_stub.go` keeps `go build` working everywhere else.
