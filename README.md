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

Download the binary for your platform from the [latest release](../../releases/latest), then:

```sh
chmod +x p3sig-<os>-<arch> && sudo mv p3sig-<os>-<arch> /usr/local/bin/p3sig
```

(Windows: rename `p3sig-windows-amd64.exe` to `p3sig.exe`.)

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

`--out` defaults to `/etc/p3sig/ssh`. KRL compilation shells out to `ssh-keygen` (already
present wherever OpenSSH is).

## Build

```sh
go build -o p3sig .
# cross-compile, e.g. macOS arm64 / Windows:
CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -o p3sig-darwin-arm64 .
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o p3sig-windows-amd64.exe .
```

Pure Go (no cgo) — the chip-backed client keys (Secure Enclave / TPM, behind Touch ID /
Windows Hello) are a planned per-OS addition that will link the platform keystore.
