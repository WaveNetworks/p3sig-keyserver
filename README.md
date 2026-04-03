# p3sig-agent

A small, dependency-minimal Go binary for machines that need to authenticate with [P3sig](https://p3sig.com).

**Inspect this code.** It handles private keys and decrypts secrets locally — you should verify it does exactly what it says before running it on your servers.

---

## What it does

`p3sig-agent` authenticates a machine identity to P3sig using Ed25519 challenge-response, then either:

- **`vault get`** — retrieves an encrypted API key from the P3sig vault and decrypts it locally (the server never sees the plaintext)
- **`ssh-keys`** — fetches the `authorized_keys` list for this machine identity, for use with sshd's `AuthorizedKeysCommand`

No secrets are sent to the server. The private key stays on disk. The vault key is decrypted in memory and printed to stdout.

---

## How it works

### Authentication

1. Agent calls `POST /v1/auth/challenge` with its identity ID
2. Server returns a random 32-byte hex challenge (valid 30 seconds, single-use)
3. Agent signs the raw challenge bytes with its Ed25519 private key
4. Server verifies the signature against the registered public key → issues a short-lived JWT

### E2E vault decryption

When a vault entry has an E2E copy, the server returns a `sodium_crypto_box_seal` ciphertext sealed to the identity's public key. The agent:

1. Converts the Ed25519 key pair to Curve25519 (X25519) via the standard birational map
2. Opens the sealed box with `nacl/box.OpenAnonymous` (wire-compatible with libsodium)
3. Prints the plaintext API key to stdout — the server never held the decryption key

### SSH authorized_keys

Agent authenticates, calls `POST /v1/ssh/authorized-keys`, and prints the OpenSSH-format public keys for this machine identity to stdout. Pair with sshd's `AuthorizedKeysCommand` to pull access keys centrally without editing files on each machine.

---

## Usage

```
p3sig-agent vault get  --api URL --identity ID --key PATH --label LABEL
p3sig-agent vault get  --api URL --identity ID --key PATH --scope SCOPE
p3sig-agent vault get  --api URL --identity ID --key PATH --vault-id ID
p3sig-agent ssh-keys   --api URL --identity ID --key PATH
```

**Flags:**

| Flag | Description |
|------|-------------|
| `--api` | P3sig API URL, e.g. `https://p3sig.com/p3sig/api/index.php` |
| `--identity` | Your P3sig identity ID (shown in the dashboard) |
| `--key` | Path to your Ed25519 private key PEM (PKCS#8) |
| `--label` | Vault entry label (for `vault get`) |
| `--scope` | Vault scope pattern (for `vault get`) |
| `--vault-id` | Vault entry ID (for `vault get`) |

---

## Key generation

```bash
# Generate private key
openssl genpkey -algorithm ed25519 -out /etc/p3sig/identity.pem

# Show public key to paste into P3sig dashboard
openssl pkey -in /etc/p3sig/identity.pem -pubout
```

Protect the private key file:

```bash
chmod 600 /etc/p3sig/identity.pem
chown nobody:nobody /etc/p3sig/identity.pem   # match AuthorizedKeysCommandUser
```

---

## SSH setup (sshd)

Add to `/etc/ssh/sshd_config`:

```
AuthorizedKeysCommand /usr/local/bin/p3sig-agent ssh-keys \
    --api https://p3sig.com/p3sig/api/index.php \
    --identity <your-identity-id> \
    --key /etc/p3sig/identity.pem
AuthorizedKeysCommandUser nobody
```

Then restart sshd:

```bash
systemctl restart sshd
```

Manage which SSH public keys have access to this machine from the P3sig dashboard — no more editing `authorized_keys` files by hand.

---

## Build

Requires Go 1.21+.

```bash
go mod tidy
go build -o p3sig-agent .

# Cross-compile for Linux
GOOS=linux GOARCH=amd64 go build -o p3sig-agent-linux-amd64 .
GOOS=linux GOARCH=arm64 go build -o p3sig-agent-linux-arm64 .
```

---

## Dependencies

| Package | Purpose |
|---------|---------|
| [`filippo.io/edwards25519`](https://pkg.go.dev/filippo.io/edwards25519) | Ed25519 → Curve25519 public key conversion |
| [`golang.org/x/crypto/nacl/box`](https://pkg.go.dev/golang.org/x/crypto/nacl/box) | NaCl sealed box decryption (libsodium-compatible) |

Standard library only beyond those two. No network clients, no config parsers, no frameworks.

---

## Security notes

- The private key is read from disk once at startup and used only to sign the challenge and derive the X25519 decryption key
- Vault plaintext is printed to stdout and never written to disk by this binary
- The JWT is held in memory for the duration of a single invocation and then discarded
- If the P3sig server is compromised, it can return a crafted ciphertext — but it still cannot decrypt vault entries sealed with your key
- Revoke the identity in the P3sig dashboard to immediately cut off all access

---

## License

MIT
