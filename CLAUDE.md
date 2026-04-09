# p3sig-agent

Single-binary Go CLI that authenticates a machine identity to P3sig using Ed25519 challenge-response. Two commands: `vault get` (retrieve and locally decrypt an E2E-sealed API key) and `ssh-keys` (fetch authorized_keys for sshd integration).

## Structure

Single-file binary: `main.go`. No subpackages, no frameworks.

## Build

Requires Go 1.21+.

```bash
go build -o p3sig-agent .
```

## Dependencies

| Package | Purpose |
|---------|---------|
| `filippo.io/edwards25519` | Ed25519 to Curve25519 public key conversion |
| `golang.org/x/crypto/nacl/box` | NaCl sealed box decryption (libsodium-compatible) |

Standard library only beyond those two.

## Usage

```
p3sig-agent vault get  --api URL --identity ID --key PATH --label LABEL
p3sig-agent vault get  --api URL --identity ID --key PATH --scope SCOPE
p3sig-agent vault get  --api URL --identity ID --key PATH --vault-id ID
p3sig-agent ssh-keys   --api URL --identity ID --key PATH
```

## How It Works

1. `POST /v1/auth/challenge` with identity ID -- server returns 32-byte hex challenge
2. Agent signs challenge with Ed25519 private key -- server verifies and issues JWT
3. For vault: server returns `sodium_crypto_box_seal` ciphertext; agent converts Ed25519 key to Curve25519, decrypts locally, prints plaintext to stdout
4. For ssh-keys: agent calls `POST /v1/ssh/authorized-keys`, prints OpenSSH keys to stdout

## Security Notes

- Private key is read from disk once, used only for signing and X25519 derivation
- Vault plaintext is printed to stdout, never written to disk
- JWT is held in memory for a single invocation then discarded
- Key files should be `chmod 600` and owned by the sshd user (typically `nobody`)
