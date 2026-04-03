// p3sig-agent — P3sig identity agent
//
// Authenticates a machine identity to p3sig.com using Ed25519 challenge-response,
// then either retrieves a vault API key (decrypting E2E sealed boxes locally)
// or fetches SSH authorized_keys for the machine.
//
// Usage:
//
//	p3sig-agent vault get  --api URL --identity ID --key PATH --label LABEL
//	p3sig-agent vault get  --api URL --identity ID --key PATH --scope SCOPE
//	p3sig-agent vault get  --api URL --identity ID --key PATH --vault-id ID
//	p3sig-agent ssh-keys   --api URL --identity ID --key PATH
//
// Flags:
//
//	--api          P3sig API base URL (e.g. https://p3sig.com/p3sig/api/index.php)
//	--identity     P3sig identity ID
//	--key          Path to Ed25519 private key PEM (PKCS#8, from openssl genpkey)
//	--label        Vault entry label (for vault get)
//	--scope        Vault scope pattern (for vault get)
//	--vault-id     Vault entry ID (for vault get)
//
// Key generation:
//
//	openssl genpkey -algorithm ed25519 -out /etc/p3sig/identity.pem
//	openssl pkey -in /etc/p3sig/identity.pem -pubout   # shows public key to register in p3sig
//
// sshd integration (put in /etc/ssh/sshd_config):
//
//	AuthorizedKeysCommand /usr/local/bin/p3sig-agent ssh-keys --api URL --identity ID --key /etc/p3sig/identity.pem
//	AuthorizedKeysCommandUser nobody

package main

import (
	"crypto/ed25519"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/nacl/box"
)

// ─── Types ────────────────────────────────────────────────────────────────────

type apiResponse struct {
	Error   string          `json:"error"`
	Success string          `json:"success"`
	Info    string          `json:"info"`
	Warning string          `json:"warning"`
	Results json.RawMessage `json:"results"`
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	if cmd == "-h" || cmd == "--help" || cmd == "help" {
		usage()
		os.Exit(0)
	}

	flags := parseFlags(os.Args[2:])

	apiBase     := flags["api"]
	identityID  := flags["identity"]
	keyPath     := flags["key"]

	if apiBase == "" || identityID == "" || keyPath == "" {
		fmt.Fprintln(os.Stderr, "error: --api, --identity, and --key are required")
		os.Exit(1)
	}

	privKey, err := loadEd25519Key(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading key: %v\n", err)
		os.Exit(1)
	}

	token, err := authenticate(apiBase, identityID, privKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "authentication failed: %v\n", err)
		os.Exit(1)
	}

	switch cmd {
	case "vault":
		if len(os.Args) < 3 || os.Args[2] != "get" {
			fmt.Fprintln(os.Stderr, "usage: p3sig-agent vault get [--label LABEL | --scope SCOPE | --vault-id ID]")
			os.Exit(1)
		}
		err = cmdVaultGet(apiBase, identityID, token, privKey, flags["vault-id"], flags["label"], flags["scope"])

	case "ssh-keys":
		err = cmdSSHKeys(apiBase, token)

	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		usage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// ─── Commands ─────────────────────────────────────────────────────────────────

// cmdVaultGet authenticates, retrieves the vault entry, decrypts if E2E, and
// prints the plaintext API key to stdout.
func cmdVaultGet(apiBase, identityID, token string, privKey ed25519.PrivateKey, vaultID, label, scope string) error {
	params := url.Values{}
	switch {
	case vaultID != "":
		params.Set("vault_id", vaultID)
	case label != "":
		params.Set("label", label)
		params.Set("identity_id", identityID)
	case scope != "":
		params.Set("scope", scope)
	default:
		return fmt.Errorf("provide --vault-id, --label, or --scope")
	}

	resp, err := apiPost(apiBase, "retrieveKey", params, token)
	if err != nil {
		return err
	}

	var result struct {
		APIKey       string `json:"api_key"`
		EncryptedKey string `json:"encrypted_key"`
		E2E          bool   `json:"e2e"`
	}
	if err := json.Unmarshal(resp.Results, &result); err != nil {
		return fmt.Errorf("parse result: %w", err)
	}

	if result.E2E {
		// Decrypt sealed box locally — server never had the plaintext
		plaintext, err := openSealedBox(result.EncryptedKey, privKey)
		if err != nil {
			return fmt.Errorf("decrypt: %w", err)
		}
		fmt.Print(plaintext)
	} else {
		// Legacy: server decrypted — no E2E copy exists yet for this entry
		fmt.Print(result.APIKey)
	}

	return nil
}

// cmdSSHKeys authenticates, fetches the authorized_keys list for this machine
// identity, and prints it to stdout (for use with sshd AuthorizedKeysCommand).
func cmdSSHKeys(apiBase, token string) error {
	resp, err := apiPost(apiBase, "getAuthorizedKeys", url.Values{}, token)
	if err != nil {
		return err
	}

	var result struct {
		AuthorizedKeys string `json:"authorized_keys"`
		Count          int    `json:"count"`
	}
	if err := json.Unmarshal(resp.Results, &result); err != nil {
		return fmt.Errorf("parse result: %w", err)
	}

	if result.AuthorizedKeys != "" {
		fmt.Println(result.AuthorizedKeys)
	}
	return nil
}

// ─── Authentication ───────────────────────────────────────────────────────────

func authenticate(apiBase, identityID string, privKey ed25519.PrivateKey) (string, error) {
	// 1. Request challenge
	resp, err := apiPost(apiBase, "requestChallenge", url.Values{"identity_id": {identityID}}, "")
	if err != nil {
		return "", fmt.Errorf("challenge request: %w", err)
	}

	var challengeResult struct {
		ChallengeID  string `json:"challenge_id"`
		ChallengeHex string `json:"challenge_hex"`
	}
	if err := json.Unmarshal(resp.Results, &challengeResult); err != nil {
		return "", fmt.Errorf("parse challenge: %w", err)
	}

	// 2. Sign the challenge bytes with Ed25519 private key
	challengeBytes, err := hex.DecodeString(challengeResult.ChallengeHex)
	if err != nil {
		return "", fmt.Errorf("decode challenge hex: %w", err)
	}

	sig    := ed25519.Sign(privKey, challengeBytes)
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	// 3. Submit signature → receive JWT
	resp, err = apiPost(apiBase, "verifyChallenge", url.Values{
		"identity_id":  {identityID},
		"challenge_id": {challengeResult.ChallengeID},
		"signature":    {sigB64},
	}, "")
	if err != nil {
		return "", fmt.Errorf("verify challenge: %w", err)
	}

	var verifyResult struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(resp.Results, &verifyResult); err != nil {
		return "", fmt.Errorf("parse token: %w", err)
	}

	if verifyResult.Token == "" {
		return "", fmt.Errorf("empty token in response")
	}

	return verifyResult.Token, nil
}

// ─── Cryptography ─────────────────────────────────────────────────────────────

// openSealedBox decrypts a base64-encoded sodium_crypto_box_seal ciphertext
// using the Ed25519 private key (converted to X25519/Curve25519).
// Wire-compatible with PHP's sodium_crypto_box_seal / sodium_crypto_box_seal_open.
func openSealedBox(encryptedB64 string, edPriv ed25519.PrivateKey) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedB64)
	if err != nil {
		return "", fmt.Errorf("invalid base64: %w", err)
	}

	edPub := edPriv.Public().(ed25519.PublicKey)

	x25519Pub, err := ed25519PubToX25519(edPub)
	if err != nil {
		return "", fmt.Errorf("public key conversion: %w", err)
	}

	x25519Priv := ed25519PrivToX25519(edPriv)

	plaintext, ok := box.OpenAnonymous(nil, ciphertext, x25519Pub, x25519Priv)
	if !ok {
		return "", fmt.Errorf("decryption failed — wrong key or corrupted ciphertext")
	}

	return string(plaintext), nil
}

// ed25519PubToX25519 converts an Ed25519 public key to a Curve25519 (X25519)
// public key via the birational map between Edwards25519 and Curve25519.
// Compatible with sodium_crypto_sign_ed25519_pk_to_curve25519.
func ed25519PubToX25519(edPub ed25519.PublicKey) (*[32]byte, error) {
	p, err := new(edwardsPoint).SetBytes([]byte(edPub))
	if err != nil {
		return nil, fmt.Errorf("invalid Ed25519 public key: %w", err)
	}
	mont := p.BytesMontgomery()
	var out [32]byte
	copy(out[:], mont)
	return &out, nil
}

// edwardsPoint is an alias to avoid import collision in the function body.
type edwardsPoint = edwards25519.Point

// ed25519PrivToX25519 converts an Ed25519 private key to a Curve25519 (X25519)
// scalar via SHA-512 and bit clamping.
// Compatible with sodium_crypto_sign_ed25519_sk_to_curve25519.
func ed25519PrivToX25519(edPriv ed25519.PrivateKey) *[32]byte {
	// Ed25519 private key = seed (32 bytes) || public key (32 bytes)
	// X25519 scalar = SHA-512(seed)[0:32] with clamping
	h := sha512.Sum512(edPriv.Seed())
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64
	var out [32]byte
	copy(out[:], h[:32])
	return &out
}

// ─── Key Loading ──────────────────────────────────────────────────────────────

// loadEd25519Key reads a PKCS#8 PEM file and returns an Ed25519 private key.
// Generate with: openssl genpkey -algorithm ed25519 -out identity.pem
func loadEd25519Key(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key in %s is not Ed25519 (got %T)", path, key)
	}

	return edKey, nil
}

// ─── HTTP ─────────────────────────────────────────────────────────────────────

func apiPost(apiBase, action string, params url.Values, token string) (*apiResponse, error) {
	params.Set("action", action)

	req, err := http.NewRequest("POST", apiBase, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST %s action=%s: %w", apiBase, action, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var apiResp apiResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("invalid JSON response: %w (body: %.200s)", err, body)
	}

	if apiResp.Error != "" {
		return nil, fmt.Errorf("%s", apiResp.Error)
	}

	return &apiResp, nil
}

// ─── CLI helpers ──────────────────────────────────────────────────────────────

func parseFlags(args []string) map[string]string {
	flags := make(map[string]string)
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "--") {
			key := strings.TrimPrefix(arg, "--")
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				flags[key] = args[i+1]
				i++
			} else {
				flags[key] = "true"
			}
		}
	}
	return flags
}

func usage() {
	fmt.Print(`p3sig-agent — P3sig identity agent

USAGE:
  p3sig-agent vault get  --api URL --identity ID --key PATH (--label L | --scope S | --vault-id V)
  p3sig-agent ssh-keys   --api URL --identity ID --key PATH

FLAGS:
  --api          P3sig API URL  (e.g. https://p3sig.com/p3sig/api/index.php)
  --identity     P3sig identity ID
  --key          Path to Ed25519 private key (PKCS#8 PEM)
  --label        Vault entry label
  --scope        Vault scope pattern
  --vault-id     Vault entry ID

KEY GENERATION:
  openssl genpkey -algorithm ed25519 -out /etc/p3sig/identity.pem
  openssl pkey -in /etc/p3sig/identity.pem -pubout   # paste public key into p3sig UI

SSHD INTEGRATION (/etc/ssh/sshd_config):
  AuthorizedKeysCommand /usr/local/bin/p3sig-agent ssh-keys \
    --api https://p3sig.com/p3sig/api/index.php \
    --identity <identity-id> --key /etc/p3sig/identity.pem
  AuthorizedKeysCommandUser nobody

BUILD:
  cd scripts/p3sig-agent && go mod tidy && go build -o p3sig-agent .
  # Cross-compile for Linux:
  GOOS=linux GOARCH=amd64 go build -o p3sig-agent-linux-amd64 .
  GOOS=linux GOARCH=arm64 go build -o p3sig-agent-linux-arm64 .
`)
}
