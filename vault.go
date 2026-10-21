package main

// `p3sig vault verify` — signed browser-vault releases (task #2598, threat 4).
//
// The browser vault's scripts load with SRI pins, but the server serves the pins too, so
// a compromised server could swap both. The p3sig deploy signs vault-release.json (sha384
// of every vault script) with a key that lives only in a GitHub secret; this command
// checks that signature against the key pinned below, then fetches every listed file
// from the live site and compares bytes. A server that changed the vault code cannot
// produce a matching signed manifest.

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
)

// vaultReleaseKey is the public half of the p3sig deploy's VAULT_RELEASE_SIGNING_KEY
// (p3sig scripts/sign_vault_release.php). A var only so tests can swap it.
var vaultReleaseKey = "Lwy+VorFzquDdGr5JGSMdM3t3/tyveagyjLvXiPRDnM="

type vaultRelease struct {
	V       int               `json:"v"`
	Kind    string            `json:"kind"`
	Commit  string            `json:"commit"`
	BuiltAt string            `json:"built_at"`
	Files   map[string]string `json:"files"`
}

var vaultPathRe = regexp.MustCompile(`^assets/js/[A-Za-z0-9_./-]+\.js$`)

// siteBase turns the API URL into the app's web root (…/p3sig).
func siteBase(api string) string {
	return strings.TrimSuffix(strings.TrimSuffix(strings.TrimRight(api, "/"), "/index.php"), "/api")
}

func cmdVault(sub string, f map[string]string) error {
	if sub != "verify" {
		return fmt.Errorf("unknown vault subcommand %q (verify)", sub)
	}
	base := siteBase(firstNonEmpty(f["url"], os.Getenv("P3SIG_URL"), defaultAPI))
	client := &http.Client{Timeout: httpTimeout}
	get := func(path string) ([]byte, error) {
		req, err := http.NewRequest("GET", base+"/"+path, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Cache-Control", "no-cache")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("GET %s: HTTP %d", path, resp.StatusCode)
		}
		return io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	}
	rel, bad, err := verifyVaultRelease(get, vaultReleaseKey)
	if err != nil {
		return err
	}
	fmt.Printf("vault release %s (built %s), signature OK\n", rel.Commit, rel.BuiltAt)
	names := make([]string, 0, len(rel.Files))
	for p := range rel.Files {
		names = append(names, p)
	}
	sort.Strings(names)
	for _, p := range names {
		if msg, ok := bad[p]; ok {
			fmt.Printf("  FAIL %s: %s\n", p, msg)
		} else {
			fmt.Printf("  ok   %s\n", p)
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("%d vault file(s) on %s do not match the signed release — do not use the browser vault; use the CLI", len(bad), base)
	}
	fmt.Println("the browser vault served by", base, "matches the signed release")
	return nil
}

// verifyVaultRelease checks vault-release.json's signature against pubB64, then hashes
// every listed file. It returns the release, a map of mismatching paths, or an error when
// the manifest itself cannot be trusted.
func verifyVaultRelease(get func(string) ([]byte, error), pubB64 string) (vaultRelease, map[string]string, error) {
	var rel vaultRelease
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return rel, nil, errors.New("bad pinned vault release key")
	}
	raw, err := get("vault-release.json")
	if err != nil {
		return rel, nil, fmt.Errorf("fetch signed release: %w", err)
	}
	var env struct {
		Manifest string `json:"manifest"`
		Sig      string `json:"sig"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return rel, nil, fmt.Errorf("vault-release.json is not JSON: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(env.Sig)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(pub), []byte(env.Manifest), sig) {
		return rel, nil, errors.New("vault-release.json signature does NOT verify against the pinned release key — the server is not serving a release p3sig signed")
	}
	dec := json.NewDecoder(strings.NewReader(env.Manifest))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rel); err != nil {
		return rel, nil, fmt.Errorf("signed manifest: %w", err)
	}
	if rel.V != 1 || rel.Kind != "p3sig-vault-release-v1" || len(rel.Files) == 0 {
		return rel, nil, errors.New("signed manifest has an unknown kind/version or no files")
	}
	bad := map[string]string{}
	for p, want := range rel.Files {
		if !vaultPathRe.MatchString(p) || strings.Contains(p, "..") {
			bad[p] = "unexpected path in manifest"
			continue
		}
		body, err := get(p)
		if err != nil {
			bad[p] = err.Error()
			continue
		}
		sum := sha512.Sum384(body)
		if got := "sha384-" + base64.StdEncoding.EncodeToString(sum[:]); got != want {
			bad[p] = "served " + got + ", signed " + want
		}
	}
	return rel, bad, nil
}
