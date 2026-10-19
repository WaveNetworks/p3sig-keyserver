package main

// org_cli.go — the `p3sig org …` verbs: a thin client layer over the org.go crypto
// core and the signed-request transport (userRequest, cli.go). Pure Go, builds on
// every platform — the only chip-specific step in the whole feature is unlocking the
// personal vault key, and that already happens via the key file / device blob before
// any of this. See docs/ORG-VAULT-CONTEXT.md.
//
// Auth: every call signs "<pubkey>|<ts>" with the account's vault key (userRequest);
// the server resolves the account and org membership from that key (p3sig_org_actor).
// The SAME vault key doubles as the personal key that unwraps the org key. The org key
// is wrapped to EVERY one of a member's keys (as the browser does), and reads try every
// wrap, so whichever of your keys you use opens it.
//
// Names are sealed too: every org secret's {label, provider} JSON is sealed to the org
// key next to its value (encrypted_meta); the server keeps no readable name.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
)

// ─── org create ─────────────────────────────────────────────────────────────

func cmdOrgCreate(f map[string]string) error {
	name := f["name"]
	if name == "" {
		return fmt.Errorf("usage: p3sig org create --name NAME")
	}
	apiBase, keyPath, err := resolveIdentity(f)
	if err != nil {
		return err
	}
	key, err := loadKey(keyPath)
	if err != nil {
		return err
	}
	ownerPub := base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	ownerKeyID, err := findMyKeyID(apiBase, keyPath, ownerPub)
	if err != nil {
		return err
	}

	orgPub, wrappedForOwner, orgPriv, err := createOrgVault(ownerPub)
	if err != nil {
		return err
	}
	defer zero(orgPriv)

	extra := url.Values{}
	extra.Set("name", name)
	extra.Set("org_public_key", orgPub)
	extra.Set("wrapped_org_key", wrappedForOwner)
	extra.Set("owner_key_id", ownerKeyID)
	var res struct {
		OrgID string `json:"org_id"`
	}
	if err := userRequest(apiBase, "createOrg", keyPath, extra, &res); err != nil {
		return err
	}
	// Wrap the org key to your OTHER keys too, so losing this one never locks you out.
	var who struct {
		UserID json.Number `json:"user_id"`
	}
	if err := userRequest(apiBase, "whoami", keyPath, nil, &who); err != nil {
		return fmt.Errorf("org created, but wrapping it to your other keys failed (grant yourself from the web): %w", err)
	}
	n, err := wrapToAllKeys(apiBase, keyPath, orgPriv, who.UserID.String(), "getMyVaultKeys", nil, ownerKeyID)
	if err != nil {
		return fmt.Errorf("org created, but wrapping it to your other keys failed (grant yourself from the web): %w", err)
	}
	fmt.Printf("created organization %q (org_id %s). Your Org Vault is ready, secured to %d of your keys.\n", name, res.OrgID, n+1)
	fmt.Println("Next:  p3sig org secret set NAME   ·   p3sig org add --email teammate@example.com")
	return nil
}

// ─── org add / grant (membership) ───────────────────────────────────────────

func cmdOrgAddMember(f map[string]string) error {
	email := f["email"]
	if email == "" {
		return fmt.Errorf("usage: p3sig org add --email a@b.com [--admin]  (the person must already have a p3sig account)")
	}
	apiBase, keyPath, err := resolveIdentity(f)
	if err != nil {
		return err
	}
	role := "member"
	if f["admin"] == "true" {
		role = "admin"
	}
	extra := url.Values{}
	extra.Set("email", email)
	extra.Set("role", role)
	var res struct {
		MemberUserID string `json:"member_user_id"`
	}
	if err := userRequest(apiBase, "addMember", keyPath, extra, &res); err != nil {
		return err
	}
	fmt.Printf("added %s as %s.\n", email, role)
	if res.MemberUserID != "" {
		fmt.Printf("grant vault access:  p3sig org grant --user %s\n", res.MemberUserID)
	}
	return nil
}

func cmdOrgGrant(f map[string]string) error {
	memberID := firstNonEmpty(f["user"], f["member"])
	if memberID == "" {
		return fmt.Errorf("usage: p3sig org grant --user MEMBER_USER_ID")
	}
	apiBase, keyPath, err := resolveIdentity(f)
	if err != nil {
		return err
	}
	key, err := loadKey(keyPath)
	if err != nil {
		return err
	}
	orgPriv, err := myOrgKey(apiBase, keyPath, key)
	if err != nil {
		return err
	}
	defer zero(orgPriv)

	extra := url.Values{}
	extra.Set("member_user_id", memberID)
	n, err := wrapToAllKeys(apiBase, keyPath, orgPriv, memberID, "getMemberKeys", extra, "")
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("member %s has no active personal key to wrap the org key to", memberID)
	}
	fmt.Printf("granted vault access to user %s (wrapped to %d key(s)).\n", memberID, n)
	return nil
}

// wrapToAllKeys wraps the org key to every active key a lookup action returns
// (getMyVaultKeys / getMemberKeys) except skipKeyID, storing each wrap for
// memberID. → the number of wraps stored.
func wrapToAllKeys(apiBase, keyPath string, orgPriv ed25519.PrivateKey, memberID, lookup string, lookupArgs url.Values, skipKeyID string) (int, error) {
	var mk struct {
		Keys []orgKeyRef `json:"keys"`
	}
	if err := userRequest(apiBase, lookup, keyPath, lookupArgs, &mk); err != nil {
		return 0, err
	}
	n := 0
	for _, k := range mk.Keys {
		if k.KeyID == skipKeyID {
			continue
		}
		wrapped, err := wrapOrgKeyFor(orgPriv, k.Pub)
		if err != nil {
			return n, err
		}
		w := url.Values{}
		w.Set("member_user_id", memberID)
		w.Set("member_key_id", k.KeyID)
		w.Set("wrapped_org_key", wrapped)
		if err := userRequest(apiBase, "wrapOrgKeyForMember", keyPath, w, nil); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// ─── org secret set / get / list ────────────────────────────────────────────

func cmdOrgSecretSet(f map[string]string, name string) error {
	if name == "" {
		return fmt.Errorf("usage: p3sig org secret set NAME [--provider P] [--bundle ID]\n" +
			"the value is read from stdin (echo -n VALUE | p3sig org secret set NAME) or prompted")
	}
	apiBase, keyPath, err := resolveIdentity(f)
	if err != nil {
		return err
	}
	var rec struct {
		Recipients []orgKeyRef `json:"recipients"`
	}
	if err := userRequest(apiBase, "getOrgRecipients", keyPath, nil, &rec); err != nil {
		return err
	}
	if len(rec.Recipients) == 0 {
		return fmt.Errorf("the org vault has no recipient key set up")
	}
	value, err := readSecretValue(name)
	if err != nil {
		return err
	}
	meta := secretMeta{Label: name, Provider: f["provider"]}
	copies := make([]sealedCopy, 0, len(rec.Recipients))
	for _, r := range rec.Recipients {
		c, err := sealSecretFor(value, meta, r.KeyID, r.Pub)
		if err != nil {
			return fmt.Errorf("seal to org key %s: %w", r.KeyID, err)
		}
		copies = append(copies, c)
	}
	payload, _ := json.Marshal(copies)

	extra := url.Values{}
	if f["bundle"] != "" {
		extra.Set("bundle_id", f["bundle"])
	}
	extra.Set("sealed_copies", string(payload))
	var res struct {
		SecretID string `json:"secret_id"`
		Sealed   int    `json:"sealed"`
	}
	if err := userRequest(apiBase, "saveSealedSecret", keyPath, extra, &res); err != nil {
		return err
	}
	fmt.Printf("stored org secret %q — value and name sealed to the org vault key; the server holds only ciphertext.\n", name)
	if f["bundle"] != "" {
		fmt.Println("machines already granted that bundle get it when an admin re-seals (web: the machine's page).")
	}
	return nil
}

func cmdOrgSecretGet(f map[string]string, name string) error {
	if name == "" {
		return fmt.Errorf("usage: p3sig org secret get NAME")
	}
	apiBase, keyPath, err := resolveIdentity(f)
	if err != nil {
		return err
	}
	key, err := loadKey(keyPath)
	if err != nil {
		return err
	}
	orgPriv, err := myOrgKey(apiBase, keyPath, key)
	if err != nil {
		return err
	}
	defer zero(orgPriv)
	named, err := orgSecretNames(apiBase, keyPath, orgPriv)
	if err != nil {
		return err
	}
	secretID := ""
	for _, n := range named {
		if n.Label == name {
			secretID = n.SecretID
			break
		}
	}
	if secretID == "" {
		return fmt.Errorf("no org secret named %q", name)
	}
	extra := url.Values{}
	extra.Set("secret_id", secretID)
	var res struct {
		Enc string `json:"encrypted_data"`
	}
	if err := userRequest(apiBase, "getSealedSecret", keyPath, extra, &res); err != nil {
		return err
	}
	val, err := openOrgSecret(res.Enc, orgPriv)
	if err != nil {
		return fmt.Errorf("open %q: %w", name, err)
	}
	fmt.Println(val)
	return nil
}

func cmdOrgSecretList(f map[string]string) error {
	apiBase, keyPath, err := resolveIdentity(f)
	if err != nil {
		return err
	}
	key, err := loadKey(keyPath)
	if err != nil {
		return err
	}
	orgPriv, err := myOrgKey(apiBase, keyPath, key)
	if err != nil {
		return err
	}
	defer zero(orgPriv)
	named, err := orgSecretNames(apiBase, keyPath, orgPriv)
	if err != nil {
		return err
	}
	if len(named) == 0 {
		fmt.Fprintln(os.Stderr, "(no org secrets)")
		return nil
	}
	for _, n := range named {
		if n.Bundle != "" {
			fmt.Printf("%s\t(%s)\n", n.Label, n.Bundle)
		} else {
			fmt.Println(n.Label)
		}
	}
	return nil
}

// ─── org rotate ─────────────────────────────────────────────────────────────

// cmdOrgRotate replaces the org vault key: every secret (value + name) is re-sealed
// to a new org key and the new key is wrapped to every key of each member who has
// access now. All crypto happens here; the server checks nothing is lost.
func cmdOrgRotate(f map[string]string) error {
	apiBase, keyPath, err := resolveIdentity(f)
	if err != nil {
		return err
	}
	key, err := loadKey(keyPath)
	if err != nil {
		return err
	}
	orgPriv, err := myOrgKey(apiBase, keyPath, key)
	if err != nil {
		return err
	}
	defer zero(orgPriv)

	list, err := fetchOrgSecrets(apiBase, keyPath)
	if err != nil {
		return err
	}
	copies := make([]OrgSecretCopy, 0, len(list))
	for _, s := range list {
		extra := url.Values{}
		extra.Set("secret_id", s.SecretID)
		var res struct {
			Enc  string `json:"encrypted_data"`
			Meta string `json:"encrypted_meta"`
		}
		if err := userRequest(apiBase, "getSealedSecret", keyPath, extra, &res); err != nil {
			return fmt.Errorf("fetch secret %s (nothing was rotated): %w", s.SecretID, err)
		}
		copies = append(copies, OrgSecretCopy{SecretID: s.SecretID, Enc: res.Enc, Meta: res.Meta})
	}

	var mem struct {
		Members []struct {
			UserID  json.Number `json:"user_id"`
			HasWrap bool        `json:"has_wrap"`
			Keys    []orgKeyRef `json:"keys"`
		} `json:"members"`
	}
	if err := userRequest(apiBase, "listOrgMembers", keyPath, nil, &mem); err != nil {
		return err
	}
	var members []OrgMemberKey
	for _, m := range mem.Members {
		if !m.HasWrap { // preserve access, don't silently grant
			continue
		}
		for _, k := range m.Keys {
			members = append(members, OrgMemberKey{UserID: m.UserID.String(), KeyID: k.KeyID, Pub: k.Pub})
		}
	}

	rot, err := rotateOrgVault(orgPriv, members, copies)
	if err != nil {
		return err
	}
	defer zero(rot.NewOrgPriv)
	sealed, _ := json.Marshal(rot.Sealed)
	wraps, _ := json.Marshal(rot.Wraps)
	extra := url.Values{}
	extra.Set("new_org_public_key", rot.NewOrgPub)
	extra.Set("sealed", string(sealed))
	extra.Set("wraps", string(wraps))
	if err := userRequest(apiBase, "rotateOrgVault", keyPath, extra, nil); err != nil {
		return err
	}
	fmt.Printf("rotated the org vault: %d secret(s) re-sealed, %d key wrap(s) for current members.\n", len(rot.Sealed), len(rot.Wraps))
	return nil
}

// ─── shared helpers ─────────────────────────────────────────────────────────

// orgKeyRef is a {key_id, public_key} pair as returned by getOrgRecipients /
// getMemberKeys.
type orgKeyRef struct {
	KeyID string `json:"key_id"`
	Pub   string `json:"public_key"`
}

// orgSecretRow is one row from listOrgSecrets: the name is sealed to the org key.
type orgSecretRow struct {
	SecretID string `json:"secret_id"`
	Bundle   string `json:"bundle"`
	Meta     string `json:"encrypted_meta"`
}

// orgSecretName is an org secret with its name opened.
type orgSecretName struct {
	SecretID string
	Bundle   string
	secretMeta
}

// findMyKeyID resolves the caller's own vault key_id (needed as owner_key_id when
// creating an org — the key the org private key is wrapped to).
func findMyKeyID(apiBase, keyPath, pubB64 string) (string, error) {
	var mk struct {
		Keys []orgKeyRef `json:"keys"`
	}
	if err := userRequest(apiBase, "getMyVaultKeys", keyPath, nil, &mk); err != nil {
		return "", err
	}
	for _, k := range mk.Keys {
		if k.Pub == pubB64 {
			return k.KeyID, nil
		}
	}
	return "", fmt.Errorf("this vault key is not registered on the account")
}

// myOrgKey fetches the caller's wraps of the org key and opens whichever was sealed
// to this personal vault key (the org key is wrapped to every one of your keys).
func myOrgKey(apiBase, keyPath string, personalPriv ed25519.PrivateKey) (ed25519.PrivateKey, error) {
	var res struct {
		Wraps []struct {
			Wrapped string `json:"wrapped_org_key"`
		} `json:"wraps"`
	}
	if err := userRequest(apiBase, "getOrgKeyWrap", keyPath, nil, &res); err != nil {
		return nil, err
	}
	if len(res.Wraps) == 0 {
		return nil, fmt.Errorf("you don't have vault access yet — ask an admin to grant it")
	}
	for _, w := range res.Wraps {
		if k, err := unwrapOrgKey(w.Wrapped, personalPriv); err == nil {
			return k, nil
		}
	}
	return nil, fmt.Errorf("none of your org key wraps opens with this vault key — ask an admin to grant access to it")
}

func fetchOrgSecrets(apiBase, keyPath string) ([]orgSecretRow, error) {
	var res struct {
		Secrets []orgSecretRow `json:"secrets"`
	}
	if err := userRequest(apiBase, "listOrgSecrets", keyPath, nil, &res); err != nil {
		return nil, err
	}
	return res.Secrets, nil
}

// orgSecretNames lists the org's secrets with their names opened by the org key,
// sorted by name.
func orgSecretNames(apiBase, keyPath string, orgPriv ed25519.PrivateKey) ([]orgSecretName, error) {
	rows, err := fetchOrgSecrets(apiBase, keyPath)
	if err != nil {
		return nil, err
	}
	out := make([]orgSecretName, 0, len(rows))
	for _, r := range rows {
		m, err := openSecretName(r.Meta, orgPriv)
		if err != nil {
			return nil, fmt.Errorf("open the name of org secret %s: %w", r.SecretID, err)
		}
		out = append(out, orgSecretName{SecretID: r.SecretID, Bundle: r.Bundle, secretMeta: m})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out, nil
}
