package main

// org_cli.go — the `p3sig org …` verbs: a thin client layer over the org.go crypto
// core and the signed-request transport (userRequest, cli.go). Pure Go, builds on
// every platform — the only chip-specific step in the whole feature is unlocking the
// personal vault key, and that already happens via the key file / device blob before
// any of this. See docs/ORG-VAULT-CONTEXT.md.
//
// Auth: every call signs "<pubkey>|<ts>" with the account's vault key (userRequest);
// the server resolves the account and org membership from that key (p3sig_org_actor).
// The SAME vault key doubles as the personal key that unwraps the org key — so it must
// be the key the org wrap was sealed to (the common single-key case).

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
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
	fmt.Printf("created organization %q (org_id %s). Your Org Vault is ready.\n", name, res.OrgID)
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
	var mk struct {
		Keys []orgKeyRef `json:"keys"`
	}
	if err := userRequest(apiBase, "getMemberKeys", keyPath, extra, &mk); err != nil {
		return err
	}
	if len(mk.Keys) == 0 {
		return fmt.Errorf("member %s has no active personal key to wrap the org key to", memberID)
	}
	target := mk.Keys[0] // match the web client: wrap to the member's first active key
	wrapped, err := wrapOrgKeyFor(orgPriv, target.Pub)
	if err != nil {
		return err
	}
	w := url.Values{}
	w.Set("member_user_id", memberID)
	w.Set("member_key_id", target.KeyID)
	w.Set("wrapped_org_key", wrapped)
	if err := userRequest(apiBase, "wrapOrgKeyForMember", keyPath, w, nil); err != nil {
		return err
	}
	fmt.Printf("granted vault access to user %s.\n", memberID)
	if len(mk.Keys) > 1 {
		fmt.Printf("note: member has %d keys; wrapped to the first only (matches the web client).\n", len(mk.Keys))
	}
	return nil
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
	type copyT struct {
		KeyID string `json:"key_id"`
		Enc   string `json:"encrypted_data"`
	}
	copies := make([]copyT, 0, len(rec.Recipients))
	for _, r := range rec.Recipients {
		enc, err := sealForKey(value, r.Pub)
		if err != nil {
			return fmt.Errorf("seal to org key %s: %w", r.KeyID, err)
		}
		copies = append(copies, copyT{KeyID: r.KeyID, Enc: enc})
	}
	payload, _ := json.Marshal(copies)

	extra := url.Values{}
	extra.Set("label", name)
	if f["provider"] != "" {
		extra.Set("provider", f["provider"])
	}
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
	fmt.Printf("stored org secret %q — sealed to the org vault key; the server holds only ciphertext.\n", name)
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
	secretID, err := resolveOrgSecretID(apiBase, keyPath, name)
	if err != nil {
		return err
	}
	extra := url.Values{}
	extra.Set("secret_id", secretID)
	var res struct {
		Enc     string `json:"encrypted_data"`
		Wrapped string `json:"wrapped_org_key"`
	}
	if err := userRequest(apiBase, "getSealedSecret", keyPath, extra, &res); err != nil {
		return err
	}
	orgPriv, err := unwrapOrgKey(res.Wrapped, key)
	if err != nil {
		return fmt.Errorf("unwrap org key (is your vault key the one access was granted to?): %w", err)
	}
	defer zero(orgPriv)
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
	secrets, err := fetchOrgSecrets(apiBase, keyPath)
	if err != nil {
		return err
	}
	if len(secrets) == 0 {
		fmt.Fprintln(os.Stderr, "(no org secrets)")
		return nil
	}
	for _, s := range secrets {
		fmt.Println(s.Label)
	}
	return nil
}

// ─── shared helpers ─────────────────────────────────────────────────────────

// orgKeyRef is a {key_id, public_key} pair as returned by getOrgRecipients /
// getMemberKeys.
type orgKeyRef struct {
	KeyID string `json:"key_id"`
	Pub   string `json:"public_key"`
}

// orgSecretMeta is one row from listOrgSecrets.
type orgSecretMeta struct {
	SecretID string `json:"secret_id"`
	Label    string `json:"label"`
	Provider string `json:"provider"`
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

// myOrgKey fetches the caller's own wrapped org key and unwraps it with their personal
// vault key, returning the held org private key.
func myOrgKey(apiBase, keyPath string, personalPriv ed25519.PrivateKey) (ed25519.PrivateKey, error) {
	var res struct {
		Wrap *struct {
			Wrapped string `json:"wrapped_org_key"`
		} `json:"wrap"`
	}
	if err := userRequest(apiBase, "getOrgKeyWrap", keyPath, nil, &res); err != nil {
		return nil, err
	}
	if res.Wrap == nil || res.Wrap.Wrapped == "" {
		return nil, fmt.Errorf("you don't have vault access yet — ask an admin to grant it")
	}
	return unwrapOrgKey(res.Wrap.Wrapped, personalPriv)
}

func fetchOrgSecrets(apiBase, keyPath string) ([]orgSecretMeta, error) {
	var res struct {
		Secrets []orgSecretMeta `json:"secrets"`
	}
	if err := userRequest(apiBase, "listOrgSecrets", keyPath, nil, &res); err != nil {
		return nil, err
	}
	return res.Secrets, nil
}

func resolveOrgSecretID(apiBase, keyPath, name string) (string, error) {
	secrets, err := fetchOrgSecrets(apiBase, keyPath)
	if err != nil {
		return "", err
	}
	for _, s := range secrets {
		if s.Label == name {
			return s.SecretID, nil
		}
	}
	return "", fmt.Errorf("no org secret named %q", name)
}
