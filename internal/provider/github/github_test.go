package github

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shivansh-sinha/ephemeral-credential-broker/internal/provider"
)

// Per design doc section 4.1 ("Testing: ... mock the GitHub API entirely --
// never hit real GitHub in tests"), every test in this file runs against an
// httptest server standing in for api.github.com. None of it touches the
// network, and none of it depends on anything outside the Go standard
// library plus this repo's own provider package -- it builds and runs
// anywhere `go test` runs, with no module-proxy access required.

func testKey(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating test RSA key: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	return key, pemBytes
}

// decodeJWT splits a compact JWT and returns its decoded header and claims,
// plus the raw signing input and signature for independent verification.
func decodeJWT(t *testing.T, tok string) (header, claims map[string]any, signingInput string, sig []byte) {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT segments, got %d in %q", len(parts), tok)
	}
	headerB, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decoding JWT header: %v", err)
	}
	claimsB, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decoding JWT claims: %v", err)
	}
	sig, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decoding JWT signature: %v", err)
	}
	if err := json.Unmarshal(headerB, &header); err != nil {
		t.Fatalf("unmarshalling JWT header: %v", err)
	}
	if err := json.Unmarshal(claimsB, &claims); err != nil {
		t.Fatalf("unmarshalling JWT claims: %v", err)
	}
	return header, claims, parts[0] + "." + parts[1], sig
}

// verifyRS256 independently checks an RS256 signature against a public
// key, so the test proves the JWT is really validly signed -- not just
// shaped like a JWT.
func verifyRS256(pub *rsa.PublicKey, signingInput string, sig []byte) error {
	digest := sha256.Sum256([]byte(signingInput))
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig)
}

func TestMint_Success(t *testing.T) {
	key, pemBytes := testKey(t)
	fixedNow := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	wantExpiresAt := fixedNow.Add(time.Hour).UTC()

	var sawInstallationAuth, sawTokenAuth, sawRevokeAuth string
	var sawTokenBody createTokenRequest

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/myorg/myrepo/installation", func(w http.ResponseWriter, r *http.Request) {
		sawInstallationAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id": 987654}`))
	})
	mux.HandleFunc("/app/installations/987654/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		sawTokenAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&sawTokenBody); err != nil {
			t.Errorf("decoding request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(createTokenResponse{
			Token:     "ghs_testtoken123",
			ExpiresAt: wantExpiresAt,
		})
	})
	mux.HandleFunc("/installation/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		sawRevokeAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	p := &Provider{APIBaseURL: server.URL, HTTPClient: server.Client(), Now: func() time.Time { return fixedNow }}

	scope := Scope{
		AppID:         "123456",
		PrivateKeyPEM: pemBytes,
		Repositories:  []string{"myorg/myrepo"},
		Permissions:   map[string]string{"contents": "read", "issues": "read"},
	}
	result, err := p.Mint(context.Background(), provider.MintRequest{Scope: scope})
	if err != nil {
		t.Fatalf("Mint returned error: %v", err)
	}

	if got := string(result.Data["token"]); got != "ghs_testtoken123" {
		t.Errorf("Data[token] = %q, want ghs_testtoken123", got)
	}
	if !result.ExpiresAt.Equal(wantExpiresAt) {
		t.Errorf("ExpiresAt = %v, want %v", result.ExpiresAt, wantExpiresAt)
	}
	if result.Handle.ProviderName != Name {
		t.Errorf("Handle.ProviderName = %q, want %q", result.Handle.ProviderName, Name)
	}
	if string(result.Handle.Opaque) != "ghs_testtoken123" {
		t.Errorf("Handle.Opaque = %q, want ghs_testtoken123", result.Handle.Opaque)
	}

	// The installation-resolve call and the token-mint call must both have
	// presented the same App JWT, bearer-style.
	if sawInstallationAuth == "" || sawInstallationAuth != sawTokenAuth {
		t.Errorf("expected the same Bearer App JWT on both calls, got %q and %q", sawInstallationAuth, sawTokenAuth)
	}
	appJWT := strings.TrimPrefix(sawInstallationAuth, "Bearer ")

	// The token-mint request must ask for exactly the requested repos and
	// permissions -- never widened, never narrowed (the broker forwards
	// what the CR asked for; see docs/THREAT_MODEL.md "misconfigured
	// scope").
	if len(sawTokenBody.Repositories) != 1 || sawTokenBody.Repositories[0] != "myorg/myrepo" {
		t.Errorf("token request repositories = %v, want [myorg/myrepo]", sawTokenBody.Repositories)
	}
	if sawTokenBody.Permissions["contents"] != "read" || sawTokenBody.Permissions["issues"] != "read" {
		t.Errorf("token request permissions = %v, want contents=read,issues=read", sawTokenBody.Permissions)
	}

	// Verify the JWT actually is what GitHub requires: RS256, iss=AppID,
	// lifetime within the 10-minute cap, and a signature that verifies
	// against the *public* half of the same key -- i.e. this is a real,
	// independently-verifiable RS256 JWT, not just three base64 blobs.
	header, claims, signingInput, sig := decodeJWT(t, appJWT)
	if header["alg"] != "RS256" {
		t.Errorf("JWT alg = %v, want RS256", header["alg"])
	}
	if header["typ"] != "JWT" {
		t.Errorf("JWT typ = %v, want JWT", header["typ"])
	}
	if iss, _ := claims["iss"].(string); iss != scope.AppID {
		t.Errorf("JWT iss = %v, want %v", claims["iss"], scope.AppID)
	}
	iat, _ := claims["iat"].(float64)
	exp, _ := claims["exp"].(float64)
	if exp-iat > jwtMaxLifetime.Seconds() {
		t.Errorf("JWT lifetime %v exceeds GitHub's %v cap", time.Duration(exp-iat)*time.Second, jwtMaxLifetime)
	}
	if err := verifyRS256(&key.PublicKey, signingInput, sig); err != nil {
		t.Errorf("JWT signature does not verify against the App's own public key: %v", err)
	}

	// Now exercise Revoke with the handle Mint returned.
	if err := p.Revoke(context.Background(), result.Handle); err != nil {
		t.Fatalf("Revoke returned error: %v", err)
	}
	if sawRevokeAuth != "Bearer ghs_testtoken123" {
		t.Errorf("revoke Authorization = %q, want %q", sawRevokeAuth, "Bearer ghs_testtoken123")
	}
}

func TestMint_ValidatesScope(t *testing.T) {
	p := New()
	cases := []struct {
		name  string
		scope any
	}{
		{"wrong scope type", "not-a-scope"},
		{"missing AppID", Scope{PrivateKeyPEM: []byte("x"), Repositories: []string{"a/b"}}},
		{"missing PrivateKeyPEM", Scope{AppID: "1", Repositories: []string{"a/b"}}},
		{"missing Repositories", Scope{AppID: "1", PrivateKeyPEM: []byte("x")}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := p.Mint(context.Background(), provider.MintRequest{Scope: c.scope}); err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}
}

func TestMint_UpstreamErrorSurfaces(t *testing.T) {
	_, pemBytes := testKey(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/myorg/myrepo/installation", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Not Found"}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	p := &Provider{APIBaseURL: server.URL, HTTPClient: server.Client()}
	scope := Scope{AppID: "1", PrivateKeyPEM: pemBytes, Repositories: []string{"myorg/myrepo"}}
	_, err := p.Mint(context.Background(), provider.MintRequest{Scope: scope})
	if err == nil {
		t.Fatal("expected an error when GitHub returns 404, got nil")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("expected error to mention the 404 status, got: %v", err)
	}
}

func TestRevoke_RejectsWrongProvider(t *testing.T) {
	p := New()
	err := p.Revoke(context.Background(), provider.CredentialHandle{ProviderName: "some-other-provider", Opaque: []byte("tok")})
	if err == nil {
		t.Fatal("expected an error revoking a handle minted by a different provider")
	}
}

func TestRevoke_RejectsEmptyHandle(t *testing.T) {
	p := New()
	err := p.Revoke(context.Background(), provider.CredentialHandle{ProviderName: Name})
	if err == nil {
		t.Fatal("expected an error revoking an empty credential handle")
	}
}
