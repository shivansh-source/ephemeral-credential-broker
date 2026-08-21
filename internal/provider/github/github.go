// Package github implements the v1 reference Provider: GitHub App
// installation tokens (design doc section 4.1). GitHub does the
// security-critical work -- minting, scoping, and ~1-hour expiry are
// enforced server-side -- so this package is a thin, well-scoped wrapper:
// sign a short-lived App JWT, resolve the installation for the target
// repos, and request an installation access token for exactly the
// repositories and permissions the CR asked for.
//
// Deliberately dependency-free: JWT signing uses only crypto/rsa and
// encoding/json from the standard library (GitHub App JWTs are a plain
// three-segment RS256 token over a two-field claim set -- not worth an
// external JWT library for), and GitHub API calls use net/http directly.
// That keeps this package (and its tests) buildable and testable with
// nothing beyond the Go standard library.
package github

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/shivansh-sinha/ephemeral-credential-broker/internal/provider"
)

const (
	// Name is the provider key used in EphemeralCredential.spec.provider.
	Name = "github-app"

	defaultAPIBaseURL = "https://api.github.com"

	// jwtMaxLifetime is GitHub's hard cap on App JWT expiry.
	jwtMaxLifetime = 10 * time.Minute
	// jwtClockSkewGuard backdates `iat` and shortens `exp` by this much, as
	// GitHub's own docs recommend, to tolerate clock drift between the
	// broker and GitHub's servers.
	jwtClockSkewGuard = 60 * time.Second
)

// Scope is the github-app provider's concrete MintRequest.Scope value. The
// controller builds one of these from spec.providerConfig.github plus the
// App credentials Secret referenced by appConfigRef -- this package never
// reads Kubernetes objects itself.
type Scope struct {
	// AppID is the GitHub App's numeric ID, as a string.
	AppID string
	// PrivateKeyPEM is the App's PKCS#1 or PKCS#8 PEM-encoded RSA private
	// key. This is the highest-value secret in the whole system -- see
	// docs/THREAT_MODEL.md.
	PrivateKeyPEM []byte
	// Repositories the installation token is scoped to (must already be
	// accessible to the App's installation).
	Repositories []string
	// Permissions requested on the token, e.g. {"contents": "read"}.
	Permissions map[string]string
}

// Provider implements provider.Provider for GitHub App installation
// tokens.
type Provider struct {
	// APIBaseURL defaults to https://api.github.com; overridable in tests
	// to point at an httptest server.
	APIBaseURL string
	// HTTPClient defaults to http.DefaultClient; overridable in tests.
	HTTPClient *http.Client
	// Now defaults to time.Now; overridable in tests for a deterministic
	// JWT `iat`/`exp`.
	Now func() time.Time
}

// New returns a Provider configured against the real GitHub API.
func New() *Provider {
	return &Provider{
		APIBaseURL: defaultAPIBaseURL,
		HTTPClient: http.DefaultClient,
		Now:        time.Now,
	}
}

// Name implements provider.Provider.
func (p *Provider) Name() string { return Name }

func (p *Provider) client() *http.Client {
	if p.HTTPClient != nil {
		return p.HTTPClient
	}
	return http.DefaultClient
}

func (p *Provider) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *Provider) baseURL() string {
	if p.APIBaseURL != "" {
		return p.APIBaseURL
	}
	return defaultAPIBaseURL
}

// Mint implements the five steps from design doc section 4.1: parse the
// App private key, sign an App JWT, resolve the installation ID for the
// target repositories, request an installation access token scoped to
// exactly the requested repositories/permissions, and return it. The
// broker never widens or narrows what the CR asks for -- an over-broad
// `permissions` block produces an over-broad token, by design (see
// docs/THREAT_MODEL.md, "misconfigured scope").
func (p *Provider) Mint(ctx context.Context, req provider.MintRequest) (provider.MintResult, error) {
	scope, ok := req.Scope.(Scope)
	if !ok {
		return provider.MintResult{}, fmt.Errorf("github: MintRequest.Scope must be github.Scope, got %T", req.Scope)
	}
	if scope.AppID == "" || len(scope.PrivateKeyPEM) == 0 {
		return provider.MintResult{}, errors.New("github: Scope.AppID and Scope.PrivateKeyPEM are required")
	}
	if len(scope.Repositories) == 0 {
		return provider.MintResult{}, errors.New("github: Scope.Repositories must not be empty")
	}

	key, err := parsePrivateKey(scope.PrivateKeyPEM)
	if err != nil {
		return provider.MintResult{}, fmt.Errorf("github: parsing App private key: %w", err)
	}

	appJWT, err := p.signAppJWT(scope.AppID, key)
	if err != nil {
		return provider.MintResult{}, fmt.Errorf("github: signing App JWT: %w", err)
	}

	installationID, err := p.resolveInstallationID(ctx, appJWT, scope.Repositories[0])
	if err != nil {
		return provider.MintResult{}, fmt.Errorf("github: resolving installation: %w", err)
	}

	tok, expiresAt, err := p.createInstallationToken(ctx, appJWT, installationID, scope.Repositories, scope.Permissions)
	if err != nil {
		return provider.MintResult{}, fmt.Errorf("github: minting installation token: %w", err)
	}

	return provider.MintResult{
		Data:      map[string][]byte{"token": []byte(tok)},
		ExpiresAt: expiresAt,
		Handle:    provider.CredentialHandle{ProviderName: Name, Opaque: []byte(tok)},
	}, nil
}

// Revoke calls DELETE /installation/token, authenticated as the token
// being revoked itself -- GitHub installation tokens can revoke
// themselves. Design doc section 4.1: called on rotation, after the new
// token is already written into the target Secret, so consumers never see
// a gap.
func (p *Provider) Revoke(ctx context.Context, handle provider.CredentialHandle) error {
	if handle.ProviderName != Name {
		return fmt.Errorf("github: cannot revoke a handle minted by provider %q", handle.ProviderName)
	}
	if len(handle.Opaque) == 0 {
		return errors.New("github: empty credential handle")
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, p.baseURL()+"/installation/token", nil)
	if err != nil {
		return err
	}
	httpReq.Header.Set("Authorization", "Bearer "+string(handle.Opaque))
	httpReq.Header.Set("Accept", "application/vnd.github+json")
	resp, err := p.client().Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("github: revoke installation token: unexpected status %d: %s", resp.StatusCode, readBody(resp))
	}
	return nil
}

func parsePrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	generic, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("not a PKCS#1 or PKCS#8 key: %w", err)
	}
	rsaKey, ok := generic.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not an RSA key")
	}
	return rsaKey, nil
}

// signAppJWT builds and RS256-signs the JWT GitHub requires to
// authenticate as the App itself (as opposed to as an installation):
// header {"alg":"RS256","typ":"JWT"}, claims {iat, exp, iss: appID}.
func (p *Provider) signAppJWT(appID string, key *rsa.PrivateKey) (string, error) {
	now := p.now()
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	claims := map[string]any{
		"iat": now.Add(-jwtClockSkewGuard).Unix(),
		"exp": now.Add(jwtMaxLifetime - jwtClockSkewGuard).Unix(),
		"iss": appID,
	}
	headerB64, err := marshalB64(header)
	if err != nil {
		return "", err
	}
	claimsB64, err := marshalB64(claims)
	if err != nil {
		return "", err
	}
	signingInput := headerB64 + "." + claimsB64
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func marshalB64(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

type installationResponse struct {
	ID int64 `json:"id"`
}

func (p *Provider) resolveInstallationID(ctx context.Context, appJWT string, repoFullName string) (int64, error) {
	url := fmt.Sprintf("%s/repos/%s/installation", p.baseURL(), repoFullName)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+appJWT)
	httpReq.Header.Set("Accept", "application/vnd.github+json")
	resp, err := p.client().Do(httpReq)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("unexpected status %d resolving installation for %s: %s", resp.StatusCode, repoFullName, readBody(resp))
	}
	var out installationResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, fmt.Errorf("decoding installation response: %w", err)
	}
	return out.ID, nil
}

type createTokenRequest struct {
	Repositories []string          `json:"repositories,omitempty"`
	Permissions  map[string]string `json:"permissions,omitempty"`
}

type createTokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (p *Provider) createInstallationToken(ctx context.Context, appJWT string, installationID int64, repos []string, perms map[string]string) (string, time.Time, error) {
	body, err := json.Marshal(createTokenRequest{Repositories: repos, Permissions: perms})
	if err != nil {
		return "", time.Time{}, err
	}
	url := fmt.Sprintf("%s/app/installations/%s/access_tokens", p.baseURL(), strconv.FormatInt(installationID, 10))
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", time.Time{}, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+appJWT)
	httpReq.Header.Set("Accept", "application/vnd.github+json")
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := p.client().Do(httpReq)
	if err != nil {
		return "", time.Time{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return "", time.Time{}, fmt.Errorf("unexpected status %d creating installation token: %s", resp.StatusCode, readBody(resp))
	}
	var out createTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", time.Time{}, fmt.Errorf("decoding token response: %w", err)
	}
	return out.Token, out.ExpiresAt, nil
}

func readBody(resp *http.Response) string {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	return string(b)
}

var _ provider.Provider = (*Provider)(nil)
