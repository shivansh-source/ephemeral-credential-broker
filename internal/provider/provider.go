// Package provider defines the pluggable interface every credential
// provider implements (design doc section 3.3). It intentionally imports
// nothing from this repo's k8s API package (api/v1alpha1) or from
// controller-runtime/client-go: the interface is plain Go, so each
// provider -- and this package itself -- builds and tests with only the
// standard library. The controller (internal/controller) is the only place
// that translates a CRD's spec.providerConfig into a concrete, provider-
// specific Scope value.
package provider

import (
	"context"
	"errors"
	"time"
)

// ErrNoRevoke is returned by Provider.Revoke when the underlying credential
// system has no way to invalidate a credential before its natural expiry
// (for example, AWS STS session credentials -- design doc section 4.2). The
// controller treats this as "nothing to do," not as a reconcile error, and
// relies on the credential's short TTL instead.
var ErrNoRevoke = errors.New("provider does not support revoke; relying on TTL expiry")

// CredentialHandle is opaque data a Provider returns from Mint and later
// needs back from the controller to Revoke that same credential. Its shape
// is entirely up to the provider (a GitHub installation token can revoke
// itself by presenting itself as the bearer credential; an STS session has
// no handle at all; a database credential's handle would be the generated
// username).
type CredentialHandle struct {
	// ProviderName that minted this credential. Lets Revoke validate it
	// isn't handed a handle from a different provider.
	ProviderName string
	// Opaque is provider-specific revoke material. Never logged.
	Opaque []byte
}

// MintRequest is what the controller asks a Provider to mint.
type MintRequest struct {
	// Scope is a provider-specific configuration value. Each Provider
	// implementation defines and type-asserts its own concrete Scope type
	// (see e.g. internal/provider/github.Scope). Passing `any` here, rather
	// than a type from api/v1alpha1, is what keeps this package free of any
	// k8s.io/* import.
	Scope any
	// TTL is the requested credential lifetime. A provider may grant a
	// shorter lifetime than requested -- see MintResult.ExpiresAt.
	TTL time.Duration
	// Namespace of the EphemeralCredential requesting this credential, for
	// provider-side auditing/naming.
	Namespace string
	// Name of the EphemeralCredential requesting this credential, for
	// provider-side auditing/naming.
	Name string
}

// MintResult is what a Provider hands back after minting.
type MintResult struct {
	// Data is written verbatim into the target Secret, keyed by the
	// provider's logical output names (e.g. "token", or "username" and
	// "password") -- EphemeralCredentialSpec.TargetSecret.Keys maps these
	// onto the actual Secret data keys.
	Data map[string][]byte
	// ExpiresAt is the actual granted expiry, which the controller trusts
	// over the requested TTL for scheduling rotation.
	ExpiresAt time.Time
	// Handle is opaque data needed to Revoke this credential later.
	Handle CredentialHandle
}

// Provider mints an ephemeral credential for a given scope and TTL. Each
// supported credential system implements this once (design doc section
// 3.3). v1 ships exactly one implementation: internal/provider/github.
type Provider interface {
	// Name returns the provider key used in spec.provider (e.g.
	// "github-app").
	Name() string

	// Mint issues a short-lived credential for the requested scope and
	// ttl. It returns the credential material, the actual expiry time the
	// provider granted (which may be shorter than requested), and an
	// error.
	Mint(ctx context.Context, req MintRequest) (MintResult, error)

	// Revoke best-effort invalidates a previously minted credential, if
	// the provider supports it. Providers that cannot revoke return
	// ErrNoRevoke; the controller then relies on TTL expiry alone.
	Revoke(ctx context.Context, handle CredentialHandle) error
}

// Registry is a simple name -> Provider lookup, used by the controller to
// resolve spec.provider to a concrete implementation without a big
// switch statement. Adding a provider means constructing one more
// implementation and passing it to NewRegistry -- the controller does not
// otherwise change (design doc section 3.3, closing paragraph).
type Registry struct {
	providers map[string]Provider
}

// NewRegistry builds a Registry from a set of providers, keyed by each
// provider's own Name().
func NewRegistry(providers ...Provider) *Registry {
	r := &Registry{providers: make(map[string]Provider, len(providers))}
	for _, p := range providers {
		r.providers[p.Name()] = p
	}
	return r
}

// Get looks up a provider by the name used in spec.provider.
func (r *Registry) Get(name string) (Provider, bool) {
	p, ok := r.providers[name]
	return p, ok
}
