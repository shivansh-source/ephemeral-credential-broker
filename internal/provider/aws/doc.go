// Package aws is a placeholder for provider 2: AWS STS temporary
// credentials, designed but NOT built in v1.
//
// See design doc section 4.2 for the full specification. Summary: assume a
// configured IAM role (optionally narrowed by a session policy) via STS
// AssumeRole / AssumeRoleWithWebIdentity, write back accessKeyId /
// secretAccessKey / sessionToken, and rely on STS's own expiry (Revoke is
// not possible -- STS sessions cannot be individually invalidated before
// they expire; return provider.ErrNoRevoke).
//
// Honest positioning (state this in any README/blog that talks about this
// package): on EKS this capability already exists natively as IRSA / EKS
// Pod Identity, and cross-cloud as workload identity federation. This
// provider is not better than the cloud-native option where that option is
// available -- it exists for non-EKS or multi-cloud clusters, and to show
// the Provider interface generalizes beyond GitHub.
//
// When this is implemented, it should satisfy provider.Provider exactly
// like internal/provider/github does, with a Scope struct of its own
// (RoleARN, SessionPolicy, Region, DurationSeconds) built by the
// controller from EphemeralCredentialSpec.ProviderConfig.AWS -- the
// controller does not otherwise need to change.
//
// Do not build this before the controller core (rotation, finalizers,
// status) is solid against the github-app provider.
package aws
