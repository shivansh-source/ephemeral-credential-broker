package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CredentialState is the lifecycle state of an EphemeralCredential, reported
// in status.state. It is the primary thing an operator looks at when they
// run `kubectl get ephemeralcredentials`.
// +kubebuilder:validation:Enum=Pending;Active;Expiring;Failed
type CredentialState string

const (
	// StatePending means the controller has observed the resource but has
	// not yet successfully minted a credential for it.
	StatePending CredentialState = "Pending"
	// StateActive means a credential is minted and written to
	// targetSecret, and the last mint or rotation succeeded.
	StateActive CredentialState = "Active"
	// StateExpiring means the credential in targetSecret is still valid,
	// but rotating it is currently failing. The workload consuming it is
	// fine for now -- the Ready condition stays True and carries the
	// rotation error -- but it will become StateFailed if rotation is
	// still failing when the credential actually expires.
	StateExpiring CredentialState = "Expiring"
	// StateFailed means the last mint or rotation attempt failed and no
	// valid credential is currently guaranteed to be in targetSecret. See
	// status.conditions for the reason.
	StateFailed CredentialState = "Failed"
)

// Condition types set on EphemeralCredential.status.conditions.
const (
	// ConditionReady summarizes whether a valid, unexpired credential is
	// currently present in targetSecret.
	ConditionReady = "Ready"
)

// Condition reasons used with ConditionReady (and surfaced in events).
const (
	ReasonPending               = "Pending"
	ReasonMintSucceeded         = "MintSucceeded"
	ReasonMintFailed            = "MintFailed"
	ReasonRotationFailed        = "RotationFailed"
	ReasonProviderNotFound      = "ProviderNotFound"
	ReasonInvalidConfig         = "InvalidConfig"
	ReasonSecretWriteFailed     = "SecretWriteFailed"
	ReasonSecretMissing         = "TargetSecretMissing"
	ReasonRevokeFailed          = "RevokeFailed"
	ReasonRotationWindowClamped = "RotationWindowClamped"
)

// ProviderName identifies which Provider implementation mints a given
// EphemeralCredential. Only "github-app" is implemented in v1; the rest are
// specified against the Provider interface (see internal/provider) but not
// built -- see design doc section 2 ("Build priority").
// +kubebuilder:validation:Enum=github-app;aws-sts;database;vault
type ProviderName string

const (
	ProviderGitHubApp ProviderName = "github-app"
	ProviderAWSSTS    ProviderName = "aws-sts"
	ProviderDatabase  ProviderName = "database"
	ProviderVault     ProviderName = "vault"
)

// LocalObjectReference is a lightweight reference to another object (always
// a Secret, in this API) in the same namespace as the EphemeralCredential.
// It intentionally mirrors corev1.LocalObjectReference rather than reusing
// it, so this API is not coupled to future changes in the core type.
type LocalObjectReference struct {
	// Name of the referent Secret, in the same namespace.
	Name string `json:"name"`
}

// TargetSecretSpec describes the Secret the minted credential is written
// into, and how the provider's output keys map onto the Secret's data keys.
type TargetSecretSpec struct {
	// Name of the Secret to create/update with the minted credential. It is
	// created in the same namespace as the EphemeralCredential and owned by
	// it (see controller finalizer handling for deletion).
	Name string `json:"name"`

	// Keys maps a provider's logical output key (e.g. "token", "username",
	// "password", "accessKeyId") to the key it is written under in the
	// target Secret's data. A provider decides which logical keys it
	// populates (see each Provider implementation); Keys lets the same
	// provider output land under whatever Secret key names the consuming
	// workload already expects.
	// +optional
	Keys map[string]string `json:"keys,omitempty"`
}

// GitHubProviderConfig configures the github-app provider (v1, implemented).
// See design doc section 4.1.
type GitHubProviderConfig struct {
	// AppConfigRef points at a Secret in the same namespace holding the
	// GitHub App's credentials, under keys "appId" and "privateKey" (PEM).
	// This Secret is the highest-value asset in the whole system -- see
	// docs/THREAT_MODEL.md.
	AppConfigRef LocalObjectReference `json:"appConfigRef"`

	// Repositories the installation token is scoped to. Must already be
	// accessible to the App's installation; the broker does not install
	// the App, it only mints tokens for repos already installed on.
	// +kubebuilder:validation:MinItems=1
	Repositories []string `json:"repositories"`

	// Permissions requested on the installation token, e.g.
	// {"contents": "read", "issues": "read"}. GitHub will refuse to mint a
	// token requesting a permission wider than the App's own installed
	// permissions -- the broker does not second-guess this, per the
	// threat model's "misconfigured scope" note.
	Permissions map[string]string `json:"permissions,omitempty"`
}

// AWSProviderConfig configures the aws-sts provider. Designed in section
// 4.2 of the design doc; NOT implemented in v1 -- see
// internal/provider/aws/doc.go. Kept in the API now so the CRD schema does
// not need a breaking change when the provider is built.
type AWSProviderConfig struct {
	// RoleARN is the IAM role to assume via AssumeRole /
	// AssumeRoleWithWebIdentity.
	RoleARN string `json:"roleArn"`

	// SessionPolicy is an optional inline IAM policy document (JSON) that
	// further restricts the assumed role's permissions for this session.
	// +optional
	SessionPolicy string `json:"sessionPolicy,omitempty"`

	// Region STS calls are made against.
	// +optional
	Region string `json:"region,omitempty"`

	// DurationSeconds is the requested STS session duration (15min to the
	// role's configured max).
	// +optional
	// +kubebuilder:validation:Minimum=900
	DurationSeconds int32 `json:"durationSeconds,omitempty"`
}

// DatabaseProviderConfig configures the database provider. Designed in
// section 4.3 of the design doc; NOT implemented in v1 -- see
// internal/provider/database/doc.go.
type DatabaseProviderConfig struct {
	// Engine is the database engine: "postgres" or "mysql".
	// +kubebuilder:validation:Enum=postgres;mysql
	Engine string `json:"engine"`

	// AdminSecretRef points at a Secret holding admin-level credentials the
	// broker uses to CREATE/DROP the ephemeral database user. Note: this is
	// a significant trust concentration -- see docs/THREAT_MODEL.md.
	AdminSecretRef LocalObjectReference `json:"adminSecretRef"`

	// ConnectionRef points at a Secret or ConfigMap-shaped reference
	// holding the connection host/port/database name to connect to.
	ConnectionRef LocalObjectReference `json:"connectionRef"`

	// Grants are the SQL GRANT statements (or an engine-appropriate
	// equivalent) applied to the newly created ephemeral user.
	Grants []string `json:"grants,omitempty"`
}

// VaultProviderConfig configures the vault provider. Designed in section
// 4.4 of the design doc as the lowest-priority, "probably never built"
// extension point -- see internal/provider/vault/doc.go.
type VaultProviderConfig struct {
	// BackendRef identifies the configured secret backend (Vault mount, or
	// cloud secrets manager) to read from.
	BackendRef LocalObjectReference `json:"backendRef"`

	// Path is the backend-specific path/name of the secret to lease.
	Path string `json:"path"`

	// Renewable indicates whether the broker should renew the existing
	// lease near expiry rather than fetching a brand new one.
	// +optional
	Renewable bool `json:"renewable,omitempty"`
}

// ProviderConfig is a discriminated union keyed by spec.provider: only the
// block matching spec.provider is read by the controller. This keeps a
// single CRD serving all four providers without a schema explosion (design
// doc section 3.1).
type ProviderConfig struct {
	// +optional
	GitHub *GitHubProviderConfig `json:"github,omitempty"`
	// +optional
	AWS *AWSProviderConfig `json:"aws,omitempty"`
	// +optional
	Database *DatabaseProviderConfig `json:"database,omitempty"`
	// +optional
	Vault *VaultProviderConfig `json:"vault,omitempty"`
}

// EphemeralCredentialSpec is the desired state of an ephemeral credential:
// which provider mints it, how long it lives, when to rotate it, and where
// it lands.
//
// The CEL rules below reject at admission time two mistakes that would
// otherwise only surface as a misbehaving controller: a rotation window
// that swallows the whole TTL (which would put every freshly-minted
// credential inside its own rotation window), and a spec.provider with no
// matching providerConfig block. Note that the first rule can only check
// the *requested* TTL -- a provider is free to grant less (GitHub always
// grants ~1h regardless), so the controller clamps the rotation window
// against the actually-granted lifetime too. See clampRotateBefore in
// internal/controller.
//
// +kubebuilder:validation:XValidation:rule="!has(self.rotateBeforeSeconds) || self.rotateBeforeSeconds < self.ttlSeconds",message="rotateBeforeSeconds must be smaller than ttlSeconds"
// +kubebuilder:validation:XValidation:rule="self.provider != 'github-app' || has(self.providerConfig.github)",message="provider github-app requires providerConfig.github"
// +kubebuilder:validation:XValidation:rule="self.provider != 'aws-sts' || has(self.providerConfig.aws)",message="provider aws-sts requires providerConfig.aws"
// +kubebuilder:validation:XValidation:rule="self.provider != 'database' || has(self.providerConfig.database)",message="provider database requires providerConfig.database"
// +kubebuilder:validation:XValidation:rule="self.provider != 'vault' || has(self.providerConfig.vault)",message="provider vault requires providerConfig.vault"
type EphemeralCredentialSpec struct {
	// Provider selects which Provider implementation mints this credential.
	Provider ProviderName `json:"provider"`

	// TTLSeconds is the requested credential lifetime. The provider may
	// grant a shorter lifetime than requested (e.g. GitHub App installation
	// tokens are always ~1 hour regardless of what is requested here) --
	// the actual granted expiry is always what status.expiresAt reports.
	// +kubebuilder:validation:Minimum=60
	TTLSeconds int32 `json:"ttlSeconds"`

	// RotateBeforeSeconds is how long before status.expiresAt the
	// controller re-mints the credential. Must be smaller than TTLSeconds.
	// +kubebuilder:validation:Minimum=30
	// +kubebuilder:default=600
	RotateBeforeSeconds int32 `json:"rotateBeforeSeconds,omitempty"`

	// TargetSecret is the Secret the minted credential is written into.
	TargetSecret TargetSecretSpec `json:"targetSecret"`

	// ProviderConfig carries the provider-specific settings. Only the
	// block matching Provider is read.
	ProviderConfig ProviderConfig `json:"providerConfig"`
}

// EphemeralCredentialStatus is the observed state of an ephemeral
// credential: this is the observability surface described in design doc
// section 3.1 -- `kubectl get ephemeralcredentials` shows state, expiry,
// and last rotation without anyone needing to read the Secret itself.
type EphemeralCredentialStatus struct {
	// State summarizes the credential's lifecycle. See CredentialState.
	// +optional
	State CredentialState `json:"state,omitempty"`

	// ExpiresAt is the actual expiry the provider granted for the current
	// credential (which may be earlier than spec.ttlSeconds would imply).
	// +optional
	ExpiresAt *metav1.Time `json:"expiresAt,omitempty"`

	// LastRotatedAt is when the current credential was minted (initial
	// mint counts as the first rotation).
	// +optional
	LastRotatedAt *metav1.Time `json:"lastRotatedAt,omitempty"`

	// ObservedGeneration is the .metadata.generation last reconciled.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions follow the standard Kubernetes conditions convention.
	// See ConditionReady and the Reason* constants.
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

// EphemeralCredential is the Schema for the ephemeralcredentials API. It is
// the entire user interface of the credential broker: a workload owner
// writes one of these, and the controller mints, rotates, and cleans up the
// underlying credential (design doc section 3.1).
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=ecred;ecreds
// +kubebuilder:printcolumn:name="Provider",type="string",JSONPath=".spec.provider"
// +kubebuilder:printcolumn:name="State",type="string",JSONPath=".status.state"
// +kubebuilder:printcolumn:name="Expires",type="date",JSONPath=".status.expiresAt"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
type EphemeralCredential struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   EphemeralCredentialSpec   `json:"spec,omitempty"`
	Status EphemeralCredentialStatus `json:"status,omitempty"`
}

// EphemeralCredentialList contains a list of EphemeralCredential.
//
// +kubebuilder:object:root=true
type EphemeralCredentialList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EphemeralCredential `json:"items"`
}

func init() {
	SchemeBuilder.Register(&EphemeralCredential{}, &EphemeralCredentialList{})
}

// finalizerName is the finalizer the controller places on every
// EphemeralCredential so it can delete targetSecret (and best-effort call
// Provider.Revoke) before the resource is actually removed.
const FinalizerName = "broker.shivansh-sinha.dev/finalizer"

// TargetSecretType is the type set on every Secret the broker writes. It is
// deliberately Opaque, not the provider-shaped kubernetes.io/... types --
// the broker does not assume how the consuming workload wants to interpret
// the data.
var TargetSecretType = corev1.SecretTypeOpaque
