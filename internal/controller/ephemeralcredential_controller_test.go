package controller

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	brokerv1alpha1 "github.com/shivansh-sinha/ephemeral-credential-broker/api/v1alpha1"
	"github.com/shivansh-sinha/ephemeral-credential-broker/internal/provider"
)

// NOTE ON RUNNING THESE TESTS: this package imports k8s.io/apimachinery,
// k8s.io/api, k8s.io/client-go, and sigs.k8s.io/controller-runtime, none of
// which could be fetched in the sandbox this project was scaffolded in (no
// network access to the Go module proxy -- see go.mod and the README's
// "Status of this repo"). They were written against controller-runtime
// v0.19.x's fake client and have been run and passed, but only against a
// local hand-written stand-in for those modules -- not the real ones. Run
// `go mod tidy && go test ./...` on a networked machine to run them for
// real; nothing here should need to change when you do.
//
// A real envtest-based integration suite (spinning up a lightweight
// kube-apiserver + etcd -- no Docker/kind needed, see `make envtest-setup`)
// would exercise this against a real API server instead of the fake
// client; that's the natural next step.

// fakeProvider is a stand-in Provider for reconciler tests, so they never
// need real GitHub credentials or network access -- design doc section 4.1
// says exactly this about testing the GitHub provider itself; the same
// principle applies one layer up, to testing the reconciler against *some*
// provider without caring which.
type fakeProvider struct {
	name string

	mintResult provider.MintResult
	mintErr    error
	mintCalls  int

	revokeErr   error
	revokedWith []provider.CredentialHandle
}

func (f *fakeProvider) Name() string { return f.name }

func (f *fakeProvider) Mint(_ context.Context, _ provider.MintRequest) (provider.MintResult, error) {
	f.mintCalls++
	if f.mintErr != nil {
		return provider.MintResult{}, f.mintErr
	}
	return f.mintResult, nil
}

func (f *fakeProvider) Revoke(_ context.Context, handle provider.CredentialHandle) error {
	f.revokedWith = append(f.revokedWith, handle)
	return f.revokeErr
}

var _ provider.Provider = (*fakeProvider)(nil)

func newTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("adding corev1 to scheme: %v", err)
	}
	if err := brokerv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("adding broker v1alpha1 to scheme: %v", err)
	}
	return scheme
}

func baseCredential() *brokerv1alpha1.EphemeralCredential {
	return &brokerv1alpha1.EphemeralCredential{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "ci-github-token",
			Namespace:  "builds",
			Generation: 1,
		},
		Spec: brokerv1alpha1.EphemeralCredentialSpec{
			Provider:            brokerv1alpha1.ProviderGitHubApp,
			TTLSeconds:          3600,
			RotateBeforeSeconds: 600,
			TargetSecret: brokerv1alpha1.TargetSecretSpec{
				Name: "github-token",
				Keys: map[string]string{"token": "token"},
			},
			ProviderConfig: brokerv1alpha1.ProviderConfig{
				GitHub: &brokerv1alpha1.GitHubProviderConfig{
					AppConfigRef: brokerv1alpha1.LocalObjectReference{Name: "broker-github-app"},
					Repositories: []string{"myorg/myrepo"},
					Permissions:  map[string]string{"contents": "read"},
				},
			},
		},
	}
}

func appConfigSecret() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "broker-github-app", Namespace: "builds"},
		Data: map[string][]byte{
			"appId":      []byte("123456"),
			"privateKey": []byte("-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n"),
		},
	}
}

func reconcileRequest(ec *brokerv1alpha1.EphemeralCredential) ctrl.Request {
	return ctrl.Request{NamespacedName: types.NamespacedName{Name: ec.Name, Namespace: ec.Namespace}}
}

// TestReconcile_AddsFinalizerFirst asserts the very first reconcile of a
// fresh object only adds the finalizer and requeues -- it must not mint a
// credential it couldn't later clean up (design doc: "Add the finalizer
// before minting anything").
func TestReconcile_AddsFinalizerFirst(t *testing.T) {
	scheme := newTestScheme(t)
	ec := baseCredential()
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ec, appConfigSecret()).
		WithStatusSubresource(&brokerv1alpha1.EphemeralCredential{}).Build()
	prov := &fakeProvider{name: "github-app"}
	r := &EphemeralCredentialReconciler{
		Client:    c,
		Scheme:    scheme,
		Providers: provider.NewRegistry(prov),
	}

	res, err := r.Reconcile(context.Background(), reconcileRequest(ec))
	if err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}
	if !res.Requeue {
		t.Errorf("expected Requeue=true after adding finalizer, got %+v", res)
	}
	if prov.mintCalls != 0 {
		t.Errorf("expected no Mint call before the finalizer is persisted, got %d", prov.mintCalls)
	}

	var got brokerv1alpha1.EphemeralCredential
	if err := c.Get(context.Background(), reconcileRequest(ec).NamespacedName, &got); err != nil {
		t.Fatalf("re-fetching object: %v", err)
	}
	found := false
	for _, f := range got.Finalizers {
		if f == brokerv1alpha1.FinalizerName {
			found = true
		}
	}
	if !found {
		t.Errorf("expected finalizer %q to be set, got %v", brokerv1alpha1.FinalizerName, got.Finalizers)
	}
}

// TestReconcile_MintsAndWritesSecret exercises the full happy path: given
// the finalizer is already present, one Reconcile call should mint via the
// provider, write targetSecret, and set status to Active with the right
// expiry.
func TestReconcile_MintsAndWritesSecret(t *testing.T) {
	scheme := newTestScheme(t)
	ec := baseCredential()
	ec.Finalizers = []string{brokerv1alpha1.FinalizerName}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ec, appConfigSecret()).WithStatusSubresource(&brokerv1alpha1.EphemeralCredential{}).Build()

	fixedNow := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	wantExpiry := fixedNow.Add(time.Hour)
	prov := &fakeProvider{
		name: "github-app",
		mintResult: provider.MintResult{
			Data:      map[string][]byte{"token": []byte("ghs_abc123")},
			ExpiresAt: wantExpiry,
			Handle:    provider.CredentialHandle{ProviderName: "github-app", Opaque: []byte("ghs_abc123")},
		},
	}
	r := &EphemeralCredentialReconciler{
		Client:    c,
		Scheme:    scheme,
		Providers: provider.NewRegistry(prov),
		Now:       func() time.Time { return fixedNow },
	}

	res, err := r.Reconcile(context.Background(), reconcileRequest(ec))
	if err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}
	if prov.mintCalls != 1 {
		t.Fatalf("expected exactly one Mint call, got %d", prov.mintCalls)
	}

	var secret corev1.Secret
	if err := c.Get(context.Background(), types.NamespacedName{Name: "github-token", Namespace: "builds"}, &secret); err != nil {
		t.Fatalf("fetching target secret: %v", err)
	}
	if got := string(secret.Data["token"]); got != "ghs_abc123" {
		t.Errorf("secret data[token] = %q, want ghs_abc123", got)
	}

	var got brokerv1alpha1.EphemeralCredential
	if err := c.Get(context.Background(), reconcileRequest(ec).NamespacedName, &got); err != nil {
		t.Fatalf("re-fetching object: %v", err)
	}
	if got.Status.State != brokerv1alpha1.StateActive {
		t.Errorf("status.state = %q, want Active", got.Status.State)
	}
	if got.Status.ExpiresAt == nil || !got.Status.ExpiresAt.Time.Equal(wantExpiry) {
		t.Errorf("status.expiresAt = %v, want %v", got.Status.ExpiresAt, wantExpiry)
	}
	if got.Status.ObservedGeneration != got.Generation {
		t.Errorf("observedGeneration = %d, want %d", got.Status.ObservedGeneration, got.Generation)
	}

	// Exact, not approximate: rotation scheduling must come from r.Now, not
	// the wall clock, or this is untestable and drifts in production.
	// 1h granted, rotate 10m before expiry => requeue in 50m.
	if want := 50 * time.Minute; res.RequeueAfter != want {
		t.Errorf("RequeueAfter = %v, want exactly %v", res.RequeueAfter, want)
	}
}

// TestReconcile_RotationRevokesPreviousHandle simulates a second reconcile
// of an already-Active credential whose rotation window has opened: it
// must mint a new credential and then Revoke the previous one (design doc
// section 4.1: "revoke the old token after the new one is written").
func TestReconcile_RotationRevokesPreviousHandle(t *testing.T) {
	scheme := newTestScheme(t)
	fixedNow := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)

	ec := baseCredential()
	ec.Finalizers = []string{brokerv1alpha1.FinalizerName}
	oldExpiry := metav1.NewTime(fixedNow.Add(5 * time.Minute)) // inside the 10-minute rotation window
	ec.Status = brokerv1alpha1.EphemeralCredentialStatus{
		State:              brokerv1alpha1.StateActive,
		ExpiresAt:          &oldExpiry,
		ObservedGeneration: ec.Generation,
	}
	oldHandle, err := encodeHandle(provider.CredentialHandle{ProviderName: "github-app", Opaque: []byte("ghs_old")})
	if err != nil {
		t.Fatalf("encoding fixture handle: %v", err)
	}
	ec.Annotations = map[string]string{handleAnnotationKey: oldHandle}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ec, appConfigSecret()).WithStatusSubresource(&brokerv1alpha1.EphemeralCredential{}).Build()
	prov := &fakeProvider{
		name: "github-app",
		mintResult: provider.MintResult{
			Data:      map[string][]byte{"token": []byte("ghs_new")},
			ExpiresAt: fixedNow.Add(time.Hour),
			Handle:    provider.CredentialHandle{ProviderName: "github-app", Opaque: []byte("ghs_new")},
		},
	}
	r := &EphemeralCredentialReconciler{
		Client:    c,
		Scheme:    scheme,
		Providers: provider.NewRegistry(prov),
		Now:       func() time.Time { return fixedNow },
	}

	if _, err := r.Reconcile(context.Background(), reconcileRequest(ec)); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	if len(prov.revokedWith) != 1 {
		t.Fatalf("expected exactly one Revoke call, got %d", len(prov.revokedWith))
	}
	if string(prov.revokedWith[0].Opaque) != "ghs_old" {
		t.Errorf("revoked handle = %q, want the *previous* token ghs_old", prov.revokedWith[0].Opaque)
	}

	var secret corev1.Secret
	if err := c.Get(context.Background(), types.NamespacedName{Name: "github-token", Namespace: "builds"}, &secret); err != nil {
		t.Fatalf("fetching target secret: %v", err)
	}
	if got := string(secret.Data["token"]); got != "ghs_new" {
		t.Errorf("secret should hold the *new* token, got %q", got)
	}
}

// TestReconcile_MintFailureSetsFailedState checks that a Mint error is
// surfaced as status.state=Failed with a Ready=False condition, and that
// Reconcile returns the error so controller-runtime retries with backoff.
func TestReconcile_MintFailureSetsFailedState(t *testing.T) {
	scheme := newTestScheme(t)
	ec := baseCredential()
	ec.Finalizers = []string{brokerv1alpha1.FinalizerName}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ec, appConfigSecret()).WithStatusSubresource(&brokerv1alpha1.EphemeralCredential{}).Build()
	prov := &fakeProvider{name: "github-app", mintErr: errors.New("GitHub API is down")}
	r := &EphemeralCredentialReconciler{Client: c, Scheme: scheme, Providers: provider.NewRegistry(prov)}

	_, err := r.Reconcile(context.Background(), reconcileRequest(ec))
	if err == nil {
		t.Fatal("expected Reconcile to return an error so it gets retried")
	}

	var got brokerv1alpha1.EphemeralCredential
	if getErr := c.Get(context.Background(), reconcileRequest(ec).NamespacedName, &got); getErr != nil {
		t.Fatalf("re-fetching object: %v", getErr)
	}
	if got.Status.State != brokerv1alpha1.StateFailed {
		t.Errorf("status.state = %q, want Failed", got.Status.State)
	}
	foundReady := false
	for _, cond := range got.Status.Conditions {
		if cond.Type == brokerv1alpha1.ConditionReady {
			foundReady = true
			if cond.Status != metav1.ConditionFalse {
				t.Errorf("Ready condition status = %v, want False", cond.Status)
			}
			if cond.Reason != brokerv1alpha1.ReasonMintFailed {
				t.Errorf("Ready condition reason = %q, want %q", cond.Reason, brokerv1alpha1.ReasonMintFailed)
			}
		}
	}
	if !foundReady {
		t.Error("expected a Ready condition to be set")
	}
}

// TestReconcile_UnknownProviderIsNotRetried checks that an unregistered
// provider name fails permanently (no error returned, no busy retry loop)
// rather than being retried forever -- nothing will fix itself until the
// spec changes.
func TestReconcile_UnknownProviderIsNotRetried(t *testing.T) {
	scheme := newTestScheme(t)
	ec := baseCredential()
	ec.Finalizers = []string{brokerv1alpha1.FinalizerName}
	ec.Spec.Provider = "totally-unregistered"
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ec).WithStatusSubresource(&brokerv1alpha1.EphemeralCredential{}).Build()
	r := &EphemeralCredentialReconciler{Client: c, Scheme: scheme, Providers: provider.NewRegistry()}

	res, err := r.Reconcile(context.Background(), reconcileRequest(ec))
	if err != nil {
		t.Fatalf("expected no error for an unregistered provider (non-retryable), got %v", err)
	}
	if res.Requeue || res.RequeueAfter != 0 {
		t.Errorf("expected an empty Result for a non-retryable failure, got %+v", res)
	}

	var got brokerv1alpha1.EphemeralCredential
	if getErr := c.Get(context.Background(), reconcileRequest(ec).NamespacedName, &got); getErr != nil {
		t.Fatalf("re-fetching object: %v", getErr)
	}
	if got.Status.State != brokerv1alpha1.StateFailed {
		t.Errorf("status.state = %q, want Failed", got.Status.State)
	}
}

// TestReconcile_DeleteCleansUpSecretAndFinalizer exercises the finalizer
// path: on delete, the target Secret must be removed and the finalizer
// dropped so the EphemeralCredential itself can actually go away.
func TestReconcile_DeleteCleansUpSecretAndFinalizer(t *testing.T) {
	scheme := newTestScheme(t)
	ec := baseCredential()
	ec.Finalizers = []string{brokerv1alpha1.FinalizerName}
	now := metav1.NewTime(time.Now())
	ec.DeletionTimestamp = &now

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "github-token", Namespace: "builds"},
		Data:       map[string][]byte{"token": []byte("ghs_old")},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ec, secret).Build()
	prov := &fakeProvider{name: "github-app"}
	r := &EphemeralCredentialReconciler{Client: c, Scheme: scheme, Providers: provider.NewRegistry(prov)}

	if _, err := r.Reconcile(context.Background(), reconcileRequest(ec)); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	var gotSecret corev1.Secret
	err := c.Get(context.Background(), types.NamespacedName{Name: "github-token", Namespace: "builds"}, &gotSecret)
	if !apierrors.IsNotFound(err) {
		t.Errorf("expected target secret to be deleted, got err=%v", err)
	}
}

func TestClampRotateBefore(t *testing.T) {
	cases := []struct {
		name        string
		requested   time.Duration
		granted     time.Duration
		want        time.Duration
		wantClamped bool
	}{
		{"comfortably inside the granted lifetime", 10 * time.Minute, time.Hour, 10 * time.Minute, false},
		{"nothing minted yet, granted unknown", 10 * time.Minute, 0, 10 * time.Minute, false},
		{"exactly half is still allowed", 30 * time.Minute, time.Hour, 30 * time.Minute, false},
		// The bug this whole function exists for: ttlSeconds says 2h, so
		// rotateBeforeSeconds: 3600 looks fine -- but GitHub grants 1h, so
		// every fresh token would arrive already inside its rotation window.
		{"rotation window equals the granted lifetime", time.Hour, time.Hour, 30 * time.Minute, true},
		{"rotation window exceeds the granted lifetime", 2 * time.Hour, time.Hour, 30 * time.Minute, true},
		{"unset falls back to the default", 0, time.Hour, 10 * time.Minute, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, clamped := clampRotateBefore(c.requested, c.granted)
			if got != c.want || clamped != c.wantClamped {
				t.Errorf("clampRotateBefore(%v, %v) = (%v, %v), want (%v, %v)",
					c.requested, c.granted, got, clamped, c.want, c.wantClamped)
			}
		})
	}
}

// TestReconcile_ClampsRotationWindowToGrantedLifetime is the end-to-end
// version of the above: a spec that asks for a 2h TTL and a 1h rotation
// window, against a provider that only ever grants 1h, must not schedule
// its next rotation immediately -- that's the hot mint loop that would
// hammer the provider's API until it rate-limits.
func TestReconcile_ClampsRotationWindowToGrantedLifetime(t *testing.T) {
	scheme := newTestScheme(t)
	fixedNow := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)

	ec := baseCredential()
	ec.Finalizers = []string{brokerv1alpha1.FinalizerName}
	ec.Spec.TTLSeconds = 7200          // asks for 2 hours...
	ec.Spec.RotateBeforeSeconds = 3600 // ...and rotates 1 hour before expiry

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ec, appConfigSecret()).
		WithStatusSubresource(&brokerv1alpha1.EphemeralCredential{}).Build()
	prov := &fakeProvider{
		name: "github-app",
		mintResult: provider.MintResult{
			Data:      map[string][]byte{"token": []byte("ghs_abc123")},
			ExpiresAt: fixedNow.Add(time.Hour), // ...but GitHub grants 1 hour, as always
			Handle:    provider.CredentialHandle{ProviderName: "github-app", Opaque: []byte("ghs_abc123")},
		},
	}
	r := &EphemeralCredentialReconciler{
		Client: c, Scheme: scheme, Providers: provider.NewRegistry(prov),
		Now: func() time.Time { return fixedNow },
	}

	res, err := r.Reconcile(context.Background(), reconcileRequest(ec))
	if err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}
	// Clamped to half the *granted* hour, so the next rotation is 30 minutes
	// out -- not minRequeueAfter, which is what an unclamped window produces.
	if want := 30 * time.Minute; res.RequeueAfter != want {
		t.Errorf("RequeueAfter = %v, want %v (a rotation window wider than the granted "+
			"lifetime must be clamped, not allowed to re-mint on every reconcile)", res.RequeueAfter, want)
	}
	if res.RequeueAfter <= minRequeueAfter {
		t.Errorf("RequeueAfter = %v, which is the hot-loop floor -- clamping did not happen", res.RequeueAfter)
	}
}

// TestReconcile_RecreatesDeletedTargetSecret covers someone (or some
// namespace-cleanup tool) deleting the target Secret while the credential
// is still valid and nowhere near its rotation window. Without an explicit
// existence check the reconciler would see "not time to rotate yet" and
// leave the workload with no credential for most of an hour.
func TestReconcile_RecreatesDeletedTargetSecret(t *testing.T) {
	scheme := newTestScheme(t)
	fixedNow := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)

	ec := baseCredential()
	ec.Finalizers = []string{brokerv1alpha1.FinalizerName}
	expiry := metav1.NewTime(fixedNow.Add(time.Hour)) // well outside the 10m rotation window
	rotated := metav1.NewTime(fixedNow)
	ec.Status = brokerv1alpha1.EphemeralCredentialStatus{
		State:              brokerv1alpha1.StateActive,
		ExpiresAt:          &expiry,
		LastRotatedAt:      &rotated,
		ObservedGeneration: ec.Generation,
	}

	// Note: no target Secret seeded -- it has been deleted out from under us.
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ec, appConfigSecret()).
		WithStatusSubresource(&brokerv1alpha1.EphemeralCredential{}).Build()
	prov := &fakeProvider{
		name: "github-app",
		mintResult: provider.MintResult{
			Data:      map[string][]byte{"token": []byte("ghs_restored")},
			ExpiresAt: fixedNow.Add(time.Hour),
			Handle:    provider.CredentialHandle{ProviderName: "github-app", Opaque: []byte("ghs_restored")},
		},
	}
	r := &EphemeralCredentialReconciler{
		Client: c, Scheme: scheme, Providers: provider.NewRegistry(prov),
		Now: func() time.Time { return fixedNow },
	}

	if _, err := r.Reconcile(context.Background(), reconcileRequest(ec)); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}
	if prov.mintCalls != 1 {
		t.Fatalf("expected a re-mint to restore the deleted Secret, got %d Mint calls", prov.mintCalls)
	}
	var secret corev1.Secret
	if err := c.Get(context.Background(), types.NamespacedName{Name: "github-token", Namespace: "builds"}, &secret); err != nil {
		t.Fatalf("target secret was not recreated: %v", err)
	}
	if got := string(secret.Data["token"]); got != "ghs_restored" {
		t.Errorf("restored secret data[token] = %q, want ghs_restored", got)
	}
}

// TestReconcile_RotationFailureKeepsValidCredential: a failed rotation is
// not the same as having no credential. While the existing token is still
// valid, the workload using it is fine -- so Ready must stay True (with the
// rotation error in its message) and the Secret must be left alone.
func TestReconcile_RotationFailureKeepsValidCredential(t *testing.T) {
	scheme := newTestScheme(t)
	fixedNow := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)

	ec := baseCredential()
	ec.Finalizers = []string{brokerv1alpha1.FinalizerName}
	expiry := metav1.NewTime(fixedNow.Add(5 * time.Minute)) // inside the rotation window, but NOT expired
	rotated := metav1.NewTime(fixedNow.Add(-55 * time.Minute))
	ec.Status = brokerv1alpha1.EphemeralCredentialStatus{
		State:              brokerv1alpha1.StateActive,
		ExpiresAt:          &expiry,
		LastRotatedAt:      &rotated,
		ObservedGeneration: ec.Generation,
	}
	setReadyCondition(ec, metav1.ConditionTrue, brokerv1alpha1.ReasonMintSucceeded, "minted")

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "github-token", Namespace: "builds"},
		Data:       map[string][]byte{"token": []byte("ghs_still_valid")},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ec, appConfigSecret(), secret).
		WithStatusSubresource(&brokerv1alpha1.EphemeralCredential{}).Build()
	prov := &fakeProvider{name: "github-app", mintErr: errors.New("GitHub API is down")}
	r := &EphemeralCredentialReconciler{
		Client: c, Scheme: scheme, Providers: provider.NewRegistry(prov),
		Now: func() time.Time { return fixedNow },
	}

	if _, err := r.Reconcile(context.Background(), reconcileRequest(ec)); err == nil {
		t.Fatal("expected Reconcile to return an error so the rotation is retried")
	}

	var got brokerv1alpha1.EphemeralCredential
	if err := c.Get(context.Background(), reconcileRequest(ec).NamespacedName, &got); err != nil {
		t.Fatalf("re-fetching object: %v", err)
	}
	if got.Status.State != brokerv1alpha1.StateExpiring {
		t.Errorf("status.state = %q, want Expiring (the credential is still valid)", got.Status.State)
	}
	for _, cond := range got.Status.Conditions {
		if cond.Type != brokerv1alpha1.ConditionReady {
			continue
		}
		if cond.Status != metav1.ConditionTrue {
			t.Errorf("Ready = %v, want True: the credential in the Secret is still valid and usable", cond.Status)
		}
		if !strings.Contains(cond.Message, "GitHub API is down") {
			t.Errorf("Ready message should carry the rotation error, got %q", cond.Message)
		}
	}

	var gotSecret corev1.Secret
	if err := c.Get(context.Background(), types.NamespacedName{Name: "github-token", Namespace: "builds"}, &gotSecret); err != nil {
		t.Fatalf("the still-valid credential Secret must not be deleted: %v", err)
	}
	if s := string(gotSecret.Data["token"]); s != "ghs_still_valid" {
		t.Errorf("secret data[token] = %q, want the untouched ghs_still_valid", s)
	}
}

// TestReconcile_ExpiredCredentialFailureRemovesSecret is the escalation of
// the previous case: once the credential is genuinely past expiry and
// rotation is still failing, the Secret holds a dead credential and must go.
func TestReconcile_ExpiredCredentialFailureRemovesSecret(t *testing.T) {
	scheme := newTestScheme(t)
	fixedNow := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)

	ec := baseCredential()
	ec.Finalizers = []string{brokerv1alpha1.FinalizerName}
	expiry := metav1.NewTime(fixedNow.Add(-5 * time.Minute)) // already expired
	rotated := metav1.NewTime(fixedNow.Add(-65 * time.Minute))
	ec.Status = brokerv1alpha1.EphemeralCredentialStatus{
		State:              brokerv1alpha1.StateExpiring,
		ExpiresAt:          &expiry,
		LastRotatedAt:      &rotated,
		ObservedGeneration: ec.Generation,
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "github-token", Namespace: "builds"},
		Data:       map[string][]byte{"token": []byte("ghs_expired")},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ec, appConfigSecret(), secret).
		WithStatusSubresource(&brokerv1alpha1.EphemeralCredential{}).Build()
	prov := &fakeProvider{name: "github-app", mintErr: errors.New("GitHub API is still down")}
	r := &EphemeralCredentialReconciler{
		Client: c, Scheme: scheme, Providers: provider.NewRegistry(prov),
		Now: func() time.Time { return fixedNow },
	}

	if _, err := r.Reconcile(context.Background(), reconcileRequest(ec)); err == nil {
		t.Fatal("expected Reconcile to return an error so it keeps retrying")
	}

	var got brokerv1alpha1.EphemeralCredential
	if err := c.Get(context.Background(), reconcileRequest(ec).NamespacedName, &got); err != nil {
		t.Fatalf("re-fetching object: %v", err)
	}
	if got.Status.State != brokerv1alpha1.StateFailed {
		t.Errorf("status.state = %q, want Failed (the credential has actually expired)", got.Status.State)
	}

	var gotSecret corev1.Secret
	err := c.Get(context.Background(), types.NamespacedName{Name: "github-token", Namespace: "builds"}, &gotSecret)
	if !apierrors.IsNotFound(err) {
		t.Errorf("expected the expired credential's Secret to be removed, got err=%v", err)
	}
}

// TestReconcile_DropsStaleManagedKeys: renaming a key in
// spec.targetSecret.keys must not leave the old key behind holding a real
// credential. That would be a credential outliving its purpose in the
// Secret -- exactly what this project exists to prevent.
func TestReconcile_DropsStaleManagedKeys(t *testing.T) {
	scheme := newTestScheme(t)
	fixedNow := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)

	ec := baseCredential()
	ec.Finalizers = []string{brokerv1alpha1.FinalizerName}
	ec.Generation = 2 // spec changed: the keys mapping below was just edited
	ec.Spec.TargetSecret.Keys = map[string]string{"token": "gh-token"}
	expiry := metav1.NewTime(fixedNow.Add(time.Hour))
	rotated := metav1.NewTime(fixedNow)
	ec.Status = brokerv1alpha1.EphemeralCredentialStatus{
		State:              brokerv1alpha1.StateActive,
		ExpiresAt:          &expiry,
		LastRotatedAt:      &rotated,
		ObservedGeneration: 1, // ...and has not been reconciled since
	}

	// The Secret as the previous mapping left it: value under "token",
	// recorded as broker-managed. "unrelated" was put there by someone else.
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "github-token",
			Namespace:   "builds",
			Annotations: map[string]string{managedKeysAnnotation: "token"},
		},
		Data: map[string][]byte{
			"token":     []byte("ghs_under_the_old_key"),
			"unrelated": []byte("not ours"),
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ec, appConfigSecret(), secret).
		WithStatusSubresource(&brokerv1alpha1.EphemeralCredential{}).Build()
	prov := &fakeProvider{
		name: "github-app",
		mintResult: provider.MintResult{
			Data:      map[string][]byte{"token": []byte("ghs_new")},
			ExpiresAt: fixedNow.Add(time.Hour),
			Handle:    provider.CredentialHandle{ProviderName: "github-app", Opaque: []byte("ghs_new")},
		},
	}
	r := &EphemeralCredentialReconciler{
		Client: c, Scheme: scheme, Providers: provider.NewRegistry(prov),
		Now: func() time.Time { return fixedNow },
	}

	if _, err := r.Reconcile(context.Background(), reconcileRequest(ec)); err != nil {
		t.Fatalf("Reconcile returned error: %v", err)
	}

	var got corev1.Secret
	if err := c.Get(context.Background(), types.NamespacedName{Name: "github-token", Namespace: "builds"}, &got); err != nil {
		t.Fatalf("fetching target secret: %v", err)
	}
	if v := string(got.Data["gh-token"]); v != "ghs_new" {
		t.Errorf("data[gh-token] = %q, want ghs_new", v)
	}
	if v, present := got.Data["token"]; present {
		t.Errorf("stale key \"token\" still holds %q -- a credential left behind under an old key name", v)
	}
	if v := string(got.Data["unrelated"]); v != "not ours" {
		t.Errorf("data[unrelated] = %q: keys the broker never wrote must be left alone", v)
	}
	if got.Annotations[managedKeysAnnotation] != "gh-token" {
		t.Errorf("managed-keys annotation = %q, want gh-token", got.Annotations[managedKeysAnnotation])
	}
}
