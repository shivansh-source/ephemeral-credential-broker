// Package controller implements the EphemeralCredential reconciler --
// design doc section 3.2, "the broker." This is where all the real
// engineering effort concentrates: watch EphemeralCredential resources,
// mint on create/spec-change, rotate before expiry, revoke the previous
// credential after rotation, and clean up on delete via a finalizer.
package controller

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	brokerv1alpha1 "github.com/shivansh-sinha/ephemeral-credential-broker/api/v1alpha1"
	"github.com/shivansh-sinha/ephemeral-credential-broker/internal/provider"
	ghprovider "github.com/shivansh-sinha/ephemeral-credential-broker/internal/provider/github"
)

// handleAnnotationKey stores the previously-minted credential's
// provider.CredentialHandle on the EphemeralCredential itself (base64 JSON),
// so the controller can call Provider.Revoke on the *old* credential after
// a rotation writes the new one. This is deliberately an annotation, not a
// field on EphemeralCredentialStatus: the design doc's CRD (section 3.1)
// keeps status to state/expiresAt/lastRotatedAt/observedGeneration/
// conditions as its public observability surface, and a credential handle
// is private controller bookkeeping, not something an operator should read
// or rely on.
const handleAnnotationKey = "broker.shivansh-sinha.dev/last-credential-handle"

// managedKeysAnnotation records, on the *target Secret*, which of its data
// keys this controller wrote. Without it, changing spec.targetSecret.keys
// would strand the old key in the Secret holding a real credential value
// forever -- the exact "credential outlives its purpose" failure this whole
// project exists to prevent. Tracking the keys we own lets us drop the ones
// we no longer write, while leaving any key someone else added alone.
const managedKeysAnnotation = "broker.shivansh-sinha.dev/managed-keys"

// defaultRotateBefore backstops EphemeralCredentialSpec.RotateBeforeSeconds
// for any object that somehow reaches the reconciler without it set (the
// CRD's own +kubebuilder:default=600 should normally make this unreachable
// once defaulting is admission-controller-enforced).
const defaultRotateBefore = 10 * time.Minute

// minRequeueAfter is the floor for a scheduled rotation requeue, so a
// credential whose rotation window has already opened (or a clock that
// jumped) can't produce a zero/negative RequeueAfter and busy-loop the
// reconciler.
const minRequeueAfter = 5 * time.Second

// EphemeralCredentialReconciler reconciles an EphemeralCredential object.
type EphemeralCredentialReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	Providers *provider.Registry
	Recorder  record.EventRecorder

	// Now defaults to time.Now; overridable in tests for deterministic
	// rotation-window math.
	Now func() time.Time
}

func (r *EphemeralCredentialReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// +kubebuilder:rbac:groups=broker.shivansh-sinha.dev,resources=ephemeralcredentials,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=broker.shivansh-sinha.dev,resources=ephemeralcredentials/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=broker.shivansh-sinha.dev,resources=ephemeralcredentials/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile implements the loop described in design doc section 3.2 and
// built out weekend-by-weekend in section 7:
//
//   - On create / spec change: mint via the configured provider, write
//     targetSecret, set status.expiresAt and state: Active.
//   - Rotation: requeue so that rotateBeforeSeconds before expiry, the
//     controller re-mints and updates the Secret in place; consumers
//     reading the Secret see updated contents with no interruption.
//   - Expiry / deletion: a finalizer removes targetSecret when the
//     EphemeralCredential is deleted; if a credential is not renewed and
//     passes its expiry, the Secret is removed too.
//   - Status: report state, expiresAt, lastRotatedAt, and conditions on
//     every reconcile.
func (r *EphemeralCredentialReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var ec brokerv1alpha1.EphemeralCredential
	if err := r.Get(ctx, req.NamespacedName, &ec); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching EphemeralCredential: %w", err)
	}

	if !ec.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, &ec)
	}

	// Add the finalizer before minting anything, so a credential is never
	// created that a later delete couldn't clean up.
	if !controllerutil.ContainsFinalizer(&ec, brokerv1alpha1.FinalizerName) {
		controllerutil.AddFinalizer(&ec, brokerv1alpha1.FinalizerName)
		if err := r.Update(ctx, &ec); err != nil {
			return ctrl.Result{}, fmt.Errorf("adding finalizer: %w", err)
		}
		// Report Pending straight away rather than leaving status.state
		// empty until the first mint lands: an operator running `kubectl
		// get ephemeralcredentials` on a resource whose very first mint is
		// slow (or is about to fail) should see "Pending", not a blank.
		if ec.Status.State == "" {
			ec.Status.State = brokerv1alpha1.StatePending
			setReadyCondition(&ec, metav1.ConditionFalse, brokerv1alpha1.ReasonPending,
				"accepted; waiting for the first mint")
			if err := r.Status().Update(ctx, &ec); err != nil {
				return ctrl.Result{}, fmt.Errorf("setting initial Pending status: %w", err)
			}
		}
		return ctrl.Result{Requeue: true}, nil
	}

	prov, ok := r.Providers.Get(string(ec.Spec.Provider))
	if !ok {
		return r.failStatus(ctx, &ec, brokerv1alpha1.ReasonProviderNotFound,
			fmt.Sprintf("no provider registered for %q -- is it implemented and wired up in cmd/main.go?", ec.Spec.Provider),
			nil, false) // not retryable: nothing changes until the spec does
	}

	now := r.now()
	rotateBefore, _ := clampRotateBefore(requestedRotateBefore(&ec), grantedLifetime(&ec))

	needsMint := ec.Status.ExpiresAt == nil ||
		ec.Generation != ec.Status.ObservedGeneration ||
		!now.Add(rotateBefore).Before(ec.Status.ExpiresAt.Time)

	if !needsMint {
		// The credential is valid and outside its rotation window -- but
		// that only means anything if the Secret holding it still exists.
		// Someone deleting the target Secret (or a namespace cleanup tool
		// sweeping it) must not leave the workload credential-less until
		// the next rotation window happens to open, which could be most of
		// an hour away. The Owns(&corev1.Secret{}) watch brings us here;
		// this check is what actually repairs it.
		exists, err := r.targetSecretExists(ctx, &ec)
		if err != nil {
			return ctrl.Result{}, err
		}
		if exists {
			requeueAfter := ec.Status.ExpiresAt.Time.Add(-rotateBefore).Sub(now)
			if requeueAfter < minRequeueAfter {
				requeueAfter = minRequeueAfter
			}
			return ctrl.Result{RequeueAfter: requeueAfter}, nil
		}
		logger.Info("target secret is missing; re-minting to restore it",
			"secret", ec.Spec.TargetSecret.Name, "namespace", ec.Namespace)
		r.event(&ec, corev1.EventTypeWarning, brokerv1alpha1.ReasonSecretMissing,
			fmt.Sprintf("target secret %q was missing; re-minting to restore it", ec.Spec.TargetSecret.Name))
		needsMint = true
	}

	previousHandle, hadPreviousHandle := decodeHandle(ec.Annotations[handleAnnotationKey])
	isRotation := ec.Status.ExpiresAt != nil

	scope, err := buildScope(ctx, r.Client, ec.Namespace, ec.Spec)
	if err != nil {
		return r.failStatus(ctx, &ec, brokerv1alpha1.ReasonInvalidConfig, err.Error(), err, true)
	}

	mintResult, err := prov.Mint(ctx, provider.MintRequest{
		Scope:     scope,
		TTL:       time.Duration(ec.Spec.TTLSeconds) * time.Second,
		Namespace: ec.Namespace,
		Name:      ec.Name,
	})
	if err != nil {
		reason := brokerv1alpha1.ReasonMintFailed
		if isRotation {
			reason = brokerv1alpha1.ReasonRotationFailed
		}
		return r.failStatus(ctx, &ec, reason, err.Error(), err, true)
	}

	if err := r.writeTargetSecret(ctx, &ec, mintResult); err != nil {
		return r.failStatus(ctx, &ec, brokerv1alpha1.ReasonSecretWriteFailed, err.Error(), err, true)
	}

	newHandleEncoded, err := encodeHandle(mintResult.Handle)
	if err != nil {
		// Not fatal to the mint itself (the Secret is already correct) --
		// just means we won't be able to revoke this credential later.
		logger.Error(err, "encoding credential handle for later revoke; continuing without it")
	} else {
		if ec.Annotations == nil {
			ec.Annotations = map[string]string{}
		}
		ec.Annotations[handleAnnotationKey] = newHandleEncoded
		if err := r.Update(ctx, &ec); err != nil {
			return ctrl.Result{}, fmt.Errorf("persisting new credential handle annotation: %w", err)
		}
	}

	expiresAt := metav1.NewTime(mintResult.ExpiresAt)
	rotatedAt := metav1.NewTime(now)
	ec.Status.State = brokerv1alpha1.StateActive
	ec.Status.ExpiresAt = &expiresAt
	ec.Status.LastRotatedAt = &rotatedAt
	ec.Status.ObservedGeneration = ec.Generation
	setReadyCondition(&ec, metav1.ConditionTrue, brokerv1alpha1.ReasonMintSucceeded,
		fmt.Sprintf("minted via %s, expires %s", ec.Spec.Provider, expiresAt.Time.Format(time.RFC3339)))
	if err := r.Status().Update(ctx, &ec); err != nil {
		return ctrl.Result{}, fmt.Errorf("updating status after mint: %w", err)
	}
	r.event(&ec, corev1.EventTypeNormal, brokerv1alpha1.ReasonMintSucceeded,
		fmt.Sprintf("minted credential via %s, expires at %s", ec.Spec.Provider, expiresAt.Time.Format(time.RFC3339)))

	// Revoke the *previous* credential only after the new one is confirmed
	// written and status is updated -- design doc section 4.1: "revoke the
	// old token after the new one is written," so consumers never see a
	// gap. Best-effort: a provider that can't revoke returns
	// provider.ErrNoRevoke, which is expected, not an error worth failing
	// reconcile over.
	if hadPreviousHandle && previousHandle.ProviderName == prov.Name() {
		if err := prov.Revoke(ctx, previousHandle); err != nil && !errors.Is(err, provider.ErrNoRevoke) {
			logger.Error(err, "best-effort revoke of previous credential failed", "provider", prov.Name())
			r.event(&ec, corev1.EventTypeWarning, brokerv1alpha1.ReasonRevokeFailed, err.Error())
		}
	}

	// Schedule the next rotation against the lifetime the provider
	// *actually granted*, not the one the spec asked for -- see
	// clampRotateBefore for why that distinction is load-bearing.
	nextRotateBefore, clamped := clampRotateBefore(requestedRotateBefore(&ec), mintResult.ExpiresAt.Sub(now))
	if clamped {
		msg := fmt.Sprintf(
			"rotateBeforeSeconds=%d is too large for the %s lifetime %s actually granted; "+
				"using %s instead to avoid re-minting on every reconcile",
			ec.Spec.RotateBeforeSeconds, mintResult.ExpiresAt.Sub(now).Round(time.Second),
			ec.Spec.Provider, nextRotateBefore.Round(time.Second))
		logger.Info(msg)
		r.event(&ec, corev1.EventTypeWarning, brokerv1alpha1.ReasonRotationWindowClamped, msg)
	}
	requeueAfter := mintResult.ExpiresAt.Add(-nextRotateBefore).Sub(now)
	if requeueAfter < minRequeueAfter {
		requeueAfter = minRequeueAfter
	}
	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

// requestedRotateBefore is spec.rotateBeforeSeconds as a Duration, with the
// CRD default applied defensively for objects that reach us without it.
func requestedRotateBefore(ec *brokerv1alpha1.EphemeralCredential) time.Duration {
	d := time.Duration(ec.Spec.RotateBeforeSeconds) * time.Second
	if d <= 0 {
		return defaultRotateBefore
	}
	return d
}

// grantedLifetime is how long the credential currently in targetSecret was
// minted for, per status: the expiry the provider granted minus when it was
// minted. Zero when nothing has been minted yet.
func grantedLifetime(ec *brokerv1alpha1.EphemeralCredential) time.Duration {
	if ec.Status.ExpiresAt == nil || ec.Status.LastRotatedAt == nil {
		return 0
	}
	return ec.Status.ExpiresAt.Time.Sub(ec.Status.LastRotatedAt.Time)
}

// clampRotateBefore keeps the rotation window strictly inside the lifetime
// the provider actually granted, returning the effective window and whether
// it had to be reduced.
//
// This is not defensive paranoia -- without it, a spec that looks perfectly
// sensible hot-loops. GitHub grants installation tokens a fixed ~1 hour
// regardless of what spec.ttlSeconds asks for, so
// `ttlSeconds: 7200, rotateBeforeSeconds: 3600` puts every freshly-minted
// token inside its own rotation window the instant it arrives: mint, notice
// we're already in the window, mint again, forever, at whatever floor
// minRequeueAfter sets. That is a self-inflicted denial of service against
// your own GitHub App's rate limit, dressed up as a rotation strategy, and
// it is reachable purely by trusting spec.ttlSeconds -- which the provider
// is free to ignore (see provider.MintResult.ExpiresAt).
//
// Half the granted lifetime is the ceiling: it always leaves a real
// steady-state gap between rotations, whatever the provider granted.
func clampRotateBefore(requested, granted time.Duration) (time.Duration, bool) {
	if requested <= 0 {
		requested = defaultRotateBefore
	}
	if granted <= 0 {
		// Nothing minted yet, so there's no granted lifetime to measure
		// against; trust the spec until the first mint tells us better.
		return requested, false
	}
	if ceiling := granted / 2; requested > ceiling {
		return ceiling, true
	}
	return requested, false
}

// reconcileDelete implements finalizer-based cleanup: best-effort revoke
// the current credential, delete targetSecret, then remove the finalizer
// so the EphemeralCredential itself can be garbage collected.
func (r *EphemeralCredentialReconciler) reconcileDelete(ctx context.Context, ec *brokerv1alpha1.EphemeralCredential) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	if !controllerutil.ContainsFinalizer(ec, brokerv1alpha1.FinalizerName) {
		return ctrl.Result{}, nil
	}

	if prov, ok := r.Providers.Get(string(ec.Spec.Provider)); ok {
		if handle, ok := decodeHandle(ec.Annotations[handleAnnotationKey]); ok && handle.ProviderName == prov.Name() {
			if err := prov.Revoke(ctx, handle); err != nil && !errors.Is(err, provider.ErrNoRevoke) {
				logger.Error(err, "best-effort revoke on delete failed", "provider", prov.Name())
			}
		}
	}

	if err := r.deleteTargetSecret(ctx, ec); err != nil {
		return ctrl.Result{}, err
	}

	controllerutil.RemoveFinalizer(ec, brokerv1alpha1.FinalizerName)
	if err := r.Update(ctx, ec); err != nil {
		return ctrl.Result{}, fmt.Errorf("removing finalizer: %w", err)
	}
	return ctrl.Result{}, nil
}

func (r *EphemeralCredentialReconciler) targetSecretExists(ctx context.Context, ec *brokerv1alpha1.EphemeralCredential) (bool, error) {
	if ec.Spec.TargetSecret.Name == "" {
		return false, nil
	}
	var secret corev1.Secret
	err := r.Get(ctx, types.NamespacedName{Name: ec.Spec.TargetSecret.Name, Namespace: ec.Namespace}, &secret)
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("checking target secret: %w", err)
	}
	return true, nil
}

func (r *EphemeralCredentialReconciler) deleteTargetSecret(ctx context.Context, ec *brokerv1alpha1.EphemeralCredential) error {
	if ec.Spec.TargetSecret.Name == "" {
		return nil
	}
	secret := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{Name: ec.Spec.TargetSecret.Name, Namespace: ec.Namespace}, secret)
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("fetching target secret for deletion: %w", err)
	}
	if err := r.Delete(ctx, secret); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("deleting target secret: %w", err)
	}
	return nil
}

// writeTargetSecret creates or in-place updates spec.targetSecret with the
// provider's mint output, mapped through spec.targetSecret.keys. A logical
// output key with no explicit mapping is written under its own name --
// this lets a minimal CR work without a full keys block, while the design
// doc's own example still shows keys being set explicitly.
//
// Keys this controller previously wrote but no longer writes (because the
// mapping changed, or the provider stopped emitting them) are deleted; keys
// it never wrote are left alone. See managedKeysAnnotation.
func (r *EphemeralCredentialReconciler) writeTargetSecret(ctx context.Context, ec *brokerv1alpha1.EphemeralCredential, mint provider.MintResult) error {
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name:      ec.Spec.TargetSecret.Name,
		Namespace: ec.Namespace,
	}}
	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
		if secret.Data == nil {
			secret.Data = map[string][]byte{}
		}

		written := make([]string, 0, len(mint.Data))
		for logicalKey, value := range mint.Data {
			secretKey := logicalKey
			if mapped, ok := ec.Spec.TargetSecret.Keys[logicalKey]; ok && mapped != "" {
				secretKey = mapped
			}
			secret.Data[secretKey] = value
			written = append(written, secretKey)
		}
		sort.Strings(written)

		for _, stale := range previouslyManagedKeys(secret) {
			if !slices.Contains(written, stale) {
				delete(secret.Data, stale)
			}
		}
		if secret.Annotations == nil {
			secret.Annotations = map[string]string{}
		}
		secret.Annotations[managedKeysAnnotation] = strings.Join(written, ",")

		secret.Type = brokerv1alpha1.TargetSecretType
		return controllerutil.SetControllerReference(ec, secret, r.Scheme)
	})
	if err != nil {
		return fmt.Errorf("writing target secret %q: %w", ec.Spec.TargetSecret.Name, err)
	}
	return nil
}

func previouslyManagedKeys(secret *corev1.Secret) []string {
	raw := secret.Annotations[managedKeysAnnotation]
	if raw == "" {
		return nil
	}
	return strings.Split(raw, ",")
}

// failStatus records a failed mint/rotation attempt and returns a Result
// telling the controller whether to retry.
//
// The important distinction it draws: a failed *rotation* is not the same
// as having no credential. If the credential already in targetSecret hasn't
// actually expired yet, the workload consuming it is still working fine --
// reporting Ready=False and state: Failed there would page someone about a
// system that is, at this moment, healthy. So while the existing credential
// is still valid this reports state: Expiring, keeps Ready=True, and folds
// the rotation error into the Ready message so it survives longer than the
// event does. Only once the credential is genuinely past its expiry does
// this escalate: remove the now-useless Secret, Ready=False, state: Failed.
//
// Non-retryable failures (e.g. an unknown provider name) return a nil error
// with an empty Result, so nothing spins until the spec itself changes.
func (r *EphemeralCredentialReconciler) failStatus(ctx context.Context, ec *brokerv1alpha1.EphemeralCredential, reason, message string, cause error, retryable bool) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	if cause != nil {
		logger.Error(cause, message, "reason", reason)
	} else {
		logger.Info(message, "reason", reason)
	}

	now := r.now()
	credentialStillValid := ec.Status.ExpiresAt != nil && now.Before(ec.Status.ExpiresAt.Time)

	if credentialStillValid {
		ec.Status.State = brokerv1alpha1.StateExpiring
		setReadyCondition(ec, metav1.ConditionTrue, brokerv1alpha1.ReasonRotationFailed,
			fmt.Sprintf("credential in %q is still valid until %s, but the last rotation attempt failed: %s",
				ec.Spec.TargetSecret.Name, ec.Status.ExpiresAt.Time.Format(time.RFC3339), message))
	} else {
		// Past expiry, or nothing ever minted: there is no usable
		// credential, so don't leave a stale one lying around claiming to
		// be one (design doc section 3.2, "Expiry/deletion").
		if ec.Status.ExpiresAt != nil {
			if delErr := r.deleteTargetSecret(ctx, ec); delErr != nil {
				logger.Error(delErr, "failed to remove expired target secret after mint failure")
			}
		}
		ec.Status.State = brokerv1alpha1.StateFailed
		setReadyCondition(ec, metav1.ConditionFalse, reason, message)
	}

	if err := r.Status().Update(ctx, ec); err != nil {
		return ctrl.Result{}, fmt.Errorf("updating status after failure: %w", err)
	}
	r.event(ec, corev1.EventTypeWarning, reason, message)

	if !retryable {
		return ctrl.Result{}, nil
	}
	if cause != nil {
		return ctrl.Result{}, cause // let controller-runtime's rate limiter back off retries
	}
	return ctrl.Result{}, errors.New(message)
}

func (r *EphemeralCredentialReconciler) event(ec *brokerv1alpha1.EphemeralCredential, eventType, reason, message string) {
	if r.Recorder == nil {
		return
	}
	r.Recorder.Event(ec, eventType, reason, message)
}

func setReadyCondition(ec *brokerv1alpha1.EphemeralCredential, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&ec.Status.Conditions, metav1.Condition{
		Type:               brokerv1alpha1.ConditionReady,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: ec.Generation,
	})
}

// storedHandle is the JSON shape persisted (base64-encoded) in
// handleAnnotationKey.
type storedHandle struct {
	ProviderName string `json:"providerName"`
	Opaque       string `json:"opaque"`
}

func encodeHandle(h provider.CredentialHandle) (string, error) {
	sh := storedHandle{ProviderName: h.ProviderName, Opaque: base64.StdEncoding.EncodeToString(h.Opaque)}
	b, err := json.Marshal(sh)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func decodeHandle(raw string) (provider.CredentialHandle, bool) {
	if raw == "" {
		return provider.CredentialHandle{}, false
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return provider.CredentialHandle{}, false
	}
	var sh storedHandle
	if err := json.Unmarshal(b, &sh); err != nil {
		return provider.CredentialHandle{}, false
	}
	opaque, err := base64.StdEncoding.DecodeString(sh.Opaque)
	if err != nil {
		return provider.CredentialHandle{}, false
	}
	return provider.CredentialHandle{ProviderName: sh.ProviderName, Opaque: opaque}, true
}

// buildScope translates spec.providerConfig into the concrete,
// provider-specific Scope value each Provider implementation expects (see
// internal/provider.MintRequest.Scope). This is the one place in the
// codebase that knows about both the CRD API types and a specific
// provider's Scope shape -- providers themselves never import
// api/v1alpha1, and internal/provider never imports any provider package.
func buildScope(ctx context.Context, c client.Client, namespace string, spec brokerv1alpha1.EphemeralCredentialSpec) (any, error) {
	switch spec.Provider {
	case brokerv1alpha1.ProviderGitHubApp:
		return buildGitHubScope(ctx, c, namespace, spec)
	case brokerv1alpha1.ProviderAWSSTS, brokerv1alpha1.ProviderDatabase, brokerv1alpha1.ProviderVault:
		return nil, fmt.Errorf("provider %q is designed but not implemented in v1 -- see design doc section 4 and internal/provider/%s/doc.go", spec.Provider, spec.Provider)
	default:
		return nil, fmt.Errorf("unknown provider %q", spec.Provider)
	}
}

func buildGitHubScope(ctx context.Context, c client.Client, namespace string, spec brokerv1alpha1.EphemeralCredentialSpec) (ghprovider.Scope, error) {
	cfg := spec.ProviderConfig.GitHub
	if cfg == nil {
		return ghprovider.Scope{}, errors.New("provider github-app requires providerConfig.github to be set")
	}
	var secret corev1.Secret
	if err := c.Get(ctx, types.NamespacedName{Name: cfg.AppConfigRef.Name, Namespace: namespace}, &secret); err != nil {
		return ghprovider.Scope{}, fmt.Errorf("fetching appConfigRef secret %q: %w", cfg.AppConfigRef.Name, err)
	}
	appID, ok := secret.Data["appId"]
	if !ok || len(appID) == 0 {
		return ghprovider.Scope{}, fmt.Errorf("secret %q is missing required key %q", cfg.AppConfigRef.Name, "appId")
	}
	privateKey, ok := secret.Data["privateKey"]
	if !ok || len(privateKey) == 0 {
		return ghprovider.Scope{}, fmt.Errorf("secret %q is missing required key %q", cfg.AppConfigRef.Name, "privateKey")
	}
	return ghprovider.Scope{
		AppID:         string(appID),
		PrivateKeyPEM: privateKey,
		Repositories:  cfg.Repositories,
		Permissions:   cfg.Permissions,
	}, nil
}

// SetupWithManager wires this reconciler into a controller-runtime
// Manager: watch EphemeralCredential, and watch owned Secrets so that
// someone deleting/editing the target Secret out from under us triggers a
// re-reconcile that puts it back.
func (r *EphemeralCredentialReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&brokerv1alpha1.EphemeralCredential{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}
