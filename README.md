# Ephemeral Credential Broker for Kubernetes

A Kubernetes controller that replaces long-lived secrets with short-lived,
scope-limited, auto-expiring credentials minted on demand.

*Portfolio project, not a startup: this capability is commoditized by cloud
providers and HashiCorp Vault. This project demonstrates the pattern
cleanly with an honest threat model; it does not sell it. See
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).*

## The problem

Kubernetes Secrets are base64-encoded, not encrypted at rest by default.
Anything with read access to Secrets in a namespace can read them in
plaintext, and cluster-scoped tooling (backup systems, log shippers, policy
engines, observability agents) frequently reads across namespaces. A
long-lived credential sitting in a Secret is a standing liability: it
doesn't expire, it's usually over-scoped relative to what the one workload
that needs it actually uses, it's widely visible to anything that can read
Secrets, and revoking it often means revoking something bigger than
intended (a whole user session, a shared key).

The fix is well-understood: don't store long-lived credentials in the
cluster. Mint short-lived, narrowly-scoped credentials on demand, deliver
them to the workload that needs them, rotate them before they expire, and
delete them when they're no longer needed. This project implements that
pattern as a Kubernetes controller.

## Architecture

```
                    ┌─────────────────────────┐
  operator writes   │   EphemeralCredential    │   status: state, expiresAt,
  ───────────────►  │   (the entire user       │   lastRotatedAt, conditions
                     │   interface)             │  ◄──────────────────────┐
                    └────────────┬─────────────┘                          │
                                 │ watched by                             │
                                 ▼                                        │
                    ┌─────────────────────────┐    Mint / Revoke   ┌──────┴──────┐
                    │   the controller         │ ──────────────►   │  Provider   │
                    │   (reconcile loop:       │                   │  interface  │
                    │   mint, rotate, expire,   │ ◄──────────────   │  (v1: only  │
                    │   finalize)               │   credential,      │  github-app)│
                    └────────────┬─────────────┘   expiry            └─────────────┘
                                 │ writes / rotates
                                 ▼
                    ┌─────────────────────────┐
                    │   target Secret          │   consumed by the
                    │   (spec.targetSecret)     │ ─ workload that needs
                    └─────────────────────────┘   the credential
```

Three pieces, matched one-to-one to the code:

- **The CRD** (`api/v1alpha1/ephemeralcredential_types.go`,
  `config/crd/bases/`) -- `EphemeralCredential` is the entire user
  interface. A workload owner writes one; the controller does the rest.
  `providerConfig` is a discriminated union keyed by `spec.provider`, so one
  CRD serves four possible providers without a schema explosion.
- **The controller** (`internal/controller/`) -- a controller-runtime
  reconciler: mint on create/spec-change, requeue to rotate before expiry,
  revoke the previous credential once the new one is written, clean up via
  a finalizer on delete, and report `state`/`expiresAt`/`lastRotatedAt`/
  `conditions` on every reconcile so credential lifecycle is inspectable
  with `kubectl get ephemeralcredentials` instead of opaque.
- **The provider interface** (`internal/provider/`) -- the design decision
  that lets this support four credential systems without over-building any
  of them. `Provider` has exactly three methods: `Name`, `Mint`, `Revoke`.
  **v1 ships exactly one implementation: GitHub App installation tokens**
  (`internal/provider/github/`). AWS STS, database credentials, and
  arbitrary vault secrets are fully specified against the same interface
  (see `internal/provider/{aws,database,vault}/doc.go` and the design doc)
  but deliberately not built -- see "Roadmap" below.

The full design rationale -- CRD field-by-field notes, each provider's
exact API sequence, the build order this was written in, and the reasoning
behind "one provider in v1"-- lives in the original design document this
repo was built from; see the docstrings throughout `internal/` and
`api/v1alpha1/` for the parts of it that matter to reading the code.

## Behaviour worth knowing about

Four decisions in the reconciler that aren't obvious from the CRD, each one
there because the obvious alternative is wrong:

- **The rotation window is clamped to the lifetime the provider actually
  granted, not the one you asked for.** GitHub hands out ~1h installation
  tokens no matter what `ttlSeconds` says. So `ttlSeconds: 7200` with
  `rotateBeforeSeconds: 3600` -- a spec that passes every field-level
  validation and looks entirely reasonable -- would put every freshly-minted
  token inside its own rotation window the moment it arrived, and re-mint on
  every single reconcile until GitHub rate-limited the App. The controller
  caps the window at half the granted lifetime and emits a
  `RotationWindowClamped` warning event when it has to.
- **A failed rotation is not the same as having no credential.** If the
  token in the Secret is still valid, the workload using it is fine, so the
  controller reports `state: Expiring` and keeps `Ready=True` -- with the
  rotation error folded into the condition message -- rather than paging
  someone about a system that currently works. It escalates to `Failed`,
  and deletes the Secret, only once the credential is genuinely past expiry.
- **Deleting the target Secret gets it back immediately.** The `Owns` watch
  brings the reconciler back, but "not time to rotate yet" would otherwise
  short-circuit it and leave the workload credential-less until the rotation
  window opened, potentially most of an hour later. The controller checks the
  Secret actually exists before deciding there's nothing to do.
- **Renaming a key in `targetSecret.keys` removes the old one.** The
  controller records which Secret data keys it wrote (in a
  `broker.shivansh-sinha.dev/managed-keys` annotation on the Secret) and
  deletes the ones it no longer writes. Otherwise a mapping change would
  strand a live credential under the old key forever -- precisely the
  "credential outlives its purpose" failure this project exists to prevent.
  Keys the broker never wrote are left alone.

## Quickstart

1. Register a GitHub App, install it on the repositories you want the
   broker to be able to mint tokens for, and grant it whatever permissions
   (`contents: read`, `issues: read`, etc.) your workloads need.
2. Install the CRD and deploy the controller:
   ```
   kubectl apply -f dist/install.yaml
   ```
   (or `make docker-build docker-push deploy IMG=<your-registry>/ephemeral-credential-broker:<tag>`
   to build and push your own image first -- `dist/install.yaml` ships with
   a placeholder `image:` field.)
3. Create the App credentials Secret the broker reads from:
   ```
   kubectl create secret generic broker-github-app \
     --from-literal=appId=<your App ID> \
     --from-file=privateKey=<path to your App's private-key.pem> \
     -n builds
   ```
4. Apply an `EphemeralCredential` (see
   `config/samples/broker_v1alpha1_ephemeralcredential.yaml`):
   ```
   kubectl apply -f config/samples/broker_v1alpha1_ephemeralcredential.yaml
   kubectl get ephemeralcredentials -n builds
   kubectl get secret github-token -n builds -o jsonpath='{.data.token}' | base64 -d
   ```

## Status of this repo

Every file in this repo -- the CRD types, the reconciler, the GitHub
provider, the manifests, both docs -- was written out in full and has now
been verified against the *real* dependency graph (`go mod tidy` on a
networked machine, committing the resulting `go.sum`) rather than only the
offline stand-in it was originally scaffolded against:

- `go build ./...`, `go vet ./...`, and `go test ./...` all pass against
  the genuine `k8s.io/api`, `k8s.io/apimachinery`, `k8s.io/client-go`, and
  `sigs.k8s.io/controller-runtime` v0.19.3 -- the same versions CI
  (`.github/workflows/ci.yml`) installs.
- All 17 tests (5 provider + 12 reconciler) pass: `internal/provider` and
  `internal/provider/github` exercise real RS256 JWT signing against a
  generated test key, a mocked GitHub API (httptest), and signature
  verification against the key's public half; `internal/controller`
  covers finalizer-before-mint ordering, mint-and-write-secret, rotation
  with revoke-the-old-token-after-the-new-one-lands, the rotation-window
  clamp, recreating a deleted target Secret, rotation failure keeping a
  still-valid credential Ready, escalation to `Failed` once it actually
  expires, stale-key cleanup, an unknown provider failing without
  retry-looping, and delete cleaning up the Secret and finalizer.
- `zz_generated.deepcopy.go` and `config/crd/bases/*.yaml` are still
  hand-written to match what `controller-gen` would produce, rather than
  generated by it -- run `make manifests generate` once `controller-gen`
  is available to confirm they match exactly.
- Not yet run: `docker build` (needs a local Docker daemon) and
  `make envtest-setup`, which gets a real (if lightweight)
  kube-apiserver + etcd to run integration tests against next, with no
  Docker/kind cluster required.

See [docs/STATUS.md](docs/STATUS.md) for a fuller snapshot of what's built,
what's tested, and what's left.

## Roadmap

- **v1 (this repo): GitHub App installation tokens.** Done.
- **AWS STS temporary credentials** -- fully specified
  (`internal/provider/aws/doc.go`), not built. On EKS this already exists
  natively as IRSA / EKS Pod Identity; this provider's honest reason to
  exist is non-EKS/multi-cloud clusters, and to show the interface
  generalizes.
- **Database credentials** (short-lived DB users/passwords) -- fully
  specified (`internal/provider/database/doc.go`), not built. The hardest
  of the three: cleanup has to survive controller restarts, or an orphaned
  DB user is a standing security hole. Do this only once the controller
  core is rock-solid against the GitHub provider.
- **Arbitrary vault secrets** -- specified
  (`internal/provider/vault/doc.go`) as the lowest-priority, "maybe never"
  extension point. This is External Secrets Operator's entire job; building
  it has no good answer to "why not just use ESO" for a portfolio project.

## License

MIT -- see [LICENSE](LICENSE).
