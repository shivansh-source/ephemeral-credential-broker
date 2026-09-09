# Project status

A snapshot of what's built, what's verified, and what's left, as of this
writing. See the [README](../README.md) for architecture and the
[threat model](THREAT_MODEL.md) for what the controller does and doesn't
defend against.

## What's built

| Piece | Location | State |
|---|---|---|
| `EphemeralCredential` CRD types | `api/v1alpha1/` | Done, hand-written deepcopy |
| CRD YAML | `config/crd/bases/` | Done, hand-written to match `controller-gen` output |
| Reconciler (mint/rotate/revoke/finalize) | `internal/controller/` | Done |
| Provider interface | `internal/provider/provider.go` | Done |
| GitHub App provider | `internal/provider/github/` | Done, only implementation shipped in v1 |
| AWS STS, database, vault providers | `internal/provider/{aws,database,vault}/doc.go` | Specified, not built (roadmap) |
| RBAC, sample CR, kustomize manifests | `config/rbac/`, `config/samples/`, `config/default/` | Done |
| Dockerfile, Makefile | repo root | Done |
| Install manifest | `dist/install.yaml` | Done |
| CI (`go vet`, `go test -race`, build, docker build) | `.github/workflows/ci.yml` | Done, green as of the go.sum fix below |
| README, threat model | `README.md`, `docs/THREAT_MODEL.md` | Done |

## What's verified

- `go build ./...`, `go vet ./...`, and `go test ./...` all pass against
  the real `k8s.io/api`, `k8s.io/apimachinery`, `k8s.io/client-go`, and
  `sigs.k8s.io/controller-runtime` v0.19.3 -- `go.sum` is now committed,
  so this no longer depends on hand-maintained indirect requires.
- 17 tests pass: 5 in `internal/provider/github` (real RS256 JWT signing,
  a mocked GitHub API, signature verification), 12 in
  `internal/controller` (finalizer-before-mint, mint-and-write-secret,
  rotation with revoke-after-write, the rotation-window clamp, recreating
  a deleted target Secret, rotation failure keeping a still-valid
  credential `Ready`, escalation to `Failed` past actual expiry,
  stale-key cleanup on a renamed `targetSecret.keys` mapping, an unknown
  provider failing without retry-looping, and delete cleaning up the
  Secret and finalizer).

## What's not verified yet

- `docker build` (needs a local Docker daemon; not run in this pass).
- `make envtest-setup` / an envtest-based integration suite against a
  real (lightweight) kube-apiserver + etcd -- exercises the reconciler
  against the genuine API server instead of the fake client.
- `make manifests generate` against a real `controller-gen`, to confirm
  the hand-written CRD YAML and `zz_generated.deepcopy.go` match exactly
  what generation would produce.

## CI fix (this pass)

CI was failing on every check because `go.mod` listed only direct
requires by hand (no `go.sum`, no indirect requires) -- written that way
because the sandbox this project was scaffolded in had no network access
to the Go module proxy. Running `go mod tidy` on a networked machine
resolved and locked the real dependency graph; that also surfaced one
actual test bug: `TestReconcile_AddsFinalizerFirst` built its fake
client without `.WithStatusSubresource(&brokerv1alpha1.EphemeralCredential{})`,
which every other reconciler test registers. Since the CRD has a real
`+kubebuilder:subresource:status`, the fake client correctly rejects a
status-subresource write on an unregistered type with `NotFound` --
exactly what a real API server would do. Fixed by registering the status
subresource in that one test, matching the others.

## Roadmap (unchanged from README)

1. AWS STS temporary credentials -- specified, not built.
2. Database credentials -- specified, not built; hardest of the three
   (cleanup must survive controller restarts).
3. Arbitrary vault secrets -- specified, lowest priority.
