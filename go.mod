module github.com/shivansh-sinha/ephemeral-credential-broker

go 1.23.0

// NOTE: this sandbox has no network access to proxy.golang.org, so these
// requirements were written by hand to match sigs.k8s.io/controller-runtime
// v0.19.3's own go.mod (the last version tested against k8s.io/* v0.31.x)
// instead of being resolved by `go get`. Run `go mod tidy` once on a machine
// with normal internet access -- it will fill in the indirect requires,
// compute go.sum, and correct any version drift if newer patch releases
// exist by the time you build this.
require (
	k8s.io/api v0.31.3
	k8s.io/apimachinery v0.31.3
	k8s.io/client-go v0.31.3
	sigs.k8s.io/controller-runtime v0.19.3
)
