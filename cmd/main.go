// Command manager runs the ephemeral credential broker: a single-replica
// controller-runtime manager hosting the EphemeralCredential reconciler
// (design doc section 3.2). No leader election, no HA -- see design doc
// section 5, "Non-goals": single replica in v1, add leader election only if
// anyone actually needs it.
package main

import (
	"crypto/tls"
	"flag"
	"os"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC,
	// etc.) so this manager can authenticate against clusters that need
	// them, even though none are required for a stock kind/kubeadm
	// cluster.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	brokerv1alpha1 "github.com/shivansh-sinha/ephemeral-credential-broker/api/v1alpha1"
	"github.com/shivansh-sinha/ephemeral-credential-broker/internal/controller"
	"github.com/shivansh-sinha/ephemeral-credential-broker/internal/provider"
	"github.com/shivansh-sinha/ephemeral-credential-broker/internal/provider/github"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(brokerv1alpha1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var probeAddr string
	var secureMetrics bool
	var enableHTTP2 bool

	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"0 disables the metrics endpoint entirely; use :8443 to expose it.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&secureMetrics, "metrics-secure", false,
		"If set, the metrics endpoint is served securely via HTTPS. Turning this on in a real "+
			"deployment also wants an authn/authz FilterProvider (see kubebuilder's own scaffold "+
			"for sigs.k8s.io/controller-runtime/pkg/metrics/filters) -- left off here to keep v1 simple.")
	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 is enabled for the metrics and webhook servers.")
	opts := zap.Options{Development: true}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// Disabling HTTP/2 by default mitigates the known Stream Reset and
	// rapid-reset DoS classes of vulnerability (CVE-2023-44487 /
	// GHSA-qppj-fm5r-hxr9) -- the same default kubebuilder scaffolds ship.
	disableHTTP2 := func(c *tls.Config) {
		if !enableHTTP2 {
			c.NextProtos = []string{"http/1.1"}
		}
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress:   metricsAddr,
			SecureServing: secureMetrics,
			TLSOpts:       []func(*tls.Config){disableHTTP2},
		},
		WebhookServer: webhook.NewServer(webhook.Options{
			TLSOpts: []func(*tls.Config){disableHTTP2},
		}),
		HealthProbeBindAddress: probeAddr,
		// LeaderElection is deliberately omitted/false: v1 is single
		// replica by design (design doc section 5, "Non-goals").
		LeaderElection: false,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// v1 registers exactly one provider: GitHub App installation tokens
	// (design doc section 2, "Build priority"). Adding AWS STS, database,
	// or vault support later means constructing one more provider here --
	// the reconciler itself does not change.
	providers := provider.NewRegistry(
		github.New(),
	)

	if err = (&controller.EphemeralCredentialReconciler{
		Client:    mgr.GetClient(),
		Scheme:    mgr.GetScheme(),
		Providers: providers,
		Recorder:  mgr.GetEventRecorderFor("ephemeral-credential-broker"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "EphemeralCredential")
		os.Exit(1)
	}
	// +kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager", "providers", []string{github.Name})
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
