// Package v1alpha1 contains API Schema definitions for the broker v1alpha1
// API group. It holds a single kind, EphemeralCredential -- the entire
// user-facing surface of the credential broker.
//
// +kubebuilder:object:generate=true
// +groupName=broker.shivansh-sinha.dev
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// GroupVersion is group version used to register these objects.
	GroupVersion = schema.GroupVersion{Group: "broker.shivansh-sinha.dev", Version: "v1alpha1"}

	// SchemeBuilder is used to add go types to the GroupVersionKind scheme.
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)
