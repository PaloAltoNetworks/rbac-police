package expand

import (
	"github.com/PaloAltoNetworks/rbac-police/pkg/collect"
	rbac "k8s.io/api/rbac/v1"
)

// Expanded RBAC permissions in a cluster
// Result of Expand()
type ExpandResult struct {
	Metadata        collect.ClusterMetadata  `json:"metadata"`
	ServiceAccounts []ExpandedServiceAccount `json:"serviceAccounts"`
	Nodes           []ExpandedNode           `json:"nodes"`
	Users           []ExpandedNamedEntry     `json:"users"`
	Groups          []ExpandedNamedEntry     `json:"groups"`
}

// RBAC permissions of a serviceAccount
type ExpandedServiceAccount struct {
	Name        string               `json:"name"`
	Namespace   string               `json:"namespace"`
	Nodes       []collect.NodeToPods `json:"nodes"`
	ProviderIAM map[string]string    `json:"providerIAM,omitempty"`
	Roles       []ExpandedRole       `json:"roles"`
}

// RBAC permissions of a node
type ExpandedNode struct {
	Name            string         `json:"name"`
	Roles           []ExpandedRole `json:"roles"`
	ServiceAccounts []string       `json:"serviceAccounts"`
}

// RBAC permissions of an identity denoted by name, like a user or a group
type ExpandedNamedEntry struct {
	Name  string         `json:"name"`
	Roles []ExpandedRole `json:"roles"`
}

// A role granted in @EffectiveNamespace
type ExpandedRole struct {
	Name               string            `json:"name"`
	EffectiveNamespace string            `json:"effectiveNamespace,omitempty"`
	Rules              []rbac.PolicyRule `json:"rules"`
}
