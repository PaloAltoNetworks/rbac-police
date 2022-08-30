package collect

import (
	v1 "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
)

// Configuration for Collect()
type CollectConfig struct {
	AllServiceAccounts  bool
	IgnoreControlPlane  bool
	DiscoverProtections bool
	NodeGroups          []string
	NodeUser            string
	Namespace           string
}

// Outpot of Collect()
// Holds the RBAC permissions of SAs, pods and nodes in a cluster
type CollectResult struct {
	Metadata        ClusterMetadata       `json:"metadata"`
	ServiceAccounts []ServiceAccountEntry `json:"serviceAccounts"`
	Nodes           []NodeEntry           `json:"nodes"`
	Roles           []RoleEntry           `json:"roles"`
}

// Database of cluster objects relevant to RBAC
type ClusterDb struct {
	Pods                []v1.Pod            // TODO: only need name, namespace, serviceaccount, and node, not full object
	Nodes               []v1.Node           // TODO: only need name, not full object
	ServiceAccounts     []v1.ServiceAccount // TODO: only need name, namespace, and annotations, not full object
	Roles               []rbac.Role
	ClusterRoles        []rbac.ClusterRole
	RoleBindings        []rbac.RoleBinding
	ClusterRoleBindings []rbac.ClusterRoleBinding
}

// Database of the RBAC permisisons of serviceAccounts, pods and nods in a cluster
type RbacDb struct {
	ServiceAccounts []ServiceAccountEntry
	Nodes           []NodeEntry
	Roles           []RoleEntry
}

type ClusterMetadata struct {
	ClusterName string   `json:"cluster"`
	Platform    string   `json:"platform"`
	Version     string   `json:"version"`
	Features    []string `json:"features"`
}

// RBAC info of a serviceAccount
type ServiceAccountEntry struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Nodes       []NodeToPods      `json:"nodes,omitempty"`
	ProviderIAM map[string]string `json:"providerIAM,omitempty"`
	Roles       []RoleRef         `json:"roles"`
}

func (s *ServiceAccountEntry) Equals(name string, namespace string) bool {
	return s.Name == name && s.Namespace == namespace
}

// RBAC info of a node
type NodeEntry struct {
	Name            string    `json:"name"`
	Roles           []RoleRef `json:"roles"`
	ServiceAccounts []string  `json:"serviceAccounts"`
}

// A Role or ClusterRole
type RoleEntry struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace,omitempty"`
	Rules     []rbac.PolicyRule `json:"rules"`
}

// The outcome of a roleBinding / clusterRoleBinding
type RoleRef struct {
	Name               string `json:"name"`
	Namespace          string `json:"namespace,omitempty"`
	EffectiveNamespace string `json:"effectiveNamespace,omitempty"`
}

// List of pods on a node
type NodeToPods struct {
	Name string   `json:"name"`
	Pods []string `json:"pods"`
}
