package collect

import (
	v1 "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
)

// CollectConfig holds the options for Collect()
type CollectConfig struct {
	AllServiceAccounts  bool
	IgnoreControlPlane  bool
	DiscoverProtections bool
	OfflineDir          string
	NodeGroups          []string
	NodeUser            string
	Namespace           string
}

// CollectResult is the output of Collect()
// Includes the cluster metadata and the RBAC data (basically ClusterMetadata + RbacDb)
type CollectResult struct {
	Metadata        ClusterMetadata       `json:"metadata"`
	ServiceAccounts []ServiceAccountEntry `json:"serviceAccounts"`
	Nodes           []NodeEntry           `json:"nodes"`
	Users           []NamedEntry          `json:"users"`
	Groups          []NamedEntry          `json:"groups"`
	Roles           []RoleEntry           `json:"roles"`
}

// ClusterDb holds cluster objects relevant to RBAC
type ClusterDb struct {
	Pods                []v1.Pod            // TODO: only need name, namespace, serviceaccount, and node, not full object
	Nodes               []v1.Node           // TODO: only need name, not full object
	ServiceAccounts     []v1.ServiceAccount // TODO: only need name, namespace, and annotations, not full object
	Roles               []rbac.Role
	ClusterRoles        []rbac.ClusterRole
	RoleBindings        []rbac.RoleBinding
	ClusterRoleBindings []rbac.ClusterRoleBinding
}

// RbacDb is a database holding the RBAC permissions in the cluster
type RbacDb struct {
	ServiceAccounts []ServiceAccountEntry
	Nodes           []NodeEntry
	Users           []NamedEntry
	Groups          []NamedEntry
	Roles           []RoleEntry
}

type ClusterMetadata struct {
	ClusterName string         `json:"cluster"`
	Platform    string         `json:"platform"`
	Version     ClusterVersion `json:"version"`
	Features    []string       `json:"features"`
}

type ClusterVersion struct {
	Major      string `json:"major"`
	Minor      string `json:"minor"`
	GitVersion string `json:"gitVersion"`
}

// ServiceAccountEntry holds the RBAC info of a serviceAccount
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

// NodeEntry holds the RBAC info of a node
type NodeEntry struct {
	Name            string    `json:"name"`
	Roles           []RoleRef `json:"roles"`
	ServiceAccounts []string  `json:"serviceAccounts"`
}

// NamedEntry marks an identity with roles denoted by only a name, like a user or a group
type NamedEntry struct {
	Name  string    `json:"name"`
	Roles []RoleRef `json:"roles"`
}

// RoleEntry describes a Role or a ClusterRole
type RoleEntry struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace,omitempty"`
	Rules     []rbac.PolicyRule `json:"rules"`
}

// RoleRef denotes the outcome of a RoleBinding or a ClusterRoleBinding
type RoleRef struct {
	Name               string `json:"name"`
	Namespace          string `json:"namespace,omitempty"`
	EffectiveNamespace string `json:"effectiveNamespace,omitempty"`
}

// NodeToPods list the pods on a node
type NodeToPods struct {
	Name string   `json:"name"`
	Pods []string `json:"pods"`
}
