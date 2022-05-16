package expand

import (
	"github.com/PaloAltoNetworks/rbac-police/pkg/collect"
)

// Expands roleRefs in collectResult so that each serviceAccount or
// node enty directly lists its permissions. For a more readble output
func Expand(collectResult collect.CollectResult) *ExpandResult {
	expandResult := ExpandResult{
		Metadata: collectResult.Metadata,
	}

	for _, serviceAccount := range collectResult.ServiceAccounts {
		expandedSA := ExpandedServiceAccount{
			Name:        serviceAccount.Name,
			Namespace:   serviceAccount.Namespace,
			Nodes:       serviceAccount.Nodes,
			ProviderIAM: serviceAccount.ProviderIAM,
		}
		expandedSA.Roles = expandRoleRefs(serviceAccount.Roles, collectResult.Roles)
		expandResult.ServiceAccounts = append(expandResult.ServiceAccounts, expandedSA)
	}

	for _, node := range collectResult.Nodes {
		expandedNode := ExpandedNode{
			Name:            node.Name,
			ServiceAccounts: node.ServiceAccounts,
		}
		expandedNode.Roles = expandRoleRefs(node.Roles, collectResult.Roles)
		expandResult.Nodes = append(expandResult.Nodes, expandedNode)
	}

	return &expandResult
}

// Exapnds @rolesRefs to their full roles from @roleObjs
func expandRoleRefs(roleRefs []collect.RoleRef, roleObjs []collect.RoleEntry) []ExpandedRole {
	var expandedRoles []ExpandedRole
	for _, roleRef := range roleRefs {
		expandedRole := ExpandedRole{
			Name:               roleRef.Name,
			EffectiveNamespace: roleRef.EffectiveNamespace,
		}
		for _, roleObj := range roleObjs {
			if roleObj.Name == roleRef.Name && roleObj.Namespace == roleRef.Namespace {
				expandedRole.Rules = roleObj.Rules
				break
			}
		}
		expandedRoles = append(expandedRoles, expandedRole)
	}
	return expandedRoles
}
